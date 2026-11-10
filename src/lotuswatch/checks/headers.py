import re
import ssl
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field, JsonValue

from lotuswatch.exceptions import TargetValidationError
from lotuswatch.models import Finding, Severity
from lotuswatch.network import PublicAddressError, PublicHTTPTransport
from lotuswatch.target import NormalizedTarget, normalize_target

DEFAULT_HEADER_TIMEOUT = 5.0
DEFAULT_MAX_REDIRECTS = 5
MAX_HEADER_VALUE_LENGTH = 2048
MIN_RECOMMENDED_HSTS_MAX_AGE = 15_552_000

HSTS_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
    "Strict-Transport-Security"
)
CSP_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
)
CONTENT_TYPE_OPTIONS_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
)
REFERRER_POLICY_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
)
PERMISSIONS_POLICY_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
)
CLICKJACKING_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
    "Content-Security-Policy/frame-ancestors"
)

REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

SECURITY_HEADER_NAMES = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Frame-Options",
)

REQUEST_HEADERS = {
    "User-Agent": "LotusWatch/0.1 (+https://github.com/PierreS64/lotuswatch)",
    "Accept": "*/*",
}


class SecurityHeaderStatus(StrEnum):
    """Possible outcomes of an HTTP security-header check."""

    COMPLETED = "completed"
    INVALID_TARGET = "invalid_target"
    REDIRECT_LOOP = "redirect_loop"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    INSECURE_REDIRECT = "insecure_redirect"
    UNSUPPORTED_REDIRECT = "unsupported_redirect"
    TIMEOUT = "timeout"
    TLS_ERROR = "tls_error"
    CONNECTION_ERROR = "connection_error"


class HeaderObservation(BaseModel):
    """Observed value for one selected HTTP response header."""

    name: str
    present: bool
    value: str | None = None
    truncated: bool = False


class SecurityHeaderCheckResult(BaseModel):
    """Structured result of an HTTP security-header check."""

    passed: bool
    status: SecurityHeaderStatus
    requested_url: str
    final_url: str
    status_code: int | None = None
    redirect_count: int = Field(default=0, ge=0)
    headers: list[HeaderObservation] = Field(default_factory=list)
    error: str | None = None


class _EndpointSelectionError(ValueError):
    """Raised when a safe HTTPS endpoint cannot be selected."""


def check_security_headers(
    target: NormalizedTarget,
    *,
    endpoint_url: str | None = None,
    transport: httpx.BaseTransport | None = None,
    timeout: float = DEFAULT_HEADER_TIMEOUT,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> SecurityHeaderCheckResult:
    """Inspect selected security headers on an HTTPS endpoint."""

    try:
        requested_url = _select_https_endpoint(target, endpoint_url)
    except _EndpointSelectionError as exc:
        fallback_url = _replace_scheme(target.url, "https")
        return _error_result(
            status=SecurityHeaderStatus.INVALID_TARGET,
            requested_url=fallback_url,
            final_url=fallback_url,
            redirect_count=0,
            error=str(exc),
        )

    current_url = requested_url
    redirect_count = 0
    visited: set[str] = set()

    client_timeout = httpx.Timeout(timeout)

    try:
        with httpx.Client(
            transport=transport if transport is not None else PublicHTTPTransport(),
            timeout=client_timeout,
            follow_redirects=False,
            headers=REQUEST_HEADERS,
            trust_env=False,
        ) as client:
            while True:
                if current_url in visited:
                    return _error_result(
                        status=SecurityHeaderStatus.REDIRECT_LOOP,
                        requested_url=requested_url,
                        final_url=current_url,
                        redirect_count=redirect_count,
                        error="A redirect loop was detected during the header check.",
                    )

                visited.add(current_url)
                client.cookies.clear()

                with client.stream("GET", current_url) as response:
                    status_code = response.status_code
                    location = response.headers.get("location")
                    response_headers = response.headers

                client.cookies.clear()

                is_redirect = (
                    status_code in REDIRECT_STATUS_CODES and location is not None
                )

                if not is_redirect:
                    return SecurityHeaderCheckResult(
                        passed=True,
                        status=SecurityHeaderStatus.COMPLETED,
                        requested_url=requested_url,
                        final_url=current_url,
                        status_code=status_code,
                        redirect_count=redirect_count,
                        headers=_collect_security_headers(response_headers),
                    )

                if redirect_count >= max_redirects:
                    return _error_result(
                        status=SecurityHeaderStatus.TOO_MANY_REDIRECTS,
                        requested_url=requested_url,
                        final_url=current_url,
                        redirect_count=redirect_count,
                        error=(
                            "Header check redirect chain exceeded the limit of "
                            f"{max_redirects} redirects."
                        ),
                    )

                try:
                    next_url = str(httpx.URL(current_url).join(location))
                except (httpx.InvalidURL, ValueError) as exc:
                    return _error_result(
                        status=SecurityHeaderStatus.INVALID_TARGET,
                        requested_url=requested_url,
                        final_url=current_url,
                        redirect_count=redirect_count,
                        error=f"Invalid redirect destination: {exc}",
                    )
                next_scheme = urlsplit(next_url).scheme.casefold()

                if next_scheme == "http":
                    return _error_result(
                        status=SecurityHeaderStatus.INSECURE_REDIRECT,
                        requested_url=requested_url,
                        final_url=next_url,
                        redirect_count=redirect_count,
                        error="HTTPS endpoint redirected to an insecure HTTP URL.",
                    )

                if next_scheme != "https":
                    return _error_result(
                        status=SecurityHeaderStatus.UNSUPPORTED_REDIRECT,
                        requested_url=requested_url,
                        final_url=next_url,
                        redirect_count=redirect_count,
                        error=(
                            "Header check redirect destination uses an "
                            f"unsupported scheme: {next_scheme or 'missing'}."
                        ),
                    )

                try:
                    next_url = _validate_endpoint_url(next_url)
                    _require_same_hostname(target, next_url)
                except _EndpointSelectionError as exc:
                    return _error_result(
                        status=SecurityHeaderStatus.INVALID_TARGET,
                        requested_url=requested_url,
                        final_url=next_url,
                        redirect_count=redirect_count,
                        error=str(exc),
                    )

                redirect_count += 1
                current_url = next_url
    except PublicAddressError as exc:
        return _error_result(
            status=SecurityHeaderStatus.INVALID_TARGET,
            requested_url=requested_url,
            final_url=current_url,
            redirect_count=redirect_count,
            error=str(exc),
        )
    except httpx.TimeoutException:
        return _error_result(
            status=SecurityHeaderStatus.TIMEOUT,
            requested_url=requested_url,
            final_url=current_url,
            redirect_count=redirect_count,
            error="The security-header request timed out.",
        )
    except httpx.RequestError as exc:
        if _caused_by_ssl_error(exc):
            status = SecurityHeaderStatus.TLS_ERROR
            message = f"Security-header TLS connection failed: {exc}"
        else:
            status = SecurityHeaderStatus.CONNECTION_ERROR
            message = f"Security-header connection failed: {exc}"

        return _error_result(
            status=status,
            requested_url=requested_url,
            final_url=current_url,
            redirect_count=redirect_count,
            error=message,
        )


def security_header_result_to_findings(
    result: SecurityHeaderCheckResult,
) -> list[Finding]:
    """Convert a completed security-header check into contextual findings."""

    if result.status is not SecurityHeaderStatus.COMPLETED or not result.passed:
        return []

    observations = {
        observation.name.casefold(): observation for observation in result.headers
    }
    findings: list[Finding] = []

    hsts = observations.get("strict-transport-security")
    hsts_value = _observed_value(hsts)
    hsts_max_age = _parse_hsts_max_age(hsts_value)

    if hsts_value is None or hsts_max_age is None:
        findings.append(
            Finding(
                id="LW-HEADER-001",
                severity=Severity.MEDIUM,
                title="Effective HSTS policy is missing",
                description=(
                    "No valid HSTS max-age directive was observed on the HTTPS "
                    "response. This weakens protection against HTTP downgrade "
                    "attempts but does not by itself demonstrate exploitability."
                ),
                evidence=_finding_evidence(
                    result,
                    {"strict_transport_security": hsts_value},
                ),
                recommendation=(
                    "After confirming the site and required subdomains work "
                    "exclusively over HTTPS, deploy an HSTS max-age appropriate "
                    "for the rollout. Validate includeSubDomains or preload "
                    "separately before enabling either directive."
                ),
                reference=HSTS_REFERENCE,
            )
        )
    elif hsts_max_age < MIN_RECOMMENDED_HSTS_MAX_AGE:
        findings.append(
            Finding(
                id="LW-HEADER-002",
                severity=Severity.LOW,
                title="HSTS max-age is shorter than recommended",
                description=(
                    "The HSTS max-age is below 15552000 seconds, so browsers "
                    "may stop enforcing HTTPS sooner than expected. This is a "
                    "defense-in-depth weakness, not proof of an exploitable flaw."
                ),
                evidence=_finding_evidence(
                    result,
                    {
                        "strict_transport_security": hsts_value,
                        "hsts_max_age": hsts_max_age,
                        "recommended_minimum_seconds": (MIN_RECOMMENDED_HSTS_MAX_AGE),
                    },
                ),
                recommendation=(
                    "Increase max-age gradually after verifying reliable HTTPS "
                    "operation. Choose a duration that matches the deployment "
                    "and rollback strategy rather than copying a policy blindly."
                ),
                reference=HSTS_REFERENCE,
            )
        )

    csp = observations.get("content-security-policy")
    csp_value = _observed_value(csp)

    if csp_value is None:
        findings.append(
            Finding(
                id="LW-HEADER-003",
                severity=Severity.MEDIUM,
                title="Content Security Policy is missing",
                description=(
                    "The response does not provide a Content-Security-Policy "
                    "header. This removes a browser defense-in-depth control but "
                    "does not mean that script injection is currently possible."
                ),
                evidence=_finding_evidence(
                    result,
                    {"content_security_policy": None},
                ),
                recommendation=(
                    "Design and test a Content Security Policy based on the "
                    "resources the application actually requires. Begin with "
                    "reporting where appropriate and tighten the policy using "
                    "observed violations."
                ),
                reference=CSP_REFERENCE,
            )
        )

    content_type_options = observations.get("x-content-type-options")
    content_type_options_value = _observed_value(content_type_options)

    if (
        content_type_options_value is None
        or content_type_options_value.strip().casefold() != "nosniff"
    ):
        findings.append(
            Finding(
                id="LW-HEADER-004",
                severity=Severity.LOW,
                title="MIME sniffing protection is missing",
                description=(
                    "X-Content-Type-Options is missing or is not set to nosniff. "
                    "This weakens browser MIME-type enforcement but does not by "
                    "itself demonstrate a content-sniffing exploit."
                ),
                evidence=_finding_evidence(
                    result,
                    {"x_content_type_options": content_type_options_value},
                ),
                recommendation=(
                    "Return X-Content-Type-Options: nosniff and ensure every "
                    "resource is served with an accurate Content-Type value."
                ),
                reference=CONTENT_TYPE_OPTIONS_REFERENCE,
            )
        )

    referrer_policy = observations.get("referrer-policy")
    referrer_policy_value = _observed_value(referrer_policy)

    if referrer_policy_value is None:
        findings.append(
            Finding(
                id="LW-HEADER-005",
                severity=Severity.LOW,
                title="Referrer Policy is missing",
                description=(
                    "The response does not define a Referrer-Policy header. "
                    "Browser defaults may expose more navigation context than "
                    "intended, although this is not proof of sensitive data loss."
                ),
                evidence=_finding_evidence(result, {"referrer_policy": None}),
                recommendation=(
                    "Select a Referrer-Policy that matches the application's "
                    "cross-origin navigation and analytics needs, then verify it "
                    "against expected user flows."
                ),
                reference=REFERRER_POLICY_REFERENCE,
            )
        )

    permissions_policy = observations.get("permissions-policy")
    permissions_policy_value = _observed_value(permissions_policy)

    if permissions_policy_value is None:
        findings.append(
            Finding(
                id="LW-HEADER-006",
                severity=Severity.INFO,
                title="Permissions Policy is missing",
                description=(
                    "The response does not define a Permissions-Policy header. "
                    "Explicit browser feature restrictions could improve defense "
                    "in depth, but their absence is not a confirmed vulnerability."
                ),
                evidence=_finding_evidence(result, {"permissions_policy": None}),
                recommendation=(
                    "Review which browser features the application and embedded "
                    "content require, then restrict only the unused or untrusted "
                    "features after compatibility testing."
                ),
                reference=PERMISSIONS_POLICY_REFERENCE,
            )
        )

    x_frame_options = observations.get("x-frame-options")
    x_frame_options_value = _observed_value(x_frame_options)

    if not _csp_has_frame_ancestors(csp_value) and not _valid_x_frame_options(
        x_frame_options_value
    ):
        findings.append(
            Finding(
                id="LW-HEADER-007",
                severity=Severity.MEDIUM,
                title="Clickjacking protection is missing",
                description=(
                    "No effective CSP frame-ancestors or X-Frame-Options "
                    "policy was observed. This weakens browser "
                    "framing defenses but does not confirm a clickjacking exploit."
                ),
                evidence=_finding_evidence(
                    result,
                    {
                        "content_security_policy": csp_value,
                        "x_frame_options": x_frame_options_value,
                    },
                ),
                recommendation=(
                    "Define an appropriate CSP frame-ancestors directive based "
                    "on the origins allowed to frame the application. Add "
                    "X-Frame-Options only when legacy browser support is needed."
                ),
                reference=CLICKJACKING_REFERENCE,
            )
        )

    return findings


def _observed_value(observation: HeaderObservation | None) -> str | None:
    if observation is None or not observation.present:
        return None

    if observation.value is None:
        return None

    return observation.value[:MAX_HEADER_VALUE_LENGTH]


def _parse_hsts_max_age(value: str | None) -> int | None:
    if value is None:
        return None

    max_age_values: list[str] = []

    for directive in value.split(";"):
        name, separator, directive_value = directive.partition("=")

        if name.strip().casefold() != "max-age":
            continue

        if not separator:
            return None

        max_age_values.append(directive_value.strip())

    if len(max_age_values) != 1 or not max_age_values[0].isdigit():
        return None

    return int(max_age_values[0])


def _csp_has_frame_ancestors(value: str | None) -> bool:
    if value is None:
        return False

    for directive in value.split(";"):
        parts = directive.strip().split(maxsplit=1)

        if parts and parts[0].casefold() == "frame-ancestors":
            if len(parts) != 2:
                return False
            sources = parts[1].split()
            if not sources or "'none'" in sources:
                return sources == ["'none'"]
            return all(_valid_frame_ancestor_source(source) for source in sources)

    return False


def _valid_frame_ancestor_source(source: str) -> bool:
    if source == "'self'":
        return True
    if source in {"*", "http:", "https:"}:
        return False
    if not re.fullmatch(r"https?://[^\s/]+", source, flags=re.IGNORECASE):
        return False
    try:
        parsed = urlsplit(source)
        return (
            parsed.hostname is not None
            and parsed.hostname != "*"
            and parsed.username is None
            and parsed.password is None
            and parsed.port != 0
        )
    except ValueError:
        return False


def _valid_x_frame_options(value: str | None) -> bool:
    return value is not None and value.strip().casefold() in {"deny", "sameorigin"}


def _finding_evidence(
    result: SecurityHeaderCheckResult,
    observed: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    evidence: dict[str, JsonValue] = {
        "final_url": result.final_url,
        "status": result.status.value,
    }

    if result.status_code is not None:
        evidence["status_code"] = result.status_code

    evidence.update(observed)
    return evidence


def _select_https_endpoint(
    target: NormalizedTarget,
    endpoint_url: str | None,
) -> str:
    if endpoint_url is not None:
        endpoint = _validate_endpoint_url(endpoint_url)
        _require_same_hostname(target, endpoint)

        if urlsplit(endpoint).scheme.casefold() == "https":
            return endpoint

    endpoint = _validate_endpoint_url(_replace_scheme(target.url, "https"))
    _require_same_hostname(target, endpoint)
    return endpoint


def _require_same_hostname(target: NormalizedTarget, endpoint_url: str) -> None:
    if urlsplit(endpoint_url).hostname != target.hostname:
        raise _EndpointSelectionError(
            "Security-header endpoint is outside the target hostname scope."
        )


def _validate_endpoint_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise _EndpointSelectionError(
            "Security-header endpoint is not a valid URL."
        ) from exc

    if parsed.scheme.casefold() not in {"http", "https"}:
        raise _EndpointSelectionError(
            "Security-header endpoint must use HTTP or HTTPS."
        )

    if parsed.hostname is None:
        raise _EndpointSelectionError(
            "Security-header endpoint must contain a hostname."
        )

    if parsed.username is not None or parsed.password is not None:
        raise _EndpointSelectionError(
            "Security-header endpoint cannot contain credentials."
        )

    try:
        return normalize_target(value).url
    except TargetValidationError as exc:
        raise _EndpointSelectionError(str(exc)) from exc


def _collect_security_headers(
    response_headers: httpx.Headers,
) -> list[HeaderObservation]:
    observations: list[HeaderObservation] = []

    for name in SECURITY_HEADER_NAMES:
        value = response_headers.get(name)

        if value is None:
            observations.append(
                HeaderObservation(
                    name=name,
                    present=False,
                )
            )
            continue

        truncated = len(value) > MAX_HEADER_VALUE_LENGTH
        observations.append(
            HeaderObservation(
                name=name,
                present=True,
                value=value[:MAX_HEADER_VALUE_LENGTH],
                truncated=truncated,
            )
        )

    return observations


def _error_result(
    *,
    status: SecurityHeaderStatus,
    requested_url: str,
    final_url: str,
    redirect_count: int,
    error: str,
) -> SecurityHeaderCheckResult:
    return SecurityHeaderCheckResult(
        passed=False,
        status=status,
        requested_url=requested_url,
        final_url=final_url,
        redirect_count=redirect_count,
        error=error,
    )


def _replace_scheme(url: str, scheme: str) -> str:
    parsed = urlsplit(url)

    return urlunsplit(
        (
            scheme,
            parsed.netloc,
            parsed.path,
            parsed.query,
            "",
        )
    )


def _caused_by_ssl_error(exc: BaseException) -> bool:
    current: BaseException | None = exc
    visited: set[int] = set()

    while current is not None and id(current) not in visited:
        if isinstance(current, ssl.SSLError):
            return True

        visited.add(id(current))
        current = current.__cause__ or current.__context__

    return False
