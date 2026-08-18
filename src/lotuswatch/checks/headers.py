import ssl
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field

from lotuswatch.target import NormalizedTarget

DEFAULT_HEADER_TIMEOUT = 5.0
DEFAULT_MAX_REDIRECTS = 5
MAX_HEADER_VALUE_LENGTH = 2048

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
            transport=transport,
            timeout=client_timeout,
            follow_redirects=False,
            headers=REQUEST_HEADERS,
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

                next_url = str(httpx.URL(current_url).join(location))
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


def _select_https_endpoint(
    target: NormalizedTarget,
    endpoint_url: str | None,
) -> str:
    if endpoint_url is not None:
        endpoint = _validate_endpoint_url(endpoint_url)

        if urlsplit(endpoint).scheme.casefold() == "https":
            return endpoint

    return _validate_endpoint_url(_replace_scheme(target.url, "https"))


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

    return urlunsplit(
        (
            parsed.scheme.casefold(),
            parsed.netloc,
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


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
