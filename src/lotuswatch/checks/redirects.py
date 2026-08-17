from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit

import httpx
from pydantic import BaseModel, Field

from lotuswatch.models import Finding, Severity
from lotuswatch.target import NormalizedTarget

DEFAULT_MAX_REDIRECTS = 5
REDIRECT_STATUS_CODES = {301, 302, 303, 307, 308}

REQUEST_HEADERS = {
    "User-Agent": "LotusWatch/0.1 (+https://github.com/)",
    "Accept": "*/*",
}


class RedirectStatus(StrEnum):
    """Possible outcomes of an HTTP-to-HTTPS redirect check."""

    PASSED = "passed"
    NO_HTTPS_REDIRECT = "no_https_redirect"
    REDIRECT_LOOP = "redirect_loop"
    TOO_MANY_REDIRECTS = "too_many_redirects"
    UNSUPPORTED_SCHEME = "unsupported_redirect_scheme"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"


class RedirectHop(BaseModel):
    """One HTTP response in a redirect chain."""

    url: str
    status_code: int
    location: str | None = None


class RedirectCheckResult(BaseModel):
    """Result of checking whether HTTP redirects to HTTPS."""

    passed: bool
    status: RedirectStatus
    initial_url: str
    final_url: str
    redirect_count: int = Field(ge=0)
    initial_status_code: int | None = None
    final_status_code: int | None = None
    hops: list[RedirectHop] = Field(default_factory=list)
    error: str | None = None


def check_http_to_https_redirect(
    target: NormalizedTarget,
    *,
    transport: httpx.BaseTransport | None = None,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> RedirectCheckResult:
    """Check whether the HTTP target ultimately redirects to HTTPS."""

    initial_url = _replace_scheme(target.url, "http")
    current_url = initial_url
    visited: set[str] = set()
    hops: list[RedirectHop] = []
    redirect_count = 0
    initial_status_code: int | None = None

    timeout = httpx.Timeout(5.0, connect=3.0)

    try:
        with httpx.Client(
            transport=transport,
            timeout=timeout,
            follow_redirects=False,
            headers=REQUEST_HEADERS,
        ) as client:
            while True:
                if current_url in visited:
                    return _make_result(
                        passed=False,
                        status=RedirectStatus.REDIRECT_LOOP,
                        initial_url=initial_url,
                        final_url=current_url,
                        redirect_count=redirect_count,
                        initial_status_code=initial_status_code,
                        final_status_code=None,
                        hops=hops,
                        error="A redirect loop was detected.",
                    )

                visited.add(current_url)
                client.cookies.clear()

                with client.stream("GET", current_url) as response:
                    status_code = response.status_code
                    location = response.headers.get("location")

                client.cookies.clear()

                if initial_status_code is None:
                    initial_status_code = status_code

                hops.append(
                    RedirectHop(
                        url=current_url,
                        status_code=status_code,
                        location=location,
                    )
                )

                is_redirect = (
                    status_code in REDIRECT_STATUS_CODES and location is not None
                )

                if not is_redirect:
                    passed = urlsplit(current_url).scheme.lower() == "https"

                    return _make_result(
                        passed=passed,
                        status=(
                            RedirectStatus.PASSED
                            if passed
                            else RedirectStatus.NO_HTTPS_REDIRECT
                        ),
                        initial_url=initial_url,
                        final_url=current_url,
                        redirect_count=redirect_count,
                        initial_status_code=initial_status_code,
                        final_status_code=status_code,
                        hops=hops,
                    )

                if redirect_count >= max_redirects:
                    return _make_result(
                        passed=False,
                        status=RedirectStatus.TOO_MANY_REDIRECTS,
                        initial_url=initial_url,
                        final_url=current_url,
                        redirect_count=redirect_count,
                        initial_status_code=initial_status_code,
                        final_status_code=status_code,
                        hops=hops,
                        error=(
                            f"Redirect chain exceeded the limit of "
                            f"{max_redirects} redirects."
                        ),
                    )

                next_url = str(httpx.URL(current_url).join(location))
                next_scheme = urlsplit(next_url).scheme.lower()

                if next_scheme not in {"http", "https"}:
                    return _make_result(
                        passed=False,
                        status=RedirectStatus.UNSUPPORTED_SCHEME,
                        initial_url=initial_url,
                        final_url=next_url,
                        redirect_count=redirect_count,
                        initial_status_code=initial_status_code,
                        final_status_code=status_code,
                        hops=hops,
                        error=(
                            "Redirect destination uses an unsupported "
                            f"scheme: {next_scheme or 'missing'}."
                        ),
                    )

                redirect_count += 1
                current_url = next_url

    except httpx.TimeoutException:
        return _make_result(
            passed=False,
            status=RedirectStatus.TIMEOUT,
            initial_url=initial_url,
            final_url=current_url,
            redirect_count=redirect_count,
            initial_status_code=initial_status_code,
            final_status_code=None,
            hops=hops,
            error="The HTTP request timed out.",
        )
    except httpx.RequestError as exc:
        return _make_result(
            passed=False,
            status=RedirectStatus.CONNECTION_ERROR,
            initial_url=initial_url,
            final_url=current_url,
            redirect_count=redirect_count,
            initial_status_code=initial_status_code,
            final_status_code=None,
            hops=hops,
            error=f"HTTP connection failed: {exc}",
        )


def redirect_result_to_finding(
    result: RedirectCheckResult,
) -> Finding | None:
    """Convert a completed failed redirect check into a finding."""

    if result.passed:
        return None

    if result.status in {
        RedirectStatus.TIMEOUT,
        RedirectStatus.CONNECTION_ERROR,
    }:
        return None

    return Finding(
        id="LW-HTTP-001",
        severity=Severity.MEDIUM,
        title="HTTP does not redirect safely to HTTPS",
        description=(
            "The HTTP endpoint did not complete a valid redirect chain "
            "to an HTTPS destination."
        ),
        evidence={
            "initial_url": result.initial_url,
            "final_url": result.final_url,
            "status": result.status.value,
            "redirect_count": result.redirect_count,
            "initial_status_code": result.initial_status_code,
            "final_status_code": result.final_status_code,
            "hops": [hop.model_dump(mode="json") for hop in result.hops],
        },
        recommendation=(
            "Configure the web server to redirect all HTTP requests "
            "to an HTTPS destination."
        ),
        reference=("https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections"),
    )


def _replace_scheme(url: str, scheme: str) -> str:
    """Return a URL with its scheme replaced."""

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


def _make_result(
    *,
    passed: bool,
    status: RedirectStatus,
    initial_url: str,
    final_url: str,
    redirect_count: int,
    initial_status_code: int | None,
    final_status_code: int | None,
    hops: list[RedirectHop],
    error: str | None = None,
) -> RedirectCheckResult:
    """Build a redirect check result."""

    return RedirectCheckResult(
        passed=passed,
        status=status,
        initial_url=initial_url,
        final_url=final_url,
        redirect_count=redirect_count,
        initial_status_code=initial_status_code,
        final_status_code=final_status_code,
        hops=hops,
        error=error,
    )
