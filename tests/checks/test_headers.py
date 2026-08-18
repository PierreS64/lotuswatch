import ssl

import httpx

from lotuswatch.checks import (
    SecurityHeaderStatus,
    check_security_headers,
)
from lotuswatch.target import normalize_target


class UnreadableStream(httpx.SyncByteStream):
    """Response stream that fails if code attempts to read its body."""

    def __init__(self) -> None:
        self.closed = False

    def __iter__(self):
        raise AssertionError("Response body must not be read.")

    def close(self) -> None:
        self.closed = True


def run_check(
    handler,
    *,
    target: str = "example.com",
    endpoint_url: str | None = None,
    max_redirects: int = 5,
):
    return check_security_headers(
        normalize_target(target),
        endpoint_url=endpoint_url,
        transport=httpx.MockTransport(handler),
        max_redirects=max_redirects,
    )


def test_collects_selected_headers_case_insensitively() -> None:
    response_headers = {
        "strict-transport-security": "max-age=31536000",
        "CONTENT-SECURITY-POLICY": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "X-Frame-Options": "DENY",
    }

    result = run_check(lambda request: httpx.Response(200, headers=response_headers))

    assert result.passed is True
    assert result.status is SecurityHeaderStatus.COMPLETED
    assert result.requested_url == "https://example.com/"
    assert result.final_url == "https://example.com/"
    assert result.status_code == 200
    assert len(result.headers) == 6
    assert all(observation.present for observation in result.headers)
    assert result.headers[0].name == "Strict-Transport-Security"
    assert result.headers[0].value == "max-age=31536000"


def test_missing_headers_are_represented_explicitly() -> None:
    result = run_check(lambda request: httpx.Response(200))

    assert len(result.headers) == 6
    assert all(not observation.present for observation in result.headers)
    assert all(observation.value is None for observation in result.headers)


def test_header_values_are_truncated_safely() -> None:
    result = run_check(
        lambda request: httpx.Response(
            200,
            headers={"Content-Security-Policy": "a" * 3000},
        )
    )

    csp = result.headers[1]

    assert csp.present is True
    assert csp.truncated is True
    assert csp.value is not None
    assert len(csp.value) == 2048


def test_response_body_is_not_read() -> None:
    stream = UnreadableStream()

    result = run_check(
        lambda request: httpx.Response(
            200,
            headers={"X-Content-Type-Options": "nosniff"},
            stream=stream,
        )
    )

    assert result.passed is True
    assert stream.closed is True


def test_http_target_falls_back_to_normalized_https_endpoint() -> None:
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200)

    result = run_check(handler, target="http://example.com/path")

    assert requested_urls == ["https://example.com/path"]
    assert result.requested_url == "https://example.com/path"


def test_explicit_https_endpoint_is_used() -> None:
    requested_urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(200)

    result = run_check(
        handler,
        endpoint_url="https://cdn.example.com/final",
    )

    assert requested_urls == ["https://cdn.example.com/final"]
    assert result.final_url == "https://cdn.example.com/final"


def test_relative_https_redirect_is_followed() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(302, headers={"Location": "/final"})

        return httpx.Response(
            200,
            headers={"X-Content-Type-Options": "nosniff"},
        )

    result = run_check(handler)

    assert result.passed is True
    assert result.final_url == "https://example.com/final"
    assert result.redirect_count == 1


def test_cookies_are_not_forwarded_between_redirects() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)

        if request.url.path == "/":
            return httpx.Response(
                302,
                headers={
                    "Location": "/final",
                    "Set-Cookie": "session=secret; Secure",
                },
            )

        return httpx.Response(200)

    result = run_check(handler)

    assert result.passed is True
    assert len(requests) == 2
    assert "cookie" not in requests[1].headers


def test_redirect_loop_is_detected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        destination = "/loop" if request.url.path == "/" else "/"
        return httpx.Response(302, headers={"Location": destination})

    result = run_check(handler)

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.REDIRECT_LOOP


def test_redirect_limit_is_enforced() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        next_path = "/one" if request.url.path == "/" else "/two"
        return httpx.Response(302, headers={"Location": next_path})

    result = run_check(handler, max_redirects=1)

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.TOO_MANY_REDIRECTS
    assert result.redirect_count == 1


def test_redirect_to_http_is_rejected() -> None:
    result = run_check(
        lambda request: httpx.Response(
            302,
            headers={"Location": "http://example.com/insecure"},
        )
    )

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.INSECURE_REDIRECT


def test_redirect_to_unsupported_scheme_is_rejected() -> None:
    result = run_check(
        lambda request: httpx.Response(
            302,
            headers={"Location": "ftp://example.com/file"},
        )
    )

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.UNSUPPORTED_REDIRECT


def test_redirect_with_credentials_is_rejected() -> None:
    result = run_check(
        lambda request: httpx.Response(
            302,
            headers={"Location": "https://user:secret@example.com/final"},
        )
    )

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.INVALID_TARGET
    assert result.error == "Security-header endpoint cannot contain credentials."


def test_timeout_is_controlled() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Request timed out.", request=request)

    result = run_check(handler)

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.TIMEOUT


def test_connection_error_is_controlled() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Connection failed.", request=request)

    result = run_check(handler)

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.CONNECTION_ERROR


def test_tls_error_is_controlled() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        try:
            raise ssl.SSLError("certificate verify failed")
        except ssl.SSLError as exc:
            raise httpx.ConnectError(
                "TLS connection failed.",
                request=request,
            ) from exc

    result = run_check(handler)

    assert result.passed is False
    assert result.status is SecurityHeaderStatus.TLS_ERROR


def test_http_error_response_still_returns_header_observations() -> None:
    result = run_check(
        lambda request: httpx.Response(
            530,
            headers={"X-Content-Type-Options": "nosniff"},
        )
    )

    assert result.passed is True
    assert result.status is SecurityHeaderStatus.COMPLETED
    assert result.status_code == 530
    assert len(result.headers) == 6
