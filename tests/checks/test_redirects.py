import httpx

from lotuswatch.checks import (
    RedirectStatus,
    check_http_to_https_redirect,
    redirect_result_to_finding,
)
from lotuswatch.target import normalize_target


def run_check(
    handler: httpx.MockTransport,
    *,
    max_redirects: int = 5,
):
    target = normalize_target("example.com")

    return check_http_to_https_redirect(
        target,
        transport=handler,
        max_redirects=max_redirects,
    )


def test_direct_http_to_https_redirect_passes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == "http://example.com/":
            return httpx.Response(
                301,
                headers={"Location": "https://example.com/"},
            )

        return httpx.Response(200)

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is True
    assert result.status is RedirectStatus.PASSED
    assert result.initial_url == "http://example.com/"
    assert result.final_url == "https://example.com/"
    assert result.redirect_count == 1
    assert result.initial_status_code == 301
    assert result.final_status_code == 200


def test_multi_step_redirect_to_https_passes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        responses = {
            "http://example.com/": httpx.Response(
                302,
                headers={"Location": "/redirect"},
            ),
            "http://example.com/redirect": httpx.Response(
                301,
                headers={"Location": "https://example.com/final"},
            ),
            "https://example.com/final": httpx.Response(200),
        }

        return responses[str(request.url)]

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is True
    assert result.status is RedirectStatus.PASSED
    assert result.redirect_count == 2
    assert result.final_url == "https://example.com/final"


def test_http_without_redirect_fails() -> None:
    transport = httpx.MockTransport(lambda request: httpx.Response(200))

    result = run_check(transport)
    finding = redirect_result_to_finding(result)

    assert result.passed is False
    assert result.status is RedirectStatus.NO_HTTPS_REDIRECT
    assert result.redirect_count == 0
    assert finding is not None
    assert finding.id == "LW-HTTP-001"


def test_redirect_loop_is_detected() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(
                302,
                headers={"Location": "/loop"},
            )

        return httpx.Response(
            302,
            headers={"Location": "/"},
        )

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is False
    assert result.status is RedirectStatus.REDIRECT_LOOP
    assert result.error == "A redirect loop was detected."


def test_redirect_limit_is_enforced() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path

        if path == "/":
            next_path = "/1"
        else:
            next_path = f"/{int(path.removeprefix('/')) + 1}"

        return httpx.Response(
            302,
            headers={"Location": next_path},
        )

    result = run_check(
        httpx.MockTransport(handler),
        max_redirects=2,
    )

    assert result.passed is False
    assert result.status is RedirectStatus.TOO_MANY_REDIRECTS
    assert result.redirect_count == 2


def test_unsupported_redirect_scheme_is_rejected() -> None:
    transport = httpx.MockTransport(
        lambda request: httpx.Response(
            302,
            headers={"Location": "ftp://example.com/file"},
        )
    )

    result = run_check(transport)

    assert result.passed is False
    assert result.status is RedirectStatus.UNSUPPORTED_SCHEME


def test_timeout_is_handled() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout(
            "Request timed out.",
            request=request,
        )

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is False
    assert result.status is RedirectStatus.TIMEOUT
    assert result.error == "The HTTP request timed out."
    assert redirect_result_to_finding(result) is None


def test_connection_error_is_handled() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(
            "Connection failed.",
            request=request,
        )

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is False
    assert result.status is RedirectStatus.CONNECTION_ERROR
    assert redirect_result_to_finding(result) is None


def test_passed_result_does_not_create_finding() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.scheme == "http":
            return httpx.Response(
                301,
                headers={"Location": "https://example.com/"},
            )

        return httpx.Response(200)

    result = run_check(httpx.MockTransport(handler))

    assert redirect_result_to_finding(result) is None


def test_redirect_to_other_hostname_is_not_requested() -> None:
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://other.example/"})

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is False
    assert result.error is not None and "scope" in result.error.lower()
    assert requested == ["http://example.com/"]


def test_redirect_to_private_ip_is_not_requested() -> None:
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(302, headers={"Location": "http://127.0.0.1/admin"})

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is False
    assert requested == ["http://example.com/"]


def test_redirect_with_credentials_is_not_requested() -> None:
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(
            302, headers={"Location": "https://user:pass@example.com/"}
        )

    result = run_check(httpx.MockTransport(handler))

    assert result.passed is False
    assert requested == ["http://example.com/"]


def test_malformed_redirect_is_controlled() -> None:
    result = run_check(
        httpx.MockTransport(
            lambda request: httpx.Response(302, headers={"Location": "https://[bad"})
        )
    )
    assert result.status is RedirectStatus.CONNECTION_ERROR
