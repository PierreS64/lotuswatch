import json
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import httpx
import pytest

import lotuswatch.notifications.webhook
from lotuswatch.exceptions import NotificationConfigurationError
from lotuswatch.models import (
    ComparisonSummary,
    NotificationChangeStatus,
    NotificationChannel,
    NotificationDeliveryStatus,
    NotificationDiagnosticCode,
    NotificationEvent,
    NotificationObservation,
    NotificationRetryPolicy,
    NotificationTimeouts,
    Severity,
    finding_id_fingerprint,
)
from lotuswatch.notifications import (
    WEBHOOK_CONTENT_TYPE,
    WEBHOOK_EVENT_HEADER,
    WEBHOOK_SCHEMA_HEADER,
    WEBHOOK_SECRET_ENVIRONMENT_VARIABLE,
    WEBHOOK_SIGNATURE_HEADER,
    WEBHOOK_URL_ENVIRONMENT_VARIABLE,
    EnvironmentSecretProvider,
    NotificationSender,
    WebhookNotificationSender,
    serialize_webhook_event,
    sign_webhook_payload,
    validate_webhook_url,
    verify_webhook_signature,
)

TARGET = "https://example.com/"
EVENT_ID = UUID("10000000-0000-4000-8000-000000000001")
WEBHOOK_URL = "https://hooks.example.com/lotuswatch?tenant=demo"


def event() -> NotificationEvent:
    finding_id = "LW-TEST-001"
    timestamp = datetime(2026, 8, 21, 10, 0, tzinfo=UTC)
    return NotificationEvent(
        event_id=EVENT_ID,
        generated_at=timestamp,
        profile_name="production",
        normalized_target=TARGET,
        run_id=UUID("20000000-0000-4000-8000-000000000001"),
        scanned_at=timestamp,
        compared_at=timestamp,
        threshold=Severity.MEDIUM,
        comparison_summary=ComparisonSummary(
            added=1,
            resolved=0,
            changed=0,
            unchanged=0,
        ),
        total_triggering_observations=1,
        truncated=False,
        observations=[
            NotificationObservation(
                fingerprint=finding_id_fingerprint(TARGET, finding_id),
                status=NotificationChangeStatus.ADDED,
                finding_id=finding_id,
                severity=Severity.HIGH,
                title="Synthetic finding",
            )
        ],
    )


def secrets(
    *,
    url: str = WEBHOOK_URL,
    signing_secret: str | None = None,
) -> EnvironmentSecretProvider:
    values = {WEBHOOK_URL_ENVIRONMENT_VARIABLE: url}
    if signing_secret is not None:
        values[WEBHOOK_SECRET_ENVIRONMENT_VARIABLE] = signing_secret
    return EnvironmentSecretProvider(values)


def sender(
    handler: httpx.MockTransport | httpx.BaseTransport,
    *,
    delays: list[float] | None = None,
    retry_policy: NotificationRetryPolicy | None = None,
) -> WebhookNotificationSender:
    selected_delays = [] if delays is None else delays
    return WebhookNotificationSender(
        transport=handler,
        retry_policy=retry_policy,
        sleep=selected_delays.append,
    )


def test_sender_implements_webhook_channel_contract() -> None:
    selected = sender(httpx.MockTransport(lambda _: httpx.Response(204)))

    assert isinstance(selected, NotificationSender)
    assert selected.channel is NotificationChannel.WEBHOOK


@pytest.mark.parametrize(
    "url",
    [
        "https://hooks.example.com/path",
        "HTTPS://HOOKS.EXAMPLE.COM:443/path?tenant=demo",
        "https://8.8.8.8/hook",
        "https://[2001:4860:4860::8888]/hook",
        "https://例え.テスト/hook",
    ],
)
def test_accepts_valid_public_https_webhook_urls(url: str) -> None:
    assert validate_webhook_url(url) == url


@pytest.mark.parametrize(
    "url",
    [
        "",
        " http://hooks.example.com/path ",
        "http://hooks.example.com/path",
        "ftp://hooks.example.com/path",
        "https://user:password@hooks.example.com/path",
        "https://hooks.example.com/path#fragment",
        "https://hooks.example.com:8443/path",
        "https://hooks.example.com/bad path",
        "https://localhost/path",
        "https://service.local/path",
        "https://service.internal/path",
        "https://service.home.arpa/path",
        "https://singlelabel/path",
        "https://-invalid.example/path",
        "https://127.0.0.1/path",
        "https://10.0.0.1/path",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/path",
        "https://[fc00::1]/path",
        "https://0.0.0.0/path",
    ],
)
def test_rejects_unsafe_or_malformed_webhook_urls_without_echo(url: str) -> None:
    with pytest.raises(NotificationConfigurationError) as error:
        validate_webhook_url(url)

    if url:
        assert url not in str(error.value)


def test_deterministic_payload_contains_only_notification_event() -> None:
    selected_event = event()
    first = serialize_webhook_event(selected_event)
    second = serialize_webhook_event(selected_event.model_copy(deep=True))
    decoded = json.loads(first)

    assert first == second
    assert b": " not in first
    assert b", " not in first
    assert decoded == selected_event.model_dump(mode="json")
    assert "evidence" not in decoded["observations"][0]
    assert "description" not in decoded["observations"][0]
    assert "recommendation" not in decoded["observations"][0]


def test_payload_size_is_enforced_before_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        lotuswatch.notifications.webhook, "MAX_WEBHOOK_PAYLOAD_BYTES", 1
    )

    with pytest.raises(NotificationConfigurationError, match="size limit"):
        serialize_webhook_event(event())


def test_hmac_signature_matches_fixed_vector_and_exact_bytes() -> None:
    body = b'{"a":1}'
    expected = "v1=179bf20a8b9040a32368814a68b0dc270823b5968498e0a73796c4202708ed8d"

    assert sign_webhook_payload(body, "test-secret") == expected
    assert verify_webhook_signature(body, expected, "test-secret") is True
    assert verify_webhook_signature(body + b"\n", expected, "test-secret") is False
    assert verify_webhook_signature(body, "v1=invalid", "test-secret") is False


@pytest.mark.parametrize(
    ("body", "secret"),
    [
        (cast(bytes, "not-bytes"), "secret"),
        (b"payload", ""),
        (b"payload", " "),
        (b"payload", "s" * 8_193),
    ],
)
def test_signature_rejects_invalid_input_without_echo(
    body: bytes,
    secret: str,
) -> None:
    with pytest.raises(NotificationConfigurationError) as error:
        sign_webhook_payload(body, secret)

    if secret:
        assert repr(secret) not in str(error.value)


def test_posts_exact_payload_headers_and_signature() -> None:
    signing_secret = "synthetic-signing-secret"
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        body = request.content
        assert request.method == "POST"
        assert str(request.url) == WEBHOOK_URL
        assert request.headers["Content-Type"] == WEBHOOK_CONTENT_TYPE
        assert request.headers[WEBHOOK_EVENT_HEADER] == str(EVENT_ID)
        assert request.headers[WEBHOOK_SCHEMA_HEADER] == "1.0"
        assert request.headers[WEBHOOK_SIGNATURE_HEADER] == sign_webhook_payload(
            body,
            signing_secret,
        )
        assert body == serialize_webhook_event(event())
        return httpx.Response(204)

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(signing_secret=signing_secret),
    )

    assert len(requests) == 1
    assert result.status is NotificationDeliveryStatus.DELIVERED
    assert signing_secret not in str(result.model_dump(mode="json"))


def test_omits_signature_header_when_secret_is_not_configured() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert WEBHOOK_SIGNATURE_HEADER not in request.headers
        return httpx.Response(200)

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert result.delivered is True


def test_missing_or_invalid_configuration_makes_no_request_and_leaks_no_url() -> None:
    requests: list[httpx.Request] = []
    private_url = "https://127.0.0.1/private?token=sensitive"
    selected_sender = sender(
        httpx.MockTransport(
            lambda request: requests.append(request) or httpx.Response(204)
        )
    )

    missing = selected_sender.deliver(
        event(),
        secrets=EnvironmentSecretProvider({}),
    )
    invalid = selected_sender.deliver(
        event(),
        secrets=secrets(url=private_url),
    )

    assert requests == []
    assert missing.status is NotificationDeliveryStatus.CONFIGURATION_ERROR
    assert invalid.status is NotificationDeliveryStatus.CONFIGURATION_ERROR
    assert private_url not in str(invalid.model_dump(mode="json"))


def test_redirect_is_rejected_and_never_followed() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(307, headers={"Location": "https://other.example/hook"})

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert len(requests) == 1
    assert result.status is NotificationDeliveryStatus.PROVIDER_REJECTED


def test_retry_clears_provider_cookie_before_next_attempt() -> None:
    requests: list[httpx.Request] = []
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert "Cookie" not in request.headers
        if len(requests) == 1:
            return httpx.Response(
                503,
                headers={"Set-Cookie": "provider-session=private; Secure"},
            )
        return httpx.Response(204)

    result = sender(httpx.MockTransport(handler), delays=delays).deliver(
        event(),
        secrets=secrets(),
    )

    assert len(requests) == 2
    assert delays == [0.25]
    assert result.delivered is True


def test_rate_limit_retry_after_is_bounded_by_policy() -> None:
    requests = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(429, headers={"Retry-After": "60"})
        return httpx.Response(204)

    result = sender(
        httpx.MockTransport(handler),
        delays=delays,
        retry_policy=NotificationRetryPolicy(max_retry_after_seconds=3),
    ).deliver(event(), secrets=secrets())

    assert result.delivered is True
    assert requests == 2
    assert delays == [3]


@pytest.mark.parametrize(
    ("first_status", "expected_requests"),
    [(400, 1), (401, 1), (500, 2), (502, 2), (503, 2), (504, 2), (501, 1)],
)
def test_response_status_retry_classification(
    first_status: int,
    expected_requests: int,
) -> None:
    requests = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(first_status if requests == 1 else 204)

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert requests == expected_requests
    assert result.status is (
        NotificationDeliveryStatus.DELIVERED
        if expected_requests == 2
        else NotificationDeliveryStatus.PROVIDER_REJECTED
    )


@pytest.mark.parametrize(
    ("error_type", "expected_status", "expected_diagnostic"),
    [
        (
            httpx.ReadTimeout,
            NotificationDeliveryStatus.TIMEOUT,
            NotificationDiagnosticCode.REQUEST_TIMED_OUT,
        ),
        (
            httpx.ConnectError,
            NotificationDeliveryStatus.CONNECTION_ERROR,
            NotificationDiagnosticCode.CONNECTION_FAILED,
        ),
    ],
)
def test_transport_errors_are_bounded_and_sanitized(
    error_type: type[httpx.TransportError],
    expected_status: NotificationDeliveryStatus,
    expected_diagnostic: NotificationDiagnosticCode,
) -> None:
    private_value = "private transport diagnostic"

    def handler(request: httpx.Request) -> httpx.Response:
        raise error_type(private_value, request=request)

    result = sender(
        httpx.MockTransport(handler),
        retry_policy=NotificationRetryPolicy(max_attempts=1),
    ).deliver(event(), secrets=secrets())

    assert result.status is expected_status
    assert result.attempts[0].diagnostic is expected_diagnostic
    assert private_value not in str(result.model_dump(mode="json"))


def test_unexpected_transport_error_is_sanitized() -> None:
    private_value = "private unexpected response"

    def handler(_: httpx.Request) -> httpx.Response:
        raise RuntimeError(private_value)

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert result.status is NotificationDeliveryStatus.ERROR
    assert private_value not in str(result.model_dump(mode="json"))


class UnreadableResponseStream(httpx.SyncByteStream):
    def __iter__(self):  # type: ignore[no-untyped-def]
        raise AssertionError("webhook response body must not be read")

    def close(self) -> None:
        return None


def test_response_body_is_not_read_or_retained() -> None:
    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(204, stream=UnreadableResponseStream())

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert result.delivered is True


def test_provider_response_body_is_not_retained_on_rejection() -> None:
    private_value = "private provider response body with token"
    result = sender(
        httpx.MockTransport(
            lambda _: httpx.Response(400, content=private_value.encode())
        )
    ).deliver(event(), secrets=secrets())

    assert result.status is NotificationDeliveryStatus.PROVIDER_REJECTED
    assert private_value not in str(result.model_dump(mode="json"))


def test_constructor_revalidates_timeout_retry_transport_and_sleep() -> None:
    invalid_timeouts = NotificationTimeouts().model_copy(
        update={"connect_seconds": 100}
    )
    invalid_retry = NotificationRetryPolicy().model_copy(update={"max_attempts": 100})

    with pytest.raises(NotificationConfigurationError, match="timeout"):
        WebhookNotificationSender(timeouts=invalid_timeouts)
    with pytest.raises(NotificationConfigurationError, match="retry"):
        WebhookNotificationSender(retry_policy=invalid_retry)
    with pytest.raises(NotificationConfigurationError, match="transport"):
        WebhookNotificationSender(transport=cast(httpx.BaseTransport, object()))
    with pytest.raises(NotificationConfigurationError, match="backoff"):
        WebhookNotificationSender(sleep=cast(object, None))
