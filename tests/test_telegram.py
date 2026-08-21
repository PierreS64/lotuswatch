import json
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import httpx
import pytest

import lotuswatch.notifications.telegram
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
    MAX_TELEGRAM_MESSAGE_LENGTH,
    TELEGRAM_API_ORIGIN,
    TELEGRAM_BOT_TOKEN_ENVIRONMENT_VARIABLE,
    TELEGRAM_CHAT_ID_ENVIRONMENT_VARIABLE,
    EnvironmentSecretProvider,
    NotificationSender,
    TelegramNotificationSender,
    render_telegram_message,
    validate_telegram_bot_token,
    validate_telegram_chat_id,
)

TARGET = "https://example.com/"
EVENT_ID = UUID("10000000-0000-4000-8000-000000000001")


def bot_token() -> str:
    return "123456789:" + ("A" * 35)


def chat_id() -> str:
    return "-100" + "1234567890"


def event(
    *,
    target: str = TARGET,
    title: str = "Synthetic finding",
    observation_count: int = 1,
) -> NotificationEvent:
    timestamp = datetime(2026, 8, 21, 10, 0, tzinfo=UTC)
    observations = []
    for index in range(observation_count):
        finding_id = f"LW-TEST-{index:03d}"
        observations.append(
            NotificationObservation(
                fingerprint=finding_id_fingerprint(target, finding_id),
                status=NotificationChangeStatus.ADDED,
                finding_id=finding_id,
                severity=Severity.HIGH,
                title=title,
            )
        )
    return NotificationEvent(
        event_id=EVENT_ID,
        generated_at=timestamp,
        profile_name="production",
        normalized_target=target,
        run_id=UUID("20000000-0000-4000-8000-000000000001"),
        scanned_at=timestamp,
        compared_at=timestamp,
        threshold=Severity.MEDIUM,
        comparison_summary=ComparisonSummary(
            added=observation_count,
            resolved=2,
            changed=3,
            unchanged=4,
        ),
        total_triggering_observations=observation_count,
        truncated=False,
        observations=observations,
    )


def secrets(
    *,
    token: str | None = None,
    selected_chat_id: str | None = None,
) -> EnvironmentSecretProvider:
    return EnvironmentSecretProvider(
        {
            TELEGRAM_BOT_TOKEN_ENVIRONMENT_VARIABLE: (
                bot_token() if token is None else token
            ),
            TELEGRAM_CHAT_ID_ENVIRONMENT_VARIABLE: (
                chat_id() if selected_chat_id is None else selected_chat_id
            ),
        }
    )


def sender(
    transport: httpx.BaseTransport,
    *,
    delays: list[float] | None = None,
    retry_policy: NotificationRetryPolicy | None = None,
) -> TelegramNotificationSender:
    selected_delays = [] if delays is None else delays
    return TelegramNotificationSender(
        transport=transport,
        retry_policy=retry_policy,
        sleep=selected_delays.append,
    )


def telegram_response(
    status_code: int = 200,
    *,
    body: object | None = None,
) -> httpx.Response:
    selected_body = {"ok": True, "result": {"message_id": 42}} if body is None else body
    return httpx.Response(status_code, json=selected_body)


def test_sender_implements_telegram_channel_contract() -> None:
    selected = sender(httpx.MockTransport(lambda _: telegram_response()))

    assert isinstance(selected, NotificationSender)
    assert selected.channel is NotificationChannel.TELEGRAM


@pytest.mark.parametrize(
    "value",
    [
        "12345:" + ("A" * 20),
        "123456789:" + ("abc_DEF-123" * 3),
        "12345678901234567890:" + ("z" * 128),
    ],
)
def test_accepts_conservative_bot_token_shapes(value: str) -> None:
    assert validate_telegram_bot_token(value) == value


@pytest.mark.parametrize(
    "value",
    [
        "",
        " 12345:" + ("A" * 20),
        "012345:" + ("A" * 20),
        "1234:" + ("A" * 20),
        "12345:short",
        "12345:" + ("A" * 19) + "!",
        "1" * 161,
    ],
)
def test_rejects_invalid_bot_tokens_without_echo(value: str) -> None:
    with pytest.raises(NotificationConfigurationError) as error:
        validate_telegram_bot_token(value)

    if value:
        assert value not in str(error.value)


@pytest.mark.parametrize(
    "value",
    ["123456", "-1001234567890", "@lotuswatch_demo"],
)
def test_accepts_numeric_and_channel_username_chat_ids(value: str) -> None:
    assert validate_telegram_chat_id(value) == value


@pytest.mark.parametrize(
    "value",
    ["", "0", "-0", "+123", " 123", "@four", "@bad-name", "1" * 65],
)
def test_rejects_invalid_chat_ids_without_echo(value: str) -> None:
    with pytest.raises(NotificationConfigurationError) as error:
        validate_telegram_chat_id(value)

    if value:
        assert value not in str(error.value)


def test_message_contains_required_summary_as_plain_text() -> None:
    selected = event(title="[click](https://invalid.example) <b>alert</b>\nnext")

    message = render_telegram_message(selected)

    assert message.startswith("LotusWatch security notification\n")
    assert "Profile: production" in message
    assert f"Target: {TARGET}" in message
    assert "Scanned: 2026-08-21T10:00:00Z" in message
    assert "Threshold: medium" in message
    assert "Changes: added=1, resolved=2, changed=3, unchanged=4" in message
    assert "Triggering findings: 1" in message
    assert "[click](https://invalid.example) <b>alert</b> next" in message
    assert len(message) <= MAX_TELEGRAM_MESSAGE_LENGTH


def test_message_is_deterministic_and_does_not_mutate_event() -> None:
    selected = event()
    snapshot = selected.model_dump(mode="python")

    assert render_telegram_message(selected) == render_telegram_message(
        selected.model_copy(deep=True)
    )
    assert selected.model_dump(mode="python") == snapshot


def test_long_message_preserves_summary_and_reports_omissions() -> None:
    selected = event(
        target=f"https://example.com/{'x' * 3_000}",
        title="T" * 120,
        observation_count=50,
    )

    message = render_telegram_message(selected)
    finding_lines = [line for line in message.splitlines() if line.startswith("- [")]

    assert len(message) <= MAX_TELEGRAM_MESSAGE_LENGTH
    assert "Target: https://example.com/" in message
    assert "..." in message.splitlines()[2]
    assert "Changes: added=50, resolved=2, changed=3, unchanged=4" in message
    assert 0 < len(finding_lines) < 50
    assert (
        f"... {50 - len(finding_lines)} additional triggering observations omitted."
        in message
    )


def test_existing_policy_truncation_is_included_in_omitted_total() -> None:
    selected = event(observation_count=2).model_copy(
        update={"total_triggering_observations": 5, "truncated": True}
    )

    message = render_telegram_message(selected)

    assert "... 3 additional triggering observations omitted." in message


def test_posts_only_expected_plain_text_json_to_fixed_method() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        decoded = json.loads(request.content)
        assert request.method == "POST"
        assert str(request.url) == (
            f"{TELEGRAM_API_ORIGIN}/bot{bot_token()}/sendMessage"
        )
        assert request.headers["Content-Type"] == "application/json"
        assert decoded == {
            "chat_id": chat_id(),
            "text": render_telegram_message(event()),
        }
        assert "parse_mode" not in decoded
        assert "entities" not in decoded
        return telegram_response()

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert len(requests) == 1
    assert result.delivered is True


def test_missing_or_invalid_configuration_makes_no_request_and_leaks_nothing() -> None:
    requests: list[httpx.Request] = []
    private_token = "123456789:" + ("P" * 35)
    private_chat_id = "-100" + "9988776655"
    selected_sender = sender(
        httpx.MockTransport(
            lambda request: requests.append(request) or telegram_response()
        )
    )

    missing = selected_sender.deliver(
        event(),
        secrets=EnvironmentSecretProvider({}),
    )
    invalid = selected_sender.deliver(
        event(),
        secrets=secrets(token=f"{private_token}!", selected_chat_id=private_chat_id),
    )

    assert requests == []
    assert missing.status is NotificationDeliveryStatus.CONFIGURATION_ERROR
    assert invalid.status is NotificationDeliveryStatus.CONFIGURATION_ERROR
    serialized = str(invalid.model_dump(mode="json"))
    assert private_token not in serialized
    assert private_chat_id not in serialized
    assert TELEGRAM_API_ORIGIN not in serialized


def test_redirect_is_rejected_and_never_followed() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            307,
            headers={"Location": "https://other.example/private"},
            json={"ok": False},
        )

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert len(requests) == 1
    assert result.status is NotificationDeliveryStatus.PROVIDER_REJECTED


@pytest.mark.parametrize("status_code", [400, 401, 403, 404])
def test_permanent_http_rejection_is_not_retried(status_code: int) -> None:
    requests = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return telegram_response(
            status_code,
            body={"ok": False, "error_code": status_code, "description": "private"},
        )

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert requests == 1
    assert result.status is NotificationDeliveryStatus.PROVIDER_REJECTED


@pytest.mark.parametrize("status_code", [500, 502, 503, 504])
def test_selected_server_failures_are_retried(status_code: int) -> None:
    requests = 0

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return telegram_response(status_code, body={"ok": False})
        return telegram_response()

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert requests == 2
    assert result.delivered is True


def test_rate_limit_retry_after_is_read_from_bounded_response_and_capped() -> None:
    requests = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return telegram_response(
                429,
                body={
                    "ok": False,
                    "error_code": 429,
                    "parameters": {"retry_after": 60},
                },
            )
        return telegram_response()

    result = sender(
        httpx.MockTransport(handler),
        delays=delays,
        retry_policy=NotificationRetryPolicy(max_retry_after_seconds=3),
    ).deliver(event(), secrets=secrets())

    assert result.delivered is True
    assert requests == 2
    assert delays == [3]


@pytest.mark.parametrize("retry_after", [-1, True, "10", 61, None])
def test_invalid_retry_after_uses_shared_backoff(retry_after: object) -> None:
    requests = 0
    delays: list[float] = []

    def handler(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return telegram_response(
                429,
                body={
                    "ok": False,
                    "error_code": 429,
                    "parameters": {"retry_after": retry_after},
                },
            )
        return telegram_response()

    result = sender(httpx.MockTransport(handler), delays=delays).deliver(
        event(),
        secrets=secrets(),
    )

    assert result.delivered is True
    assert delays == [0.25]


@pytest.mark.parametrize(
    "body",
    [
        b"",
        b"not-json",
        b'{"ok":true}',
        b'{"ok":true,"result":{}}',
        b'{"ok":true,"result":{"message_id":true}}',
        b'{"ok":true,"ok":false,"result":{"message_id":1}}',
        b'{"ok":NaN,"result":{"message_id":1}}',
    ],
)
def test_success_status_requires_unambiguous_structured_response(body: bytes) -> None:
    result = sender(
        httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                content=body,
                headers={"Content-Type": "application/json"},
            )
        )
    ).deliver(event(), secrets=secrets())

    assert result.status is NotificationDeliveryStatus.PROVIDER_REJECTED


def test_oversized_response_is_rejected_without_retaining_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_value = "private Telegram response"
    monkeypatch.setattr(
        lotuswatch.notifications.telegram,
        "MAX_TELEGRAM_RESPONSE_BYTES",
        8,
    )

    result = sender(
        httpx.MockTransport(
            lambda _: httpx.Response(200, content=private_value.encode())
        )
    ).deliver(event(), secrets=secrets())

    assert result.status is NotificationDeliveryStatus.PROVIDER_REJECTED
    assert private_value not in str(result.model_dump(mode="json"))


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


class TimeoutResponseStream(httpx.SyncByteStream):
    def __init__(self, request: httpx.Request) -> None:
        self.request = request

    def __iter__(self):  # type: ignore[no-untyped-def]
        raise httpx.ReadTimeout("private body timeout", request=self.request)

    def close(self) -> None:
        return None


def test_timeout_while_reading_response_body_is_retried() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        if requests == 1:
            return httpx.Response(200, stream=TimeoutResponseStream(request))
        return telegram_response()

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert requests == 2
    assert result.delivered is True


def test_retry_clears_provider_cookie_before_next_attempt() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        assert "Cookie" not in request.headers
        if requests == 1:
            return httpx.Response(
                503,
                headers={"Set-Cookie": "telegram-session=private; Secure"},
                json={"ok": False},
            )
        return telegram_response()

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )

    assert requests == 2
    assert result.delivered is True


def test_unexpected_error_does_not_leak_token_chat_url_or_body() -> None:
    private_value = "private provider response with credentials"

    def handler(_: httpx.Request) -> httpx.Response:
        raise RuntimeError(private_value)

    result = sender(httpx.MockTransport(handler)).deliver(
        event(),
        secrets=secrets(),
    )
    serialized = str(result.model_dump(mode="json"))

    assert result.status is NotificationDeliveryStatus.ERROR
    assert bot_token() not in serialized
    assert chat_id() not in serialized
    assert TELEGRAM_API_ORIGIN not in serialized
    assert private_value not in serialized


def test_constructor_revalidates_timeout_retry_transport_and_sleep() -> None:
    invalid_timeouts = NotificationTimeouts().model_copy(
        update={"connect_seconds": 100}
    )
    invalid_retry = NotificationRetryPolicy().model_copy(update={"max_attempts": 100})

    with pytest.raises(NotificationConfigurationError, match="timeout"):
        TelegramNotificationSender(timeouts=invalid_timeouts)
    with pytest.raises(NotificationConfigurationError, match="retry"):
        TelegramNotificationSender(retry_policy=invalid_retry)
    with pytest.raises(NotificationConfigurationError, match="transport"):
        TelegramNotificationSender(transport=cast(httpx.BaseTransport, object()))
    with pytest.raises(NotificationConfigurationError, match="backoff"):
        TelegramNotificationSender(sleep=cast(object, None))
