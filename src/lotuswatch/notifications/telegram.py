import json
import re
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime

import httpx
from pydantic import ValidationError

from lotuswatch.exceptions import NotificationConfigurationError
from lotuswatch.models import (
    NotificationAttemptOutcome,
    NotificationChannel,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
    NotificationDiagnosticCode,
    NotificationEvent,
    NotificationRetryPolicy,
    NotificationTimeouts,
)
from lotuswatch.notifications.delivery import (
    SecretProvider,
    execute_notification_attempts,
)

TELEGRAM_BOT_TOKEN_ENVIRONMENT_VARIABLE = "LOTUSWATCH_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID_ENVIRONMENT_VARIABLE = "LOTUSWATCH_TELEGRAM_CHAT_ID"
TELEGRAM_API_ORIGIN = "https://api.telegram.org"
TELEGRAM_SEND_MESSAGE_METHOD = "sendMessage"
MAX_TELEGRAM_BOT_TOKEN_LENGTH = 160
MAX_TELEGRAM_CHAT_ID_LENGTH = 64
MAX_TELEGRAM_MESSAGE_LENGTH = 4_096
MAX_TELEGRAM_TARGET_DISPLAY_LENGTH = 2_048
MAX_TELEGRAM_REQUEST_BYTES = 32 * 1_024
MAX_TELEGRAM_RESPONSE_BYTES = 64 * 1_024

_BOT_TOKEN_PATTERN = re.compile(r"^[1-9][0-9]{4,19}:[A-Za-z0-9_-]{20,128}$")
_NUMERIC_CHAT_ID_PATTERN = re.compile(r"^-?[1-9][0-9]{0,19}$")
_USERNAME_CHAT_ID_PATTERN = re.compile(r"^@[A-Za-z][A-Za-z0-9_]{4,31}$")
_RETRYABLE_SERVER_STATUSES = {500, 502, 503, 504}
_WHITESPACE_PATTERN = re.compile(r"\s+")


@dataclass(frozen=True, slots=True)
class _TelegramConfiguration:
    request_url: str
    chat_id: str


class TelegramNotificationSender:
    """Deliver concise plain-text notification events through Telegram."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeouts: NotificationTimeouts | None = None,
        retry_policy: NotificationRetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if transport is not None and not isinstance(transport, httpx.BaseTransport):
            raise NotificationConfigurationError(
                "Telegram transport configuration is invalid."
            )
        if not callable(sleep):
            raise NotificationConfigurationError(
                "Telegram backoff configuration is invalid."
            )
        self._transport = transport
        self._timeouts = _validated_timeouts(
            NotificationTimeouts() if timeouts is None else timeouts
        )
        self._retry_policy = _validated_retry_policy(
            NotificationRetryPolicy() if retry_policy is None else retry_policy
        )
        self._sleep = sleep

    @property
    def channel(self) -> NotificationChannel:
        return NotificationChannel.TELEGRAM

    def deliver(
        self,
        event: NotificationEvent,
        *,
        secrets: SecretProvider,
    ) -> NotificationDeliveryResult:
        try:
            message = render_telegram_message(event)
            configuration = _load_configuration(secrets)
            body = _serialize_request(configuration.chat_id, message)
        except NotificationConfigurationError:
            return self._terminal_result(
                event,
                NotificationDeliveryStatus.CONFIGURATION_ERROR,
                NotificationDiagnosticCode.CONFIGURATION_INVALID,
            )

        try:
            client = httpx.Client(
                transport=self._transport,
                timeout=httpx.Timeout(
                    connect=self._timeouts.connect_seconds,
                    read=self._timeouts.read_seconds,
                    write=self._timeouts.write_seconds,
                    pool=self._timeouts.pool_seconds,
                ),
                follow_redirects=False,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
                trust_env=False,
            )
        except Exception:  # noqa: BLE001 - sanitize HTTP client construction failures.
            return self._terminal_result(
                event,
                NotificationDeliveryStatus.ERROR,
                NotificationDiagnosticCode.UNEXPECTED_FAILURE,
            )

        def operation(_: int) -> NotificationAttemptOutcome:
            client.cookies.clear()
            try:
                with client.stream(
                    "POST",
                    configuration.request_url,
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "User-Agent": "LotusWatch-Notification/1.0",
                    },
                ) as response:
                    return _response_outcome(response)
            except httpx.TimeoutException:
                return NotificationAttemptOutcome(
                    status=NotificationDeliveryStatus.TIMEOUT,
                    retryable=True,
                    diagnostic=NotificationDiagnosticCode.REQUEST_TIMED_OUT,
                )
            except httpx.TransportError:
                return NotificationAttemptOutcome(
                    status=NotificationDeliveryStatus.CONNECTION_ERROR,
                    retryable=True,
                    diagnostic=NotificationDiagnosticCode.CONNECTION_FAILED,
                )

        try:
            return execute_notification_attempts(
                self.channel,
                event,
                operation,
                retry_policy=self._retry_policy,
                sleep=self._sleep,
            )
        finally:
            with suppress(Exception):
                client.close()

    def _terminal_result(
        self,
        event: NotificationEvent,
        status: NotificationDeliveryStatus,
        diagnostic: NotificationDiagnosticCode,
    ) -> NotificationDeliveryResult:
        return execute_notification_attempts(
            self.channel,
            event,
            lambda _: NotificationAttemptOutcome(
                status=status,
                diagnostic=diagnostic,
            ),
            retry_policy=self._retry_policy,
            sleep=self._sleep,
        )


def render_telegram_message(event: NotificationEvent) -> str:
    """Render a deterministic bounded plain-text Telegram notification."""

    validated = _validated_event(event)
    summary = validated.comparison_summary
    target = _bounded_plain_text(
        validated.normalized_target,
        MAX_TELEGRAM_TARGET_DISPLAY_LENGTH,
    )
    base_lines = [
        "LotusWatch security notification",
        f"Profile: {_plain_text(validated.profile_name)}",
        f"Target: {target}",
        f"Scanned: {_utc_text(validated.scanned_at)}",
        f"Threshold: {validated.threshold.value}",
        (
            "Changes: "
            f"added={summary.added}, resolved={summary.resolved}, "
            f"changed={summary.changed}, unchanged={summary.unchanged}"
        ),
        f"Triggering findings: {validated.total_triggering_observations}",
        f"Event ID: {validated.event_id}",
    ]
    observation_lines = [
        (
            f"- [{observation.status.value.upper()}] "
            f"{observation.severity.value.upper()} {observation.finding_id}: "
            f"{_plain_text(observation.title)}"
        )
        for observation in validated.observations
    ]

    for included_count in range(len(observation_lines), -1, -1):
        omitted_count = validated.total_triggering_observations - included_count
        lines = [*base_lines, "", *observation_lines[:included_count]]
        if omitted_count:
            lines.append(
                f"... {omitted_count} additional triggering observations omitted."
            )
        message = "\n".join(lines)
        if len(message) <= MAX_TELEGRAM_MESSAGE_LENGTH:
            return message

    raise NotificationConfigurationError("Telegram message exceeds its size limit.")


def validate_telegram_bot_token(value: str) -> str:
    """Validate a Telegram bot token without exposing it in diagnostics."""

    if (
        not isinstance(value, str)
        or len(value) > MAX_TELEGRAM_BOT_TOKEN_LENGTH
        or _BOT_TOKEN_PATTERN.fullmatch(value) is None
    ):
        raise NotificationConfigurationError("Telegram bot token is invalid.")
    return value


def validate_telegram_chat_id(value: str) -> str:
    """Validate a numeric chat identifier or public channel username."""

    if (
        not isinstance(value, str)
        or len(value) > MAX_TELEGRAM_CHAT_ID_LENGTH
        or (
            _NUMERIC_CHAT_ID_PATTERN.fullmatch(value) is None
            and _USERNAME_CHAT_ID_PATTERN.fullmatch(value) is None
        )
    ):
        raise NotificationConfigurationError("Telegram chat identifier is invalid.")
    return value


def _load_configuration(secrets: SecretProvider) -> _TelegramConfiguration:
    if not isinstance(secrets, SecretProvider):
        raise NotificationConfigurationError("Telegram secret provider is invalid.")
    try:
        bot_token = secrets.get_secret(
            TELEGRAM_BOT_TOKEN_ENVIRONMENT_VARIABLE,
            max_length=MAX_TELEGRAM_BOT_TOKEN_LENGTH,
        )
        chat_id = secrets.get_secret(
            TELEGRAM_CHAT_ID_ENVIRONMENT_VARIABLE,
            max_length=MAX_TELEGRAM_CHAT_ID_LENGTH,
        )
    except Exception as exc:
        raise NotificationConfigurationError(
            "Telegram environment configuration is invalid."
        ) from exc
    assert bot_token is not None
    assert chat_id is not None
    bot_token = validate_telegram_bot_token(bot_token)
    chat_id = validate_telegram_chat_id(chat_id)
    return _TelegramConfiguration(
        request_url=(
            f"{TELEGRAM_API_ORIGIN}/bot{bot_token}/{TELEGRAM_SEND_MESSAGE_METHOD}"
        ),
        chat_id=chat_id,
    )


def _serialize_request(chat_id: str, message: str) -> bytes:
    body = json.dumps(
        {"chat_id": chat_id, "text": message},
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(body) > MAX_TELEGRAM_REQUEST_BYTES:
        raise NotificationConfigurationError("Telegram request exceeds its size limit.")
    return body


def _response_outcome(response: httpx.Response) -> NotificationAttemptOutcome:
    status = response.status_code
    if status in _RETRYABLE_SERVER_STATUSES:
        return _provider_rejection(retryable=True)

    response_data = _bounded_json_response(response)
    if status == 429:
        return _provider_rejection(
            retryable=True,
            retry_after_seconds=_response_retry_after(response_data),
        )
    if not 200 <= status < 300:
        return _provider_rejection()
    if not isinstance(response_data, dict):
        return _provider_rejection()
    result = response_data.get("result")
    if response_data.get("ok") is True and isinstance(result, dict):
        message_id = result.get("message_id")
        if (
            not isinstance(message_id, bool)
            and isinstance(message_id, int)
            and message_id >= 0
        ):
            return NotificationAttemptOutcome(
                status=NotificationDeliveryStatus.DELIVERED
            )
    if response_data.get("ok") is not False:
        return _provider_rejection()

    error_code = response_data.get("error_code")
    if error_code == 429:
        return _provider_rejection(
            retryable=True,
            retry_after_seconds=_response_retry_after(response_data),
        )
    if error_code in _RETRYABLE_SERVER_STATUSES:
        return _provider_rejection(retryable=True)
    return _provider_rejection()


def _bounded_json_response(response: httpx.Response) -> object | None:
    chunks: list[bytes] = []
    total = 0
    try:
        for chunk in response.iter_bytes():
            total += len(chunk)
            if total > MAX_TELEGRAM_RESPONSE_BYTES:
                return None
            chunks.append(chunk)
        raw = b"".join(chunks)
        if not raw:
            return None
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonstandard_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate Telegram response key")
        result[key] = value
    return result


def _reject_nonstandard_json_constant(value: str) -> None:
    raise ValueError(f"non-standard Telegram JSON constant: {value}")


def _response_retry_after(response_data: object | None) -> float | None:
    if not isinstance(response_data, dict):
        return None
    parameters = response_data.get("parameters")
    if not isinstance(parameters, dict):
        return None
    retry_after = parameters.get("retry_after")
    if (
        isinstance(retry_after, bool)
        or not isinstance(retry_after, (int, float))
        or retry_after < 0
        or retry_after > 60
    ):
        return None
    return float(retry_after)


def _provider_rejection(
    *,
    retryable: bool = False,
    retry_after_seconds: float | None = None,
) -> NotificationAttemptOutcome:
    return NotificationAttemptOutcome(
        status=NotificationDeliveryStatus.PROVIDER_REJECTED,
        retryable=retryable,
        retry_after_seconds=retry_after_seconds,
        diagnostic=NotificationDiagnosticCode.PROVIDER_REJECTED,
    )


def _validated_event(event: NotificationEvent) -> NotificationEvent:
    if not isinstance(event, NotificationEvent):
        raise NotificationConfigurationError("Telegram event is invalid.")
    try:
        return NotificationEvent.model_validate(event.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationConfigurationError("Telegram event is invalid.") from exc


def _plain_text(value: str) -> str:
    return _WHITESPACE_PATTERN.sub(" ", value).strip()


def _bounded_plain_text(value: str, limit: int) -> str:
    normalized = _plain_text(value)
    if len(normalized) <= limit:
        return normalized
    return f"{normalized[: limit - 3]}..."


def _utc_text(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _validated_timeouts(timeouts: NotificationTimeouts) -> NotificationTimeouts:
    if not isinstance(timeouts, NotificationTimeouts):
        raise NotificationConfigurationError(
            "Telegram timeout configuration is invalid."
        )
    try:
        return NotificationTimeouts.model_validate(timeouts.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationConfigurationError(
            "Telegram timeout configuration is invalid."
        ) from exc


def _validated_retry_policy(
    policy: NotificationRetryPolicy,
) -> NotificationRetryPolicy:
    if not isinstance(policy, NotificationRetryPolicy):
        raise NotificationConfigurationError("Telegram retry configuration is invalid.")
    try:
        return NotificationRetryPolicy.model_validate(policy.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationConfigurationError(
            "Telegram retry configuration is invalid."
        ) from exc


__all__ = [
    "MAX_TELEGRAM_BOT_TOKEN_LENGTH",
    "MAX_TELEGRAM_CHAT_ID_LENGTH",
    "MAX_TELEGRAM_MESSAGE_LENGTH",
    "MAX_TELEGRAM_REQUEST_BYTES",
    "MAX_TELEGRAM_RESPONSE_BYTES",
    "MAX_TELEGRAM_TARGET_DISPLAY_LENGTH",
    "TELEGRAM_API_ORIGIN",
    "TELEGRAM_BOT_TOKEN_ENVIRONMENT_VARIABLE",
    "TELEGRAM_CHAT_ID_ENVIRONMENT_VARIABLE",
    "TELEGRAM_SEND_MESSAGE_METHOD",
    "TelegramNotificationSender",
    "render_telegram_message",
    "validate_telegram_bot_token",
    "validate_telegram_chat_id",
]
