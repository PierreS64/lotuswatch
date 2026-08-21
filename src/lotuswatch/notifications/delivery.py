import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from typing import Protocol, runtime_checkable

from pydantic import ValidationError

from lotuswatch.exceptions import (
    NotificationConfigurationError,
    NotificationDeliveryError,
    NotificationSecretError,
)
from lotuswatch.models import (
    MAX_NOTIFICATION_CHANNELS,
    NotificationAttemptOutcome,
    NotificationChannel,
    NotificationDeliveryAttempt,
    NotificationDeliveryBatch,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
    NotificationDiagnosticCode,
    NotificationEvent,
    NotificationRetryPolicy,
)

MAX_NOTIFICATION_SECRET_LENGTH = 8_192
ENVIRONMENT_VARIABLE_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]{0,127}$")

AttemptOperation = Callable[[int], NotificationAttemptOutcome]
SleepFunction = Callable[[float], None]


@runtime_checkable
class SecretProvider(Protocol):
    """Resolve one explicitly named notification secret."""

    def get_secret(
        self,
        name: str,
        *,
        required: bool = True,
        max_length: int = MAX_NOTIFICATION_SECRET_LENGTH,
    ) -> str | None:
        """Return one bounded secret without exposing unrelated values."""


class EnvironmentSecretProvider:
    """Resolve explicitly requested secrets from a supplied environment mapping."""

    def __init__(self, environment: Mapping[str, str] | None = None) -> None:
        self._environment = os.environ if environment is None else environment

    def get_secret(
        self,
        name: str,
        *,
        required: bool = True,
        max_length: int = MAX_NOTIFICATION_SECRET_LENGTH,
    ) -> str | None:
        if (
            not isinstance(name, str)
            or ENVIRONMENT_VARIABLE_PATTERN.fullmatch(name) is None
        ):
            raise NotificationSecretError(
                "Notification environment variable name is invalid."
            )
        if not isinstance(required, bool):
            raise NotificationSecretError(
                f"Notification environment variable {name} has invalid requirements."
            )
        if (
            isinstance(max_length, bool)
            or not isinstance(max_length, int)
            or not 1 <= max_length <= MAX_NOTIFICATION_SECRET_LENGTH
        ):
            raise NotificationSecretError(
                f"Notification environment variable {name} has an invalid size limit."
            )

        value = self._environment.get(name)
        if value is None:
            if required:
                raise NotificationSecretError(
                    f"Required notification environment variable {name} is not set."
                )
            return None
        if not isinstance(value, str) or not value.strip():
            raise NotificationSecretError(
                f"Notification environment variable {name} is empty or invalid."
            )
        if len(value) > max_length:
            raise NotificationSecretError(
                f"Notification environment variable {name} exceeds its size limit."
            )
        return value


@runtime_checkable
class NotificationSender(Protocol):
    """Provider-neutral sender used by aggregate notification orchestration."""

    @property
    def channel(self) -> NotificationChannel:
        """Return the channel implemented by this sender."""

    def deliver(
        self,
        event: NotificationEvent,
        *,
        secrets: SecretProvider,
    ) -> NotificationDeliveryResult:
        """Deliver one event and return a controlled channel result."""


def execute_notification_attempts(
    channel: NotificationChannel,
    event: NotificationEvent,
    operation: AttemptOperation,
    *,
    retry_policy: NotificationRetryPolicy | None = None,
    sleep: SleepFunction = time.sleep,
) -> NotificationDeliveryResult:
    """Execute one provider operation with bounded retry and sanitized failures."""

    channel = _validated_channel(channel)
    event = _validated_event(event)
    if not callable(operation):
        raise NotificationDeliveryError("Notification attempt operation is invalid.")
    if not callable(sleep):
        raise NotificationDeliveryError("Notification backoff function is invalid.")
    policy = _validated_retry_policy(
        NotificationRetryPolicy() if retry_policy is None else retry_policy
    )
    attempts: list[NotificationDeliveryAttempt] = []

    for attempt_number in range(1, policy.max_attempts + 1):
        try:
            outcome = operation(attempt_number)
            if not isinstance(outcome, NotificationAttemptOutcome):
                raise TypeError("invalid notification outcome")
            outcome = NotificationAttemptOutcome.model_validate(
                outcome.model_dump(mode="python")
            )
        except NotificationConfigurationError:
            outcome = NotificationAttemptOutcome(
                status=NotificationDeliveryStatus.CONFIGURATION_ERROR,
                diagnostic=NotificationDiagnosticCode.CONFIGURATION_INVALID,
            )
        except Exception:  # noqa: BLE001 - sanitize provider callback failures.
            outcome = NotificationAttemptOutcome(
                status=NotificationDeliveryStatus.ERROR,
                diagnostic=NotificationDiagnosticCode.UNEXPECTED_FAILURE,
            )

        will_retry = outcome.retryable and attempt_number < policy.max_attempts
        delay = _retry_delay(policy, attempt_number, outcome) if will_retry else None
        attempts.append(
            NotificationDeliveryAttempt(
                attempt_number=attempt_number,
                status=outcome.status,
                retryable=will_retry,
                delay_before_next_seconds=delay,
                diagnostic=outcome.diagnostic,
            )
        )

        if not will_retry:
            break

        assert delay is not None
        try:
            sleep(delay)
        except Exception:  # noqa: BLE001 - sanitize injected backoff failures.
            attempts[-1] = NotificationDeliveryAttempt(
                attempt_number=attempt_number,
                status=NotificationDeliveryStatus.ERROR,
                diagnostic=NotificationDiagnosticCode.BACKOFF_FAILED,
            )
            break

    return NotificationDeliveryResult(
        event_id=event.event_id,
        channel=channel,
        status=attempts[-1].status,
        attempts=attempts,
    )


def deliver_notification_channels(
    event: NotificationEvent,
    senders: Sequence[NotificationSender],
    *,
    secrets: SecretProvider | None = None,
) -> NotificationDeliveryBatch:
    """Deliver one event through requested senders while isolating channel failures."""

    event = _validated_event(event)
    if not isinstance(senders, Sequence) or isinstance(senders, (str, bytes)):
        raise NotificationDeliveryError("Notification senders must be a sequence.")
    if not 1 <= len(senders) <= MAX_NOTIFICATION_CHANNELS:
        raise NotificationDeliveryError(
            f"Notification sender count must be between 1 and {MAX_NOTIFICATION_CHANNELS}."
        )
    secret_provider = EnvironmentSecretProvider() if secrets is None else secrets
    if not isinstance(secret_provider, SecretProvider):
        raise NotificationDeliveryError("Notification secret provider is invalid.")

    validated_senders: list[tuple[NotificationChannel, NotificationSender]] = []
    channels: set[NotificationChannel] = set()
    for sender in senders:
        if not isinstance(sender, NotificationSender):
            raise NotificationDeliveryError("Notification sender is invalid.")
        try:
            channel = _validated_channel(sender.channel)
        except Exception as exc:
            raise NotificationDeliveryError(
                "Notification sender channel is invalid."
            ) from exc
        if channel in channels:
            raise NotificationDeliveryError(
                "Notification senders contain a duplicate channel."
            )
        channels.add(channel)
        validated_senders.append((channel, sender))

    results: list[NotificationDeliveryResult] = []
    for channel, sender in validated_senders:
        try:
            result = sender.deliver(
                event.model_copy(deep=True),
                secrets=secret_provider,
            )
            result = _validated_sender_result(result, event, channel)
        except NotificationConfigurationError:
            result = _failure_result(
                event,
                channel,
                NotificationDeliveryStatus.CONFIGURATION_ERROR,
                NotificationDiagnosticCode.CONFIGURATION_INVALID,
            )
        except Exception:  # noqa: BLE001 - isolate and sanitize sender failures.
            result = _failure_result(
                event,
                channel,
                NotificationDeliveryStatus.ERROR,
                NotificationDiagnosticCode.UNEXPECTED_FAILURE,
            )
        results.append(result)

    return NotificationDeliveryBatch(event_id=event.event_id, results=results)


def _validated_channel(channel: NotificationChannel) -> NotificationChannel:
    if not isinstance(channel, NotificationChannel):
        raise NotificationDeliveryError("Notification channel is invalid.")
    return channel


def _validated_event(event: NotificationEvent) -> NotificationEvent:
    if not isinstance(event, NotificationEvent):
        raise NotificationDeliveryError("Notification event is invalid.")
    try:
        return NotificationEvent.model_validate(event.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationDeliveryError("Notification event is invalid.") from exc


def _validated_retry_policy(
    policy: NotificationRetryPolicy,
) -> NotificationRetryPolicy:
    if not isinstance(policy, NotificationRetryPolicy):
        raise NotificationDeliveryError("Notification retry policy is invalid.")
    try:
        return NotificationRetryPolicy.model_validate(policy.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationDeliveryError(
            "Notification retry policy is invalid."
        ) from exc


def _retry_delay(
    policy: NotificationRetryPolicy,
    attempt_number: int,
    outcome: NotificationAttemptOutcome,
) -> float:
    if outcome.retry_after_seconds is not None:
        return min(
            outcome.retry_after_seconds,
            policy.max_retry_after_seconds,
        )
    exponential = policy.initial_backoff_seconds * (
        policy.backoff_multiplier ** (attempt_number - 1)
    )
    return min(exponential, policy.max_backoff_seconds)


def _validated_sender_result(
    result: NotificationDeliveryResult,
    event: NotificationEvent,
    channel: NotificationChannel,
) -> NotificationDeliveryResult:
    if not isinstance(result, NotificationDeliveryResult):
        raise NotificationDeliveryError("Notification sender result is invalid.")
    try:
        result = NotificationDeliveryResult.model_validate(
            result.model_dump(mode="python")
        )
    except ValidationError as exc:
        raise NotificationDeliveryError(
            "Notification sender result is invalid."
        ) from exc
    if result.event_id != event.event_id or result.channel is not channel:
        raise NotificationDeliveryError(
            "Notification sender result identity is invalid."
        )
    return result


def _failure_result(
    event: NotificationEvent,
    channel: NotificationChannel,
    status: NotificationDeliveryStatus,
    diagnostic: NotificationDiagnosticCode,
) -> NotificationDeliveryResult:
    return NotificationDeliveryResult(
        event_id=event.event_id,
        channel=channel,
        status=status,
        attempts=[
            NotificationDeliveryAttempt(
                attempt_number=1,
                status=status,
                diagnostic=diagnostic,
            )
        ],
    )


__all__ = [
    "ENVIRONMENT_VARIABLE_PATTERN",
    "MAX_NOTIFICATION_SECRET_LENGTH",
    "EnvironmentSecretProvider",
    "NotificationSender",
    "SecretProvider",
    "deliver_notification_channels",
    "execute_notification_attempts",
]
