from enum import StrEnum
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

MAX_NOTIFICATION_ATTEMPTS = 5
MAX_NOTIFICATION_CHANNELS = 8
MAX_NOTIFICATION_RETRY_DELAY_SECONDS = 60.0


class NotificationChannel(StrEnum):
    """Notification providers supported by the delivery contract."""

    WEBHOOK = "webhook"
    TELEGRAM = "telegram"


class NotificationDeliveryStatus(StrEnum):
    """Controlled outcomes from one notification channel."""

    DELIVERED = "delivered"
    SKIPPED = "skipped"
    CONFIGURATION_ERROR = "configuration_error"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    PROVIDER_REJECTED = "provider_rejected"
    ERROR = "error"


class NotificationDiagnosticCode(StrEnum):
    """Fixed diagnostics that cannot retain provider-controlled content."""

    CONFIGURATION_INVALID = "configuration_invalid"
    REQUEST_TIMED_OUT = "request_timed_out"
    CONNECTION_FAILED = "connection_failed"
    PROVIDER_REJECTED = "provider_rejected"
    UNEXPECTED_FAILURE = "unexpected_failure"
    BACKOFF_FAILED = "backoff_failed"


_RETRYABLE_STATUSES = {
    NotificationDeliveryStatus.TIMEOUT,
    NotificationDeliveryStatus.CONNECTION_ERROR,
    NotificationDeliveryStatus.PROVIDER_REJECTED,
}


class NotificationTimeouts(BaseModel):
    """Bounded timeout values available to notification providers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    connect_seconds: float = Field(default=3.0, ge=0.1, le=30.0)
    read_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    write_seconds: float = Field(default=5.0, ge=0.1, le=30.0)
    pool_seconds: float = Field(default=3.0, ge=0.1, le=30.0)


class NotificationRetryPolicy(BaseModel):
    """Bounded retry and backoff settings shared by notification providers."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    max_attempts: int = Field(default=3, ge=1, le=MAX_NOTIFICATION_ATTEMPTS)
    initial_backoff_seconds: float = Field(default=0.25, ge=0.0, le=10.0)
    backoff_multiplier: float = Field(default=2.0, ge=1.0, le=4.0)
    max_backoff_seconds: float = Field(default=2.0, ge=0.0, le=30.0)
    max_retry_after_seconds: float = Field(
        default=10.0,
        ge=0.0,
        le=MAX_NOTIFICATION_RETRY_DELAY_SECONDS,
    )

    @model_validator(mode="after")
    def validate_backoff_bounds(self) -> Self:
        if self.initial_backoff_seconds > self.max_backoff_seconds:
            raise ValueError("Initial notification backoff exceeds its maximum.")
        return self


class NotificationAttemptOutcome(BaseModel):
    """Provider-classified outcome returned to the retry executor."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )

    status: NotificationDeliveryStatus
    retryable: bool = False
    retry_after_seconds: float | None = Field(
        default=None,
        ge=0.0,
        le=MAX_NOTIFICATION_RETRY_DELAY_SECONDS,
    )
    diagnostic: NotificationDiagnosticCode | None = None

    @model_validator(mode="after")
    def validate_retry_state(self) -> Self:
        if self.status is NotificationDeliveryStatus.SKIPPED:
            raise ValueError("Notification attempt outcome cannot be skipped.")
        if self.retryable and self.status not in _RETRYABLE_STATUSES:
            raise ValueError("Notification outcome status cannot be retried.")
        if self.retry_after_seconds is not None and not self.retryable:
            raise ValueError("Notification retry delay requires a retryable outcome.")
        return self


class NotificationDeliveryAttempt(BaseModel):
    """Bounded public record of one provider delivery attempt."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )

    attempt_number: int = Field(ge=1, le=MAX_NOTIFICATION_ATTEMPTS)
    status: NotificationDeliveryStatus
    retryable: bool = False
    delay_before_next_seconds: float | None = Field(
        default=None,
        ge=0.0,
        le=MAX_NOTIFICATION_RETRY_DELAY_SECONDS,
    )
    diagnostic: NotificationDiagnosticCode | None = None

    @model_validator(mode="after")
    def validate_retry_state(self) -> Self:
        if self.status is NotificationDeliveryStatus.SKIPPED:
            raise ValueError("Notification delivery attempt cannot be skipped.")
        if self.retryable and self.status not in _RETRYABLE_STATUSES:
            raise ValueError("Notification attempt status cannot be retried.")
        if self.delay_before_next_seconds is not None and not self.retryable:
            raise ValueError("Notification retry delay requires a retryable attempt.")
        return self


class NotificationDeliveryResult(BaseModel):
    """Final controlled result for one requested notification channel."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    channel: NotificationChannel
    status: NotificationDeliveryStatus
    attempts: list[NotificationDeliveryAttempt] = Field(
        default_factory=list,
        max_length=MAX_NOTIFICATION_ATTEMPTS,
    )

    @property
    def delivered(self) -> bool:
        return self.status is NotificationDeliveryStatus.DELIVERED

    @model_validator(mode="after")
    def validate_attempts(self) -> Self:
        if self.status is NotificationDeliveryStatus.SKIPPED:
            if self.attempts:
                raise ValueError("Skipped notification result cannot contain attempts.")
            return self

        if not self.attempts:
            raise ValueError("Notification result requires at least one attempt.")
        expected_numbers = list(range(1, len(self.attempts) + 1))
        if [attempt.attempt_number for attempt in self.attempts] != expected_numbers:
            raise ValueError("Notification attempt numbers are not consecutive.")
        if self.attempts[-1].status is not self.status:
            raise ValueError("Notification result does not match its final attempt.")
        if any(
            attempt.status is NotificationDeliveryStatus.DELIVERED
            for attempt in self.attempts[:-1]
        ):
            raise ValueError("Notification cannot continue after successful delivery.")
        if any(
            not attempt.retryable or attempt.delay_before_next_seconds is None
            for attempt in self.attempts[:-1]
        ):
            raise ValueError(
                "Intermediate notification attempts must schedule a retry."
            )
        if self.attempts[-1].retryable:
            raise ValueError("Final notification attempt cannot remain retryable.")
        if self.attempts[-1].delay_before_next_seconds is not None:
            raise ValueError(
                "Final notification attempt cannot schedule another retry."
            )
        return self


class NotificationDeliveryBatch(BaseModel):
    """Ordered aggregate results for one notification event."""

    model_config = ConfigDict(extra="forbid")

    event_id: UUID
    results: list[NotificationDeliveryResult] = Field(
        min_length=1,
        max_length=MAX_NOTIFICATION_CHANNELS,
    )

    @property
    def all_delivered(self) -> bool:
        return all(result.delivered for result in self.results)

    @property
    def has_failures(self) -> bool:
        return any(
            result.status
            not in {
                NotificationDeliveryStatus.DELIVERED,
                NotificationDeliveryStatus.SKIPPED,
            }
            for result in self.results
        )

    @model_validator(mode="after")
    def validate_results(self) -> Self:
        channels: set[NotificationChannel] = set()
        for result in self.results:
            if result.event_id != self.event_id:
                raise ValueError("Notification result event identifier does not match.")
            if result.channel in channels:
                raise ValueError("Notification batch contains a duplicate channel.")
            channels.add(result.channel)
        return self
