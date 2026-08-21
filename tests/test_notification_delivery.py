from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from lotuswatch.exceptions import (
    NotificationConfigurationError,
    NotificationDeliveryError,
    NotificationSecretError,
)
from lotuswatch.models import (
    ComparisonSummary,
    NotificationAttemptOutcome,
    NotificationChangeStatus,
    NotificationChannel,
    NotificationDeliveryAttempt,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
    NotificationDiagnosticCode,
    NotificationEvent,
    NotificationObservation,
    NotificationRetryPolicy,
    Severity,
    finding_id_fingerprint,
)
from lotuswatch.notifications import (
    EnvironmentSecretProvider,
    NotificationSender,
    SecretProvider,
    deliver_notification_channels,
    execute_notification_attempts,
)

TARGET = "https://example.com/"
EVENT_ID = UUID("10000000-0000-4000-8000-000000000001")


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


def delivery_result(
    channel: NotificationChannel,
    status: NotificationDeliveryStatus = NotificationDeliveryStatus.DELIVERED,
    *,
    event_id: UUID = EVENT_ID,
) -> NotificationDeliveryResult:
    return NotificationDeliveryResult(
        event_id=event_id,
        channel=channel,
        status=status,
        attempts=[
            NotificationDeliveryAttempt(
                attempt_number=1,
                status=status,
            )
        ],
    )


class NonEnumeratingEnvironment(Mapping[str, str]):
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def __getitem__(self, key: str) -> str:
        return self.values[key]

    def __iter__(self) -> Iterator[str]:
        raise AssertionError("environment must not be enumerated")

    def __len__(self) -> int:
        return len(self.values)


def test_environment_provider_resolves_only_requested_name() -> None:
    provider = EnvironmentSecretProvider(
        NonEnumeratingEnvironment(
            {
                "LOTUSWATCH_SELECTED": "selected-value",
                "LOTUSWATCH_UNRELATED": "unrelated-value",
            }
        )
    )

    assert provider.get_secret("LOTUSWATCH_SELECTED") == "selected-value"


def test_environment_provider_handles_required_and_optional_missing_values() -> None:
    provider = EnvironmentSecretProvider({})

    assert provider.get_secret("LOTUSWATCH_OPTIONAL", required=False) is None
    with pytest.raises(NotificationSecretError, match="LOTUSWATCH_REQUIRED"):
        provider.get_secret("LOTUSWATCH_REQUIRED")


@pytest.mark.parametrize("value", ["", " ", "\t"])
def test_environment_provider_rejects_empty_value_without_echoing_it(
    value: str,
) -> None:
    provider = EnvironmentSecretProvider({"LOTUSWATCH_SECRET": value})

    with pytest.raises(NotificationSecretError, match="empty or invalid") as error:
        provider.get_secret("LOTUSWATCH_SECRET")

    assert repr(value) not in str(error.value)


def test_environment_provider_rejects_oversized_value_without_leak() -> None:
    private_value = "sensitive-value-" * 10
    provider = EnvironmentSecretProvider({"LOTUSWATCH_SECRET": private_value})

    with pytest.raises(NotificationSecretError, match="size limit") as error:
        provider.get_secret("LOTUSWATCH_SECRET", max_length=20)

    assert private_value not in str(error.value)


def test_environment_provider_rejects_non_string_value_without_leak() -> None:
    private_value = 123456
    provider = EnvironmentSecretProvider(
        cast(Mapping[str, str], {"LOTUSWATCH_SECRET": private_value})
    )

    with pytest.raises(NotificationSecretError, match="empty or invalid") as error:
        provider.get_secret("LOTUSWATCH_SECRET")

    assert str(private_value) not in str(error.value)


@pytest.mark.parametrize(
    "name",
    ["", "lowercase", "1INVALID", "INVALID-NAME", "A" * 129],
)
def test_environment_provider_rejects_invalid_variable_name(name: str) -> None:
    with pytest.raises(NotificationSecretError, match="name is invalid"):
        EnvironmentSecretProvider({}).get_secret(name)


@pytest.mark.parametrize("max_length", [0, -1, 8_193, True, "10"])
def test_environment_provider_rejects_invalid_size_limit(
    max_length: object,
) -> None:
    with pytest.raises(NotificationSecretError, match="invalid size limit"):
        EnvironmentSecretProvider({"LOTUSWATCH_SECRET": "value"}).get_secret(
            "LOTUSWATCH_SECRET",
            max_length=cast(int, max_length),
        )


def test_environment_provider_satisfies_secret_protocol() -> None:
    assert isinstance(EnvironmentSecretProvider({}), SecretProvider)


def test_attempt_executor_delivers_on_first_attempt() -> None:
    calls: list[int] = []

    def operation(attempt_number: int) -> NotificationAttemptOutcome:
        calls.append(attempt_number)
        return NotificationAttemptOutcome(status=NotificationDeliveryStatus.DELIVERED)

    result = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        operation,
        sleep=lambda _: pytest.fail("sleep must not run"),
    )

    assert calls == [1]
    assert result.status is NotificationDeliveryStatus.DELIVERED
    assert result.delivered is True
    assert result.attempts[0].retryable is False


def test_attempt_executor_retries_transient_outcomes_with_backoff() -> None:
    outcomes = iter(
        [
            NotificationAttemptOutcome(
                status=NotificationDeliveryStatus.TIMEOUT,
                retryable=True,
                diagnostic=NotificationDiagnosticCode.REQUEST_TIMED_OUT,
            ),
            NotificationAttemptOutcome(
                status=NotificationDeliveryStatus.CONNECTION_ERROR,
                retryable=True,
                diagnostic=NotificationDiagnosticCode.CONNECTION_FAILED,
            ),
            NotificationAttemptOutcome(
                status=NotificationDeliveryStatus.DELIVERED,
            ),
        ]
    )
    calls: list[int] = []
    delays: list[float] = []

    def operation(attempt_number: int) -> NotificationAttemptOutcome:
        calls.append(attempt_number)
        return next(outcomes)

    result = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        operation,
        sleep=delays.append,
    )

    assert calls == [1, 2, 3]
    assert delays == [0.25, 0.5]
    assert result.status is NotificationDeliveryStatus.DELIVERED
    assert [item.retryable for item in result.attempts] == [True, True, False]
    assert [item.delay_before_next_seconds for item in result.attempts] == [
        0.25,
        0.5,
        None,
    ]


def test_attempt_executor_bounds_retry_after() -> None:
    calls = 0
    delays: list[float] = []

    def operation(_: int) -> NotificationAttemptOutcome:
        nonlocal calls
        calls += 1
        if calls == 1:
            return NotificationAttemptOutcome(
                status=NotificationDeliveryStatus.PROVIDER_REJECTED,
                retryable=True,
                retry_after_seconds=60,
                diagnostic=NotificationDiagnosticCode.PROVIDER_REJECTED,
            )
        return NotificationAttemptOutcome(status=NotificationDeliveryStatus.DELIVERED)

    result = execute_notification_attempts(
        NotificationChannel.TELEGRAM,
        event(),
        operation,
        retry_policy=NotificationRetryPolicy(max_retry_after_seconds=3),
        sleep=delays.append,
    )

    assert result.delivered is True
    assert delays == [3]


def test_attempt_executor_does_not_retry_permanent_outcome() -> None:
    calls: list[int] = []

    def operation(attempt_number: int) -> NotificationAttemptOutcome:
        calls.append(attempt_number)
        return NotificationAttemptOutcome(
            status=NotificationDeliveryStatus.PROVIDER_REJECTED,
            retryable=False,
            diagnostic=NotificationDiagnosticCode.PROVIDER_REJECTED,
        )

    result = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        operation,
        sleep=lambda _: pytest.fail("sleep must not run"),
    )

    assert calls == [1]
    assert result.status is NotificationDeliveryStatus.PROVIDER_REJECTED


def test_attempt_executor_stops_at_maximum_attempts() -> None:
    calls: list[int] = []
    delays: list[float] = []

    def operation(attempt_number: int) -> NotificationAttemptOutcome:
        calls.append(attempt_number)
        return NotificationAttemptOutcome(
            status=NotificationDeliveryStatus.TIMEOUT,
            retryable=True,
            diagnostic=NotificationDiagnosticCode.REQUEST_TIMED_OUT,
        )

    result = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        operation,
        retry_policy=NotificationRetryPolicy(max_attempts=2),
        sleep=delays.append,
    )

    assert calls == [1, 2]
    assert delays == [0.25]
    assert result.status is NotificationDeliveryStatus.TIMEOUT
    assert result.attempts[-1].retryable is False
    assert result.attempts[-1].delay_before_next_seconds is None


def test_attempt_executor_sanitizes_secret_and_unexpected_errors() -> None:
    private_value = "sensitive-provider-value"

    def secret_error(_: int) -> NotificationAttemptOutcome:
        raise NotificationSecretError(private_value)

    def unexpected_error(_: int) -> NotificationAttemptOutcome:
        raise RuntimeError(private_value)

    configuration = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        secret_error,
    )
    unexpected = execute_notification_attempts(
        NotificationChannel.TELEGRAM,
        event(),
        unexpected_error,
    )

    assert configuration.status is NotificationDeliveryStatus.CONFIGURATION_ERROR
    assert unexpected.status is NotificationDeliveryStatus.ERROR
    assert private_value not in str(configuration.model_dump(mode="json"))
    assert private_value not in str(unexpected.model_dump(mode="json"))


def test_attempt_executor_classifies_general_configuration_error() -> None:
    def invalid_configuration(_: int) -> NotificationAttemptOutcome:
        raise NotificationConfigurationError("private configuration")

    result = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        invalid_configuration,
    )

    assert result.status is NotificationDeliveryStatus.CONFIGURATION_ERROR
    assert "private configuration" not in str(result.model_dump(mode="json"))


def test_attempt_executor_sanitizes_invalid_outcome() -> None:
    result = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        lambda _: cast(NotificationAttemptOutcome, {"response": "private"}),
    )

    assert result.status is NotificationDeliveryStatus.ERROR
    assert (
        result.attempts[0].diagnostic is NotificationDiagnosticCode.UNEXPECTED_FAILURE
    )


def test_attempt_executor_sanitizes_backoff_failure() -> None:
    private_value = "private-backoff-error"

    def failing_sleep(_: float) -> None:
        raise RuntimeError(private_value)

    result = execute_notification_attempts(
        NotificationChannel.WEBHOOK,
        event(),
        lambda _: NotificationAttemptOutcome(
            status=NotificationDeliveryStatus.TIMEOUT,
            retryable=True,
        ),
        sleep=failing_sleep,
    )

    assert result.status is NotificationDeliveryStatus.ERROR
    assert result.attempts[-1].diagnostic is NotificationDiagnosticCode.BACKOFF_FAILED
    assert private_value not in str(result.model_dump(mode="json"))


@dataclass
class FakeSender:
    channel: NotificationChannel
    status: NotificationDeliveryStatus = NotificationDeliveryStatus.DELIVERED
    calls: list[UUID] = field(default_factory=list)
    error: Exception | None = None
    result_event_id: UUID = EVENT_ID

    def deliver(
        self,
        selected_event: NotificationEvent,
        *,
        secrets: SecretProvider,
    ) -> NotificationDeliveryResult:
        assert isinstance(secrets, SecretProvider)
        self.calls.append(selected_event.event_id)
        if self.error is not None:
            raise self.error
        return delivery_result(
            self.channel,
            self.status,
            event_id=self.result_event_id,
        )


def test_sender_protocol_and_aggregate_preserve_requested_order() -> None:
    telegram = FakeSender(NotificationChannel.TELEGRAM)
    webhook = FakeSender(NotificationChannel.WEBHOOK)

    assert isinstance(telegram, NotificationSender)
    batch = deliver_notification_channels(
        event(),
        [telegram, webhook],
        secrets=EnvironmentSecretProvider({}),
    )

    assert [item.channel for item in batch.results] == [
        NotificationChannel.TELEGRAM,
        NotificationChannel.WEBHOOK,
    ]
    assert batch.all_delivered is True
    assert telegram.calls == [EVENT_ID]
    assert webhook.calls == [EVENT_ID]


def test_aggregate_continues_after_sender_failure_and_sanitizes_error() -> None:
    private_value = "private-provider-response"
    failing = FakeSender(
        NotificationChannel.WEBHOOK,
        error=RuntimeError(private_value),
    )
    succeeding = FakeSender(NotificationChannel.TELEGRAM)

    batch = deliver_notification_channels(event(), [failing, succeeding])

    assert [item.status for item in batch.results] == [
        NotificationDeliveryStatus.ERROR,
        NotificationDeliveryStatus.DELIVERED,
    ]
    assert failing.calls == [EVENT_ID]
    assert succeeding.calls == [EVENT_ID]
    assert private_value not in str(batch.model_dump(mode="json"))


def test_aggregate_classifies_secret_failure_as_configuration_error() -> None:
    sender = FakeSender(
        NotificationChannel.WEBHOOK,
        error=NotificationSecretError("private-secret"),
    )

    batch = deliver_notification_channels(event(), [sender])

    assert batch.results[0].status is NotificationDeliveryStatus.CONFIGURATION_ERROR
    assert (
        batch.results[0].attempts[0].diagnostic
        is NotificationDiagnosticCode.CONFIGURATION_INVALID
    )


def test_aggregate_rejects_duplicate_channels_before_delivery() -> None:
    first = FakeSender(NotificationChannel.WEBHOOK)
    second = FakeSender(NotificationChannel.WEBHOOK)

    with pytest.raises(NotificationDeliveryError, match="duplicate channel"):
        deliver_notification_channels(event(), [first, second])

    assert first.calls == []
    assert second.calls == []


def test_aggregate_converts_invalid_sender_result_to_controlled_error() -> None:
    sender = FakeSender(
        NotificationChannel.WEBHOOK,
        result_event_id=UUID("10000000-0000-4000-8000-000000000099"),
    )

    batch = deliver_notification_channels(event(), [sender])

    assert batch.results[0].status is NotificationDeliveryStatus.ERROR
    assert (
        batch.results[0].attempts[0].diagnostic
        is NotificationDiagnosticCode.UNEXPECTED_FAILURE
    )


def test_aggregate_passes_independent_event_copy_to_each_sender() -> None:
    observed_titles: list[str] = []

    @dataclass
    class MutatingSender:
        channel: NotificationChannel
        replacement: str

        def deliver(
            self,
            selected_event: NotificationEvent,
            *,
            secrets: SecretProvider,
        ) -> NotificationDeliveryResult:
            observed_titles.append(selected_event.observations[0].title)
            selected_event.observations[0].title = self.replacement
            return delivery_result(self.channel)

    original = event()
    deliver_notification_channels(
        original,
        [
            MutatingSender(NotificationChannel.WEBHOOK, "mutated webhook"),
            MutatingSender(NotificationChannel.TELEGRAM, "mutated telegram"),
        ],
    )

    assert observed_titles == ["Synthetic finding", "Synthetic finding"]
    assert original.observations[0].title == "Synthetic finding"


@pytest.mark.parametrize("senders", [[], [FakeSender(NotificationChannel.WEBHOOK)] * 9])
def test_aggregate_rejects_sender_count_outside_bounds(
    senders: list[FakeSender],
) -> None:
    with pytest.raises(NotificationDeliveryError, match="sender count"):
        deliver_notification_channels(event(), senders)


def test_aggregate_rejects_invalid_secret_provider_before_delivery() -> None:
    sender = FakeSender(NotificationChannel.WEBHOOK)

    with pytest.raises(NotificationDeliveryError, match="secret provider is invalid"):
        deliver_notification_channels(
            event(),
            [sender],
            secrets=cast(SecretProvider, object()),
        )

    assert sender.calls == []
