from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from lotuswatch.models import (
    ComparisonSummary,
    NotificationAttemptOutcome,
    NotificationChangeStatus,
    NotificationChannel,
    NotificationDeliveryAttempt,
    NotificationDeliveryBatch,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
    NotificationDiagnosticCode,
    NotificationEvent,
    NotificationObservation,
    NotificationRetryPolicy,
    NotificationTimeouts,
    Severity,
    finding_id_fingerprint,
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


def attempt(
    number: int,
    status: NotificationDeliveryStatus,
    *,
    retryable: bool = False,
    delay: float | None = None,
) -> NotificationDeliveryAttempt:
    return NotificationDeliveryAttempt(
        attempt_number=number,
        status=status,
        retryable=retryable,
        delay_before_next_seconds=delay,
    )


def result(
    channel: NotificationChannel,
    status: NotificationDeliveryStatus,
    *,
    event_id: UUID = EVENT_ID,
) -> NotificationDeliveryResult:
    return NotificationDeliveryResult(
        event_id=event_id,
        channel=channel,
        status=status,
        attempts=[]
        if status is NotificationDeliveryStatus.SKIPPED
        else [attempt(1, status)],
    )


def test_default_timeout_and_retry_configuration_is_bounded() -> None:
    timeouts = NotificationTimeouts()
    retry = NotificationRetryPolicy()

    assert timeouts.model_dump() == {
        "connect_seconds": 3.0,
        "read_seconds": 5.0,
        "write_seconds": 5.0,
        "pool_seconds": 3.0,
    }
    assert retry.model_dump() == {
        "max_attempts": 3,
        "initial_backoff_seconds": 0.25,
        "backoff_multiplier": 2.0,
        "max_backoff_seconds": 2.0,
        "max_retry_after_seconds": 10.0,
    }


@pytest.mark.parametrize(
    ("model", "values"),
    [
        (NotificationTimeouts, {"connect_seconds": 0}),
        (NotificationTimeouts, {"read_seconds": 31}),
        (NotificationRetryPolicy, {"max_attempts": 0}),
        (NotificationRetryPolicy, {"max_attempts": 6}),
        (NotificationRetryPolicy, {"backoff_multiplier": 0.5}),
        (NotificationRetryPolicy, {"max_retry_after_seconds": 61}),
    ],
)
def test_rejects_timeout_and_retry_values_outside_bounds(
    model: type[NotificationTimeouts] | type[NotificationRetryPolicy],
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(values)


def test_rejects_initial_backoff_above_maximum() -> None:
    with pytest.raises(ValidationError, match="backoff exceeds its maximum"):
        NotificationRetryPolicy(
            initial_backoff_seconds=2,
            max_backoff_seconds=1,
        )


def test_attempt_outcome_accepts_retryable_transient_status() -> None:
    outcome = NotificationAttemptOutcome(
        status=NotificationDeliveryStatus.TIMEOUT,
        retryable=True,
        retry_after_seconds=2,
        diagnostic=NotificationDiagnosticCode.REQUEST_TIMED_OUT,
    )

    assert outcome.retryable is True
    assert outcome.retry_after_seconds == 2


def test_attempt_models_reject_skipped_status() -> None:
    with pytest.raises(ValidationError, match="outcome cannot be skipped"):
        NotificationAttemptOutcome(status=NotificationDeliveryStatus.SKIPPED)

    with pytest.raises(ValidationError, match="attempt cannot be skipped"):
        NotificationDeliveryAttempt(
            attempt_number=1,
            status=NotificationDeliveryStatus.SKIPPED,
        )


@pytest.mark.parametrize(
    "status",
    [
        NotificationDeliveryStatus.DELIVERED,
        NotificationDeliveryStatus.CONFIGURATION_ERROR,
        NotificationDeliveryStatus.ERROR,
    ],
)
def test_rejects_retryable_permanent_or_terminal_outcome(
    status: NotificationDeliveryStatus,
) -> None:
    with pytest.raises(ValidationError, match="cannot be retried"):
        NotificationAttemptOutcome(status=status, retryable=True)


def test_rejects_retry_delay_on_non_retryable_attempt() -> None:
    with pytest.raises(ValidationError, match="requires a retryable attempt"):
        NotificationDeliveryAttempt(
            attempt_number=1,
            status=NotificationDeliveryStatus.TIMEOUT,
            retryable=False,
            delay_before_next_seconds=1,
        )


def test_diagnostic_is_fixed_enum_and_hides_arbitrary_input() -> None:
    private_value = "provider response containing a token"

    with pytest.raises(ValidationError) as error:
        NotificationAttemptOutcome(
            status=NotificationDeliveryStatus.ERROR,
            diagnostic=private_value,
        )

    assert private_value not in str(error.value)


def test_validates_delivered_result_and_property() -> None:
    delivered = result(
        NotificationChannel.WEBHOOK,
        NotificationDeliveryStatus.DELIVERED,
    )

    assert delivered.delivered is True
    assert delivered.attempts[0].attempt_number == 1


def test_skipped_result_has_no_attempts() -> None:
    skipped = result(
        NotificationChannel.TELEGRAM,
        NotificationDeliveryStatus.SKIPPED,
    )

    assert skipped.delivered is False
    assert skipped.attempts == []


def test_rejects_non_consecutive_attempt_numbers() -> None:
    with pytest.raises(ValidationError, match="not consecutive"):
        NotificationDeliveryResult(
            event_id=EVENT_ID,
            channel=NotificationChannel.WEBHOOK,
            status=NotificationDeliveryStatus.DELIVERED,
            attempts=[
                attempt(
                    1,
                    NotificationDeliveryStatus.TIMEOUT,
                    retryable=True,
                    delay=1,
                ),
                attempt(3, NotificationDeliveryStatus.DELIVERED),
            ],
        )


def test_rejects_result_status_different_from_final_attempt() -> None:
    with pytest.raises(ValidationError, match="does not match its final attempt"):
        NotificationDeliveryResult(
            event_id=EVENT_ID,
            channel=NotificationChannel.WEBHOOK,
            status=NotificationDeliveryStatus.DELIVERED,
            attempts=[attempt(1, NotificationDeliveryStatus.TIMEOUT)],
        )


def test_rejects_intermediate_attempt_without_scheduled_retry() -> None:
    with pytest.raises(ValidationError, match="must schedule a retry"):
        NotificationDeliveryResult(
            event_id=EVENT_ID,
            channel=NotificationChannel.WEBHOOK,
            status=NotificationDeliveryStatus.DELIVERED,
            attempts=[
                attempt(1, NotificationDeliveryStatus.TIMEOUT),
                attempt(2, NotificationDeliveryStatus.DELIVERED),
            ],
        )


def test_rejects_retryable_final_attempt_without_delay() -> None:
    with pytest.raises(ValidationError, match="cannot remain retryable"):
        NotificationDeliveryResult(
            event_id=EVENT_ID,
            channel=NotificationChannel.WEBHOOK,
            status=NotificationDeliveryStatus.TIMEOUT,
            attempts=[
                attempt(
                    1,
                    NotificationDeliveryStatus.TIMEOUT,
                    retryable=True,
                )
            ],
        )


def test_rejects_retry_delay_on_final_attempt() -> None:
    with pytest.raises(ValidationError, match="Final notification attempt"):
        NotificationDeliveryResult(
            event_id=EVENT_ID,
            channel=NotificationChannel.WEBHOOK,
            status=NotificationDeliveryStatus.TIMEOUT,
            attempts=[
                attempt(
                    1,
                    NotificationDeliveryStatus.TIMEOUT,
                    retryable=True,
                    delay=1,
                )
            ],
        )


def test_batch_preserves_order_and_reports_success() -> None:
    batch = NotificationDeliveryBatch(
        event_id=EVENT_ID,
        results=[
            result(
                NotificationChannel.TELEGRAM,
                NotificationDeliveryStatus.DELIVERED,
            ),
            result(
                NotificationChannel.WEBHOOK,
                NotificationDeliveryStatus.DELIVERED,
            ),
        ],
    )

    assert [item.channel for item in batch.results] == [
        NotificationChannel.TELEGRAM,
        NotificationChannel.WEBHOOK,
    ]
    assert batch.all_delivered is True
    assert batch.has_failures is False


def test_batch_distinguishes_skipped_and_failed_results() -> None:
    skipped_batch = NotificationDeliveryBatch(
        event_id=EVENT_ID,
        results=[
            result(
                NotificationChannel.WEBHOOK,
                NotificationDeliveryStatus.SKIPPED,
            )
        ],
    )
    failed_batch = NotificationDeliveryBatch(
        event_id=EVENT_ID,
        results=[
            result(
                NotificationChannel.WEBHOOK,
                NotificationDeliveryStatus.ERROR,
            )
        ],
    )

    assert skipped_batch.all_delivered is False
    assert skipped_batch.has_failures is False
    assert failed_batch.has_failures is True


def test_batch_rejects_duplicate_channel_and_mismatched_event() -> None:
    with pytest.raises(ValidationError, match="duplicate channel"):
        NotificationDeliveryBatch(
            event_id=EVENT_ID,
            results=[
                result(
                    NotificationChannel.WEBHOOK,
                    NotificationDeliveryStatus.DELIVERED,
                ),
                result(
                    NotificationChannel.WEBHOOK,
                    NotificationDeliveryStatus.ERROR,
                ),
            ],
        )

    with pytest.raises(ValidationError, match="event identifier does not match"):
        NotificationDeliveryBatch(
            event_id=EVENT_ID,
            results=[
                result(
                    NotificationChannel.WEBHOOK,
                    NotificationDeliveryStatus.DELIVERED,
                    event_id=UUID("10000000-0000-4000-8000-000000000099"),
                )
            ],
        )


def test_event_remains_valid_for_delivery_models() -> None:
    assert NotificationEvent.model_validate(event().model_dump()) == event()
