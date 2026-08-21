from datetime import UTC, datetime, timedelta, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError

from lotuswatch.models import (
    ComparisonSummary,
    NotificationChangeStatus,
    NotificationEvent,
    NotificationObservation,
    NotificationSelection,
    NotificationSelectionReason,
    Severity,
    finding_id_fingerprint,
)

TARGET = "https://example.com/"
EVENT_ID = UUID("10000000-0000-4000-8000-000000000001")
RUN_ID = UUID("20000000-0000-4000-8000-000000000001")
GENERATED_AT = datetime(2026, 8, 21, 10, 0, tzinfo=UTC)
SCANNED_AT = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)
COMPARED_AT = datetime(2026, 8, 21, 9, 1, tzinfo=UTC)


def observation(
    finding_id: str = "LW-TEST-001",
    *,
    severity: Severity = Severity.HIGH,
    status: NotificationChangeStatus = NotificationChangeStatus.ADDED,
    target: str = TARGET,
) -> NotificationObservation:
    return NotificationObservation(
        fingerprint=finding_id_fingerprint(target, finding_id),
        status=status,
        finding_id=finding_id,
        severity=severity,
        title=f"Synthetic {finding_id}",
    )


def event_data(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "event_id": EVENT_ID,
        "generated_at": GENERATED_AT,
        "profile_name": "production",
        "normalized_target": TARGET,
        "run_id": RUN_ID,
        "scanned_at": SCANNED_AT,
        "compared_at": COMPARED_AT,
        "threshold": Severity.MEDIUM,
        "comparison_summary": ComparisonSummary(
            added=1,
            resolved=0,
            changed=0,
            unchanged=0,
        ),
        "total_triggering_observations": 1,
        "truncated": False,
        "observations": [observation()],
    }
    data.update(overrides)
    return data


def test_validates_and_serializes_minimal_event() -> None:
    event = NotificationEvent.model_validate(event_data())
    serialized = event.model_dump(mode="json")

    assert serialized["notification_schema_version"] == "1.0"
    assert serialized["normalized_target"] == TARGET
    assert serialized["generated_at"] == "2026-08-21T10:00:00Z"
    assert serialized["observations"][0] == {
        "fingerprint": finding_id_fingerprint(TARGET, "LW-TEST-001"),
        "status": "added",
        "finding_id": "LW-TEST-001",
        "severity": "high",
        "title": "Synthetic LW-TEST-001",
    }
    assert "evidence" not in str(serialized).casefold()
    assert "recommendation" not in str(serialized).casefold()
    assert "description" not in str(serialized).casefold()


def test_normalizes_equivalent_target_and_timestamps() -> None:
    utc_plus_seven = timezone(timedelta(hours=7))
    event = NotificationEvent.model_validate(
        event_data(
            normalized_target=" HTTPS://EXAMPLE.COM/#fragment ",
            generated_at=datetime(2026, 8, 21, 17, 0, tzinfo=utc_plus_seven),
        )
    )

    assert event.normalized_target == TARGET
    assert event.generated_at == GENERATED_AT


@pytest.mark.parametrize("field", ["generated_at", "scanned_at", "compared_at"])
def test_rejects_naive_timestamps(field: str) -> None:
    with pytest.raises(ValidationError, match="must include a timezone"):
        NotificationEvent.model_validate(
            event_data(**{field: GENERATED_AT.replace(tzinfo=None)})
        )


def test_rejects_invalid_target_without_echoing_value() -> None:
    private_value = "not a valid target"

    with pytest.raises(
        ValidationError, match="Notification target is invalid"
    ) as error:
        NotificationEvent.model_validate(event_data(normalized_target=private_value))

    assert private_value not in str(error.value)


def test_rejects_fingerprint_identity_mismatch() -> None:
    mismatched = observation("LW-TEST-002")
    data = mismatched.model_dump(mode="python")
    data["finding_id"] = "LW-TEST-001"

    with pytest.raises(ValidationError, match="does not match its finding identity"):
        NotificationEvent.model_validate(
            event_data(observations=[NotificationObservation.model_validate(data)])
        )


def test_rejects_duplicate_fingerprint() -> None:
    duplicate = observation()

    with pytest.raises(ValidationError, match="duplicate fingerprint"):
        NotificationEvent.model_validate(
            event_data(
                comparison_summary=ComparisonSummary(
                    added=2,
                    resolved=0,
                    changed=0,
                    unchanged=0,
                ),
                total_triggering_observations=2,
                observations=[duplicate, duplicate.model_copy(deep=True)],
            )
        )


def test_rejects_observation_below_threshold() -> None:
    with pytest.raises(ValidationError, match="does not meet its severity threshold"):
        NotificationEvent.model_validate(
            event_data(
                threshold=Severity.HIGH,
                observations=[observation(severity=Severity.MEDIUM)],
            )
        )


def test_rejects_inconsistent_summary_status_count() -> None:
    with pytest.raises(ValidationError, match="too many changed observations"):
        NotificationEvent.model_validate(
            event_data(
                observations=[observation(status=NotificationChangeStatus.CHANGED)],
            )
        )


@pytest.mark.parametrize(
    ("total", "truncated", "message"),
    [
        (0, False, "greater than or equal to 1"),
        (2, False, "truncation state is inconsistent"),
        (1, True, "truncation state is inconsistent"),
    ],
)
def test_rejects_inconsistent_triggering_and_truncation(
    total: int,
    truncated: bool,
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        NotificationEvent.model_validate(
            event_data(
                comparison_summary=ComparisonSummary(
                    added=2,
                    resolved=0,
                    changed=0,
                    unchanged=0,
                ),
                total_triggering_observations=total,
                truncated=truncated,
            )
        )


def test_accepts_consistent_truncated_event() -> None:
    event = NotificationEvent.model_validate(
        event_data(
            comparison_summary=ComparisonSummary(
                added=2,
                resolved=0,
                changed=0,
                unchanged=0,
            ),
            total_triggering_observations=2,
            truncated=True,
        )
    )

    assert event.truncated is True


def test_rejects_non_deterministic_observation_order() -> None:
    lower = observation("LW-TEST-001", severity=Severity.MEDIUM)
    higher = observation("LW-TEST-002", severity=Severity.CRITICAL)

    with pytest.raises(ValidationError, match="not deterministically ordered"):
        NotificationEvent.model_validate(
            event_data(
                comparison_summary=ComparisonSummary(
                    added=2,
                    resolved=0,
                    changed=0,
                    unchanged=0,
                ),
                total_triggering_observations=2,
                observations=[lower, higher],
            )
        )


@pytest.mark.parametrize(
    ("reason", "selected_event", "valid"),
    [
        (NotificationSelectionReason.SELECTED, True, True),
        (NotificationSelectionReason.SELECTED, False, False),
        (NotificationSelectionReason.INITIAL_BASELINE, False, True),
        (NotificationSelectionReason.INITIAL_BASELINE, True, False),
        (NotificationSelectionReason.NO_MATCHING_FINDINGS, False, True),
    ],
)
def test_selection_requires_event_only_for_selected_reason(
    reason: NotificationSelectionReason,
    selected_event: bool,
    valid: bool,
) -> None:
    values = {
        "reason": reason,
        "event": NotificationEvent.model_validate(event_data())
        if selected_event
        else None,
    }

    if valid:
        assert NotificationSelection.model_validate(values).reason is reason
    else:
        with pytest.raises(ValidationError, match="reason and event are inconsistent"):
            NotificationSelection.model_validate(values)
