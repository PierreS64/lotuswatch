from datetime import UTC, datetime
from typing import cast
from uuid import UUID

import pytest

from lotuswatch.exceptions import NotificationPolicyError
from lotuswatch.models import (
    ComparisonStatus,
    Finding,
    NotificationChangeStatus,
    NotificationSelectionReason,
    ScanReport,
    Severity,
    compare_reports,
)
from lotuswatch.monitoring import MonitoringExecutionResult
from lotuswatch.notifications import select_monitoring_notification
from lotuswatch.scanner import ScanExecutionResult
from lotuswatch.storage import MonitoredTarget, StoredScanRun

TARGET = "https://example.com/"
PROFILE_ID = UUID("10000000-0000-4000-8000-000000000001")
BASELINE_RUN_ID = UUID("20000000-0000-4000-8000-000000000001")
CURRENT_RUN_ID = UUID("20000000-0000-4000-8000-000000000002")
EVENT_ID = UUID("30000000-0000-4000-8000-000000000001")
BASELINE_TIME = datetime(2026, 8, 21, 8, 0, tzinfo=UTC)
CURRENT_TIME = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)
COMPARED_AT = datetime(2026, 8, 21, 9, 1, tzinfo=UTC)
GENERATED_AT = datetime(2026, 8, 21, 9, 2, tzinfo=UTC)
SEVERITIES = list(Severity)


def finding(
    finding_id: str,
    severity: Severity,
    *,
    evidence_value: str = "same",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        title=f"Synthetic {finding_id}",
        description="Synthetic notification policy finding.",
        evidence={"private_detail": evidence_value},
        recommendation="Review the synthetic finding.",
    )


def report(findings: list[Finding], *, scanned_at: datetime) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.5",
        original_target="example.com",
        normalized_url=TARGET,
        scanned_at=scanned_at,
        checks=[],
        findings=findings,
    )


def monitoring_result(
    baseline_findings: list[Finding] | None,
    current_findings: list[Finding],
) -> MonitoringExecutionResult:
    profile = MonitoredTarget.create(
        name="production",
        original_target="example.com",
        normalized_url=TARGET,
        target_id=PROFILE_ID,
        created_at=BASELINE_TIME,
    )
    current_report = report(current_findings, scanned_at=CURRENT_TIME)
    current_run = StoredScanRun.create(
        target_id=PROFILE_ID,
        report=current_report,
        run_id=CURRENT_RUN_ID,
        stored_at=CURRENT_TIME,
    )

    if baseline_findings is None:
        baseline_run = None
        comparison = None
    else:
        baseline_report = report(baseline_findings, scanned_at=BASELINE_TIME)
        baseline_run = StoredScanRun.create(
            target_id=PROFILE_ID,
            report=baseline_report,
            run_id=BASELINE_RUN_ID,
            stored_at=BASELINE_TIME,
        )
        comparison = compare_reports(
            baseline_report,
            current_report,
            compared_at=COMPARED_AT,
        )

    return MonitoringExecutionResult(
        profile=profile,
        scan=cast(ScanExecutionResult, object()),
        stored_run=current_run,
        baseline_run=baseline_run,
        comparison=comparison,
        skipped_baseline_candidates=0,
    )


def test_initial_baseline_returns_explicit_no_notification_reason() -> None:
    result = select_monitoring_notification(
        monitoring_result(None, [finding("LW-TEST-001", Severity.CRITICAL)]),
        Severity.INFO,
    )

    assert result.reason is NotificationSelectionReason.INITIAL_BASELINE
    assert result.event is None


@pytest.mark.parametrize(
    ("severity", "threshold", "expected"),
    [
        (severity, threshold, SEVERITIES.index(severity) >= SEVERITIES.index(threshold))
        for severity in SEVERITIES
        for threshold in SEVERITIES
    ],
)
def test_added_finding_severity_threshold_boundaries(
    severity: Severity,
    threshold: Severity,
    expected: bool,
) -> None:
    result = select_monitoring_notification(
        monitoring_result([], [finding("LW-TEST-001", severity)]),
        threshold,
        event_id=EVENT_ID,
        generated_at=GENERATED_AT,
    )

    assert (result.event is not None) is expected
    assert result.reason is (
        NotificationSelectionReason.SELECTED
        if expected
        else NotificationSelectionReason.NO_MATCHING_FINDINGS
    )


def test_changed_finding_uses_current_severity_and_snapshot() -> None:
    result = select_monitoring_notification(
        monitoring_result(
            [
                finding(
                    "LW-TEST-001",
                    Severity.CRITICAL,
                    evidence_value="baseline-private",
                )
            ],
            [
                finding(
                    "LW-TEST-001",
                    Severity.LOW,
                    evidence_value="current-private",
                )
            ],
        ),
        Severity.LOW,
        event_id=EVENT_ID,
        generated_at=GENERATED_AT,
    )

    assert result.event is not None
    assert result.event.observations[0].status is NotificationChangeStatus.CHANGED
    assert result.event.observations[0].severity is Severity.LOW
    assert "private" not in str(result.event.model_dump(mode="json"))


def test_resolved_unchanged_and_below_threshold_findings_do_not_trigger() -> None:
    unchanged = finding("LW-TEST-001", Severity.CRITICAL)
    result = select_monitoring_notification(
        monitoring_result(
            [unchanged, finding("LW-TEST-002", Severity.CRITICAL)],
            [
                unchanged.model_copy(deep=True),
                finding("LW-TEST-003", Severity.LOW),
            ],
        ),
        Severity.MEDIUM,
    )

    assert result.reason is NotificationSelectionReason.NO_MATCHING_FINDINGS
    assert result.event is None


def test_builds_metadata_summary_and_minimal_observations() -> None:
    result = select_monitoring_notification(
        monitoring_result(
            [
                finding("LW-TEST-001", Severity.LOW),
                finding("LW-TEST-002", Severity.MEDIUM),
                finding("LW-TEST-003", Severity.INFO),
            ],
            [
                finding("LW-TEST-002", Severity.HIGH),
                finding("LW-TEST-003", Severity.INFO),
                finding("LW-TEST-004", Severity.CRITICAL),
            ],
        ),
        Severity.HIGH,
        event_id=EVENT_ID,
        generated_at=GENERATED_AT,
    )

    assert result.event is not None
    event = result.event
    assert event.event_id == EVENT_ID
    assert event.generated_at == GENERATED_AT
    assert event.profile_name == "production"
    assert event.normalized_target == TARGET
    assert event.run_id == CURRENT_RUN_ID
    assert event.scanned_at == CURRENT_TIME
    assert event.compared_at == COMPARED_AT
    assert event.comparison_summary.model_dump() == {
        "added": 1,
        "resolved": 1,
        "changed": 1,
        "unchanged": 1,
    }
    assert [item.finding_id for item in event.observations] == [
        "LW-TEST-004",
        "LW-TEST-002",
    ]


def test_observations_are_bounded_and_deterministically_ordered() -> None:
    current = [
        finding(
            f"LW-TEST-{index:03d}",
            SEVERITIES[index % len(SEVERITIES)],
        )
        for index in range(1, 56)
    ]

    result = select_monitoring_notification(
        monitoring_result([], list(reversed(current))),
        Severity.INFO,
        event_id=EVENT_ID,
        generated_at=GENERATED_AT,
    )

    assert result.event is not None
    assert len(result.event.observations) == 50
    assert result.event.total_triggering_observations == 55
    assert result.event.truncated is True
    observed_ranks = [
        SEVERITIES.index(item.severity) for item in result.event.observations
    ]
    assert observed_ranks == sorted(observed_ranks, reverse=True)


def test_result_is_independent_from_later_comparison_mutation() -> None:
    monitoring = monitoring_result([], [finding("LW-TEST-001", Severity.HIGH)])
    result = select_monitoring_notification(
        monitoring,
        Severity.HIGH,
        event_id=EVENT_ID,
        generated_at=GENERATED_AT,
    )
    assert result.event is not None
    assert monitoring.comparison is not None

    current = monitoring.comparison.findings[0].current_finding
    assert current is not None
    current.title = "Mutated after selection"

    assert result.event.observations[0].title == "Synthetic LW-TEST-001"


def test_rejects_inconsistent_initial_baseline_state() -> None:
    result = monitoring_result([], [])
    inconsistent = MonitoringExecutionResult(
        profile=result.profile,
        scan=result.scan,
        stored_run=result.stored_run,
        baseline_run=result.baseline_run,
        comparison=None,
        skipped_baseline_candidates=0,
    )

    with pytest.raises(NotificationPolicyError, match="baseline state is inconsistent"):
        select_monitoring_notification(inconsistent, Severity.INFO)


def test_rejects_mismatched_stored_run_profile_without_private_data() -> None:
    result = monitoring_result([], [finding("LW-TEST-001", Severity.HIGH)])
    mismatched_profile = result.profile.model_copy(
        update={"id": UUID("10000000-0000-4000-8000-000000000099")}
    )
    inconsistent = MonitoringExecutionResult(
        profile=mismatched_profile,
        scan=result.scan,
        stored_run=result.stored_run,
        baseline_run=result.baseline_run,
        comparison=result.comparison,
        skipped_baseline_candidates=0,
    )

    with pytest.raises(NotificationPolicyError, match="does not match") as error:
        select_monitoring_notification(inconsistent, Severity.INFO)

    assert TARGET not in str(error.value)


def test_rejects_non_result_and_invalid_threshold() -> None:
    with pytest.raises(NotificationPolicyError, match="monitoring execution result"):
        select_monitoring_notification(
            cast(MonitoringExecutionResult, object()),
            Severity.INFO,
        )

    with pytest.raises(NotificationPolicyError, match="threshold is invalid"):
        select_monitoring_notification(
            monitoring_result([], []),
            cast(Severity, "high"),
        )


def test_only_added_and_changed_statuses_are_observed() -> None:
    unchanged = finding("LW-TEST-001", Severity.CRITICAL)
    result = select_monitoring_notification(
        monitoring_result(
            [unchanged, finding("LW-TEST-002", Severity.HIGH)],
            [
                unchanged.model_copy(deep=True),
                finding("LW-TEST-003", Severity.HIGH),
            ],
        ),
        Severity.INFO,
        event_id=EVENT_ID,
        generated_at=GENERATED_AT,
    )

    assert result.event is not None
    assert {item.status for item in result.event.observations} == {
        NotificationChangeStatus.ADDED
    }
    assert {item.status for item in result.event.observations}.isdisjoint(
        {ComparisonStatus.RESOLVED, ComparisonStatus.UNCHANGED}
    )
