from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import ValidationError

from lotuswatch.exceptions import NotificationPolicyError
from lotuswatch.models import (
    MAX_NOTIFICATION_OBSERVATIONS,
    ComparisonReport,
    ComparisonStatus,
    NotificationChangeStatus,
    NotificationEvent,
    NotificationObservation,
    NotificationSelection,
    NotificationSelectionReason,
    Severity,
)
from lotuswatch.monitoring import MonitoringExecutionResult
from lotuswatch.policy import SEVERITY_RANK, severity_meets_threshold
from lotuswatch.storage import MonitoredTarget, StoredScanRun


def select_monitoring_notification(
    result: MonitoringExecutionResult,
    threshold: Severity,
    *,
    event_id: UUID | None = None,
    generated_at: datetime | None = None,
) -> NotificationSelection:
    """Select a minimal notification event from one stored monitoring run."""

    if not isinstance(result, MonitoringExecutionResult):
        raise NotificationPolicyError(
            "Notification input must be a monitoring execution result."
        )
    if not isinstance(threshold, Severity):
        raise NotificationPolicyError("Notification threshold is invalid.")

    profile = _validated_profile(result.profile)
    stored_run = _validated_stored_run(result.stored_run)
    _validate_stored_run_profile(profile, stored_run)

    if result.comparison is None:
        if result.baseline_run is not None:
            raise NotificationPolicyError(
                "Initial notification baseline state is inconsistent."
            )
        return NotificationSelection(
            reason=NotificationSelectionReason.INITIAL_BASELINE
        )

    if result.baseline_run is None:
        raise NotificationPolicyError(
            "Notification comparison baseline state is inconsistent."
        )

    baseline_run = _validated_stored_run(result.baseline_run)
    _validate_stored_run_profile(profile, baseline_run)
    comparison = _validated_comparison(result.comparison)
    _validate_comparison_metadata(profile, baseline_run, stored_run, comparison)
    candidates = _triggering_observations(comparison, threshold)
    if not candidates:
        return NotificationSelection(
            reason=NotificationSelectionReason.NO_MATCHING_FINDINGS
        )

    candidates.sort(
        key=lambda observation: (
            -SEVERITY_RANK[observation.severity],
            observation.finding_id,
            observation.fingerprint,
        )
    )
    selected = candidates[:MAX_NOTIFICATION_OBSERVATIONS]
    try:
        event = NotificationEvent(
            event_id=event_id or uuid4(),
            generated_at=generated_at or datetime.now(UTC),
            profile_name=profile.name,
            normalized_target=profile.normalized_url,
            run_id=stored_run.metadata.id,
            scanned_at=stored_run.metadata.scanned_at,
            compared_at=comparison.compared_at,
            threshold=threshold,
            comparison_summary=comparison.summary.model_copy(deep=True),
            total_triggering_observations=len(candidates),
            truncated=len(candidates) > len(selected),
            observations=selected,
        )
    except (ValidationError, TypeError, ValueError) as exc:
        raise NotificationPolicyError(
            "Notification event could not be validated."
        ) from exc

    return NotificationSelection(
        reason=NotificationSelectionReason.SELECTED,
        event=event,
    )


def _validated_profile(profile: MonitoredTarget) -> MonitoredTarget:
    if not isinstance(profile, MonitoredTarget):
        raise NotificationPolicyError("Notification monitoring profile is invalid.")
    try:
        return MonitoredTarget.model_validate(profile.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationPolicyError(
            "Notification monitoring profile is invalid."
        ) from exc


def _validated_stored_run(stored_run: StoredScanRun) -> StoredScanRun:
    if not isinstance(stored_run, StoredScanRun):
        raise NotificationPolicyError("Notification stored run is invalid.")
    try:
        return StoredScanRun.model_validate(stored_run.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationPolicyError("Notification stored run is invalid.") from exc


def _validated_comparison(comparison: ComparisonReport) -> ComparisonReport:
    if not isinstance(comparison, ComparisonReport):
        raise NotificationPolicyError("Notification comparison is invalid.")
    try:
        return ComparisonReport.model_validate(comparison.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationPolicyError("Notification comparison is invalid.") from exc


def _validate_stored_run_profile(
    profile: MonitoredTarget,
    stored_run: StoredScanRun,
) -> None:
    if stored_run.metadata.target_id != profile.id:
        raise NotificationPolicyError(
            "Notification stored run does not match its monitoring profile."
        )
    if stored_run.report.target.normalized_url != profile.normalized_url:
        raise NotificationPolicyError(
            "Notification stored run does not match its monitoring target."
        )


def _validate_comparison_metadata(
    profile: MonitoredTarget,
    baseline_run: StoredScanRun,
    stored_run: StoredScanRun,
    comparison: ComparisonReport,
) -> None:
    if comparison.normalized_target != profile.normalized_url:
        raise NotificationPolicyError(
            "Notification comparison does not match its monitoring target."
        )
    if comparison.current.scanned_at != stored_run.metadata.scanned_at:
        raise NotificationPolicyError(
            "Notification comparison does not match its stored run timestamp."
        )
    if comparison.current.lotuswatch_version != stored_run.metadata.lotuswatch_version:
        raise NotificationPolicyError(
            "Notification comparison does not match its stored LotusWatch version."
        )
    if comparison.baseline.scanned_at != baseline_run.metadata.scanned_at:
        raise NotificationPolicyError(
            "Notification comparison does not match its baseline timestamp."
        )
    if (
        comparison.baseline.lotuswatch_version
        != baseline_run.metadata.lotuswatch_version
    ):
        raise NotificationPolicyError(
            "Notification comparison does not match its baseline LotusWatch version."
        )


def _triggering_observations(
    comparison: ComparisonReport,
    threshold: Severity,
) -> list[NotificationObservation]:
    observations: list[NotificationObservation] = []
    for item in comparison.findings:
        if item.status not in {ComparisonStatus.ADDED, ComparisonStatus.CHANGED}:
            continue
        current = item.current_finding
        assert current is not None
        if not severity_meets_threshold(current.severity, threshold):
            continue
        observations.append(
            NotificationObservation(
                fingerprint=item.fingerprint,
                status=NotificationChangeStatus(item.status.value),
                finding_id=current.id,
                severity=current.severity,
                title=current.title,
            )
        )
    return observations


__all__ = ["select_monitoring_notification"]
