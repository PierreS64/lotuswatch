from dataclasses import dataclass
from datetime import datetime

from lotuswatch.exceptions import (
    ComparisonError,
    MonitoringComparisonError,
    MonitoringProfileDisabledError,
    MonitoringProfileNotFoundError,
    MonitoringTargetCompatibilityError,
    TargetValidationError,
)
from lotuswatch.models import ComparisonReport, ScanReport, compare_reports
from lotuswatch.scanner import ScanCheckRunner, ScanExecutionResult, execute_scan
from lotuswatch.storage import (
    DEFAULT_QUERY_LIMIT,
    MonitoredTarget,
    MonitoringStore,
    StoredScanRun,
)
from lotuswatch.target import NormalizedTarget, normalize_target

MAX_BASELINE_CANDIDATES = DEFAULT_QUERY_LIMIT


@dataclass(frozen=True, slots=True)
class MonitoringExecutionResult:
    """Complete result of one stored monitored scan."""

    profile: MonitoredTarget
    scan: ScanExecutionResult
    stored_run: StoredScanRun
    baseline_run: StoredScanRun | None
    comparison: ComparisonReport | None
    skipped_baseline_candidates: int

    @property
    def is_initial_baseline(self) -> bool:
        return self.baseline_run is None


def execute_monitoring_run(
    store: MonitoringStore,
    profile_name: str,
    *,
    lotuswatch_version: str,
    runner: ScanCheckRunner | None = None,
    scanned_at: datetime | None = None,
    stored_at: datetime | None = None,
    compared_at: datetime | None = None,
) -> MonitoringExecutionResult:
    """Scan one enabled profile, compare it, and persist one complete run."""

    profile = store.get_target_by_name(profile_name)
    if profile is None:
        raise MonitoringProfileNotFoundError("Monitoring target profile was not found.")
    if not profile.enabled:
        raise MonitoringProfileDisabledError(
            "Monitoring target profile is disabled. Enable it before running a scan."
        )

    target = _validated_profile_target(profile)
    scan = execute_scan(
        target,
        lotuswatch_version=lotuswatch_version,
        runner=runner,
        scanned_at=scanned_at,
    )
    _validate_scan_target(profile, scan.report)

    baseline, skipped_candidates = _find_previous_compatible_run(
        store,
        profile,
        scan.report,
    )
    comparison = _compare_with_baseline(
        baseline,
        scan.report,
        compared_at=compared_at,
    )
    pending_run = StoredScanRun.create(
        target_id=profile.id,
        report=scan.report,
        stored_at=stored_at,
    )
    stored_run = store.save_scan_run(pending_run)

    return MonitoringExecutionResult(
        profile=profile.model_copy(deep=True),
        scan=scan,
        stored_run=stored_run,
        baseline_run=(None if baseline is None else baseline.model_copy(deep=True)),
        comparison=(None if comparison is None else comparison.model_copy(deep=True)),
        skipped_baseline_candidates=skipped_candidates,
    )


def _validated_profile_target(profile: MonitoredTarget) -> NormalizedTarget:
    try:
        target = normalize_target(profile.normalized_url)
    except TargetValidationError as exc:
        raise MonitoringTargetCompatibilityError(
            "Stored monitoring target is invalid."
        ) from exc

    if target.url != profile.normalized_url:
        raise MonitoringTargetCompatibilityError(
            "Stored monitoring target is not canonical."
        )
    return target


def _validate_scan_target(profile: MonitoredTarget, report: ScanReport) -> None:
    try:
        report_target = normalize_target(report.target.normalized_url).url
    except TargetValidationError as exc:
        raise MonitoringTargetCompatibilityError(
            "Monitoring scan produced an invalid target."
        ) from exc

    if report_target != profile.normalized_url:
        raise MonitoringTargetCompatibilityError(
            "Monitoring scan result does not match the stored target."
        )


def _find_previous_compatible_run(
    store: MonitoringStore,
    profile: MonitoredTarget,
    current_report: ScanReport,
) -> tuple[StoredScanRun | None, int]:
    candidates = store.list_scan_runs(
        profile.id,
        limit=MAX_BASELINE_CANDIDATES,
    )
    skipped = 0

    for metadata in candidates:
        if metadata.scanned_at >= current_report.scanned_at:
            skipped += 1
            continue

        candidate = store.get_scan_run(metadata.id)
        if candidate is None:
            raise MonitoringComparisonError(
                "A baseline candidate changed while the monitoring run was executing."
            )

        try:
            candidate_target = normalize_target(
                candidate.report.target.normalized_url
            ).url
        except TargetValidationError:
            skipped += 1
            continue

        if candidate_target != profile.normalized_url:
            skipped += 1
            continue

        return candidate, skipped

    return None, skipped


def _compare_with_baseline(
    baseline: StoredScanRun | None,
    current_report: ScanReport,
    *,
    compared_at: datetime | None,
) -> ComparisonReport | None:
    if baseline is None:
        return None

    try:
        return compare_reports(
            baseline.report,
            current_report,
            compared_at=compared_at,
        )
    except ComparisonError as exc:
        raise MonitoringComparisonError(
            "Stored baseline and current scan could not be compared safely."
        ) from exc


__all__ = [
    "MAX_BASELINE_CANDIDATES",
    "MonitoringExecutionResult",
    "execute_monitoring_run",
]
