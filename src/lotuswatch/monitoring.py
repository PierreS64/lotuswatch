from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from lotuswatch.exceptions import (
    ComparisonError,
    MonitoringComparisonError,
    MonitoringProfileDisabledError,
    MonitoringProfileNotFoundError,
    MonitoringRetentionError,
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
MAX_RETENTION_KEEP = 1_000_000


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


@dataclass(frozen=True, slots=True)
class MonitoringHistoryResult:
    """Validated stored runs for one monitoring profile."""

    profile: MonitoredTarget
    runs: tuple[StoredScanRun, ...]


@dataclass(frozen=True, slots=True)
class RetentionPlan:
    """Deterministic run identifiers selected for explicit pruning."""

    profile: MonitoredTarget
    keep: int
    total_runs: int
    run_ids: tuple[UUID, ...]

    @property
    def removal_count(self) -> int:
        return len(self.run_ids)

    @property
    def remaining_runs(self) -> int:
        return self.total_runs - self.removal_count


def load_monitoring_history(
    store: MonitoringStore,
    profile_name: str,
    *,
    limit: int = DEFAULT_QUERY_LIMIT,
) -> MonitoringHistoryResult:
    """Load bounded, newest-first, fully validated profile history."""

    profile = _require_profile(store, profile_name)
    metadata = store.list_scan_runs(profile.id, limit=limit)
    runs: list[StoredScanRun] = []
    for item in metadata:
        run = store.get_scan_run(item.id)
        if run is None:
            raise MonitoringComparisonError(
                "Scan history changed while it was being loaded."
            )
        runs.append(run)

    return MonitoringHistoryResult(
        profile=profile.model_copy(deep=True),
        runs=tuple(runs),
    )


def plan_monitoring_retention(
    store: MonitoringStore,
    profile_name: str,
    *,
    keep: int,
) -> RetentionPlan:
    """Preview exactly which runs are outside the retained newest set."""

    if (
        isinstance(keep, bool)
        or not isinstance(keep, int)
        or not 1 <= keep <= MAX_RETENTION_KEEP
    ):
        raise MonitoringRetentionError(
            f"Retention keep count must be between 1 and {MAX_RETENTION_KEEP}."
        )

    profile = _require_profile(store, profile_name)
    total_runs = store.count_scan_runs(profile.id)
    run_ids = tuple(store.preview_scan_run_prune(profile.id, keep=keep))
    expected_removals = max(total_runs - keep, 0)
    if len(run_ids) != expected_removals:
        raise MonitoringRetentionError(
            "Scan history changed while the retention preview was generated."
        )

    return RetentionPlan(
        profile=profile.model_copy(deep=True),
        keep=keep,
        total_runs=total_runs,
        run_ids=run_ids,
    )


def apply_monitoring_retention(
    store: MonitoringStore,
    plan: RetentionPlan,
) -> int:
    """Delete only the identifiers in a previously generated plan."""

    if not isinstance(plan, RetentionPlan):
        raise MonitoringRetentionError("Retention plan is invalid.")
    current_profile = store.get_target(plan.profile.id)
    if current_profile is None or current_profile != plan.profile:
        raise MonitoringRetentionError(
            "Monitoring profile changed after the retention preview."
        )
    if not plan.run_ids:
        return 0

    return store.delete_scan_runs(
        plan.profile.id,
        plan.run_ids,
        expected_total=plan.total_runs,
    )


def _require_profile(
    store: MonitoringStore,
    profile_name: str,
) -> MonitoredTarget:
    profile = store.get_target_by_name(profile_name)
    if profile is None:
        raise MonitoringProfileNotFoundError("Monitoring target profile was not found.")
    return profile


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

    profile = _require_profile(store, profile_name)
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
    "MAX_RETENTION_KEEP",
    "MonitoringExecutionResult",
    "MonitoringHistoryResult",
    "RetentionPlan",
    "apply_monitoring_retention",
    "execute_monitoring_run",
    "load_monitoring_history",
    "plan_monitoring_retention",
]
