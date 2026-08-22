from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from lotuswatch.exceptions import (
    ComparisonInputError,
    ComparisonTargetMismatchError,
    DuplicateFindingFingerprintError,
    TargetValidationError,
)
from lotuswatch.models.finding import Finding
from lotuswatch.models.fingerprint import finding_fingerprint
from lotuswatch.models.report import ScanReport
from lotuswatch.target import normalize_target

_FINGERPRINT_PATTERN = r"^lwfp:v1:sha256:[0-9a-f]{64}$"
COMPARISON_REPORT_SCHEMA_VERSION = "1.0"


class ComparisonStatus(StrEnum):
    """Change classifications supported by report comparison."""

    ADDED = "added"
    RESOLVED = "resolved"
    CHANGED = "changed"
    UNCHANGED = "unchanged"


class ComparisonReportMetadata(BaseModel):
    """Source scan metadata preserved in a comparison report."""

    model_config = ConfigDict(extra="forbid")

    scan_schema_version: Literal["1.0"] = "1.0"
    lotuswatch_version: str = Field(min_length=1)
    scanned_at: datetime

    @field_validator("scanned_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        """Require a timezone-aware timestamp and normalize it to UTC."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Scan timestamp must include a timezone.")

        return value.astimezone(UTC)


class FindingComparison(BaseModel):
    """Baseline and current snapshots for one finding identity."""

    model_config = ConfigDict(extra="forbid")

    fingerprint: str = Field(pattern=_FINGERPRINT_PATTERN)
    status: ComparisonStatus
    baseline_finding: Finding | None = None
    current_finding: Finding | None = None

    @model_validator(mode="after")
    def validate_snapshot_presence(self) -> Self:
        """Require snapshots appropriate for the comparison status."""

        baseline_present = self.baseline_finding is not None
        current_present = self.current_finding is not None

        if self.status is ComparisonStatus.ADDED:
            valid = not baseline_present and current_present
        elif self.status is ComparisonStatus.RESOLVED:
            valid = baseline_present and not current_present
        else:
            valid = baseline_present and current_present

        if not valid:
            raise ValueError(
                f"{self.status.value} comparison has invalid finding snapshots."
            )

        return self


class ComparisonSummary(BaseModel):
    """Finding change counters for a comparison report."""

    model_config = ConfigDict(extra="forbid")

    added: int = Field(ge=0)
    resolved: int = Field(ge=0)
    changed: int = Field(ge=0)
    unchanged: int = Field(ge=0)


class ComparisonReport(BaseModel):
    """Serializable result of comparing two LotusWatch scan reports."""

    model_config = ConfigDict(extra="forbid")

    comparison_schema_version: Literal["1.0"] = "1.0"
    normalized_target: str = Field(min_length=1)
    baseline: ComparisonReportMetadata
    current: ComparisonReportMetadata
    compared_at: datetime
    summary: ComparisonSummary
    findings: list[FindingComparison] = Field(default_factory=list)

    @field_validator("normalized_target")
    @classmethod
    def normalize_comparison_target(cls, value: str) -> str:
        """Validate and canonicalize the comparison target."""

        try:
            return normalize_target(value).url
        except TargetValidationError as exc:
            raise ValueError("Comparison target is invalid.") from exc

    @field_validator("compared_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        """Require a timezone-aware timestamp and normalize it to UTC."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Comparison timestamp must include a timezone.")

        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_findings_and_summary(self) -> Self:
        """Validate entry identity, uniqueness, and exact summary counters."""

        fingerprints: set[str] = set()
        counts = {status: 0 for status in ComparisonStatus}

        for comparison in self.findings:
            if comparison.fingerprint in fingerprints:
                raise ValueError("Comparison contains a duplicate fingerprint.")
            fingerprints.add(comparison.fingerprint)
            counts[comparison.status] += 1

            for finding in (
                comparison.baseline_finding,
                comparison.current_finding,
            ):
                if finding is None:
                    continue
                if (
                    finding_fingerprint(self.normalized_target, finding)
                    != comparison.fingerprint
                ):
                    raise ValueError(
                        "Comparison fingerprint does not match its finding snapshot."
                    )

        expected = {
            ComparisonStatus.ADDED: self.summary.added,
            ComparisonStatus.RESOLVED: self.summary.resolved,
            ComparisonStatus.CHANGED: self.summary.changed,
            ComparisonStatus.UNCHANGED: self.summary.unchanged,
        }
        if counts != expected:
            raise ValueError("Comparison summary does not match finding entries.")

        return self


_STATUS_ORDER = {
    ComparisonStatus.ADDED: 0,
    ComparisonStatus.RESOLVED: 1,
    ComparisonStatus.CHANGED: 2,
    ComparisonStatus.UNCHANGED: 3,
}


def _validated_report(report: ScanReport, source: str) -> ScanReport:
    """Revalidate an input report without exposing its arbitrary contents."""

    if not isinstance(report, ScanReport):
        raise ComparisonInputError(f"{source} input must be a ScanReport.")

    try:
        return ScanReport.model_validate(report.model_dump(mode="python"))
    except ValidationError as exc:
        raise ComparisonInputError(f"{source} scan report is invalid.") from exc


def _canonical_report_target(report: ScanReport, source: str) -> str:
    """Return a validated canonical target for a source report."""

    try:
        return normalize_target(report.target.normalized_url).url
    except TargetValidationError as exc:
        raise ComparisonInputError(
            f"{source} scan report has an invalid normalized target."
        ) from exc


def _index_findings(
    findings: Iterable[Finding],
    normalized_target: str,
    source: str,
) -> dict[str, Finding]:
    """Index deep finding snapshots and reject duplicate identities."""

    indexed: dict[str, Finding] = {}
    for finding in findings:
        fingerprint = finding_fingerprint(normalized_target, finding)
        if fingerprint in indexed:
            raise DuplicateFindingFingerprintError(
                f"{source} scan report contains duplicate finding identities."
            )
        indexed[fingerprint] = finding.model_copy(deep=True)
    return indexed


def _comparison_status(
    baseline_finding: Finding | None,
    current_finding: Finding | None,
) -> ComparisonStatus:
    """Classify one finding identity from its available snapshots."""

    if baseline_finding is None:
        return ComparisonStatus.ADDED
    if current_finding is None:
        return ComparisonStatus.RESOLVED
    if baseline_finding.model_dump(mode="json") == current_finding.model_dump(
        mode="json"
    ):
        return ComparisonStatus.UNCHANGED
    return ComparisonStatus.CHANGED


def compare_reports(
    baseline: ScanReport,
    current: ScanReport,
    *,
    compared_at: datetime | None = None,
) -> ComparisonReport:
    """Compare two scan reports for the same canonical target."""

    baseline = _validated_report(baseline, "Baseline")
    current = _validated_report(current, "Current")
    baseline_target = _canonical_report_target(baseline, "Baseline")
    current_target = _canonical_report_target(current, "Current")

    if baseline_target != current_target:
        raise ComparisonTargetMismatchError(
            "Baseline and current scan reports represent different targets."
        )

    baseline_findings = _index_findings(
        baseline.findings,
        baseline_target,
        "Baseline",
    )
    current_findings = _index_findings(
        current.findings,
        current_target,
        "Current",
    )
    comparisons: list[FindingComparison] = []

    for fingerprint in baseline_findings.keys() | current_findings.keys():
        baseline_finding = baseline_findings.get(fingerprint)
        current_finding = current_findings.get(fingerprint)
        comparisons.append(
            FindingComparison(
                fingerprint=fingerprint,
                status=_comparison_status(baseline_finding, current_finding),
                baseline_finding=baseline_finding,
                current_finding=current_finding,
            )
        )

    comparisons.sort(
        key=lambda comparison: (
            _STATUS_ORDER[comparison.status],
            comparison.fingerprint,
        )
    )
    counts = {
        status: sum(comparison.status is status for comparison in comparisons)
        for status in ComparisonStatus
    }

    return ComparisonReport(
        normalized_target=baseline_target,
        baseline=ComparisonReportMetadata(
            scan_schema_version=baseline.schema_version,
            lotuswatch_version=baseline.lotuswatch_version,
            scanned_at=baseline.scanned_at,
        ),
        current=ComparisonReportMetadata(
            scan_schema_version=current.schema_version,
            lotuswatch_version=current.lotuswatch_version,
            scanned_at=current.scanned_at,
        ),
        compared_at=compared_at or datetime.now(UTC),
        summary=ComparisonSummary(
            added=counts[ComparisonStatus.ADDED],
            resolved=counts[ComparisonStatus.RESOLVED],
            changed=counts[ComparisonStatus.CHANGED],
            unchanged=counts[ComparisonStatus.UNCHANGED],
        ),
        findings=comparisons,
    )
