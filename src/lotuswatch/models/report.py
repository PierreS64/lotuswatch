from datetime import UTC, datetime
from typing import Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
)

from lotuswatch.models.finding import Finding

SCAN_REPORT_SCHEMA_VERSION = "1.0"


class ReportTarget(BaseModel):
    """Target information included in a scan report."""

    model_config = ConfigDict(extra="forbid")

    input: str = Field(min_length=1)
    normalized_url: str = Field(min_length=1)


class ScanSummary(BaseModel):
    """Summary counters for a scan report."""

    model_config = ConfigDict(extra="forbid")

    checks_completed: int = Field(ge=0)
    findings_total: int = Field(ge=0)


class ScanReport(BaseModel):
    """Serializable report produced by a LotusWatch scan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    lotuswatch_version: str = Field(min_length=1)
    target: ReportTarget
    scanned_at: datetime
    summary: ScanSummary
    checks: list[dict[str, JsonValue]] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    @field_validator("scanned_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        """Require a timezone-aware timestamp and normalize it to UTC."""

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Scan timestamp must include a timezone.")

        return value.astimezone(UTC)

    @classmethod
    def create(
        cls,
        *,
        lotuswatch_version: str,
        original_target: str,
        normalized_url: str,
        checks: list[dict[str, JsonValue]],
        findings: list[Finding],
        checks_completed: int | None = None,
        scanned_at: datetime | None = None,
    ) -> Self:
        """Create a report and calculate its summary."""

        completed_count = len(checks) if checks_completed is None else checks_completed

        if not 0 <= completed_count <= len(checks):
            raise ValueError(
                "Completed check count must be between zero and the number "
                "of recorded checks."
            )

        return cls(
            lotuswatch_version=lotuswatch_version,
            target=ReportTarget(
                input=original_target,
                normalized_url=normalized_url,
            ),
            scanned_at=scanned_at or datetime.now(UTC),
            summary=ScanSummary(
                checks_completed=completed_count,
                findings_total=len(findings),
            ),
            checks=checks,
            findings=findings,
        )
