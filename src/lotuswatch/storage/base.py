from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Protocol, Self, runtime_checkable
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lotuswatch.models import ScanReport

DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1_000


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _normalize_utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Monitoring timestamp must include a timezone.")

    return value.astimezone(UTC)


class MonitoredTarget(BaseModel):
    """Backend-neutral stored monitoring target."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: UUID
    name: str = Field(min_length=1, max_length=100)
    original_target: str = Field(min_length=1, max_length=4_096)
    normalized_url: str = Field(min_length=1, max_length=4_096)
    enabled: bool = True
    created_at: datetime
    updated_at: datetime

    @field_validator("created_at", "updated_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        return _normalize_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_timestamp_order(self) -> Self:
        if self.updated_at < self.created_at:
            raise ValueError("Target update timestamp cannot precede creation.")
        return self

    @classmethod
    def create(
        cls,
        *,
        name: str,
        original_target: str,
        normalized_url: str,
        enabled: bool = True,
        target_id: UUID | None = None,
        created_at: datetime | None = None,
    ) -> Self:
        timestamp = created_at or _utc_now()
        return cls(
            id=target_id or uuid4(),
            name=name,
            original_target=original_target,
            normalized_url=normalized_url,
            enabled=enabled,
            created_at=timestamp,
            updated_at=timestamp,
        )


class ScanRunMetadata(BaseModel):
    """Backend-neutral metadata for one stored scan run."""

    model_config = ConfigDict(extra="forbid")

    id: UUID
    target_id: UUID
    report_schema_version: str = Field(min_length=1, max_length=32)
    lotuswatch_version: str = Field(min_length=1, max_length=100)
    scanned_at: datetime
    stored_at: datetime

    @field_validator("scanned_at", "stored_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        return _normalize_utc_timestamp(value)


class StoredScanRun(BaseModel):
    """Validated scan report and metadata stored as one logical run."""

    model_config = ConfigDict(extra="forbid")

    metadata: ScanRunMetadata
    report: ScanReport

    @model_validator(mode="after")
    def validate_report_metadata(self) -> Self:
        if self.metadata.report_schema_version != self.report.schema_version:
            raise ValueError("Stored report schema metadata does not match the report.")
        if self.metadata.lotuswatch_version != self.report.lotuswatch_version:
            raise ValueError("Stored LotusWatch version does not match the report.")
        if self.metadata.scanned_at != self.report.scanned_at:
            raise ValueError("Stored scan timestamp does not match the report.")
        return self

    @classmethod
    def create(
        cls,
        *,
        target_id: UUID,
        report: ScanReport,
        run_id: UUID | None = None,
        stored_at: datetime | None = None,
    ) -> Self:
        validated_report = ScanReport.model_validate(report.model_dump(mode="python"))
        return cls(
            metadata=ScanRunMetadata(
                id=run_id or uuid4(),
                target_id=target_id,
                report_schema_version=validated_report.schema_version,
                lotuswatch_version=validated_report.lotuswatch_version,
                scanned_at=validated_report.scanned_at,
                stored_at=stored_at or _utc_now(),
            ),
            report=validated_report,
        )


@runtime_checkable
class MonitoringStore(Protocol):
    """Storage contract consumed by monitoring application workflows."""

    def initialize(self) -> None:
        """Initialize or validate the backing store schema."""

    def create_target(self, target: MonitoredTarget) -> MonitoredTarget:
        """Persist a new monitoring target."""

    def get_target(self, target_id: UUID) -> MonitoredTarget | None:
        """Load a target by identifier."""

    def get_target_by_name(self, name: str) -> MonitoredTarget | None:
        """Load a target by its unique profile name."""

    def list_targets(
        self,
        *,
        limit: int = DEFAULT_QUERY_LIMIT,
    ) -> list[MonitoredTarget]:
        """List stored targets in deterministic name order."""

    def set_target_enabled(
        self,
        target_id: UUID,
        *,
        enabled: bool,
        updated_at: datetime | None = None,
    ) -> MonitoredTarget | None:
        """Update target state without deleting its history."""

    def save_scan_run(self, run: StoredScanRun) -> StoredScanRun:
        """Persist a validated scan run atomically."""

    def get_scan_run(self, run_id: UUID) -> StoredScanRun | None:
        """Load one validated scan run by identifier."""

    def list_scan_runs(
        self,
        target_id: UUID,
        *,
        limit: int = DEFAULT_QUERY_LIMIT,
    ) -> list[ScanRunMetadata]:
        """List bounded run metadata in newest-first order."""

    def get_latest_scan_run(self, target_id: UUID) -> StoredScanRun | None:
        """Load the newest stored run for one target."""

    def count_scan_runs(self, target_id: UUID) -> int:
        """Count stored runs for one target."""

    def preview_scan_run_prune(
        self,
        target_id: UUID,
        *,
        keep: int,
    ) -> list[UUID]:
        """Return the deterministic run identifiers eligible for pruning."""

    def delete_scan_runs(
        self,
        target_id: UUID,
        run_ids: Sequence[UUID],
        *,
        expected_total: int | None = None,
    ) -> int:
        """Delete exactly the selected runs while preserving one run."""


__all__ = [
    "DEFAULT_QUERY_LIMIT",
    "MAX_QUERY_LIMIT",
    "MonitoredTarget",
    "MonitoringStore",
    "ScanRunMetadata",
    "StoredScanRun",
]
