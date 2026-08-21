from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from lotuswatch.exceptions import TargetValidationError
from lotuswatch.models.comparison import ComparisonSummary
from lotuswatch.models.finding import FINDING_ID_PATTERN, Severity
from lotuswatch.models.fingerprint import finding_id_fingerprint
from lotuswatch.target import normalize_target

NOTIFICATION_EVENT_SCHEMA_VERSION = "1.0"
MAX_NOTIFICATION_OBSERVATIONS = 50
FINGERPRINT_PATTERN = r"^lwfp:v1:sha256:[0-9a-f]{64}$"
PROFILE_NAME_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"

_SEVERITY_ORDER = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def _normalize_utc_timestamp(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Notification timestamp must include a timezone.")
    return value.astimezone(UTC)


class NotificationChangeStatus(StrEnum):
    """Finding changes that can trigger an initial notification policy."""

    ADDED = "added"
    CHANGED = "changed"


class NotificationSelectionReason(StrEnum):
    """Controlled outcomes from notification policy selection."""

    SELECTED = "selected"
    INITIAL_BASELINE = "initial_baseline"
    NO_MATCHING_FINDINGS = "no_matching_findings"


class NotificationObservation(BaseModel):
    """Minimal finding identity included in a notification event."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )

    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    status: NotificationChangeStatus
    finding_id: str = Field(pattern=FINDING_ID_PATTERN)
    severity: Severity
    title: str = Field(min_length=1, max_length=120)


class NotificationEvent(BaseModel):
    """Minimal validated event selected from one monitoring comparison."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        hide_input_in_errors=True,
    )

    notification_schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    generated_at: datetime
    profile_name: str = Field(pattern=PROFILE_NAME_PATTERN)
    normalized_target: str = Field(min_length=1, max_length=4_096)
    run_id: UUID
    scanned_at: datetime
    compared_at: datetime
    threshold: Severity
    comparison_summary: ComparisonSummary
    total_triggering_observations: int = Field(ge=1)
    truncated: bool
    observations: list[NotificationObservation] = Field(
        min_length=1,
        max_length=MAX_NOTIFICATION_OBSERVATIONS,
    )

    @field_validator("normalized_target")
    @classmethod
    def normalize_event_target(cls, value: str) -> str:
        try:
            return normalize_target(value).url
        except TargetValidationError as exc:
            raise ValueError("Notification target is invalid.") from exc

    @field_validator("generated_at", "scanned_at", "compared_at")
    @classmethod
    def normalize_timestamp_to_utc(cls, value: datetime) -> datetime:
        return _normalize_utc_timestamp(value)

    @model_validator(mode="after")
    def validate_observations(self) -> Self:
        available_changes = (
            self.comparison_summary.added + self.comparison_summary.changed
        )
        if self.total_triggering_observations > available_changes:
            raise ValueError(
                "Notification triggering total exceeds added and changed findings."
            )
        if self.total_triggering_observations < len(self.observations):
            raise ValueError(
                "Notification triggering total is smaller than observations."
            )
        if self.truncated is not (
            self.total_triggering_observations > len(self.observations)
        ):
            raise ValueError("Notification truncation state is inconsistent.")

        fingerprints: set[str] = set()
        status_counts = {status: 0 for status in NotificationChangeStatus}
        for observation in self.observations:
            if observation.fingerprint in fingerprints:
                raise ValueError("Notification contains a duplicate fingerprint.")
            fingerprints.add(observation.fingerprint)
            status_counts[observation.status] += 1

            expected_fingerprint = finding_id_fingerprint(
                self.normalized_target,
                observation.finding_id,
            )
            if observation.fingerprint != expected_fingerprint:
                raise ValueError(
                    "Notification fingerprint does not match its finding identity."
                )
            if _SEVERITY_ORDER[observation.severity] < _SEVERITY_ORDER[self.threshold]:
                raise ValueError(
                    "Notification observation does not meet its severity threshold."
                )

        if (
            status_counts[NotificationChangeStatus.ADDED]
            > self.comparison_summary.added
        ):
            raise ValueError("Notification contains too many added observations.")
        if (
            status_counts[NotificationChangeStatus.CHANGED]
            > self.comparison_summary.changed
        ):
            raise ValueError("Notification contains too many changed observations.")

        expected_order = sorted(
            self.observations,
            key=lambda observation: (
                -_SEVERITY_ORDER[observation.severity],
                observation.finding_id,
                observation.fingerprint,
            ),
        )
        if self.observations != expected_order:
            raise ValueError(
                "Notification observations are not deterministically ordered."
            )

        return self


class NotificationSelection(BaseModel):
    """Selected event or an explicit reason why no event was produced."""

    model_config = ConfigDict(extra="forbid")

    reason: NotificationSelectionReason
    event: NotificationEvent | None = None

    @model_validator(mode="after")
    def validate_event_presence(self) -> Self:
        if (self.reason is NotificationSelectionReason.SELECTED) is (
            self.event is None
        ):
            raise ValueError(
                "Notification selection reason and event are inconsistent."
            )
        return self
