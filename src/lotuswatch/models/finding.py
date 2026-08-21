from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, JsonValue

FINDING_ID_PATTERN = r"^LW-[A-Z][A-Z0-9_]*-\d{3}$"


class Severity(StrEnum):
    """Severity levels supported by LotusWatch."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A security or configuration issue identified by LotusWatch."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    id: str = Field(
        pattern=FINDING_ID_PATTERN,
        examples=["LW-HTTP-001"],
    )
    severity: Severity
    title: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=1_000)
    evidence: dict[str, JsonValue] = Field(default_factory=dict)
    recommendation: str = Field(min_length=1, max_length=1_000)
    reference: HttpUrl | None = None
