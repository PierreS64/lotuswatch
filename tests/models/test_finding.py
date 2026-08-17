import pytest
from pydantic import ValidationError

from lotuswatch.models import Finding, Severity


def make_finding(**overrides: object) -> Finding:
    """Create a valid finding with optional field overrides."""

    data: dict[str, object] = {
        "id": "LW-HTTP-001",
        "severity": Severity.MEDIUM,
        "title": "HTTP does not redirect to HTTPS",
        "description": "The website remains accessible over HTTP.",
        "evidence": {
            "initial_url": "http://example.com/",
            "status_code": 200,
        },
        "recommendation": "Redirect all HTTP requests to HTTPS.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
    }
    data.update(overrides)

    return Finding.model_validate(data)


@pytest.mark.parametrize(
    "severity",
    [
        Severity.INFO,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.HIGH,
        Severity.CRITICAL,
    ],
)
def test_accepts_supported_severity(severity: Severity) -> None:
    finding = make_finding(severity=severity)

    assert finding.severity is severity


def test_serializes_to_json_compatible_data() -> None:
    finding = make_finding()

    serialized = finding.model_dump(mode="json")

    assert serialized["id"] == "LW-HTTP-001"
    assert serialized["severity"] == "medium"
    assert serialized["evidence"]["status_code"] == 200
    assert isinstance(serialized["reference"], str)


@pytest.mark.parametrize(
    "finding_id",
    [
        "HTTP-001",
        "LW-HTTP",
        "LW-http-001",
        "LW-HTTP-1",
        "LW-HTTP-0001",
        "LW--001",
    ],
)
def test_rejects_invalid_finding_id(finding_id: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(id=finding_id)


def test_rejects_invalid_severity() -> None:
    with pytest.raises(ValidationError):
        make_finding(severity="urgent")


@pytest.mark.parametrize(
    "field",
    [
        "title",
        "description",
        "recommendation",
    ],
)
def test_rejects_empty_required_text(field: str) -> None:
    with pytest.raises(ValidationError):
        make_finding(**{field: "   "})


def test_reference_is_optional() -> None:
    finding = make_finding(reference=None)

    assert finding.reference is None


def test_evidence_defaults_to_empty_dictionary() -> None:
    finding = Finding(
        id="LW-TLS-001",
        severity=Severity.INFO,
        title="TLS check completed",
        description="The TLS configuration check completed successfully.",
        recommendation="No action is currently required.",
    )

    assert finding.evidence == {}


def test_rejects_non_json_evidence() -> None:
    with pytest.raises(ValidationError):
        make_finding(evidence={"raw_data": b"binary data"})


def test_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        make_finding(unexpected_field="unexpected value")


def test_strips_surrounding_whitespace() -> None:
    finding = make_finding(title="  Missing HTTPS redirect  ")

    assert finding.title == "Missing HTTPS redirect"
