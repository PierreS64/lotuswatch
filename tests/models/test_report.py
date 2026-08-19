from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from lotuswatch.models import Finding, ScanReport, Severity


def make_finding() -> Finding:
    return Finding(
        id="LW-HTTP-001",
        severity=Severity.MEDIUM,
        title="HTTP does not redirect safely to HTTPS",
        description="The HTTP endpoint remains available.",
        evidence={"status_code": 200},
        recommendation="Redirect all HTTP requests to HTTPS.",
    )


def test_creates_report_with_calculated_summary() -> None:
    report = ScanReport.create(
        lotuswatch_version="0.1.0-alpha.1",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[{"name": "http_to_https_redirect", "passed": False}],
        findings=[make_finding()],
        scanned_at=datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
    )

    assert report.schema_version == "1.0"
    assert report.summary.checks_completed == 1
    assert report.summary.findings_total == 1
    assert report.target.input == "example.com"
    assert report.target.normalized_url == "https://example.com/"


def test_serializes_report_to_json_compatible_data() -> None:
    report = ScanReport.create(
        lotuswatch_version="0.1.0-alpha.1",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[],
        findings=[],
        scanned_at=datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
    )

    serialized = report.model_dump(mode="json")

    assert serialized["schema_version"] == "1.0"
    assert serialized["scanned_at"].endswith("Z")
    assert serialized["findings"] == []


def test_accepts_explicit_completed_check_count() -> None:
    report = ScanReport.create(
        lotuswatch_version="0.1.0-alpha.2",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[{"name": "one"}, {"name": "two"}],
        findings=[],
        checks_completed=1,
    )

    assert report.summary.checks_completed == 1


@pytest.mark.parametrize("checks_completed", [-1, 2])
def test_rejects_completed_count_outside_recorded_checks(
    checks_completed: int,
) -> None:
    with pytest.raises(ValueError, match="Completed check count"):
        ScanReport.create(
            lotuswatch_version="0.1.0-alpha.2",
            original_target="example.com",
            normalized_url="https://example.com/",
            checks=[{"name": "one"}],
            findings=[],
            checks_completed=checks_completed,
        )


def test_rejects_naive_timestamp() -> None:
    with pytest.raises(
        ValidationError,
        match="timestamp must include a timezone",
    ):
        ScanReport.create(
            lotuswatch_version="0.1.0-alpha.1",
            original_target="example.com",
            normalized_url="https://example.com/",
            checks=[],
            findings=[],
            scanned_at=datetime(
                2026,
                8,
                18,
                10,
                0,
                tzinfo=UTC,
            ).replace(tzinfo=None),
        )


def test_normalizes_timestamp_to_utc() -> None:
    utc_plus_seven = timezone(timedelta(hours=7))

    report = ScanReport.create(
        lotuswatch_version="0.1.0-alpha.1",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[],
        findings=[],
        scanned_at=datetime(2026, 8, 18, 17, 0, tzinfo=utc_plus_seven),
    )

    assert report.scanned_at == datetime(2026, 8, 18, 10, 0, tzinfo=UTC)
