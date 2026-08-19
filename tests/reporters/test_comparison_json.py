import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lotuswatch.exceptions import (
    ReportAlreadyExistsError,
    ReportWriteError,
)
from lotuswatch.models import (
    ComparisonReport,
    Finding,
    ScanReport,
    Severity,
    compare_reports,
)
from lotuswatch.reporters import write_json_comparison_report


def make_comparison() -> ComparisonReport:
    finding = Finding(
        id="LW-TEST-001",
        severity=Severity.LOW,
        title="Chính sách bảo mật cần được xem xét",
        description="A synthetic finding used for a comparison writer test.",
        evidence={"z_value": 2, "a_value": 1},
        recommendation="Review the synthetic policy.",
    )
    baseline = ScanReport.create(
        lotuswatch_version="0.1.0-alpha.2",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[],
        findings=[],
        scanned_at=datetime(2026, 8, 18, 8, 0, tzinfo=UTC),
    )
    current = ScanReport.create(
        lotuswatch_version="0.1.0-alpha.3",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[],
        findings=[finding],
        scanned_at=datetime(2026, 8, 19, 8, 0, tzinfo=UTC),
    )
    return compare_reports(
        baseline,
        current,
        compared_at=datetime(2026, 8, 19, 9, 0, tzinfo=UTC),
    )


def test_writes_valid_deterministic_utf8_comparison_json(tmp_path: Path) -> None:
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    comparison = make_comparison()

    returned_path = write_json_comparison_report(comparison, first_path)
    write_json_comparison_report(comparison, second_path)

    first_payload = first_path.read_text(encoding="utf-8")
    assert returned_path == first_path
    assert first_payload == second_path.read_text(encoding="utf-8")
    assert first_payload.endswith("\n")
    assert "Chính sách bảo mật" in first_payload

    data = json.loads(first_payload)
    validated = ComparisonReport.model_validate(data)

    assert validated.comparison_schema_version == "1.0"
    assert validated.summary.added == 1
    assert validated.findings[0].current_finding is not None
    assert list(data) == sorted(data)
    assert list(data["findings"][0]["current_finding"]["evidence"]) == [
        "a_value",
        "z_value",
    ]


def test_does_not_overwrite_existing_comparison_file(tmp_path: Path) -> None:
    output = tmp_path / "comparison.json"
    output.write_text("original content", encoding="utf-8")

    with pytest.raises(ReportAlreadyExistsError):
        write_json_comparison_report(make_comparison(), output)

    assert output.read_text(encoding="utf-8") == "original content"


def test_rejects_missing_comparison_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "missing" / "comparison.json"

    with pytest.raises(ReportWriteError):
        write_json_comparison_report(make_comparison(), output)

    assert not output.exists()
