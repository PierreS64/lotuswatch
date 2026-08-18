import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from lotuswatch.exceptions import (
    ReportAlreadyExistsError,
    ReportWriteError,
)
from lotuswatch.models import ScanReport
from lotuswatch.reporters import write_json_report


def make_report() -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.1",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[{"name": "http_to_https_redirect", "passed": True}],
        findings=[],
        scanned_at=datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
    )


def test_writes_valid_utf8_json(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    returned_path = write_json_report(make_report(), output)

    assert returned_path == output
    assert output.exists()

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["schema_version"] == "1.0"
    assert data["target"]["input"] == "example.com"
    assert data["summary"]["checks_completed"] == 1


def test_does_not_overwrite_existing_file(tmp_path: Path) -> None:
    output = tmp_path / "report.json"
    output.write_text("original content", encoding="utf-8")

    with pytest.raises(ReportAlreadyExistsError):
        write_json_report(make_report(), output)

    assert output.read_text(encoding="utf-8") == "original content"


def test_rejects_missing_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "missing" / "report.json"

    with pytest.raises(ReportWriteError):
        write_json_report(make_report(), output)

    assert not output.exists()
