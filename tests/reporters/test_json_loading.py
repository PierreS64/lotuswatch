import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

import lotuswatch.reporters.json as json_reporter
from lotuswatch.exceptions import (
    ReportCompatibilityError,
    ReportFormatError,
    ReportReadError,
    ReportTooLargeError,
    ReportValidationError,
)
from lotuswatch.models import ScanReport
from lotuswatch.reporters import load_json_report


def valid_report_data() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "lotuswatch_version": "0.1.0-alpha.3",
        "target": {
            "input": "example.com",
            "normalized_url": "https://example.com/",
        },
        "scanned_at": "2026-08-19T08:30:00Z",
        "summary": {
            "checks_completed": 1,
            "findings_total": 0,
        },
        "checks": [
            {
                "name": "http_to_https_redirect",
                "completed": True,
            }
        ],
        "findings": [],
    }


def write_report(path: Path, data: object | None = None) -> bytes:
    document = valid_report_data() if data is None else data
    payload = (json.dumps(document, indent=2) + "\n").encode()
    path.write_bytes(payload)
    return payload


def test_loads_valid_schema_1_report(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    original_payload = write_report(report_path)

    report = load_json_report(report_path)

    assert isinstance(report, ScanReport)
    assert report.schema_version == "1.0"
    assert report.target.normalized_url == "https://example.com/"
    assert report.scanned_at == datetime(2026, 8, 19, 8, 30, tzinfo=UTC)
    assert report_path.read_bytes() == original_payload


def test_rejects_missing_report(tmp_path: Path) -> None:
    report_path = tmp_path / "missing.json"

    with pytest.raises(ReportReadError, match="does not exist"):
        load_json_report(report_path)


def test_rejects_directory_path(tmp_path: Path) -> None:
    with pytest.raises(ReportReadError, match="is not a file"):
        load_json_report(tmp_path)


def test_rejects_unreadable_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "report.json"
    write_report(report_path)

    def raise_permission_error(*args: object, **kwargs: object) -> None:
        raise PermissionError("private operating-system diagnostic")

    monkeypatch.setattr(Path, "open", raise_permission_error)

    with pytest.raises(ReportReadError, match="Unable to read scan report") as error:
        load_json_report(report_path)

    assert "private operating-system diagnostic" not in str(error.value)


def test_rejects_report_larger_than_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "large.json"
    report_path.write_bytes(b"x" * 65)
    monkeypatch.setattr(json_reporter, "MAX_REPORT_SIZE_BYTES", 64)

    with pytest.raises(ReportTooLargeError, match="64-byte limit"):
        load_json_report(report_path)


def test_rechecks_size_during_bounded_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report_path = tmp_path / "report.json"
    write_report(report_path)
    original_stat = Path.stat

    def report_small_size(path: Path, *args: object, **kwargs: object) -> object:
        result = original_stat(path, *args, **kwargs)
        return result.__class__(
            (
                result.st_mode,
                result.st_ino,
                result.st_dev,
                result.st_nlink,
                result.st_uid,
                result.st_gid,
                1,
                result.st_atime,
                result.st_mtime,
                result.st_ctime,
            )
        )

    monkeypatch.setattr(Path, "stat", report_small_size)
    monkeypatch.setattr(json_reporter, "MAX_REPORT_SIZE_BYTES", 64)

    with pytest.raises(ReportTooLargeError, match="64-byte limit"):
        load_json_report(report_path)


def test_rejects_invalid_utf8(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_bytes(b'{"schema_version": "1.0", "value": \xff}')

    with pytest.raises(ReportFormatError, match="not valid UTF-8"):
        load_json_report(report_path)


def test_rejects_malformed_json_without_echoing_contents(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text('{"secret": "TOP-SECRET"', encoding="utf-8")

    with pytest.raises(ReportFormatError, match="malformed JSON") as error:
        load_json_report(report_path)

    assert "TOP-SECRET" not in str(error.value)


@pytest.mark.parametrize(
    "document",
    [
        '{"schema_version": "1.0", "schema_version": "1.0"}',
        '{"schema_version": "1.0", "value": NaN}',
    ],
)
def test_rejects_ambiguous_or_non_standard_json(
    tmp_path: Path,
    document: str,
) -> None:
    report_path = tmp_path / "report.json"
    report_path.write_text(document, encoding="utf-8")

    with pytest.raises(ReportFormatError, match="malformed JSON"):
        load_json_report(report_path)


def test_rejects_non_object_json(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    write_report(report_path, [])

    with pytest.raises(ReportValidationError, match="must contain a JSON object"):
        load_json_report(report_path)


def test_rejects_missing_schema_version(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    data = valid_report_data()
    del data["schema_version"]
    write_report(report_path, data)

    with pytest.raises(ReportCompatibilityError, match="version is missing"):
        load_json_report(report_path)


def test_rejects_unsupported_schema_without_echoing_value(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"
    data = valid_report_data()
    data["schema_version"] = "private-future-version"
    write_report(report_path, data)

    with pytest.raises(
        ReportCompatibilityError, match="version is unsupported"
    ) as error:
        load_json_report(report_path)

    assert "private-future-version" not in str(error.value)


@pytest.mark.parametrize("schema_version", [None, 1, [], {}])
def test_rejects_non_string_schema_version(
    tmp_path: Path,
    schema_version: object,
) -> None:
    report_path = tmp_path / "report.json"
    data = valid_report_data()
    data["schema_version"] = schema_version
    write_report(report_path, data)

    with pytest.raises(ReportCompatibilityError, match="version is unsupported"):
        load_json_report(report_path)


def test_rejects_model_validation_failure_without_echoing_data(
    tmp_path: Path,
) -> None:
    report_path = tmp_path / "report.json"
    data = valid_report_data()
    data["target"] = {
        "input": "TOP-SECRET",
        "normalized_url": "",
    }
    write_report(report_path, data)

    with pytest.raises(
        ReportValidationError, match="does not match schema 1.0"
    ) as error:
        load_json_report(report_path)

    assert "TOP-SECRET" not in str(error.value)
