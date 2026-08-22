import json
from pathlib import Path
from stat import S_ISREG

from pydantic import BaseModel, ValidationError

from lotuswatch.exceptions import (
    ReportAlreadyExistsError,
    ReportCompatibilityError,
    ReportFormatError,
    ReportReadError,
    ReportTooLargeError,
    ReportValidationError,
    ReportWriteError,
)
from lotuswatch.models import (
    SCAN_REPORT_SCHEMA_VERSION,
    ComparisonReport,
    ScanReport,
)

MAX_REPORT_SIZE_BYTES = 5 * 1024 * 1024
SUPPORTED_SCAN_REPORT_SCHEMA_VERSIONS = frozenset({SCAN_REPORT_SCHEMA_VERSION})


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting ambiguous duplicate keys."""

    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_non_finite_json_number(_value: str) -> None:
    """Reject non-standard JSON constants such as NaN and Infinity."""

    raise ValueError("Non-finite JSON numbers are unsupported.")


def _read_bounded_report_bytes(report_path: Path) -> bytes:
    """Read a regular report file without exceeding the configured size limit."""

    try:
        file_stat = report_path.stat()
    except FileNotFoundError as exc:
        raise ReportReadError(
            f"Scan report file does not exist: {report_path}"
        ) from exc
    except OSError as exc:
        raise ReportReadError(f"Unable to inspect scan report: {report_path}") from exc

    if not S_ISREG(file_stat.st_mode):
        raise ReportReadError(f"Scan report path is not a file: {report_path}")

    if file_stat.st_size > MAX_REPORT_SIZE_BYTES:
        raise ReportTooLargeError(
            f"Scan report exceeds the {MAX_REPORT_SIZE_BYTES}-byte limit: {report_path}"
        )

    try:
        with report_path.open("rb") as report_file:
            payload = report_file.read(MAX_REPORT_SIZE_BYTES + 1)
    except FileNotFoundError as exc:
        raise ReportReadError(
            f"Scan report file does not exist: {report_path}"
        ) from exc
    except IsADirectoryError as exc:
        raise ReportReadError(f"Scan report path is not a file: {report_path}") from exc
    except OSError as exc:
        raise ReportReadError(f"Unable to read scan report: {report_path}") from exc

    if len(payload) > MAX_REPORT_SIZE_BYTES:
        raise ReportTooLargeError(
            f"Scan report exceeds the {MAX_REPORT_SIZE_BYTES}-byte limit: {report_path}"
        )

    return payload


def load_json_report(report_path: Path) -> ScanReport:
    """Load and validate a bounded, versioned LotusWatch scan report."""

    report_path = Path(report_path)
    payload = _read_bounded_report_bytes(report_path)

    try:
        document = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReportFormatError(
            f"Scan report is not valid UTF-8: {report_path}"
        ) from exc

    try:
        report_data = json.loads(
            document,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_non_finite_json_number,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ReportFormatError(
            f"Scan report contains malformed JSON: {report_path}"
        ) from exc

    if not isinstance(report_data, dict):
        raise ReportValidationError(
            f"Scan report must contain a JSON object: {report_path}"
        )

    if "schema_version" not in report_data:
        raise ReportCompatibilityError(
            f"Scan report schema version is missing: {report_path}"
        )

    schema_version = report_data["schema_version"]
    if (
        not isinstance(schema_version, str)
        or schema_version not in SUPPORTED_SCAN_REPORT_SCHEMA_VERSIONS
    ):
        raise ReportCompatibilityError(
            f"Scan report schema version is unsupported: {report_path}"
        )

    try:
        return ScanReport.model_validate(report_data)
    except ValidationError as exc:
        raise ReportValidationError(
            f"Scan report does not match schema 1.0: {report_path}"
        ) from exc


def _write_json_model(
    model: BaseModel,
    output: Path,
    *,
    sort_keys: bool,
) -> Path:
    """Write a Pydantic model as UTF-8 JSON without overwriting files."""

    output = Path(output)

    if not output.parent.exists():
        raise ReportWriteError(f"Output directory does not exist: {output.parent}")

    if not output.parent.is_dir():
        raise ReportWriteError(f"Output parent is not a directory: {output.parent}")

    try:
        with output.open("x", encoding="utf-8", newline="\n") as report_file:
            json.dump(
                model.model_dump(mode="json"),
                report_file,
                ensure_ascii=False,
                indent=2,
                sort_keys=sort_keys,
            )
            report_file.write("\n")
    except FileExistsError as exc:
        raise ReportAlreadyExistsError(f"Report already exists: {output}") from exc
    except OSError as exc:
        raise ReportWriteError(f"Unable to write report: {output}") from exc

    return output


def write_json_report(report: ScanReport, output: Path) -> Path:
    """Write a scan report as UTF-8 JSON without overwriting files."""

    return _write_json_model(report, output, sort_keys=False)


def write_json_comparison_report(
    report: ComparisonReport,
    output: Path,
) -> Path:
    """Write a deterministic comparison report without overwriting files."""

    return _write_json_model(report, output, sort_keys=True)
