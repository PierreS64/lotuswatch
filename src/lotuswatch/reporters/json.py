import json
from pathlib import Path

from lotuswatch.exceptions import (
    ReportAlreadyExistsError,
    ReportWriteError,
)
from lotuswatch.models import ScanReport


def write_json_report(report: ScanReport, output: Path) -> Path:
    """Write a scan report as UTF-8 JSON without overwriting files."""

    output = Path(output)

    if not output.parent.exists():
        raise ReportWriteError(f"Output directory does not exist: {output.parent}")

    if not output.parent.is_dir():
        raise ReportWriteError(f"Output parent is not a directory: {output.parent}")

    try:
        with output.open("x", encoding="utf-8", newline="\n") as report_file:
            json.dump(
                report.model_dump(mode="json"),
                report_file,
                ensure_ascii=False,
                indent=2,
            )
            report_file.write("\n")
    except FileExistsError as exc:
        raise ReportAlreadyExistsError(f"Report already exists: {output}") from exc
    except OSError as exc:
        raise ReportWriteError(f"Unable to write report: {output}") from exc

    return output
