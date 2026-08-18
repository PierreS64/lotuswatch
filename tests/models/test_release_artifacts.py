import json
import tomllib
from pathlib import Path

from lotuswatch import __version__
from lotuswatch.models import ScanReport

PROJECT_ROOT = Path(__file__).parents[2]


def test_version_metadata_matches_package_version() -> None:
    pyproject = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert pyproject["project"]["version"] == __version__
    assert __version__ == "0.1.0-alpha.2"


def test_sample_report_validates_and_matches_summary() -> None:
    sample_path = PROJECT_ROOT / "examples" / "sample-report.json"
    sample_data = json.loads(sample_path.read_text(encoding="utf-8"))

    report = ScanReport.model_validate(sample_data)

    assert report.lotuswatch_version == __version__
    assert report.summary.checks_completed == len(report.checks) == 3
    assert report.summary.findings_total == len(report.findings) == 3
    assert report.target.normalized_url == "https://demo.example/"
