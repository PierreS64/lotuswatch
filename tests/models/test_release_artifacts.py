import json
import os
import re
import tomllib
from pathlib import Path

import pytest

from lotuswatch import __version__
from lotuswatch.checks import CAACheckResult, EmailDNSCheckResult
from lotuswatch.models import (
    ComparisonReport,
    ComparisonStatus,
    ScanReport,
    compare_reports,
)

PROJECT_ROOT = Path(__file__).parents[2]
EXAMPLES_ROOT = PROJECT_ROOT / "examples"
SCAN_EXAMPLES = (
    "sample-report.json",
    "baseline-report.json",
    "current-report.json",
)
MONITORING_EXAMPLE = EXAMPLES_ROOT / "monitoring-session.txt"
DATABASE_FILE_ENDINGS = (
    ".db",
    ".db-journal",
    ".db-shm",
    ".db-wal",
    ".sqlite",
    ".sqlite-journal",
    ".sqlite-shm",
    ".sqlite-wal",
)


def test_version_metadata_matches_package_version() -> None:
    pyproject = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert pyproject["project"]["version"] == __version__
    assert __version__ == "0.1.0-alpha.5"


@pytest.mark.parametrize("filename", SCAN_EXAMPLES)
def test_synthetic_scan_reports_validate(filename: str) -> None:
    report_path = EXAMPLES_ROOT / filename
    report = ScanReport.model_validate_json(report_path.read_text(encoding="utf-8"))

    assert report.lotuswatch_version == __version__
    assert report.summary.checks_completed == len(report.checks)
    assert report.summary.findings_total == len(report.findings)
    assert report.target.normalized_url == "https://demo.example/"


def test_sample_report_validates_and_matches_summary() -> None:
    sample_path = EXAMPLES_ROOT / "sample-report.json"
    sample_data = json.loads(sample_path.read_text(encoding="utf-8"))

    report = ScanReport.model_validate(sample_data)

    assert report.lotuswatch_version == __version__
    assert report.summary.checks_completed == len(report.checks) == 5
    assert report.summary.findings_total == len(report.findings) == 4
    assert report.target.normalized_url == "https://demo.example/"

    check_names = [check["name"] for check in report.checks]
    assert check_names == [
        "http_to_https_redirect",
        "tls_certificate",
        "http_security_headers",
        "dns_caa",
        "dns_email_authentication",
    ]

    caa_data = dict(report.checks[3])
    email_dns_data = dict(report.checks[4])
    caa_data.pop("name")
    email_dns_data.pop("name")

    CAACheckResult.model_validate(caa_data)
    EmailDNSCheckResult.model_validate(email_dns_data)

    serialized = sample_path.read_text(encoding="utf-8").casefold()
    assert "password" not in serialized
    assert "api_key" not in serialized
    assert "demo.example" in serialized


def test_synthetic_comparison_matches_source_reports() -> None:
    baseline = ScanReport.model_validate_json(
        (EXAMPLES_ROOT / "baseline-report.json").read_text(encoding="utf-8")
    )
    current = ScanReport.model_validate_json(
        (EXAMPLES_ROOT / "current-report.json").read_text(encoding="utf-8")
    )
    comparison_path = EXAMPLES_ROOT / "comparison-report.json"
    comparison = ComparisonReport.model_validate_json(
        comparison_path.read_text(encoding="utf-8")
    )

    regenerated = compare_reports(
        baseline,
        current,
        compared_at=comparison.compared_at,
    )

    assert comparison == regenerated
    assert comparison.baseline.lotuswatch_version == __version__
    assert comparison.current.lotuswatch_version == __version__
    assert comparison.summary.model_dump() == {
        "added": 1,
        "resolved": 1,
        "changed": 1,
        "unchanged": 1,
    }
    assert {entry.status for entry in comparison.findings} == set(ComparisonStatus)


@pytest.mark.parametrize(
    "filename",
    (*SCAN_EXAMPLES, "comparison-report.json"),
)
def test_synthetic_artifacts_contain_no_private_target_data(filename: str) -> None:
    serialized = (EXAMPLES_ROOT / filename).read_text(encoding="utf-8").casefold()

    assert "demo.example" in serialized
    assert "password" not in serialized
    assert "api_key" not in serialized
    assert "access_token" not in serialized


def test_synthetic_monitoring_session_is_safe_and_documents_commands() -> None:
    serialized = MONITORING_EXAMPLE.read_text(encoding="utf-8").casefold()

    assert "demo.example" in serialized
    assert "no database file is included" in serialized
    assert "monitor add" in serialized
    assert "monitor run" in serialized
    assert "monitor history" in serialized
    assert "monitor prune" in serialized
    assert "password" not in serialized
    assert "api_key" not in serialized
    assert "access_token" not in serialized


def test_repository_contains_no_generated_monitoring_database() -> None:
    excluded_directories = {".git", ".pytest_cache", ".ruff_cache", ".venv"}
    discovered: list[Path] = []

    for root, directories, filenames in os.walk(PROJECT_ROOT):
        directories[:] = [
            directory
            for directory in directories
            if directory not in excluded_directories
        ]
        for filename in filenames:
            if filename.casefold().endswith(DATABASE_FILE_ENDINGS):
                discovered.append(Path(root, filename).relative_to(PROJECT_ROOT))

    assert discovered == []


@pytest.mark.parametrize(
    "relative_path",
    [
        "README.md",
        "SECURITY.md",
        "docs/ci.md",
        "docs/monitoring.md",
        "docs/scope.md",
    ],
)
def test_documentation_links_and_code_fences(relative_path: str) -> None:
    document_path = PROJECT_ROOT / relative_path
    text = document_path.read_text(encoding="utf-8")

    assert text.count("```") % 2 == 0

    for target in re.findall(r"\[[^]]+\]\((?!https?://)([^)#]+)(?:#[^)]*)?\)", text):
        resolved = (document_path.parent / target).resolve()
        assert resolved.exists(), f"Broken relative link in {relative_path}: {target}"
