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
    NotificationChangeStatus,
    NotificationEvent,
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
NOTIFICATION_EXAMPLE = EXAMPLES_ROOT / "notification-event.json"
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
    assert __version__ == "0.1.0b1"


def test_beta_installation_and_database_maintenance_guidance() -> None:
    readme = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    monitoring = (PROJECT_ROOT / "docs" / "monitoring.md").read_text(encoding="utf-8")
    compatibility = (PROJECT_ROOT / "docs" / "compatibility.md").read_text(
        encoding="utf-8"
    )
    publishing = (PROJECT_ROOT / "docs" / "publishing.md").read_text(encoding="utf-8")

    assert "python -m pip install --pre lotuswatch-security" in readme
    assert 'python -m pip install "lotuswatch-security==0.1.0b1"' in readme
    assert 'python -m pip install -e ".[dev]"' in readme
    assert "lotuswatch monitor database check" in readme
    assert "lotuswatch monitor database backup" in readme
    assert "never overwrite" in monitoring.casefold() or "refuses existing" in (
        monitoring.casefold()
    )
    assert "not encrypt" in monitoring.casefold()
    assert "python -m pip install --pre --upgrade lotuswatch-security" in compatibility
    assert "--no-deps" in publishing
    assert "dependencies only from" in publishing


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


def test_synthetic_notification_event_validates_and_matches_comparison() -> None:
    event = NotificationEvent.model_validate_json(
        NOTIFICATION_EXAMPLE.read_text(encoding="utf-8")
    )
    comparison = ComparisonReport.model_validate_json(
        (EXAMPLES_ROOT / "comparison-report.json").read_text(encoding="utf-8")
    )

    assert event.normalized_target == "https://demo.example/"
    assert event.comparison_summary == comparison.summary
    assert event.total_triggering_observations == len(event.observations) == 1
    assert event.truncated is False
    assert event.observations[0].status is NotificationChangeStatus.CHANGED

    comparison_entry = next(
        item
        for item in comparison.findings
        if item.fingerprint == event.observations[0].fingerprint
    )
    assert comparison_entry.status is ComparisonStatus.CHANGED
    assert comparison_entry.current_finding is not None
    assert event.observations[0].finding_id == comparison_entry.current_finding.id
    assert event.observations[0].severity == comparison_entry.current_finding.severity
    assert event.observations[0].title == comparison_entry.current_finding.title

    serialized = NOTIFICATION_EXAMPLE.read_text(encoding="utf-8").casefold()
    assert "evidence" not in serialized
    assert "description" not in serialized
    assert "recommendation" not in serialized
    assert "webhook" not in serialized
    assert "telegram" not in serialized


@pytest.mark.parametrize(
    "filename",
    (*SCAN_EXAMPLES, "comparison-report.json", "notification-event.json"),
)
def test_synthetic_artifacts_contain_no_private_target_data(filename: str) -> None:
    serialized = (EXAMPLES_ROOT / filename).read_text(encoding="utf-8").casefold()

    assert "demo.example" in serialized
    assert "password" not in serialized
    assert "api_key" not in serialized
    assert "access_token" not in serialized


def test_synthetic_monitoring_session_is_safe_and_documents_commands() -> None:
    serialized = MONITORING_EXAMPLE.read_text(encoding="utf-8").casefold()

    assert "0.1.0b1" in serialized
    assert "demo.example" in serialized
    assert "no database file is included" in serialized
    assert "monitor add" in serialized
    assert "monitor run" in serialized
    assert "monitor history" in serialized
    assert "monitor prune" in serialized
    assert "--notify webhook" in serialized
    assert "--notify-on medium" in serialized
    assert "--notification-dry-run" in serialized
    assert "provider request not sent" in serialized
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


def test_repository_contains_no_notification_delivery_artifacts() -> None:
    excluded_directories = {".git", ".pytest_cache", ".ruff_cache", ".venv"}
    unsafe_name = re.compile(
        r"(?:webhook|telegram|notification).*(?:response|delivery).*(?:json|log|txt)$",
        re.IGNORECASE,
    )
    discovered: list[Path] = []

    for root, directories, filenames in os.walk(PROJECT_ROOT):
        directories[:] = [
            directory
            for directory in directories
            if directory not in excluded_directories
        ]
        for filename in filenames:
            if unsafe_name.search(filename):
                discovered.append(Path(root, filename).relative_to(PROJECT_ROOT))

    assert discovered == []


def test_repository_contains_no_literal_notification_credentials() -> None:
    excluded_directories = {".git", ".pytest_cache", ".ruff_cache", ".venv"}
    text_endings = {".md", ".py", ".json", ".toml", ".txt", ".yml", ".yaml"}
    bot_token = re.compile(r"\b[1-9][0-9]{4,19}:[A-Za-z0-9_-]{20,128}\b")
    secret_assignment = re.compile(
        r"LOTUSWATCH_(?:WEBHOOK_URL|WEBHOOK_SECRET|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID)\s*=\s*\S+"
    )
    discovered: list[Path] = []

    for root, directories, filenames in os.walk(PROJECT_ROOT):
        directories[:] = [
            directory
            for directory in directories
            if directory not in excluded_directories
        ]
        for filename in filenames:
            path = Path(root, filename)
            if path.suffix.casefold() not in text_endings:
                continue
            text = path.read_text(encoding="utf-8")
            if bot_token.search(text) or secret_assignment.search(text):
                discovered.append(path.relative_to(PROJECT_ROOT))

    assert discovered == []


@pytest.mark.parametrize(
    "relative_path",
    [
        "README.md",
        "SECURITY.md",
        "docs/ci.md",
        "docs/compatibility.md",
        "docs/monitoring.md",
        "docs/publishing.md",
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
