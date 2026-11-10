"""Tests for the offline Markdown security triage output."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lotuswatch.cli import app
from lotuswatch.exceptions import ReportAlreadyExistsError, ReportWriteError
from lotuswatch.models import Finding, ScanReport, Severity, compare_reports
from lotuswatch.reporters import (
    render_markdown_triage_report,
    write_json_report,
    write_markdown_triage_report,
)

runner = CliRunner()
BASE = datetime(2026, 11, 10, 8, 0, tzinfo=UTC)
CURRENT = datetime(2026, 11, 11, 8, 0, tzinfo=UTC)


def finding(
    identifier: str,
    severity: Severity = Severity.LOW,
    *,
    title: str = "Example finding",
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        id=identifier,
        severity=severity,
        title=title,
        description="A synthetic configuration observation.",
        evidence=evidence or {"secret": "never show raw evidence"},
        recommendation="Review the configuration.",
    )


def scan(
    findings: list[Finding],
    *,
    timestamp: datetime,
) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0b1",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[],
        findings=findings,
        scanned_at=timestamp,
    )


def comparison():
    old = scan(
        [
            finding("LW-TEST-001", Severity.LOW, title="Old title"),
            finding("LW-TEST-002"),
            finding("LW-TEST-003"),
        ],
        timestamp=BASE,
    )
    new = scan(
        [
            finding("LW-TEST-001", Severity.HIGH, title="New *title*"),
            finding("LW-TEST-003"),
            finding(
                "LW-TEST-004",
                Severity.CRITICAL,
                title="[click](https://example.net) | <script>alert(1)</script>",
            ),
        ],
        timestamp=CURRENT,
    )
    return compare_reports(old, new, compared_at=CURRENT)


def test_triage_prioritizes_new_and_changed_findings() -> None:
    output = render_markdown_triage_report(comparison())

    assert "| 1 | 1 | 1 | 1 |" in output
    assert output.index("LW-TEST-004") < output.index("LW-TEST-001")
    assert "Current severity:** high" in output
    assert "Baseline severity:** low" in output
    assert "## Resolved findings (1)" in output
    assert "LW-TEST-002" in output
    assert "LW-TEST-003" not in output
    assert "never show raw evidence" not in output


def test_triage_escapes_untrusted_markdown_and_html() -> None:
    output = render_markdown_triage_report(comparison())

    assert r"\[click\]\(https://example" in output
    assert r"\| &lt;script&gt;" in output
    assert "<script>" not in output
    assert r"New \*title\*" in output


def test_empty_triage_is_clear() -> None:
    original = scan([finding("LW-TEST-001")], timestamp=BASE)
    updated = scan([finding("LW-TEST-001")], timestamp=CURRENT)
    output = render_markdown_triage_report(compare_reports(original, updated))
    assert "No added or changed findings." in output
    assert "## Resolved findings (0)" in output


def test_markdown_writer_does_not_overwrite(tmp_path: Path) -> None:
    destination = tmp_path / "triage.md"
    destination.write_text("original", encoding="utf-8")
    with pytest.raises(ReportAlreadyExistsError):
        write_markdown_triage_report(comparison(), destination)
    assert destination.read_text(encoding="utf-8") == "original"


def test_markdown_writer_rejects_nonexistent_directory(tmp_path: Path) -> None:
    with pytest.raises(ReportWriteError):
        write_markdown_triage_report(
            comparison(), tmp_path / "missing" / "triage.md"
        )


def test_compare_markdown_cli(tmp_path: Path) -> None:
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    output = tmp_path / "triage.md"
    write_json_report(
        scan(
            [
                finding("LW-TEST-001", Severity.LOW, title="Old title"),
                finding("LW-TEST-002"),
                finding("LW-TEST-003"),
            ],
            timestamp=BASE,
        ),
        before,
    )
    write_json_report(
        scan(
            [
                finding("LW-TEST-001", Severity.HIGH, title="New *title*"),
                finding("LW-TEST-003"),
                finding(
                    "LW-TEST-004",
                    Severity.CRITICAL,
                    title="[click](https://example.net) | <script>alert(1)</script>",
                ),
            ],
            timestamp=CURRENT,
        ),
        after,
    )
    result = runner.invoke(
        app,
        [
            "compare", str(before), str(after), "--format", "markdown",
            "-o", str(output),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Comparison report written" in result.output
    assert "## Findings requiring review (2)" in output.read_text(
        encoding="utf-8"
    )


def test_compare_markdown_requires_output() -> None:
    result = runner.invoke(
        app, ["compare", "old.json", "new.json", "--format", "markdown"]
    )
    assert result.exit_code == 2
    assert "--output is required" in result.output


def test_compare_markdown_respects_policy(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"
    destination = tmp_path / "triage.md"
    write_json_report(scan([], timestamp=BASE), baseline)
    write_json_report(
        scan([finding("LW-TEST-004", Severity.HIGH)], timestamp=CURRENT),
        current,
    )
    result = runner.invoke(
        app,
        [
            "compare", str(baseline), str(current), "--format", "markdown",
            "--output", str(destination), "--fail-on", "high",
        ],
    )
    assert result.exit_code == 1, result.output
    assert destination.exists()
    assert "POLICY FAIL" in result.output
