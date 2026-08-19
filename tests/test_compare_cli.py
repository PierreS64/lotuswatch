import json
from datetime import UTC, datetime
from pathlib import Path

from rich.text import Text
from typer.testing import CliRunner, Result

import lotuswatch.cli
from lotuswatch.cli import app
from lotuswatch.models import (
    ComparisonReport,
    Finding,
    ScanReport,
    Severity,
)
from lotuswatch.reporters import write_json_report

runner = CliRunner()
BASELINE_TIME = datetime(2026, 8, 18, 8, 0, tzinfo=UTC)
CURRENT_TIME = datetime(2026, 8, 19, 8, 0, tzinfo=UTC)


def plain_output(result: Result) -> str:
    return Text.from_ansi(result.stdout + result.stderr).plain


def make_finding(
    finding_id: str,
    *,
    severity: Severity = Severity.LOW,
    title: str | None = None,
    evidence: dict[str, object] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        title=title or f"Finding {finding_id}",
        description=f"Description for {finding_id}.",
        evidence=evidence or {"observed": True},
        recommendation=f"Recommendation for {finding_id}.",
    )


def write_scan_report(
    path: Path,
    findings: list[Finding] | None = None,
    *,
    normalized_url: str = "https://example.com/",
    lotuswatch_version: str = "0.1.0-alpha.3",
    scanned_at: datetime = BASELINE_TIME,
) -> Path:
    report = ScanReport.create(
        lotuswatch_version=lotuswatch_version,
        original_target="example.com",
        normalized_url=normalized_url,
        checks=[],
        findings=findings or [],
        scanned_at=scanned_at,
    )
    return write_json_report(report, path)


def test_compare_help_explains_baseline_and_current_order() -> None:
    result = runner.invoke(app, ["compare", "--help"])
    output = plain_output(result)

    assert result.exit_code == 0
    assert "{baseline} {current}" in output
    assert "older baseline scan report" in output
    assert "newer current scan report" in output
    assert "without running a new scan" in output


def test_compare_renders_all_change_sections(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    unchanged = make_finding("LW-TEST-001")
    changed_before = make_finding(
        "LW-TEST-002",
        severity=Severity.LOW,
        title="Old title",
        evidence={"status": 200},
    )
    changed_after = make_finding(
        "LW-TEST-002",
        severity=Severity.HIGH,
        title="New title",
        evidence={"status": 500},
    )
    resolved = make_finding("LW-TEST-003")
    added = make_finding("LW-TEST-004")
    write_scan_report(baseline_path, [unchanged, changed_before, resolved])
    write_scan_report(
        current_path,
        [added, changed_after, unchanged],
        scanned_at=CURRENT_TIME,
    )

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])
    output = plain_output(result)

    assert result.exit_code == 0
    assert "Target: https://example.com/" in output
    assert "Baseline: 2026-08-18T08:00:00Z" in output
    assert "Current: 2026-08-19T08:00:00Z" in output
    assert "Added: 1" in output
    assert "Resolved: 1" in output
    assert "Changed: 1" in output
    assert "Unchanged: 1" in output
    assert output.index("Added findings (1)") < output.index("Resolved findings (1)")
    assert output.index("Resolved findings (1)") < output.index("Changed findings (1)")
    assert "LW-TEST-004" in output
    assert "LW-TEST-003" in output
    assert "LW-TEST-002" in output
    assert "LW-TEST-001" not in output
    assert 'Severity baseline: "low"' in output
    assert 'Severity current: "high"' in output
    assert 'Evidence baseline: {"status":200}' in output
    assert 'Evidence current: {"status":500}' in output
    assert 'Title baseline: "Old title"' in output
    assert 'Title current: "New title"' in output
    assert "lwfp:v1:sha256:" in output


def test_unchanged_comparison_is_concise(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    unchanged = make_finding("LW-TEST-001", title="Do not list this finding")
    write_scan_report(baseline_path, [unchanged])
    write_scan_report(current_path, [unchanged], scanned_at=CURRENT_TIME)

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])
    output = plain_output(result)

    assert result.exit_code == 0
    assert "PASS No finding changes detected" in output
    assert "Unchanged: 1" in output
    assert "Do not list this finding" not in output
    assert "Added findings (0)" in output
    assert "Resolved findings (0)" in output
    assert "Changed findings (0)" in output


def test_changed_console_values_are_bounded_and_markup_escaped(
    tmp_path: Path,
) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_value = "[bold]" + "x" * 500
    current_value = "[red]" + "y" * 500
    write_scan_report(
        baseline_path,
        [make_finding("LW-TEST-001", evidence={"value": baseline_value})],
    )
    write_scan_report(
        current_path,
        [make_finding("LW-TEST-001", evidence={"value": current_value})],
        scanned_at=CURRENT_TIME,
    )

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])
    output = plain_output(result)

    assert result.exit_code == 0
    assert baseline_value not in output
    assert current_value not in output
    assert "[bold]" in output
    assert "[red]" in output
    assert "..." in output


def test_compare_does_not_run_scan_checks(monkeypatch, tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    write_scan_report(baseline_path)
    write_scan_report(current_path, scanned_at=CURRENT_TIME)

    def unexpected_scan(*args: object, **kwargs: object) -> None:
        raise AssertionError("Comparison attempted to start a network scan.")

    monkeypatch.setattr(lotuswatch.cli, "check_http_to_https_redirect", unexpected_scan)
    monkeypatch.setattr(lotuswatch.cli, "check_tls_certificate", unexpected_scan)
    monkeypatch.setattr(lotuswatch.cli, "check_security_headers", unexpected_scan)
    monkeypatch.setattr(lotuswatch.cli, "check_caa_records", unexpected_scan)
    monkeypatch.setattr(lotuswatch.cli, "check_email_dns_records", unexpected_scan)

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])

    assert result.exit_code == 0


def test_compare_json_format_requires_output() -> None:
    result = runner.invoke(
        app,
        ["compare", "baseline.json", "current.json", "--format", "json"],
    )
    output = plain_output(result)

    assert result.exit_code == 2
    assert "--output is required" in output


def test_compare_output_requires_json_format(tmp_path: Path) -> None:
    output_path = tmp_path / "comparison.json"

    result = runner.invoke(
        app,
        [
            "compare",
            "baseline.json",
            "current.json",
            "--output",
            str(output_path),
        ],
    )
    output = plain_output(result)

    assert result.exit_code == 2
    assert "--output requires --format json" in output
    assert not output_path.exists()


def test_compare_writes_valid_json_report(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output_path = tmp_path / "comparison.json"
    write_scan_report(baseline_path)
    write_scan_report(
        current_path,
        [make_finding("LW-TEST-001")],
        scanned_at=CURRENT_TIME,
    )

    result = runner.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(current_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )
    output = plain_output(result)

    assert result.exit_code == 0
    assert "Comparison report written" in output
    assert "Review this file before sharing" in output
    assert output_path.exists()

    data = json.loads(output_path.read_text(encoding="utf-8"))
    comparison = ComparisonReport.model_validate(data)

    assert comparison.summary.added == 1
    assert comparison.normalized_target == "https://example.com/"


def test_compare_does_not_overwrite_existing_output(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output_path = tmp_path / "comparison.json"
    write_scan_report(baseline_path)
    write_scan_report(current_path, scanned_at=CURRENT_TIME)
    output_path.write_text("keep this content", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(current_path),
            "--format",
            "json",
            "--output",
            str(output_path),
        ],
    )
    output = plain_output(result)

    assert result.exit_code == 2
    assert "already exists" in output
    assert output_path.read_text(encoding="utf-8") == "keep this content"
    assert "Traceback" not in output


def test_compare_reports_missing_input_without_traceback(tmp_path: Path) -> None:
    current_path = tmp_path / "current.json"
    write_scan_report(current_path, scanned_at=CURRENT_TIME)

    result = runner.invoke(
        app,
        ["compare", str(tmp_path / "missing.json"), str(current_path)],
    )
    output = plain_output(result)

    assert result.exit_code == 2
    assert "does not exist" in output
    assert "Traceback" not in output


def test_compare_reports_malformed_input_without_traceback(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_path.write_text('{"schema_version":', encoding="utf-8")
    write_scan_report(current_path, scanned_at=CURRENT_TIME)

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])
    output = plain_output(result)

    assert result.exit_code == 2
    assert "malformed JSON" in output
    assert "Traceback" not in output


def test_compare_reports_incompatible_input_without_traceback(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    baseline_path.write_text('{"schema_version":"2.0"}', encoding="utf-8")
    write_scan_report(current_path, scanned_at=CURRENT_TIME)

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])
    output = plain_output(result)

    assert result.exit_code == 2
    assert "schema version is unsupported" in output
    assert "Traceback" not in output


def test_compare_rejects_different_targets_without_traceback(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    write_scan_report(baseline_path)
    write_scan_report(
        current_path,
        normalized_url="https://other.example/",
        scanned_at=CURRENT_TIME,
    )

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])
    output = plain_output(result)

    assert result.exit_code == 2
    assert "different targets" in output
    assert "Traceback" not in output


def test_compare_rejects_duplicate_identity_without_traceback(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    duplicate = make_finding("LW-TEST-001")
    write_scan_report(baseline_path, [duplicate, duplicate])
    write_scan_report(current_path, scanned_at=CURRENT_TIME)

    result = runner.invoke(app, ["compare", str(baseline_path), str(current_path)])
    output = plain_output(result)

    assert result.exit_code == 2
    assert "duplicate" in output
    assert "finding identities" in output
    assert "Traceback" not in output
