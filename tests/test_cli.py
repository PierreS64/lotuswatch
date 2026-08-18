import json
from pathlib import Path

from typer.testing import CliRunner

import lotuswatch.cli
from lotuswatch.checks import RedirectCheckResult, RedirectStatus
from lotuswatch.cli import app

runner = CliRunner()


def test_help_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Monitor websites" in result.stdout


def test_scan_accepts_and_normalizes_target(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        lambda target: successful_redirect_result(),
    )

    result = runner.invoke(app, ["scan", "EXAMPLE.COM"])

    assert result.exit_code == 0
    assert "EXAMPLE.COM" in result.stdout
    assert "https://example.com/" in result.stdout
    assert "PASS" in result.stdout


def test_scan_rejects_unsupported_scheme() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    output = result.stdout + result.stderr

    assert result.exit_code == 2
    assert "Only HTTP and HTTPS" in output
    assert "Traceback" not in output


def successful_redirect_result() -> RedirectCheckResult:
    return RedirectCheckResult(
        passed=True,
        status=RedirectStatus.PASSED,
        initial_url="http://example.com/",
        final_url="https://example.com/",
        redirect_count=1,
        initial_status_code=301,
        final_status_code=200,
    )


def test_json_format_requires_output() -> None:
    result = runner.invoke(
        app,
        ["scan", "example.com", "--format", "json"],
    )

    output = result.stdout + result.stderr

    assert result.exit_code == 2
    assert "--output is required" in output


def test_output_requires_json_format(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["scan", "example.com", "--output", str(report_path)],
    )

    output = result.stdout + result.stderr

    assert result.exit_code == 2
    assert "--output requires --format json" in output
    assert not report_path.exists()


def test_scan_writes_json_report(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        lambda target: successful_redirect_result(),
    )

    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        [
            "scan",
            "EXAMPLE.COM",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    assert result.exit_code == 0
    assert report_path.exists()
    assert "Report written" in result.stdout

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["schema_version"] == "1.0"
    assert report["target"]["input"] == "EXAMPLE.COM"
    assert report["target"]["normalized_url"] == "https://example.com/"
    assert report["summary"]["checks_completed"] == 1
    assert report["summary"]["findings_total"] == 0
    assert report["checks"][0]["name"] == "http_to_https_redirect"


def test_scan_does_not_overwrite_existing_report(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        lambda target: successful_redirect_result(),
    )

    report_path = tmp_path / "report.json"
    report_path.write_text("keep this content", encoding="utf-8")

    result = runner.invoke(
        app,
        [
            "scan",
            "example.com",
            "--format",
            "json",
            "--output",
            str(report_path),
        ],
    )

    output = result.stdout + result.stderr

    assert result.exit_code == 2
    assert "already exists" in output
    assert report_path.read_text(encoding="utf-8") == "keep this content"
