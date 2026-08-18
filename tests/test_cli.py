import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

import lotuswatch.cli
from lotuswatch.checks import (
    HeaderObservation,
    RedirectCheckResult,
    RedirectStatus,
    SecurityHeaderCheckResult,
    SecurityHeaderStatus,
    TLSCheckResult,
    TLSStatus,
)
from lotuswatch.cli import app

runner = CliRunner()


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


def successful_tls_result(*, days: int = 90) -> TLSCheckResult:
    return TLSCheckResult(
        passed=True,
        status=TLSStatus.PASSED,
        hostname="example.com",
        port=443,
        tls_version="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        not_after=datetime(2026, 11, 16, tzinfo=UTC),
        days_until_expiry=days,
    )


def successful_header_result() -> SecurityHeaderCheckResult:
    values = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "X-Frame-Options": None,
    }

    return SecurityHeaderCheckResult(
        passed=True,
        status=SecurityHeaderStatus.COMPLETED,
        requested_url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        redirect_count=0,
        headers=[
            HeaderObservation(
                name=name,
                present=value is not None,
                value=value,
            )
            for name, value in values.items()
        ],
    )


def missing_header_result() -> SecurityHeaderCheckResult:
    names = (
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-Frame-Options",
    )

    return SecurityHeaderCheckResult(
        passed=True,
        status=SecurityHeaderStatus.COMPLETED,
        requested_url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        redirect_count=0,
        headers=[
            HeaderObservation(name=name, present=False)
            for name in names
        ],
    )


def stub_successful_checks(monkeypatch) -> None:
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        lambda target: successful_redirect_result(),
    )
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_tls_certificate",
        lambda target: successful_tls_result(),
    )
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_security_headers",
        lambda target, *, endpoint_url=None: successful_header_result(),
    )


def test_help_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Monitor websites" in result.stdout


def test_scan_runs_all_checks_and_renders_sections_in_order(monkeypatch) -> None:
    calls: list[str] = []
    received_endpoint: list[str | None] = []

    def redirect_check(target):
        calls.append("redirect")
        return successful_redirect_result()

    def tls_check(target):
        calls.append("tls")
        return successful_tls_result()

    def header_check(target, *, endpoint_url=None):
        calls.append("headers")
        received_endpoint.append(endpoint_url)
        return successful_header_result()

    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        redirect_check,
    )
    monkeypatch.setattr(lotuswatch.cli, "check_tls_certificate", tls_check)
    monkeypatch.setattr(lotuswatch.cli, "check_security_headers", header_check)

    result = runner.invoke(app, ["scan", "EXAMPLE.COM"])

    assert result.exit_code == 0
    assert calls == ["redirect", "tls", "headers"]
    assert received_endpoint == ["https://example.com/"]
    assert "EXAMPLE.COM" in result.stdout
    assert "https://example.com/" in result.stdout
    assert result.stdout.index("HTTP to HTTPS redirect") < result.stdout.index(
        "TLS certificate"
    )
    assert result.stdout.index("TLS certificate") < result.stdout.index(
        "HTTP security headers"
    )
    assert result.stdout.index("HTTP security headers") < result.stdout.index(
        "Scan summary"
    )
    assert "Checks completed: 3/3" in result.stdout
    assert "Findings: 0" in result.stdout


def test_scan_rejects_unsupported_scheme() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    output = result.stdout + result.stderr

    assert result.exit_code == 2
    assert "Only HTTP and HTTPS" in output
    assert "Traceback" not in output


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


def test_scan_writes_all_check_results_to_json(
    monkeypatch,
    tmp_path: Path,
) -> None:
    stub_successful_checks(monkeypatch)
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
    assert report["summary"]["checks_completed"] == 3
    assert report["summary"]["findings_total"] == 0
    assert [check["name"] for check in report["checks"]] == [
        "http_to_https_redirect",
        "tls_certificate",
        "http_security_headers",
    ]


def test_controlled_errors_do_not_stop_independent_checks(monkeypatch) -> None:
    calls: list[str] = []

    def redirect_check(target):
        calls.append("redirect")
        return RedirectCheckResult(
            passed=False,
            status=RedirectStatus.TIMEOUT,
            initial_url="http://example.com/",
            final_url="http://example.com/",
            redirect_count=0,
            error="The HTTP request timed out.",
        )

    def tls_check(target):
        calls.append("tls")
        return TLSCheckResult(
            passed=False,
            status=TLSStatus.CONNECTION_ERROR,
            hostname="example.com",
            port=443,
            error="TLS connection failed.",
        )

    def header_check(target, *, endpoint_url=None):
        calls.append("headers")
        return SecurityHeaderCheckResult(
            passed=False,
            status=SecurityHeaderStatus.CONNECTION_ERROR,
            requested_url="https://example.com/",
            final_url="https://example.com/",
            error="Security-header connection failed.",
        )

    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        redirect_check,
    )
    monkeypatch.setattr(lotuswatch.cli, "check_tls_certificate", tls_check)
    monkeypatch.setattr(lotuswatch.cli, "check_security_headers", header_check)

    result = runner.invoke(app, ["scan", "example.com"])

    assert result.exit_code == 0
    assert calls == ["redirect", "tls", "headers"]
    assert result.stdout.count("ERROR") == 3
    assert "Checks completed: 0/3" in result.stdout
    assert "Traceback" not in result.stdout + result.stderr


def test_json_report_collects_multiple_findings_and_summary_counts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        lambda target: RedirectCheckResult(
            passed=False,
            status=RedirectStatus.NO_HTTPS_REDIRECT,
            initial_url="http://example.com/",
            final_url="http://example.com/",
            redirect_count=0,
            initial_status_code=200,
            final_status_code=200,
        ),
    )
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_tls_certificate",
        lambda target: successful_tls_result(days=14),
    )
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_security_headers",
        lambda target, *, endpoint_url=None: missing_header_result(),
    )
    report_path = tmp_path / "report.json"

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

    assert result.exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    finding_ids = [finding["id"] for finding in report["findings"]]

    assert len(report["checks"]) == 3
    assert report["summary"]["checks_completed"] == len(report["checks"])
    assert report["summary"]["findings_total"] == len(report["findings"]) == 8
    assert finding_ids == [
        "LW-HTTP-001",
        "LW-TLS-002",
        "LW-HEADER-001",
        "LW-HEADER-003",
        "LW-HEADER-004",
        "LW-HEADER-005",
        "LW-HEADER-006",
        "LW-HEADER-007",
    ]
    assert "Severity: critical 0, high 0, medium 5, low 2, info 1" in result.stdout


def test_scan_does_not_overwrite_existing_report(
    monkeypatch,
    tmp_path: Path,
) -> None:
    stub_successful_checks(monkeypatch)
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
