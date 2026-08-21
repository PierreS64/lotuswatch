import json
from datetime import UTC, datetime
from pathlib import Path

from rich.text import Text
from typer.testing import CliRunner, Result

import lotuswatch.cli
import lotuswatch.notifications
import lotuswatch.scanner
import lotuswatch.storage
from lotuswatch import __version__
from lotuswatch.checks import (
    CAACheckResult,
    CAACheckStatus,
    CAARecord,
    DMARCPolicy,
    DNSQueryResult,
    DNSQueryStatus,
    DNSRecordType,
    DNSRecordValue,
    EmailDNSCheckResult,
    EmailDNSStatus,
    HeaderObservation,
    RedirectCheckResult,
    RedirectStatus,
    SecurityHeaderCheckResult,
    SecurityHeaderStatus,
    TLSCheckResult,
    TLSStatus,
)
from lotuswatch.cli import app
from lotuswatch.models import Finding, Severity

runner = CliRunner()


def plain_output(result: Result) -> str:
    """Return combined CLI output without terminal styling sequences."""

    return Text.from_ansi(result.stdout + result.stderr).plain


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
        headers=[HeaderObservation(name=name, present=False) for name in names],
    )


def successful_caa_result() -> CAACheckResult:
    return CAACheckResult(
        completed=True,
        status=CAACheckStatus.POLICY_FOUND,
        hostname="example.com",
        queried_names=["example.com."],
        effective_name="example.com.",
        records=[
            CAARecord(
                flags=0,
                tag="issue",
                value="ca.example",
                issuer_critical=False,
                known_tag=True,
            )
        ],
    )


def missing_caa_result() -> CAACheckResult:
    return CAACheckResult(
        completed=True,
        status=CAACheckStatus.NO_POLICY,
        hostname="example.com",
        queried_names=["example.com.", "com."],
    )


def dns_query_result(
    query_name: str,
    *,
    value: str | None = None,
    status: DNSQueryStatus = DNSQueryStatus.ANSWER,
    error: str | None = None,
) -> DNSQueryResult:
    record = DNSRecordValue(value=value) if value is not None else None
    completed = status in {
        DNSQueryStatus.ANSWER,
        DNSQueryStatus.NO_ANSWER,
        DNSQueryStatus.NXDOMAIN,
    }
    return DNSQueryResult(
        completed=completed,
        answered=record is not None,
        status=status,
        query_name=query_name,
        record_type=DNSRecordType.TXT,
        records=[record] if record is not None else [],
        error=error,
    )


def successful_email_dns_result() -> EmailDNSCheckResult:
    spf_record = DNSRecordValue(value="v=spf1 -all")
    dmarc_record = DNSRecordValue(value="v=DMARC1; p=reject")
    return EmailDNSCheckResult(
        completed=True,
        status=EmailDNSStatus.COMPLETED,
        hostname="example.com",
        spf_query=dns_query_result("example.com.", value=spf_record.value),
        dmarc_query=dns_query_result(
            "_dmarc.example.com.",
            value=dmarc_record.value,
        ),
        spf_records=[spf_record],
        dmarc_records=[dmarc_record],
        dmarc_policy=DMARCPolicy.REJECT,
        spf_interpretation_complete=True,
        dmarc_interpretation_complete=True,
    )


def missing_email_dns_result() -> EmailDNSCheckResult:
    return EmailDNSCheckResult(
        completed=True,
        status=EmailDNSStatus.COMPLETED,
        hostname="example.com",
        spf_query=dns_query_result(
            "example.com.",
            status=DNSQueryStatus.NO_ANSWER,
        ),
        dmarc_query=dns_query_result(
            "_dmarc.example.com.",
            status=DNSQueryStatus.NXDOMAIN,
        ),
        spf_interpretation_complete=True,
        dmarc_interpretation_complete=True,
    )


def stub_successful_checks(monkeypatch) -> None:
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_http_to_https_redirect",
        lambda target: successful_redirect_result(),
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_tls_certificate",
        lambda target: successful_tls_result(),
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_security_headers",
        lambda target, *, endpoint_url=None: successful_header_result(),
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_caa_records",
        lambda target: successful_caa_result(),
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_email_dns_records",
        lambda target: successful_email_dns_result(),
    )


def stub_scan_finding(
    monkeypatch,
    severity: Severity,
) -> Finding:
    stub_successful_checks(monkeypatch)
    finding = Finding(
        id="LW-HTTP-001",
        severity=severity,
        title="Synthetic policy finding",
        description="A synthetic finding used for CLI policy tests.",
        evidence={"status": 200},
        recommendation="Review the synthetic finding.",
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "redirect_result_to_finding",
        lambda result: finding,
    )
    return finding


def test_help_command() -> None:
    result = runner.invoke(app, ["--help"])
    output = plain_output(result)

    assert result.exit_code == 0
    assert "Monitor websites" in output
    assert "--version" in output


def test_version_option_has_no_scan_storage_or_secret_side_effects(
    monkeypatch,
) -> None:
    def unexpected_call(*_args, **_kwargs):
        raise AssertionError("version output must not cross a side-effect boundary")

    monkeypatch.setattr(lotuswatch.cli, "execute_scan", unexpected_call)
    monkeypatch.setattr(
        lotuswatch.storage.SQLiteMonitoringStore,
        "initialize",
        unexpected_call,
    )
    monkeypatch.setattr(
        lotuswatch.notifications.EnvironmentSecretProvider,
        "get_secret",
        unexpected_call,
    )

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert plain_output(result).strip() == __version__


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

    def caa_check(target):
        calls.append("caa")
        return successful_caa_result()

    def email_dns_check(target):
        calls.append("email_dns")
        return successful_email_dns_result()

    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_http_to_https_redirect",
        redirect_check,
    )
    monkeypatch.setattr(lotuswatch.scanner, "check_tls_certificate", tls_check)
    monkeypatch.setattr(lotuswatch.scanner, "check_security_headers", header_check)
    monkeypatch.setattr(lotuswatch.scanner, "check_caa_records", caa_check)
    monkeypatch.setattr(lotuswatch.scanner, "check_email_dns_records", email_dns_check)

    result = runner.invoke(app, ["scan", "EXAMPLE.COM"])
    output = plain_output(result)

    assert result.exit_code == 0
    assert calls == ["redirect", "tls", "headers", "caa", "email_dns"]
    assert received_endpoint == ["https://example.com/"]
    assert "EXAMPLE.COM" in output
    assert "https://example.com/" in output
    assert output.index("HTTP to HTTPS redirect") < output.index("TLS certificate")
    assert output.index("TLS certificate") < output.index("HTTP security headers")
    assert output.index("HTTP security headers") < output.index("DNS CAA records")
    assert output.index("DNS CAA records") < output.index("DNS email authentication")
    assert output.index("DNS email authentication") < output.index("Scan summary")
    assert "Checks recorded: 5" in output
    assert "Checks completed: 5/5" in output
    assert "Findings: 0" in output


def test_scan_help_documents_fail_on() -> None:
    result = runner.invoke(app, ["scan", "--help"])
    output = plain_output(result)

    assert result.exit_code == 0
    assert "--fail-on" in output
    assert "Return exit code 1" in output


def test_scan_without_policy_keeps_default_exit_zero(monkeypatch) -> None:
    stub_scan_finding(monkeypatch, Severity.CRITICAL)

    result = runner.invoke(app, ["scan", "example.com"])

    assert result.exit_code == 0


def test_scan_policy_returns_one_after_console_rendering(monkeypatch) -> None:
    stub_scan_finding(monkeypatch, Severity.MEDIUM)

    result = runner.invoke(
        app,
        ["scan", "example.com", "--fail-on", "medium"],
    )
    output = plain_output(result)

    assert result.exit_code == 1
    assert "Scan summary" in output
    assert "Findings: 1" in output
    assert "POLICY FAIL" in output
    assert "medium or higher" in output
    assert output.index("Scan summary") < output.index("POLICY FAIL")


def test_scan_policy_ignores_finding_below_threshold(monkeypatch) -> None:
    stub_scan_finding(monkeypatch, Severity.LOW)

    result = runner.invoke(
        app,
        ["scan", "example.com", "--fail-on", "medium"],
    )

    assert result.exit_code == 0


def test_scan_policy_writes_json_before_exit_one(monkeypatch, tmp_path: Path) -> None:
    stub_scan_finding(monkeypatch, Severity.HIGH)
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
            "--fail-on",
            "high",
        ],
    )
    output = plain_output(result)

    assert result.exit_code == 1
    assert report_path.exists()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["findings_total"] == 1
    assert "Report written" in output
    assert output.index("Report written") < output.index("POLICY FAIL")


def test_scan_rejects_invalid_policy_threshold() -> None:
    result = runner.invoke(
        app,
        ["scan", "example.com", "--fail-on", "urgent"],
    )
    output = plain_output(result)

    assert result.exit_code == 2
    assert "Invalid value for '--fail-on'" in output
    assert "Traceback" not in output


def test_scan_rejects_unsupported_scheme() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    output = plain_output(result)

    assert result.exit_code == 2
    assert "Only HTTP and HTTPS" in output
    assert "Traceback" not in output


def test_json_format_requires_output() -> None:
    result = runner.invoke(
        app,
        ["scan", "example.com", "--format", "json"],
    )

    output = plain_output(result)

    assert result.exit_code == 2
    assert "--output is required" in output


def test_output_requires_json_format(tmp_path: Path) -> None:
    report_path = tmp_path / "report.json"

    result = runner.invoke(
        app,
        ["scan", "example.com", "--output", str(report_path)],
    )

    output = plain_output(result)

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
    output = plain_output(result)

    assert result.exit_code == 0
    assert report_path.exists()
    assert "Report written" in output

    report = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["schema_version"] == "1.0"
    assert report["target"]["input"] == "EXAMPLE.COM"
    assert report["target"]["normalized_url"] == "https://example.com/"
    assert report["summary"]["checks_completed"] == 5
    assert report["summary"]["findings_total"] == 0
    assert [check["name"] for check in report["checks"]] == [
        "http_to_https_redirect",
        "tls_certificate",
        "http_security_headers",
        "dns_caa",
        "dns_email_authentication",
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

    def caa_check(target):
        calls.append("caa")
        return CAACheckResult(
            completed=False,
            status=CAACheckStatus.TIMEOUT,
            hostname="example.com",
            queried_names=["example.com."],
            error="DNS query timed out.",
        )

    def email_dns_check(target):
        calls.append("email_dns")
        return EmailDNSCheckResult(
            completed=False,
            status=EmailDNSStatus.FAILED,
            hostname="example.com",
            spf_query=dns_query_result(
                "example.com.",
                status=DNSQueryStatus.TIMEOUT,
                error="SPF DNS query timed out.",
            ),
            dmarc_query=dns_query_result(
                "_dmarc.example.com.",
                status=DNSQueryStatus.NO_NAMESERVERS,
                error="No DNS nameserver answered DMARC.",
            ),
        )

    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_http_to_https_redirect",
        redirect_check,
    )
    monkeypatch.setattr(lotuswatch.scanner, "check_tls_certificate", tls_check)
    monkeypatch.setattr(lotuswatch.scanner, "check_security_headers", header_check)
    monkeypatch.setattr(lotuswatch.scanner, "check_caa_records", caa_check)
    monkeypatch.setattr(lotuswatch.scanner, "check_email_dns_records", email_dns_check)

    result = runner.invoke(app, ["scan", "example.com"])
    output = plain_output(result)

    assert result.exit_code == 0
    assert calls == ["redirect", "tls", "headers", "caa", "email_dns"]
    assert output.count("ERROR") == 5
    assert "Checks completed: 0/5" in output
    assert "Traceback" not in output

    policy_result = runner.invoke(
        app,
        ["scan", "example.com", "--fail-on", "info"],
    )
    policy_output = plain_output(policy_result)

    assert policy_result.exit_code == 0
    assert policy_output.count("ERROR") == 5
    assert "Checks completed: 0/5" in policy_output
    assert "POLICY FAIL" not in policy_output


def test_json_report_collects_multiple_findings_and_summary_counts(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        lotuswatch.scanner,
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
        lotuswatch.scanner,
        "check_tls_certificate",
        lambda target: successful_tls_result(days=14),
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_security_headers",
        lambda target, *, endpoint_url=None: missing_header_result(),
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_caa_records",
        lambda target: missing_caa_result(),
    )
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_email_dns_records",
        lambda target: missing_email_dns_result(),
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
    output = plain_output(result)

    assert result.exit_code == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    finding_ids = [finding["id"] for finding in report["findings"]]

    assert len(report["checks"]) == 5
    assert report["summary"]["checks_completed"] == len(report["checks"])
    assert report["summary"]["findings_total"] == len(report["findings"]) == 11
    assert finding_ids == [
        "LW-HTTP-001",
        "LW-TLS-002",
        "LW-HEADER-001",
        "LW-HEADER-003",
        "LW-HEADER-004",
        "LW-HEADER-005",
        "LW-HEADER-006",
        "LW-HEADER-007",
        "LW-DNS-001",
        "LW-DNS-003",
        "LW-DNS-005",
    ]
    assert "Severity: critical 0, high 0, medium 5, low 2, info 4" in output


def test_caa_error_does_not_stop_successful_email_dns_check(monkeypatch) -> None:
    stub_successful_checks(monkeypatch)
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_caa_records",
        lambda target: CAACheckResult(
            completed=False,
            status=CAACheckStatus.TIMEOUT,
            hostname="example.com",
            queried_names=["example.com."],
            error="CAA DNS query timed out.",
        ),
    )

    result = runner.invoke(app, ["scan", "example.com"])
    output = plain_output(result)

    assert result.exit_code == 0
    assert "CAA DNS query timed out" in output
    assert "DNS email authentication" in output
    assert "SPF and DMARC observations completed" in output
    assert "Checks completed: 4/5" in output
    assert "Traceback" not in output


def test_email_dns_error_remains_in_json_with_successful_caa(
    monkeypatch,
    tmp_path: Path,
) -> None:
    stub_successful_checks(monkeypatch)
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_email_dns_records",
        lambda target: EmailDNSCheckResult(
            completed=False,
            status=EmailDNSStatus.FAILED,
            hostname="example.com",
            spf_query=dns_query_result(
                "example.com.",
                status=DNSQueryStatus.TIMEOUT,
                error="SPF query timed out.",
            ),
            dmarc_query=dns_query_result(
                "_dmarc.example.com.",
                status=DNSQueryStatus.NO_NAMESERVERS,
                error="DMARC nameservers failed.",
            ),
        ),
    )
    report_path = tmp_path / "partial-report.json"

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
    checks = {check["name"]: check for check in report["checks"]}

    assert report["summary"]["checks_completed"] == 4
    assert checks["dns_caa"]["status"] == "policy_found"
    assert checks["dns_email_authentication"]["status"] == "failed"
    assert checks["dns_email_authentication"]["spf_query"]["status"] == "timeout"


def test_dns_console_bounds_caa_values_and_omits_txt_values(monkeypatch) -> None:
    stub_successful_checks(monkeypatch)
    long_caa_value = "[bold]" + "x" * 200
    caa_records = [
        CAARecord(
            flags=0,
            tag="issue",
            value=long_caa_value if index == 0 else f"ca-{index}.example",
            issuer_critical=False,
            known_tag=True,
        )
        for index in range(6)
    ]
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_caa_records",
        lambda target: CAACheckResult(
            completed=True,
            status=CAACheckStatus.POLICY_FOUND,
            hostname="example.com",
            queried_names=["example.com."],
            effective_name="example.com.",
            records=caa_records,
        ),
    )
    email_result = successful_email_dns_result()
    assert email_result.spf_query is not None
    email_result.spf_query.records[
        0
    ].value = "v=spf1 include:private-mail-provider.example -all"
    email_result.spf_records[0].value = email_result.spf_query.records[0].value
    monkeypatch.setattr(
        lotuswatch.scanner,
        "check_email_dns_records",
        lambda target: email_result,
    )

    result = runner.invoke(app, ["scan", "example.com"])
    output = plain_output(result)

    assert result.exit_code == 0
    assert long_caa_value not in output
    assert "[bold]" in output
    assert "1 additional record(s) not displayed" in output
    assert "private-mail-provider" not in output


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

    output = plain_output(result)

    assert result.exit_code == 2
    assert "already exists" in output
    assert report_path.read_text(encoding="utf-8") == "keep this content"
