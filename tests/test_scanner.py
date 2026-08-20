from dataclasses import dataclass, field
from datetime import UTC, datetime

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
from lotuswatch.models import ScanReport
from lotuswatch.scanner import execute_scan
from lotuswatch.target import NormalizedTarget, normalize_target


@dataclass
class StubScanCheckRunner:
    redirect_result: RedirectCheckResult
    tls_result: TLSCheckResult
    header_result: SecurityHeaderCheckResult
    caa_result: CAACheckResult
    email_dns_result: EmailDNSCheckResult
    calls: list[str] = field(default_factory=list)
    header_endpoints: list[str | None] = field(default_factory=list)

    def check_redirect(self, target: NormalizedTarget) -> RedirectCheckResult:
        self.calls.append("redirect")
        return self.redirect_result

    def check_tls(self, target: NormalizedTarget) -> TLSCheckResult:
        self.calls.append("tls")
        return self.tls_result

    def check_headers(
        self,
        target: NormalizedTarget,
        *,
        endpoint_url: str | None,
    ) -> SecurityHeaderCheckResult:
        self.calls.append("headers")
        self.header_endpoints.append(endpoint_url)
        return self.header_result

    def check_caa(self, target: NormalizedTarget) -> CAACheckResult:
        self.calls.append("caa")
        return self.caa_result

    def check_email_dns(self, target: NormalizedTarget) -> EmailDNSCheckResult:
        self.calls.append("email_dns")
        return self.email_dns_result


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


def successful_runner() -> StubScanCheckRunner:
    header_values = {
        "Strict-Transport-Security": "max-age=31536000",
        "Content-Security-Policy": "frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=()",
        "X-Frame-Options": None,
    }
    spf_record = DNSRecordValue(value="v=spf1 -all")
    dmarc_record = DNSRecordValue(value="v=DMARC1; p=reject")

    return StubScanCheckRunner(
        redirect_result=RedirectCheckResult(
            passed=True,
            status=RedirectStatus.PASSED,
            initial_url="http://example.com/",
            final_url="https://example.com/",
            redirect_count=1,
            initial_status_code=301,
            final_status_code=200,
        ),
        tls_result=TLSCheckResult(
            passed=True,
            status=TLSStatus.PASSED,
            hostname="example.com",
            port=443,
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            not_after=datetime(2027, 1, 1, tzinfo=UTC),
            days_until_expiry=90,
        ),
        header_result=SecurityHeaderCheckResult(
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
                for name, value in header_values.items()
            ],
        ),
        caa_result=CAACheckResult(
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
        ),
        email_dns_result=EmailDNSCheckResult(
            completed=True,
            status=EmailDNSStatus.COMPLETED,
            hostname="example.com",
            spf_query=dns_query_result(
                "example.com.",
                value=spf_record.value,
            ),
            dmarc_query=dns_query_result(
                "_dmarc.example.com.",
                value=dmarc_record.value,
            ),
            spf_records=[spf_record],
            dmarc_records=[dmarc_record],
            dmarc_policy=DMARCPolicy.REJECT,
            spf_interpretation_complete=True,
            dmarc_interpretation_complete=True,
        ),
    )


def test_execute_scan_runs_in_order_and_builds_valid_report() -> None:
    runner = successful_runner()
    target = normalize_target("EXAMPLE.COM")
    scanned_at = datetime(2026, 8, 19, 15, 0, tzinfo=UTC)

    result = execute_scan(
        target,
        lotuswatch_version="0.1.0-alpha.4",
        runner=runner,
        scanned_at=scanned_at,
    )

    assert runner.calls == ["redirect", "tls", "headers", "caa", "email_dns"]
    assert runner.header_endpoints == ["https://example.com/"]
    assert result.normalized_target == target
    assert result.recorded_checks == result.completed_checks == 5
    assert result.findings == []
    assert [check["name"] for check in result.checks] == [
        "http_to_https_redirect",
        "tls_certificate",
        "http_security_headers",
        "dns_caa",
        "dns_email_authentication",
    ]
    assert result.report.scanned_at == scanned_at
    assert result.report.target.input == "EXAMPLE.COM"
    assert result.report.target.normalized_url == "https://example.com/"
    assert result.report.summary.checks_completed == 5
    assert result.report.summary.findings_total == 0
    assert ScanReport.model_validate(result.report.model_dump()) == result.report


def test_execute_scan_continues_after_controlled_errors() -> None:
    runner = StubScanCheckRunner(
        redirect_result=RedirectCheckResult(
            passed=False,
            status=RedirectStatus.TIMEOUT,
            initial_url="http://example.com/",
            final_url="http://example.com/",
            redirect_count=0,
            error="HTTP request timed out.",
        ),
        tls_result=TLSCheckResult(
            passed=False,
            status=TLSStatus.CONNECTION_ERROR,
            hostname="example.com",
            port=443,
            error="TLS connection failed.",
        ),
        header_result=SecurityHeaderCheckResult(
            passed=False,
            status=SecurityHeaderStatus.CONNECTION_ERROR,
            requested_url="https://example.com/",
            final_url="https://example.com/",
            error="Header request failed.",
        ),
        caa_result=CAACheckResult(
            completed=False,
            status=CAACheckStatus.TIMEOUT,
            hostname="example.com",
            queried_names=["example.com."],
            error="CAA query timed out.",
        ),
        email_dns_result=EmailDNSCheckResult(
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
                error="No DMARC nameserver answered.",
            ),
        ),
    )

    result = execute_scan(
        normalize_target("example.com"),
        lotuswatch_version="0.1.0-alpha.4",
        runner=runner,
    )

    assert runner.calls == ["redirect", "tls", "headers", "caa", "email_dns"]
    assert runner.header_endpoints == [None]
    assert result.recorded_checks == 5
    assert result.completed_checks == 0
    assert result.findings == []
    assert result.report.summary.checks_completed == 0
    assert [check["status"] for check in result.checks] == [
        "timeout",
        "connection_error",
        "connection_error",
        "timeout",
        "failed",
    ]


def test_execute_scan_aggregates_findings_and_summary() -> None:
    runner = successful_runner()
    runner.redirect_result = RedirectCheckResult(
        passed=False,
        status=RedirectStatus.NO_HTTPS_REDIRECT,
        initial_url="http://example.com/",
        final_url="http://example.com/",
        redirect_count=0,
        initial_status_code=200,
        final_status_code=200,
    )
    runner.tls_result.days_until_expiry = 14
    runner.header_result.headers = [
        HeaderObservation(name=name, present=False)
        for name in (
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
            "X-Frame-Options",
        )
    ]
    runner.caa_result = CAACheckResult(
        completed=True,
        status=CAACheckStatus.NO_POLICY,
        hostname="example.com",
        queried_names=["example.com.", "com."],
    )
    runner.email_dns_result = EmailDNSCheckResult(
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

    result = execute_scan(
        normalize_target("example.com"),
        lotuswatch_version="0.1.0-alpha.4",
        runner=runner,
    )

    finding_ids = [finding.id for finding in result.findings]
    assert result.completed_checks == 5
    assert result.report.summary.findings_total == len(result.findings) == 11
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
