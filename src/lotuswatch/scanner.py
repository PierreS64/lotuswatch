from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, JsonValue

from lotuswatch.checks import (
    CAACheckResult,
    EmailDNSCheckResult,
    RedirectCheckResult,
    RedirectStatus,
    SecurityHeaderCheckResult,
    SecurityHeaderStatus,
    TLSCheckResult,
    TLSStatus,
    caa_result_to_findings,
    check_caa_records,
    check_email_dns_records,
    check_http_to_https_redirect,
    check_security_headers,
    check_tls_certificate,
    email_dns_result_to_findings,
    redirect_result_to_finding,
    security_header_result_to_findings,
    tls_result_to_findings,
)
from lotuswatch.models import Finding, ScanReport
from lotuswatch.target import NormalizedTarget


class ScanCheckRunner(Protocol):
    """Check execution contract used by the reusable scan service."""

    def check_redirect(self, target: NormalizedTarget) -> RedirectCheckResult:
        """Inspect HTTP-to-HTTPS redirect behavior."""

    def check_tls(self, target: NormalizedTarget) -> TLSCheckResult:
        """Inspect the target TLS certificate."""

    def check_headers(
        self,
        target: NormalizedTarget,
        *,
        endpoint_url: str | None,
    ) -> SecurityHeaderCheckResult:
        """Inspect selected HTTP security headers."""

    def check_caa(self, target: NormalizedTarget) -> CAACheckResult:
        """Inspect the effective CAA record set."""

    def check_email_dns(self, target: NormalizedTarget) -> EmailDNSCheckResult:
        """Inspect SPF and DMARC observations."""


class DefaultScanCheckRunner:
    """Run the production LotusWatch checks without presentation concerns."""

    def check_redirect(self, target: NormalizedTarget) -> RedirectCheckResult:
        return check_http_to_https_redirect(target)

    def check_tls(self, target: NormalizedTarget) -> TLSCheckResult:
        return check_tls_certificate(target)

    def check_headers(
        self,
        target: NormalizedTarget,
        *,
        endpoint_url: str | None,
    ) -> SecurityHeaderCheckResult:
        return check_security_headers(target, endpoint_url=endpoint_url)

    def check_caa(self, target: NormalizedTarget) -> CAACheckResult:
        return check_caa_records(target)

    def check_email_dns(self, target: NormalizedTarget) -> EmailDNSCheckResult:
        return check_email_dns_records(target)


@dataclass(frozen=True, slots=True)
class ScanExecutionResult:
    """Complete reusable result of one LotusWatch scan execution."""

    normalized_target: NormalizedTarget
    redirect_result: RedirectCheckResult
    redirect_findings: list[Finding]
    tls_result: TLSCheckResult
    tls_findings: list[Finding]
    header_result: SecurityHeaderCheckResult
    header_findings: list[Finding]
    caa_result: CAACheckResult
    caa_findings: list[Finding]
    email_dns_result: EmailDNSCheckResult
    email_dns_findings: list[Finding]
    checks: list[dict[str, JsonValue]]
    completed_checks: int
    findings: list[Finding]
    report: ScanReport

    @property
    def recorded_checks(self) -> int:
        """Return the number of serialized check results."""

        return len(self.checks)


def execute_scan(
    target: NormalizedTarget,
    *,
    lotuswatch_version: str,
    runner: ScanCheckRunner | None = None,
    scanned_at: datetime | None = None,
) -> ScanExecutionResult:
    """Run all checks and return a presentation-independent scan result."""

    check_runner = runner or DefaultScanCheckRunner()

    redirect_result = check_runner.check_redirect(target)
    redirect_finding = redirect_result_to_finding(redirect_result)
    redirect_findings = [redirect_finding] if redirect_finding is not None else []

    tls_result = check_runner.check_tls(target)
    tls_findings = tls_result_to_findings(tls_result)

    header_result = check_runner.check_headers(
        target,
        endpoint_url=_redirect_https_endpoint(target, redirect_result),
    )
    header_findings = security_header_result_to_findings(header_result)

    caa_result = check_runner.check_caa(target)
    caa_findings = caa_result_to_findings(caa_result)

    email_dns_result = check_runner.check_email_dns(target)
    email_dns_findings = email_dns_result_to_findings(email_dns_result)

    findings = (
        redirect_findings
        + tls_findings
        + header_findings
        + caa_findings
        + email_dns_findings
    )
    executed_checks: list[tuple[str, BaseModel, bool]] = [
        (
            "http_to_https_redirect",
            redirect_result,
            redirect_result.status
            not in {RedirectStatus.TIMEOUT, RedirectStatus.CONNECTION_ERROR},
        ),
        (
            "tls_certificate",
            tls_result,
            tls_result.status in {TLSStatus.PASSED, TLSStatus.VERIFICATION_ERROR},
        ),
        (
            "http_security_headers",
            header_result,
            header_result.status is SecurityHeaderStatus.COMPLETED,
        ),
        ("dns_caa", caa_result, caa_result.completed),
        (
            "dns_email_authentication",
            email_dns_result,
            email_dns_result.completed,
        ),
    ]
    checks = [_named_check_data(name, result) for name, result, _ in executed_checks]
    completed_checks = sum(completed for _, _, completed in executed_checks)
    report = ScanReport.create(
        lotuswatch_version=lotuswatch_version,
        original_target=target.original,
        normalized_url=target.url,
        checks=checks,
        findings=findings,
        checks_completed=completed_checks,
        scanned_at=scanned_at,
    )

    return ScanExecutionResult(
        normalized_target=target,
        redirect_result=redirect_result,
        redirect_findings=redirect_findings,
        tls_result=tls_result,
        tls_findings=tls_findings,
        header_result=header_result,
        header_findings=header_findings,
        caa_result=caa_result,
        caa_findings=caa_findings,
        email_dns_result=email_dns_result,
        email_dns_findings=email_dns_findings,
        checks=checks,
        completed_checks=completed_checks,
        findings=findings,
        report=report,
    )


def _redirect_https_endpoint(
    target: NormalizedTarget, result: RedirectCheckResult
) -> str | None:
    parsed = urlsplit(result.final_url)
    if (
        result.passed
        and parsed.scheme.casefold() == "https"
        and parsed.hostname == target.hostname
    ):
        return result.final_url

    return None


def _named_check_data(
    name: str,
    result: BaseModel,
) -> dict[str, JsonValue]:
    data = result.model_dump(mode="json")
    data["name"] = name
    return data


__all__ = [
    "DefaultScanCheckRunner",
    "ScanCheckRunner",
    "ScanExecutionResult",
    "execute_scan",
]
