import sqlite3
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

import lotuswatch.monitoring
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
from lotuswatch.exceptions import (
    MonitoringComparisonError,
    MonitoringProfileDisabledError,
    MonitoringProfileNotFoundError,
    MonitoringTargetCompatibilityError,
    StoreConflictError,
)
from lotuswatch.models import (
    ComparisonReport,
    Finding,
    ScanReport,
    Severity,
)
from lotuswatch.monitoring import execute_monitoring_run
from lotuswatch.scanner import ScanExecutionResult, execute_scan
from lotuswatch.storage import (
    MonitoredTarget,
    SQLiteMonitoringStore,
    StoredScanRun,
)
from lotuswatch.target import NormalizedTarget, normalize_target


@dataclass
class StubScanCheckRunner:
    redirect_result: RedirectCheckResult
    tls_result: TLSCheckResult
    header_result: SecurityHeaderCheckResult
    caa_result: CAACheckResult
    email_dns_result: EmailDNSCheckResult
    calls: list[str] = field(default_factory=list)

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
        return self.header_result

    def check_caa(self, target: NormalizedTarget) -> CAACheckResult:
        self.calls.append("caa")
        return self.caa_result

    def check_email_dns(self, target: NormalizedTarget) -> EmailDNSCheckResult:
        self.calls.append("email_dns")
        return self.email_dns_result


def dns_query_result(query_name: str, value: str) -> DNSQueryResult:
    return DNSQueryResult(
        completed=True,
        answered=True,
        status=DNSQueryStatus.ANSWER,
        query_name=query_name,
        record_type=DNSRecordType.TXT,
        records=[DNSRecordValue(value=value)],
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
    spf_value = "v=spf1 -all"
    dmarc_value = "v=DMARC1; p=reject"

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
            spf_query=dns_query_result("example.com.", spf_value),
            dmarc_query=dns_query_result(
                "_dmarc.example.com.",
                dmarc_value,
            ),
            spf_records=[DNSRecordValue(value=spf_value)],
            dmarc_records=[DNSRecordValue(value=dmarc_value)],
            dmarc_policy=DMARCPolicy.REJECT,
            spf_interpretation_complete=True,
            dmarc_interpretation_complete=True,
        ),
    )


def initialized_store(tmp_path: Path) -> SQLiteMonitoringStore:
    store = SQLiteMonitoringStore(tmp_path / "monitoring.db")
    store.initialize()
    return store


def add_profile(
    store: SQLiteMonitoringStore,
    *,
    enabled: bool = True,
) -> MonitoredTarget:
    return store.create_target(
        MonitoredTarget.create(
            name="production",
            original_target="example.com",
            normalized_url="https://example.com/",
            enabled=enabled,
            created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
        )
    )


def finding(
    finding_id: str,
    *,
    severity: Severity = Severity.LOW,
    evidence_value: str = "baseline",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        title=f"Synthetic {finding_id}",
        description="Synthetic monitoring comparison finding.",
        evidence={"value": evidence_value},
        recommendation="Review the synthetic finding.",
    )


def report(
    *,
    scanned_at: datetime,
    findings: list[Finding] | None = None,
    normalized_url: str = "https://example.com/",
) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.4",
        original_target=normalized_url,
        normalized_url=normalized_url,
        scanned_at=scanned_at,
        checks=[{"name": "synthetic", "status": "passed"}],
        findings=[] if findings is None else findings,
    )


def save_run(
    store: SQLiteMonitoringStore,
    profile: MonitoredTarget,
    *,
    scanned_at: datetime,
    findings: list[Finding] | None = None,
    normalized_url: str = "https://example.com/",
) -> StoredScanRun:
    return store.save_scan_run(
        StoredScanRun.create(
            target_id=profile.id,
            report=report(
                scanned_at=scanned_at,
                findings=findings,
                normalized_url=normalized_url,
            ),
            stored_at=scanned_at,
        )
    )


def scan_result(
    *,
    scanned_at: datetime,
    findings: list[Finding] | None = None,
    normalized_url: str = "https://example.com/",
) -> ScanExecutionResult:
    target = normalize_target(normalized_url)
    base = execute_scan(
        target,
        lotuswatch_version="0.1.0-alpha.4",
        runner=successful_runner(),
        scanned_at=scanned_at,
    )
    selected_findings = [] if findings is None else findings
    selected_report = ScanReport.create(
        lotuswatch_version=base.report.lotuswatch_version,
        original_target=target.original,
        normalized_url=target.url,
        scanned_at=scanned_at,
        checks=base.checks,
        findings=selected_findings,
        checks_completed=base.completed_checks,
    )
    return replace(
        base,
        findings=selected_findings,
        report=selected_report,
    )


def install_scan_result(
    monkeypatch: pytest.MonkeyPatch,
    result: ScanExecutionResult,
) -> list[str]:
    calls: list[str] = []

    def fake_execute_scan(
        target: NormalizedTarget,
        *,
        lotuswatch_version: str,
        runner: object | None = None,
        scanned_at: datetime | None = None,
    ) -> ScanExecutionResult:
        calls.append(target.url)
        return result

    monkeypatch.setattr(lotuswatch.monitoring, "execute_scan", fake_execute_scan)
    return calls


def test_first_run_executes_once_and_stores_initial_baseline(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    profile = add_profile(store)
    runner = successful_runner()
    scanned_at = datetime(2026, 8, 20, 9, 0, tzinfo=UTC)
    stored_at = datetime(2026, 8, 20, 9, 1, tzinfo=UTC)

    result = execute_monitoring_run(
        store,
        profile.name,
        lotuswatch_version="0.1.0-alpha.4",
        runner=runner,
        scanned_at=scanned_at,
        stored_at=stored_at,
    )

    assert runner.calls == ["redirect", "tls", "headers", "caa", "email_dns"]
    assert result.is_initial_baseline is True
    assert result.baseline_run is None
    assert result.comparison is None
    assert result.stored_run.metadata.stored_at == stored_at
    assert store.list_scan_runs(profile.id) == [result.stored_run.metadata]
    loaded = store.get_scan_run(result.stored_run.metadata.id)
    assert loaded == result.stored_run
    assert loaded is not None
    assert ScanReport.model_validate(loaded.report.model_dump()) == loaded.report


def test_second_run_comparison_has_all_four_statuses(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = initialized_store(tmp_path)
    profile = add_profile(store)
    baseline_findings = [
        finding("LW-TEST-001"),
        finding("LW-TEST-002", severity=Severity.MEDIUM),
        finding("LW-TEST-003"),
    ]
    baseline = save_run(
        store,
        profile,
        scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
        findings=baseline_findings,
    )
    current_findings = [
        finding("LW-TEST-004"),
        finding(
            "LW-TEST-002",
            severity=Severity.HIGH,
            evidence_value="current",
        ),
        finding("LW-TEST-003"),
    ]
    current_scan = scan_result(
        scanned_at=datetime(2026, 8, 20, 10, 0, tzinfo=UTC),
        findings=current_findings,
    )
    calls = install_scan_result(monkeypatch, current_scan)

    result = execute_monitoring_run(
        store,
        profile.name,
        lotuswatch_version="0.1.0-alpha.4",
        compared_at=datetime(2026, 8, 20, 10, 1, tzinfo=UTC),
    )

    assert calls == ["https://example.com/"]
    assert result.baseline_run == baseline
    assert result.comparison is not None
    assert result.comparison.summary.added == 1
    assert result.comparison.summary.resolved == 1
    assert result.comparison.summary.changed == 1
    assert result.comparison.summary.unchanged == 1
    assert (
        ComparisonReport.model_validate(result.comparison.model_dump())
        == result.comparison
    )
    assert len(store.list_scan_runs(profile.id)) == 2


def test_newest_earlier_compatible_baseline_is_selected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = initialized_store(tmp_path)
    profile = add_profile(store)
    compatible = save_run(
        store,
        profile,
        scanned_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )
    save_run(
        store,
        profile,
        scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
        normalized_url="https://other.example/",
    )
    save_run(
        store,
        profile,
        scanned_at=datetime(2026, 8, 20, 11, 0, tzinfo=UTC),
    )
    install_scan_result(
        monkeypatch,
        scan_result(scanned_at=datetime(2026, 8, 20, 10, 0, tzinfo=UTC)),
    )

    result = execute_monitoring_run(
        store,
        profile.name,
        lotuswatch_version="0.1.0-alpha.4",
    )

    assert result.baseline_run == compatible
    assert result.skipped_baseline_candidates == 2
    assert result.comparison is not None
    assert result.comparison.normalized_target == profile.normalized_url


def test_missing_or_disabled_profile_is_not_scanned(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    runner = successful_runner()

    with pytest.raises(MonitoringProfileNotFoundError):
        execute_monitoring_run(
            store,
            "missing",
            lotuswatch_version="0.1.0-alpha.4",
            runner=runner,
        )

    add_profile(store, enabled=False)
    with pytest.raises(MonitoringProfileDisabledError):
        execute_monitoring_run(
            store,
            "production",
            lotuswatch_version="0.1.0-alpha.4",
            runner=runner,
        )

    assert runner.calls == []


def test_persistence_failure_leaves_no_partial_run(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    profile = add_profile(store)
    runner = successful_runner()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_monitoring_run
            AFTER INSERT ON scan_runs
            BEGIN
                SELECT RAISE(ABORT, 'synthetic persistence failure');
            END
            """
        )

    with pytest.raises(StoreConflictError):
        execute_monitoring_run(
            store,
            profile.name,
            lotuswatch_version="0.1.0-alpha.4",
            runner=runner,
            scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
        )

    assert runner.calls == ["redirect", "tls", "headers", "caa", "email_dns"]
    assert store.list_scan_runs(profile.id) == []


def test_controlled_operational_error_is_preserved_in_stored_report(
    tmp_path: Path,
) -> None:
    store = initialized_store(tmp_path)
    profile = add_profile(store)
    runner = successful_runner()
    runner.redirect_result = RedirectCheckResult(
        passed=False,
        status=RedirectStatus.TIMEOUT,
        initial_url="http://example.com/",
        final_url="http://example.com/",
        redirect_count=0,
        error="The redirect check timed out.",
    )

    result = execute_monitoring_run(
        store,
        profile.name,
        lotuswatch_version="0.1.0-alpha.4",
        runner=runner,
        scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
    )
    loaded = store.get_scan_run(result.stored_run.metadata.id)

    assert result.scan.completed_checks == 4
    assert loaded is not None
    assert loaded.report.summary.checks_completed == 4
    assert loaded.report.checks[0]["status"] == "timeout"
    assert loaded.report.checks[0]["error"] == "The redirect check timed out."


def test_mismatched_scan_target_is_not_stored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = initialized_store(tmp_path)
    profile = add_profile(store)
    install_scan_result(
        monkeypatch,
        scan_result(
            scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
            normalized_url="https://other.example/",
        ),
    )

    with pytest.raises(MonitoringTargetCompatibilityError):
        execute_monitoring_run(
            store,
            profile.name,
            lotuswatch_version="0.1.0-alpha.4",
        )

    assert store.list_scan_runs(profile.id) == []


def test_comparison_failure_occurs_before_current_run_is_stored(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = initialized_store(tmp_path)
    profile = add_profile(store)
    baseline_finding = finding("LW-TEST-005")
    save_run(
        store,
        profile,
        scanned_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
        findings=[baseline_finding],
    )
    duplicate = finding("LW-TEST-005", evidence_value="duplicate")
    install_scan_result(
        monkeypatch,
        scan_result(
            scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
            findings=[duplicate, duplicate.model_copy(deep=True)],
        ),
    )

    with pytest.raises(MonitoringComparisonError):
        execute_monitoring_run(
            store,
            profile.name,
            lotuswatch_version="0.1.0-alpha.4",
        )

    assert len(store.list_scan_runs(profile.id)) == 1
