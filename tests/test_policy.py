from datetime import UTC, datetime

import pytest

from lotuswatch.models import Finding, ScanReport, Severity, compare_reports
from lotuswatch.policy import (
    comparison_findings_meet_threshold,
    scan_findings_meet_threshold,
    severity_meets_threshold,
)

SEVERITIES = list(Severity)
TARGET = "https://example.com/"


def make_finding(
    finding_id: str,
    severity: Severity,
    *,
    evidence_value: str = "same",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        title=f"Finding {finding_id}",
        description=f"Description for {finding_id}.",
        evidence={"value": evidence_value},
        recommendation=f"Recommendation for {finding_id}.",
    )


def make_report(
    findings: list[Finding] | None = None,
    *,
    scanned_at: datetime,
) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.3",
        original_target="example.com",
        normalized_url=TARGET,
        checks=[],
        findings=findings or [],
        scanned_at=scanned_at,
    )


@pytest.mark.parametrize(
    ("severity", "threshold", "expected"),
    [
        (severity, threshold, SEVERITIES.index(severity) >= SEVERITIES.index(threshold))
        for severity in SEVERITIES
        for threshold in SEVERITIES
    ],
)
def test_severity_threshold_boundaries(
    severity: Severity,
    threshold: Severity,
    expected: bool,
) -> None:
    assert severity_meets_threshold(severity, threshold) is expected


def test_scan_policy_evaluates_all_findings() -> None:
    findings = [
        make_finding("LW-TEST-001", Severity.INFO),
        make_finding("LW-TEST-002", Severity.HIGH),
    ]

    assert scan_findings_meet_threshold(findings, Severity.HIGH)
    assert not scan_findings_meet_threshold(findings, Severity.CRITICAL)
    assert not scan_findings_meet_threshold([], Severity.INFO)


def test_comparison_policy_evaluates_added_finding() -> None:
    baseline = make_report([], scanned_at=datetime(2026, 8, 18, tzinfo=UTC))
    current = make_report(
        [make_finding("LW-TEST-001", Severity.MEDIUM)],
        scanned_at=datetime(2026, 8, 19, tzinfo=UTC),
    )
    comparison = compare_reports(baseline, current)

    assert comparison_findings_meet_threshold(comparison, Severity.MEDIUM)
    assert not comparison_findings_meet_threshold(comparison, Severity.HIGH)


def test_comparison_policy_uses_current_changed_severity() -> None:
    baseline = make_report(
        [make_finding("LW-TEST-001", Severity.CRITICAL, evidence_value="before")],
        scanned_at=datetime(2026, 8, 18, tzinfo=UTC),
    )
    current = make_report(
        [make_finding("LW-TEST-001", Severity.LOW, evidence_value="after")],
        scanned_at=datetime(2026, 8, 19, tzinfo=UTC),
    )
    comparison = compare_reports(baseline, current)

    assert comparison_findings_meet_threshold(comparison, Severity.LOW)
    assert not comparison_findings_meet_threshold(comparison, Severity.MEDIUM)


def test_comparison_policy_detects_changed_severity_increase() -> None:
    baseline = make_report(
        [make_finding("LW-TEST-001", Severity.LOW)],
        scanned_at=datetime(2026, 8, 18, tzinfo=UTC),
    )
    current = make_report(
        [make_finding("LW-TEST-001", Severity.HIGH)],
        scanned_at=datetime(2026, 8, 19, tzinfo=UTC),
    )
    comparison = compare_reports(baseline, current)

    assert comparison_findings_meet_threshold(comparison, Severity.HIGH)


def test_comparison_policy_ignores_resolved_finding() -> None:
    baseline = make_report(
        [make_finding("LW-TEST-001", Severity.CRITICAL)],
        scanned_at=datetime(2026, 8, 18, tzinfo=UTC),
    )
    current = make_report([], scanned_at=datetime(2026, 8, 19, tzinfo=UTC))
    comparison = compare_reports(baseline, current)

    assert not comparison_findings_meet_threshold(comparison, Severity.INFO)


def test_comparison_policy_ignores_unchanged_finding() -> None:
    finding = make_finding("LW-TEST-001", Severity.CRITICAL)
    baseline = make_report([finding], scanned_at=datetime(2026, 8, 18, tzinfo=UTC))
    current = make_report([finding], scanned_at=datetime(2026, 8, 19, tzinfo=UTC))
    comparison = compare_reports(baseline, current)

    assert not comparison_findings_meet_threshold(comparison, Severity.INFO)
