"""Opt-in severity policies for command-line exit decisions."""

from collections.abc import Iterable

from lotuswatch.models import ComparisonReport, ComparisonStatus, Finding, Severity

SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def severity_meets_threshold(severity: Severity, threshold: Severity) -> bool:
    """Return whether a severity is equal to or above a threshold."""

    return SEVERITY_RANK[severity] >= SEVERITY_RANK[threshold]


def scan_findings_meet_threshold(
    findings: Iterable[Finding],
    threshold: Severity,
) -> bool:
    """Evaluate all findings produced by one scan."""

    return any(
        severity_meets_threshold(finding.severity, threshold) for finding in findings
    )


def comparison_findings_meet_threshold(
    comparison: ComparisonReport,
    threshold: Severity,
) -> bool:
    """Evaluate added and changed current findings in a comparison."""

    for finding_comparison in comparison.findings:
        if finding_comparison.status not in {
            ComparisonStatus.ADDED,
            ComparisonStatus.CHANGED,
        }:
            continue

        current_finding = finding_comparison.current_finding
        assert current_finding is not None

        if severity_meets_threshold(current_finding.severity, threshold):
            return True

    return False
