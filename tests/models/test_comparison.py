from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest
from pydantic import ValidationError

from lotuswatch.exceptions import (
    ComparisonInputError,
    ComparisonTargetMismatchError,
    DuplicateFindingFingerprintError,
)
from lotuswatch.models import (
    ComparisonReport,
    ComparisonStatus,
    Finding,
    FindingComparison,
    ScanReport,
    Severity,
    compare_reports,
    finding_fingerprint,
)

BASELINE_TIME = datetime(2026, 8, 18, 8, 0, tzinfo=UTC)
CURRENT_TIME = datetime(2026, 8, 19, 8, 0, tzinfo=UTC)
COMPARISON_TIME = datetime(2026, 8, 19, 9, 0, tzinfo=UTC)
TARGET = "https://example.com/"


def make_finding(
    finding_id: str,
    *,
    severity: Severity = Severity.LOW,
    evidence: dict[str, object] | None = None,
    title: str | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        title=title or f"Finding {finding_id}",
        description=f"Description for {finding_id}.",
        evidence=evidence or {"observed": True},
        recommendation=f"Recommendation for {finding_id}.",
    )


def make_report(
    findings: list[Finding] | None = None,
    *,
    normalized_url: str = TARGET,
    lotuswatch_version: str = "0.1.0-alpha.3",
    scanned_at: datetime = BASELINE_TIME,
) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version=lotuswatch_version,
        original_target="example.com",
        normalized_url=normalized_url,
        checks=[],
        findings=findings or [],
        scanned_at=scanned_at,
    )


def finding_id(comparison: FindingComparison) -> str:
    finding = comparison.current_finding or comparison.baseline_finding
    assert finding is not None
    return finding.id


def test_compares_two_empty_reports() -> None:
    result = compare_reports(
        make_report(),
        make_report(scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )

    assert result.comparison_schema_version == "1.0"
    assert result.normalized_target == TARGET
    assert result.summary.added == 0
    assert result.summary.resolved == 0
    assert result.summary.changed == 0
    assert result.summary.unchanged == 0
    assert result.findings == []


def test_classifies_all_comparison_statuses() -> None:
    unchanged = make_finding("LW-TEST-001")
    changed_before = make_finding(
        "LW-TEST-002",
        severity=Severity.LOW,
        evidence={"value": "before"},
    )
    changed_after = make_finding(
        "LW-TEST-002",
        severity=Severity.HIGH,
        evidence={"value": "after"},
    )
    resolved = make_finding("LW-TEST-003")
    added = make_finding("LW-TEST-004")

    result = compare_reports(
        make_report([unchanged, changed_before, resolved]),
        make_report(
            [added, changed_after, unchanged.model_copy(deep=True)],
            scanned_at=CURRENT_TIME,
        ),
        compared_at=COMPARISON_TIME,
    )
    by_id = {finding_id(item): item for item in result.findings}

    assert by_id["LW-TEST-001"].status is ComparisonStatus.UNCHANGED
    assert by_id["LW-TEST-002"].status is ComparisonStatus.CHANGED
    assert by_id["LW-TEST-003"].status is ComparisonStatus.RESOLVED
    assert by_id["LW-TEST-004"].status is ComparisonStatus.ADDED
    assert result.summary.model_dump() == {
        "added": 1,
        "resolved": 1,
        "changed": 1,
        "unchanged": 1,
    }
    assert [item.status for item in result.findings] == [
        ComparisonStatus.ADDED,
        ComparisonStatus.RESOLVED,
        ComparisonStatus.CHANGED,
        ComparisonStatus.UNCHANGED,
    ]


def test_preserves_expected_snapshots_for_each_status() -> None:
    unchanged = make_finding("LW-TEST-001")
    changed_before = make_finding("LW-TEST-002", evidence={"value": "before"})
    changed_after = make_finding("LW-TEST-002", evidence={"value": "after"})
    resolved = make_finding("LW-TEST-003")
    added = make_finding("LW-TEST-004")

    result = compare_reports(
        make_report([unchanged, changed_before, resolved]),
        make_report([unchanged, changed_after, added], scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )
    by_id = {finding_id(item): item for item in result.findings}

    assert by_id["LW-TEST-001"].baseline_finding is not None
    assert by_id["LW-TEST-001"].current_finding is not None
    assert by_id["LW-TEST-002"].baseline_finding is not None
    assert by_id["LW-TEST-002"].current_finding is not None
    assert by_id["LW-TEST-003"].baseline_finding is not None
    assert by_id["LW-TEST-003"].current_finding is None
    assert by_id["LW-TEST-004"].baseline_finding is None
    assert by_id["LW-TEST-004"].current_finding is not None


def test_severity_and_evidence_change_is_one_changed_entry() -> None:
    baseline_finding = make_finding(
        "LW-TEST-001",
        severity=Severity.LOW,
        evidence={"status": 200},
    )
    current_finding = make_finding(
        "LW-TEST-001",
        severity=Severity.CRITICAL,
        evidence={"status": 500},
    )

    result = compare_reports(
        make_report([baseline_finding]),
        make_report([current_finding], scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )

    assert len(result.findings) == 1
    assert result.findings[0].status is ComparisonStatus.CHANGED
    assert result.summary.changed == 1
    assert result.summary.added == 0
    assert result.summary.resolved == 0


def test_report_metadata_changes_do_not_change_finding() -> None:
    finding = make_finding("LW-TEST-001")

    result = compare_reports(
        make_report(
            [finding],
            lotuswatch_version="0.1.0-alpha.2",
            scanned_at=BASELINE_TIME,
        ),
        make_report(
            [finding],
            lotuswatch_version="0.1.0-alpha.3",
            scanned_at=CURRENT_TIME,
        ),
        compared_at=COMPARISON_TIME,
    )

    assert result.findings[0].status is ComparisonStatus.UNCHANGED
    assert result.baseline.lotuswatch_version == "0.1.0-alpha.2"
    assert result.baseline.scanned_at == BASELINE_TIME
    assert result.current.lotuswatch_version == "0.1.0-alpha.3"
    assert result.current.scanned_at == CURRENT_TIME


def test_accepts_equivalent_canonical_targets() -> None:
    result = compare_reports(
        make_report(normalized_url=" HTTPS://EXAMPLE.COM/#baseline "),
        make_report(normalized_url=TARGET, scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )

    assert result.normalized_target == TARGET


def test_rejects_different_targets() -> None:
    with pytest.raises(
        ComparisonTargetMismatchError,
        match="different targets",
    ):
        compare_reports(
            make_report(normalized_url=TARGET),
            make_report(
                normalized_url="https://other.example/",
                scanned_at=CURRENT_TIME,
            ),
        )


def test_rejects_invalid_normalized_target_without_echoing_value() -> None:
    private_value = "private target value"

    with pytest.raises(
        ComparisonInputError, match="invalid normalized target"
    ) as error:
        compare_reports(
            make_report(normalized_url=private_value),
            make_report(scanned_at=CURRENT_TIME),
        )

    assert private_value not in str(error.value)


@pytest.mark.parametrize("duplicate_source", ["baseline", "current"])
def test_rejects_duplicate_finding_identity(duplicate_source: str) -> None:
    duplicate_findings = [
        make_finding("LW-TEST-001", evidence={"value": "one"}),
        make_finding("LW-TEST-001", evidence={"value": "two"}),
    ]
    baseline = make_report(duplicate_findings if duplicate_source == "baseline" else [])
    current = make_report(
        duplicate_findings if duplicate_source == "current" else [],
        scanned_at=CURRENT_TIME,
    )

    with pytest.raises(
        DuplicateFindingFingerprintError,
        match=duplicate_source.capitalize(),
    ):
        compare_reports(baseline, current)


def test_returns_deterministic_order_for_reordered_inputs() -> None:
    baseline_findings = [
        make_finding("LW-TEST-003"),
        make_finding("LW-TEST-001"),
        make_finding("LW-TEST-002"),
    ]
    current_findings = [
        make_finding("LW-TEST-004"),
        make_finding("LW-TEST-001"),
        make_finding("LW-TEST-002", title="Changed title"),
    ]

    first = compare_reports(
        make_report(baseline_findings),
        make_report(current_findings, scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )
    second = compare_reports(
        make_report(list(reversed(baseline_findings))),
        make_report(list(reversed(current_findings)), scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )

    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_result_snapshots_are_independent_from_input_reports() -> None:
    baseline_finding = make_finding("LW-TEST-001", title="Original title")
    current_finding = baseline_finding.model_copy(deep=True)
    baseline = make_report([baseline_finding])
    current = make_report([current_finding], scanned_at=CURRENT_TIME)

    result = compare_reports(baseline, current, compared_at=COMPARISON_TIME)
    baseline.findings[0].title = "Mutated after comparison"
    current.findings[0].title = "Also mutated"

    assert result.findings[0].baseline_finding is not None
    assert result.findings[0].current_finding is not None
    assert result.findings[0].baseline_finding.title == "Original title"
    assert result.findings[0].current_finding.title == "Original title"


def test_serializes_to_json_compatible_data() -> None:
    finding = make_finding("LW-TEST-001")
    utc_plus_seven = timezone(timedelta(hours=7))
    compared_at = datetime(2026, 8, 19, 16, 0, tzinfo=utc_plus_seven)

    result = compare_reports(
        make_report(),
        make_report([finding], scanned_at=CURRENT_TIME),
        compared_at=compared_at,
    )
    serialized = result.model_dump(mode="json")

    assert serialized["comparison_schema_version"] == "1.0"
    assert serialized["compared_at"] == "2026-08-19T09:00:00Z"
    assert serialized["findings"][0]["status"] == "added"
    assert serialized["findings"][0]["baseline_finding"] is None
    assert serialized["findings"][0]["current_finding"]["id"] == "LW-TEST-001"


def test_rejects_summary_that_does_not_match_entries() -> None:
    finding = make_finding("LW-TEST-001")
    result = compare_reports(
        make_report(),
        make_report([finding], scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )
    data = result.model_dump(mode="python")
    data["summary"]["added"] = 2

    with pytest.raises(ValidationError, match="summary does not match"):
        ComparisonReport.model_validate(data)


def test_rejects_status_with_invalid_snapshot_presence() -> None:
    finding = make_finding("LW-TEST-001")
    fingerprint = finding_fingerprint(TARGET, finding)

    with pytest.raises(ValidationError, match="invalid finding snapshots"):
        FindingComparison(
            fingerprint=fingerprint,
            status=ComparisonStatus.ADDED,
            baseline_finding=finding,
            current_finding=None,
        )


def test_rejects_fingerprint_that_does_not_match_snapshot() -> None:
    finding = make_finding("LW-TEST-001")
    result = compare_reports(
        make_report(),
        make_report([finding], scanned_at=CURRENT_TIME),
        compared_at=COMPARISON_TIME,
    )
    data = result.model_dump(mode="python")
    data["findings"][0]["fingerprint"] = f"lwfp:v1:sha256:{'0' * 64}"

    with pytest.raises(ValidationError, match="does not match"):
        ComparisonReport.model_validate(data)


def test_rejects_naive_comparison_timestamp() -> None:
    with pytest.raises(ValidationError, match="must include a timezone"):
        compare_reports(
            make_report(),
            make_report(scanned_at=CURRENT_TIME),
            compared_at=COMPARISON_TIME.replace(tzinfo=None),
        )


def test_rejects_non_report_input() -> None:
    with pytest.raises(ComparisonInputError, match="must be a ScanReport"):
        compare_reports(
            cast(ScanReport, {"schema_version": "1.0"}),
            make_report(scanned_at=CURRENT_TIME),
        )


def test_revalidates_bypass_constructed_report() -> None:
    invalid_report = make_report().model_copy(update={"lotuswatch_version": ""})

    with pytest.raises(ComparisonInputError, match="scan report is invalid"):
        compare_reports(invalid_report, make_report(scanned_at=CURRENT_TIME))
