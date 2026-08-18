import pytest

from lotuswatch.checks import (
    HeaderObservation,
    SecurityHeaderCheckResult,
    SecurityHeaderStatus,
    security_header_result_to_findings,
)
from lotuswatch.models import ScanReport, Severity

HEADER_NAMES = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-Frame-Options",
)


def completed_result(
    values: dict[str, str | None],
) -> SecurityHeaderCheckResult:
    normalized_values = {name.casefold(): value for name, value in values.items()}
    observations = []

    for name in HEADER_NAMES:
        value = normalized_values.get(name.casefold())
        observations.append(
            HeaderObservation(
                name=name,
                present=value is not None,
                value=value,
            )
        )

    return SecurityHeaderCheckResult(
        passed=True,
        status=SecurityHeaderStatus.COMPLETED,
        requested_url="https://example.com/",
        final_url="https://www.example.com/",
        status_code=200,
        redirect_count=1,
        headers=observations,
    )


def secure_values() -> dict[str, str]:
    return {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
    }


def finding_by_id(
    result: SecurityHeaderCheckResult,
    finding_id: str,
):
    return next(
        finding
        for finding in security_header_result_to_findings(result)
        if finding.id == finding_id
    )


def test_fully_configured_response_produces_no_findings() -> None:
    assert security_header_result_to_findings(completed_result(secure_values())) == []


@pytest.mark.parametrize(
    ("missing_header", "finding_id", "severity"),
    [
        ("Strict-Transport-Security", "LW-HEADER-001", Severity.MEDIUM),
        ("Content-Security-Policy", "LW-HEADER-003", Severity.MEDIUM),
        ("X-Content-Type-Options", "LW-HEADER-004", Severity.LOW),
        ("Referrer-Policy", "LW-HEADER-005", Severity.LOW),
        ("Permissions-Policy", "LW-HEADER-006", Severity.INFO),
    ],
)
def test_missing_header_produces_expected_finding(
    missing_header: str,
    finding_id: str,
    severity: Severity,
) -> None:
    values = secure_values()
    del values[missing_header]

    finding = finding_by_id(completed_result(values), finding_id)

    assert finding.severity is severity
    assert "not proof" in finding.description or "does not" in finding.description


@pytest.mark.parametrize(
    "value",
    [
        "max-age=15551999",
        "MAX-AGE=0; INCLUDESUBDOMAINS",
        "includeSubDomains; MaX-aGe = 86400",
    ],
)
def test_short_hsts_max_age_produces_low_finding(value: str) -> None:
    values = secure_values()
    values["Strict-Transport-Security"] = value

    finding = finding_by_id(completed_result(values), "LW-HEADER-002")

    assert finding.severity is Severity.LOW
    assert finding.evidence["hsts_max_age"] < 15_552_000


def test_hsts_threshold_does_not_produce_finding() -> None:
    values = secure_values()
    values["Strict-Transport-Security"] = "max-age=15552000"

    ids = {
        finding.id
        for finding in security_header_result_to_findings(completed_result(values))
    }

    assert "LW-HEADER-001" not in ids
    assert "LW-HEADER-002" not in ids


@pytest.mark.parametrize(
    "value",
    [
        "includeSubDomains",
        "max-age=not-a-number",
        "max-age=-1",
        "max-age=100; max-age=200",
        "max-age",
    ],
)
def test_malformed_hsts_is_handled_as_no_effective_policy(value: str) -> None:
    values = secure_values()
    values["Strict-Transport-Security"] = value

    finding = finding_by_id(completed_result(values), "LW-HEADER-001")

    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["strict_transport_security"] == value


@pytest.mark.parametrize("value", ["NOSNIFF", " nosniff ", "NoSnIfF"])
def test_nosniff_comparison_is_case_insensitive(value: str) -> None:
    values = secure_values()
    values["X-Content-Type-Options"] = value

    ids = {
        finding.id
        for finding in security_header_result_to_findings(completed_result(values))
    }

    assert "LW-HEADER-004" not in ids


def test_invalid_content_type_options_produces_low_finding() -> None:
    values = secure_values()
    values["X-Content-Type-Options"] = "sniff"

    finding = finding_by_id(completed_result(values), "LW-HEADER-004")

    assert finding.severity is Severity.LOW
    assert finding.evidence["x_content_type_options"] == "sniff"


@pytest.mark.parametrize(
    "csp",
    [
        "default-src 'self'; frame-ancestors 'none'",
        "DEFAULT-SRC 'self'; FRAME-ANCESTORS https://parent.example",
        "frame-ancestors 'self' ; script-src 'self'",
    ],
)
def test_csp_frame_ancestors_suppresses_clickjacking_finding(csp: str) -> None:
    values = secure_values()
    values["Content-Security-Policy"] = csp

    ids = {
        finding.id
        for finding in security_header_result_to_findings(completed_result(values))
    }

    assert "LW-HEADER-007" not in ids


def test_x_frame_options_suppresses_clickjacking_finding_without_csp_directive(
) -> None:
    values = secure_values()
    values["Content-Security-Policy"] = "default-src 'self'"
    values["X-Frame-Options"] = "SAMEORIGIN"

    ids = {
        finding.id
        for finding in security_header_result_to_findings(completed_result(values))
    }

    assert "LW-HEADER-007" not in ids


def test_missing_both_clickjacking_controls_produces_medium_finding() -> None:
    values = secure_values()
    values["Content-Security-Policy"] = "default-src 'self'"

    finding = finding_by_id(completed_result(values), "LW-HEADER-007")

    assert finding.severity is Severity.MEDIUM
    assert finding.evidence["content_security_policy"] == "default-src 'self'"
    assert finding.evidence["x_frame_options"] is None


@pytest.mark.parametrize(
    "status",
    [
        SecurityHeaderStatus.INVALID_TARGET,
        SecurityHeaderStatus.REDIRECT_LOOP,
        SecurityHeaderStatus.TOO_MANY_REDIRECTS,
        SecurityHeaderStatus.INSECURE_REDIRECT,
        SecurityHeaderStatus.UNSUPPORTED_REDIRECT,
        SecurityHeaderStatus.TIMEOUT,
        SecurityHeaderStatus.TLS_ERROR,
        SecurityHeaderStatus.CONNECTION_ERROR,
    ],
)
def test_incomplete_header_check_produces_no_findings(
    status: SecurityHeaderStatus,
) -> None:
    result = SecurityHeaderCheckResult(
        passed=False,
        status=status,
        requested_url="https://example.com/",
        final_url="https://example.com/",
        error="The request did not complete.",
    )

    assert security_header_result_to_findings(result) == []


def test_finding_evidence_uses_final_url_and_serializes_to_json() -> None:
    values = secure_values()
    del values["Referrer-Policy"]
    finding = finding_by_id(completed_result(values), "LW-HEADER-005")

    report = ScanReport.create(
        lotuswatch_version="0.2.0-alpha.2",
        original_target="example.com",
        normalized_url="https://example.com/",
        checks=[],
        findings=[finding],
    )
    serialized = report.model_dump(mode="json")

    assert finding.evidence["final_url"] == "https://www.example.com/"
    assert serialized["findings"][0]["id"] == "LW-HEADER-005"
    assert serialized["findings"][0]["evidence"]["status_code"] == 200


def test_finding_evidence_caps_manually_supplied_header_value() -> None:
    values = secure_values()
    values["X-Content-Type-Options"] = "x" * 3_000

    finding = finding_by_id(completed_result(values), "LW-HEADER-004")

    assert len(finding.evidence["x_content_type_options"]) == 2_048
