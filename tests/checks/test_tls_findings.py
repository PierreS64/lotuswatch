from datetime import UTC, datetime

import pytest

from lotuswatch.checks import (
    TLSCheckResult,
    TLSStatus,
    tls_result_to_findings,
)
from lotuswatch.models import Severity


def passed_result(days_until_expiry: int) -> TLSCheckResult:
    return TLSCheckResult(
        passed=True,
        status=TLSStatus.PASSED,
        hostname="example.com",
        port=443,
        tls_version="TLSv1.3",
        not_after=datetime(2026, 9, 17, 10, 0, tzinfo=UTC),
        days_until_expiry=days_until_expiry,
    )


def verification_error_result(
    *,
    verification_code: int | None,
    error: str,
) -> TLSCheckResult:
    return TLSCheckResult(
        passed=False,
        status=TLSStatus.VERIFICATION_ERROR,
        hostname="example.com",
        port=443,
        verification_code=verification_code,
        error=error,
    )


@pytest.mark.parametrize(
    ("days", "expected_id", "expected_severity"),
    [
        (31, None, None),
        (30, "LW-TLS-001", Severity.LOW),
        (15, "LW-TLS-001", Severity.LOW),
        (14, "LW-TLS-002", Severity.MEDIUM),
        (1, "LW-TLS-002", Severity.MEDIUM),
        (0, "LW-TLS-002", Severity.MEDIUM),
        (-1, "LW-TLS-003", Severity.CRITICAL),
    ],
)
def test_certificate_expiration_boundaries(
    days: int,
    expected_id: str | None,
    expected_severity: Severity | None,
) -> None:
    findings = tls_result_to_findings(passed_result(days))

    if expected_id is None:
        assert findings == []
        return

    assert len(findings) == 1
    assert findings[0].id == expected_id
    assert findings[0].severity is expected_severity
    assert findings[0].evidence["days_until_expiry"] == days


def test_expiration_finding_evidence_is_json_compatible() -> None:
    finding = tls_result_to_findings(passed_result(14))[0]

    serialized = finding.model_dump(mode="json")

    assert serialized["evidence"]["hostname"] == "example.com"
    assert serialized["evidence"]["port"] == 443
    assert serialized["evidence"]["not_after"].endswith("+00:00")


def test_expired_verification_code_produces_critical_finding() -> None:
    result = verification_error_result(
        verification_code=10,
        error="Certificate verification failed.",
    )

    findings = tls_result_to_findings(result)

    assert len(findings) == 1
    assert findings[0].id == "LW-TLS-003"
    assert findings[0].severity is Severity.CRITICAL


def test_expired_diagnostic_produces_critical_finding() -> None:
    result = verification_error_result(
        verification_code=None,
        error="Certificate verification failed: certificate has expired",
    )

    finding = tls_result_to_findings(result)[0]

    assert finding.id == "LW-TLS-003"
    assert finding.severity is Severity.CRITICAL


def test_hostname_mismatch_code_produces_high_finding() -> None:
    result = verification_error_result(
        verification_code=62,
        error="Certificate verification failed.",
    )

    finding = tls_result_to_findings(result)[0]

    assert finding.id == "LW-TLS-004"
    assert finding.severity is Severity.HIGH


def test_hostname_mismatch_diagnostic_produces_high_finding() -> None:
    result = verification_error_result(
        verification_code=None,
        error="Certificate is not valid for example.com",
    )

    finding = tls_result_to_findings(result)[0]

    assert finding.id == "LW-TLS-004"
    assert finding.severity is Severity.HIGH


def test_ambiguous_verification_error_remains_generic() -> None:
    result = verification_error_result(
        verification_code=20,
        error="Unable to get local issuer certificate",
    )

    finding = tls_result_to_findings(result)[0]

    assert finding.id == "LW-TLS-005"
    assert finding.severity is Severity.HIGH
    assert "does not prove a more specific cause" in finding.description


@pytest.mark.parametrize(
    "status",
    [
        TLSStatus.DNS_ERROR,
        TLSStatus.TIMEOUT,
        TLSStatus.CONNECTION_ERROR,
        TLSStatus.HANDSHAKE_ERROR,
        TLSStatus.CERTIFICATE_ERROR,
    ],
)
def test_operational_errors_do_not_create_security_findings(
    status: TLSStatus,
) -> None:
    result = TLSCheckResult(
        passed=False,
        status=status,
        hostname="example.com",
        port=443,
        error="The check could not complete.",
    )

    assert tls_result_to_findings(result) == []
