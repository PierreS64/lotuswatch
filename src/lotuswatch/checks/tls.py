import socket
import ssl
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, JsonValue

from lotuswatch.models import Finding, Severity
from lotuswatch.network import (
    PublicAddressError,
    PublicResolutionError,
    resolve_public_address,
)
from lotuswatch.target import NormalizedTarget

DEFAULT_TLS_PORT = 443
DEFAULT_TLS_TIMEOUT = 5.0
TLS_EXPIRY_LOW_MAX_DAYS = 30
TLS_EXPIRY_MEDIUM_MAX_DAYS = 14

EXPIRED_CERTIFICATE_VERIFY_CODE = 10
HOSTNAME_MISMATCH_VERIFY_CODE = 62

TLS_REFERENCE = (
    "https://developer.mozilla.org/en-US/docs/Web/Security/Transport_Layer_Security"
)


class TLSStatus(StrEnum):
    """Possible outcomes of a TLS certificate check."""

    PASSED = "passed"
    VERIFICATION_ERROR = "verification_error"
    DNS_ERROR = "dns_error"
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    HANDSHAKE_ERROR = "handshake_error"
    CERTIFICATE_ERROR = "certificate_error"


class TLSCheckResult(BaseModel):
    """Structured result of a verified TLS certificate check."""

    passed: bool
    status: TLSStatus
    hostname: str
    port: int = Field(ge=1, le=65535)
    tls_version: str | None = None
    cipher: str | None = None
    cipher_protocol: str | None = None
    cipher_bits: int | None = Field(default=None, ge=0)
    subject: dict[str, str] = Field(default_factory=dict)
    issuer: dict[str, str] = Field(default_factory=dict)
    serial_number: str | None = None
    subject_alt_names: list[str] = Field(default_factory=list)
    not_before: datetime | None = None
    not_after: datetime | None = None
    days_until_expiry: int | None = None
    verification_code: int | None = None
    error: str | None = None


class _CertificateParseError(ValueError):
    """Raised when a verified peer certificate cannot be parsed."""


def check_tls_certificate(
    target: NormalizedTarget,
    *,
    timeout: float = DEFAULT_TLS_TIMEOUT,
    now: datetime | None = None,
) -> TLSCheckResult:
    """Perform a verified TLS handshake and inspect the peer certificate."""

    hostname = target.hostname
    port = target.port or DEFAULT_TLS_PORT
    checked_at = _normalize_now(now)

    context = ssl.create_default_context()
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True

    try:
        with (
            socket.create_connection(
                (resolve_public_address(hostname, port, timeout=timeout), port),
                timeout=timeout,
            ) as raw_socket,
            context.wrap_socket(
                raw_socket,
                server_hostname=hostname,
            ) as tls_socket,
        ):
            certificate = tls_socket.getpeercert()
            tls_version = tls_socket.version()
            cipher_details = tls_socket.cipher()

        return _build_success_result(
            hostname=hostname,
            port=port,
            certificate=certificate,
            tls_version=tls_version,
            cipher_details=cipher_details,
            checked_at=checked_at,
        )
    except ssl.SSLCertVerificationError as exc:
        return _build_error_result(
            hostname=hostname,
            port=port,
            status=TLSStatus.VERIFICATION_ERROR,
            error=_verification_error_message(exc),
            verification_code=getattr(exc, "verify_code", None),
        )
    except (socket.gaierror, PublicResolutionError) as exc:
        return _build_error_result(
            hostname=hostname,
            port=port,
            status=TLSStatus.DNS_ERROR,
            error=f"DNS resolution failed: {exc}",
        )
    except TimeoutError:
        return _build_error_result(
            hostname=hostname,
            port=port,
            status=TLSStatus.TIMEOUT,
            error="The TLS connection timed out.",
        )
    except ssl.SSLError as exc:
        return _build_error_result(
            hostname=hostname,
            port=port,
            status=TLSStatus.HANDSHAKE_ERROR,
            error=f"TLS handshake failed: {exc}",
        )
    except (OSError, PublicAddressError) as exc:
        return _build_error_result(
            hostname=hostname,
            port=port,
            status=TLSStatus.CONNECTION_ERROR,
            error=f"TLS connection failed: {exc}",
        )
    except _CertificateParseError as exc:
        return _build_error_result(
            hostname=hostname,
            port=port,
            status=TLSStatus.CERTIFICATE_ERROR,
            error=str(exc),
        )


def tls_result_to_findings(result: TLSCheckResult) -> list[Finding]:
    """Convert a TLS check result into actionable security findings."""

    if result.status is TLSStatus.PASSED:
        return _expiration_findings(result)

    if result.status is TLSStatus.VERIFICATION_ERROR:
        return [_verification_finding(result)]

    return []


def _expiration_findings(result: TLSCheckResult) -> list[Finding]:
    days = result.days_until_expiry

    if days is None or days > TLS_EXPIRY_LOW_MAX_DAYS:
        return []

    evidence = _base_finding_evidence(result)

    if days < 0:
        return [
            Finding(
                id="LW-TLS-003",
                severity=Severity.CRITICAL,
                title="TLS certificate has expired",
                description=(
                    "The verified certificate validity period has ended. "
                    "Clients may reject the HTTPS connection."
                ),
                evidence=evidence,
                recommendation=(
                    "Replace or renew the certificate immediately and confirm "
                    "that the complete certificate chain is served correctly."
                ),
                reference=TLS_REFERENCE,
            )
        ]

    if days <= TLS_EXPIRY_MEDIUM_MAX_DAYS:
        return [
            Finding(
                id="LW-TLS-002",
                severity=Severity.MEDIUM,
                title="TLS certificate expires very soon",
                description=(
                    "The certificate expires within 14 days. A renewal delay "
                    "could interrupt trusted HTTPS access."
                ),
                evidence=evidence,
                recommendation=(
                    "Renew the certificate promptly and verify that automated "
                    "renewal and deployment are working."
                ),
                reference=TLS_REFERENCE,
            )
        ]

    return [
        Finding(
            id="LW-TLS-001",
            severity=Severity.LOW,
            title="TLS certificate expires soon",
            description=(
                "The certificate expires within 30 days. Renewal should be "
                "scheduled before the validity period ends."
            ),
            evidence=evidence,
            recommendation=(
                "Confirm the renewal schedule and monitor the certificate "
                "until the renewed certificate is deployed."
            ),
            reference=TLS_REFERENCE,
        )
    ]


def _verification_finding(result: TLSCheckResult) -> Finding:
    evidence = _base_finding_evidence(result)

    if _is_expired_verification_error(result):
        return Finding(
            id="LW-TLS-003",
            severity=Severity.CRITICAL,
            title="TLS certificate has expired",
            description=(
                "The TLS handshake reported that the certificate has expired, "
                "so clients cannot establish a normally trusted connection."
            ),
            evidence=evidence,
            recommendation=(
                "Replace or renew the certificate immediately and verify the "
                "certificate chain after deployment."
            ),
            reference=TLS_REFERENCE,
        )

    if _is_hostname_mismatch(result):
        return Finding(
            id="LW-TLS-004",
            severity=Severity.HIGH,
            title="TLS certificate hostname mismatch",
            description=(
                "The certificate is not valid for the requested hostname, so "
                "clients cannot verify the identity of the endpoint."
            ),
            evidence=evidence,
            recommendation=(
                "Deploy a certificate whose Subject Alternative Names include "
                "the requested hostname and confirm the correct certificate is "
                "served through SNI."
            ),
            reference=TLS_REFERENCE,
        )

    return Finding(
        id="LW-TLS-005",
        severity=Severity.HIGH,
        title="TLS certificate verification failed",
        description=(
            "The certificate could not be verified using the local trusted "
            "certificate authorities. The diagnostic does not prove a more "
            "specific cause."
        ),
        evidence=evidence,
        recommendation=(
            "Review the certificate chain, issuing authority, hostname, and "
            "validity period, then retest using a standard trusted client."
        ),
        reference=TLS_REFERENCE,
    )


def _base_finding_evidence(result: TLSCheckResult) -> dict[str, JsonValue]:
    evidence: dict[str, JsonValue] = {
        "hostname": result.hostname,
        "port": result.port,
        "status": result.status.value,
    }

    if result.days_until_expiry is not None:
        evidence["days_until_expiry"] = result.days_until_expiry

    if result.not_after is not None:
        evidence["not_after"] = result.not_after.isoformat()

    if result.verification_code is not None:
        evidence["verification_code"] = result.verification_code

    if result.error is not None:
        evidence["error"] = result.error

    return evidence


def _is_expired_verification_error(result: TLSCheckResult) -> bool:
    if result.verification_code == EXPIRED_CERTIFICATE_VERIFY_CODE:
        return True

    error = (result.error or "").casefold()
    return "expired" in error


def _is_hostname_mismatch(result: TLSCheckResult) -> bool:
    if result.verification_code == HOSTNAME_MISMATCH_VERIFY_CODE:
        return True

    error = (result.error or "").casefold()
    return "hostname mismatch" in error or "not valid for" in error


def _build_success_result(
    *,
    hostname: str,
    port: int,
    certificate: dict[str, Any],
    tls_version: str | None,
    cipher_details: tuple[str, str, int] | None,
    checked_at: datetime,
) -> TLSCheckResult:
    not_before = _parse_certificate_time(certificate, "notBefore")
    not_after = _parse_certificate_time(certificate, "notAfter")
    days_until_expiry = int((not_after - checked_at).total_seconds() // 86400)

    cipher = None
    cipher_protocol = None
    cipher_bits = None

    if cipher_details is not None:
        cipher, cipher_protocol, cipher_bits = cipher_details

    return TLSCheckResult(
        passed=True,
        status=TLSStatus.PASSED,
        hostname=hostname,
        port=port,
        tls_version=tls_version,
        cipher=cipher,
        cipher_protocol=cipher_protocol,
        cipher_bits=cipher_bits,
        subject=_flatten_distinguished_name(certificate.get("subject")),
        issuer=_flatten_distinguished_name(certificate.get("issuer")),
        serial_number=_optional_string(certificate.get("serialNumber")),
        subject_alt_names=_parse_subject_alt_names(certificate.get("subjectAltName")),
        not_before=not_before,
        not_after=not_after,
        days_until_expiry=days_until_expiry,
    )


def _build_error_result(
    *,
    hostname: str,
    port: int,
    status: TLSStatus,
    error: str,
    verification_code: int | None = None,
) -> TLSCheckResult:
    return TLSCheckResult(
        passed=False,
        status=status,
        hostname=hostname,
        port=port,
        verification_code=verification_code,
        error=error,
    )


def _normalize_now(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("TLS check time must include a timezone.")

    return value.astimezone(UTC)


def _parse_certificate_time(
    certificate: dict[str, Any],
    field: str,
) -> datetime:
    value = certificate.get(field)

    if not isinstance(value, str) or not value:
        raise _CertificateParseError(f"Verified certificate is missing {field}.")

    try:
        timestamp = ssl.cert_time_to_seconds(value)
    except ValueError as exc:
        raise _CertificateParseError(
            f"Verified certificate contains an invalid {field} value."
        ) from exc

    return datetime.fromtimestamp(timestamp, UTC)


def _flatten_distinguished_name(value: object) -> dict[str, str]:
    result: dict[str, str] = {}

    if not isinstance(value, tuple):
        return result

    for relative_name in value:
        if not isinstance(relative_name, tuple):
            continue

        for attribute in relative_name:
            if (
                isinstance(attribute, tuple)
                and len(attribute) == 2
                and isinstance(attribute[0], str)
                and isinstance(attribute[1], str)
            ):
                result[attribute[0]] = attribute[1]

    return result


def _parse_subject_alt_names(value: object) -> list[str]:
    result: list[str] = []

    if not isinstance(value, tuple):
        return result

    for entry in value:
        if (
            isinstance(entry, tuple)
            and len(entry) == 2
            and isinstance(entry[0], str)
            and isinstance(entry[1], str)
        ):
            result.append(f"{entry[0]}:{entry[1]}")

    return result


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _verification_error_message(exc: ssl.SSLCertVerificationError) -> str:
    message = getattr(exc, "verify_message", None)

    if isinstance(message, str) and message:
        return f"Certificate verification failed: {message}"

    return f"Certificate verification failed: {exc}"
