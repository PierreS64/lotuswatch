import socket
import ssl
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field

from lotuswatch.target import NormalizedTarget

DEFAULT_TLS_PORT = 443
DEFAULT_TLS_TIMEOUT = 5.0


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
                (hostname, port),
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
    except socket.gaierror as exc:
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
    except OSError as exc:
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
