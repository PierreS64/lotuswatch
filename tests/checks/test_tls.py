import socket
import ssl
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from lotuswatch.checks import TLSStatus, check_tls_certificate
from lotuswatch.target import normalize_target


def valid_certificate() -> dict[str, object]:
    return {
        "subject": ((("commonName", "example.com"),),),
        "issuer": (
            (("countryName", "US"),),
            (("organizationName", "Example CA"),),
        ),
        "serialNumber": "01AB",
        "notBefore": "Aug  1 00:00:00 2026 GMT",
        "notAfter": "Sep 17 10:00:00 2026 GMT",
        "subjectAltName": (
            ("DNS", "example.com"),
            ("DNS", "www.example.com"),
        ),
    }


def configure_successful_tls(
    monkeypatch: pytest.MonkeyPatch,
    certificate: dict[str, object] | None = None,
) -> tuple[MagicMock, list[object]]:
    raw_socket = MagicMock()
    raw_socket.__enter__.return_value = raw_socket
    raw_socket.__exit__.return_value = False

    tls_socket = MagicMock()
    tls_socket.__enter__.return_value = tls_socket
    tls_socket.__exit__.return_value = False
    tls_socket.getpeercert.return_value = certificate or valid_certificate()
    tls_socket.version.return_value = "TLSv1.3"
    tls_socket.cipher.return_value = (
        "TLS_AES_256_GCM_SHA384",
        "TLSv1.3",
        256,
    )

    context = MagicMock()
    context.wrap_socket.return_value = tls_socket

    connection_arguments: list[object] = []

    def create_connection(
        address: tuple[str, int],
        timeout: float,
    ) -> MagicMock:
        connection_arguments.extend([address, timeout])
        return raw_socket

    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(socket, "create_connection", create_connection)

    return context, connection_arguments


def test_verified_certificate_produces_structured_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context, connection_arguments = configure_successful_tls(monkeypatch)
    target = normalize_target("example.com")

    result = check_tls_certificate(
        target,
        timeout=4.0,
        now=datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
    )

    assert result.passed is True
    assert result.status is TLSStatus.PASSED
    assert result.hostname == "example.com"
    assert result.port == 443
    assert result.tls_version == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.cipher_protocol == "TLSv1.3"
    assert result.cipher_bits == 256
    assert result.subject == {"commonName": "example.com"}
    assert result.issuer == {
        "countryName": "US",
        "organizationName": "Example CA",
    }
    assert result.serial_number == "01AB"
    assert result.subject_alt_names == [
        "DNS:example.com",
        "DNS:www.example.com",
    ]
    assert result.not_before == datetime(2026, 8, 1, 0, 0, tzinfo=UTC)
    assert result.not_after == datetime(2026, 9, 17, 10, 0, tzinfo=UTC)
    assert result.days_until_expiry == 30
    assert connection_arguments == [("example.com", 443), 4.0]
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True
    context.wrap_socket.assert_called_once()
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "example.com"


def test_explicit_target_port_is_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, connection_arguments = configure_successful_tls(monkeypatch)
    target = normalize_target("https://example.com:8443")

    result = check_tls_certificate(
        target,
        now=datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
    )

    assert result.port == 8443
    assert connection_arguments[0] == ("example.com", 8443)


def test_certificate_verification_error_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = MagicMock()
    raw_socket = MagicMock()
    raw_socket.__enter__.return_value = raw_socket

    error = ssl.SSLCertVerificationError(1, "certificate verify failed")
    error.verify_code = 62
    error.verify_message = "Hostname mismatch"
    context.wrap_socket.side_effect = error

    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: raw_socket,
    )

    result = check_tls_certificate(normalize_target("example.com"))

    assert result.passed is False
    assert result.status is TLSStatus.VERIFICATION_ERROR
    assert result.verification_code == 62
    assert result.error == "Certificate verification failed: Hostname mismatch"


def test_dns_error_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_dns_error(
        address: tuple[str, int],
        timeout: float,
    ) -> None:
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "create_connection", raise_dns_error)

    result = check_tls_certificate(normalize_target("example.com"))

    assert result.passed is False
    assert result.status is TLSStatus.DNS_ERROR
    assert result.error is not None
    assert result.error.startswith("DNS resolution failed:")


def test_timeout_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_timeout(
        address: tuple[str, int],
        timeout: float,
    ) -> None:
        raise TimeoutError

    monkeypatch.setattr(socket, "create_connection", raise_timeout)

    result = check_tls_certificate(normalize_target("example.com"))

    assert result.passed is False
    assert result.status is TLSStatus.TIMEOUT
    assert result.error == "The TLS connection timed out."


def test_handshake_error_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = MagicMock()
    raw_socket = MagicMock()
    raw_socket.__enter__.return_value = raw_socket
    context.wrap_socket.side_effect = ssl.SSLError("wrong version number")

    monkeypatch.setattr(ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(
        socket,
        "create_connection",
        lambda address, timeout: raw_socket,
    )

    result = check_tls_certificate(normalize_target("example.com"))

    assert result.passed is False
    assert result.status is TLSStatus.HANDSHAKE_ERROR
    assert result.error is not None
    assert result.error.startswith("TLS handshake failed:")


def test_connection_error_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def raise_connection_error(
        address: tuple[str, int],
        timeout: float,
    ) -> None:
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(socket, "create_connection", raise_connection_error)

    result = check_tls_certificate(normalize_target("example.com"))

    assert result.passed is False
    assert result.status is TLSStatus.CONNECTION_ERROR
    assert result.error is not None
    assert result.error.startswith("TLS connection failed:")


def test_malformed_verified_certificate_is_controlled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    certificate = valid_certificate()
    certificate.pop("notAfter")
    configure_successful_tls(monkeypatch, certificate)

    result = check_tls_certificate(
        normalize_target("example.com"),
        now=datetime(2026, 8, 18, 10, 0, tzinfo=UTC),
    )

    assert result.passed is False
    assert result.status is TLSStatus.CERTIFICATE_ERROR
    assert result.error == "Verified certificate is missing notAfter."


def test_naive_check_time_is_rejected() -> None:
    naive_time = datetime(2026, 8, 18, 10, 0, tzinfo=UTC).replace(tzinfo=None)

    with pytest.raises(ValueError, match="must include a timezone"):
        check_tls_certificate(
            normalize_target("example.com"),
            now=naive_time,
        )
