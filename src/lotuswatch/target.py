import re
from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit

from lotuswatch.exceptions import TargetValidationError

SUPPORTED_SCHEMES = {"http", "https"}

DOMAIN_LABEL_PATTERN = re.compile(
    r"^(?!-)[a-z0-9-]{1,63}(?<!-)$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class NormalizedTarget:
    """A validated and normalized website target."""

    original: str
    url: str
    scheme: str
    hostname: str
    port: int | None


def normalize_target(value: str) -> NormalizedTarget:
    """Validate and normalize a domain or HTTP/HTTPS URL."""

    original = value
    value = value.strip()

    if not value:
        raise TargetValidationError("Target cannot be empty.")

    if any(character.isspace() for character in value):
        raise TargetValidationError("Target cannot contain whitespace.")

    if "://" not in value:
        if ":" in value and not _looks_like_host_with_port(value):
            raise TargetValidationError("Target must use the HTTP or HTTPS scheme.")

        value = f"https://{value}"

    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise TargetValidationError("Target is not a valid URL.") from exc

    scheme = parsed.scheme.lower()

    if scheme not in SUPPORTED_SCHEMES:
        raise TargetValidationError("Only HTTP and HTTPS targets are supported.")

    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError(
            "Targets containing embedded credentials are not allowed."
        )

    hostname = parsed.hostname

    if hostname is None:
        raise TargetValidationError("Target must contain a hostname.")

    hostname = _normalize_hostname(hostname)

    try:
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("Target contains an invalid port.") from exc

    netloc = _build_netloc(hostname, port)
    path = parsed.path or "/"

    normalized_url = urlunsplit(
        (
            scheme,
            netloc,
            path,
            parsed.query,
            "",
        )
    )

    return NormalizedTarget(
        original=original,
        url=normalized_url,
        scheme=scheme,
        hostname=hostname,
        port=port,
    )


def _normalize_hostname(hostname: str) -> str:
    """Normalize and validate a hostname or IP address."""

    hostname = hostname.rstrip(".").lower()

    if not hostname:
        raise TargetValidationError("Target must contain a hostname.")

    try:
        address = ip_address(hostname)
    except ValueError:
        pass
    else:
        if not address.is_global:
            raise TargetValidationError("Target IP address must be public.")
        return str(address)

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise TargetValidationError("Target contains an invalid hostname.") from exc

    if len(ascii_hostname) > 253:
        raise TargetValidationError("Hostname is too long.")

    labels = ascii_hostname.split(".")

    if any(not DOMAIN_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise TargetValidationError("Target contains an invalid hostname.")

    return ascii_hostname


def _build_netloc(hostname: str, port: int | None) -> str:
    """Build a URL network location from a hostname and optional port."""

    try:
        ip = ip_address(hostname)
    except ValueError:
        host = hostname
    else:
        host = f"[{hostname}]" if ip.version == 6 else hostname

    if port is None:
        return host

    return f"{host}:{port}"


def _looks_like_host_with_port(value: str) -> bool:
    """Return whether a scheme-less value resembles host:port."""

    host, separator, port = value.partition(":")

    return bool(separator and host and port.isdigit() and "/" not in host)
