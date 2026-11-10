"""Public-address enforcement at the connection boundary."""

from ipaddress import ip_address

import dns.exception
import dns.resolver
import httpx


class PublicAddressError(ValueError):
    """A hostname has no exclusively public connection addresses."""


class PublicResolutionError(PublicAddressError):
    """The bounded public-address DNS lookup did not complete."""


def _resolve_addresses(hostname: str, timeout: float) -> list[str]:
    resolver = dns.resolver.Resolver()
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(
                hostname,
                record_type,
                lifetime=max(timeout / 2, 0.1),
                raise_on_no_answer=False,
            )
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            raise PublicResolutionError(f"DNS resolution failed: {exc}") from exc
        if answer.rrset is not None:
            addresses.extend(record.to_text() for record in answer)
    return addresses


def resolve_public_address(hostname: str, port: int, *, timeout: float = 3.0) -> str:
    """Resolve a hostname and choose one address only if every answer is public."""

    try:
        literal = ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if not literal.is_global:
            raise PublicAddressError("Connection destination is not a public IP.")
        return str(literal)

    addresses = [ip_address(answer) for answer in _resolve_addresses(hostname, timeout)]
    if not addresses:
        raise PublicResolutionError("Connection destination has no IP addresses.")
    if any(not address.is_global for address in addresses):
        raise PublicAddressError("Connection destination resolves to a non-public IP.")
    return str(addresses[0])


class PublicHTTPTransport(httpx.BaseTransport):
    """Pin each HTTP connection to a validated IP while keeping Host and TLS SNI."""

    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport or httpx.HTTPTransport(
            trust_env=False,
            limits=httpx.Limits(max_keepalive_connections=0),
        )

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        hostname = request.url.host
        if hostname is None:
            raise PublicAddressError("Connection destination has no hostname.")
        port = request.url.port or (443 if request.url.scheme == "https" else 80)
        connect_timeout = request.extensions.get("timeout", {}).get("connect")
        address = resolve_public_address(hostname, port, timeout=connect_timeout or 3.0)
        extensions = dict(request.extensions)
        extensions["sni_hostname"] = hostname
        pinned = httpx.Request(
            method=request.method,
            url=request.url.copy_with(host=address),
            headers=request.headers,
            stream=request.stream,
            extensions=extensions,
        )
        return self._transport.handle_request(pinned)

    def close(self) -> None:
        self._transport.close()
