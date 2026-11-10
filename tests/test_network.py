import dns.resolver
import httpx
import pytest

from lotuswatch.network import (
    PublicAddressError,
    PublicHTTPTransport,
    resolve_public_address,
)


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.1.2.3",),
        ("169.254.169.254",),
        ("8.8.8.8", "192.168.1.1"),
        ("8.8.8.8", "::1"),
    ],
)
def test_dns_answers_must_all_be_public(monkeypatch, addresses) -> None:
    monkeypatch.setattr(
        "lotuswatch.network._resolve_addresses", lambda hostname, timeout: addresses
    )
    with pytest.raises(PublicAddressError):
        resolve_public_address("example.com", 443)


def test_literal_public_ip_does_not_query_dns(monkeypatch) -> None:
    monkeypatch.setattr(
        "lotuswatch.network._resolve_addresses",
        lambda hostname, timeout: pytest.fail("Literal IP was resolved"),
    )
    assert resolve_public_address("8.8.8.8", 443) == "8.8.8.8"


def test_dns_query_uses_bounded_lifetime(monkeypatch) -> None:
    queried = []

    class NoAnswer:
        rrset = None

    class FakeResolver:
        def resolve(self, hostname, record_type, *, lifetime, raise_on_no_answer):
            queried.append((record_type, lifetime, raise_on_no_answer))
            return NoAnswer()

    monkeypatch.setattr(dns.resolver, "Resolver", FakeResolver)
    with pytest.raises(PublicAddressError):
        resolve_public_address("example.com", 443, timeout=4.0)
    assert queried == [("A", 2.0, False), ("AAAA", 2.0, False)]


def test_transport_pins_address_and_preserves_host_and_sni(monkeypatch) -> None:
    monkeypatch.setattr(
        "lotuswatch.network._resolve_addresses",
        lambda hostname, timeout: ["8.8.8.8"],
    )
    captured = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200)

    with httpx.Client(
        transport=PublicHTTPTransport(httpx.MockTransport(handler))
    ) as client:
        response = client.get("https://example.com/path", timeout=2.0)

    assert response.status_code == 200
    assert str(captured[0].url) == "https://8.8.8.8/path"
    assert captured[0].headers["host"] == "example.com"
    assert captured[0].extensions["sni_hostname"] == "example.com"
    assert captured[0].extensions["timeout"]["connect"] == 2.0


def test_rebinding_to_private_answer_blocks_second_request(monkeypatch) -> None:
    calls = iter([["8.8.8.8"], ["127.0.0.1"]])
    monkeypatch.setattr(
        "lotuswatch.network._resolve_addresses",
        lambda hostname, timeout: next(calls),
    )
    requested = []

    def handler(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200)

    with httpx.Client(
        transport=PublicHTTPTransport(httpx.MockTransport(handler))
    ) as client:
        assert client.get("http://example.com/").status_code == 200
        with pytest.raises(PublicAddressError):
            client.get("https://example.com/next")

    assert requested == ["http://8.8.8.8/"]
