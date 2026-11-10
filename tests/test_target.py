import pytest

from lotuswatch.exceptions import TargetValidationError
from lotuswatch.target import normalize_target


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("example.com", "https://example.com/"),
        ("EXAMPLE.COM", "https://example.com/"),
        ("http://example.com", "http://example.com/"),
        ("https://example.com/", "https://example.com/"),
        (
            "https://example.com/path",
            "https://example.com/path",
        ),
        (
            "https://example.com/path?source=test",
            "https://example.com/path?source=test",
        ),
        (
            "https://example.com/#section",
            "https://example.com/",
        ),
        (
            "example.com:8080",
            "https://example.com:8080/",
        ),
    ],
)
def test_normalize_valid_target(value: str, expected: str) -> None:
    target = normalize_target(value)

    assert target.url == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "   ",
        "ftp://example.com",
        "https://user:password@example.com",
        "https://example.com:invalid",
        "https://-example.com",
        "https://example..com",
        "https://example_com",
        "not a domain",
    ],
)
def test_reject_invalid_target(value: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_target(value)


def test_preserves_original_input() -> None:
    target = normalize_target("  EXAMPLE.COM  ")

    assert target.original == "  EXAMPLE.COM  "
    assert target.url == "https://example.com/"


def test_removes_fragment() -> None:
    target = normalize_target("https://example.com/docs#installation")

    assert target.url == "https://example.com/docs"


def test_exposes_normalized_components() -> None:
    target = normalize_target("https://EXAMPLE.COM:8443/path")

    assert target.scheme == "https"
    assert target.hostname == "example.com"
    assert target.port == 8443


@pytest.mark.parametrize(
    "value",
    [
        "http://127.0.0.1/",
        "http://10.0.0.1/",
        "http://169.254.169.254/",
        "http://192.168.1.1/",
        "http://100.64.0.1/",
        "http://0.0.0.0/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://[::ffff:127.0.0.1]/",
    ],
)
def test_rejects_non_public_ip_targets(value: str) -> None:
    with pytest.raises(TargetValidationError):
        normalize_target(value)


def test_accepts_public_ip_target() -> None:
    assert normalize_target("https://8.8.8.8/").hostname == "8.8.8.8"
