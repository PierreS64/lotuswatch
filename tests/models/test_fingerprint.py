import re
from typing import cast

import pytest
from pydantic import ValidationError

from lotuswatch.exceptions import TargetValidationError
from lotuswatch.models import (
    FINDING_FINGERPRINT_VERSION,
    Finding,
    Severity,
    finding_fingerprint,
)


def make_finding(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "id": "LW-HTTP-001",
        "severity": Severity.MEDIUM,
        "title": "HTTP does not redirect to HTTPS",
        "description": "The website remains accessible over HTTP.",
        "evidence": {
            "initial_url": "http://example.com/",
            "status_code": 200,
        },
        "recommendation": "Redirect all HTTP requests to HTTPS.",
        "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
    }
    data.update(overrides)
    return Finding.model_validate(data)


def test_matches_canonical_v1_test_vector() -> None:
    fingerprint = finding_fingerprint("https://example.com/", make_finding())

    assert fingerprint == (
        "lwfp:v1:sha256:"
        "1a846f12bf5a874c7dcc7960b430b836e973c27258c14f45f481e35622d270b0"
    )


def test_output_contains_version_algorithm_and_digest() -> None:
    fingerprint = finding_fingerprint("https://example.com/", make_finding())

    assert FINDING_FINGERPRINT_VERSION == 1
    assert re.fullmatch(r"lwfp:v1:sha256:[0-9a-f]{64}", fingerprint)


@pytest.mark.parametrize(
    "target",
    [
        "example.com",
        " HTTPS://EXAMPLE.COM/#section ",
        "https://example.com/",
    ],
)
def test_equivalent_target_inputs_share_fingerprint(target: str) -> None:
    expected = finding_fingerprint("https://example.com/", make_finding())

    assert finding_fingerprint(target, make_finding()) == expected


@pytest.mark.parametrize(
    "target",
    [
        "http://example.com/",
        "https://example.com/admin",
        "https://other.example/",
    ],
)
def test_different_normalized_targets_change_fingerprint(target: str) -> None:
    original = finding_fingerprint("https://example.com/", make_finding())

    assert finding_fingerprint(target, make_finding()) != original


def test_different_finding_identifier_changes_fingerprint() -> None:
    original = finding_fingerprint("https://example.com/", make_finding())
    other = finding_fingerprint(
        "https://example.com/",
        make_finding(id="LW-TLS-001"),
    )

    assert other != original


def test_descriptive_and_volatile_fields_do_not_change_identity() -> None:
    original = make_finding()
    changed = make_finding(
        severity=Severity.CRITICAL,
        title="Completely different title",
        description="Updated description after a later scan.",
        evidence={
            "status_code": 503,
            "initial_url": "http://example.com/changed",
            "observed_at": "2026-08-19T12:00:00Z",
        },
        recommendation="Use a different remediation plan.",
        reference="https://example.com/new-reference",
    )

    assert finding_fingerprint("https://example.com/", changed) == finding_fingerprint(
        "https://example.com/", original
    )


def test_evidence_dictionary_order_does_not_change_identity() -> None:
    first = make_finding(evidence={"status_code": 200, "url": "http://example.com/"})
    second = make_finding(evidence={"url": "http://example.com/", "status_code": 200})

    assert finding_fingerprint("https://example.com/", first) == finding_fingerprint(
        "https://example.com/", second
    )


def test_generation_does_not_mutate_or_serialize_fingerprint() -> None:
    finding = make_finding()
    before = finding.model_dump(mode="json")

    finding_fingerprint("https://example.com/", finding)

    assert finding.model_dump(mode="json") == before
    assert "fingerprint" not in finding.model_dump(mode="json")


@pytest.mark.parametrize(
    "target",
    [
        "",
        "ftp://example.com/",
        "https://user:password@example.com/",
    ],
)
def test_rejects_invalid_target(target: str) -> None:
    with pytest.raises(TargetValidationError):
        finding_fingerprint(target, make_finding())


def test_rejects_non_string_target() -> None:
    with pytest.raises(TypeError, match="normalized_target must be a string"):
        finding_fingerprint(cast(str, 123), make_finding())


def test_rejects_non_finding_input() -> None:
    with pytest.raises(TypeError, match="finding must be a Finding instance"):
        finding_fingerprint(
            "https://example.com/",
            cast(Finding, {"id": "LW-HTTP-001"}),
        )


def test_revalidates_constructed_finding() -> None:
    invalid_finding = make_finding().model_copy(update={"id": "invalid"})

    with pytest.raises(ValidationError):
        finding_fingerprint("https://example.com/", invalid_finding)
