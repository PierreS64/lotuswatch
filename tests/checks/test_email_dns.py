from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from lotuswatch.checks import (
    DMARCPolicy,
    EmailDNSStatus,
    check_email_dns_records,
    email_dns_result_to_findings,
)
from lotuswatch.checks.dns import MAX_DNS_RECORDS
from lotuswatch.models import Severity
from lotuswatch.target import normalize_target


@dataclass
class FakeRrset:
    ttl: int


class FakeAnswer(list):
    def __init__(self, records: list[Any], *, ttl: int = 300) -> None:
        super().__init__(records)
        self.rrset = FakeRrset(ttl=ttl)


class FakeResolver:
    def __init__(self, responses: dict[str, FakeAnswer | BaseException]) -> None:
        self.responses = responses
        self.timeout = 0.0
        self.lifetime = 0.0
        self.calls: list[str] = []

    def resolve(
        self,
        qname,
        rdtype: str,
        *,
        lifetime: float,
        search: bool,
    ) -> FakeAnswer:
        query_name = qname.to_text().casefold()
        self.calls.append(query_name)

        assert rdtype == "TXT"
        assert search is False
        assert lifetime > 0

        response = self.responses.get(query_name, dns.resolver.NoAnswer())

        if isinstance(response, BaseException):
            raise response

        return response


def txt_record(value: str):
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        value,
    )


def run_check(
    *,
    spf: list[str] | BaseException | None = None,
    dmarc: list[str] | BaseException | None = None,
):
    responses: dict[str, FakeAnswer | BaseException] = {}

    if isinstance(spf, BaseException):
        responses["example.com."] = spf
    elif spf is not None:
        responses["example.com."] = FakeAnswer([txt_record(value) for value in spf])

    if isinstance(dmarc, BaseException):
        responses["_dmarc.example.com."] = dmarc
    elif dmarc is not None:
        responses["_dmarc.example.com."] = FakeAnswer(
            [txt_record(value) for value in dmarc]
        )

    resolver = FakeResolver(responses)
    result = check_email_dns_records(
        normalize_target("example.com"),
        resolver=resolver,
    )
    return result, resolver


def test_queries_spf_and_dmarc_names_and_recognizes_mixed_case() -> None:
    result, resolver = run_check(
        spf=['"  V=SpF1 include:_spf.example -all  "'],
        dmarc=['"V=dMaRc1; P=ReJeCt"'],
    )

    assert result.completed is True
    assert result.status is EmailDNSStatus.COMPLETED
    assert resolver.calls == ["example.com.", "_dmarc.example.com."]
    assert [record.value for record in result.spf_records] == [
        "  V=SpF1 include:_spf.example -all  "
    ]
    assert result.dmarc_policy is DMARCPolicy.REJECT
    assert email_dns_result_to_findings(result) == []


def test_reconstructs_multi_segment_spf_before_interpretation() -> None:
    resolver = FakeResolver(
        {
            "example.com.": FakeAnswer(
                [txt_record('"v=spf1 include:_spf.example " "-all"')]
            ),
            "_dmarc.example.com.": FakeAnswer([txt_record('"v=DMARC1; p=reject"')]),
        }
    )

    result = check_email_dns_records(
        normalize_target("example.com"),
        resolver=resolver,
    )

    assert result.spf_records[0].value == "v=spf1 include:_spf.example -all"
    assert email_dns_result_to_findings(result) == []


def test_spf_version_requires_token_boundary() -> None:
    result, _ = run_check(
        spf=['"v=spf10 -all"'],
        dmarc=['"v=DMARC1; p=reject"'],
    )

    findings = email_dns_result_to_findings(result)

    assert [finding.id for finding in findings] == ["LW-DNS-003"]


def test_multiple_spf_records_produce_medium_finding() -> None:
    result, _ = run_check(
        spf=[
            '"google-site-verification=value"',
            '"v=spf1 include:_spf.one -all"',
            '"V=SPF1 include:_spf.two -all"',
        ],
        dmarc=['"v=DMARC1; p=reject"'],
    )

    findings = email_dns_result_to_findings(result)

    assert len(findings) == 1
    assert findings[0].id == "LW-DNS-004"
    assert findings[0].severity is Severity.MEDIUM
    assert "permanent evaluation error" in findings[0].description
    assert len(findings[0].evidence["observed_records"]) == 3
    assert len(findings[0].evidence["spf_records"]) == 2


def test_missing_spf_and_dmarc_are_informational_only() -> None:
    result, _ = run_check(
        spf=['"unrelated=value"'],
        dmarc=['"unrelated=value"'],
    )

    findings = email_dns_result_to_findings(result)

    assert [finding.id for finding in findings] == ["LW-DNS-003", "LW-DNS-005"]
    assert all(finding.severity is Severity.INFO for finding in findings)
    assert all("does not establish" in finding.description for finding in findings)


def test_dmarc_none_produces_monitoring_finding() -> None:
    result, _ = run_check(
        spf=['"v=spf1 -all"'],
        dmarc=['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'],
    )

    findings = email_dns_result_to_findings(result)

    assert len(findings) == 1
    assert findings[0].id == "LW-DNS-006"
    assert findings[0].severity is Severity.INFO
    assert findings[0].evidence["dmarc_policy"] == "none"


@pytest.mark.parametrize("policy", ["quarantine", "reject"])
def test_enforcement_dmarc_policies_produce_no_finding(policy: str) -> None:
    result, _ = run_check(
        spf=['"v=spf1 -all"'],
        dmarc=[f'"v=DMARC1; p={policy}"'],
    )

    assert email_dns_result_to_findings(result) == []


@pytest.mark.parametrize(
    "record",
    [
        '"v=DMARC1; rua=mailto:dmarc@example.com"',
        '"v=DMARC1; p=none; P=reject"',
        '"v=DMARC1; p=observe"',
        '"v=DMARC1; p="',
    ],
)
def test_missing_duplicate_or_invalid_dmarc_policy_produces_low_finding(
    record: str,
) -> None:
    result, _ = run_check(
        spf=['"v=spf1 -all"'],
        dmarc=[record],
    )

    findings = email_dns_result_to_findings(result)

    assert result.dmarc_policy is DMARCPolicy.INVALID
    assert len(findings) == 1
    assert findings[0].id == "LW-DNS-007"
    assert findings[0].severity is Severity.LOW


def test_multiple_dmarc_records_are_ambiguous() -> None:
    result, _ = run_check(
        spf=['"v=spf1 -all"'],
        dmarc=['"v=DMARC1; p=none"', '"v=DMARC1; p=reject"'],
    )

    findings = email_dns_result_to_findings(result)

    assert result.dmarc_policy is DMARCPolicy.INVALID
    assert [finding.id for finding in findings] == ["LW-DNS-007"]


def test_dmarc_version_tag_must_be_first() -> None:
    result, _ = run_check(
        spf=['"v=spf1 -all"'],
        dmarc=['"p=reject; v=DMARC1"'],
    )

    assert result.dmarc_records == []
    assert [finding.id for finding in email_dns_result_to_findings(result)] == [
        "LW-DNS-005"
    ]


@pytest.mark.parametrize(
    "error",
    [
        dns.resolver.LifetimeTimeout(),
        dns.resolver.NoNameservers(),
        dns.exception.FormError(),
    ],
)
def test_spf_operational_failure_does_not_produce_missing_spf_finding(
    error: BaseException,
) -> None:
    result, _ = run_check(spf=error, dmarc=None)

    findings = email_dns_result_to_findings(result)

    assert result.status is EmailDNSStatus.PARTIAL
    assert result.spf_interpretation_complete is False
    assert [finding.id for finding in findings] == ["LW-DNS-005"]


def test_dmarc_operational_failure_does_not_produce_dmarc_finding() -> None:
    result, _ = run_check(
        spf=None,
        dmarc=dns.resolver.LifetimeTimeout(),
    )

    findings = email_dns_result_to_findings(result)

    assert result.status is EmailDNSStatus.PARTIAL
    assert result.dmarc_interpretation_complete is False
    assert [finding.id for finding in findings] == ["LW-DNS-003"]


def test_both_operational_failures_produce_no_findings() -> None:
    result, _ = run_check(
        spf=dns.resolver.LifetimeTimeout(),
        dmarc=dns.resolver.NoNameservers(),
    )

    assert result.completed is False
    assert result.status is EmailDNSStatus.FAILED
    assert email_dns_result_to_findings(result) == []


def test_truncated_txt_answer_does_not_produce_missing_finding() -> None:
    unrelated = [f'"token-{index:02d}=value"' for index in range(MAX_DNS_RECORDS + 1)]
    result, _ = run_check(
        spf=unrelated,
        dmarc=['"v=DMARC1; p=reject"'],
    )

    assert result.spf_query is not None
    assert result.spf_query.records_truncated is True
    assert result.spf_interpretation_complete is False
    assert result.status is EmailDNSStatus.PARTIAL
    assert email_dns_result_to_findings(result) == []


@pytest.mark.parametrize(
    "target",
    ["192.0.2.10", "https://[2001:db8::10]", "localhost"],
)
def test_unusable_email_dns_name_is_not_applicable(target: str) -> None:
    resolver = FakeResolver({})

    result = check_email_dns_records(
        normalize_target(target),
        resolver=resolver,
    )

    assert result.status is EmailDNSStatus.NOT_APPLICABLE
    assert result.spf_query is None
    assert result.dmarc_query is None
    assert resolver.calls == []
    assert email_dns_result_to_findings(result) == []


def test_result_and_findings_are_json_serializable() -> None:
    result, _ = run_check(spf=None, dmarc=['"v=DMARC1; p=none"'])

    serialized_result = result.model_dump(mode="json")
    serialized_findings = [
        finding.model_dump(mode="json")
        for finding in email_dns_result_to_findings(result)
    ]

    assert serialized_result["status"] == "completed"
    assert serialized_result["dmarc_policy"] == "none"
    assert [finding["id"] for finding in serialized_findings] == [
        "LW-DNS-003",
        "LW-DNS-006",
    ]
