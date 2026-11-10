from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from lotuswatch.checks import (
    CAACheckStatus,
    CAARecord,
    caa_result_to_findings,
    check_caa_records,
)
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

        assert rdtype == "CAA"
        assert search is False
        assert lifetime > 0

        response = self.responses.get(query_name, dns.resolver.NoAnswer())

        if isinstance(response, BaseException):
            raise response

        return response


def caa_record(value: str):
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.CAA,
        value,
    )


def test_uses_caa_rrset_on_exact_hostname() -> None:
    resolver = FakeResolver(
        {
            "www.example.com.": FakeAnswer(
                [caa_record('0 issue "letsencrypt.org"')],
                ttl=600,
            )
        }
    )

    result = check_caa_records(
        normalize_target("www.example.com"),
        resolver=resolver,
    )

    assert result.completed is True
    assert result.status is CAACheckStatus.POLICY_FOUND
    assert result.queried_names == ["www.example.com."]
    assert result.effective_name == "www.example.com."
    assert result.ttl == 600
    assert resolver.calls == ["www.example.com."]
    assert result.records == [
        CAARecord(
            flags=0,
            tag="issue",
            value="letsencrypt.org",
            issuer_critical=False,
            known_tag=True,
        )
    ]


def test_uses_first_parent_caa_rrset_in_deterministic_order() -> None:
    resolver = FakeResolver(
        {"example.com.": FakeAnswer([caa_record('0 issuewild "ca.example"')])}
    )

    result = check_caa_records(
        normalize_target("shop.eu.example.com"),
        resolver=resolver,
    )

    assert result.status is CAACheckStatus.POLICY_FOUND
    assert result.queried_names == [
        "shop.eu.example.com.",
        "eu.example.com.",
        "example.com.",
    ]
    assert result.effective_name == "example.com."
    assert resolver.calls == result.queried_names


def test_no_policy_traverses_to_tld_but_never_queries_root() -> None:
    resolver = FakeResolver({})

    result = check_caa_records(
        normalize_target("www.example.com"),
        resolver=resolver,
    )

    assert result.completed is True
    assert result.status is CAACheckStatus.NO_POLICY
    assert result.queried_names == [
        "www.example.com.",
        "example.com.",
        "com.",
    ]
    assert "." not in resolver.calls


def test_query_limit_is_incomplete_and_produces_no_finding() -> None:
    result = check_caa_records(
        normalize_target("one.two.example.com"),
        resolver=FakeResolver({}),
        max_query_names=2,
    )

    assert result.completed is False
    assert result.status is CAACheckStatus.QUERY_LIMIT_REACHED
    assert result.queried_names == ["one.two.example.com.", "two.example.com."]
    assert caa_result_to_findings(result) == []


@pytest.mark.parametrize("max_query_names", [0, 33])
def test_rejects_invalid_query_limit(max_query_names: int) -> None:
    with pytest.raises(ValueError, match="query-name limit"):
        check_caa_records(
            normalize_target("example.com"),
            resolver=FakeResolver({}),
            max_query_names=max_query_names,
        )


@pytest.mark.parametrize(
    ("error", "expected_status"),
    [
        (dns.resolver.LifetimeTimeout(), CAACheckStatus.TIMEOUT),
        (dns.resolver.NoNameservers(), CAACheckStatus.NO_NAMESERVERS),
        (dns.exception.FormError(), CAACheckStatus.DNS_ERROR),
    ],
)
def test_operational_failure_stops_chain_without_findings(
    error: BaseException,
    expected_status: CAACheckStatus,
) -> None:
    resolver = FakeResolver(
        {
            "www.example.com.": dns.resolver.NoAnswer(),
            "example.com.": error,
            "com.": FakeAnswer([caa_record('0 issue "ca.example"')]),
        }
    )

    result = check_caa_records(
        normalize_target("www.example.com"),
        resolver=resolver,
    )

    assert result.completed is False
    assert result.status is expected_status
    assert result.queried_names == ["www.example.com.", "example.com."]
    assert "com." not in resolver.calls
    assert caa_result_to_findings(result) == []


def test_ip_address_is_not_applicable_and_produces_no_finding() -> None:
    resolver = FakeResolver({})

    result = check_caa_records(
        normalize_target("8.8.8.8"),
        resolver=resolver,
    )

    assert result.completed is False
    assert result.status is CAACheckStatus.NOT_APPLICABLE
    assert resolver.calls == []
    assert caa_result_to_findings(result) == []


def test_known_tags_are_case_insensitive_and_preserve_observed_values() -> None:
    resolver = FakeResolver(
        {
            "example.com.": FakeAnswer(
                [
                    caa_record('0 ISSUE "ca.example"'),
                    caa_record('0 IssueWild ";"'),
                    caa_record('0 IODEF "mailto:security@example.com"'),
                ]
            )
        }
    )

    result = check_caa_records(
        normalize_target("example.com"),
        resolver=resolver,
    )

    assert [record.tag for record in result.records] == [
        "IODEF",
        "ISSUE",
        "IssueWild",
    ]
    assert all(record.known_tag for record in result.records)
    assert caa_result_to_findings(result) == []


def test_issue_semicolon_is_intentional_policy_not_a_finding() -> None:
    result = check_caa_records(
        normalize_target("example.com"),
        resolver=FakeResolver(
            {"example.com.": FakeAnswer([caa_record('0 issue ";"')])}
        ),
    )

    assert result.status is CAACheckStatus.POLICY_FOUND
    assert result.records[0].value == ";"
    assert caa_result_to_findings(result) == []


def test_flag_value_one_is_not_the_issuer_critical_bit() -> None:
    result = check_caa_records(
        normalize_target("example.com"),
        resolver=FakeResolver(
            {"example.com.": FakeAnswer([caa_record('1 future "value"')])}
        ),
    )

    assert result.records[0].issuer_critical is False
    assert result.records[0].known_tag is False
    assert caa_result_to_findings(result) == []


def test_unknown_issuer_critical_property_produces_low_finding() -> None:
    result = check_caa_records(
        normalize_target("example.com"),
        resolver=FakeResolver(
            {
                "example.com.": FakeAnswer(
                    [
                        caa_record('0 issue "ca.example"'),
                        caa_record('128 future "required-policy"'),
                    ],
                    ttl=900,
                )
            }
        ),
    )

    findings = caa_result_to_findings(result)

    assert len(findings) == 1
    assert findings[0].id == "LW-DNS-002"
    assert findings[0].severity is Severity.LOW
    assert "may refuse issuance" in findings[0].description
    assert findings[0].evidence["hostname"] == "example.com"
    assert findings[0].evidence["effective_name"] == "example.com."
    assert findings[0].evidence["ttl"] == 900
    assert findings[0].evidence["unknown_critical_records"] == [
        {
            "flags": 128,
            "tag": "future",
            "value": "required-policy",
            "issuer_critical": True,
            "known_tag": False,
            "truncated": False,
        }
    ]


def test_missing_policy_produces_only_conservative_info_finding() -> None:
    result = check_caa_records(
        normalize_target("example.com"),
        resolver=FakeResolver({}),
    )

    findings = caa_result_to_findings(result)

    assert len(findings) == 1
    assert findings[0].id == "LW-DNS-001"
    assert findings[0].severity is Severity.INFO
    assert "not evidence" in findings[0].description
    assert findings[0].evidence == {
        "hostname": "example.com",
        "status": "no_policy",
        "queried_names": ["example.com.", "com."],
        "effective_name": None,
        "records": [],
        "records_truncated": False,
    }


def test_invalid_typed_record_is_incomplete_and_produces_no_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from lotuswatch.checks import caa as caa_module
    from lotuswatch.checks.dns import (
        DNSQueryResult,
        DNSQueryStatus,
        DNSRecordType,
        DNSRecordValue,
    )

    monkeypatch.setattr(
        caa_module,
        "query_dns_records",
        lambda *args, **kwargs: DNSQueryResult(
            completed=True,
            answered=True,
            status=DNSQueryStatus.ANSWER,
            query_name="example.com.",
            record_type=DNSRecordType.CAA,
            records=[DNSRecordValue(value="invalid", attributes={})],
        ),
    )

    result = check_caa_records(normalize_target("example.com"))

    assert result.completed is False
    assert result.status is CAACheckStatus.INVALID_RESPONSE
    assert caa_result_to_findings(result) == []


def test_result_and_finding_evidence_are_json_serializable() -> None:
    result = check_caa_records(
        normalize_target("example.com"),
        resolver=FakeResolver(
            {"example.com.": FakeAnswer([caa_record('128 custom "value"')])}
        ),
    )

    serialized_result = result.model_dump(mode="json")
    serialized_finding = caa_result_to_findings(result)[0].model_dump(mode="json")

    assert serialized_result["status"] == "policy_found"
    assert serialized_result["records"][0]["issuer_critical"] is True
    assert serialized_finding["evidence"]["records"][0]["tag"] == "custom"
