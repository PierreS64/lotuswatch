from dataclasses import dataclass
from typing import Any

import dns.exception
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest

from lotuswatch.checks import (
    DNSQueryStatus,
    DNSRecordType,
    query_dns_records,
)
from lotuswatch.checks.dns import (
    MAX_DNS_ERROR_LENGTH,
    MAX_DNS_RECORD_LENGTH,
    MAX_DNS_RECORDS,
)


@dataclass
class FakeRrset:
    ttl: int


class FakeAnswer(list):
    def __init__(self, records: list[Any], *, ttl: int = 300) -> None:
        super().__init__(records)
        self.rrset = FakeRrset(ttl=ttl)


class FakeResolver:
    def __init__(
        self,
        *,
        answer: FakeAnswer | None = None,
        error: BaseException | None = None,
    ) -> None:
        self.answer = answer if answer is not None else FakeAnswer([])
        self.error = error
        self.timeout = 0.0
        self.lifetime = 0.0
        self.calls: list[dict[str, object]] = []

    def resolve(
        self,
        qname,
        rdtype: str,
        *,
        lifetime: float,
        search: bool,
    ) -> FakeAnswer:
        self.calls.append(
            {
                "qname": qname.to_text(),
                "rdtype": rdtype,
                "lifetime": lifetime,
                "search": search,
            }
        )

        if self.error is not None:
            raise self.error

        return self.answer


def txt_record(value: str):
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.TXT,
        value,
    )


def caa_record(value: str):
    return dns.rdata.from_text(
        dns.rdataclass.IN,
        dns.rdatatype.CAA,
        value,
    )


def long_txt_record(value: str):
    segments = [value[index : index + 200] for index in range(0, len(value), 200)]
    return txt_record(" ".join(f'"{segment}"' for segment in segments))


def test_queries_absolute_name_with_explicit_limits() -> None:
    resolver = FakeResolver(
        answer=FakeAnswer([caa_record('0 issue "letsencrypt.org"')], ttl=600)
    )

    result = query_dns_records(
        "WWW.Example.COM",
        "caa",
        resolver=resolver,
        timeout=1.5,
        lifetime=4.0,
    )

    assert result.completed is True
    assert result.answered is True
    assert result.status is DNSQueryStatus.ANSWER
    assert result.query_name == "www.example.com."
    assert result.record_type is DNSRecordType.CAA
    assert result.ttl == 600
    assert resolver.timeout == 1.5
    assert resolver.lifetime == 4.0
    assert resolver.calls == [
        {
            "qname": "WWW.Example.COM.",
            "rdtype": "CAA",
            "lifetime": 4.0,
            "search": False,
        }
    ]


def test_serializes_typed_caa_fields() -> None:
    resolver = FakeResolver(
        answer=FakeAnswer([caa_record('128 custom "policy.example"')])
    )

    record = query_dns_records(
        "example.com",
        DNSRecordType.CAA,
        resolver=resolver,
    ).records[0]

    assert record.value == "128 custom policy.example"
    assert record.attributes == {
        "flags": 128,
        "tag": "custom",
        "value": "policy.example",
    }
    assert record.truncated is False


def test_joins_multi_segment_txt_record() -> None:
    resolver = FakeResolver(
        answer=FakeAnswer([txt_record('"v=spf1 " "include:_spf.example " "-all"')])
    )

    result = query_dns_records(
        "example.com.",
        DNSRecordType.TXT,
        resolver=resolver,
    )

    assert result.records[0].value == "v=spf1 include:_spf.example -all"
    assert result.records[0].attributes == {}


@pytest.mark.parametrize(
    ("error", "expected_status", "completed"),
    [
        (dns.resolver.NoAnswer(), DNSQueryStatus.NO_ANSWER, True),
        (dns.resolver.NXDOMAIN(), DNSQueryStatus.NXDOMAIN, True),
        (dns.resolver.LifetimeTimeout(), DNSQueryStatus.TIMEOUT, False),
        (dns.resolver.NoNameservers(), DNSQueryStatus.NO_NAMESERVERS, False),
        (dns.exception.FormError(), DNSQueryStatus.ERROR, False),
        (OSError("network unavailable"), DNSQueryStatus.ERROR, False),
    ],
)
def test_maps_controlled_resolver_outcomes(
    error: BaseException,
    expected_status: DNSQueryStatus,
    completed: bool,
) -> None:
    result = query_dns_records(
        "example.com",
        DNSRecordType.TXT,
        resolver=FakeResolver(error=error),
    )

    assert result.status is expected_status
    assert result.completed is completed
    assert result.answered is False
    assert result.records == []

    if completed:
        assert result.error is None
    else:
        assert result.error is not None


def test_empty_answer_is_treated_as_no_answer() -> None:
    result = query_dns_records(
        "example.com",
        DNSRecordType.TXT,
        resolver=FakeResolver(answer=FakeAnswer([], ttl=120)),
    )

    assert result.status is DNSQueryStatus.NO_ANSWER
    assert result.completed is True
    assert result.answered is False
    assert result.ttl == 120


def test_caps_record_count_and_value_length() -> None:
    records = [
        long_txt_record(f"{index:02d}-" + "x" * MAX_DNS_RECORD_LENGTH)
        for index in range(MAX_DNS_RECORDS + 5)
    ]

    result = query_dns_records(
        "example.com",
        DNSRecordType.TXT,
        resolver=FakeResolver(answer=FakeAnswer(records)),
    )

    assert len(result.records) == MAX_DNS_RECORDS
    assert result.records_truncated is True
    assert all(len(record.value) == MAX_DNS_RECORD_LENGTH for record in result.records)
    assert all(record.truncated for record in result.records)


def test_caps_error_diagnostic_length() -> None:
    result = query_dns_records(
        "example.com",
        DNSRecordType.TXT,
        resolver=FakeResolver(error=OSError("x" * 2_000)),
    )

    assert result.status is DNSQueryStatus.ERROR
    assert len(result.error or "") == MAX_DNS_ERROR_LENGTH


def test_invalid_query_name_returns_controlled_error() -> None:
    result = query_dns_records(
        "bad..example.com",
        DNSRecordType.TXT,
        resolver=FakeResolver(),
    )

    assert result.status is DNSQueryStatus.ERROR
    assert result.completed is False
    assert "Invalid DNS query name" in (result.error or "")


@pytest.mark.parametrize("record_type", ["A", "MX", "ANY", "AXFR"])
def test_rejects_unsupported_record_type(record_type: str) -> None:
    with pytest.raises(ValueError, match="Unsupported DNS record type"):
        query_dns_records("example.com", record_type, resolver=FakeResolver())


@pytest.mark.parametrize(
    ("timeout", "lifetime", "message"),
    [
        (0.0, 5.0, "timeout"),
        (-1.0, 5.0, "timeout"),
        (2.0, 0.0, "lifetime"),
        (2.0, -1.0, "lifetime"),
    ],
)
def test_rejects_non_positive_resource_limits(
    timeout: float,
    lifetime: float,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        query_dns_records(
            "example.com",
            DNSRecordType.TXT,
            resolver=FakeResolver(),
            timeout=timeout,
            lifetime=lifetime,
        )


def test_result_serializes_to_json() -> None:
    result = query_dns_records(
        "example.com",
        DNSRecordType.TXT,
        resolver=FakeResolver(answer=FakeAnswer([txt_record('"hello"')])),
    )

    serialized = result.model_dump(mode="json")

    assert serialized["status"] == "answer"
    assert serialized["record_type"] == "TXT"
    assert serialized["records"] == [
        {
            "value": "hello",
            "attributes": {},
            "truncated": False,
        }
    ]
