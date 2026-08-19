from enum import StrEnum
from typing import Any, Protocol

import dns.exception
import dns.name
import dns.resolver
from pydantic import BaseModel, ConfigDict, Field, JsonValue

DEFAULT_DNS_TIMEOUT = 2.0
DEFAULT_DNS_LIFETIME = 5.0
MAX_DNS_RECORDS = 50
MAX_DNS_RECORD_LENGTH = 2_048
MAX_DNS_ERROR_LENGTH = 512


class DNSRecordType(StrEnum):
    """DNS record types supported by the Sprint 3 query layer."""

    CAA = "CAA"
    TXT = "TXT"


class DNSQueryStatus(StrEnum):
    """Possible outcomes of one bounded DNS query."""

    ANSWER = "answer"
    NO_ANSWER = "no_answer"
    NXDOMAIN = "nxdomain"
    TIMEOUT = "timeout"
    NO_NAMESERVERS = "no_nameservers"
    ERROR = "error"


class DNSRecordValue(BaseModel):
    """One bounded and JSON-compatible DNS record value."""

    model_config = ConfigDict(extra="forbid")

    value: str
    attributes: dict[str, JsonValue] = Field(default_factory=dict)
    truncated: bool = False


class DNSQueryResult(BaseModel):
    """Structured result of one DNS record-set query."""

    model_config = ConfigDict(extra="forbid")

    completed: bool
    answered: bool
    status: DNSQueryStatus
    query_name: str = Field(min_length=1)
    record_type: DNSRecordType
    records: list[DNSRecordValue] = Field(default_factory=list)
    ttl: int | None = Field(default=None, ge=0)
    records_truncated: bool = False
    error: str | None = None


class ResolverProtocol(Protocol):
    """Small resolver surface used by the production query and offline tests."""

    timeout: float
    lifetime: float

    def resolve(
        self,
        qname: dns.name.Name,
        rdtype: str,
        *,
        lifetime: float,
        search: bool,
    ) -> Any: ...


def query_dns_records(
    query_name: str,
    record_type: DNSRecordType | str,
    *,
    resolver: ResolverProtocol | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    lifetime: float = DEFAULT_DNS_LIFETIME,
) -> DNSQueryResult:
    """Query one supported DNS record set with explicit resource limits."""

    normalized_type = _normalize_record_type(record_type)

    if timeout <= 0:
        raise ValueError("DNS timeout must be greater than zero.")

    if lifetime <= 0:
        raise ValueError("DNS lifetime must be greater than zero.")

    try:
        absolute_name = _absolute_query_name(query_name)
    except (dns.exception.DNSException, ValueError) as exc:
        return _error_result(
            status=DNSQueryStatus.ERROR,
            query_name=query_name or "<empty>",
            record_type=normalized_type,
            error=f"Invalid DNS query name: {exc}",
        )

    canonical_name = absolute_name.canonicalize().to_text()
    active_resolver = resolver or dns.resolver.Resolver(configure=True)
    active_resolver.timeout = timeout
    active_resolver.lifetime = lifetime

    try:
        answer = active_resolver.resolve(
            absolute_name,
            normalized_type.value,
            lifetime=lifetime,
            search=False,
        )
    except dns.resolver.NoAnswer:
        return _empty_result(
            status=DNSQueryStatus.NO_ANSWER,
            query_name=canonical_name,
            record_type=normalized_type,
        )
    except dns.resolver.NXDOMAIN:
        return _empty_result(
            status=DNSQueryStatus.NXDOMAIN,
            query_name=canonical_name,
            record_type=normalized_type,
        )
    except (dns.resolver.LifetimeTimeout, dns.exception.Timeout) as exc:
        return _error_result(
            status=DNSQueryStatus.TIMEOUT,
            query_name=canonical_name,
            record_type=normalized_type,
            error=f"DNS query timed out: {exc}",
        )
    except dns.resolver.NoNameservers as exc:
        return _error_result(
            status=DNSQueryStatus.NO_NAMESERVERS,
            query_name=canonical_name,
            record_type=normalized_type,
            error=f"No DNS nameserver could answer the query: {exc}",
        )
    except (dns.exception.DNSException, OSError) as exc:
        return _error_result(
            status=DNSQueryStatus.ERROR,
            query_name=canonical_name,
            record_type=normalized_type,
            error=f"DNS query failed: {exc}",
        )

    all_records = [_serialize_record(record, normalized_type) for record in answer]
    all_records.sort(key=lambda record: record.value)
    retained_records = all_records[:MAX_DNS_RECORDS]

    return DNSQueryResult(
        completed=True,
        answered=bool(retained_records),
        status=(
            DNSQueryStatus.ANSWER if retained_records else DNSQueryStatus.NO_ANSWER
        ),
        query_name=canonical_name,
        record_type=normalized_type,
        records=retained_records,
        ttl=_answer_ttl(answer),
        records_truncated=len(all_records) > MAX_DNS_RECORDS,
    )


def _normalize_record_type(value: DNSRecordType | str) -> DNSRecordType:
    if isinstance(value, DNSRecordType):
        return value

    try:
        return DNSRecordType(value.strip().upper())
    except ValueError as exc:
        supported = ", ".join(record_type.value for record_type in DNSRecordType)
        raise ValueError(
            f"Unsupported DNS record type. Supported types: {supported}."
        ) from exc


def _absolute_query_name(value: str) -> dns.name.Name:
    if not value or not value.strip():
        raise ValueError("DNS query name cannot be empty.")

    name = dns.name.from_text(value.strip())

    if not name.is_absolute():
        name = name.concatenate(dns.name.root)

    return name


def _serialize_record(
    record: Any,
    record_type: DNSRecordType,
) -> DNSRecordValue:
    if record_type is DNSRecordType.TXT:
        value = _txt_record_value(record)
        bounded_value, truncated = _bounded_text(value)
        return DNSRecordValue(
            value=bounded_value,
            truncated=truncated,
        )

    flags = int(record.flags)
    tag = _dns_bytes_to_text(record.tag)
    caa_value = _dns_bytes_to_text(record.value)
    bounded_caa_value, value_truncated = _bounded_text(caa_value)
    display_value = f"{flags} {tag} {caa_value}"
    bounded_display, display_truncated = _bounded_text(display_value)

    return DNSRecordValue(
        value=bounded_display,
        attributes={
            "flags": flags,
            "tag": tag,
            "value": bounded_caa_value,
        },
        truncated=value_truncated or display_truncated,
    )


def _txt_record_value(record: Any) -> str:
    strings = getattr(record, "strings", None)

    if strings is None:
        return str(record.to_text())

    joined = b"".join(
        segment if isinstance(segment, bytes) else str(segment).encode("utf-8")
        for segment in strings
    )
    return joined.decode("utf-8", errors="backslashreplace")


def _dns_bytes_to_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")

    return str(value)


def _bounded_text(value: str) -> tuple[str, bool]:
    truncated = len(value) > MAX_DNS_RECORD_LENGTH
    return value[:MAX_DNS_RECORD_LENGTH], truncated


def _answer_ttl(answer: Any) -> int | None:
    rrset = getattr(answer, "rrset", None)
    ttl = getattr(rrset, "ttl", None)

    if isinstance(ttl, int) and ttl >= 0:
        return ttl

    return None


def _empty_result(
    *,
    status: DNSQueryStatus,
    query_name: str,
    record_type: DNSRecordType,
) -> DNSQueryResult:
    return DNSQueryResult(
        completed=True,
        answered=False,
        status=status,
        query_name=query_name,
        record_type=record_type,
    )


def _error_result(
    *,
    status: DNSQueryStatus,
    query_name: str,
    record_type: DNSRecordType,
    error: str,
) -> DNSQueryResult:
    return DNSQueryResult(
        completed=False,
        answered=False,
        status=status,
        query_name=query_name,
        record_type=record_type,
        error=error[:MAX_DNS_ERROR_LENGTH],
    )
