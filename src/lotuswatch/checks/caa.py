from enum import StrEnum
from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from lotuswatch.checks.dns import (
    DEFAULT_DNS_LIFETIME,
    DEFAULT_DNS_TIMEOUT,
    MAX_DNS_ERROR_LENGTH,
    MAX_DNS_RECORD_LENGTH,
    MAX_DNS_RECORDS,
    DNSQueryStatus,
    DNSRecordType,
    DNSRecordValue,
    ResolverProtocol,
    query_dns_records,
)
from lotuswatch.models import Finding, Severity
from lotuswatch.target import NormalizedTarget

MAX_CAA_QUERY_NAMES = 32
CAA_ISSUER_CRITICAL_FLAG = 128
KNOWN_CAA_TAGS = frozenset({"issue", "issuewild", "iodef"})
CAA_REFERENCE = "https://www.rfc-editor.org/rfc/rfc8659.html"


class CAACheckStatus(StrEnum):
    """Possible outcomes of a bounded effective CAA lookup."""

    POLICY_FOUND = "policy_found"
    NO_POLICY = "no_policy"
    NOT_APPLICABLE = "not_applicable"
    QUERY_LIMIT_REACHED = "query_limit_reached"
    TIMEOUT = "timeout"
    NO_NAMESERVERS = "no_nameservers"
    DNS_ERROR = "dns_error"
    INVALID_RESPONSE = "invalid_response"


class CAARecord(BaseModel):
    """One typed and bounded CAA property observation."""

    model_config = ConfigDict(extra="forbid")

    flags: int = Field(ge=0, le=255)
    tag: str = Field(min_length=1, max_length=255)
    value: str = Field(max_length=MAX_DNS_RECORD_LENGTH)
    issuer_critical: bool
    known_tag: bool
    truncated: bool = False


class CAACheckResult(BaseModel):
    """Structured result of resolving the effective CAA record set."""

    model_config = ConfigDict(extra="forbid")

    completed: bool
    status: CAACheckStatus
    hostname: str = Field(min_length=1, max_length=253)
    queried_names: list[str] = Field(
        default_factory=list,
        max_length=MAX_CAA_QUERY_NAMES,
    )
    effective_name: str | None = None
    records: list[CAARecord] = Field(default_factory=list, max_length=MAX_DNS_RECORDS)
    ttl: int | None = Field(default=None, ge=0)
    records_truncated: bool = False
    error: str | None = Field(default=None, max_length=MAX_DNS_ERROR_LENGTH)


def check_caa_records(
    target: NormalizedTarget,
    *,
    resolver: ResolverProtocol | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    lifetime: float = DEFAULT_DNS_LIFETIME,
    max_query_names: int = MAX_CAA_QUERY_NAMES,
) -> CAACheckResult:
    """Find the first CAA RRset from the hostname toward the DNS root."""

    if not 1 <= max_query_names <= MAX_CAA_QUERY_NAMES:
        raise ValueError(
            f"CAA query-name limit must be between 1 and {MAX_CAA_QUERY_NAMES}."
        )

    hostname = target.hostname

    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        return CAACheckResult(
            completed=False,
            status=CAACheckStatus.NOT_APPLICABLE,
            hostname=hostname,
            error="CAA records apply to DNS names, not IP address targets.",
        )

    candidate_names = _caa_candidate_names(hostname)
    query_names = candidate_names[:max_query_names]
    queried_names: list[str] = []

    for candidate in query_names:
        query = query_dns_records(
            candidate,
            DNSRecordType.CAA,
            resolver=resolver,
            timeout=timeout,
            lifetime=lifetime,
        )
        queried_names.append(query.query_name)

        if not query.completed:
            return CAACheckResult(
                completed=False,
                status=_incomplete_status(query.status),
                hostname=hostname,
                queried_names=queried_names,
                error=query.error,
            )

        if not query.answered:
            continue

        records = _parse_caa_records(query.records)

        if records is None:
            return CAACheckResult(
                completed=False,
                status=CAACheckStatus.INVALID_RESPONSE,
                hostname=hostname,
                queried_names=queried_names,
                effective_name=query.query_name,
                error="The DNS response contained an invalid CAA record.",
            )

        return CAACheckResult(
            completed=True,
            status=CAACheckStatus.POLICY_FOUND,
            hostname=hostname,
            queried_names=queried_names,
            effective_name=query.query_name,
            records=records,
            ttl=query.ttl,
            records_truncated=query.records_truncated,
        )

    if len(candidate_names) > len(query_names):
        return CAACheckResult(
            completed=False,
            status=CAACheckStatus.QUERY_LIMIT_REACHED,
            hostname=hostname,
            queried_names=queried_names,
            error=(
                "CAA parent traversal reached the configured query-name limit "
                "before a complete conclusion was available."
            ),
        )

    return CAACheckResult(
        completed=True,
        status=CAACheckStatus.NO_POLICY,
        hostname=hostname,
        queried_names=queried_names,
    )


def caa_result_to_findings(result: CAACheckResult) -> list[Finding]:
    """Convert a completed CAA check into conservative findings."""

    if not result.completed:
        return []

    if result.status is CAACheckStatus.NO_POLICY:
        return [
            Finding(
                id="LW-DNS-001",
                severity=Severity.INFO,
                title="Effective CAA policy is not configured",
                description=(
                    "No CAA record set was found for the target hostname or "
                    "the parent names inspected. This leaves certificate "
                    "issuance subject to the normal public CA ecosystem, but "
                    "it is not evidence that an unauthorized certificate exists."
                ),
                evidence=_finding_evidence(result),
                recommendation=(
                    "Review which certificate authorities and automated "
                    "renewal services the domain requires. If additional "
                    "issuance control is appropriate, publish and test a CAA "
                    "policy without disrupting legitimate renewal."
                ),
                reference=CAA_REFERENCE,
            )
        ]

    if result.status is not CAACheckStatus.POLICY_FOUND:
        return []

    unknown_critical = [
        record
        for record in result.records
        if record.issuer_critical and not record.known_tag
    ]

    if not unknown_critical:
        return []

    evidence = _finding_evidence(result)
    evidence["unknown_critical_records"] = [
        record.model_dump(mode="json") for record in unknown_critical
    ]

    return [
        Finding(
            id="LW-DNS-002",
            severity=Severity.LOW,
            title="Unknown issuer-critical CAA property is present",
            description=(
                "The effective CAA record set contains an unknown property "
                "with the issuer-critical flag. Certificate authorities that "
                "do not support that property may refuse issuance, which can "
                "create certificate availability or renewal risk."
            ),
            evidence=evidence,
            recommendation=(
                "Confirm that every required certificate authority supports "
                "the critical property. Remove the property or clear the "
                "critical flag only after validating the intended issuance policy."
            ),
            reference=CAA_REFERENCE,
        )
    ]


def _caa_candidate_names(hostname: str) -> list[str]:
    labels = hostname.rstrip(".").split(".")
    return [".".join(labels[index:]) for index in range(len(labels))]


def _parse_caa_records(records: list[DNSRecordValue]) -> list[CAARecord] | None:
    parsed: list[CAARecord] = []

    for record in records:
        flags = record.attributes.get("flags")
        tag = record.attributes.get("tag")
        value = record.attributes.get("value")

        if (
            not isinstance(flags, int)
            or isinstance(flags, bool)
            or not 0 <= flags <= 255
            or not isinstance(tag, str)
            or not tag
            or not isinstance(value, str)
        ):
            return None

        normalized_tag = tag.casefold()
        parsed.append(
            CAARecord(
                flags=flags,
                tag=tag,
                value=value,
                issuer_critical=bool(flags & CAA_ISSUER_CRITICAL_FLAG),
                known_tag=normalized_tag in KNOWN_CAA_TAGS,
                truncated=record.truncated,
            )
        )

    return parsed


def _incomplete_status(status: DNSQueryStatus) -> CAACheckStatus:
    if status is DNSQueryStatus.TIMEOUT:
        return CAACheckStatus.TIMEOUT

    if status is DNSQueryStatus.NO_NAMESERVERS:
        return CAACheckStatus.NO_NAMESERVERS

    return CAACheckStatus.DNS_ERROR


def _finding_evidence(result: CAACheckResult) -> dict[str, JsonValue]:
    evidence: dict[str, JsonValue] = {
        "hostname": result.hostname,
        "status": result.status.value,
        "queried_names": result.queried_names,
        "effective_name": result.effective_name,
        "records": [record.model_dump(mode="json") for record in result.records],
        "records_truncated": result.records_truncated,
    }

    if result.ttl is not None:
        evidence["ttl"] = result.ttl

    return evidence
