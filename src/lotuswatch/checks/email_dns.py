from enum import StrEnum
from ipaddress import ip_address

from pydantic import BaseModel, ConfigDict, Field, JsonValue

from lotuswatch.checks.dns import (
    DEFAULT_DNS_LIFETIME,
    DEFAULT_DNS_TIMEOUT,
    MAX_DNS_RECORDS,
    DNSQueryResult,
    DNSRecordType,
    DNSRecordValue,
    ResolverProtocol,
    query_dns_records,
)
from lotuswatch.models import Finding, Severity
from lotuswatch.target import NormalizedTarget

SPF_REFERENCE = "https://www.rfc-editor.org/rfc/rfc7208.html"
DMARC_REFERENCE = "https://www.rfc-editor.org/rfc/rfc7489.html"


class EmailDNSStatus(StrEnum):
    """Overall state of the independent SPF and DMARC observations."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class DMARCPolicy(StrEnum):
    """DMARC policy values interpreted by LotusWatch."""

    NONE = "none"
    QUARANTINE = "quarantine"
    REJECT = "reject"
    INVALID = "invalid"


class EmailDNSCheckResult(BaseModel):
    """Structured SPF and DMARC TXT observations for one DNS name."""

    model_config = ConfigDict(extra="forbid")

    completed: bool
    status: EmailDNSStatus
    hostname: str = Field(min_length=1, max_length=253)
    spf_query: DNSQueryResult | None = None
    dmarc_query: DNSQueryResult | None = None
    spf_records: list[DNSRecordValue] = Field(
        default_factory=list,
        max_length=MAX_DNS_RECORDS,
    )
    dmarc_records: list[DNSRecordValue] = Field(
        default_factory=list,
        max_length=MAX_DNS_RECORDS,
    )
    dmarc_policy: DMARCPolicy | None = None
    spf_interpretation_complete: bool = False
    dmarc_interpretation_complete: bool = False


def check_email_dns_records(
    target: NormalizedTarget,
    *,
    resolver: ResolverProtocol | None = None,
    timeout: float = DEFAULT_DNS_TIMEOUT,
    lifetime: float = DEFAULT_DNS_LIFETIME,
) -> EmailDNSCheckResult:
    """Inspect bounded SPF and DMARC TXT records without evaluating mail."""

    hostname = target.hostname

    if not _is_usable_email_dns_name(hostname):
        return EmailDNSCheckResult(
            completed=False,
            status=EmailDNSStatus.NOT_APPLICABLE,
            hostname=hostname,
        )

    spf_query = query_dns_records(
        hostname,
        DNSRecordType.TXT,
        resolver=resolver,
        timeout=timeout,
        lifetime=lifetime,
    )
    dmarc_query = query_dns_records(
        f"_dmarc.{hostname}",
        DNSRecordType.TXT,
        resolver=resolver,
        timeout=timeout,
        lifetime=lifetime,
    )

    spf_records = [
        record for record in spf_query.records if _is_spf_record(record.value)
    ]
    dmarc_records = [
        record for record in dmarc_query.records if _is_dmarc_record(record.value)
    ]
    spf_complete = spf_query.completed and not spf_query.records_truncated
    dmarc_complete = dmarc_query.completed and not dmarc_query.records_truncated
    dmarc_policy = (
        _parse_dmarc_policy(dmarc_records) if dmarc_complete and dmarc_records else None
    )

    status = _overall_status(spf_complete, dmarc_complete)

    return EmailDNSCheckResult(
        completed=status is EmailDNSStatus.COMPLETED,
        status=status,
        hostname=hostname,
        spf_query=spf_query,
        dmarc_query=dmarc_query,
        spf_records=spf_records,
        dmarc_records=dmarc_records,
        dmarc_policy=dmarc_policy,
        spf_interpretation_complete=spf_complete,
        dmarc_interpretation_complete=dmarc_complete,
    )


def email_dns_result_to_findings(result: EmailDNSCheckResult) -> list[Finding]:
    """Convert complete SPF and DMARC observations into conservative findings."""

    findings: list[Finding] = []

    if result.spf_interpretation_complete and result.spf_query is not None:
        findings.extend(_spf_findings(result))

    if result.dmarc_interpretation_complete and result.dmarc_query is not None:
        findings.extend(_dmarc_findings(result))

    return findings


def _spf_findings(result: EmailDNSCheckResult) -> list[Finding]:
    if not result.spf_records:
        return [
            Finding(
                id="LW-DNS-003",
                severity=Severity.INFO,
                title="SPF record is not published",
                description=(
                    "No SPF version 1 TXT record was observed at the target "
                    "DNS name. This is an email-authentication posture "
                    "observation and does not establish that the domain sends "
                    "email or is currently spoofable."
                ),
                evidence=_spf_evidence(result),
                recommendation=(
                    "Determine whether the domain is used in email identities. "
                    "If it is, inventory every legitimate sender before "
                    "publishing and testing a single SPF policy."
                ),
                reference=SPF_REFERENCE,
            )
        ]

    if len(result.spf_records) > 1:
        return [
            Finding(
                id="LW-DNS-004",
                severity=Severity.MEDIUM,
                title="Multiple SPF records are published",
                description=(
                    "More than one SPF version 1 TXT record was observed. SPF "
                    "evaluation requires a single selected record, so this "
                    "configuration can produce a permanent evaluation error."
                ),
                evidence=_spf_evidence(result),
                recommendation=(
                    "Consolidate the authorized senders into one SPF record. "
                    "Validate the combined policy and its DNS lookup behavior "
                    "before removing the duplicate records."
                ),
                reference=SPF_REFERENCE,
            )
        ]

    return []


def _dmarc_findings(result: EmailDNSCheckResult) -> list[Finding]:
    if not result.dmarc_records:
        return [
            Finding(
                id="LW-DNS-005",
                severity=Severity.INFO,
                title="DMARC record is not published",
                description=(
                    "No DMARC1 policy record was observed at the queried "
                    "_dmarc DNS name. This is an email-authentication posture "
                    "observation and does not establish that the domain sends "
                    "email or is currently spoofable."
                ),
                evidence=_dmarc_evidence(result),
                recommendation=(
                    "Determine whether the domain is used for email. If it is, "
                    "deploy DMARC only after SPF and DKIM alignment are "
                    "understood, beginning with a monitored policy where appropriate."
                ),
                reference=DMARC_REFERENCE,
            )
        ]

    if result.dmarc_policy is DMARCPolicy.NONE:
        return [
            Finding(
                id="LW-DNS-006",
                severity=Severity.INFO,
                title="DMARC uses a monitoring policy",
                description=(
                    "The observed DMARC policy is p=none. This requests "
                    "monitoring without asking receivers to quarantine or "
                    "reject messages that fail DMARC evaluation."
                ),
                evidence=_dmarc_evidence(result),
                recommendation=(
                    "Review DMARC reports and confirm that every legitimate "
                    "sender aligns correctly. Increase enforcement gradually "
                    "only when the domain owner is ready for the delivery impact."
                ),
                reference=DMARC_REFERENCE,
            )
        ]

    if result.dmarc_policy is DMARCPolicy.INVALID:
        return [
            Finding(
                id="LW-DNS-007",
                severity=Severity.LOW,
                title="DMARC policy value is invalid or ambiguous",
                description=(
                    "A DMARC1 record is present, but the record set does not "
                    "provide exactly one valid p value of none, quarantine, or "
                    "reject. Receivers may be unable to apply the intended policy."
                ),
                evidence=_dmarc_evidence(result),
                recommendation=(
                    "Publish exactly one DMARC policy record with one valid p "
                    "tag. Confirm the intended policy and reporting settings "
                    "with the domain's email operators before changing DNS."
                ),
                reference=DMARC_REFERENCE,
            )
        ]

    return []


def _is_usable_email_dns_name(hostname: str) -> bool:
    try:
        ip_address(hostname)
    except ValueError:
        return "." in hostname

    return False


def _is_spf_record(value: str) -> bool:
    parts = value.strip().split(maxsplit=1)
    return bool(parts and parts[0].casefold() == "v=spf1")


def _is_dmarc_record(value: str) -> bool:
    first_tag = value.strip().split(";", maxsplit=1)[0]
    name, separator, tag_value = first_tag.partition("=")
    return bool(
        separator
        and name.strip().casefold() == "v"
        and tag_value.strip().casefold() == "dmarc1"
    )


def _parse_dmarc_policy(records: list[DNSRecordValue]) -> DMARCPolicy:
    if len(records) != 1:
        return DMARCPolicy.INVALID

    policy_values: list[str] = []

    for segment in records[0].value.split(";"):
        name, separator, value = segment.partition("=")

        if separator and name.strip().casefold() == "p":
            policy_values.append(value.strip().casefold())

    if len(policy_values) != 1:
        return DMARCPolicy.INVALID

    try:
        return DMARCPolicy(policy_values[0])
    except ValueError:
        return DMARCPolicy.INVALID


def _overall_status(spf_complete: bool, dmarc_complete: bool) -> EmailDNSStatus:
    if spf_complete and dmarc_complete:
        return EmailDNSStatus.COMPLETED

    if spf_complete or dmarc_complete:
        return EmailDNSStatus.PARTIAL

    return EmailDNSStatus.FAILED


def _spf_evidence(result: EmailDNSCheckResult) -> dict[str, JsonValue]:
    assert result.spf_query is not None
    return _query_evidence(
        hostname=result.hostname,
        query=result.spf_query,
        matching_key="spf_records",
        matching_records=result.spf_records,
    )


def _dmarc_evidence(result: EmailDNSCheckResult) -> dict[str, JsonValue]:
    assert result.dmarc_query is not None
    evidence = _query_evidence(
        hostname=result.hostname,
        query=result.dmarc_query,
        matching_key="dmarc_records",
        matching_records=result.dmarc_records,
    )
    evidence["dmarc_policy"] = (
        result.dmarc_policy.value if result.dmarc_policy is not None else None
    )
    return evidence


def _query_evidence(
    *,
    hostname: str,
    query: DNSQueryResult,
    matching_key: str,
    matching_records: list[DNSRecordValue],
) -> dict[str, JsonValue]:
    return {
        "hostname": hostname,
        "query_name": query.query_name,
        "query_status": query.status.value,
        "observed_records": [
            record.model_dump(mode="json") for record in query.records
        ],
        matching_key: [record.model_dump(mode="json") for record in matching_records],
        "records_truncated": query.records_truncated,
    }
