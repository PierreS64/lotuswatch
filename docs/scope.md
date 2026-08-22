# LotusWatch v0.1 Scope

## Goal

LotusWatch inspects public website transport and security configuration and
turns technical observations into understandable, structured results.

Version 0.1 focuses on low-impact, defensive checks. It is not a penetration
testing framework and does not attempt to exploit identified conditions.

## Implemented

The current codebase supports:

- Domain and HTTP/HTTPS URL validation
- HTTPS as the default scheme when none is provided
- Hostname, port, and embedded-credential validation
- URL normalization and fragment removal
- HTTP-to-HTTPS redirect detection
- Relative and multi-step redirect handling
- A maximum redirect limit
- Redirect-loop and unsupported-scheme detection
- Explicit request timeouts
- Controlled handling of connection errors
- Verified TLS handshakes using the requested hostname as SNI
- TLS version, cipher, certificate identity, issuer, and validity observations
- Certificate expiration and verification findings
- Inspection of six selected HTTP security headers
- Contextual HSTS, CSP, MIME-sniffing, referrer, permissions, and framing findings
- Bounded CAA and TXT queries through the system-configured recursive resolver
- Effective CAA lookup from the target hostname toward the DNS root
- Conservative CAA policy and issuer-critical property findings
- SPF version 1 record identification at the target DNS name
- DMARC record and `p` policy inspection at `_dmarc.<domain>`
- Conservative missing, duplicate, monitoring, and invalid email DNS findings
- Independent continuation after controlled check errors when safe
- Consolidated console sections and severity totals
- Multi-check JSON reports
- Structured findings and severity levels
- Console output
- Versioned UTF-8 JSON reports
- UTC report timestamps
- Protection against accidental report overwrite
- Bounded loading and validation of existing local scan reports
- Stable, versioned finding fingerprints
- Same-target baseline and current report comparison
- Added, resolved, changed, and unchanged finding classification
- Console and deterministic JSON comparison output
- Opt-in scan and comparison severity exit policies for CI/CD
- Backend-neutral monitoring storage contract with a versioned local SQLite
  implementation
- Named local target registration, listing, enable, and disable commands
- On-demand monitored scans with validated report persistence
- Automatic comparison with the newest earlier compatible stored run
- Bounded history inspection and stored-report console or JSON export
- Dry-run retention previews and explicit transactional pruning
- Bounded SQLite integrity inspection and validated non-overwriting online backup
- PowerShell Task Scheduler and POSIX cron integration guidance
- Minimal versioned notification event selection for added and changed findings
- Opt-in generic HTTPS webhook delivery with optional HMAC-SHA256 signing
- Opt-in bounded plain-text Telegram Bot API delivery
- Notification dry runs, deterministic multi-channel delivery, and partial-success
  exit behavior
- Fixed alpha.5 and alpha.6 compatibility fixtures for supported JSON,
  fingerprint, and SQLite schema versions
- Installed wheel and source-distribution compatibility smoke tests
- GitHub Actions formatting, linting, and test checks on Python 3.12 through 3.14

## Planned Beyond the Current Alpha

The following capabilities are not implemented yet:

- TLS protocol and cipher-suite grading
- Certificate revocation and Certificate Transparency checks
- Full Content Security Policy analysis
- DNSSEC validation
- DKIM selector discovery and validation
- Full SPF mechanism, include, alignment, and lookup-limit evaluation
- Organizational-domain and inherited DMARC policy discovery
- Built-in background daemon installation
- Email notification delivery
- Persistent notification queues, replay, and delivery history
- Web dashboards and database-backed trend visualization
- Report signing, provenance verification, or tamper detection
- Custom policy expressions, allowlists, and finding suppressions

## Explicitly Excluded

The following activities are outside the v0.1 scope:

- Vulnerability exploitation
- Credential guessing or brute force
- SQL injection or cross-site scripting payloads
- Authentication or authorization bypass
- Port-range scanning
- Website crawling
- Directory or endpoint enumeration
- WAF, CAPTCHA, or rate-limit evasion
- Denial-of-service or load testing
- DNS zone transfers, brute force, subdomain enumeration, or `ANY` queries
- Custom nameserver probing or automatic DNS-over-HTTPS/TLS/QUIC
- Sending email, connecting to SMTP, or retrieving DMARC reports
- Reading, modifying, or deleting private data

## Current Network Behavior

For one scan, LotusWatch:

- Starts with the HTTP version of the normalized target
- Sends streamed `GET` requests without retaining response bodies
- Uses an explicit timeout
- Follows no more than five redirects
- Accepts only HTTP and HTTPS redirect destinations
- Opens a verified TLS connection using the requested hostname as SNI
- Inspects the peer certificate returned by that connection
- Sends a streamed `GET` request to the selected HTTPS endpoint for headers
- Rejects HTTPS-to-HTTP downgrades during the header check
- Keeps TLS certificate verification enabled for HTTPS requests
- Clears cookies between requests
- Limits captured header values to 2048 characters
- Uses the system-configured recursive DNS resolver
- Applies a two-second per-attempt DNS timeout and five-second total lifetime
- Queries CAA from the target hostname toward parent names, with at most 32
  query names and no DNS root query
- Queries TXT at the target DNS name for SPF and at `_dmarc.<domain>` for DMARC
- Supports only explicit CAA and TXT queries
- Retains at most 50 records and 2048 characters per DNS record value
- Does not perform `ANY`, `AXFR`, reverse-DNS, wildcard, or enumeration queries

The five check groups run in the order redirect, TLS certificate, HTTP security
headers, CAA, then email DNS authentication. A controlled error in one group
does not stop an independent group when continuing is safe. A partial or failed
DNS query remains visible instead of being converted into a missing-control
finding.

Automated tests use mocked HTTP and DNS responses and do not access public
websites or public DNS resolvers.

The `compare` command does not perform a scan or make a network request. It
reads two explicitly selected local UTF-8 JSON files, treats them as untrusted
input, limits each input to 5 MiB, rejects ambiguous JSON and unsupported scan
schemas, and validates both reports before comparison. The first argument is
the older baseline and the second is the newer current report. LotusWatch
requires both reports to represent the same canonical target, but it does not
authenticate their source or enforce their chronological order.

The `monitor run` command performs the same five bounded check groups as one
ordinary scan and stores the validated result. Target registration, listing,
enable, disable, history, show, and prune commands operate only on the selected
local database and perform no website or DNS request. LotusWatch does not run a
background daemon; recurring execution is delegated to an operating-system
scheduler configured by the user.

Database check and backup commands also perform no network request. They require
an explicit existing SQLite source, validate its physical and logical state,
and never repair or migrate it. Backup uses a private temporary file and the
SQLite online backup API, validates the completed copy, and refuses to replace
an existing destination. These commands do not restore, merge, replicate,
encrypt, authenticate, sign, upload, schedule, or automatically rotate data.

Compatibility verification reads only fixed synthetic local fixtures. It does
not scan a target or contact a provider. Installed-artifact tests copy those
fixtures outside the source tree, materialize a temporary monitoring database,
and verify supported alpha-era data through the installed package. Package,
scan report, comparison, notification, fingerprint, and database versions are
independent; see [`compatibility.md`](compatibility.md) for the beta contract.

When notification options are selected, `monitor run` first completes and
stores the validated scan. It then selects only added findings and current
snapshots of changed findings that meet the explicit threshold. The initial
baseline, resolved findings, unchanged findings, and below-threshold changes
do not cause provider traffic. A notification dry run selects and renders the
event without constructing a provider, resolving its secrets, or sending a
request.

Webhook delivery sends a bounded HTTPS `POST` to the explicitly configured
public endpoint. Redirects and environment proxy inheritance are disabled,
TLS certificate verification remains enabled, cookies are cleared between
attempts, and provider response bodies are not read or retained. Timeouts,
connection failures, `429`, and selected transient `5xx` responses can be
retried within the shared bounded attempt and delay policy.

Telegram delivery sends a bounded JSON `POST` only to the fixed official Bot
API HTTPS origin and `sendMessage` method. Messages are plain text with no
Markdown or HTML parse mode and are limited to 4096 characters. Telegram JSON
responses are read through a byte limit and validated before delivery is
accepted. Rate-limit delays are bounded. LotusWatch does not request bot
profiles, updates, chat history, media, or other Telegram operations.

## Data Handling

LotusWatch does not intentionally store response bodies, cookies, passwords,
or authentication tokens.

JSON reports can contain:

- The original user input
- The normalized target URL
- Redirect destinations
- HTTP status codes
- TLS version and cipher observations
- Certificate subject, issuer, serial number, names, and validity timestamps
- Selected HTTP security-header values
- CAA flags, tags, values, effective names, queried names, and TTL observations
- TXT values observed at the SPF and DMARC query names
- Parsed SPF record selections and DMARC policy observations
- Controlled error diagnostics
- Finding evidence

Supported historical artifacts remain subject to current bounds and validation.
Compatibility does not prove their origin, integrity, timestamps, or factual
accuracy. Unsupported future schema versions are rejected rather than silently
rewritten or reinterpreted.

Comparison reports can repeat baseline and current finding snapshots,
including their evidence, references, and remediation text. As a result, a
comparison report may contain sensitive data originating from either input,
even when one finding is resolved in the current scan. Loading and comparison
do not modify the source reports.

Finding fingerprints are derived from the normalized target and finding
identifier. They intentionally exclude severity and other finding content so
those fields can change while identity remains stable. Fingerprints are not
anonymization: predictable input can be tested against them. They are also not
digital signatures and do not prove report integrity, ownership, or origin.

The monitoring database stores public target profiles, scan timestamps,
LotusWatch and report schema versions, complete validated scan reports, and
opaque run identifiers. Stored reports retain the same potentially sensitive
fields as exported JSON. The database is local SQLite and is not encrypted,
authenticated, signed, or synchronized by LotusWatch. Database files,
journals, WAL and shared-memory files, exports, backups, terminal captures, and
scheduler logs must be protected according to the sensitivity of their data.

Notification events contain a profile name, canonical target, event and run
identifiers, timestamps, a selected severity threshold, comparison totals,
and bounded finding identifiers, severities, titles, statuses, and stable
fingerprints. They exclude complete reports, finding evidence, descriptions,
recommendations, certificate details, selected headers, DNS values, and check
diagnostics. Events remain sensitive because they reveal target identity and
selected security observations.

Webhook URLs, optional webhook HMAC secrets, Telegram bot tokens, and Telegram
chat identifiers are resolved only from explicitly named environment
variables when delivery is required. They are not accepted through CLI flags,
stored in SQLite, or serialized into notification results. A webhook URL can
contain sensitive query parameters, and a Telegram token is part of the Bot
API request path. Protect process environments, scheduler configuration,
terminal output, and provider-side logs accordingly.

Webhook HMAC authenticates exact request bytes to a receiver sharing the
secret; it does not encrypt the event, establish report provenance, or provide
exactly-once delivery. Telegram messages are also not encrypted by LotusWatch
beyond the HTTPS transport provided by the remote service. LotusWatch does not
store notification delivery history or provider responses.

Retention is a local explicit operation. Preview lists the exact run IDs
outside the newest retained set, and deletion requires `--apply`, one guarded
transaction, an unchanged plan, and at least one remaining run. LotusWatch does
not delete history automatically or manage backup retention. Database backup is
an explicit non-overwriting local command and does not run on a schedule.

Targets and redirect destinations may include query parameters. Do not place
secrets in a target URL, and review every generated report before sharing or
committing it. Certificate metadata and response headers may also reveal
infrastructure or policy details that should not be published for a private
system.

## Authorization Boundary

Each scan or monitored run creates traffic comparable to a small number of
ordinary browser requests, one TLS handshake, and bounded queries through the
configured recursive DNS resolver. Run LotusWatch at a low frequency against
public endpoints and DNS names you are permitted to inspect, and stop if the
service or resolver rejects or rate-limits the requests. An operating-system
scheduler must not create overlapping or unexpectedly frequent runs.

Notification endpoints are operator-selected destinations, not scan-target
data. Configure only provider accounts and public HTTPS webhook endpoints that
you are authorized to use. Provider requests occur after the monitored scan is
stored and can be retried, so scheduled frequency and provider rate limits
must be considered independently from target scan traffic.

Any future intrusive capability must require explicit authorization from the
system owner and additional safeguards appropriate to its risk.

## Interpretation

A `PASS` only means that the individual limited check passed. For example, a
redirect check can pass even when the final HTTPS endpoint returns an error
status, and observed security headers can still contain an unsuitable policy.
Missing headers describe reduced defense in depth rather than proof of an
exploitable vulnerability. A LotusWatch result is not proof that a website is
secure, healthy, or free of vulnerabilities.

Missing CAA, SPF, or DMARC records are posture observations, not proof of
certificate mis-issuance, email use, or active spoofing. CAA describes current
issuance policy and is not a relying-party certificate validation mechanism.
LotusWatch does not infer that a domain sends email merely because it hosts a
website. Operational DNS errors and truncated results remain incomplete checks
and do not generate misleading missing-record findings.

Report comparison classifies a current-only finding as `added`, a
baseline-only finding as `resolved`, the same identity with different finding
content as `changed`, and identical content as `unchanged`. It compares
findings rather than all raw check data, so a zero-change result is not proof
that the target or every observation stayed identical.

Without `--fail-on`, completed scan and comparison commands return success even
when findings are present. An explicitly selected severity policy returns exit
code `1` when its threshold is met; input, usage, compatibility, comparison,
and output errors return exit code `2`. Comparison policy evaluates only added
findings and current snapshots of changed findings. A policy exit is distinct
from an operational failure, and severity is not a complete risk score.

A monitoring command distinguishes several outcomes. Scan completion records
whether each check reached a conclusion; findings describe selected security
observations; comparison totals describe changes from a compatible baseline;
and storage success confirms that the validated run was persisted. A stored
run can contain findings or controlled operational errors. None of these states
alone proves that the target is secure, available, or exploitable.

Notifications are disabled by default. With explicit channels and a threshold,
`SKIPPED` means the initial baseline or comparison policy required no delivery,
`DELIVERED` means a bounded provider response was validated, and configuration
or provider outcomes mean delivery failed after storage. Exit code `3` reports
this partial-success state: the scan is stored, but at least one requested
notification failed. It does not mean the scan was rolled back or lost.

Delivery is best effort. A provider can accept a request while its response is
lost, causing a retry or later monitoring run to produce a duplicate. LotusWatch
does not claim exactly-once delivery, persist a retry queue, or authenticate
provider-side processing. Notification thresholds remain automation policies,
not complete risk scores.
