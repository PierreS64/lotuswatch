# Security Policy

## Supported Versions

LotusWatch is currently an early alpha project. Security fixes are applied to
the latest code on the `main` branch.

| Version | Supported |
| --- | --- |
| `main` | Yes |
| `0.1.x-alpha` | Best effort |
| Older versions | No |

## Reporting a Vulnerability

Please do not publish exploitable details, proof-of-concept payloads, secrets,
or private scan reports in a public GitHub issue.

Use GitHub's private vulnerability reporting option in the repository
**Security** tab when it is available. Include:

- A concise description of the vulnerability
- The affected version or commit
- Security impact and realistic attack scenario
- Minimal steps to reproduce the problem
- Suggested remediation, if known

If private vulnerability reporting is unavailable, open a public issue titled
`Security contact request` without technical details or sensitive data. A
private communication method can then be arranged with the maintainer.

Reports will be reviewed on a best-effort basis. Please allow time for the
issue to be reproduced and fixed before public disclosure.

## Sensitive Data

Do not submit any of the following in issues, discussions, pull requests, or
sample reports:

- Passwords or access tokens
- Cookies or session identifiers
- Private keys or certificates containing private keys
- Internal or private URLs
- Customer data
- Reports containing confidential redirect destinations or query parameters
- Reports containing private DNS names, CAA policy, TXT records, SPF data, or
  DMARC reporting addresses
- Baseline, current, or comparison reports containing private findings or
  historical infrastructure details
- Monitoring databases, SQLite journals, WAL or shared-memory files, backups,
  scheduler logs, or exported historical reports
- Webhook endpoint URLs, HMAC secrets, Telegram bot tokens, or Telegram chat
  identifiers
- Notification events, terminal captures, delivery logs, or provider responses

LotusWatch reports can contain the original target, normalized URL, redirect
destinations, HTTP status codes, certificate metadata, selected security-header
values, DNS query names, CAA values, TXT records, parsed SPF and DMARC
observations, and controlled error diagnostics. TXT data can include provider
identifiers, verification tokens, reporting addresses, or other operational
metadata. These details can reveal private hostnames, query parameters,
infrastructure, or security policy. Review generated reports before sharing or
committing them.

Comparison reports can preserve complete baseline and current finding
snapshots. Resolved findings may therefore remain present in comparison output
after they disappear from the current scan. Treat both source reports and the
derived comparison as sensitive. Finding fingerprints do not anonymize target
identity and do not authenticate or sign report contents.

Local monitoring stores complete validated reports and historical target
metadata in SQLite. LotusWatch does not encrypt, authenticate, or sign the
database or its backups. Restrict filesystem access to database files and their
journal, WAL, and shared-memory companions. Stop scheduled jobs before making a
consistent backup, protect scheduler output, and review stored reports before
exporting, sharing, or committing them. Retention is explicit and does not
replace a backup and data-handling policy.

Notification events are intentionally smaller than scan reports but remain
sensitive. They contain the monitored profile and canonical target, event and
run identifiers, timestamps, the selected threshold, comparison totals, and
bounded finding identifiers, severities, titles, statuses, and fingerprints.
They do not contain complete reports, evidence, descriptions, recommendations,
certificate metadata, header values, DNS records, or check diagnostics.

Notification credentials are resolved only from the explicitly named
environment variables required by a selected provider. LotusWatch does not
accept them as CLI values, store them in SQLite, or include them in public
delivery results. Protect scheduler and process environments. A webhook URL
can contain sensitive query parameters, and a Telegram bot token forms part of
the Bot API request path; neither complete URL should be logged or shared.

Optional webhook HMAC-SHA256 authenticates the exact transmitted bytes when
the receiver protects the same secret. It does not encrypt the event, sign the
stored scan, establish report provenance, or prevent replay. Telegram content
uses plain text to avoid formatting injection and relies on provider HTTPS for
transport protection. LotusWatch does not retain webhook response bodies or
Telegram provider responses in delivery results or history.

## Authorized Use

LotusWatch is intended for defensive inspection of public website security
configuration.

The current redirect and header checks make a small number of streamed HTTP
requests without retaining response bodies. The TLS check performs one verified
handshake and inspects the peer certificate. Cookies are cleared between
redirect requests, and captured header values are limited in length. These
checks also make bounded CAA and TXT queries through the system-configured
recursive resolver. DNS record counts, values, diagnostics, and CAA traversal
are limited; LotusWatch does not perform `ANY`, `AXFR`, reverse-DNS, wildcard,
or enumeration queries. The checks do not attempt exploitation, but you must
still run them only against public endpoints and DNS names you are permitted to
inspect.

The comparison command reads only the two local report paths supplied by the
user and performs no website or DNS requests. It bounds and validates those
files, but it does not establish who created them, whether they were modified,
or whether the baseline is genuinely older than the current report.

Each `monitor run` performs the same bounded network checks as a normal scan.
Registration, listing, history, show, enable, disable, and prune operations use
only the selected local database. LotusWatch does not install a daemon or
coordinate overlapping scheduler jobs; configure recurring runs at a safe
frequency and use one process per database.

Notifications add outbound provider traffic only when explicitly selected,
after the monitored scan has been stored, and only when added or changed
current findings meet the selected threshold. Webhook delivery contacts the
configured public HTTPS endpoint. Telegram delivery contacts only the fixed
official Bot API origin and `sendMessage` method. Use only provider accounts,
chat destinations, and webhook receivers that you are authorized to access.
LotusWatch does not retrieve updates, chat history, bot profiles, or unrelated
provider data.

Do not use LotusWatch to:

- Bypass authentication or authorization
- Test stolen or guessed credentials
- Evade rate limits, WAFs, CAPTCHAs, or access controls
- Exploit vulnerabilities
- Perform denial-of-service testing
- Access, modify, or destroy data without permission

Users are responsible for complying with applicable laws, contracts, terms of
service, and acceptable-use policies.

## Security Limitations

LotusWatch findings may contain false positives or false negatives. A `PASS`
only applies to the specific check that produced it and must not be interpreted
as proof that the target is secure. A missing security header describes a
defense-in-depth weakness and is not proof that the website is exploitable.
Missing CAA, SPF, or DMARC records do not prove certificate mis-issuance, email
use, or spoofability. DNS results can also be incomplete because of resolver
failures, caching, truncation, or the absence of DNSSEC validation. LotusWatch
does not perform full TLS configuration analysis, full CSP or SPF evaluation,
DNSSEC or DKIM validation, authenticated testing, crawling, or vulnerability
exploitation.

Severity-based exit policies are opt-in automation decisions. Exit code `1`
means the selected threshold matched a finding; it does not mean LotusWatch
crashed, prove exploitability, or provide a complete security risk score.

Notification exit code `3` is a partial-success state. It means the monitored
scan was stored but one or more explicitly requested deliveries failed. It
does not indicate that the stored run was deleted, rolled back, or invalid.
Initial baselines do not alert by default, and resolved or unchanged findings
do not independently trigger the current notification policy.

Notification delivery is best effort. Bounded retries can duplicate a message
if the provider accepted a request but its response was lost. LotusWatch does
not provide exactly-once delivery, a persistent queue, delivery replay,
provider-response history, automatic credential rotation, or verification of
provider-side processing. Severity thresholds remain operator-selected
automation policies rather than complete risk scores.

SQLite locking uses a bounded busy timeout and is not a substitute for
multi-process coordination. Monitoring history can contain false positives,
false negatives, controlled operational errors, and stale infrastructure
details. Stored scan completion, finding counts, comparison changes, and
successful persistence are separate states and none proves that a target is
secure or exploitable.
