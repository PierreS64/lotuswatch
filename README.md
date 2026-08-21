# LotusWatch

[![CI](https://github.com/PierreS64/lotuswatch/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/PierreS64/lotuswatch/actions/workflows/ci.yml)

LotusWatch is an open-source command-line tool that inspects public website
security configuration and presents the results in a clear, structured form.

> [!WARNING]
> LotusWatch is experimental software under active development. It is not a
> replacement for a complete security assessment.

## Current Features

- Validate and normalize domains and HTTP/HTTPS URLs.
- Reject unsupported schemes and URLs containing embedded credentials.
- Check whether an HTTP endpoint redirects safely to HTTPS.
- Limit redirect chains and detect redirect loops.
- Inspect TLS certificate identity, validity, issuer, and expiration.
- Report certificates that are expiring, expired, mismatched, or untrusted.
- Inspect HSTS, CSP, MIME-sniffing, referrer, permissions, and framing headers.
- Query bounded CAA and TXT records through the system recursive resolver.
- Inspect effective CAA certificate-issuance policy on a hostname or parent.
- Inspect SPF and DMARC records without performing full email-policy evaluation.
- Report missing, conflicting, or ambiguous DNS controls conservatively.
- Handle controlled network, TLS, and parsing errors without a traceback.
- Produce structured findings with evidence and remediation guidance.
- Display separate check results and a severity summary in the terminal.
- Export versioned UTF-8 JSON reports.
- Protect existing report files from accidental overwrite.
- Load existing reports as bounded, untrusted local input.
- Compare baseline and current reports without making network requests.
- Classify findings as added, resolved, changed, or unchanged.
- Generate stable, versioned finding fingerprints for comparison identity.
- Provide opt-in severity thresholds for CI/CD exit policies.
- Register named local monitoring targets in a versioned SQLite database.
- Store validated scan history and compare each run with its previous baseline.
- Inspect and export stored history without rerunning a scan.
- Preview and explicitly apply guarded history retention.
- Support recurring runs through operating-system schedulers without a daemon.
- Select minimal notification events from added and changed findings.
- Deliver opt-in HTTPS webhook notifications with optional HMAC-SHA256 signing.
- Deliver opt-in bounded plain-text Telegram Bot API notifications.
- Preview notification selection without resolving secrets or contacting providers.
- Verify formatting, linting, and tests on Python 3.12, 3.13, and 3.14 in CI.

## Requirements

- Python 3.12 or newer
- Git

The project is currently developed with Python 3.14 on Windows. GitHub Actions
also verifies Python 3.12, 3.13, and 3.14 on Linux.

## Package Names

LotusWatch uses three related names:

- `lotuswatch-security` is the Python distribution name used by package
  indexes and installation tools.
- `lotuswatch` is the command installed into the active environment.
- `lotuswatch` is also the Python import package used by library consumers.

The project is not published to PyPI during the alpha.6 release. Until the
packaging workflow is complete, install contributors' checkouts in editable
mode as described below.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/PierreS64/lotuswatch.git
cd lotuswatch
```

### 2. Create a virtual environment

Windows PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If Python 3.14 is not installed, replace `3.14` with an installed version that
is at least Python 3.12.

Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install LotusWatch

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The editable installation makes source-code changes available without
reinstalling the package.

## Usage

Display the main help page:

```bash
lotuswatch --help
```

Display the installed version without running a scan or opening a monitoring
database:

```bash
lotuswatch --version
```

Display help for the scan command:

```bash
lotuswatch scan --help
```

Display help for the comparison command:

```bash
lotuswatch compare --help
```

Display help for local monitoring commands:

```bash
lotuswatch monitor --help
```

### Run a console scan

```bash
lotuswatch scan example.com
```

LotusWatch also accepts a complete HTTP or HTTPS URL:

```bash
lotuswatch scan https://example.com/path
```

When a scheme is omitted, LotusWatch normalizes the target to HTTPS while
still checking the corresponding HTTP endpoint for redirect behavior.

### Generate a JSON report

```bash
lotuswatch scan example.com --format json --output report.json
```

The output file includes:

- Report schema and LotusWatch versions
- Original and normalized target
- UTC scan timestamp
- Redirect, TLS certificate, HTTP security-header, CAA, SPF, and DMARC details
- Summary counters
- Structured findings with evidence, severity, and remediation guidance

LotusWatch refuses to overwrite an existing report. Choose a new output path
or move the previous report before running the command again.

See [`examples/sample-report.json`](https://github.com/PierreS64/lotuswatch/blob/main/examples/sample-report.json) for a safe,
synthetic scan example using the reserved `demo.example` domain.

### Compare two scan reports

Pass the older report first as the baseline and the newer report second as the
current report:

```bash
lotuswatch compare examples/baseline-report.json examples/current-report.json
```

Both reports must use a supported scan schema and represent the same canonical
target. Comparison reads local JSON only; it does not run a new scan or make
website or DNS requests.

Generate a deterministic JSON comparison report:

```bash
lotuswatch compare examples/baseline-report.json examples/current-report.json \
  --format json \
  --output comparison.json
```

The four comparison states are:

- `added`: present only in the current report.
- `resolved`: present only in the baseline report.
- `changed`: present in both reports with the same identity but different
  serialized finding content.
- `unchanged`: present in both reports with identical serialized content.

LotusWatch identifies the same finding category on the same normalized target
with a fingerprint such as `lwfp:v1:sha256:...`. Severity, evidence, and
descriptive text are excluded from that identity so their changes can be
reported as `changed`. A fingerprint is a stable identifier, not anonymization,
and it is not a digital signature or proof that a report is authentic.

Safe synthetic inputs and expected output are available in
[`examples/baseline-report.json`](https://github.com/PierreS64/lotuswatch/blob/main/examples/baseline-report.json),
[`examples/current-report.json`](https://github.com/PierreS64/lotuswatch/blob/main/examples/current-report.json), and
[`examples/comparison-report.json`](https://github.com/PierreS64/lotuswatch/blob/main/examples/comparison-report.json).

### Store local monitoring history

LotusWatch can keep validated scan reports in a local SQLite database. The
default per-user database paths are:

- Windows: `%LOCALAPPDATA%\LotusWatch\monitoring.db`
- macOS: `~/Library/Application Support/LotusWatch/monitoring.db`
- Linux: `$XDG_DATA_HOME/lotuswatch/monitoring.db`, or
  `~/.local/share/lotuswatch/monitoring.db` when `XDG_DATA_HOME` is unset

Use `--database` with an absolute path for automation and scheduled jobs.

Register a named public target without scanning it:

```bash
lotuswatch monitor add production example.com
```

List, disable, or re-enable profiles:

```bash
lotuswatch monitor list
lotuswatch monitor disable production
lotuswatch monitor enable production
```

Run one monitored scan:

```bash
lotuswatch monitor run production
```

The first compatible run establishes an initial baseline. A later run is
stored only after validation and is compared automatically with the newest
earlier compatible run for the same canonical target. The command displays
added, resolved, changed, and unchanged totals.

Notifications are disabled by default. Select one or both channels and an
explicit threshold for added findings and current snapshots of changed
findings:

```bash
lotuswatch monitor run production --notify webhook --notify-on medium
lotuswatch monitor run production --notify telegram --notify-on high
lotuswatch monitor run production --notify webhook --notify telegram --notify-on high
```

Webhook delivery reads `LOTUSWATCH_WEBHOOK_URL` and the optional
`LOTUSWATCH_WEBHOOK_SECRET`. Telegram delivery reads
`LOTUSWATCH_TELEGRAM_BOT_TOKEN` and `LOTUSWATCH_TELEGRAM_CHAT_ID`. These values
are resolved only when their channel actually needs delivery. They are not
accepted as CLI values or stored in SQLite.

The initial baseline does not alert by default. Resolved and unchanged
findings do not independently trigger an alert, and a below-threshold
comparison makes no provider request. Preview a selected event without
resolving secrets or sending it:

```bash
lotuswatch monitor run production \
  --notify webhook \
  --notify-on medium \
  --notification-dry-run
```

Webhook notifications send a minimal versioned JSON event. An optional
HMAC-SHA256 header authenticates the exact payload bytes to a receiver sharing
the secret; it does not encrypt the event. Telegram notifications use bounded
plain text without Markdown or HTML formatting. Both providers use bounded
timeouts and retries, so a timeout after remote acceptance can cause duplicate
delivery. LotusWatch does not claim exactly-once notification delivery.

Notification output appears after the stored run identifier. `DELIVERED`
means the provider returned a validated success. `CONFIGURATION ERROR` means a
required environment value was missing or invalid. Other provider failures
remain controlled delivery results. Exit code `3` means the scan was stored
but at least one explicitly requested notification failed; it does not mean
the stored scan was lost.

Inspect recent history and one complete stored report:

```bash
lotuswatch monitor history production --limit 20
lotuswatch monitor show RUN_ID
```

Export one stored report with existing-file protection:

```bash
lotuswatch monitor show RUN_ID --format json --output stored-report.json
```

Preview retention before explicitly applying it:

```bash
lotuswatch monitor prune production --keep 30
lotuswatch monitor prune production --keep 30 --apply
```

The first command is always a dry run and lists every eligible run ID. The
applied command preserves the profile and at least one run, and rejects a
stale plan if history changed.

Scan completion, finding presence, comparison changes, and storage success are
different conclusions. A stored run can contain findings or controlled
operational errors. A successful monitoring command means its validated run
was stored; it is not a claim that the target is secure or finding-free.

Monitoring databases and exports can contain URLs, certificate metadata,
headers, DNS values, diagnostics, and evidence. They are not encrypted or
authenticated by LotusWatch. Restrict filesystem access, do not put secrets in
target query strings, and protect backups and scheduler logs. LotusWatch does
not run a background daemon; see [`docs/monitoring.md`](https://github.com/PierreS64/lotuswatch/blob/main/docs/monitoring.md) for
PowerShell Task Scheduler, cron, locking, backup, and privacy guidance. A safe
illustrative session is available in
[`examples/monitoring-session.txt`](https://github.com/PierreS64/lotuswatch/blob/main/examples/monitoring-session.txt). A safe
minimal event is available in
[`examples/notification-event.json`](https://github.com/PierreS64/lotuswatch/blob/main/examples/notification-event.json).

### Use severity policies in CI/CD

Commands keep their normal exit behavior unless `--fail-on` is explicitly
selected. This scan fails the chosen policy when a `medium` or higher finding
is generated:

```bash
lotuswatch scan example.com --fail-on medium
```

For comparison, only added findings and current snapshots of changed findings
are evaluated. Resolved and unchanged findings do not trigger the policy:

```bash
lotuswatch compare baseline.json current.json --fail-on medium
```

For `scan` and `compare`, exit code `0` means the command completed without
meeting the selected policy or no policy was selected. Exit code `1` means an
explicit severity policy was met. Exit code `2` means command usage, input,
compatibility, comparison, or output validation failed. Notification-enabled
`monitor run` additionally uses exit code `3` when the scan was stored but an
explicitly requested delivery failed. A policy or notification exit is not an
application crash, and finding severity is not a complete risk score. See
[`docs/ci.md`](https://github.com/PierreS64/lotuswatch/blob/main/docs/ci.md) for PowerShell, POSIX, and JSON-output examples.

## Interpreting Redirect Results

- `PASS` means the HTTP endpoint completed a redirect chain to HTTPS.
- `FAIL` means the chain ended on HTTP or could not redirect safely.
- `ERROR` means the check could not complete because of a timeout or connection
  failure.
- `WARNING` can appear when the redirect reaches HTTPS but the destination
  returns an HTTP error status.

A redirect `PASS` does not prove that the complete website is healthy or free
of vulnerabilities. It only describes the redirect behavior tested by the
current check.

## Interpreting TLS Results

- `PASS` means the certificate was verified for the requested hostname and its
  validity data could be inspected.
- `WARNING` means the verified certificate is approaching expiration.
- `FAIL` means certificate verification failed, such as for an expired,
  mismatched, or otherwise untrusted certificate.
- `ERROR` means the TLS check could not complete because of an operational
  problem such as DNS, timeout, connection, handshake, or parsing failure.

TLS findings cover certificate expiration and verification only. LotusWatch
does not currently grade cipher suites, protocol configuration, certificate
transparency, revocation status, or the complete server-side TLS setup.

TLS finding categories mean:

- Expiration findings indicate that renewal is approaching or overdue.
- Hostname mismatch means the certificate identity does not match the hostname
  requested by LotusWatch.
- Generic verification failure means the local trust check failed but the
  available diagnostic does not support a more specific conclusion.

An operational TLS `ERROR` is not automatically treated as a certificate
vulnerability because DNS, connectivity, or local environment problems can
prevent the check from completing.

## Interpreting HTTP Security Header Results

LotusWatch observes these response headers on the final HTTPS endpoint:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `X-Frame-Options`

`PASS` means the selected controls satisfy the current limited rules.
`WARNING` means one or more controls are missing, malformed, or weaker than the
current threshold. `ERROR` means the header request could not complete.

Missing headers weaken browser defense in depth but do not prove that the
website is exploitable. A policy can also be present and still be ineffective
or inappropriate for the application. LotusWatch does not perform full CSP
analysis, policy bypass testing, or application-specific policy generation.

Security-header finding categories mean:

- HSTS findings indicate a missing, malformed, or short-lived HTTPS retention
  policy.
- CSP findings indicate that no Content Security Policy header was observed;
  LotusWatch does not judge the complete strength of a present policy.
- MIME-sniffing findings indicate that `nosniff` protection was not observed.
- Referrer and Permissions Policy findings indicate that the browser behavior
  is not explicitly constrained by those selected headers.
- Framing findings indicate that neither CSP `frame-ancestors` nor
  `X-Frame-Options` was observed; this is not proof of a working clickjacking
  attack.

## Interpreting DNS Results

LotusWatch runs two DNS check groups after the website checks:

- `DNS CAA records` searches the target hostname and then its parent names for
  the first effective CAA record set. The search is bounded and never queries
  the DNS root.
- `DNS email authentication` queries TXT at the target name for SPF and at
  `_dmarc.<domain>` for DMARC.

`PASS` means the limited DNS observation completed without a current finding.
`WARNING` means a conservative configuration or posture finding was recorded.
`ERROR` means a timeout, nameserver failure, malformed response, query limit,
or another operational condition prevented a complete conclusion.

CAA finding categories mean:

- `LW-DNS-001` is informational: no effective CAA policy was observed. This
  reduces explicit control over certificate issuance but does not prove that
  an unauthorized certificate exists.
- `LW-DNS-002` indicates that an unknown CAA property has the issuer-critical
  flag. Some compliant certificate authorities may refuse issuance if they do
  not support that property.
- A valid CAA policy, including an intentional `issue ";"` denial policy, does
  not produce a finding solely because of its policy choice.

SPF and DMARC finding categories mean:

- `LW-DNS-003` and `LW-DNS-005` are informational observations for missing SPF
  or DMARC. LotusWatch does not assume that a website domain sends email, and
  missing records do not prove that the domain is currently spoofable.
- `LW-DNS-004` reports multiple SPF records because SPF selection can fail
  permanently when more than one version 1 record exists.
- `LW-DNS-006` reports DMARC `p=none` as a monitoring policy, not as a confirmed
  vulnerability.
- `LW-DNS-007` reports a missing, duplicate, or unsupported DMARC `p` value.
  Valid `p=quarantine` and `p=reject` choices do not produce findings solely
  because of their enforcement level.

LotusWatch does not validate DNSSEC, discover DKIM selectors, follow SPF
`include` mechanisms, apply the SPF ten-lookup limit, determine an
organizational domain from the Public Suffix List, or test real email. A DNS
`ERROR` is kept separate from a configuration finding because resolver and
network failures do not establish a target weakness.

## Scan Summary

Each scan records five groups: redirect, TLS, headers, CAA, and email DNS
authentication. The terminal summary distinguishes recorded checks from checks
that completed far enough to produce a conclusion, then reports finding counts
by severity. LotusWatch does not calculate an overall risk score.

## Development

Apply code formatting:

```bash
ruff format .
```

Check formatting without modifying files:

```bash
ruff format --check .
```

Run static checks:

```bash
ruff check .
```

Run the automated tests:

```bash
pytest
```

Before creating a commit, run:

```bash
ruff format --check .
ruff check .
pytest
```

Tests for network behavior use mocked HTTP and DNS responses and do not depend
on public websites or public DNS resolvers.

## Project Structure

```text
lotuswatch/
|-- .github/
|   `-- workflows/
|       `-- ci.yml
|-- docs/
|   |-- ci.md
|   |-- monitoring.md
|   `-- scope.md
|-- examples/
|   |-- baseline-report.json
|   |-- comparison-report.json
|   |-- current-report.json
|   |-- monitoring-session.txt
|   |-- notification-event.json
|   `-- sample-report.json
|-- src/
|   `-- lotuswatch/
|       |-- checks/
|       |   |-- caa.py
|       |   |-- dns.py
|       |   |-- email_dns.py
|       |   |-- headers.py
|       |   |-- redirects.py
|       |   `-- tls.py
|       |-- models/
|       |   |-- comparison.py
|       |   |-- finding.py
|       |   |-- fingerprint.py
|       |   |-- notification.py
|       |   |-- notification_delivery.py
|       |   `-- report.py
|       |-- notifications/
|       |   |-- delivery.py
|       |   |-- monitoring.py
|       |   |-- policy.py
|       |   |-- telegram.py
|       |   `-- webhook.py
|       |-- reporters/
|       |   `-- json.py
|       |-- storage/
|       |   |-- base.py
|       |   |-- paths.py
|       |   `-- sqlite.py
|       |-- cli.py
|       |-- exceptions.py
|       |-- monitoring.py
|       |-- monitoring_cli.py
|       |-- policy.py
|       |-- scanner.py
|       `-- target.py
|-- tests/
|   |-- checks/
|   |-- models/
|   |-- reporters/
|   |-- storage/
|   |-- test_cli.py
|   |-- test_monitor_cli.py
|   |-- test_monitor_notifications.py
|   |-- test_monitoring.py
|   |-- test_notification_delivery.py
|   |-- test_notification_policy.py
|   |-- test_telegram.py
|   |-- test_target.py
|   `-- test_webhook.py
|-- LICENSE
|-- README.md
|-- SECURITY.md
`-- pyproject.toml
```

## Scope and Authorized Use

The scan command and each `monitor run` command make a small number of ordinary
HTTP requests, one TLS connection, and bounded CAA and TXT queries through the
system recursive resolver. Use them at a low frequency and only against public
endpoints and DNS names that you are permitted to inspect. Registration,
listing, history, show, prune, and compare commands operate on explicitly
selected local data and perform no target network requests. When notification
delivery is explicitly selected and its policy matches, `monitor run` also
sends bounded outbound traffic to the configured HTTPS webhook and/or the
fixed Telegram Bot API endpoint after storing the scan.

Do not use LotusWatch to bypass authentication, evade protective controls,
perform denial-of-service testing, test credentials, or exploit a system
without explicit authorization.

Users are responsible for complying with applicable laws, contracts, terms of
service, and acceptable-use policies. See [`docs/scope.md`](https://github.com/PierreS64/lotuswatch/blob/main/docs/scope.md) for
the detailed technical scope.

## Limitations

- Results may contain false positives or false negatives.
- Redirect success does not prove endpoint availability or application safety.
- TLS inspection does not grade protocols, cipher suites, revocation, or all
  certificate-chain deployment details.
- Security-header inspection does not evaluate full policy correctness or
  prove that a missing control is exploitable.
- CAA inspection does not validate DNSSEC, correlate Certificate Transparency
  logs, or prove that certificate mis-issuance occurred.
- SPF inspection identifies version 1 records but does not evaluate mechanisms,
  recursive includes, alignment, or DNS lookup limits.
- DMARC inspection checks the exact `_dmarc` name and selected `p` syntax but
  does not discover organizational-domain policy, DKIM, or real message behavior.
- LotusWatch inspects one selected HTTPS response and does not crawl the site.
- Domain ownership is not verified automatically.
- Report comparison detects changes in LotusWatch findings, not every change
  in the target, its checks, or its infrastructure.
- Finding fingerprints can be guessed from predictable target and finding
  values; they neither anonymize data nor authenticate reports.
- Comparison requires supported reports for the same canonical target and does
  not verify report provenance, integrity, or chronological order.
- Severity thresholds are user-selected automation policies, not an overall
  security or business-risk assessment.
- Monitoring uses a local SQLite database and does not provide database
  encryption, authentication, cloud synchronization, or multi-process write
  coordination beyond bounded SQLite locking.
- LotusWatch does not install a background daemon. Recurring execution depends
  on an external scheduler and operators must prevent overlapping jobs against
  the same database.
- Stored history observes LotusWatch scan results rather than every target or
  infrastructure change. Backups, scheduler logs, and retention remain the
  operator's responsibility.
- Notifications are best effort and have no persistent queue, delivery
  history, replay command, or exactly-once guarantee.
- Webhook HMAC authenticates exact payload bytes but does not encrypt events;
  receivers, endpoint availability, and secret rotation remain operator
  responsibilities.
- Telegram messages are bounded plain text and can omit additional triggering
  observations. LotusWatch does not manage bot permissions, chats, or provider
  availability.
- Notification events and logs can reveal profile names, public targets,
  finding identifiers, severities, titles, and comparison totals.
- JSON reports can contain target URLs, redirect destinations, certificate
  metadata, selected header values, DNS CAA and TXT records, diagnostics, and
  finding evidence. Comparison reports can contain finding snapshots from both
  inputs. Review all reports before sharing or committing them.

## Roadmap

- [x] Initial command-line interface
- [x] Target validation and normalization
- [x] Structured finding model
- [x] HTTP-to-HTTPS redirect detection
- [x] Redirect-loop and timeout handling
- [x] JSON report generation
- [x] TLS certificate inspection and expiration findings
- [x] Selected HTTP security-header checks and findings
- [x] Consolidated console and JSON scan output
- [x] GitHub Actions quality checks on Python 3.12, 3.13, and 3.14
- [x] Bounded DNS query foundation
- [x] CAA checks and findings
- [x] SPF and DMARC checks and findings
- [x] Safe local scan report loading
- [x] Stable finding fingerprints
- [x] Baseline and current report comparison
- [x] Console and JSON comparison output
- [x] Opt-in CI/CD severity exit policies
- [x] Local target registry and versioned SQLite history
- [x] On-demand monitoring with automatic previous-run comparison
- [x] History inspection, explicit retention, and scheduler guidance
- [x] Opt-in HTTPS webhook and Telegram notifications
- [ ] Built-in background daemon
- [ ] Email notifications
- [ ] Persistent notification queue and delivery history
- [ ] Web dashboard

## Contributing

Bug reports, feature suggestions, documentation improvements, and pull
requests are welcome. Open an issue before proposing a major change so its
scope and design can be discussed first.

Do not include credentials, private URLs, access tokens, cookies, private
keys, or sensitive scan reports in issues or pull requests.

## Security

Read [`SECURITY.md`](https://github.com/PierreS64/lotuswatch/blob/main/SECURITY.md) before reporting a vulnerability in
LotusWatch. Do not disclose exploitable details in a public issue.

## License

LotusWatch is released under the [MIT License](https://github.com/PierreS64/lotuswatch/blob/main/LICENSE).
