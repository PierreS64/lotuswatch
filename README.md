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
- Verify formatting, linting, and tests on Python 3.12, 3.13, and 3.14 in CI.

## Requirements

- Python 3.12 or newer
- Git

The project is currently developed with Python 3.14 on Windows. GitHub Actions
also verifies Python 3.12, 3.13, and 3.14 on Linux.

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

Display help for the scan command:

```bash
lotuswatch scan --help
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

See [`examples/sample-report.json`](examples/sample-report.json) for a safe,
synthetic example using the reserved `demo.example` domain.

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
|   `-- scope.md
|-- examples/
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
|       |   |-- finding.py
|       |   `-- report.py
|       |-- reporters/
|       |   `-- json.py
|       |-- cli.py
|       |-- exceptions.py
|       `-- target.py
|-- tests/
|   |-- checks/
|   |-- models/
|   |-- reporters/
|   |-- test_cli.py
|   `-- test_target.py
|-- LICENSE
|-- README.md
|-- SECURITY.md
`-- pyproject.toml
```

## Scope and Authorized Use

The current version makes a small number of ordinary HTTP requests, one TLS
connection, and bounded CAA and TXT queries through the system recursive
resolver. Use it at a low frequency and only against public endpoints and DNS
names that you are permitted to inspect.

Do not use LotusWatch to bypass authentication, evade protective controls,
perform denial-of-service testing, test credentials, or exploit a system
without explicit authorization.

Users are responsible for complying with applicable laws, contracts, terms of
service, and acceptable-use policies. See [`docs/scope.md`](docs/scope.md) for
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
- JSON reports can contain target URLs, redirect destinations, certificate
  metadata, selected header values, DNS CAA and TXT records, diagnostics, and
  finding evidence. Review them before sharing or committing them.

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
- [ ] Scheduled monitoring
- [ ] Email and Telegram alerts
- [ ] Web dashboard

## Contributing

Bug reports, feature suggestions, documentation improvements, and pull
requests are welcome. Open an issue before proposing a major change so its
scope and design can be discussed first.

Do not include credentials, private URLs, access tokens, cookies, private
keys, or sensitive scan reports in issues or pull requests.

## Security

Read [`SECURITY.md`](SECURITY.md) before reporting a vulnerability in
LotusWatch. Do not disclose exploitable details in a public issue.

## License

LotusWatch is released under the [MIT License](LICENSE).
