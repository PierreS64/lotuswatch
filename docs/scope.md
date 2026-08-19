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
- Scheduled monitoring and alerting
- Historical storage, dashboards, and trend analysis

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

Targets and redirect destinations may include query parameters. Do not place
secrets in a target URL, and review every generated report before sharing or
committing it. Certificate metadata and response headers may also reveal
infrastructure or policy details that should not be published for a private
system.

## Authorization Boundary

The implemented checks create traffic comparable to a small number of ordinary
browser requests, one TLS handshake, and bounded queries through the configured
recursive DNS resolver. Run LotusWatch at a low frequency against public
endpoints and DNS names you are permitted to inspect, and stop if the service
or resolver rejects or rate-limits the requests.

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
