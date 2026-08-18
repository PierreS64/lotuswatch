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
- Independent continuation after controlled check errors when safe
- Consolidated console sections and severity totals
- Multi-check JSON reports
- Structured findings and severity levels
- Console output
- Versioned UTF-8 JSON reports
- UTC report timestamps
- Protection against accidental report overwrite

## Planned Beyond the Current Alpha

The following capabilities are not implemented yet:

- TLS protocol and cipher-suite grading
- Certificate revocation and Certificate Transparency checks
- Full Content Security Policy analysis
- DNS security checks
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

The three check groups run in the order redirect, TLS certificate, then HTTP
security headers. A controlled error in one group does not stop an independent
group when continuing is safe.

Automated tests use mocked HTTP responses and do not access public websites.

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
- Controlled error diagnostics
- Finding evidence

Targets and redirect destinations may include query parameters. Do not place
secrets in a target URL, and review every generated report before sharing or
committing it. Certificate metadata and response headers may also reveal
infrastructure or policy details that should not be published for a private
system.

## Authorization Boundary

The implemented checks create traffic comparable to a small number of ordinary
browser requests plus one TLS handshake. Run LotusWatch at a low frequency
against public endpoints you are permitted to access, and stop if the service
rejects or rate-limits the requests.

Any future intrusive capability must require explicit authorization from the
system owner and additional safeguards appropriate to its risk.

## Interpretation

A `PASS` only means that the individual limited check passed. For example, a
redirect check can pass even when the final HTTPS endpoint returns an error
status, and observed security headers can still contain an unsuitable policy.
Missing headers describe reduced defense in depth rather than proof of an
exploitable vulnerability. A LotusWatch result is not proof that a website is
secure, healthy, or free of vulnerabilities.
