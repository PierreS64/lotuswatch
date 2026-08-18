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
- Structured findings and severity levels
- Console output
- Versioned UTF-8 JSON reports
- UTC report timestamps
- Protection against accidental report overwrite

## Planned for v0.1

The following defensive checks are planned but are not implemented yet:

- TLS certificate issuer and expiration inspection
- Selected HTTP security-header checks
- Clear remediation guidance for each new check
- Additional console and report summaries

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

For the redirect check, LotusWatch:

- Starts with the HTTP version of the normalized target
- Sends streamed `GET` requests without retaining response bodies
- Uses an explicit timeout
- Follows no more than five redirects
- Accepts only HTTP and HTTPS redirect destinations
- Keeps TLS certificate verification enabled
- Clears cookies between requests

Automated tests use mocked HTTP responses and do not access public websites.

## Data Handling

LotusWatch does not intentionally store response bodies, cookies, passwords,
or authentication tokens.

JSON reports can contain:

- The original user input
- The normalized target URL
- Redirect destinations
- HTTP status codes
- Finding evidence

Targets and redirect destinations may include query parameters. Do not place
secrets in a target URL, and review every generated report before sharing or
committing it.

## Authorization Boundary

The current redirect check creates traffic comparable to a small number of
ordinary browser requests. Run it at a low frequency against public endpoints
you are permitted to access, and stop if the service rejects or rate-limits the
requests.

Any future intrusive capability must require explicit authorization from the
system owner and additional safeguards appropriate to its risk.

## Interpretation

A `PASS` only means that the individual check passed. For example, a redirect
check can pass even when the final HTTPS endpoint returns an error status. A
LotusWatch result is not proof that a website is secure, healthy, or free of
vulnerabilities.
