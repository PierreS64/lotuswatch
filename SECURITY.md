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

LotusWatch reports can contain the original target, normalized URL, redirect
destinations, HTTP status codes, certificate metadata, selected security-header
values, DNS query names, CAA values, TXT records, parsed SPF and DMARC
observations, and controlled error diagnostics. TXT data can include provider
identifiers, verification tokens, reporting addresses, or other operational
metadata. These details can reveal private hostnames, query parameters,
infrastructure, or security policy. Review generated reports before sharing or
committing them.

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
