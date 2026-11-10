# LotusWatch Security Triage Report

> Generated from two existing scan reports; no new scan was performed.
> Review target information before sharing. Raw evidence is omitted.

**Target:** https://demo\.example/
**Baseline scanned:** 2026-08-19T12:00:00Z
**Current scanned:** 2026-08-19T13:00:00Z
**Compared at:** 2026-11-10T15:42:29.064260Z

## Change summary

| Added | Changed | Resolved | Unchanged |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 1 |

## Findings requiring review (2)

| Severity | Status | Finding ID | Title |
| --- | --- | --- | --- |
| medium | changed | LW-HEADER-003 | Content Security Policy is missing |
| info | added | LW-DNS-001 | No effective CAA policy was found |

### LW-HEADER-003: Content Security Policy is missing

- **Change:** changed
- **Current severity:** medium
- **Baseline severity:** medium
- **Description:** The response does not provide a Content\-Security\-Policy header\. This removes a browser defense\-in\-depth control but does not prove exploitability\.
- **Suggested remediation:** Design and test a Content Security Policy based on the resources the application actually requires\.

### LW-DNS-001: No effective CAA policy was found

- **Change:** added
- **Current severity:** info
- **Description:** No effective CAA record set was observed\. This reduces explicit certificate\-issuance control but does not prove mis\-issuance\.
- **Suggested remediation:** Consider publishing a CAA policy that lists the certificate authorities permitted to issue for the domain\.

## Resolved findings (1)

- LW-DNS-006 (info): DMARC uses a monitoring policy

## Analyst follow-up

- [ ] Verify changes against the expected website configuration.
- [ ] Review the original JSON scan reports for supporting evidence.
- [ ] Confirm priority with the system owner and track remediation.
- [ ] Re-scan an authorized target to validate the fix.

LotusWatch findings indicate configuration observations, not proof of exploitation or compromise.
