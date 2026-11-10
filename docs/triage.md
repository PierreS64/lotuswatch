# Security Triage Report (Markdown)

LotusWatch can turn a saved comparison of two website security scans into a
human-readable Markdown triage note. This is useful when reviewing changes with
a teammate or describing a defensive monitoring workflow in a portfolio.
For the system architecture and design limits, see the
[portfolio case study](portfolio.md).

The command operates on **existing JSON reports** and does not perform a new
network request:

```bash
lotuswatch compare examples/baseline-report.json examples/current-report.json \
  --format markdown --output triage.md
```

Run that command from the repository root after installing the contributor
checkout. The input files use the reserved synthetic `demo.example` domain;
the command reads files only. To repeat the demo, remove or rename your local
`triage.md` before rerunning because LotusWatch does not overwrite output.

The synthetic baseline includes a medium severity missing CSP finding and
informational missing Permissions Policy and monitoring-only DMARC findings.
The current report retains Permissions Policy unchanged, changes the CSP
finding's observed response status, resolves the DMARC observation, and adds
an informational missing CAA finding. The complete sample inputs are
[`baseline-report.json`](../examples/baseline-report.json) and
[`current-report.json`](../examples/current-report.json).

The resulting Markdown begins with this summary and review queue (the
comparison timestamp changes on each run):

```markdown
| Added | Changed | Resolved | Unchanged |
| ---: | ---: | ---: | ---: |
| 1 | 1 | 1 | 1 |

| Severity | Status | Finding ID | Title |
| --- | --- | --- | --- |
| medium | changed | LW-HEADER-003 | Content Security Policy is missing |
| info | added | LW-DNS-001 | No effective CAA policy was found |
```

The full generated example is [`triage-report.md`](../examples/triage-report.md).
Use the current severity to review the medium CSP finding before the
informational CAA observation. A critical or high added/changed finding would
take precedence. Check the original JSON evidence and confirm the expected
configuration with the system owner before assigning remediation.

The four states describe differences between serialized findings:

| State | Meaning | Analyst action |
| --- | --- | --- |
| `added` | Only in the current report | Review and prioritize by current severity. |
| `changed` | Same finding identity, different content | Review new evidence and severity. |
| `resolved` | Only in the baseline report | Verify the control changed as intended. |
| `unchanged` | Same identity and content in both reports | Keep under routine review. |

`resolved` does not prove a fix, and `unchanged` does not imply safety. A scan
can miss behavior on other paths or at another time. Findings are observations
of security configuration; they do not demonstrate exploitation or that the
system was compromised.

The output includes:

- A summary of added, changed, resolved, and unchanged findings.
- Added and changed findings, sorted by current severity (highest first).
- Descriptions, suggested remediation, and baseline/current severity when changed.
- Resolved findings and an analyst follow-up checklist.

Unchanged findings are not listed individually. Raw evidence, notification
secrets, and full scan results are not copied into the Markdown output. The
target URL, finding titles, descriptions, and recommendations may still contain
sensitive details; review the report before sharing.

Markdown and HTML metacharacters in finding text are escaped to avoid turning
untrusted observations into links or embedded HTML in rendered reports. The
report does not make a claim that a host was compromised.

LotusWatch does **not overwrite** an existing output path. Choose a new path
for each generated report.

The optional `--fail-on` threshold still applies: a generated report can
coexist with exit code 1 if an added or changed finding meets the threshold.

```bash
lotuswatch compare examples/baseline-report.json examples/current-report.json \
  --format markdown --output triage-high.md --fail-on high
```

The existing `--format console` and `--format json` options retain their
prior behavior. The scan command continues to accept only console and JSON.
