# Security Triage Report (Markdown)

LotusWatch can turn a saved comparison of two website security scans into a
human-readable Markdown triage note. This is useful when reviewing changes with
a teammate or describing a defensive monitoring workflow in a portfolio.

The command operates on **existing JSON reports** and does not perform a new
network request:

```bash
lotuswatch compare examples/baseline-report.json examples/current-report.json \
  --format markdown --output triage.md
```

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
