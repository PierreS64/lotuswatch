# CI/CD Exit Policies

LotusWatch commands return exit code `0` by default after a completed command, even when findings are present. Use `--fail-on` to opt into a severity threshold for CI/CD workflows.

Supported thresholds, from lowest to highest, are:

`info`, `low`, `medium`, `high`, and `critical`.

## Scan Policy

The scan policy evaluates every generated finding:

```bash
lotuswatch scan example.com --fail-on medium
```

This command returns exit code `1` when at least one finding is `medium`, `high`, or `critical`.

## Comparison Policy

The comparison policy evaluates only added findings and the current snapshot of changed findings:

```bash
lotuswatch compare baseline.json current.json --fail-on medium
```

Resolved and unchanged findings never trigger the comparison policy. A changed finding is evaluated using its current severity.

## JSON Output

LotusWatch finishes writing requested JSON output before returning exit code `1`:

```bash
lotuswatch compare baseline.json current.json \
  --format json \
  --output comparison.json \
  --fail-on medium
```

An existing output file is never overwritten. Output and input errors remain CLI errors and return exit code `2` instead of a policy exit.

## Reading the Exit Code

PowerShell:

```powershell
lotuswatch compare baseline.json current.json --fail-on medium
$LASTEXITCODE
```

POSIX-compatible shells:

```bash
lotuswatch compare baseline.json current.json --fail-on medium
echo $?
```

## Exit Code Contract

- `0`: The command completed and the selected policy threshold was not met, or no policy was selected.
- `1`: The command completed and the selected severity policy threshold was met.
- `2`: CLI usage, report input, compatibility, comparison, or output validation failed.
- `3`: A monitoring run was stored, but at least one explicitly requested
  notification delivery failed.

A policy exit does not mean LotusWatch crashed. Finding severity is not a complete risk score and does not prove exploitability. Operationally incomplete scan checks remain visible in console and JSON results and are not automatically converted into security findings.

## Installed-Artifact Compatibility Checks

CI builds one wheel and one source distribution, verifies their bounded archive
inventories, and installs each artifact on Python 3.12, 3.13, and 3.14. Each
clean installation also validates the fixed alpha.5 and alpha.6 fixtures after
copying them outside the repository:

```bash
python scripts/smoke_install_distribution.py path/to/artifact \
  --compatibility-fixtures tests/fixtures/compatibility
```

This check loads supported scan, comparison, notification, fingerprint, and
monitoring database versions without running a scan or contacting a provider.
The complete beta contract is documented in
[`compatibility.md`](compatibility.md).
