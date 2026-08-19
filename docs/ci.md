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

A policy exit does not mean LotusWatch crashed. Finding severity is not a complete risk score and does not prove exploitability. Operationally incomplete scan checks remain visible in console and JSON results and are not automatically converted into security findings.
