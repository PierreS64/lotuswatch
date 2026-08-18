# LotusWatch

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
- Handle request timeouts and connection errors without a traceback.
- Produce structured security findings.
- Display results in the terminal.
- Export versioned UTF-8 JSON reports.
- Protect existing report files from accidental overwrite.

## Requirements

- Python 3.12 or newer
- Git

The project is currently developed and tested with Python 3.14 on Windows. The
code is configured to remain compatible with Python 3.12 and newer.

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
- Redirect check details and HTTP status codes
- Summary counters
- Structured findings

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

Tests for network behavior use mocked HTTP responses and do not depend on
public websites.

## Project Structure

```text
lotuswatch/
|-- docs/
|   `-- scope.md
|-- examples/
|   `-- sample-report.json
|-- src/
|   `-- lotuswatch/
|       |-- checks/
|       |   `-- redirects.py
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

The current version makes a small number of ordinary HTTP requests to inspect
redirect behavior. Use it at a low frequency and only against public endpoints
that you are permitted to access.

Do not use LotusWatch to bypass authentication, evade protective controls,
perform denial-of-service testing, test credentials, or exploit a system
without explicit authorization.

Users are responsible for complying with applicable laws, contracts, terms of
service, and acceptable-use policies. See [`docs/scope.md`](docs/scope.md) for
the detailed technical scope.

## Limitations

- Results may contain false positives or false negatives.
- Redirect success does not prove endpoint availability or application safety.
- TLS certificates and HTTP security headers are not inspected yet.
- Domain ownership is not verified automatically.
- JSON reports can contain target URLs and redirect destinations. Review them
  before sharing or committing them.

## Roadmap

- [x] Initial command-line interface
- [x] Target validation and normalization
- [x] Structured finding model
- [x] HTTP-to-HTTPS redirect detection
- [x] Redirect-loop and timeout handling
- [x] JSON report generation
- [ ] TLS certificate inspection
- [ ] HTTP security-header checks
- [ ] DNS security checks
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
