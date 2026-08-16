# LotusWatch

LotusWatch is an open-source command-line tool for monitoring website
security configurations and presenting potential risks in a clear,
actionable format.

> [!WARNING]
> LotusWatch is currently under active development and is not ready for
> production use.

## Current Status

The current version provides the initial command-line interface.

Planned checks include:

- HTTP-to-HTTPS redirect detection
- TLS certificate expiration
- HTTP security headers
- DNS security configuration
- JSON reports
- Scheduled monitoring and alerts

## Requirements

- Python 3.12 or newer
- Git

LotusWatch is currently tested with Python 3.14.

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/lotuswatch.git
cd lotuswatch
```

Replace `YOUR_USERNAME` with your GitHub username.

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

On Linux or macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install LotusWatch

```bash
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

The editable installation allows source-code changes to take effect without
reinstalling the project.

## Usage

Display the help page:

```bash
lotuswatch --help
```

Display help for the scan command:

```bash
lotuswatch scan --help
```

Run the current scan placeholder:

```bash
lotuswatch scan example.com
```

A complete URL is also accepted:

```bash
lotuswatch scan https://example.com/
```

The scanning functionality is still under development.

## Development

Run the automated tests:

```bash
pytest
```

Check the source code:

```bash
ruff check .
```

Check code formatting:

```bash
ruff format --check .
```

Apply automatic formatting:

```bash
ruff format .
```

Before creating a commit, run:

```bash
ruff check .
pytest
```

## Project Structure

```text
lotuswatch/
├── src/
│   └── lotuswatch/
│       ├── __init__.py
│       └── cli.py
├── tests/
│   └── test_cli.py
├── docs/
│   └── scope.md
├── examples/
├── .gitignore
├── LICENSE
├── README.md
├── SECURITY.md
└── pyproject.toml
```

## Project Scope

LotusWatch is intended to perform defensive checks such as:

- Validating website targets
- Detecting HTTP-to-HTTPS redirects
- Inspecting TLS certificate expiration
- Checking selected HTTP security headers
- Producing console and JSON reports

LotusWatch does not perform:

- Vulnerability exploitation
- Credential attacks
- Brute-force attacks
- Denial-of-service testing
- Unauthorized network scanning

See [`docs/scope.md`](docs/scope.md) for the complete scope.

## Authorized Use

Only use LotusWatch on systems that you own or systems for which you have
explicit authorization to inspect.

Users are responsible for complying with applicable laws, contracts, and
acceptable-use policies.

## Limitations

LotusWatch is experimental software. Its findings may contain false positives
or false negatives and must not be treated as a complete security assessment.

## Roadmap

- [x] Initial command-line interface
- [x] Automated CLI tests
- [ ] Target validation and normalization
- [ ] HTTP-to-HTTPS redirect detection
- [ ] HTTP security-header checks
- [ ] TLS certificate inspection
- [ ] JSON report generation
- [ ] Scheduled monitoring
- [ ] Email and Telegram alerts
- [ ] Web dashboard

## Contributing

LotusWatch is currently in its early development stage.

Bug reports, feature suggestions, documentation improvements, and pull
requests are welcome. Please open an issue before proposing a major change.

## Security

Please read [`SECURITY.md`](SECURITY.md) before reporting a security
vulnerability.

Do not include passwords, access tokens, cookies, private keys, or sensitive
scan results in public issues.

## License

LotusWatch is released under the [MIT License](LICENSE).