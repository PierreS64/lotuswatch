# Beta Compatibility and Upgrade Policy

This document defines the compatibility contract for the LotusWatch `0.1.0`
beta series. Beta 1 verifies this contract against fixed alpha.5 and alpha.6
fixtures so supported data can be checked before and after installation or
upgrade.

LotusWatch beta releases are still pre-release software. Commands, output, and
behavior can evolve during the beta. An incompatible persisted-data change
must be documented explicitly and must use a new schema or fingerprint version,
or provide a reviewed migration path. This policy is not a stable `1.0.0`
compatibility guarantee.

## Independent Version Domains

LotusWatch deliberately versions persisted formats independently from the
installed package:

| Version domain | Current supported value | Purpose |
| --- | --- | --- |
| Python package | `0.1.0b1` | Installed code and distribution metadata |
| Scan report schema | `1.0` | Individual JSON scan reports |
| Comparison schema | `1.0` | JSON baseline comparison reports |
| Notification schema | `1.0` | Minimal webhook and Telegram event content |
| Finding fingerprint | `1` | Stable target-and-finding identity |
| Monitoring database | `1` | Local SQLite tables and stored reports |

A historical `lotuswatch_version` value such as `0.1.0-alpha.5` identifies the
code that produced an artifact. It does not make schema `1.0` incompatible with
a newer package. Conversely, changing only a package version never grants
permission to reinterpret an unsupported schema.

The beta compatibility suite proves that valid alpha.5 and alpha.6 artifacts
using the supported versions above remain readable. Arbitrary development
snapshots, malformed artifacts, and unsupported future schema versions are not
accepted.

## Public Beta Contract

During the `0.1.0` beta series, LotusWatch intends to preserve these public CLI
entry points:

- `lotuswatch --version`
- `lotuswatch scan`
- `lotuswatch compare`
- `lotuswatch monitor add`, `list`, `enable`, `disable`, and `run`
- `lotuswatch monitor history`, `show`, and `prune`
- `lotuswatch monitor database check` and `backup`

Documented options for output selection, local database selection, severity
policies, and opt-in notifications are part of the beta contract. Additive
options can be introduced. Removing or redefining an option requires explicit
release documentation and, where persisted data is involved, a versioned format
or migration path.

The documented process exit codes remain:

- `0`: the command completed without a selected policy or delivery failure.
- `1`: an explicitly selected scan or comparison severity policy matched.
- `2`: usage, input, compatibility, scan orchestration, comparison, output, or
  storage validation failed.
- `3`: a monitoring run was stored, but at least one requested notification
  delivery failed.

Finding severity is not a complete risk score. Exit-code compatibility does not
claim that a target is secure, exploitable, or available.

## Persisted Data Compatibility

Valid scan report schema `1.0`, comparison schema `1.0`, notification schema
`1.0`, finding fingerprint version `1`, and monitoring database schema `1` are
read-compatible during the `0.1.0` beta series unless a later release explicitly
documents a successor and its migration boundary.

Old data remains untrusted input. Current size limits, duplicate-key rejection,
non-finite-number rejection, target normalization, model validation, fingerprint
validation, database integrity checks, and foreign-key checks still apply.
Compatibility never bypasses a current safety check.

An unsupported future version fails explicitly. LotusWatch does not silently
downgrade it, partially migrate it, rewrite it, delete it, or guess its meaning.
Use `lotuswatch monitor database check --database <path>` before an upgrade and
create a separate non-overwriting backup before testing new software against a
valuable monitoring database.

## Regression Fixtures

The repository keeps immutable synthetic compatibility fixtures under
`tests/fixtures/compatibility`. They use only the reserved `demo.example`
domain, deterministic timestamps, and fake opaque identifiers. The database
fixture is a JSON representation used to materialize schema `1` in a temporary
directory; no generated SQLite database is committed.

The test suite fixes SHA-256 digests for the fixture inventory, validates every
supported version domain, regenerates the comparison, opens the materialized
database without rewriting its rows, and rejects unsupported future versions.
Installed wheel and source-distribution smoke tests copy these fixtures outside
the repository and validate them through the installed package.

Fixture hashes detect accidental test-data changes. They are not signatures and
do not authenticate user reports, databases, or their producer.

## Upgrade from an Editable Alpha Checkout

Before changing environments:

1. Stop overlapping scheduled monitoring jobs.
2. Record the current version with `lotuswatch --version`.
3. Run `lotuswatch monitor database check --database <absolute-database-path>`.
4. Create a separate backup with `lotuswatch monitor database backup
   <absolute-backup-path> --database <absolute-database-path>`.
5. Protect the database and backup as sensitive, unencrypted local history.
6. Update the checkout, recreate or activate the intended virtual environment,
   and reinstall the reviewed source with `python -m pip install -e ".[dev]"`.
7. Run `lotuswatch --version` and repeat the database check before restoring
   scheduled jobs.

Do not overwrite the only database copy, and do not treat a successful schema
check as proof of report provenance or authenticity.

## Install or Upgrade to a PyPI Beta

Install an explicit reviewed version in a fresh environment when practical:

```bash
python -m pip install "lotuswatch-security==0.1.0b1"
lotuswatch --version
```

An explicit pre-release version does not need pip's general `--pre` resolver
option. To request the newest available LotusWatch pre-release without pinning
an exact version, use `--pre` deliberately and review the resolved version:

```bash
python -m pip install --pre --upgrade lotuswatch-security
lotuswatch --version
```

Contributor checkouts continue to use editable installation from the
repository. Do not mix an editable checkout and an index installation in the
same environment when verifying upgrade behavior.

PyPI installation changes the installed package; it does not migrate, restore,
authenticate, encrypt, or back up local monitoring data automatically.
The complete TestPyPI and production sequence is documented in the
[`Trusted Publishing runbook`](publishing.md).

## Trust Boundary

Compatibility means that current code can validate and interpret a supported
format. It does not prove who created an artifact, when it was created, whether
it was modified, or whether its observations are true. Reports, comparisons,
notifications, SQLite databases, and backups can contain sensitive target and
finding data and must be protected and reviewed before sharing.
