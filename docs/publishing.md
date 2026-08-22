# Trusted Publishing Runbook

LotusWatch publishes the `lotuswatch-security` distribution through GitHub
Actions Trusted Publishing. The workflow exchanges GitHub's short-lived OpenID
Connect identity for a short-lived upload credential. It does not use a PyPI
API token, `.pypirc`, password, repository secret, or environment secret.

Publishing is maintainer-operated release infrastructure. Do not run the
workflow from a feature branch, pull request, fork, or unreviewed commit.

## Workflow Boundary

The dedicated workflow is `.github/workflows/publish.yml`.

- A manual `workflow_dispatch` on `main` publishes the reviewed beta artifacts
  to TestPyPI.
- A GitHub Release `published` event publishes the matching reviewed tag to
  production PyPI.
- Ordinary pushes, pull requests, and `main` CI never publish.
- The build job has only `contents: read` and receives no OIDC permission.
- The build job validates the event, distribution name, package metadata,
  package-code version, expected version or release tag, archive inventory,
  metadata rendering, clean installation, and alpha-era compatibility fixtures.
- The wheel and source distribution are built once and uploaded as one GitHub
  Actions artifact.
- A selected publish job downloads that exact artifact and does not rebuild it.
- Only the selected publish job receives `id-token: write`.
- TestPyPI uses the `testpypi` GitHub environment.
- Production PyPI uses the protected `pypi` GitHub environment.

The workflow is intentionally limited to a canonical PEP 440 beta version such
as `0.1.0b1`. Development releases, local versions, alpha versions, arbitrary
branches, mismatched tags, and non-prerelease GitHub Releases fail before build
artifacts are uploaded for publication.

## Required Maintainer Setup

Enable multi-factor authentication on both the PyPI and TestPyPI maintainer
accounts before configuring publishers.

Create these GitHub environments in repository settings:

### `testpypi`

- Environment name: `testpypi`
- Do not add an API token or publishing secret.
- Restrict deployment to the `main` branch where the repository plan supports
  environment deployment rules.
- Optional approval can be used for an additional manual checkpoint.

### `pypi`

- Environment name: `pypi`
- Add at least one required reviewer.
- Disable self-review when the repository plan supports it.
- Restrict deployment to protected release tags or the maintainer-controlled
  release process.
- Do not add an API token or publishing secret.

Add a repository ruleset or equivalent maintainer-only process that protects
creation and modification of release tags matching `v*`. Production publishing
already checks that the release tag normalizes to the project version, but tag
protection prevents an unauthorized actor from choosing the reviewed release
identity in the first place.

## Trusted Publisher Registration

Register the following exact identity on TestPyPI:

| Field | Value |
| --- | --- |
| PyPI project | `lotuswatch-security` |
| GitHub owner | `PierreS64` |
| GitHub repository | `lotuswatch` |
| Workflow filename | `publish.yml` |
| Environment | `testpypi` |

Register the following exact pending publisher on production PyPI before the
first public publication:

| Field | Value |
| --- | --- |
| PyPI project | `lotuswatch-security` |
| GitHub owner | `PierreS64` |
| GitHub repository | `lotuswatch` |
| Workflow filename | `publish.yml` |
| Environment | `pypi` |

The owner, repository, workflow filename, and environment are part of the OIDC
identity and must match exactly, including case where the service treats it as
significant. TestPyPI and PyPI are separate services and require separate
publisher configuration.

A pending PyPI Trusted Publisher allows the first trusted publication to create
the project. It does not reserve the distribution name. Before the first upload,
another user could legitimately register that name. Recheck the project page and
publisher state immediately before the Beta 1 production release. Stop if the
name or ownership state is unexpected.

## TestPyPI Publication

After the Beta 1 preparation pull request is merged and all `main` CI jobs are
green:

1. Open **Actions → Publish Python package → Run workflow**.
2. Select the `main` branch.
3. Enter the exact canonical project version, for example `0.1.0b1`, in
   `expected_version`.
4. Review and start the workflow.
5. Confirm the build job validates one wheel and one source distribution.
6. Approve the `testpypi` environment if approval was configured.
7. Wait for the automatic TestPyPI installation job.

The post-publication job downloads only LotusWatch from TestPyPI:

```bash
python -m pip --isolated download \
  --no-deps \
  --only-binary=:all: \
  --index-url https://test.pypi.org/simple/ \
  "lotuswatch-security==0.1.0b1"
```

It then installs that local wheel while resolving dependencies only from the
normal PyPI index. TestPyPI is never configured as an `--extra-index-url`, so
dependency resolution cannot mix TestPyPI packages with normal PyPI packages.
The clean environment verifies distribution metadata, the `lotuswatch` import,
`lotuswatch --version`, CLI help, `pip check`, and all compatibility fixtures.

The equivalent maintainer command is:

```bash
python -m scripts.smoke_testpypi 0.1.0b1 \
  --compatibility-fixtures tests/fixtures/compatibility
```

Do not proceed to production if publication or the clean installation check
fails.

## Production PyPI Publication

Production publication is not manually dispatched. After the reviewed TestPyPI
artifact and installation checks succeed:

1. Confirm `main` still points to the reviewed release commit and all CI jobs
   are green.
2. Create the planned protected tag, such as `v0.1.0b1`, on that exact commit.
3. Create a GitHub pre-release from that tag.
4. Review the release notes and publish the GitHub pre-release.
5. The `release: published` event starts `.github/workflows/publish.yml`.
6. The build job checks that `v0.1.0b1` normalizes to the same version as both
   `pyproject.toml` and `lotuswatch.__version__`.
7. A required reviewer approves the protected `pypi` environment.
8. The PyPI job downloads and publishes the unchanged reviewed workflow
   artifact.
9. Verify the PyPI project page, filenames, hashes, attestations, metadata, and a
   clean installation before closing the sprint milestone.

Do not create or publish the GitHub Release until TestPyPI validation is
complete. Publishing the GitHub Release is the production publication trigger.

## Attestations

The pinned official PyPI publication action keeps PEP 740 attestations enabled
for both indexes. PyPI associates an attestation with each uploaded distribution
artifact when the index and Trusted Publishing flow support it.

An attestation binds an artifact digest to the GitHub OIDC workflow identity and
provides verifiable publication provenance. It does not prove that LotusWatch is
secure, that its dependencies are safe, that a scan report is authentic, or that
a reported finding is correct. Preserve and review the index-generated
attestations and displayed hashes; do not replace them with self-authored claims.

## Failure and Recovery

Python package index versions are immutable. The workflow deliberately does not
set `skip-existing`.

- If validation or build fails before publication, fix the branch through a pull
  request and restart only after the reviewed change reaches `main`.
- If TestPyPI publication succeeds but installation verification fails, stop the
  release. Diagnose the published artifact and prepare a new beta version.
- If either wheel or source distribution reaches an index, do not delete and
  reuse that version as a recovery strategy.
- If production publication is partial or fails after any file is accepted,
  prepare a new version such as `0.1.0b2`, repeat TestPyPI validation, create a
  new tag and GitHub Release, and publish the new immutable version.
- Never work around a failure by adding a token, enabling `skip-existing`,
  rebuilding inside the OIDC-enabled job, or weakening environment protection.

Repository history, Git tags, GitHub Releases, index files, and attestations must
remain consistent enough for a maintainer to identify exactly which reviewed
source produced each published artifact.
