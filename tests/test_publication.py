from __future__ import annotations

import os
import re
from pathlib import Path

import pytest
from packaging.version import Version

import scripts.smoke_testpypi as testpypi_module
from scripts.smoke_testpypi import (
    DOWNLOAD_RETRY_SECONDS,
    PYPI_SIMPLE_INDEX_URL,
    TESTPYPI_SIMPLE_INDEX_URL,
    _validate_beta_version,
    download_testpypi_wheel,
)
from scripts.smoke_testpypi import TestPyPISmokeError as PyPISmokeError
from scripts.validate_publication import (
    EXPECTED_DISTRIBUTION_NAME,
    PublicationIdentity,
    PublicationValidationError,
    load_publication_identity,
    validate_publication_event,
)

PROJECT_ROOT = Path(__file__).parents[1]
PUBLISH_WORKFLOW = PROJECT_ROOT / ".github" / "workflows" / "publish.yml"
PUBLISH_ACTION_SHA = "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"


def _write_project(
    root: Path,
    *,
    project_version: str = "0.1.0b1",
    package_version: str | None = None,
    distribution_name: str = EXPECTED_DISTRIBUTION_NAME,
) -> None:
    package_version = package_version or project_version
    package = root / "src" / "lotuswatch"
    package.mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        "\n".join(
            (
                "[project]",
                f'name = "{distribution_name}"',
                f'version = "{project_version}"',
            )
        ),
        encoding="utf-8",
    )
    (package / "__init__.py").write_text(
        f'__version__ = "{package_version}"\n',
        encoding="utf-8",
    )


def test_load_publication_identity_requires_matching_beta_metadata(
    tmp_path: Path,
) -> None:
    _write_project(tmp_path)

    identity = load_publication_identity(tmp_path)

    assert identity.distribution_name == EXPECTED_DISTRIBUTION_NAME
    assert identity.version == Version("0.1.0b1")


@pytest.mark.parametrize(
    ("project_version", "package_version", "distribution_name"),
    [
        ("0.1.0-alpha.6", None, EXPECTED_DISTRIBUTION_NAME),
        ("0.1.0b1.dev1", None, EXPECTED_DISTRIBUTION_NAME),
        ("0.1.0b1+private", None, EXPECTED_DISTRIBUTION_NAME),
        ("0.1.0b1", "0.1.0b2", EXPECTED_DISTRIBUTION_NAME),
        ("0.1.0b1", None, "lotuswatch_security"),
        ("0.1.0b1", None, "private-project"),
    ],
)
def test_load_publication_identity_rejects_unsafe_metadata(
    tmp_path: Path,
    project_version: str,
    package_version: str | None,
    distribution_name: str,
) -> None:
    _write_project(
        tmp_path,
        project_version=project_version,
        package_version=package_version,
        distribution_name=distribution_name,
    )

    with pytest.raises(PublicationValidationError):
        load_publication_identity(tmp_path)


def test_testpypi_event_requires_main_and_exact_expected_version() -> None:
    identity = PublicationIdentity(EXPECTED_DISTRIBUTION_NAME, Version("0.1.0b1"))

    result = validate_publication_event(
        identity,
        destination="testpypi",
        git_ref="refs/heads/main",
        expected_version="0.1.0b1",
    )

    assert result == identity.version

    with pytest.raises(PublicationValidationError, match="main"):
        validate_publication_event(
            identity,
            destination="testpypi",
            git_ref="refs/heads/feature",
            expected_version="0.1.0b1",
        )
    with pytest.raises(PublicationValidationError, match="canonical"):
        validate_publication_event(
            identity,
            destination="testpypi",
            git_ref="refs/heads/main",
            expected_version="0.1.0b2",
        )
    with pytest.raises(PublicationValidationError, match="canonical"):
        validate_publication_event(
            identity,
            destination="testpypi",
            git_ref="refs/heads/main",
            expected_version="0.1.0-beta.1",
        )


def test_pypi_event_requires_matching_tag_ref_and_prerelease() -> None:
    identity = PublicationIdentity(EXPECTED_DISTRIBUTION_NAME, Version("0.1.0b1"))

    result = validate_publication_event(
        identity,
        destination="pypi",
        git_ref="refs/tags/v0.1.0b1",
        release_tag="v0.1.0b1",
        release_prerelease=True,
    )

    assert result == identity.version

    for values in (
        {
            "git_ref": "refs/tags/v0.1.0b2",
            "release_tag": "v0.1.0b2",
            "release_prerelease": True,
        },
        {
            "git_ref": "refs/tags/v0.1.0b1",
            "release_tag": "v0.1.0b1",
            "release_prerelease": False,
        },
        {
            "git_ref": "refs/heads/main",
            "release_tag": "v0.1.0b1",
            "release_prerelease": True,
        },
    ):
        with pytest.raises(PublicationValidationError):
            validate_publication_event(identity, destination="pypi", **values)


@pytest.mark.parametrize("version", ["0.1.0-alpha.6", "0.1.0b1.dev1", "1.0"])
def test_testpypi_smoke_requires_plain_beta_version(version: str) -> None:
    with pytest.raises(PyPISmokeError):
        _validate_beta_version(version)


def test_testpypi_download_uses_only_testpypi_without_dependencies(
    tmp_path: Path,
) -> None:
    observed: list[str] = []

    def fake_download(command: list[str]) -> None:
        observed.extend(command)
        (tmp_path / "lotuswatch_security-0.1.0b1-py3-none-any.whl").touch()

    wheel = download_testpypi_wheel(
        Version("0.1.0b1"),
        tmp_path,
        command_runner=fake_download,
        sleeper=lambda _delay: None,
    )

    assert wheel.name == "lotuswatch_security-0.1.0b1-py3-none-any.whl"
    assert "--isolated" in observed
    assert "--no-deps" in observed
    assert "--only-binary=:all:" in observed
    assert TESTPYPI_SIMPLE_INDEX_URL in observed
    assert PYPI_SIMPLE_INDEX_URL not in observed
    assert "--extra-index-url" not in observed


def test_testpypi_download_retries_bounded_index_visibility(
    tmp_path: Path,
) -> None:
    attempts = 0
    delays: list[float] = []

    def eventually_available(_command: list[str]) -> None:
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise PyPISmokeError("not visible yet")
        (tmp_path / "lotuswatch_security-0.1.0b1-py3-none-any.whl").touch()

    download_testpypi_wheel(
        Version("0.1.0b1"),
        tmp_path,
        command_runner=eventually_available,
        sleeper=delays.append,
    )

    assert attempts == 3
    assert delays == [DOWNLOAD_RETRY_SECONDS, DOWNLOAD_RETRY_SECONDS]


def test_testpypi_smoke_installs_local_wheel_with_only_pypi_dependencies(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture_root = tmp_path / "fixtures"
    fixture_root.mkdir()
    observed: dict[str, object] = {}

    def fake_download(version: Version, destination: Path) -> Path:
        observed["download_version"] = version
        wheel = destination / "lotuswatch_security-0.1.0b1-py3-none-any.whl"
        wheel.touch()
        return wheel

    def fake_smoke_install(artifact: Path, **options: object) -> None:
        observed["artifact"] = artifact
        observed.update(options)

    monkeypatch.setattr(testpypi_module, "download_testpypi_wheel", fake_download)
    monkeypatch.setattr(testpypi_module, "smoke_install", fake_smoke_install)

    testpypi_module.smoke_test_testpypi(
        "0.1.0b1",
        compatibility_fixtures=fixture_root,
    )

    assert observed["download_version"] == Version("0.1.0b1")
    assert Path(observed["artifact"]).name.endswith("-py3-none-any.whl")
    assert observed["compatibility_fixtures"] == fixture_root
    assert observed["index_url"] == PYPI_SIMPLE_INDEX_URL
    assert observed["isolated_pip"] is True


def test_publish_workflow_has_least_privilege_event_boundaries() -> None:
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "release:" in workflow
    assert "- published" in workflow
    assert "pull_request" not in workflow
    assert "pull_request_target" not in workflow
    assert "\n  push:" not in workflow
    assert "permissions:\n  contents: read" in workflow
    assert workflow.count("id-token: write") == 2
    assert "id-token: write" not in workflow.split("  publish-testpypi:", 1)[0]
    assert "environment:\n      name: testpypi" in workflow
    assert "environment:\n      name: pypi" in workflow
    assert "if: github.event_name == 'workflow_dispatch'" in workflow
    assert "if: github.event_name == 'release'" in workflow


def test_publish_workflow_builds_once_and_reuses_pinned_artifact() -> None:
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")
    action_references = re.findall(r"^\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)

    assert action_references
    assert all(
        re.fullmatch(r"[^@\s]+@[0-9a-f]{40}", reference)
        for reference in action_references
    )
    assert workflow.count("python -m build --outdir dist") == 1
    assert (
        workflow.count(
            "actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4"
        )
        == 1
    )
    assert (
        workflow.count(
            "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53"
        )
        == 2
    )
    assert workflow.count(f"pypa/gh-action-pypi-publish@{PUBLISH_ACTION_SHA}") == 2
    assert workflow.count("attestations: true") == 2
    assert "skip-existing:" not in workflow
    assert "password:" not in workflow
    assert "secrets." not in workflow
    assert "PYPI_TOKEN" not in workflow
    assert ".pypirc" not in workflow


def test_publish_workflow_validates_versions_and_testpypi_index_separation() -> None:
    workflow = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "scripts/validate_publication.py" in workflow
    assert '--git-ref "$GITHUB_REF"' in workflow
    assert "github.event.release.tag_name" in workflow
    assert "expected_version:" in workflow
    assert "repository-url: https://test.pypi.org/legacy/" in workflow
    assert "python -m scripts.smoke_testpypi" in workflow
    assert "--compatibility-fixtures tests/fixtures/compatibility" in workflow


def test_repository_contains_no_pypi_credentials_or_configuration() -> None:
    excluded_directories = {".git", ".pytest_cache", ".ruff_cache", ".venv"}
    token_pattern = re.compile(r"\bpypi-[A-Za-z0-9_-]{20,}\b")
    discovered: list[Path] = []

    for root, directories, filenames in os.walk(PROJECT_ROOT):
        directories[:] = [
            directory
            for directory in directories
            if directory not in excluded_directories
        ]
        for filename in filenames:
            path = Path(root, filename)
            if filename.casefold() == ".pypirc":
                discovered.append(path.relative_to(PROJECT_ROOT))
                continue
            if path.suffix.casefold() not in {
                ".json",
                ".md",
                ".py",
                ".toml",
                ".txt",
                ".yaml",
                ".yml",
            }:
                continue
            if token_pattern.search(path.read_text(encoding="utf-8")):
                discovered.append(path.relative_to(PROJECT_ROOT))

    assert discovered == []
