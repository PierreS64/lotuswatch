import io
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest
from packaging.version import Version

from scripts.smoke_install_distribution import (
    SmokeInstallError,
    _copy_compatibility_fixtures,
    expected_artifact_version,
)
from scripts.verify_distribution import (
    DistributionVerificationError,
    _reject_forbidden_path,
    _scan_text_member,
    _validate_member_name,
    inspect_sdist,
    inspect_wheel,
)

PROJECT_ROOT = Path(__file__).parents[1]


@pytest.mark.parametrize(
    "name",
    [
        "../private.txt",
        "/absolute.txt",
        "folder/../../private.txt",
        "folder\\windows.txt",
        "folder/./ambiguous.txt",
    ],
)
def test_archive_member_names_reject_unsafe_paths(name: str) -> None:
    with pytest.raises(DistributionVerificationError):
        _validate_member_name(name, set())


def test_archive_member_names_reject_case_insensitive_duplicates() -> None:
    seen: set[str] = set()

    assert _validate_member_name("lotuswatch/module.py", seen) == (
        "lotuswatch/module.py"
    )
    with pytest.raises(DistributionVerificationError, match="Duplicate"):
        _validate_member_name("LOTUSWATCH/MODULE.PY", seen)


def test_wheel_inspection_rejects_symbolic_links(tmp_path: Path) -> None:
    wheel = tmp_path / "unsafe.whl"
    member = zipfile.ZipInfo("lotuswatch/link.py")
    member.create_system = 3
    member.external_attr = (stat.S_IFLNK | 0o777) << 16
    with zipfile.ZipFile(wheel, mode="w") as archive:
        archive.writestr(member, "target.py")

    with pytest.raises(DistributionVerificationError, match="link"):
        inspect_wheel(wheel)


def test_sdist_inspection_rejects_special_members(tmp_path: Path) -> None:
    sdist = tmp_path / "unsafe.tar.gz"
    link = tarfile.TarInfo("package/link.py")
    link.type = tarfile.SYMTYPE
    link.linkname = "target.py"
    with tarfile.open(sdist, mode="w:gz") as archive:
        archive.addfile(link, io.BytesIO())

    with pytest.raises(DistributionVerificationError, match="special member"):
        inspect_sdist(sdist)


@pytest.mark.parametrize(
    "name",
    [
        "tests/test_private.py",
        "lotuswatch/history.db",
        "lotuswatch/history.sqlite-wal",
        "lotuswatch/.env",
        "lotuswatch/private.key",
        "lotuswatch/telegram-response.json",
    ],
)
def test_distribution_paths_reject_repository_and_sensitive_artifacts(
    name: str,
) -> None:
    with pytest.raises(DistributionVerificationError):
        _reject_forbidden_path(name)


@pytest.mark.parametrize(
    ("name", "data"),
    [
        (
            "lotuswatch/config.txt",
            b"LOTUSWATCH_WEBHOOK_" + b"SECRET=do-not-package-this-value",
        ),
        (
            "lotuswatch/config.json",
            b'{"token":"123456:' + b'abcdefghijklmnopqrstuvwxyz_ABCD"}',
        ),
        (
            "lotuswatch/manual-target.md",
            b"https://kinetictech" + b".icu/",
        ),
    ],
)
def test_distribution_text_scan_rejects_credentials_and_private_targets(
    name: str,
    data: bytes,
) -> None:
    with pytest.raises(DistributionVerificationError):
        _scan_text_member(name, data)


def test_distribution_text_scan_allows_environment_variable_names() -> None:
    _scan_text_member(
        "lotuswatch/config.py",
        b'WEBHOOK_VARIABLE = "LOTUSWATCH_WEBHOOK_URL"',
    )


def test_expected_artifact_version_accepts_wheel_and_sdist() -> None:
    assert expected_artifact_version(
        Path("lotuswatch_security-0.1.0a6-py3-none-any.whl")
    ) == Version("0.1.0a6")
    assert expected_artifact_version(
        Path("lotuswatch_security-0.1.0a6.tar.gz")
    ) == Version("0.1.0a6")


def test_expected_artifact_version_rejects_other_files() -> None:
    with pytest.raises(SmokeInstallError):
        expected_artifact_version(Path("report.json"))


def test_compatibility_fixtures_copy_as_exact_bounded_inventory(
    tmp_path: Path,
) -> None:
    source = PROJECT_ROOT / "tests" / "fixtures" / "compatibility"
    destination = tmp_path / "copied"

    result = _copy_compatibility_fixtures(source, destination)

    assert result == destination
    assert {path.name: path.read_bytes() for path in destination.iterdir()} == {
        path.name: path.read_bytes() for path in source.iterdir()
    }


def test_compatibility_fixture_copy_rejects_unexpected_inventory(
    tmp_path: Path,
) -> None:
    source = tmp_path / "fixtures"
    source.mkdir()
    (source / "unexpected.json").write_text("{}", encoding="utf-8")

    with pytest.raises(SmokeInstallError, match="inventory"):
        _copy_compatibility_fixtures(source, tmp_path / "copied")


def test_package_ci_builds_and_smokes_without_publish_permissions() -> None:
    workflow = (PROJECT_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "pull_request_target" not in workflow
    assert "id-token: write" not in workflow
    assert "gh-action-pypi-publish" not in workflow
    assert "PYPI_TOKEN" not in workflow
    assert "package-build:" in workflow
    assert "package-install:" in workflow
    assert "python scripts/verify_distribution.py dist" in workflow
    assert "python scripts/smoke_install_distribution.py" in workflow
    assert workflow.count("--compatibility-fixtures tests/fixtures/compatibility") == 2
    assert (
        "actions/upload-artifact@330a01c490aca151604b8cf639adc76d48f6c5d4" in workflow
    )
    assert (
        "actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53" in workflow
    )


def test_source_distribution_manifest_excludes_repository_tests() -> None:
    manifest = (PROJECT_ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "prune tests" in manifest.splitlines()
