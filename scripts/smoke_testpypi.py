"""Download LotusWatch alone from TestPyPI and smoke-test it with PyPI deps."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final

from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import InvalidVersion, Version

from scripts.smoke_install_distribution import smoke_install

EXPECTED_DISTRIBUTION_NAME: Final = "lotuswatch-security"
TESTPYPI_SIMPLE_INDEX_URL: Final = "https://test.pypi.org/simple/"
PYPI_SIMPLE_INDEX_URL: Final = "https://pypi.org/simple/"
MAX_DOWNLOAD_ATTEMPTS: Final = 6
DOWNLOAD_RETRY_SECONDS: Final = 10.0


class TestPyPISmokeError(RuntimeError):
    """Raised when the TestPyPI artifact cannot be verified safely."""


def _validate_beta_version(value: str) -> Version:
    try:
        version = Version(value)
    except InvalidVersion as exc:
        raise TestPyPISmokeError("TestPyPI version is invalid.") from exc
    if (
        not version.is_prerelease
        or version.is_devrelease
        or version.local is not None
        or version.pre is None
        or version.pre[0] != "b"
    ):
        raise TestPyPISmokeError("TestPyPI smoke testing requires a beta version.")
    return version


def _isolated_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INPUT"] = "1"
    return environment


def _run_download(command: list[str]) -> None:
    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
            env=_isolated_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TestPyPISmokeError(
            "Unable to download the requested TestPyPI wheel."
        ) from exc


def download_testpypi_wheel(
    version: Version,
    destination: Path,
    *,
    command_runner: Callable[[list[str]], None] = _run_download,
    sleeper: Callable[[float], None] = time.sleep,
) -> Path:
    """Download exactly one LotusWatch wheel without resolving dependencies."""

    destination = destination.resolve()
    if not destination.is_dir() or destination.is_symlink():
        raise TestPyPISmokeError("Download destination must be a real directory.")
    requirement = f"{EXPECTED_DISTRIBUTION_NAME}=={version}"
    command = [
        sys.executable,
        "-m",
        "pip",
        "--isolated",
        "download",
        "--no-deps",
        "--only-binary=:all:",
        "--index-url",
        TESTPYPI_SIMPLE_INDEX_URL,
        "--dest",
        str(destination),
        requirement,
    ]

    for attempt in range(1, MAX_DOWNLOAD_ATTEMPTS + 1):
        try:
            command_runner(command)
            break
        except TestPyPISmokeError:
            if attempt == MAX_DOWNLOAD_ATTEMPTS:
                raise
            sleeper(DOWNLOAD_RETRY_SECONDS)

    entries = list(destination.iterdir())
    if len(entries) != 1:
        raise TestPyPISmokeError(
            "TestPyPI download did not produce exactly one artifact."
        )
    wheel = entries[0]
    if not wheel.is_file() or wheel.is_symlink() or wheel.suffix != ".whl":
        raise TestPyPISmokeError("TestPyPI artifact must be one regular wheel.")
    try:
        name, artifact_version, _build, _tags = parse_wheel_filename(wheel.name)
    except ValueError as exc:
        raise TestPyPISmokeError("TestPyPI wheel filename is invalid.") from exc
    if (
        canonicalize_name(name) != canonicalize_name(EXPECTED_DISTRIBUTION_NAME)
        or artifact_version != version
    ):
        raise TestPyPISmokeError(
            "TestPyPI wheel identity does not match the requested release."
        )
    return wheel


def smoke_test_testpypi(
    version_text: str,
    *,
    compatibility_fixtures: Path | None = None,
) -> None:
    """Download from TestPyPI, then install with dependencies only from PyPI."""

    version = _validate_beta_version(version_text)
    with tempfile.TemporaryDirectory(prefix="lotuswatch-testpypi-") as raw_root:
        download_directory = Path(raw_root) / "download"
        download_directory.mkdir()
        wheel = download_testpypi_wheel(version, download_directory)
        smoke_install(
            wheel,
            compatibility_fixtures=compatibility_fixtures,
            index_url=PYPI_SIMPLE_INDEX_URL,
            isolated_pip=True,
        )


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Smoke-test one published LotusWatch TestPyPI beta wheel."
    )
    parser.add_argument("version")
    parser.add_argument("--compatibility-fixtures", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        smoke_test_testpypi(
            arguments.version,
            compatibility_fixtures=arguments.compatibility_fixtures,
        )
    except (TestPyPISmokeError, ValueError) as exc:
        print(f"TestPyPI smoke test failed: {exc}")
        return 1
    print(f"TestPyPI smoke test passed: {arguments.version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
