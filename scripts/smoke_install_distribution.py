"""Install and smoke-test one LotusWatch distribution outside the source tree."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path
from typing import Final

from packaging.utils import parse_sdist_filename, parse_wheel_filename
from packaging.version import Version


class SmokeInstallError(RuntimeError):
    """Raised when an isolated installed-artifact check fails."""


MAX_COMPATIBILITY_FIXTURE_SIZE_BYTES: Final = 5 * 1024 * 1024
COMPATIBILITY_FIXTURE_FILENAMES: Final = (
    "alpha5-scan-report.json",
    "alpha6-scan-report.json",
    "alpha6-comparison-report.json",
    "alpha6-notification-event.json",
    "alpha5-monitoring-v1.json",
    "fingerprint-v1.json",
)


def expected_artifact_version(path: Path) -> Version:
    if path.suffix == ".whl":
        return parse_wheel_filename(path.name)[1]
    if path.name.endswith(".tar.gz"):
        return parse_sdist_filename(path.name)[1]
    raise SmokeInstallError("Artifact must be a wheel or .tar.gz source distribution.")


def smoke_install(
    artifact: Path,
    *,
    compatibility_fixtures: Path | None = None,
    index_url: str | None = None,
    isolated_pip: bool = False,
) -> None:
    artifact = artifact.resolve()
    if not artifact.is_file() or artifact.is_symlink():
        raise SmokeInstallError("Artifact must be a regular local file.")
    expected_version = expected_artifact_version(artifact)

    with tempfile.TemporaryDirectory(prefix="lotuswatch-installed-smoke-") as raw_root:
        root = Path(raw_root).resolve()
        environment_root = root / "environment"
        working_directory = root / "working-directory"
        working_directory.mkdir()
        venv.EnvBuilder(with_pip=True).create(environment_root)

        python = _environment_executable(environment_root, "python")
        environment = _isolated_environment()

        install_command = [str(python), "-m", "pip"]
        if isolated_pip:
            install_command.append("--isolated")
        install_command.append("install")
        if index_url is not None:
            install_command.extend(("--index-url", index_url))
        install_command.append(str(artifact))
        _run(
            install_command,
            cwd=working_directory,
            environment=environment,
        )
        lotuswatch = _environment_executable(environment_root, "lotuswatch")
        _run(
            [str(python), "-m", "pip", "check"],
            cwd=working_directory,
            environment=environment,
        )
        inspection = _run(
            [
                str(python),
                "-c",
                (
                    "import json; import lotuswatch; "
                    "from importlib.metadata import version; "
                    "print(json.dumps({'package_version': lotuswatch.__version__, "
                    "'distribution_version': version('lotuswatch-security'), "
                    "'module_file': lotuswatch.__file__}))"
                ),
            ],
            cwd=working_directory,
            environment=environment,
        )
        try:
            details = json.loads(inspection.stdout)
            package_version = Version(details["package_version"])
            distribution_version = Version(details["distribution_version"])
            module_file = Path(details["module_file"]).resolve()
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            raise SmokeInstallError(
                "Installed package inspection was invalid."
            ) from exc

        if (
            package_version != expected_version
            or distribution_version != expected_version
        ):
            raise SmokeInstallError(
                "Installed package version does not match the artifact."
            )
        if not module_file.is_relative_to(environment_root):
            raise SmokeInstallError(
                "Installed import resolved outside the virtual environment."
            )

        version_result = _run(
            [str(lotuswatch), "--version"],
            cwd=working_directory,
            environment=environment,
        )
        if Version(version_result.stdout.strip()) != expected_version:
            raise SmokeInstallError(
                "Installed CLI version does not match the artifact."
            )

        help_result = _run(
            [str(lotuswatch), "--help"],
            cwd=working_directory,
            environment=environment,
        )
        for expected_command in ("scan", "compare", "monitor"):
            if expected_command not in help_result.stdout:
                raise SmokeInstallError("Installed CLI help is incomplete.")

        if compatibility_fixtures is not None:
            copied_fixtures = _copy_compatibility_fixtures(
                compatibility_fixtures,
                working_directory / "compatibility-fixtures",
            )
            verifier = (
                Path(__file__).with_name("verify_compatibility_fixtures.py").resolve()
            )
            if not verifier.is_file() or verifier.is_symlink():
                raise SmokeInstallError("Compatibility verifier script is unavailable.")
            _run(
                [str(python), str(verifier), str(copied_fixtures)],
                cwd=working_directory,
                environment=environment,
            )


def _copy_compatibility_fixtures(source: Path, destination: Path) -> Path:
    """Copy an exact bounded fixture inventory outside the source tree."""

    if source.is_symlink():
        raise SmokeInstallError("Compatibility fixture path must be a real directory.")
    try:
        source = source.resolve(strict=True)
    except OSError as exc:
        raise SmokeInstallError(
            "Compatibility fixture directory is unavailable."
        ) from exc
    if not source.is_dir():
        raise SmokeInstallError("Compatibility fixture path must be a real directory.")

    try:
        entries = {path.name: path for path in source.iterdir()}
    except OSError as exc:
        raise SmokeInstallError(
            "Unable to inspect compatibility fixture directory."
        ) from exc
    if set(entries) != set(COMPATIBILITY_FIXTURE_FILENAMES):
        raise SmokeInstallError(
            "Compatibility fixture inventory is incomplete or unexpected."
        )
    try:
        destination.mkdir()
    except OSError as exc:
        raise SmokeInstallError(
            "Unable to create isolated compatibility fixture directory."
        ) from exc
    for filename in COMPATIBILITY_FIXTURE_FILENAMES:
        fixture = entries[filename]
        if not fixture.is_file() or fixture.is_symlink():
            raise SmokeInstallError(
                "Compatibility fixture must be a regular local file."
            )
        try:
            size = fixture.stat().st_size
            if size > MAX_COMPATIBILITY_FIXTURE_SIZE_BYTES:
                raise SmokeInstallError("Compatibility fixture exceeds the size limit.")
            payload = fixture.read_bytes()
        except OSError as exc:
            raise SmokeInstallError("Unable to read compatibility fixture.") from exc
        if len(payload) != size:
            raise SmokeInstallError("Compatibility fixture changed while being copied.")
        try:
            (destination / filename).write_bytes(payload)
        except OSError as exc:
            raise SmokeInstallError("Unable to copy compatibility fixture.") from exc
    return destination


def _environment_executable(environment_root: Path, name: str) -> Path:
    if os.name == "nt":
        filename = f"{name}.exe"
        path = environment_root / "Scripts" / filename
    else:
        path = environment_root / "bin" / name
    if not path.is_file():
        raise SmokeInstallError(f"Virtual environment executable is missing: {name}")
    return path


def _isolated_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_INPUT"] = "1"
    return environment


def _run(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SmokeInstallError("Installed-artifact command failed.") from exc


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Install and smoke-test one LotusWatch distribution artifact."
    )
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--compatibility-fixtures", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        smoke_install(
            arguments.artifact,
            compatibility_fixtures=arguments.compatibility_fixtures,
        )
    except (SmokeInstallError, ValueError) as exc:
        print(f"Installed-artifact smoke test failed: {exc}")
        return 1
    print(f"Installed-artifact smoke test passed: {arguments.artifact.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
