"""Validate LotusWatch wheel and source-distribution contents without extraction."""

from __future__ import annotations

import argparse
import re
import stat
import tarfile
import tomllib
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from email.policy import default as email_policy
from pathlib import Path, PurePosixPath
from typing import Final

from packaging.utils import (
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import Version

MAX_ARCHIVE_SIZE_BYTES: Final = 10 * 1024 * 1024
MAX_ARCHIVE_MEMBERS: Final = 512
MAX_MEMBER_SIZE_BYTES: Final = 5 * 1024 * 1024
MAX_TOTAL_UNCOMPRESSED_BYTES: Final = 25 * 1024 * 1024

EXPECTED_DISTRIBUTION_NAME: Final = "lotuswatch-security"
EXPECTED_WHEEL_TAGS: Final = {"py3-none-any"}

FORBIDDEN_PARTS: Final = {
    ".git",
    ".github",
    ".idea",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".vscode",
    "__pycache__",
    "build",
    "dist",
    "docs",
    "examples",
    "htmlcov",
    "outputs",
    "reports",
    "tests",
}
FORBIDDEN_FILENAMES: Final = {
    ".env",
    ".pypirc",
    "report.json",
}
FORBIDDEN_SUFFIXES: Final = {
    ".coverage",
    ".db",
    ".db-journal",
    ".db-shm",
    ".db-wal",
    ".key",
    ".pem",
    ".pyc",
    ".pyo",
    ".sqlite",
    ".sqlite-journal",
    ".sqlite-shm",
    ".sqlite-wal",
}
TEXT_SUFFIXES: Final = {
    ".cfg",
    ".json",
    ".md",
    ".py",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

TELEGRAM_TOKEN_PATTERN: Final = re.compile(
    rb"\b[1-9][0-9]{4,19}:[A-Za-z0-9_-]{20,128}\b"
)
SECRET_ASSIGNMENT_PATTERN: Final = re.compile(
    rb"LOTUSWATCH_(?:WEBHOOK_URL|WEBHOOK_SECRET|TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID)"
    rb"\s*=\s*[^\s\"']+"
)
PRIVATE_TARGET_PATTERN: Final = re.compile(
    rb"(?:kinetictech" rb"\.icu|cellphones" rb"\.com\.vn)",
    re.IGNORECASE,
)


class DistributionVerificationError(ValueError):
    """Raised when a built distribution violates the expected boundary."""


@dataclass(frozen=True, slots=True)
class ProjectIdentity:
    name: str
    canonical_name: str
    version: Version
    source_modules: frozenset[str]


@dataclass(frozen=True, slots=True)
class ArchiveContents:
    files: dict[str, bytes]

    @property
    def names(self) -> set[str]:
        return set(self.files)


def load_project_identity(project_root: Path) -> ProjectIdentity:
    """Load the expected public identity and runtime module inventory."""

    pyproject_path = project_root / "pyproject.toml"
    try:
        configuration = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
        project = configuration["project"]
        name = project["name"]
        version = Version(project["version"])
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise DistributionVerificationError(
            "Unable to load expected project metadata."
        ) from exc

    if not isinstance(name, str):
        raise DistributionVerificationError("Project name is invalid.")

    source_root = project_root / "src"
    source_modules = frozenset(
        path.relative_to(source_root).as_posix()
        for path in source_root.glob("lotuswatch/**/*.py")
        if path.is_file()
    )
    if not source_modules or "lotuswatch/__init__.py" not in source_modules:
        raise DistributionVerificationError("Runtime source inventory is incomplete.")

    return ProjectIdentity(
        name=name,
        canonical_name=canonicalize_name(name),
        version=version,
        source_modules=source_modules,
    )


def inspect_wheel(path: Path) -> ArchiveContents:
    """Read one bounded wheel into memory after validating every member."""

    _validate_archive_file(path)
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    total_size = 0

    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            _validate_member_count(members)
            for member in members:
                name = _validate_member_name(member.filename, seen)
                mode = member.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise DistributionVerificationError(
                        f"Wheel link member is not allowed: {name}"
                    )
                if member.flag_bits & 0x1:
                    raise DistributionVerificationError(
                        f"Encrypted wheel member is not allowed: {name}"
                    )
                if member.is_dir():
                    continue
                total_size = _validated_total_size(
                    name,
                    member.file_size,
                    total_size,
                )
                data = archive.read(member)
                if len(data) != member.file_size:
                    raise DistributionVerificationError(
                        f"Wheel member size changed while reading: {name}"
                    )
                files[name] = data
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise DistributionVerificationError("Wheel archive is unreadable.") from exc

    return ArchiveContents(files=files)


def inspect_sdist(path: Path) -> ArchiveContents:
    """Read one bounded gzip source distribution without filesystem extraction."""

    _validate_archive_file(path)
    files: dict[str, bytes] = {}
    seen: set[str] = set()
    total_size = 0

    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            _validate_member_count(members)
            for member in members:
                name = _validate_member_name(member.name, seen)
                if member.isdir():
                    continue
                if not member.isfile():
                    raise DistributionVerificationError(
                        f"Source distribution special member is not allowed: {name}"
                    )
                total_size = _validated_total_size(name, member.size, total_size)
                stream = archive.extractfile(member)
                if stream is None:
                    raise DistributionVerificationError(
                        f"Source distribution member is unreadable: {name}"
                    )
                data = stream.read(MAX_MEMBER_SIZE_BYTES + 1)
                if len(data) != member.size:
                    raise DistributionVerificationError(
                        f"Source distribution member size changed: {name}"
                    )
                files[name] = data
    except (OSError, tarfile.TarError) as exc:
        raise DistributionVerificationError(
            "Source distribution archive is unreadable."
        ) from exc

    return ArchiveContents(files=files)


def verify_distribution_directory(
    distribution_directory: Path,
    *,
    project_root: Path,
) -> tuple[Path, Path]:
    """Validate the exact wheel and source distribution in one directory."""

    if not distribution_directory.is_dir() or distribution_directory.is_symlink():
        raise DistributionVerificationError(
            "Distribution path must be a real local directory."
        )
    artifacts = sorted(path for path in distribution_directory.iterdir())
    if any(not path.is_file() or path.is_symlink() for path in artifacts):
        raise DistributionVerificationError(
            "Distribution directory contains an unsupported entry."
        )

    wheels = [path for path in artifacts if path.suffix == ".whl"]
    sdists = [path for path in artifacts if path.name.endswith(".tar.gz")]
    if len(artifacts) != 2 or len(wheels) != 1 or len(sdists) != 1:
        raise DistributionVerificationError(
            "Expected exactly one wheel and one .tar.gz source distribution."
        )

    identity = load_project_identity(project_root)
    wheel_path = wheels[0]
    sdist_path = sdists[0]
    _validate_artifact_filenames(wheel_path, sdist_path, identity)
    _verify_wheel_contents(wheel_path, inspect_wheel(wheel_path), identity)
    _verify_sdist_contents(sdist_path, inspect_sdist(sdist_path), identity)
    return wheel_path, sdist_path


def _validate_archive_file(path: Path) -> None:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DistributionVerificationError(
            "Distribution artifact is unreadable."
        ) from exc
    if not path.is_file() or path.is_symlink():
        raise DistributionVerificationError(
            "Distribution artifact must be a regular local file."
        )
    if not 0 < size <= MAX_ARCHIVE_SIZE_BYTES:
        raise DistributionVerificationError("Distribution artifact size is invalid.")


def _validate_member_count(members: list[object]) -> None:
    if not 1 <= len(members) <= MAX_ARCHIVE_MEMBERS:
        raise DistributionVerificationError("Archive member count is invalid.")


def _validate_member_name(raw_name: str, seen: set[str]) -> str:
    if not isinstance(raw_name, str) or not raw_name or "\x00" in raw_name:
        raise DistributionVerificationError("Archive member name is invalid.")
    if "\\" in raw_name:
        raise DistributionVerificationError(
            "Archive member uses a non-portable path separator."
        )
    raw_parts = raw_name.removesuffix("/").split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise DistributionVerificationError(
            f"Unsafe archive member path is not allowed: {raw_name}"
        )
    path = PurePosixPath(raw_name)
    if path.is_absolute():
        raise DistributionVerificationError(
            f"Unsafe archive member path is not allowed: {raw_name}"
        )
    normalized = path.as_posix().rstrip("/")
    identity = normalized.casefold()
    if identity in seen:
        raise DistributionVerificationError(
            f"Duplicate archive member is not allowed: {normalized}"
        )
    seen.add(identity)
    return normalized


def _validated_total_size(name: str, size: int, current_total: int) -> int:
    if not 0 <= size <= MAX_MEMBER_SIZE_BYTES:
        raise DistributionVerificationError(f"Archive member is too large: {name}")
    total = current_total + size
    if total > MAX_TOTAL_UNCOMPRESSED_BYTES:
        raise DistributionVerificationError("Archive expands beyond its size limit.")
    return total


def _validate_artifact_filenames(
    wheel_path: Path,
    sdist_path: Path,
    identity: ProjectIdentity,
) -> None:
    try:
        wheel_name, wheel_version, _build, wheel_tags = parse_wheel_filename(
            wheel_path.name
        )
        sdist_name, sdist_version = parse_sdist_filename(sdist_path.name)
    except ValueError as exc:
        raise DistributionVerificationError(
            "Distribution artifact filename is invalid."
        ) from exc

    if canonicalize_name(wheel_name) != identity.canonical_name:
        raise DistributionVerificationError("Wheel distribution name is incorrect.")
    if canonicalize_name(sdist_name) != identity.canonical_name:
        raise DistributionVerificationError("Source distribution name is incorrect.")
    if wheel_version != identity.version or sdist_version != identity.version:
        raise DistributionVerificationError("Distribution version is incorrect.")
    if {str(tag) for tag in wheel_tags} != EXPECTED_WHEEL_TAGS:
        raise DistributionVerificationError(
            "Wheel must use the pure-Python py3-none-any tag."
        )


def _verify_wheel_contents(
    path: Path,
    contents: ArchiveContents,
    identity: ProjectIdentity,
) -> None:
    dist_info = _single_dist_info_directory(contents.names)
    allowed_prefixes = ("lotuswatch/", f"{dist_info}/")
    for name, data in contents.files.items():
        if not name.startswith(allowed_prefixes):
            raise DistributionVerificationError(
                f"Unexpected wheel member is not allowed: {name}"
            )
        _reject_forbidden_path(name)
        _scan_text_member(name, data)

    missing_modules = identity.source_modules - contents.names
    if missing_modules:
        raise DistributionVerificationError("Wheel is missing runtime modules.")

    required = {
        f"{dist_info}/METADATA",
        f"{dist_info}/WHEEL",
        f"{dist_info}/entry_points.txt",
        f"{dist_info}/RECORD",
        f"{dist_info}/licenses/LICENSE",
    }
    if not required <= contents.names:
        raise DistributionVerificationError("Wheel metadata inventory is incomplete.")
    _verify_core_metadata(contents.files[f"{dist_info}/METADATA"], identity)
    entry_points = contents.files[f"{dist_info}/entry_points.txt"].decode("utf-8")
    if "lotuswatch = lotuswatch.cli:app" not in entry_points:
        raise DistributionVerificationError("Console entry point is missing.")


def _verify_sdist_contents(
    path: Path,
    contents: ArchiveContents,
    identity: ProjectIdentity,
) -> None:
    expected_root = path.name.removesuffix(".tar.gz")
    prefix = f"{expected_root}/"
    if not contents.names or any(
        not name.startswith(prefix) for name in contents.names
    ):
        raise DistributionVerificationError(
            "Source distribution root directory is invalid."
        )

    relative_files = {
        name.removeprefix(prefix): data for name, data in contents.files.items()
    }
    allowed_root_files = {
        "LICENSE",
        "MANIFEST.in",
        "PKG-INFO",
        "README.md",
        "pyproject.toml",
        "setup.cfg",
    }
    for name, data in relative_files.items():
        if not (
            name in allowed_root_files
            or name.startswith(("src/lotuswatch/", "src/lotuswatch_security.egg-info/"))
        ):
            raise DistributionVerificationError(
                f"Unexpected source distribution member is not allowed: {name}"
            )
        _reject_forbidden_path(name)
        _scan_text_member(name, data)

    required_modules = {f"src/{name}" for name in identity.source_modules}
    if not required_modules <= set(relative_files):
        raise DistributionVerificationError(
            "Source distribution is missing runtime modules."
        )
    required = {"LICENSE", "MANIFEST.in", "PKG-INFO", "README.md", "pyproject.toml"}
    if not required <= set(relative_files):
        raise DistributionVerificationError(
            "Source distribution metadata inventory is incomplete."
        )
    _verify_core_metadata(relative_files["PKG-INFO"], identity)


def _single_dist_info_directory(names: set[str]) -> str:
    candidates = {
        name.split("/", 1)[0]
        for name in names
        if ".dist-info/" in name and name.split("/", 1)[0].endswith(".dist-info")
    }
    if len(candidates) != 1:
        raise DistributionVerificationError(
            "Wheel must contain exactly one dist-info directory."
        )
    return candidates.pop()


def _reject_forbidden_path(name: str) -> None:
    path = PurePosixPath(name)
    parts = {part.casefold() for part in path.parts}
    filename = path.name.casefold()
    if parts & FORBIDDEN_PARTS:
        raise DistributionVerificationError(f"Forbidden artifact path: {name}")
    if filename in FORBIDDEN_FILENAMES or filename.endswith(".report.json"):
        raise DistributionVerificationError(f"Forbidden artifact file: {name}")
    if any(filename.endswith(suffix) for suffix in FORBIDDEN_SUFFIXES):
        raise DistributionVerificationError(f"Forbidden artifact suffix: {name}")
    if re.search(
        r"(?:webhook|telegram|notification).*(?:response|delivery).*(?:json|log|txt)$",
        filename,
        re.IGNORECASE,
    ):
        raise DistributionVerificationError(f"Provider output is not allowed: {name}")


def _scan_text_member(name: str, data: bytes) -> None:
    if PurePosixPath(name).suffix.casefold() not in TEXT_SUFFIXES:
        return
    if TELEGRAM_TOKEN_PATTERN.search(data):
        raise DistributionVerificationError(f"Credential-like value found in: {name}")
    if SECRET_ASSIGNMENT_PATTERN.search(data):
        raise DistributionVerificationError(f"Secret assignment found in: {name}")
    if PRIVATE_TARGET_PATTERN.search(data):
        raise DistributionVerificationError(f"Private test target found in: {name}")


def _verify_core_metadata(data: bytes, identity: ProjectIdentity) -> None:
    try:
        metadata = BytesParser(policy=email_policy).parsebytes(data)
        name = metadata["Name"]
        version = Version(metadata["Version"])
    except (TypeError, ValueError) as exc:
        raise DistributionVerificationError("Core Metadata is invalid.") from exc
    if not isinstance(name, str):
        raise DistributionVerificationError("Core Metadata name is invalid.")
    if canonicalize_name(name) != identity.canonical_name:
        raise DistributionVerificationError("Core Metadata name is incorrect.")
    if version != identity.version:
        raise DistributionVerificationError("Core Metadata version is incorrect.")
    if metadata["License-Expression"] != "MIT":
        raise DistributionVerificationError("Core Metadata license is incorrect.")
    if "LICENSE" not in (metadata.get_all("License-File") or []):
        raise DistributionVerificationError("Core Metadata license file is missing.")
    if metadata["Requires-Python"] != ">=3.12":
        raise DistributionVerificationError(
            "Core Metadata Python requirement is incorrect."
        )


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate LotusWatch wheel and source-distribution artifacts."
    )
    parser.add_argument("distribution_directory", type=Path)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        wheel, sdist = verify_distribution_directory(
            arguments.distribution_directory.resolve(),
            project_root=arguments.project_root.resolve(),
        )
    except DistributionVerificationError as exc:
        print(f"Distribution verification failed: {exc}")
        return 1
    print(f"Verified wheel: {wheel.name}")
    print(f"Verified source distribution: {sdist.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
