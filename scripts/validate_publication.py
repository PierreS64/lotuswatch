"""Validate a LotusWatch Trusted Publishing event before building artifacts."""

from __future__ import annotations

import argparse
import ast
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

EXPECTED_DISTRIBUTION_NAME = "lotuswatch-security"
EXPECTED_MAIN_REF = "refs/heads/main"


class PublicationValidationError(RuntimeError):
    """Raised when an event cannot safely publish the declared project."""


@dataclass(frozen=True, slots=True)
class PublicationIdentity:
    distribution_name: str
    version: Version


def load_publication_identity(project_root: Path) -> PublicationIdentity:
    """Load and cross-check distribution and package version declarations."""

    try:
        project_root = project_root.resolve(strict=True)
        configuration = tomllib.loads(
            (project_root / "pyproject.toml").read_text(encoding="utf-8")
        )
        project = configuration["project"]
        distribution_name = project["name"]
        project_version = Version(project["version"])
        package_source = project_root / "src" / "lotuswatch" / "__init__.py"
        package_tree = ast.parse(package_source.read_text(encoding="utf-8"))
    except (
        OSError,
        KeyError,
        TypeError,
        SyntaxError,
        tomllib.TOMLDecodeError,
        InvalidVersion,
    ) as exc:
        raise PublicationValidationError(
            "Unable to load publication identity safely."
        ) from exc

    if distribution_name != EXPECTED_DISTRIBUTION_NAME:
        raise PublicationValidationError("Distribution name is not publishable.")

    package_version_value: object | None = None
    for statement in package_tree.body:
        if not isinstance(statement, ast.Assign):
            continue
        if any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in statement.targets
        ):
            try:
                package_version_value = ast.literal_eval(statement.value)
            except (ValueError, TypeError) as exc:
                raise PublicationValidationError(
                    "Package version declaration is not a literal."
                ) from exc
            break
    if not isinstance(package_version_value, str):
        raise PublicationValidationError("Package version declaration is missing.")
    try:
        package_version = Version(package_version_value)
    except InvalidVersion as exc:
        raise PublicationValidationError(
            "Package version declaration is invalid."
        ) from exc
    if package_version != project_version:
        raise PublicationValidationError(
            "Project and package version declarations do not match."
        )
    if (
        not project_version.is_prerelease
        or project_version.is_devrelease
        or project_version.local is not None
        or project_version.pre is None
        or project_version.pre[0] != "b"
    ):
        raise PublicationValidationError(
            "Trusted Publishing is limited to a reviewed beta version."
        )

    return PublicationIdentity(
        distribution_name=distribution_name,
        version=project_version,
    )


def validate_publication_event(
    identity: PublicationIdentity,
    *,
    destination: str,
    git_ref: str,
    expected_version: str = "",
    release_tag: str = "",
    release_prerelease: bool = False,
) -> Version:
    """Validate the event boundary and return the canonical package version."""

    if destination == "testpypi":
        if git_ref != EXPECTED_MAIN_REF:
            raise PublicationValidationError(
                "TestPyPI publication must be dispatched from main."
            )
        if not expected_version:
            raise PublicationValidationError(
                "TestPyPI publication requires an expected version."
            )
        try:
            requested = Version(expected_version)
        except InvalidVersion as exc:
            raise PublicationValidationError(
                "Expected TestPyPI version is invalid."
            ) from exc
        if requested != identity.version or expected_version != str(identity.version):
            raise PublicationValidationError(
                "Expected TestPyPI version is not the canonical project version."
            )
        if release_tag or release_prerelease:
            raise PublicationValidationError(
                "TestPyPI publication received unexpected release metadata."
            )
        return identity.version

    if destination == "pypi":
        if expected_version:
            raise PublicationValidationError(
                "PyPI release publication received a manual version input."
            )
        if not release_tag.startswith("v") or len(release_tag) == 1:
            raise PublicationValidationError(
                "Published release tag must start with v and contain a version."
            )
        try:
            tagged_version = Version(release_tag[1:])
        except InvalidVersion as exc:
            raise PublicationValidationError(
                "Published release tag is not a valid version."
            ) from exc
        if tagged_version != identity.version:
            raise PublicationValidationError(
                "Published release tag does not match project metadata."
            )
        expected_tag_ref = f"refs/tags/{release_tag}"
        if git_ref != expected_tag_ref:
            raise PublicationValidationError(
                "Published release ref does not match its tag."
            )
        if not release_prerelease:
            raise PublicationValidationError(
                "A beta package requires a GitHub pre-release."
            )
        return identity.version

    raise PublicationValidationError("Publication destination is unsupported.")


def _parse_boolean(value: str) -> bool:
    normalized = value.strip().casefold()
    if normalized == "true":
        return True
    if normalized in {"", "false"}:
        return False
    raise PublicationValidationError("Release prerelease state is invalid.")


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a LotusWatch package publication event."
    )
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--destination", choices=("testpypi", "pypi"), required=True)
    parser.add_argument("--git-ref", required=True)
    parser.add_argument("--expected-version", default="")
    parser.add_argument("--release-tag", default="")
    parser.add_argument("--release-prerelease", default="false")
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        identity = load_publication_identity(arguments.project_root)
        version = validate_publication_event(
            identity,
            destination=arguments.destination,
            git_ref=arguments.git_ref,
            expected_version=arguments.expected_version,
            release_tag=arguments.release_tag,
            release_prerelease=_parse_boolean(arguments.release_prerelease),
        )
    except PublicationValidationError as exc:
        print(f"Publication validation failed: {exc}", file=sys.stderr)
        return 1
    print(str(version))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
