import re
import tomllib
from pathlib import Path

from packaging.version import Version

from lotuswatch import __version__

PROJECT_ROOT = Path(__file__).parents[1]
PYPROJECT_PATH = PROJECT_ROOT / "pyproject.toml"
README_PATH = PROJECT_ROOT / "README.md"


def project_configuration() -> dict[str, object]:
    return tomllib.loads(PYPROJECT_PATH.read_text(encoding="utf-8"))


def test_build_backend_and_package_discovery_are_explicit() -> None:
    configuration = project_configuration()

    assert configuration["build-system"] == {
        "requires": ["setuptools>=77.0.3"],
        "build-backend": "setuptools.build_meta",
    }
    assert configuration["tool"]["setuptools"]["packages"]["find"] == {
        "where": ["src"],
        "include": ["lotuswatch*"],
        "namespaces": False,
    }


def test_project_identity_and_version_metadata_are_consistent() -> None:
    project = project_configuration()["project"]

    assert project["name"] == "lotuswatch-security"
    assert project["scripts"] == {"lotuswatch": "lotuswatch.cli:app"}
    assert project["requires-python"] == ">=3.12"
    assert Version(project["version"]) == Version(__version__)


def test_project_uses_pep_639_mit_license_metadata() -> None:
    project = project_configuration()["project"]

    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert (PROJECT_ROOT / "LICENSE").is_file()
    assert all(
        not classifier.startswith("License ::") for classifier in project["classifiers"]
    )


def test_supported_python_and_public_project_metadata_are_declared() -> None:
    project = project_configuration()["project"]
    classifiers = set(project["classifiers"])

    assert {
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
    } <= classifiers
    assert project["keywords"] == [
        "security",
        "monitoring",
        "tls",
        "http",
        "dns",
        "cli",
    ]
    assert project["urls"] == {
        "Homepage": "https://github.com/PierreS64/lotuswatch",
        "Documentation": "https://github.com/PierreS64/lotuswatch#readme",
        "Repository": "https://github.com/PierreS64/lotuswatch.git",
        "Issues": "https://github.com/PierreS64/lotuswatch/issues",
        "Changelog": "https://github.com/PierreS64/lotuswatch/releases",
    }


def test_runtime_and_development_dependencies_remain_separate() -> None:
    project = project_configuration()["project"]
    runtime_dependencies = project["dependencies"]
    development_dependencies = project["optional-dependencies"]["dev"]
    distribution_dependencies = project["optional-dependencies"]["distribution"]

    assert runtime_dependencies
    assert development_dependencies
    assert not any(
        dependency.casefold().startswith(("pytest", "ruff"))
        for dependency in runtime_dependencies
    )
    assert any(item.startswith("pytest") for item in development_dependencies)
    assert any(item.startswith("ruff") for item in development_dependencies)
    assert any(item.startswith("build") for item in distribution_dependencies)
    assert any(item.startswith("packaging") for item in distribution_dependencies)
    assert any(item.startswith("twine") for item in distribution_dependencies)
    assert not set(runtime_dependencies) & set(distribution_dependencies)


def test_readme_uses_package_index_safe_links() -> None:
    readme = README_PATH.read_text(encoding="utf-8")
    markdown_targets = re.findall(r"\[[^]]+\]\(([^)]+)\)", readme)

    assert markdown_targets
    assert all(target.startswith(("https://", "#")) for target in markdown_targets)
    assert "lotuswatch-security" in readme
    assert "lotuswatch --version" in readme
