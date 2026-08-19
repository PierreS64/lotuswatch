import json
import re
import tomllib
from pathlib import Path

import pytest

from lotuswatch import __version__
from lotuswatch.checks import CAACheckResult, EmailDNSCheckResult
from lotuswatch.models import ScanReport

PROJECT_ROOT = Path(__file__).parents[2]


def test_version_metadata_matches_package_version() -> None:
    pyproject = tomllib.loads(
        (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )

    assert pyproject["project"]["version"] == __version__
    assert __version__ == "0.1.0-alpha.3"


def test_sample_report_validates_and_matches_summary() -> None:
    sample_path = PROJECT_ROOT / "examples" / "sample-report.json"
    sample_data = json.loads(sample_path.read_text(encoding="utf-8"))

    report = ScanReport.model_validate(sample_data)

    assert report.lotuswatch_version == __version__
    assert report.summary.checks_completed == len(report.checks) == 5
    assert report.summary.findings_total == len(report.findings) == 4
    assert report.target.normalized_url == "https://demo.example/"

    check_names = [check["name"] for check in report.checks]
    assert check_names == [
        "http_to_https_redirect",
        "tls_certificate",
        "http_security_headers",
        "dns_caa",
        "dns_email_authentication",
    ]

    caa_data = dict(report.checks[3])
    email_dns_data = dict(report.checks[4])
    caa_data.pop("name")
    email_dns_data.pop("name")

    CAACheckResult.model_validate(caa_data)
    EmailDNSCheckResult.model_validate(email_dns_data)

    serialized = sample_path.read_text(encoding="utf-8").casefold()
    assert "password" not in serialized
    assert "api_key" not in serialized
    assert "demo.example" in serialized


@pytest.mark.parametrize(
    "relative_path",
    ["README.md", "SECURITY.md", "docs/scope.md"],
)
def test_documentation_links_and_code_fences(relative_path: str) -> None:
    document_path = PROJECT_ROOT / relative_path
    text = document_path.read_text(encoding="utf-8")

    assert text.count("```") % 2 == 0

    for target in re.findall(r"\[[^]]+\]\((?!https?://)([^)#]+)(?:#[^)]*)?\)", text):
        resolved = (document_path.parent / target).resolve()
        assert resolved.exists(), f"Broken relative link in {relative_path}: {target}"
