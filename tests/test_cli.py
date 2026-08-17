from typer.testing import CliRunner

import lotuswatch.cli
from lotuswatch.checks import RedirectCheckResult, RedirectStatus
from lotuswatch.cli import app

runner = CliRunner()


def test_help_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Monitor websites" in result.stdout


def test_scan_accepts_and_normalizes_target(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        lotuswatch.cli,
        "check_http_to_https_redirect",
        lambda target: successful_redirect_result(),
    )

    result = runner.invoke(app, ["scan", "EXAMPLE.COM"])

    assert result.exit_code == 0
    assert "EXAMPLE.COM" in result.stdout
    assert "https://example.com/" in result.stdout
    assert "PASS" in result.stdout


def test_scan_rejects_unsupported_scheme() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    output = result.stdout + result.stderr

    assert result.exit_code == 2
    assert "Only HTTP and HTTPS" in output
    assert "Traceback" not in output


def successful_redirect_result() -> RedirectCheckResult:
    return RedirectCheckResult(
        passed=True,
        status=RedirectStatus.PASSED,
        initial_url="http://example.com/",
        final_url="https://example.com/",
        redirect_count=1,
        initial_status_code=301,
        final_status_code=200,
    )
