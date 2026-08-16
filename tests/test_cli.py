from typer.testing import CliRunner

from lotuswatch.cli import app

runner = CliRunner()


def test_help_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Monitor websites" in result.stdout


def test_scan_accepts_and_normalizes_target() -> None:
    result = runner.invoke(app, ["scan", "EXAMPLE.COM"])

    assert result.exit_code == 0
    assert "EXAMPLE.COM" in result.stdout
    assert "https://example.com/" in result.stdout


def test_scan_rejects_unsupported_scheme() -> None:
    result = runner.invoke(app, ["scan", "ftp://example.com"])

    output = result.stdout + result.stderr

    assert result.exit_code == 2
    assert "Only HTTP and HTTPS" in output
    assert "Traceback" not in output
