from typer.testing import CliRunner

from lotuswatch.cli import app

runner = CliRunner()


def test_help_command() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "Monitor websites" in result.stdout


def test_scan_accepts_target() -> None:
    result = runner.invoke(app, ["scan", "example.com"])

    assert result.exit_code == 0
    assert "example.com" in result.stdout
