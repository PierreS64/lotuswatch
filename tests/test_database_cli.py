import sqlite3
from pathlib import Path

import pytest
from rich.text import Text
from typer.testing import CliRunner, Result

import lotuswatch.monitoring
from lotuswatch.cli import app
from lotuswatch.storage import MonitoredTarget, SQLiteMonitoringStore

runner = CliRunner()


def plain_output(result: Result) -> str:
    return Text.from_ansi(result.stdout + result.stderr).plain


def make_database(path: Path) -> SQLiteMonitoringStore:
    store = SQLiteMonitoringStore(path)
    store.initialize()
    store.create_target(
        MonitoredTarget.create(
            name="production",
            original_target="example.com",
            normalized_url="https://example.com/",
        )
    )
    return store


def test_monitor_help_exposes_database_check_and_backup() -> None:
    monitor_help = runner.invoke(app, ["monitor", "--help"])
    database_help = runner.invoke(app, ["monitor", "database", "--help"])

    assert monitor_help.exit_code == 0
    assert "database" in plain_output(monitor_help)
    assert database_help.exit_code == 0
    assert "check" in plain_output(database_help)
    assert "backup" in plain_output(database_help)


@pytest.mark.parametrize("command", [["check"], ["backup", "backup.db"]])
def test_database_commands_require_explicit_source(command: list[str]) -> None:
    result = runner.invoke(app, ["monitor", "database", *command])

    assert result.exit_code == 2
    assert "--database is required" in plain_output(result)


def test_database_check_reports_bounded_counts_without_scanning(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database = tmp_path / "monitoring data.db"
    make_database(database)

    def unexpected_scan(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("database check must not run a scan")

    monkeypatch.setattr(lotuswatch.monitoring, "execute_scan", unexpected_scan)
    result = runner.invoke(
        app,
        ["monitor", "database", "check", "--database", str(database)],
    )
    output = plain_output(result)

    assert result.exit_code == 0
    assert "database check passed" in output
    assert "Schema version: 1" in output
    assert "Targets inspected: 1" in output
    assert "Runs inspected: 0" in output
    assert "example.com" not in output


def test_database_check_missing_source_does_not_create_it(tmp_path: Path) -> None:
    database = tmp_path / "missing.db"

    result = runner.invoke(
        app,
        ["monitor", "database", "check", "--database", str(database)],
    )

    assert result.exit_code == 2
    assert "does not exist" in plain_output(result)
    assert not database.exists()


def test_database_backup_creates_valid_non_overwriting_copy(tmp_path: Path) -> None:
    database = tmp_path / "dữ liệu nguồn.db"
    destination = tmp_path / "bản sao.db"
    make_database(database)

    result = runner.invoke(
        app,
        [
            "monitor",
            "database",
            "backup",
            str(destination),
            "--database",
            str(database),
        ],
    )
    output = plain_output(result)

    assert result.exit_code == 0
    assert "database backup completed" in output
    assert "Targets inspected: 1" in output
    assert "not encrypted" in output
    assert "authenticated, or signed" in output
    assert SQLiteMonitoringStore(destination).check_database().targets_inspected == 1


def test_database_backup_refuses_existing_destination_without_modification(
    tmp_path: Path,
) -> None:
    database = tmp_path / "source.db"
    destination = tmp_path / "existing.db"
    make_database(database)
    destination.write_bytes(b"existing-sensitive-content")

    result = runner.invoke(
        app,
        [
            "monitor",
            "database",
            "backup",
            str(destination),
            "--database",
            str(database),
        ],
    )

    assert result.exit_code == 2
    assert "already exists" in plain_output(result)
    assert "existing-sensitive-content" not in plain_output(result)
    assert destination.read_bytes() == b"existing-sensitive-content"


def test_database_errors_do_not_expose_stored_values(tmp_path: Path) -> None:
    database = tmp_path / "monitoring.db"
    make_database(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE monitored_targets SET name = ?",
            ("private-profile-value",),
        )
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE monitored_targets SET enabled = 2")

    result = runner.invoke(
        app,
        ["monitor", "database", "check", "--database", str(database)],
    )
    output = plain_output(result)

    assert result.exit_code == 2
    assert "private-profile-value" not in output
    assert "Traceback" not in output
