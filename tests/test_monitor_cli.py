from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from rich.text import Text
from typer.testing import CliRunner, Result

import lotuswatch.cli
import lotuswatch.monitoring
import lotuswatch.monitoring_cli
from lotuswatch.cli import app
from lotuswatch.exceptions import StoreWriteError
from lotuswatch.models import ScanReport
from lotuswatch.storage import SQLiteMonitoringStore, StoredScanRun

runner = CliRunner()


def plain_output(result: Result) -> str:
    return Text.from_ansi(result.stdout + result.stderr).plain


def compact_output(result: Result) -> str:
    without_borders = "".join(
        " " if "\u2500" <= character <= "\u257f" else character
        for character in plain_output(result)
    )
    return " ".join(without_borders.split())


def database_arguments(database_path: Path) -> list[str]:
    return ["--database", str(database_path)]


def invoke_add(
    database_path: Path,
    name: str,
    target: str,
) -> Result:
    return runner.invoke(
        app,
        ["monitor", "add", name, target, *database_arguments(database_path)],
    )


def open_store(database_path: Path) -> SQLiteMonitoringStore:
    store = SQLiteMonitoringStore(database_path)
    store.initialize()
    return store


def make_report(*, scanned_at: datetime) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.4",
        original_target="example.com",
        normalized_url="https://example.com/",
        scanned_at=scanned_at,
        checks=[{"name": "synthetic", "status": "passed"}],
        findings=[],
    )


def test_monitor_help_lists_target_management_commands() -> None:
    result = runner.invoke(app, ["monitor", "--help"])
    output = compact_output(result)

    assert result.exit_code == 0
    assert "add" in output
    assert "list" in output
    assert "run" in output
    assert "enable" in output
    assert "disable" in output


def test_add_stores_canonical_target_without_running_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"

    def unexpected_scan(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("monitor add must not run a scan")

    monkeypatch.setattr(lotuswatch.cli, "execute_scan", unexpected_scan)

    result = invoke_add(
        database_path,
        "production",
        "EXAMPLE.COM/path?mode=test%27",
    )
    output = compact_output(result)

    assert result.exit_code == 0
    assert "Added monitoring target" in output
    assert "https://example.com/path?mode=test%27" in output
    assert "No scan was run" in output

    profiles = open_store(database_path).list_targets()
    assert len(profiles) == 1
    assert profiles[0].name == "production"
    assert profiles[0].original_target == "EXAMPLE.COM/path?mode=test%27"
    assert profiles[0].normalized_url == "https://example.com/path?mode=test%27"


@pytest.mark.parametrize(
    "name",
    ["bad name", ".hidden", "bad/name", "bad*name", "x" * 65],
)
def test_add_rejects_invalid_profile_names(
    tmp_path: Path,
    name: str,
) -> None:
    database_path = tmp_path / "monitoring.db"

    result = invoke_add(database_path, name, "example.com")
    output = plain_output(result)

    assert result.exit_code == 2
    assert "Profile name must contain 1 to 64" in output
    assert not database_path.exists()


@pytest.mark.parametrize(
    ("target", "expected_message"),
    [
        (
            "https://user:password@example.com",
            "embedded credentials are not allowed",
        ),
        ("ftp://example.com", "Only HTTP and HTTPS targets are supported"),
        ("not a target", "Target cannot contain whitespace"),
    ],
)
def test_add_rejects_invalid_or_secret_bearing_targets(
    tmp_path: Path,
    target: str,
    expected_message: str,
) -> None:
    database_path = tmp_path / "monitoring.db"

    result = invoke_add(database_path, "production", target)
    output = compact_output(result)

    assert result.exit_code == 2
    assert expected_message in output
    assert not database_path.exists()


def test_duplicate_name_and_canonical_target_preserve_original_profile(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "monitoring.db"
    first = invoke_add(database_path, "production", "example.com")

    duplicate_name = invoke_add(
        database_path,
        "production",
        "another.example",
    )
    duplicate_target = invoke_add(
        database_path,
        "staging",
        "https://EXAMPLE.com/",
    )

    assert first.exit_code == 0
    assert duplicate_name.exit_code == 2
    assert duplicate_target.exit_code == 2
    assert "already exists" in plain_output(duplicate_name)
    assert "already exists" in plain_output(duplicate_target)

    profiles = open_store(database_path).list_targets()
    assert len(profiles) == 1
    assert profiles[0].name == "production"
    assert profiles[0].normalized_url == "https://example.com/"


def test_list_is_deterministic_bounded_and_displays_last_run(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "monitoring.db"
    assert invoke_add(database_path, "beta", "beta.example").exit_code == 0
    assert invoke_add(database_path, "Alpha", "alpha.example").exit_code == 0
    assert invoke_add(database_path, "alpha", "lower.example").exit_code == 0

    store = open_store(database_path)
    alpha = store.get_target_by_name("Alpha")
    assert alpha is not None
    scanned_at = datetime(2026, 8, 20, 10, 30, tzinfo=UTC)
    store.save_scan_run(
        StoredScanRun.create(
            target_id=alpha.id,
            report=make_report(scanned_at=scanned_at),
        )
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "list",
            *database_arguments(database_path),
            "--limit",
            "2",
        ],
        terminal_width=180,
    )
    output = plain_output(result)

    assert result.exit_code == 0
    assert output.index("Alpha") < output.index("alpha")
    assert "beta" not in output
    assert "https://alpha.example/" in output
    assert "2026-08-20T10:30:00Z" in output
    assert "Never" in output


def test_list_empty_database_is_concise(tmp_path: Path) -> None:
    database_path = tmp_path / "monitoring.db"

    result = runner.invoke(
        app,
        ["monitor", "list", *database_arguments(database_path)],
    )

    assert result.exit_code == 0
    assert "No monitoring targets registered" in plain_output(result)


def test_disable_and_enable_preserve_scan_history(tmp_path: Path) -> None:
    database_path = tmp_path / "monitoring.db"
    assert invoke_add(database_path, "production", "example.com").exit_code == 0
    store = open_store(database_path)
    profile = store.get_target_by_name("production")
    assert profile is not None
    run = StoredScanRun.create(
        target_id=profile.id,
        report=make_report(
            scanned_at=datetime(2026, 8, 20, 11, 0, tzinfo=UTC),
        ),
    )
    store.save_scan_run(run)

    disabled = runner.invoke(
        app,
        ["monitor", "disable", "production", *database_arguments(database_path)],
    )
    disabled_profile = open_store(database_path).get_target_by_name("production")
    enabled = runner.invoke(
        app,
        ["monitor", "enable", "production", *database_arguments(database_path)],
    )
    final_store = open_store(database_path)
    enabled_profile = final_store.get_target_by_name("production")

    assert disabled.exit_code == 0
    assert "history was preserved" in plain_output(disabled)
    assert disabled_profile is not None and disabled_profile.enabled is False
    assert enabled.exit_code == 0
    assert enabled_profile is not None and enabled_profile.enabled is True
    assert final_store.get_scan_run(run.metadata.id) == run


def test_enable_missing_profile_returns_controlled_error(tmp_path: Path) -> None:
    database_path = tmp_path / "monitoring.db"

    result = runner.invoke(
        app,
        ["monitor", "enable", "missing", *database_arguments(database_path)],
    )
    output = plain_output(result)

    assert result.exit_code == 2
    assert "profile was not found" in output
    assert "Traceback" not in output


def test_incompatible_database_error_does_not_leak_contents(tmp_path: Path) -> None:
    database_path = tmp_path / "monitoring.db"
    database_path.write_text("private-database-content", encoding="utf-8")

    result = runner.invoke(
        app,
        ["monitor", "list", *database_arguments(database_path)],
    )
    output = compact_output(result)

    assert result.exit_code == 2
    assert "not a supported SQLite database" in output
    assert "private-database-content" not in output
    assert "Traceback" not in output


def test_monitor_run_missing_or_disabled_profile_never_scans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"

    def unexpected_scan(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("missing or disabled profiles must not be scanned")

    monkeypatch.setattr(lotuswatch.monitoring, "execute_scan", unexpected_scan)

    missing = runner.invoke(
        app,
        ["monitor", "run", "missing", *database_arguments(database_path)],
    )
    assert invoke_add(database_path, "production", "example.com").exit_code == 0
    disabled = runner.invoke(
        app,
        ["monitor", "disable", "production", *database_arguments(database_path)],
    )
    disabled_run = runner.invoke(
        app,
        ["monitor", "run", "production", *database_arguments(database_path)],
    )

    assert missing.exit_code == 2
    assert "profile was not found" in compact_output(missing)
    assert disabled.exit_code == 0
    assert disabled_run.exit_code == 2
    assert "profile is disabled" in compact_output(disabled_run)


def test_monitor_run_renders_initial_baseline(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    run_id = uuid4()
    synthetic_result = SimpleNamespace(
        profile=SimpleNamespace(
            name="production",
            normalized_url="https://example.com/",
        ),
        scan=SimpleNamespace(
            completed_checks=4,
            recorded_checks=5,
            findings=[object(), object()],
        ),
        stored_run=SimpleNamespace(metadata=SimpleNamespace(id=run_id)),
        baseline_run=None,
        comparison=None,
        skipped_baseline_candidates=0,
    )
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: synthetic_result,
    )

    result = runner.invoke(
        app,
        ["monitor", "run", "production", *database_arguments(database_path)],
    )
    output = compact_output(result)

    assert result.exit_code == 0
    assert "monitoring run stored" in output
    assert str(run_id) in output
    assert "Scan status: INCOMPLETE (4/5 checks completed)" in output
    assert "Findings: 2" in output
    assert "Initial baseline" in output
    assert "no comparison is available yet" in output


def test_monitor_run_renders_previous_run_comparison(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    baseline_id = uuid4()
    synthetic_result = SimpleNamespace(
        profile=SimpleNamespace(
            name="production",
            normalized_url="https://example.com/",
        ),
        scan=SimpleNamespace(
            completed_checks=5,
            recorded_checks=5,
            findings=[object()] * 4,
        ),
        stored_run=SimpleNamespace(metadata=SimpleNamespace(id=uuid4())),
        baseline_run=SimpleNamespace(metadata=SimpleNamespace(id=baseline_id)),
        comparison=SimpleNamespace(
            summary=SimpleNamespace(
                added=1,
                resolved=1,
                changed=1,
                unchanged=1,
            )
        ),
        skipped_baseline_candidates=2,
    )
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: synthetic_result,
    )

    result = runner.invoke(
        app,
        ["monitor", "run", "production", *database_arguments(database_path)],
    )
    output = compact_output(result)

    assert result.exit_code == 0
    assert "Scan status: COMPLETE" in output
    assert "Skipped earlier incompatible or non-earlier run candidates: 2" in output
    assert "Comparison with previous run" in output
    assert f"Baseline run ID: {baseline_id}" in output
    assert "Added: 1" in output
    assert "Resolved: 1" in output
    assert "Changed: 1" in output
    assert "Unchanged: 1" in output


def test_monitor_run_storage_failure_is_controlled(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"

    def fail_storage(*_args: object, **_kwargs: object) -> None:
        raise StoreWriteError("Unable to store monitoring run.")

    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        fail_storage,
    )

    result = runner.invoke(
        app,
        ["monitor", "run", "production", *database_arguments(database_path)],
    )
    output = compact_output(result)

    assert result.exit_code == 2
    assert "Unable to store monitoring run" in output
    assert "Traceback" not in output
