import os
import sqlite3
import stat
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

import lotuswatch.storage.sqlite as sqlite_storage
from lotuswatch.exceptions import (
    MonitoringStoreError,
    StoreBackupAlreadyExistsError,
    StoreBackupDestinationError,
    StoreBackupError,
    StoreCompatibilityError,
    StoreInitializationError,
    StoreIntegrityError,
    StoreReadError,
)
from lotuswatch.models import ScanReport
from lotuswatch.storage import (
    MONITORING_SCHEMA_VERSION,
    MonitoredTarget,
    SQLiteMonitoringStore,
    StoredScanRun,
)


def populated_store(root: Path) -> tuple[SQLiteMonitoringStore, MonitoredTarget]:
    store = SQLiteMonitoringStore(root / "monitoring database.db")
    store.initialize()
    target = store.create_target(
        MonitoredTarget.create(
            name="production",
            original_target="example.com",
            normalized_url="https://example.com/",
            created_at=datetime(2026, 8, 21, 8, 0, tzinfo=UTC),
        )
    )
    report = ScanReport.create(
        lotuswatch_version="0.1.0-alpha.6",
        original_target="example.com",
        normalized_url="https://example.com/",
        scanned_at=datetime(2026, 8, 21, 9, 0, tzinfo=UTC),
        checks=[{"name": "synthetic", "status": "passed"}],
        findings=[],
    )
    store.save_scan_run(StoredScanRun.create(target_id=target.id, report=report))
    return store, target


def test_check_database_validates_physical_and_logical_contents(
    tmp_path: Path,
) -> None:
    store, _target = populated_store(tmp_path)
    before = store.database_path.read_bytes()

    result = store.check_database()

    assert result.schema_version == MONITORING_SCHEMA_VERSION
    assert result.targets_inspected == 1
    assert result.runs_inspected == 1
    assert store.database_path.read_bytes() == before


def test_check_requires_an_existing_regular_database(tmp_path: Path) -> None:
    missing = tmp_path / "missing.db"
    directory = tmp_path / "directory.db"
    directory.mkdir()

    with pytest.raises(StoreInitializationError):
        SQLiteMonitoringStore(missing).check_database()
    with pytest.raises(StoreInitializationError):
        SQLiteMonitoringStore(directory).check_database()

    assert not missing.exists()


def test_check_rejects_corrupt_physical_database_without_diagnostic_leak(
    tmp_path: Path,
) -> None:
    store, _target = populated_store(tmp_path)
    data = store.database_path.read_bytes()
    store.database_path.write_bytes(data[:200])

    with pytest.raises(MonitoringStoreError) as error:
        store.check_database()

    assert "malformed" not in str(error.value).casefold()


def test_check_rejects_missing_or_invalid_schema_columns(tmp_path: Path) -> None:
    store, _target = populated_store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "ALTER TABLE scan_runs RENAME COLUMN report_size_bytes TO hidden_value"
        )

    with pytest.raises(StoreCompatibilityError) as error:
        store.check_database()

    assert "hidden_value" not in str(error.value)


def test_check_rejects_unsupported_schema_version(tmp_path: Path) -> None:
    store, _target = populated_store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE schema_metadata SET value = ? WHERE key = ?",
            ("999-private", "schema_version"),
        )

    with pytest.raises(StoreCompatibilityError) as error:
        store.check_database()

    assert "999-private" not in str(error.value)


def test_check_rejects_foreign_key_violations(tmp_path: Path) -> None:
    store, _target = populated_store(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE scan_runs SET target_id = ?",
            (str(uuid4()),),
        )

    with pytest.raises(StoreIntegrityError):
        store.check_database()


def test_check_revalidates_target_state_and_stored_report(tmp_path: Path) -> None:
    target_store, _target = populated_store(tmp_path / "target")
    with sqlite3.connect(target_store.database_path) as connection:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute("UPDATE monitored_targets SET enabled = 2")

    with pytest.raises(StoreReadError):
        target_store.check_database()

    report_store, _target = populated_store(tmp_path / "report")
    private_payload = '{"schema_version":"1.0","private":"do-not-leak"}'
    with sqlite3.connect(report_store.database_path) as connection:
        connection.execute(
            "UPDATE scan_runs SET report_json = ?, report_size_bytes = ?",
            (private_payload, len(private_payload.encode("utf-8"))),
        )

    with pytest.raises(StoreReadError) as error:
        report_store.check_database()
    assert "do-not-leak" not in str(error.value)


def test_check_applies_bounded_logical_row_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _target = populated_store(tmp_path)
    monkeypatch.setattr(sqlite_storage, "MAX_DATABASE_CHECK_TARGETS", 0)

    with pytest.raises(StoreIntegrityError, match="bounded inspection limit"):
        store.check_database()


def test_backup_round_trip_is_valid_and_source_is_unchanged(tmp_path: Path) -> None:
    source_root = tmp_path / "nguồn dữ liệu"
    source_root.mkdir()
    store, target = populated_store(source_root)
    before = store.database_path.read_bytes()
    destination = tmp_path / "bản sao an toàn.db"

    result = store.backup_database(destination)

    assert result.destination == destination.resolve()
    assert result.validation.targets_inspected == 1
    assert result.validation.runs_inspected == 1
    assert store.database_path.read_bytes() == before
    backup_store = SQLiteMonitoringStore(destination)
    assert backup_store.check_database() == result.validation
    assert backup_store.get_target(target.id) == target
    assert len(backup_store.list_scan_runs(target.id)) == 1


@pytest.mark.parametrize("destination", ["", "\x00invalid.db"])
def test_backup_rejects_empty_or_invalid_destination_paths(
    tmp_path: Path,
    destination: str,
) -> None:
    store, _target = populated_store(tmp_path)

    with pytest.raises(StoreBackupDestinationError):
        store.backup_database(destination)


@pytest.mark.parametrize("destination_kind", ["file", "directory"])
def test_backup_never_replaces_existing_entries(
    tmp_path: Path,
    destination_kind: str,
) -> None:
    store, _target = populated_store(tmp_path / "source")
    destination = tmp_path / "existing.db"
    if destination_kind == "file":
        destination.write_bytes(b"existing-private-content")
    else:
        destination.mkdir()

    with pytest.raises(StoreBackupAlreadyExistsError):
        store.backup_database(destination)

    if destination_kind == "file":
        assert destination.read_bytes() == b"existing-private-content"
    else:
        assert destination.is_dir()


def test_backup_rejects_source_and_hard_link_aliases(tmp_path: Path) -> None:
    store, _target = populated_store(tmp_path)

    with pytest.raises(StoreBackupDestinationError):
        store.backup_database(store.database_path)

    alias = tmp_path / "source-alias.db"
    try:
        os.link(store.database_path, alias)
    except OSError:
        pytest.skip("Hard links are unavailable in this environment.")
    with pytest.raises(StoreBackupDestinationError):
        store.backup_database(alias)


def test_backup_rejects_symbolic_link_destination_and_parent(tmp_path: Path) -> None:
    store, _target = populated_store(tmp_path / "source")
    real_file = tmp_path / "real.db"
    real_file.write_bytes(b"existing")
    destination_link = tmp_path / "destination-link.db"
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    parent_link = tmp_path / "parent-link"
    try:
        os.symlink(real_file, destination_link)
        os.symlink(real_parent, parent_link, target_is_directory=True)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this environment.")

    with pytest.raises(StoreBackupAlreadyExistsError):
        store.backup_database(destination_link)
    with pytest.raises(StoreBackupDestinationError):
        store.backup_database(parent_link / "backup.db")


def test_failed_copy_removes_only_owned_temporary_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _target = populated_store(tmp_path)
    destination = tmp_path / "backup.db"
    unrelated = tmp_path / ".backup.db.unrelated.tmp"
    unrelated.write_bytes(b"preserve")

    def fail_copy(temporary: Path) -> None:
        temporary.write_bytes(b"incomplete-private-backup")
        raise StoreBackupError("Synthetic controlled backup failure.")

    monkeypatch.setattr(store, "_copy_database_online", fail_copy)

    with pytest.raises(StoreBackupError):
        store.backup_database(destination)

    assert not destination.exists()
    assert unrelated.read_bytes() == b"preserve"
    assert list(tmp_path.glob(".backup.db.lotuswatch-*.tmp")) == []


def test_corrupt_completed_copy_is_rejected_before_finalization(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _target = populated_store(tmp_path)
    destination = tmp_path / "backup.db"
    original_copy = store._copy_database_online

    def copy_then_corrupt(temporary: Path) -> None:
        original_copy(temporary)
        with closing(sqlite3.connect(temporary)) as connection:
            connection.execute(
                "UPDATE scan_runs SET report_size_bytes = report_size_bytes + 1"
            )
            connection.commit()

    monkeypatch.setattr(store, "_copy_database_online", copy_then_corrupt)

    with pytest.raises(StoreReadError):
        store.backup_database(destination)

    assert not destination.exists()
    assert list(tmp_path.glob(".backup.db.lotuswatch-*.tmp")) == []


def test_destination_race_does_not_replace_competing_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _target = populated_store(tmp_path)
    destination = tmp_path / "backup.db"

    def competing_link(_source: Path, selected_destination: Path) -> None:
        Path(selected_destination).write_bytes(b"competitor-content")
        raise FileExistsError

    monkeypatch.setattr(sqlite_storage.os, "link", competing_link)

    with pytest.raises(StoreBackupAlreadyExistsError):
        store.backup_database(destination)

    assert destination.read_bytes() == b"competitor-content"
    assert list(tmp_path.glob(".backup.db.lotuswatch-*.tmp")) == []


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode bits are not portable")
def test_backup_uses_restrictive_permissions_where_supported(tmp_path: Path) -> None:
    store, _target = populated_store(tmp_path)
    destination = tmp_path / "backup.db"

    store.backup_database(destination)

    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
