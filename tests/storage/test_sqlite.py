import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from types import MethodType
from uuid import uuid4

import pytest

from lotuswatch.exceptions import (
    StoreCompatibilityError,
    StoreConflictError,
    StoredReportTooLargeError,
    StoreInitializationError,
    StoreReadError,
    StoreValidationError,
)
from lotuswatch.models import ScanReport
from lotuswatch.storage import (
    MAX_STORED_REPORT_SIZE_BYTES,
    MONITORING_SCHEMA_VERSION,
    MonitoredTarget,
    SQLiteMonitoringStore,
    StoredScanRun,
)


def make_target() -> MonitoredTarget:
    return MonitoredTarget.create(
        name="production",
        original_target="example.com",
        normalized_url="https://example.com/",
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )


def make_report(
    *,
    scanned_at: datetime | None = None,
    check_value: str = "passed",
) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.4",
        original_target="example.com",
        normalized_url="https://example.com/",
        scanned_at=scanned_at or datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
        checks=[{"name": "synthetic", "value": check_value}],
        findings=[],
    )


def initialized_store(tmp_path: Path) -> SQLiteMonitoringStore:
    store = SQLiteMonitoringStore(tmp_path / "monitoring.db")
    store.initialize()
    return store


def test_schema_v1_initialization_is_idempotent(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        version = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = ?",
            ("schema_version",),
        ).fetchone()
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            ).fetchall()
        }
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(scan_runs)"
        ).fetchall()

    assert version == (MONITORING_SCHEMA_VERSION,)
    assert {"schema_metadata", "monitored_targets", "scan_runs"}.issubset(tables)
    assert any(row[2] == "monitored_targets" for row in foreign_keys)


def test_initialization_creates_missing_parent_directory(tmp_path: Path) -> None:
    database_path = tmp_path / "nested" / "data" / "monitoring.db"

    SQLiteMonitoringStore(database_path).initialize()

    assert database_path.is_file()


def test_non_database_and_empty_existing_files_are_not_replaced(
    tmp_path: Path,
) -> None:
    non_database = tmp_path / "not-a-database.db"
    non_database.write_text("private existing content", encoding="utf-8")
    empty_file = tmp_path / "empty.db"
    empty_file.touch()

    with pytest.raises(StoreCompatibilityError) as non_database_error:
        SQLiteMonitoringStore(non_database).initialize()
    with pytest.raises(StoreCompatibilityError):
        SQLiteMonitoringStore(empty_file).initialize()

    assert "private existing content" not in str(non_database_error.value)
    assert non_database.read_text(encoding="utf-8") == "private existing content"


def test_symbolic_link_database_path_is_rejected(tmp_path: Path) -> None:
    real_database = tmp_path / "real.db"
    SQLiteMonitoringStore(real_database).initialize()
    link = tmp_path / "link.db"
    try:
        os.symlink(real_database, link)
    except OSError:
        pytest.skip("Symbolic links are unavailable in this environment.")

    with pytest.raises(StoreInitializationError):
        SQLiteMonitoringStore(link).initialize()


def test_unrelated_and_unsupported_sqlite_schemas_are_rejected(
    tmp_path: Path,
) -> None:
    unrelated = tmp_path / "unrelated.db"
    with sqlite3.connect(unrelated) as connection:
        connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")

    unsupported = tmp_path / "unsupported.db"
    with sqlite3.connect(unsupported) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_metadata (key, value) VALUES (?, ?)",
            ("schema_version", "999"),
        )

    with pytest.raises(StoreCompatibilityError):
        SQLiteMonitoringStore(unrelated).initialize()
    with pytest.raises(StoreCompatibilityError):
        SQLiteMonitoringStore(unsupported).initialize()


def test_schema_creation_rolls_back_atomically(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteMonitoringStore(tmp_path / "monitoring.db")

    def fail_after_partial_schema(self, connection: sqlite3.Connection) -> None:
        connection.execute("CREATE TABLE partial_schema (id TEXT PRIMARY KEY)")
        raise sqlite3.OperationalError("private migration diagnostic")

    monkeypatch.setattr(
        store,
        "_create_schema_v1",
        MethodType(fail_after_partial_schema, store),
    )

    with pytest.raises(StoreInitializationError) as error:
        store.initialize()

    with sqlite3.connect(store.database_path) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_schema WHERE type = 'table'"
        ).fetchall()

    assert "private migration diagnostic" not in str(error.value)
    assert tables == []


def test_reports_are_stored_as_bounded_canonical_json(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    target = store.create_target(make_target())
    run = StoredScanRun.create(target_id=target.id, report=make_report())
    store.save_scan_run(run)

    with sqlite3.connect(store.database_path) as connection:
        payload, recorded_size = connection.execute(
            "SELECT report_json, report_size_bytes FROM scan_runs WHERE id = ?",
            (str(run.metadata.id),),
        ).fetchone()

    expected = json.dumps(
        run.report.model_dump(mode="json"),
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    assert payload == expected
    assert recorded_size == len(payload.encode("utf-8"))


def test_oversized_report_is_rejected_before_database_write(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    target = store.create_target(make_target())
    report = make_report(check_value="x" * MAX_STORED_REPORT_SIZE_BYTES)
    run = StoredScanRun.create(target_id=target.id, report=report)

    with pytest.raises(StoredReportTooLargeError):
        store.save_scan_run(run)

    assert store.list_scan_runs(target.id) == []


def test_corrupted_report_json_and_metadata_fail_without_content_leak(
    tmp_path: Path,
) -> None:
    store = initialized_store(tmp_path)
    target = store.create_target(make_target())
    run = StoredScanRun.create(target_id=target.id, report=make_report())
    store.save_scan_run(run)
    corrupted = '{"schema_version":"1.0","secret":"do-not-leak"}'

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            UPDATE scan_runs
            SET report_json = ?, report_size_bytes = ?
            WHERE id = ?
            """,
            (
                corrupted,
                len(corrupted.encode("utf-8")),
                str(run.metadata.id),
            ),
        )

    with pytest.raises(StoreReadError) as error:
        store.get_scan_run(run.metadata.id)

    assert "do-not-leak" not in str(error.value)


def test_inconsistent_stored_metadata_is_rejected(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    target = store.create_target(make_target())
    run = StoredScanRun.create(target_id=target.id, report=make_report())
    store.save_scan_run(run)

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE scan_runs SET lotuswatch_version = ? WHERE id = ?",
            ("different-version", str(run.metadata.id)),
        )

    with pytest.raises(StoreReadError):
        store.get_scan_run(run.metadata.id)


def test_failed_insert_transaction_leaves_no_partial_run(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    target = store.create_target(make_target())
    run = StoredScanRun.create(target_id=target.id, report=make_report())

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_scan_run
            AFTER INSERT ON scan_runs
            BEGIN
                SELECT RAISE(ABORT, 'private trigger diagnostic');
            END
            """
        )

    with pytest.raises(StoreConflictError) as error:
        store.save_scan_run(run)

    with sqlite3.connect(store.database_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM scan_runs").fetchone()[0]

    assert "private trigger diagnostic" not in str(error.value)
    assert count == 0


def test_bypass_constructed_invalid_models_are_revalidated(tmp_path: Path) -> None:
    store = initialized_store(tmp_path)
    invalid_target = MonitoredTarget.model_construct(
        id=uuid4(),
        name="",
        original_target="example.com",
        normalized_url="https://example.com/",
        enabled=True,
        created_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
        updated_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
    )

    with pytest.raises(StoreValidationError):
        store.create_target(invalid_target)


@pytest.mark.parametrize("timeout", [0, -1, 61])
def test_invalid_busy_timeout_is_rejected(tmp_path: Path, timeout: float) -> None:
    with pytest.raises(StoreValidationError):
        SQLiteMonitoringStore(
            tmp_path / "monitoring.db",
            busy_timeout_seconds=timeout,
        )
