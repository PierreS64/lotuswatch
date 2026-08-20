import json
import os
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from stat import S_ISREG
from uuid import UUID

from pydantic import ValidationError

from lotuswatch.exceptions import (
    MonitoringStoreError,
    StoreCompatibilityError,
    StoreConflictError,
    StoredReportTooLargeError,
    StoreInitializationError,
    StoreReadError,
    StoreValidationError,
    StoreWriteError,
)
from lotuswatch.models import ScanReport
from lotuswatch.storage.base import (
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    MonitoredTarget,
    ScanRunMetadata,
    StoredScanRun,
)
from lotuswatch.storage.paths import resolve_monitoring_database_path

MONITORING_SCHEMA_VERSION = "1"
MAX_STORED_REPORT_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_BUSY_TIMEOUT_SECONDS = 5.0
MAX_DELETE_BATCH_SIZE = 400
_SQLITE_HEADER = b"SQLite format 3\x00"
_REQUIRED_TABLE_COLUMNS = {
    "schema_metadata": {"key", "value"},
    "monitored_targets": {
        "id",
        "name",
        "original_target",
        "normalized_url",
        "enabled",
        "created_at",
        "updated_at",
    },
    "scan_runs": {
        "id",
        "target_id",
        "report_schema_version",
        "lotuswatch_version",
        "scanned_at",
        "stored_at",
        "report_json",
        "report_size_bytes",
    },
}


class SQLiteMonitoringStore:
    """Versioned SQLite implementation of the monitoring storage contract."""

    def __init__(
        self,
        database_path: str | os.PathLike[str] | None = None,
        *,
        busy_timeout_seconds: float = DEFAULT_BUSY_TIMEOUT_SECONDS,
    ) -> None:
        if not 0 < busy_timeout_seconds <= 60:
            raise StoreValidationError(
                "SQLite busy timeout must be greater than zero and at most 60 seconds."
            )

        self.database_path = resolve_monitoring_database_path(database_path)
        self.busy_timeout_seconds = busy_timeout_seconds

    def initialize(self) -> None:
        """Create schema version 1 or validate an existing database."""

        created = self._prepare_database_file()

        try:
            with self._connection() as connection, self._transaction(connection):
                tables = self._user_table_names(connection)
                if not tables:
                    self._create_schema_v1(connection)
                else:
                    self._validate_schema_v1(connection, tables)
        except MonitoringStoreError:
            raise
        except sqlite3.DatabaseError as exc:
            raise StoreInitializationError(
                f"Unable to initialize monitoring database: {self.database_path}"
            ) from exc

        if created:
            self._restrict_new_database_permissions()

    def create_target(self, target: MonitoredTarget) -> MonitoredTarget:
        """Persist one validated monitoring target."""

        target = self._validated_target(target)
        data = target.model_dump(mode="json")

        try:
            with self._connection() as connection, self._transaction(connection):
                connection.execute(
                    """
                        INSERT INTO monitored_targets (
                            id, name, original_target, normalized_url, enabled,
                            created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                    (
                        data["id"],
                        data["name"],
                        data["original_target"],
                        data["normalized_url"],
                        int(data["enabled"]),
                        data["created_at"],
                        data["updated_at"],
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Monitoring target identifier, name, or canonical URL already exists."
            ) from exc
        except sqlite3.DatabaseError as exc:
            raise StoreWriteError("Unable to store monitoring target.") from exc

        return target.model_copy(deep=True)

    def get_target(self, target_id: UUID) -> MonitoredTarget | None:
        """Load one target by identifier."""

        return self._get_target_by_column("id", str(target_id))

    def get_target_by_name(self, name: str) -> MonitoredTarget | None:
        """Load one target by exact profile name."""

        if not isinstance(name, str) or not name:
            raise StoreValidationError("Monitoring target name must not be empty.")
        return self._get_target_by_column("name", name)

    def list_targets(
        self,
        *,
        limit: int = DEFAULT_QUERY_LIMIT,
    ) -> list[MonitoredTarget]:
        """List targets in deterministic case-sensitive name order."""

        limit = self._validated_limit(limit)
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    """
                    SELECT id, name, original_target, normalized_url, enabled,
                           created_at, updated_at
                    FROM monitored_targets
                    ORDER BY name COLLATE BINARY ASC, id ASC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise StoreReadError("Unable to list monitoring targets.") from exc

        return [self._target_from_row(row) for row in rows]

    def set_target_enabled(
        self,
        target_id: UUID,
        *,
        enabled: bool,
        updated_at: datetime | None = None,
    ) -> MonitoredTarget | None:
        """Update target state while preserving its scan runs."""

        if not isinstance(enabled, bool):
            raise StoreValidationError("Monitoring target state must be boolean.")
        timestamp = updated_at or datetime.now(UTC)

        try:
            with self._connection() as connection, self._transaction(connection):
                row = connection.execute(
                    """
                        SELECT id, name, original_target, normalized_url, enabled,
                               created_at, updated_at
                        FROM monitored_targets
                        WHERE id = ?
                        """,
                    (str(target_id),),
                ).fetchone()
                if row is None:
                    return None

                current = self._target_from_row(row)
                updated = MonitoredTarget.model_validate(
                    {
                        **current.model_dump(mode="python"),
                        "enabled": enabled,
                        "updated_at": timestamp,
                    }
                )
                updated_data = updated.model_dump(mode="json")
                connection.execute(
                    """
                        UPDATE monitored_targets
                        SET enabled = ?, updated_at = ?
                        WHERE id = ?
                        """,
                    (
                        int(updated_data["enabled"]),
                        updated_data["updated_at"],
                        str(target_id),
                    ),
                )
        except ValidationError as exc:
            raise StoreValidationError(
                "Monitoring target update timestamp is invalid."
            ) from exc
        except sqlite3.DatabaseError as exc:
            raise StoreWriteError("Unable to update monitoring target.") from exc

        return updated.model_copy(deep=True)

    def save_scan_run(self, run: StoredScanRun) -> StoredScanRun:
        """Persist one complete validated scan run in a transaction."""

        run = self._validated_run(run)
        report_json, report_size = self._serialize_report(run.report)
        metadata = run.metadata.model_dump(mode="json")

        try:
            with self._connection() as connection, self._transaction(connection):
                connection.execute(
                    """
                        INSERT INTO scan_runs (
                            id, target_id, report_schema_version,
                            lotuswatch_version, scanned_at, stored_at,
                            report_json, report_size_bytes
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                    (
                        metadata["id"],
                        metadata["target_id"],
                        metadata["report_schema_version"],
                        metadata["lotuswatch_version"],
                        metadata["scanned_at"],
                        metadata["stored_at"],
                        report_json,
                        report_size,
                    ),
                )
        except sqlite3.IntegrityError as exc:
            raise StoreConflictError(
                "Scan run identifier conflicts or its monitoring target is missing."
            ) from exc
        except sqlite3.DatabaseError as exc:
            raise StoreWriteError("Unable to store scan run.") from exc

        return run.model_copy(deep=True)

    def get_scan_run(self, run_id: UUID) -> StoredScanRun | None:
        """Load and revalidate one complete stored scan run."""

        try:
            with self._connection() as connection:
                row = connection.execute(
                    self._scan_run_select_sql("WHERE id = ?"),
                    (str(run_id),),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise StoreReadError("Unable to load scan run.") from exc

        return None if row is None else self._stored_run_from_row(row)

    def list_scan_runs(
        self,
        target_id: UUID,
        *,
        limit: int = DEFAULT_QUERY_LIMIT,
    ) -> list[ScanRunMetadata]:
        """List bounded scan metadata in newest-first order."""

        limit = self._validated_limit(limit)
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    """
                    SELECT id, target_id, report_schema_version,
                           lotuswatch_version, scanned_at, stored_at
                    FROM scan_runs
                    WHERE target_id = ?
                    ORDER BY scanned_at DESC, stored_at DESC, id ASC
                    LIMIT ?
                    """,
                    (str(target_id), limit),
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise StoreReadError("Unable to list scan runs.") from exc

        return [self._metadata_from_row(row) for row in rows]

    def get_latest_scan_run(self, target_id: UUID) -> StoredScanRun | None:
        """Load the newest complete run for one target."""

        try:
            with self._connection() as connection:
                row = connection.execute(
                    self._scan_run_select_sql(
                        """
                        WHERE target_id = ?
                        ORDER BY scanned_at DESC, stored_at DESC, id ASC
                        LIMIT 1
                        """
                    ),
                    (str(target_id),),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise StoreReadError("Unable to load latest scan run.") from exc

        return None if row is None else self._stored_run_from_row(row)

    def count_scan_runs(self, target_id: UUID) -> int:
        """Count stored runs for one target."""

        try:
            with self._connection() as connection:
                row = connection.execute(
                    "SELECT COUNT(*) AS run_count FROM scan_runs WHERE target_id = ?",
                    (str(target_id),),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise StoreReadError("Unable to count scan history.") from exc

        if row is None or not isinstance(row["run_count"], int):
            raise StoreReadError("Stored scan history count is invalid.")
        return int(row["run_count"])

    def preview_scan_run_prune(
        self,
        target_id: UUID,
        *,
        keep: int,
    ) -> list[UUID]:
        """Return runs outside the newest retained set without deleting them."""

        keep = self._validated_keep_count(keep)
        try:
            with self._connection() as connection:
                rows = connection.execute(
                    """
                    SELECT id
                    FROM scan_runs
                    WHERE target_id = ?
                    ORDER BY scanned_at DESC, stored_at DESC, id ASC
                    LIMIT -1 OFFSET ?
                    """,
                    (str(target_id), keep),
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise StoreReadError("Unable to preview scan history retention.") from exc

        try:
            return [UUID(str(row["id"])) for row in rows]
        except (TypeError, ValueError) as exc:
            raise StoreReadError("Stored scan-run identifier is invalid.") from exc

    def delete_scan_runs(
        self,
        target_id: UUID,
        run_ids: Sequence[UUID],
        *,
        expected_total: int | None = None,
    ) -> int:
        """Delete exactly selected target runs in one guarded transaction."""

        selected_ids = self._validated_run_ids(run_ids)
        if expected_total is not None:
            expected_total = self._validated_history_total(expected_total)
        if not selected_ids:
            return 0

        try:
            with self._connection() as connection, self._transaction(connection):
                rows = connection.execute(
                    "SELECT id FROM scan_runs WHERE target_id = ?",
                    (str(target_id),),
                ).fetchall()
                existing_ids = {str(row["id"]) for row in rows}
                selected_values = {str(run_id) for run_id in selected_ids}

                if expected_total is not None and len(existing_ids) != expected_total:
                    raise StoreConflictError(
                        "Scan history changed after the retention preview."
                    )
                if not selected_values.issubset(existing_ids):
                    raise StoreConflictError(
                        "Scan history changed after the retention preview."
                    )
                if len(existing_ids) - len(selected_values) < 1:
                    raise StoreValidationError(
                        "Retention must preserve at least one scan run."
                    )

                deleted = 0
                for offset in range(0, len(selected_ids), MAX_DELETE_BATCH_SIZE):
                    batch = selected_ids[offset : offset + MAX_DELETE_BATCH_SIZE]
                    placeholders = ",".join("?" for _ in batch)
                    cursor = connection.execute(
                        f"""
                        DELETE FROM scan_runs
                        WHERE target_id = ? AND id IN ({placeholders})
                        """,
                        (str(target_id), *(str(run_id) for run_id in batch)),
                    )
                    deleted += cursor.rowcount

                if deleted != len(selected_ids):
                    raise StoreConflictError(
                        "Scan history changed while retention was applied."
                    )
        except (StoreConflictError, StoreValidationError):
            raise
        except sqlite3.DatabaseError as exc:
            raise StoreWriteError("Unable to prune scan history.") from exc

        return deleted

    def _prepare_database_file(self) -> bool:
        path = self.database_path

        if path.is_symlink():
            raise StoreInitializationError(
                f"Monitoring database path must not be a symbolic link: {path}"
            )

        try:
            file_stat = path.stat()
        except FileNotFoundError:
            return self._create_empty_database_file()
        except OSError as exc:
            raise StoreInitializationError(
                f"Unable to inspect monitoring database: {path}"
            ) from exc

        if not S_ISREG(file_stat.st_mode):
            raise StoreInitializationError(
                f"Monitoring database path is not a regular file: {path}"
            )
        if file_stat.st_size == 0:
            raise StoreCompatibilityError(
                f"Existing monitoring database file is empty: {path}"
            )

        try:
            with path.open("rb") as database_file:
                header = database_file.read(len(_SQLITE_HEADER))
        except OSError as exc:
            raise StoreInitializationError(
                f"Unable to read monitoring database header: {path}"
            ) from exc

        if header != _SQLITE_HEADER:
            raise StoreCompatibilityError(
                f"Existing file is not a supported SQLite database: {path}"
            )

        return False

    def _create_empty_database_file(self) -> bool:
        path = self.database_path
        parent = path.parent

        try:
            parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise StoreInitializationError(
                f"Unable to create monitoring data directory: {parent}"
            ) from exc

        if not parent.is_dir():
            raise StoreInitializationError(
                f"Monitoring database parent is not a directory: {parent}"
            )

        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise StoreInitializationError(
                f"Monitoring database path changed during creation: {path}"
            ) from exc
        except OSError as exc:
            raise StoreInitializationError(
                f"Unable to create monitoring database: {path}"
            ) from exc
        else:
            os.close(descriptor)

        return True

    def _restrict_new_database_permissions(self) -> None:
        try:
            self.database_path.chmod(0o600)
        except OSError:
            return

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        try:
            connection = sqlite3.connect(
                self.database_path,
                timeout=self.busy_timeout_seconds,
                isolation_level=None,
            )
        except sqlite3.Error as exc:
            raise StoreInitializationError(
                f"Unable to open monitoring database: {self.database_path}"
            ) from exc

        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            timeout_ms = int(self.busy_timeout_seconds * 1_000)
            connection.execute(f"PRAGMA busy_timeout = {timeout_ms}")
            connection.execute("PRAGMA trusted_schema = OFF")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self, connection: sqlite3.Connection) -> Iterator[None]:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        else:
            connection.execute("COMMIT")

    def _user_table_names(self, connection: sqlite3.Connection) -> set[str]:
        rows = connection.execute(
            """
            SELECT name
            FROM sqlite_schema
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        ).fetchall()
        return {str(row["name"]) for row in rows}

    def _create_schema_v1(self, connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE schema_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "INSERT INTO schema_metadata (key, value) VALUES (?, ?)",
            ("schema_version", MONITORING_SCHEMA_VERSION),
        )
        connection.execute(
            """
            CREATE TABLE monitored_targets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                original_target TEXT NOT NULL,
                normalized_url TEXT NOT NULL UNIQUE,
                enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE scan_runs (
                id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                report_schema_version TEXT NOT NULL,
                lotuswatch_version TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                stored_at TEXT NOT NULL,
                report_json TEXT NOT NULL,
                report_size_bytes INTEGER NOT NULL
                    CHECK (report_size_bytes >= 0),
                FOREIGN KEY (target_id) REFERENCES monitored_targets(id)
                    ON UPDATE RESTRICT ON DELETE RESTRICT
            )
            """
        )
        connection.execute(
            """
            CREATE INDEX scan_runs_target_time_idx
            ON scan_runs (target_id, scanned_at DESC, stored_at DESC, id ASC)
            """
        )

    def _validate_schema_v1(
        self,
        connection: sqlite3.Connection,
        tables: set[str],
    ) -> None:
        if "schema_metadata" not in tables:
            raise StoreCompatibilityError(
                "Existing SQLite database is not a LotusWatch monitoring store."
            )

        row = connection.execute(
            "SELECT value FROM schema_metadata WHERE key = ?",
            ("schema_version",),
        ).fetchone()
        if row is None or row["value"] != MONITORING_SCHEMA_VERSION:
            raise StoreCompatibilityError(
                "Monitoring database schema version is unsupported."
            )

        required_tables = set(_REQUIRED_TABLE_COLUMNS)
        if not required_tables.issubset(tables):
            raise StoreCompatibilityError("Monitoring database schema is incomplete.")

        for table, required_columns in _REQUIRED_TABLE_COLUMNS.items():
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            columns = {str(column["name"]) for column in rows}
            if not required_columns.issubset(columns):
                raise StoreCompatibilityError(
                    "Monitoring database schema is incompatible."
                )

    def _get_target_by_column(
        self,
        column: str,
        value: str,
    ) -> MonitoredTarget | None:
        if column not in {"id", "name"}:
            raise StoreValidationError("Unsupported monitoring target lookup.")

        try:
            with self._connection() as connection:
                row = connection.execute(
                    f"""
                    SELECT id, name, original_target, normalized_url, enabled,
                           created_at, updated_at
                    FROM monitored_targets
                    WHERE {column} = ?
                    """,
                    (value,),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise StoreReadError("Unable to load monitoring target.") from exc

        return None if row is None else self._target_from_row(row)

    def _target_from_row(self, row: sqlite3.Row) -> MonitoredTarget:
        try:
            return MonitoredTarget.model_validate(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "original_target": row["original_target"],
                    "normalized_url": row["normalized_url"],
                    "enabled": bool(row["enabled"]),
                    "created_at": row["created_at"],
                    "updated_at": row["updated_at"],
                }
            )
        except (ValidationError, ValueError, TypeError) as exc:
            raise StoreReadError("Stored monitoring target is invalid.") from exc

    def _metadata_from_row(self, row: sqlite3.Row) -> ScanRunMetadata:
        try:
            return ScanRunMetadata.model_validate(
                {
                    "id": row["id"],
                    "target_id": row["target_id"],
                    "report_schema_version": row["report_schema_version"],
                    "lotuswatch_version": row["lotuswatch_version"],
                    "scanned_at": row["scanned_at"],
                    "stored_at": row["stored_at"],
                }
            )
        except (ValidationError, ValueError, TypeError) as exc:
            raise StoreReadError("Stored scan metadata is invalid.") from exc

    def _stored_run_from_row(self, row: sqlite3.Row) -> StoredScanRun:
        metadata = self._metadata_from_row(row)
        report_json = row["report_json"]
        recorded_size = row["report_size_bytes"]

        if not isinstance(report_json, str) or not isinstance(recorded_size, int):
            raise StoreReadError("Stored scan report payload is invalid.")

        actual_size = len(report_json.encode("utf-8"))
        if actual_size != recorded_size:
            raise StoreReadError("Stored scan report size metadata is invalid.")
        if actual_size > MAX_STORED_REPORT_SIZE_BYTES:
            raise StoredReportTooLargeError(
                "Stored scan report exceeds the supported size limit."
            )

        report = self._parse_stored_report(report_json)
        try:
            return StoredScanRun(metadata=metadata, report=report)
        except ValidationError as exc:
            raise StoreReadError(
                "Stored scan report metadata is inconsistent."
            ) from exc

    def _validated_target(self, target: MonitoredTarget) -> MonitoredTarget:
        if not isinstance(target, MonitoredTarget):
            raise StoreValidationError("Target must be a MonitoredTarget.")
        try:
            return MonitoredTarget.model_validate(target.model_dump(mode="python"))
        except ValidationError as exc:
            raise StoreValidationError("Monitoring target is invalid.") from exc

    def _validated_run(self, run: StoredScanRun) -> StoredScanRun:
        if not isinstance(run, StoredScanRun):
            raise StoreValidationError("Scan run must be a StoredScanRun.")
        try:
            return StoredScanRun.model_validate(run.model_dump(mode="python"))
        except ValidationError as exc:
            raise StoreValidationError("Stored scan run is invalid.") from exc

    def _serialize_report(self, report: ScanReport) -> tuple[str, int]:
        try:
            validated = ScanReport.model_validate(report.model_dump(mode="python"))
            payload = json.dumps(
                validated.model_dump(mode="json"),
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (ValidationError, TypeError, ValueError) as exc:
            raise StoreValidationError(
                "Scan report cannot be serialized safely."
            ) from exc

        payload_size = len(payload.encode("utf-8"))
        if payload_size > MAX_STORED_REPORT_SIZE_BYTES:
            raise StoredReportTooLargeError(
                "Scan report exceeds the supported storage size limit."
            )
        return payload, payload_size

    def _parse_stored_report(self, payload: str) -> ScanReport:
        def reject_duplicate_keys(
            pairs: list[tuple[str, object]],
        ) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON object key.")
                result[key] = value
            return result

        def reject_non_finite_number(_value: str) -> None:
            raise ValueError("Non-finite JSON number.")

        try:
            document = json.loads(
                payload,
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_non_finite_number,
            )
        except (json.JSONDecodeError, RecursionError, ValueError) as exc:
            raise StoreReadError("Stored scan report contains malformed JSON.") from exc

        if not isinstance(document, dict):
            raise StoreReadError("Stored scan report must contain a JSON object.")
        if document.get("schema_version") != "1.0":
            raise StoreCompatibilityError(
                "Stored scan report schema version is unsupported."
            )

        try:
            return ScanReport.model_validate(document)
        except ValidationError as exc:
            raise StoreReadError(
                "Stored scan report does not match schema 1.0."
            ) from exc

    def _validated_limit(self, limit: int) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise StoreValidationError("Storage query limit must be an integer.")
        if not 1 <= limit <= MAX_QUERY_LIMIT:
            raise StoreValidationError(
                f"Storage query limit must be between 1 and {MAX_QUERY_LIMIT}."
            )
        return limit

    def _validated_keep_count(self, keep: int) -> int:
        if isinstance(keep, bool) or not isinstance(keep, int) or keep < 1:
            raise StoreValidationError(
                "Retention keep count must be a positive integer."
            )
        return keep

    def _validated_history_total(self, total: int) -> int:
        if isinstance(total, bool) or not isinstance(total, int) or total < 0:
            raise StoreValidationError("Expected scan history total is invalid.")
        return total

    def _validated_run_ids(self, run_ids: Sequence[UUID]) -> list[UUID]:
        if isinstance(run_ids, (str, bytes)) or not isinstance(run_ids, Sequence):
            raise StoreValidationError("Retention run identifiers must be a sequence.")

        validated: list[UUID] = []
        for run_id in run_ids:
            if not isinstance(run_id, UUID):
                raise StoreValidationError("Retention run identifier is invalid.")
            validated.append(run_id)

        if len(set(validated)) != len(validated):
            raise StoreValidationError(
                "Retention run identifiers must not contain duplicates."
            )
        return validated

    def _scan_run_select_sql(self, suffix: str) -> str:
        return f"""
            SELECT id, target_id, report_schema_version,
                   lotuswatch_version, scanned_at, stored_at,
                   report_json, report_size_bytes
            FROM scan_runs
            {suffix}
        """


__all__ = [
    "DEFAULT_BUSY_TIMEOUT_SECONDS",
    "MAX_DELETE_BATCH_SIZE",
    "MAX_STORED_REPORT_SIZE_BYTES",
    "MONITORING_SCHEMA_VERSION",
    "SQLiteMonitoringStore",
]
