import json
import os
import secrets
import sqlite3
import stat
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from stat import S_ISREG
from uuid import UUID

from pydantic import ValidationError

from lotuswatch.exceptions import (
    MonitoringStoreError,
    StoreBackupAlreadyExistsError,
    StoreBackupDestinationError,
    StoreBackupError,
    StoreCompatibilityError,
    StoreConflictError,
    StoredReportTooLargeError,
    StoreInitializationError,
    StoreIntegrityError,
    StoreReadError,
    StoreValidationError,
    StoreWriteError,
)
from lotuswatch.models import ScanReport
from lotuswatch.storage.base import (
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    DatabaseBackupResult,
    DatabaseCheckResult,
    MonitoredTarget,
    ScanRunMetadata,
    StoredScanRun,
)
from lotuswatch.storage.paths import resolve_monitoring_database_path

MONITORING_SCHEMA_VERSION = "1"
MAX_STORED_REPORT_SIZE_BYTES = 5 * 1024 * 1024
DEFAULT_BUSY_TIMEOUT_SECONDS = 5.0
MAX_DELETE_BATCH_SIZE = 400
MAX_DATABASE_CHECK_TARGETS = 10_000
MAX_DATABASE_CHECK_RUNS = 100_000
DATABASE_CHECK_BATCH_SIZE = 200
_SQLITE_HEADER = b"SQLite format 3\x00"
_EXPECTED_TABLE_COLUMNS = {
    "schema_metadata": {
        "key": ("TEXT", 0, 1),
        "value": ("TEXT", 1, 0),
    },
    "monitored_targets": {
        "id": ("TEXT", 0, 1),
        "name": ("TEXT", 1, 0),
        "original_target": ("TEXT", 1, 0),
        "normalized_url": ("TEXT", 1, 0),
        "enabled": ("INTEGER", 1, 0),
        "created_at": ("TEXT", 1, 0),
        "updated_at": ("TEXT", 1, 0),
    },
    "scan_runs": {
        "id": ("TEXT", 0, 1),
        "target_id": ("TEXT", 1, 0),
        "report_schema_version": ("TEXT", 1, 0),
        "lotuswatch_version": ("TEXT", 1, 0),
        "scanned_at": ("TEXT", 1, 0),
        "stored_at": ("TEXT", 1, 0),
        "report_json": ("TEXT", 1, 0),
        "report_size_bytes": ("INTEGER", 1, 0),
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

    def check_database(self) -> DatabaseCheckResult:
        """Inspect an existing database without creating or modifying it."""

        self._require_existing_database_file()
        try:
            with self._readonly_connection() as connection:
                self._validate_physical_integrity(connection)
                tables = self._user_table_names(connection)
                self._validate_schema_v1(connection, tables)
                self._validate_foreign_key_state(connection)
                self._validate_logical_value_bounds(connection)
                target_count = self._bounded_table_count(
                    connection,
                    table="monitored_targets",
                    maximum=MAX_DATABASE_CHECK_TARGETS,
                )
                run_count = self._bounded_table_count(
                    connection,
                    table="scan_runs",
                    maximum=MAX_DATABASE_CHECK_RUNS,
                )
                targets = self._inspect_all_targets(connection, target_count)
                self._inspect_all_runs(connection, run_count, targets)
        except MonitoringStoreError:
            raise
        except sqlite3.DatabaseError as exc:
            raise StoreIntegrityError(
                "Monitoring database integrity inspection failed."
            ) from exc

        return DatabaseCheckResult(
            schema_version=MONITORING_SCHEMA_VERSION,
            targets_inspected=target_count,
            runs_inspected=run_count,
        )

    def backup_database(
        self,
        destination: str | os.PathLike[str],
    ) -> DatabaseBackupResult:
        """Create and validate a consistent backup without replacing a path."""

        self.check_database()
        destination_path = self._validate_backup_destination(destination)
        temporary_path = self._create_private_backup_file(destination_path)
        finalized = False

        try:
            self._copy_database_online(temporary_path)
            validation = SQLiteMonitoringStore(
                temporary_path,
                busy_timeout_seconds=self.busy_timeout_seconds,
            ).check_database()
            self._finalize_backup(temporary_path, destination_path)
            finalized = True
        except MonitoringStoreError:
            raise
        except sqlite3.DatabaseError as exc:
            raise StoreBackupError(
                "Unable to create a consistent monitoring database backup."
            ) from exc
        except OSError as exc:
            raise StoreBackupError(
                "Unable to finalize monitoring database backup safely."
            ) from exc
        finally:
            if not finalized:
                self._remove_owned_temporary_file(temporary_path)

        return DatabaseBackupResult(
            destination=destination_path,
            validation=validation,
        )

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
        if not os.path.lexists(path):
            return self._create_empty_database_file()

        self._validate_existing_database_file(path)
        return False

    def _require_existing_database_file(self) -> None:
        if not os.path.lexists(self.database_path):
            raise StoreInitializationError(
                f"Monitoring database does not exist: {self.database_path}"
            )
        self._validate_existing_database_file(self.database_path)

    def _validate_existing_database_file(self, path: Path) -> None:
        try:
            file_stat = path.lstat()
        except OSError as exc:
            raise StoreInitializationError(
                f"Unable to inspect monitoring database: {path}"
            ) from exc

        if self._is_link_or_reparse(path, file_stat):
            raise StoreInitializationError(
                f"Monitoring database path must not be a link or reparse point: {path}"
            )
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

    def _is_link_or_reparse(self, path: Path, file_stat: os.stat_result) -> bool:
        reparse_attribute = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
        file_attributes = getattr(file_stat, "st_file_attributes", 0)
        is_junction = getattr(path, "is_junction", lambda: False)
        return bool(
            path.is_symlink()
            or is_junction()
            or (reparse_attribute and file_attributes & reparse_attribute)
        )

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
        self._restrict_file_permissions(self.database_path)

    def _restrict_file_permissions(self, path: Path) -> None:
        try:
            path.chmod(0o600)
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
    def _readonly_connection(self) -> Iterator[sqlite3.Connection]:
        try:
            database_uri = f"{self.database_path.as_uri()}?mode=ro"
            connection = sqlite3.connect(
                database_uri,
                uri=True,
                timeout=self.busy_timeout_seconds,
                isolation_level=None,
            )
        except (OSError, sqlite3.Error) as exc:
            raise StoreInitializationError(
                f"Unable to open monitoring database: {self.database_path}"
            ) from exc

        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA foreign_keys = ON")
            timeout_ms = int(self.busy_timeout_seconds * 1_000)
            connection.execute(f"PRAGMA busy_timeout = {timeout_ms}")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("BEGIN")
            yield connection
        finally:
            try:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            finally:
                connection.close()

    def _validate_backup_destination(
        self,
        destination: str | os.PathLike[str],
    ) -> Path:
        if not isinstance(destination, (str, os.PathLike)):
            raise StoreBackupDestinationError("Backup destination path is invalid.")
        try:
            raw_destination = os.fspath(destination)
        except TypeError as exc:
            raise StoreBackupDestinationError(
                "Backup destination path is invalid."
            ) from exc
        if (
            not isinstance(raw_destination, str)
            or not raw_destination.strip()
            or "\x00" in raw_destination
        ):
            raise StoreBackupDestinationError(
                "Backup destination path must not be empty."
            )

        try:
            destination_path = Path(os.path.abspath(Path(raw_destination).expanduser()))
            source_path = self.database_path.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise StoreBackupDestinationError(
                "Backup destination path cannot be resolved safely."
            ) from exc

        if os.path.lexists(destination_path):
            try:
                if os.path.samefile(source_path, destination_path):
                    raise StoreBackupDestinationError(
                        "Backup destination must differ from the source database."
                    )
            except OSError:
                pass
            raise StoreBackupAlreadyExistsError(
                f"Backup destination already exists: {destination_path}"
            )

        parent = destination_path.parent
        try:
            parent_stat = parent.lstat()
        except OSError as exc:
            raise StoreBackupDestinationError(
                f"Backup destination directory is unavailable: {parent}"
            ) from exc
        if self._is_link_or_reparse(parent, parent_stat) or not parent.is_dir():
            raise StoreBackupDestinationError(
                f"Backup destination parent must be a real directory: {parent}"
            )

        try:
            resolved_candidate = parent.resolve(strict=True) / destination_path.name
        except (OSError, RuntimeError) as exc:
            raise StoreBackupDestinationError(
                f"Backup destination directory is unavailable: {parent}"
            ) from exc
        if os.path.normcase(str(resolved_candidate)) == os.path.normcase(
            str(source_path)
        ):
            raise StoreBackupDestinationError(
                "Backup destination must differ from the source database."
            )
        return destination_path

    def _create_private_backup_file(self, destination: Path) -> Path:
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW

        for _attempt in range(10):
            candidate = destination.parent / (
                f".{destination.name}.lotuswatch-{secrets.token_hex(12)}.tmp"
            )
            try:
                descriptor = os.open(candidate, flags, 0o600)
            except FileExistsError:
                continue
            except OSError as exc:
                raise StoreBackupError(
                    "Unable to create a private temporary backup file."
                ) from exc
            else:
                os.close(descriptor)

            try:
                candidate_stat = candidate.lstat()
            except OSError as exc:
                self._remove_owned_temporary_file(candidate)
                raise StoreBackupError(
                    "Unable to inspect the temporary backup file."
                ) from exc
            if self._is_link_or_reparse(candidate, candidate_stat) or not S_ISREG(
                candidate_stat.st_mode
            ):
                self._remove_owned_temporary_file(candidate)
                raise StoreBackupError("Temporary backup path is not a regular file.")
            return candidate

        raise StoreBackupError("Unable to allocate a private temporary backup file.")

    def _copy_database_online(self, destination: Path) -> None:
        try:
            with (
                self._readonly_connection() as source_connection,
                closing(
                    sqlite3.connect(
                        destination,
                        timeout=self.busy_timeout_seconds,
                        isolation_level=None,
                    )
                ) as destination_connection,
            ):
                source_connection.backup(
                    destination_connection,
                    pages=256,
                    sleep=0.05,
                )
        except MonitoringStoreError:
            raise
        except sqlite3.DatabaseError as exc:
            raise StoreBackupError(
                "Unable to copy monitoring history into the backup."
            ) from exc
        self._restrict_file_permissions(destination)

    def _finalize_backup(self, temporary: Path, destination: Path) -> None:
        if os.path.lexists(destination):
            raise StoreBackupAlreadyExistsError(
                f"Backup destination already exists: {destination}"
            )
        try:
            os.link(temporary, destination)
        except FileExistsError as exc:
            raise StoreBackupAlreadyExistsError(
                f"Backup destination already exists: {destination}"
            ) from exc
        except OSError as exc:
            raise StoreBackupError(
                "Unable to finalize monitoring database backup safely."
            ) from exc

        self._restrict_file_permissions(destination)
        try:
            temporary.unlink()
        except OSError:
            return

    def _remove_owned_temporary_file(self, path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            return

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

    def _validate_physical_integrity(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        rows = connection.execute("PRAGMA integrity_check(1)").fetchmany(2)
        if len(rows) != 1 or rows[0][0] != "ok":
            raise StoreIntegrityError(
                "Monitoring database failed its physical integrity check."
            )

    def _validate_foreign_key_state(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        state = connection.execute("PRAGMA foreign_keys").fetchone()
        if state is None or state[0] != 1:
            raise StoreIntegrityError(
                "Monitoring database foreign-key enforcement is unavailable."
            )

        definitions = connection.execute(
            "PRAGMA foreign_key_list(scan_runs)"
        ).fetchall()
        expected = (
            "monitored_targets",
            "target_id",
            "id",
            "RESTRICT",
            "RESTRICT",
        )
        observed = {
            (
                str(row["table"]),
                str(row["from"]),
                str(row["to"]),
                str(row["on_update"]).upper(),
                str(row["on_delete"]).upper(),
            )
            for row in definitions
        }
        if expected not in observed:
            raise StoreCompatibilityError(
                "Monitoring database foreign-key schema is incompatible."
            )

        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise StoreIntegrityError(
                "Monitoring database contains an invalid target relationship."
            )

    def _bounded_table_count(
        self,
        connection: sqlite3.Connection,
        *,
        table: str,
        maximum: int,
    ) -> int:
        if table not in {"monitored_targets", "scan_runs"}:
            raise StoreIntegrityError("Unsupported database inspection table.")
        row = connection.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
        if row is None or not isinstance(row["count"], int) or row["count"] < 0:
            raise StoreIntegrityError("Monitoring database row count is invalid.")
        count = int(row["count"])
        if count > maximum:
            raise StoreIntegrityError(
                "Monitoring database exceeds the bounded inspection limit."
            )
        return count

    def _validate_logical_value_bounds(
        self,
        connection: sqlite3.Connection,
    ) -> None:
        invalid_target = connection.execute(
            """
            SELECT 1
            FROM monitored_targets
            WHERE typeof(id) != 'text' OR length(id) > 128
               OR typeof(name) != 'text' OR length(name) > 100
               OR typeof(original_target) != 'text'
               OR length(CAST(original_target AS BLOB)) > 16384
               OR typeof(normalized_url) != 'text'
               OR length(CAST(normalized_url AS BLOB)) > 16384
               OR typeof(enabled) != 'integer'
               OR typeof(created_at) != 'text' OR length(created_at) > 128
               OR typeof(updated_at) != 'text' OR length(updated_at) > 128
            LIMIT 1
            """
        ).fetchone()
        if invalid_target is not None:
            raise StoreIntegrityError(
                "Stored monitoring target metadata exceeds its supported bounds."
            )

        invalid_run = connection.execute(
            """
            SELECT 1
            FROM scan_runs
            WHERE typeof(id) != 'text' OR length(id) > 128
               OR typeof(target_id) != 'text' OR length(target_id) > 128
               OR typeof(report_schema_version) != 'text'
               OR length(report_schema_version) > 32
               OR typeof(lotuswatch_version) != 'text'
               OR length(lotuswatch_version) > 100
               OR typeof(scanned_at) != 'text' OR length(scanned_at) > 128
               OR typeof(stored_at) != 'text' OR length(stored_at) > 128
               OR typeof(report_json) != 'text'
               OR typeof(report_size_bytes) != 'integer'
               OR report_size_bytes < 0
               OR report_size_bytes > ?
               OR length(CAST(report_json AS BLOB)) != report_size_bytes
               OR length(CAST(report_json AS BLOB)) > ?
            LIMIT 1
            """,
            (MAX_STORED_REPORT_SIZE_BYTES, MAX_STORED_REPORT_SIZE_BYTES),
        ).fetchone()
        if invalid_run is not None:
            raise StoreIntegrityError(
                "Stored scan metadata or report payload exceeds its supported bounds."
            )

    def _inspect_all_targets(
        self,
        connection: sqlite3.Connection,
        expected_count: int,
    ) -> dict[UUID, MonitoredTarget]:
        cursor = connection.execute(
            """
            SELECT id, name, original_target, normalized_url, enabled,
                   created_at, updated_at
            FROM monitored_targets
            ORDER BY id ASC
            """
        )
        inspected: dict[UUID, MonitoredTarget] = {}
        while rows := cursor.fetchmany(DATABASE_CHECK_BATCH_SIZE):
            for row in rows:
                target = self._target_from_row(row)
                if target.id in inspected:
                    raise StoreIntegrityError(
                        "Monitoring database contains duplicate target metadata."
                    )
                inspected[target.id] = target
        if len(inspected) != expected_count:
            raise StoreIntegrityError(
                "Monitoring target count changed during inspection."
            )
        return inspected

    def _inspect_all_runs(
        self,
        connection: sqlite3.Connection,
        expected_count: int,
        targets: dict[UUID, MonitoredTarget],
    ) -> None:
        cursor = connection.execute(self._scan_run_select_sql("ORDER BY id ASC"))
        inspected = 0
        while rows := cursor.fetchmany(DATABASE_CHECK_BATCH_SIZE):
            for row in rows:
                run = self._stored_run_from_row(row)
                target = targets.get(run.metadata.target_id)
                if target is None:
                    raise StoreIntegrityError(
                        "Stored scan run references an unknown monitoring target."
                    )
                if run.report.target.normalized_url != target.normalized_url:
                    raise StoreIntegrityError(
                        "Stored scan report target is inconsistent."
                    )
                inspected += 1
        if inspected != expected_count:
            raise StoreIntegrityError(
                "Stored scan-run count changed during inspection."
            )

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
            """
            SELECT 1 AS supported
            FROM schema_metadata
            WHERE key = ? AND value = ?
            LIMIT 1
            """,
            ("schema_version", MONITORING_SCHEMA_VERSION),
        ).fetchone()
        if row is None:
            raise StoreCompatibilityError(
                "Monitoring database schema version is unsupported."
            )

        required_tables = set(_EXPECTED_TABLE_COLUMNS)
        if not required_tables.issubset(tables):
            raise StoreCompatibilityError("Monitoring database schema is incomplete.")

        for table, expected_columns in _EXPECTED_TABLE_COLUMNS.items():
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            columns = {
                str(column["name"]): (
                    str(column["type"]).upper(),
                    int(column["notnull"]),
                    int(column["pk"]),
                )
                for column in rows
            }
            if any(
                columns.get(name) != definition
                for name, definition in expected_columns.items()
            ):
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
        enabled = row["enabled"]
        if (
            not isinstance(enabled, int)
            or isinstance(enabled, bool)
            or enabled
            not in {
                0,
                1,
            }
        ):
            raise StoreReadError("Stored monitoring target state is invalid.")
        try:
            return MonitoredTarget.model_validate(
                {
                    "id": row["id"],
                    "name": row["name"],
                    "original_target": row["original_target"],
                    "normalized_url": row["normalized_url"],
                    "enabled": bool(enabled),
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
    "DATABASE_CHECK_BATCH_SIZE",
    "DEFAULT_BUSY_TIMEOUT_SECONDS",
    "MAX_DATABASE_CHECK_RUNS",
    "MAX_DATABASE_CHECK_TARGETS",
    "MAX_DELETE_BATCH_SIZE",
    "MAX_STORED_REPORT_SIZE_BYTES",
    "MONITORING_SCHEMA_VERSION",
    "SQLiteMonitoringStore",
]
