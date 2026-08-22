"""Verify immutable alpha-era compatibility fixtures with installed LotusWatch."""

from __future__ import annotations

import argparse
import json
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Final
from uuid import UUID

from pydantic import ValidationError

from lotuswatch.exceptions import LotusWatchError
from lotuswatch.models import (
    FINDING_FINGERPRINT_VERSION,
    ComparisonReport,
    NotificationEvent,
    compare_reports,
    finding_id_fingerprint,
)
from lotuswatch.reporters import load_json_report
from lotuswatch.storage import MONITORING_SCHEMA_VERSION, SQLiteMonitoringStore

MAX_FIXTURE_SIZE_BYTES: Final = 5 * 1024 * 1024
COMPATIBILITY_FIXTURE_FILENAMES: Final = (
    "alpha5-scan-report.json",
    "alpha6-scan-report.json",
    "alpha6-comparison-report.json",
    "alpha6-notification-event.json",
    "alpha5-monitoring-v1.json",
    "fingerprint-v1.json",
)


class CompatibilityVerificationError(RuntimeError):
    """Raised when a supported historical fixture cannot be read safely."""


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_non_finite(_value: str) -> None:
    raise ValueError("Non-finite JSON number.")


def _load_json_object(path: Path) -> dict[str, object]:
    if path.is_symlink():
        raise CompatibilityVerificationError(
            "Compatibility fixture must be a regular local file."
        )
    try:
        path = path.resolve(strict=True)
        if not path.is_file():
            raise CompatibilityVerificationError(
                "Compatibility fixture must be a regular local file."
            )
        size = path.stat().st_size
        if size > MAX_FIXTURE_SIZE_BYTES:
            raise CompatibilityVerificationError(
                "Compatibility fixture exceeds the size limit."
            )
        payload = path.read_bytes()
        if len(payload) != size:
            raise CompatibilityVerificationError(
                "Compatibility fixture changed while being read."
            )
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except CompatibilityVerificationError:
        raise
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise CompatibilityVerificationError(
            "Compatibility fixture is unreadable or malformed."
        ) from exc
    if not isinstance(document, dict):
        raise CompatibilityVerificationError(
            "Compatibility fixture must contain a JSON object."
        )
    return document


def _require_fixture_directory(root: Path) -> dict[str, Path]:
    if root.is_symlink():
        raise CompatibilityVerificationError(
            "Compatibility fixture path must be a real directory."
        )
    try:
        resolved = root.resolve(strict=True)
    except OSError as exc:
        raise CompatibilityVerificationError(
            "Compatibility fixture directory is unavailable."
        ) from exc
    if not resolved.is_dir():
        raise CompatibilityVerificationError(
            "Compatibility fixture path must be a real directory."
        )
    try:
        discovered = {path.name: path for path in resolved.iterdir()}
    except OSError as exc:
        raise CompatibilityVerificationError(
            "Unable to inspect compatibility fixture directory."
        ) from exc
    if set(discovered) != set(COMPATIBILITY_FIXTURE_FILENAMES):
        raise CompatibilityVerificationError(
            "Compatibility fixture inventory is incomplete or unexpected."
        )
    return discovered


def _materialize_monitoring_v1(document: dict[str, object], path: Path) -> None:
    if document.get("monitoring_schema_version") != "1":
        raise CompatibilityVerificationError(
            "Historical monitoring schema version is unsupported."
        )
    target = document.get("target")
    run = document.get("run")
    if not isinstance(target, dict) or not isinstance(run, dict):
        raise CompatibilityVerificationError(
            "Historical monitoring fixture structure is invalid."
        )

    expected_target_keys = {
        "id",
        "name",
        "original_target",
        "normalized_url",
        "enabled",
        "created_at",
        "updated_at",
    }
    expected_run_keys = {
        "id",
        "target_id",
        "report_schema_version",
        "lotuswatch_version",
        "scanned_at",
        "stored_at",
        "report_json",
        "report_size_bytes",
    }
    if set(target) != expected_target_keys or set(run) != expected_run_keys:
        raise CompatibilityVerificationError(
            "Historical monitoring fixture fields are invalid."
        )

    report_json = run["report_json"]
    report_size = run["report_size_bytes"]
    if (
        not isinstance(report_json, str)
        or not isinstance(report_size, int)
        or isinstance(report_size, bool)
        or len(report_json.encode("utf-8")) != report_size
    ):
        raise CompatibilityVerificationError(
            "Historical stored report size is inconsistent."
        )

    schema = """
        PRAGMA foreign_keys = ON;
        CREATE TABLE schema_metadata (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE TABLE monitored_targets (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            original_target TEXT NOT NULL,
            normalized_url TEXT NOT NULL UNIQUE,
            enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE scan_runs (
            id TEXT PRIMARY KEY,
            target_id TEXT NOT NULL,
            report_schema_version TEXT NOT NULL,
            lotuswatch_version TEXT NOT NULL,
            scanned_at TEXT NOT NULL,
            stored_at TEXT NOT NULL,
            report_json TEXT NOT NULL,
            report_size_bytes INTEGER NOT NULL CHECK (report_size_bytes >= 0),
            FOREIGN KEY (target_id) REFERENCES monitored_targets(id)
                ON UPDATE RESTRICT ON DELETE RESTRICT
        );
        CREATE INDEX scan_runs_target_time_idx
        ON scan_runs (target_id, scanned_at DESC, stored_at DESC, id ASC);
    """
    try:
        with closing(sqlite3.connect(path)) as connection:
            connection.executescript(schema)
            connection.execute(
                "INSERT INTO schema_metadata (key, value) VALUES (?, ?)",
                ("schema_version", document["monitoring_schema_version"]),
            )
            connection.execute(
                """
                INSERT INTO monitored_targets (
                    id, name, original_target, normalized_url, enabled,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target["id"],
                    target["name"],
                    target["original_target"],
                    target["normalized_url"],
                    int(target["enabled"]),
                    target["created_at"],
                    target["updated_at"],
                ),
            )
            connection.execute(
                """
                INSERT INTO scan_runs (
                    id, target_id, report_schema_version, lotuswatch_version,
                    scanned_at, stored_at, report_json, report_size_bytes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    run["id"],
                    run["target_id"],
                    run["report_schema_version"],
                    run["lotuswatch_version"],
                    run["scanned_at"],
                    run["stored_at"],
                    report_json,
                    report_size,
                ),
            )
            connection.commit()
    except (KeyError, TypeError, ValueError, sqlite3.DatabaseError) as exc:
        raise CompatibilityVerificationError(
            "Unable to materialize historical monitoring fixture."
        ) from exc


def verify_compatibility_fixtures(root: Path) -> None:
    """Validate all supported alpha-era artifacts with the installed package."""

    fixtures = _require_fixture_directory(root)
    try:
        alpha5 = load_json_report(fixtures["alpha5-scan-report.json"])
        alpha6 = load_json_report(fixtures["alpha6-scan-report.json"])
        comparison = ComparisonReport.model_validate(
            _load_json_object(fixtures["alpha6-comparison-report.json"])
        )
        notification = NotificationEvent.model_validate(
            _load_json_object(fixtures["alpha6-notification-event.json"])
        )
    except (ValidationError, ValueError) as exc:
        raise CompatibilityVerificationError(
            "Historical JSON fixture failed current model validation."
        ) from exc

    if alpha5.lotuswatch_version != "0.1.0-alpha.5":
        raise CompatibilityVerificationError("Alpha.5 report metadata is invalid.")
    if alpha6.lotuswatch_version != "0.1.0-alpha.6":
        raise CompatibilityVerificationError("Alpha.6 report metadata is invalid.")
    regenerated = compare_reports(alpha5, alpha6, compared_at=comparison.compared_at)
    if regenerated != comparison:
        raise CompatibilityVerificationError(
            "Historical comparison does not match its source reports."
        )
    if notification.comparison_summary != comparison.summary:
        raise CompatibilityVerificationError(
            "Historical notification does not match its comparison."
        )

    fingerprint = _load_json_object(fixtures["fingerprint-v1.json"])
    if fingerprint.get("fingerprint_version") != FINDING_FINGERPRINT_VERSION:
        raise CompatibilityVerificationError(
            "Historical fingerprint version is unsupported."
        )
    expected_fingerprint = finding_id_fingerprint(
        fingerprint.get("normalized_target"),
        fingerprint.get("finding_id"),
    )
    if fingerprint.get("fingerprint") != expected_fingerprint:
        raise CompatibilityVerificationError(
            "Historical fingerprint value is inconsistent."
        )

    database_fixture = _load_json_object(fixtures["alpha5-monitoring-v1.json"])
    with tempfile.TemporaryDirectory(prefix="lotuswatch-compatibility-") as raw:
        database = Path(raw) / "alpha5-monitoring.db"
        _materialize_monitoring_v1(database_fixture, database)
        before = database.read_bytes()
        store = SQLiteMonitoringStore(database)
        result = store.check_database()
        after = database.read_bytes()
        if before != after:
            raise CompatibilityVerificationError(
                "Historical database changed during compatibility inspection."
            )
        if (
            result.schema_version != MONITORING_SCHEMA_VERSION
            or result.targets_inspected != 1
            or result.runs_inspected != 1
        ):
            raise CompatibilityVerificationError(
                "Historical database inspection summary is invalid."
            )
        run_document = database_fixture.get("run")
        if not isinstance(run_document, dict):
            raise CompatibilityVerificationError(
                "Historical monitoring run metadata is invalid."
            )
        try:
            run_id = UUID(str(run_document.get("id")))
        except ValueError as exc:
            raise CompatibilityVerificationError(
                "Historical monitoring run identifier is invalid."
            ) from exc
        run = store.get_scan_run(run_id)
        if run is None or run.report != alpha5:
            raise CompatibilityVerificationError(
                "Historical stored report could not be loaded."
            )


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify supported LotusWatch compatibility fixtures."
    )
    parser.add_argument("fixture_directory", type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = _parse_arguments()
    try:
        verify_compatibility_fixtures(arguments.fixture_directory)
    except CompatibilityVerificationError as exc:
        print(f"Compatibility fixture verification failed: {exc}")
        return 1
    except (LotusWatchError, ValidationError, OSError, TypeError, ValueError):
        print("Compatibility fixture verification failed safely.")
        return 1
    print("Compatibility fixture verification passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
