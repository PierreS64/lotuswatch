import hashlib
import json
import sqlite3
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from lotuswatch.exceptions import ReportCompatibilityError, StoreCompatibilityError
from lotuswatch.models import (
    COMPARISON_REPORT_SCHEMA_VERSION,
    FINDING_FINGERPRINT_VERSION,
    NOTIFICATION_EVENT_SCHEMA_VERSION,
    SCAN_REPORT_SCHEMA_VERSION,
    ComparisonReport,
    NotificationEvent,
    compare_reports,
    finding_id_fingerprint,
)
from lotuswatch.reporters import load_json_report
from lotuswatch.storage import MONITORING_SCHEMA_VERSION, SQLiteMonitoringStore
from scripts.verify_compatibility_fixtures import (
    CompatibilityVerificationError,
    _load_json_object,
    _materialize_monitoring_v1,
    verify_compatibility_fixtures,
)

PROJECT_ROOT = Path(__file__).parents[1]
FIXTURE_ROOT = PROJECT_ROOT / "tests" / "fixtures" / "compatibility"
FIXTURE_HASHES = {
    "alpha5-monitoring-v1.json": (
        "b96002e28a6349b64b748735c7cf79f2a92399169b8ebd3533e48661cc7b1a5d"
    ),
    "alpha5-scan-report.json": (
        "610fb507ee346200a9b07694c0df5bc103a339ac43feebde805d67b45c8bb45d"
    ),
    "alpha6-comparison-report.json": (
        "7041277a6a34ffc99c3f38bebae76a9aad71ec5a73eb3ef7ba8077234ae6408d"
    ),
    "alpha6-notification-event.json": (
        "cc4c53240a8213477a63998da3a34eea9df16ddd2137212b6be3cba151d42cd9"
    ),
    "alpha6-scan-report.json": (
        "ed1b4e3320c14987a6c2f0cd6f28caba66d3800f47fad762c9cb288bd01667ab"
    ),
    "fingerprint-v1.json": (
        "f0582d244cd64a5e213d80bb34ae8f5c14e62397bc2208d97044de5d1edd58a2"
    ),
}


def test_supported_compatibility_versions_are_explicit() -> None:
    assert SCAN_REPORT_SCHEMA_VERSION == "1.0"
    assert COMPARISON_REPORT_SCHEMA_VERSION == "1.0"
    assert NOTIFICATION_EVENT_SCHEMA_VERSION == "1.0"
    assert FINDING_FINGERPRINT_VERSION == 1
    assert MONITORING_SCHEMA_VERSION == "1"


def test_immutable_compatibility_fixture_inventory_and_hashes() -> None:
    discovered = {path.name: path for path in FIXTURE_ROOT.iterdir()}

    assert set(discovered) == set(FIXTURE_HASHES)
    for filename, expected_hash in FIXTURE_HASHES.items():
        payload = discovered[filename].read_bytes().replace(b"\r\n", b"\n")
        digest = hashlib.sha256(payload).hexdigest()
        assert digest == expected_hash, f"Compatibility fixture changed: {filename}"


def test_compatibility_fixtures_are_safe_and_use_reserved_names() -> None:
    combined = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(FIXTURE_ROOT.iterdir())
    ).casefold()

    assert "demo.example" in combined
    assert "kinetictech.icu" not in combined
    assert "cellphones.com.vn" not in combined
    assert "lotuswatch_webhook_url" not in combined
    assert "lotuswatch_webhook_secret" not in combined
    assert "lotuswatch_telegram_bot_token" not in combined
    assert "lotuswatch_telegram_chat_id" not in combined


def test_complete_alpha_compatibility_fixture_verification() -> None:
    verify_compatibility_fixtures(FIXTURE_ROOT)


def test_alpha_scan_reports_load_without_source_rewrite() -> None:
    alpha5_path = FIXTURE_ROOT / "alpha5-scan-report.json"
    alpha6_path = FIXTURE_ROOT / "alpha6-scan-report.json"
    before = {path: path.read_bytes() for path in (alpha5_path, alpha6_path)}

    alpha5 = load_json_report(alpha5_path)
    alpha6 = load_json_report(alpha6_path)

    assert alpha5.lotuswatch_version == "0.1.0-alpha.5"
    assert alpha6.lotuswatch_version == "0.1.0-alpha.6"
    assert alpha5.target.normalized_url == alpha6.target.normalized_url
    assert {path: path.read_bytes() for path in before} == before


def test_alpha_comparison_regenerates_with_version_metadata_only() -> None:
    alpha5 = load_json_report(FIXTURE_ROOT / "alpha5-scan-report.json")
    alpha6 = load_json_report(FIXTURE_ROOT / "alpha6-scan-report.json")
    stored = ComparisonReport.model_validate(
        _load_json_object(FIXTURE_ROOT / "alpha6-comparison-report.json")
    )

    regenerated = compare_reports(alpha5, alpha6, compared_at=stored.compared_at)

    assert regenerated == stored
    assert stored.baseline.lotuswatch_version == "0.1.0-alpha.5"
    assert stored.current.lotuswatch_version == "0.1.0-alpha.6"


def test_alpha_notification_and_fingerprint_remain_valid() -> None:
    event = NotificationEvent.model_validate(
        _load_json_object(FIXTURE_ROOT / "alpha6-notification-event.json")
    )
    fingerprint = _load_json_object(FIXTURE_ROOT / "fingerprint-v1.json")

    assert event.notification_schema_version == NOTIFICATION_EVENT_SCHEMA_VERSION
    assert fingerprint["fingerprint_version"] == FINDING_FINGERPRINT_VERSION
    assert fingerprint["fingerprint"] == finding_id_fingerprint(
        fingerprint["normalized_target"],
        fingerprint["finding_id"],
    )


def test_alpha5_monitoring_database_opens_and_preserves_rows(tmp_path: Path) -> None:
    database_fixture = _load_json_object(FIXTURE_ROOT / "alpha5-monitoring-v1.json")
    database = tmp_path / "alpha5.db"
    _materialize_monitoring_v1(database_fixture, database)
    store = SQLiteMonitoringStore(database)

    with sqlite3.connect(database) as connection:
        before = connection.execute(
            "SELECT * FROM monitored_targets, scan_runs"
        ).fetchall()

    check = store.check_database()
    run_id = UUID(database_fixture["run"]["id"])
    stored = store.get_scan_run(run_id)
    store.initialize()

    with sqlite3.connect(database) as connection:
        after = connection.execute(
            "SELECT * FROM monitored_targets, scan_runs"
        ).fetchall()

    assert check.targets_inspected == check.runs_inspected == 1
    assert stored is not None
    assert stored.report.lotuswatch_version == "0.1.0-alpha.5"
    assert before == after


def test_future_scan_schema_fails_without_rewriting_input(tmp_path: Path) -> None:
    source = _load_json_object(FIXTURE_ROOT / "alpha5-scan-report.json")
    source["schema_version"] = "999.0"
    path = tmp_path / "future-report.json"
    path.write_text(json.dumps(source), encoding="utf-8")
    before = path.read_bytes()

    with pytest.raises(ReportCompatibilityError):
        load_json_report(path)

    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("filename", "version_field", "model"),
    [
        (
            "alpha6-comparison-report.json",
            "comparison_schema_version",
            ComparisonReport,
        ),
        (
            "alpha6-notification-event.json",
            "notification_schema_version",
            NotificationEvent,
        ),
    ],
)
def test_future_model_schema_versions_fail_explicitly(
    filename: str,
    version_field: str,
    model: type[ComparisonReport] | type[NotificationEvent],
) -> None:
    document = _load_json_object(FIXTURE_ROOT / filename)
    document[version_field] = "999.0"

    with pytest.raises(ValidationError) as error:
        model.model_validate(document)

    assert version_field in str(error.value)


def test_future_database_schema_fails_without_modification(tmp_path: Path) -> None:
    fixture = _load_json_object(FIXTURE_ROOT / "alpha5-monitoring-v1.json")
    fixture["monitoring_schema_version"] = "999"
    database = tmp_path / "future.db"

    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE schema_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO schema_metadata (key, value) VALUES (?, ?)",
            ("schema_version", fixture["monitoring_schema_version"]),
        )
    before = database.read_bytes()

    with pytest.raises(StoreCompatibilityError):
        SQLiteMonitoringStore(database).check_database()

    assert database.read_bytes() == before


def test_fixture_loader_rejects_duplicate_keys_without_value_leak(
    tmp_path: Path,
) -> None:
    fixture = tmp_path / "duplicate.json"
    fixture.write_text(
        '{"schema_version":"1.0","schema_version":"private-value"}',
        encoding="utf-8",
    )

    with pytest.raises(CompatibilityVerificationError) as error:
        _load_json_object(fixture)

    assert "private-value" not in str(error.value)
