from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from lotuswatch.exceptions import (
    StoreConflictError,
    StoreValidationError,
)
from lotuswatch.models import ScanReport
from lotuswatch.storage import (
    MAX_QUERY_LIMIT,
    MonitoredTarget,
    MonitoringStore,
    SQLiteMonitoringStore,
    StoredScanRun,
)


@pytest.fixture(params=[SQLiteMonitoringStore], ids=["sqlite"])
def store(request: pytest.FixtureRequest, tmp_path: Path) -> MonitoringStore:
    backend = request.param(tmp_path / "monitoring.db")
    backend.initialize()
    assert isinstance(backend, MonitoringStore)
    return backend


def make_target(
    *,
    name: str = "production",
    normalized_url: str = "https://example.com/",
    target_id: UUID | None = None,
) -> MonitoredTarget:
    return MonitoredTarget.create(
        name=name,
        original_target="example.com",
        normalized_url=normalized_url,
        target_id=target_id,
        created_at=datetime(2026, 8, 20, 8, 0, tzinfo=UTC),
    )


def make_report(*, scanned_at: datetime) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.4",
        original_target="example.com",
        normalized_url="https://example.com/",
        scanned_at=scanned_at,
        checks=[{"name": "synthetic", "status": "passed"}],
        findings=[],
    )


def make_run(
    target_id: UUID,
    *,
    scanned_at: datetime,
    stored_at: datetime | None = None,
    run_id: UUID | None = None,
) -> StoredScanRun:
    return StoredScanRun.create(
        target_id=target_id,
        report=make_report(scanned_at=scanned_at),
        stored_at=stored_at,
        run_id=run_id,
    )


def test_target_round_trip_and_hostile_values_use_contract(
    store: MonitoringStore,
) -> None:
    hostile_name = "prod'); DROP TABLE scan_runs; --"
    target = make_target(name=hostile_name)

    created = store.create_target(target)

    assert created == target
    assert created is not target
    assert store.get_target(target.id) == target
    assert store.get_target_by_name(hostile_name) == target
    assert store.list_targets() == [target]


def test_target_listing_is_bounded_and_deterministic(store: MonitoringStore) -> None:
    beta = make_target(name="beta", normalized_url="https://beta.example/")
    alpha = make_target(name="Alpha", normalized_url="https://alpha.example/")
    lowercase = make_target(name="alpha", normalized_url="https://lower.example/")
    for target in (beta, lowercase, alpha):
        store.create_target(target)

    assert [target.name for target in store.list_targets(limit=2)] == [
        "Alpha",
        "alpha",
    ]


@pytest.mark.parametrize("limit", [0, MAX_QUERY_LIMIT + 1, True, 1.5])
def test_invalid_query_limits_are_rejected(
    store: MonitoringStore,
    limit: object,
) -> None:
    with pytest.raises(StoreValidationError):
        store.list_targets(limit=limit)  # type: ignore[arg-type]


def test_duplicate_target_values_do_not_replace_existing_data(
    store: MonitoringStore,
) -> None:
    original = make_target()
    store.create_target(original)

    with pytest.raises(StoreConflictError):
        store.create_target(make_target(name=original.name))

    with pytest.raises(StoreConflictError):
        store.create_target(
            make_target(
                name="another",
                normalized_url=original.normalized_url,
            )
        )

    assert store.list_targets() == [original]


def test_target_state_update_preserves_scan_history(store: MonitoringStore) -> None:
    target = make_target()
    store.create_target(target)
    run = make_run(
        target.id,
        scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
    )
    store.save_scan_run(run)

    updated = store.set_target_enabled(
        target.id,
        enabled=False,
        updated_at=datetime(2026, 8, 20, 10, 0, tzinfo=UTC),
    )

    assert updated is not None
    assert updated.enabled is False
    assert updated.created_at == target.created_at
    assert store.get_scan_run(run.metadata.id) == run
    assert store.set_target_enabled(uuid4(), enabled=False) is None


def test_scan_run_round_trip_returns_independent_validated_copies(
    store: MonitoringStore,
) -> None:
    target = make_target()
    store.create_target(target)
    run = make_run(
        target.id,
        scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
        stored_at=datetime(2026, 8, 20, 9, 1, tzinfo=UTC),
    )

    saved = store.save_scan_run(run)
    loaded = store.get_scan_run(run.metadata.id)

    assert saved == run
    assert saved is not run
    assert loaded == run
    assert loaded is not None
    loaded.report.target.input = "mutated.example"

    reloaded = store.get_scan_run(run.metadata.id)
    assert reloaded is not None
    assert reloaded.report.target.input == "example.com"
    assert reloaded.report.summary.checks_completed == 1
    assert reloaded.report.summary.findings_total == 0


def test_run_listing_and_latest_selection_are_deterministic(
    store: MonitoringStore,
) -> None:
    target = make_target()
    store.create_target(target)
    first_time = datetime(2026, 8, 20, 9, 0, tzinfo=UTC)
    first = make_run(
        target.id,
        scanned_at=first_time,
        stored_at=first_time + timedelta(minutes=1),
    )
    second = make_run(
        target.id,
        scanned_at=first_time + timedelta(hours=1),
        stored_at=first_time + timedelta(hours=1, minutes=1),
    )
    store.save_scan_run(first)
    store.save_scan_run(second)

    metadata = store.list_scan_runs(target.id, limit=1)

    assert metadata == [second.metadata]
    assert store.get_latest_scan_run(target.id) == second
    assert store.list_scan_runs(uuid4()) == []
    assert store.get_latest_scan_run(uuid4()) is None


def test_duplicate_or_orphan_scan_run_is_rejected_atomically(
    store: MonitoringStore,
) -> None:
    target = make_target()
    store.create_target(target)
    run = make_run(
        target.id,
        scanned_at=datetime(2026, 8, 20, 9, 0, tzinfo=UTC),
    )
    store.save_scan_run(run)

    with pytest.raises(StoreConflictError):
        store.save_scan_run(run)

    orphan = make_run(
        uuid4(),
        scanned_at=datetime(2026, 8, 20, 10, 0, tzinfo=UTC),
    )
    with pytest.raises(StoreConflictError):
        store.save_scan_run(orphan)

    assert store.list_scan_runs(target.id) == [run.metadata]
