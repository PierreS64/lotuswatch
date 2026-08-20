import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, NoReturn
from uuid import UUID

import typer
from rich.console import Console
from rich.markup import escape

from lotuswatch import __version__
from lotuswatch.exceptions import (
    MonitoringRunError,
    MonitoringStoreError,
    StoreConflictError,
    TargetValidationError,
)
from lotuswatch.monitoring import MonitoringExecutionResult, execute_monitoring_run
from lotuswatch.storage import (
    DEFAULT_QUERY_LIMIT,
    MAX_QUERY_LIMIT,
    MonitoredTarget,
    ScanRunMetadata,
    SQLiteMonitoringStore,
)
from lotuswatch.target import normalize_target

PROFILE_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

monitor_app = typer.Typer(
    help="Register and manage local website monitoring targets.",
    no_args_is_help=True,
)

console = Console()

DatabaseOption = Annotated[
    Path | None,
    typer.Option(
        "--database",
        help="Path to the local SQLite monitoring database.",
    ),
]


@monitor_app.command("add")
def add_target(
    name: Annotated[
        str,
        typer.Argument(
            help="Unique case-sensitive profile name (1-64 ASCII letters, digits, ._-)."
        ),
    ],
    target: Annotated[
        str,
        typer.Argument(
            help=(
                "Public HTTP or HTTPS domain or URL to monitor. "
                "Do not include credentials or secrets."
            )
        ),
    ],
    database: DatabaseOption = None,
) -> None:
    """Register a target without running a scan."""

    _validate_profile_name(name)
    try:
        normalized = normalize_target(target)
    except TargetValidationError as exc:
        raise typer.BadParameter(str(exc), param_hint="target") from exc

    store = _open_store(database)
    profile = MonitoredTarget.create(
        name=name,
        original_target=normalized.original,
        normalized_url=normalized.url,
    )

    try:
        created = store.create_target(profile)
    except StoreConflictError as exc:
        raise typer.BadParameter(
            str(exc),
            param_hint="name/target",
        ) from exc
    except MonitoringStoreError as exc:
        _raise_storage_error(exc)

    console.print(
        f"[green]Added monitoring target:[/green] [bold]{escape(created.name)}[/bold]"
    )
    console.print(f"Target: [cyan]{escape(created.normalized_url)}[/cyan]")
    console.print("No scan was run.")


@monitor_app.command("list")
def list_targets(
    database: DatabaseOption = None,
    limit: Annotated[
        int,
        typer.Option(
            "--limit",
            min=1,
            max=MAX_QUERY_LIMIT,
            help="Maximum number of profiles to display.",
        ),
    ] = DEFAULT_QUERY_LIMIT,
) -> None:
    """List registered targets in deterministic profile-name order."""

    store = _open_store(database)
    try:
        profiles = store.list_targets(limit=limit)
        latest_runs: dict[UUID, ScanRunMetadata | None] = {}
        for profile in profiles:
            run_metadata = store.list_scan_runs(profile.id, limit=1)
            latest_runs[profile.id] = run_metadata[0] if run_metadata else None
    except MonitoringStoreError as exc:
        _raise_storage_error(exc)

    if not profiles:
        console.print("[yellow]No monitoring targets registered.[/yellow]")
        return

    console.print(f"[bold]Monitoring targets ({len(profiles)})[/bold]")

    for index, profile in enumerate(profiles):
        latest = latest_runs[profile.id]
        if index:
            console.print()
        console.print(f"Name: [bold]{escape(profile.name)}[/bold]")
        console.print(
            f"Canonical target: [cyan]{escape(profile.normalized_url)}[/cyan]"
        )
        console.print(f"State: {'enabled' if profile.enabled else 'disabled'}")
        console.print(f"Created (UTC): {_display_timestamp(profile.created_at)}")
        last_run = "Never" if latest is None else _display_timestamp(latest.scanned_at)
        console.print(f"Last run (UTC): {last_run}")


@monitor_app.command("run")
def run_target(
    name: Annotated[str, typer.Argument(help="Enabled profile name to scan.")],
    database: DatabaseOption = None,
) -> None:
    """Scan one profile, store the report, and compare its previous run."""

    _validate_profile_name(name)
    store = _open_store(database)
    try:
        result = execute_monitoring_run(
            store,
            name,
            lotuswatch_version=__version__,
        )
    except MonitoringRunError as exc:
        raise typer.BadParameter(str(exc), param_hint="name") from exc
    except MonitoringStoreError as exc:
        _raise_storage_error(exc)

    _render_monitoring_run(result)


@monitor_app.command("enable")
def enable_target(
    name: Annotated[str, typer.Argument(help="Profile name to enable.")],
    database: DatabaseOption = None,
) -> None:
    """Enable a monitoring target without changing its history."""

    _set_target_state(name, enabled=True, database=database)


@monitor_app.command("disable")
def disable_target(
    name: Annotated[str, typer.Argument(help="Profile name to disable.")],
    database: DatabaseOption = None,
) -> None:
    """Disable a monitoring target without changing its history."""

    _set_target_state(name, enabled=False, database=database)


def _set_target_state(
    name: str,
    *,
    enabled: bool,
    database: Path | None,
) -> None:
    _validate_profile_name(name)
    store = _open_store(database)

    try:
        profile = store.get_target_by_name(name)
        if profile is None:
            raise typer.BadParameter(
                "Monitoring target profile was not found.",
                param_hint="name",
            )
        updated = store.set_target_enabled(profile.id, enabled=enabled)
    except MonitoringStoreError as exc:
        _raise_storage_error(exc)

    if updated is None:
        raise typer.BadParameter(
            "Monitoring target profile was not found.",
            param_hint="name",
        )

    state = "enabled" if enabled else "disabled"
    console.print(
        f"[green]Monitoring target {state}:[/green] [bold]{escape(updated.name)}[/bold]"
    )
    console.print("Existing scan history was preserved.")


def _open_store(database: Path | None) -> SQLiteMonitoringStore:
    store = SQLiteMonitoringStore(database)
    try:
        store.initialize()
    except MonitoringStoreError as exc:
        raise typer.BadParameter(str(exc), param_hint="--database") from exc
    return store


def _validate_profile_name(name: str) -> None:
    if not PROFILE_NAME_PATTERN.fullmatch(name):
        raise typer.BadParameter(
            "Profile name must contain 1 to 64 letters, digits, dots, "
            "underscores, or hyphens and must start with a letter or digit.",
            param_hint="name",
        )


def _raise_storage_error(error: MonitoringStoreError) -> NoReturn:
    raise typer.BadParameter(str(error), param_hint="--database") from error


def _render_monitoring_run(result: MonitoringExecutionResult) -> None:
    scan_status = (
        "COMPLETE"
        if result.scan.completed_checks == result.scan.recorded_checks
        else "INCOMPLETE"
    )
    status_style = "green" if scan_status == "COMPLETE" else "yellow"

    console.print("[bold green]LotusWatch[/bold green] monitoring run stored")
    console.print(f"Profile: [bold]{escape(result.profile.name)}[/bold]")
    console.print(f"Target: [cyan]{escape(result.profile.normalized_url)}[/cyan]")
    console.print(f"Run ID: {result.stored_run.metadata.id}")
    console.print(
        f"Scan status: [{status_style}]{scan_status}[/{status_style}] "
        f"({result.scan.completed_checks}/{result.scan.recorded_checks} "
        "checks completed)"
    )
    console.print(f"Findings: {len(result.scan.findings)}")

    if result.skipped_baseline_candidates:
        console.print(
            "[yellow]Skipped earlier incompatible or non-earlier run "
            f"candidates: {result.skipped_baseline_candidates}[/yellow]"
        )

    if result.comparison is None:
        console.print("\n[bold]Initial baseline[/bold]")
        console.print(
            "This is the first compatible stored run; no comparison is available yet."
        )
        return

    assert result.baseline_run is not None
    summary = result.comparison.summary
    console.print("\n[bold]Comparison with previous run[/bold]")
    console.print(f"Baseline run ID: {result.baseline_run.metadata.id}")
    console.print(f"Added: {summary.added}")
    console.print(f"Resolved: {summary.resolved}")
    console.print(f"Changed: {summary.changed}")
    console.print(f"Unchanged: {summary.unchanged}")


def _display_timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


__all__ = ["PROFILE_NAME_PATTERN", "monitor_app"]
