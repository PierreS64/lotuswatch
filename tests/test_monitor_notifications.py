from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

import pytest
from rich.text import Text
from typer.testing import CliRunner, Result

import lotuswatch.monitoring_cli
import lotuswatch.notifications.monitoring
from lotuswatch.cli import app
from lotuswatch.exceptions import NotificationDeliveryError
from lotuswatch.models import (
    Finding,
    NotificationChannel,
    NotificationDeliveryAttempt,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
    NotificationDiagnosticCode,
    ScanReport,
    Severity,
    compare_reports,
)
from lotuswatch.monitoring import MonitoringExecutionResult
from lotuswatch.notifications import (
    NotificationSender,
    SecretProvider,
    execute_monitoring_notifications,
)
from lotuswatch.scanner import ScanExecutionResult
from lotuswatch.storage import MonitoredTarget, SQLiteMonitoringStore, StoredScanRun

runner = CliRunner()
TARGET = "https://example.com/"
PROFILE_ID = UUID("10000000-0000-4000-8000-000000000001")
BASELINE_RUN_ID = UUID("20000000-0000-4000-8000-000000000001")
CURRENT_RUN_ID = UUID("20000000-0000-4000-8000-000000000002")
BASELINE_TIME = datetime(2026, 8, 21, 8, 0, tzinfo=UTC)
CURRENT_TIME = datetime(2026, 8, 21, 9, 0, tzinfo=UTC)


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


def finding(
    finding_id: str,
    severity: Severity,
    *,
    title: str | None = None,
    evidence_value: str = "same",
) -> Finding:
    return Finding(
        id=finding_id,
        severity=severity,
        title=title or f"Synthetic {finding_id}",
        description="Synthetic monitoring notification finding.",
        evidence={"private_detail": evidence_value},
        recommendation="Review the synthetic finding.",
    )


def report(findings: list[Finding], *, scanned_at: datetime) -> ScanReport:
    return ScanReport.create(
        lotuswatch_version="0.1.0-alpha.5",
        original_target="example.com",
        normalized_url=TARGET,
        scanned_at=scanned_at,
        checks=[{"name": "synthetic", "status": "passed"}],
        findings=findings,
    )


def monitoring_result(
    baseline_findings: list[Finding] | None,
    current_findings: list[Finding],
    *,
    profile: MonitoredTarget | None = None,
) -> MonitoringExecutionResult:
    selected_profile = profile or MonitoredTarget.create(
        name="production",
        original_target="example.com",
        normalized_url=TARGET,
        target_id=PROFILE_ID,
        created_at=BASELINE_TIME,
    )
    current_report = report(current_findings, scanned_at=CURRENT_TIME)
    current_run = StoredScanRun.create(
        target_id=selected_profile.id,
        report=current_report,
        run_id=CURRENT_RUN_ID,
        stored_at=CURRENT_TIME,
    )

    if baseline_findings is None:
        baseline_run = None
        comparison = None
    else:
        baseline_report = report(baseline_findings, scanned_at=BASELINE_TIME)
        baseline_run = StoredScanRun.create(
            target_id=selected_profile.id,
            report=baseline_report,
            run_id=BASELINE_RUN_ID,
            stored_at=BASELINE_TIME,
        )
        comparison = compare_reports(
            baseline_report,
            current_report,
            compared_at=CURRENT_TIME,
        )

    scan = cast(
        ScanExecutionResult,
        type(
            "SyntheticScan",
            (),
            {
                "completed_checks": 1,
                "recorded_checks": 1,
                "findings": current_findings,
            },
        )(),
    )
    return MonitoringExecutionResult(
        profile=selected_profile,
        scan=scan,
        stored_run=current_run,
        baseline_run=baseline_run,
        comparison=comparison,
        skipped_baseline_candidates=0,
    )


class ExplodingSecretProvider:
    def get_secret(
        self,
        name: str,
        *,
        required: bool = True,
        max_length: int = 8_192,
    ) -> str | None:
        raise AssertionError(
            f"secret must not be resolved: {name}/{required}/{max_length}"
        )


class FakeSender:
    def __init__(
        self,
        channel: NotificationChannel,
        calls: list[NotificationChannel],
        *,
        status: NotificationDeliveryStatus = NotificationDeliveryStatus.DELIVERED,
    ) -> None:
        self._channel = channel
        self._calls = calls
        self._status = status

    @property
    def channel(self) -> NotificationChannel:
        return self._channel

    def deliver(
        self,
        event,  # type: ignore[no-untyped-def]
        *,
        secrets: SecretProvider,
    ) -> NotificationDeliveryResult:
        assert isinstance(secrets, SecretProvider)
        self._calls.append(self.channel)
        diagnostic = (
            None
            if self._status is NotificationDeliveryStatus.DELIVERED
            else NotificationDiagnosticCode.PROVIDER_REJECTED
        )
        return NotificationDeliveryResult(
            event_id=event.event_id,
            channel=self.channel,
            status=self._status,
            attempts=[
                NotificationDeliveryAttempt(
                    attempt_number=1,
                    status=self._status,
                    diagnostic=diagnostic,
                )
            ],
        )


def test_service_initial_baseline_does_not_touch_senders_or_secrets() -> None:
    result = execute_monitoring_notifications(
        monitoring_result(None, [finding("LW-TEST-001", Severity.CRITICAL)]),
        [NotificationChannel.WEBHOOK],
        Severity.INFO,
        secrets=cast(SecretProvider, ExplodingSecretProvider()),
        senders=cast(list[NotificationSender], [object()]),
    )

    assert result.selection.event is None
    assert result.delivery is None
    assert result.delivery_required is False


def test_service_below_threshold_does_not_touch_senders_or_secrets() -> None:
    result = execute_monitoring_notifications(
        monitoring_result([], [finding("LW-TEST-001", Severity.LOW)]),
        [NotificationChannel.TELEGRAM],
        Severity.HIGH,
        secrets=cast(SecretProvider, ExplodingSecretProvider()),
        senders=cast(list[NotificationSender], [object()]),
    )

    assert result.selection.event is None
    assert result.delivery is None


def test_service_dry_run_selects_event_without_touching_provider() -> None:
    result = execute_monitoring_notifications(
        monitoring_result([], [finding("LW-TEST-001", Severity.HIGH)]),
        [NotificationChannel.WEBHOOK],
        Severity.MEDIUM,
        dry_run=True,
        secrets=cast(SecretProvider, ExplodingSecretProvider()),
        senders=cast(list[NotificationSender], [object()]),
    )

    assert result.selection.event is not None
    assert result.dry_run is True
    assert result.delivery is None
    assert result.delivery_required is False


def test_service_delivers_channels_in_selected_order_and_continues_failures() -> None:
    calls: list[NotificationChannel] = []
    senders = [
        FakeSender(
            NotificationChannel.TELEGRAM,
            calls,
            status=NotificationDeliveryStatus.PROVIDER_REJECTED,
        ),
        FakeSender(NotificationChannel.WEBHOOK, calls),
    ]

    result = execute_monitoring_notifications(
        monitoring_result([], [finding("LW-TEST-001", Severity.HIGH)]),
        [NotificationChannel.TELEGRAM, NotificationChannel.WEBHOOK],
        Severity.MEDIUM,
        senders=senders,
    )

    assert calls == [NotificationChannel.TELEGRAM, NotificationChannel.WEBHOOK]
    assert result.delivery is not None
    assert [item.status for item in result.delivery.results] == [
        NotificationDeliveryStatus.PROVIDER_REJECTED,
        NotificationDeliveryStatus.DELIVERED,
    ]
    assert result.has_delivery_failures is True


@pytest.mark.parametrize(
    "channels",
    [
        [],
        [NotificationChannel.WEBHOOK, NotificationChannel.WEBHOOK],
        [cast(NotificationChannel, "webhook")],
    ],
)
def test_service_rejects_invalid_channel_selection(
    channels: list[NotificationChannel],
) -> None:
    with pytest.raises(NotificationDeliveryError):
        execute_monitoring_notifications(
            monitoring_result(None, []),
            channels,
            Severity.MEDIUM,
        )


def test_service_rejects_sender_order_mismatch_only_when_delivery_is_required() -> None:
    with pytest.raises(NotificationDeliveryError, match="order"):
        execute_monitoring_notifications(
            monitoring_result([], [finding("LW-TEST-001", Severity.HIGH)]),
            [NotificationChannel.WEBHOOK],
            Severity.MEDIUM,
            senders=[FakeSender(NotificationChannel.TELEGRAM, [])],
        )


@pytest.mark.parametrize(
    "arguments",
    [
        ["--notify", "webhook"],
        ["--notify-on", "medium"],
        ["--notification-dry-run"],
        [
            "--notify",
            "webhook",
            "--notify",
            "webhook",
            "--notify-on",
            "medium",
        ],
        ["--notify", "invalid", "--notify-on", "medium"],
        ["--notify", "webhook", "--notify-on", "invalid"],
    ],
)
def test_cli_rejects_invalid_notification_options_before_storage(
    tmp_path: Path,
    arguments: list[str],
) -> None:
    database_path = tmp_path / "monitoring.db"

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            *arguments,
            *database_arguments(database_path),
        ],
    )

    assert result.exit_code == 2
    assert not database_path.exists()


def test_cli_without_notification_options_preserves_existing_behavior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    selected_result = monitoring_result(None, [])
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: selected_result,
    )
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_notifications",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("notifications must remain disabled by default")
        ),
    )

    result = runner.invoke(
        app,
        ["monitor", "run", "production", *database_arguments(database_path)],
    )

    assert result.exit_code == 0
    assert "Notifications" not in plain_output(result)


def test_cli_initial_baseline_skips_every_channel_without_provider_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: monitoring_result(
            None,
            [finding("LW-TEST-001", Severity.CRITICAL)],
        ),
    )
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "WebhookNotificationSender",
        lambda: (_ for _ in ()).throw(AssertionError("provider must not be created")),
    )
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "TelegramNotificationSender",
        lambda: (_ for _ in ()).throw(AssertionError("provider must not be created")),
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            "--notify",
            "webhook",
            "--notify",
            "telegram",
            "--notify-on",
            "info",
            *database_arguments(database_path),
        ],
    )
    output = compact_output(result)

    assert result.exit_code == 0
    assert "webhook: SKIPPED (initial baseline)" in output
    assert "telegram: SKIPPED (initial baseline)" in output


def test_cli_below_threshold_skips_provider_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: monitoring_result(
            [],
            [finding("LW-TEST-001", Severity.LOW)],
        ),
    )
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "WebhookNotificationSender",
        lambda: (_ for _ in ()).throw(AssertionError("provider must not be created")),
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            "--notify",
            "webhook",
            "--notify-on",
            "high",
            *database_arguments(database_path),
        ],
    )

    assert result.exit_code == 0
    assert "webhook: SKIPPED (no matching findings)" in compact_output(result)


def test_cli_dry_run_stores_and_renders_event_without_provider_or_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    private_value = "private-notification-secret"
    selected_result = monitoring_result(
        [],
        [
            finding(
                "LW-TEST-001",
                Severity.HIGH,
                title="[bold]Synthetic title[/bold]",
            )
        ],
    )
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: selected_result,
    )
    monkeypatch.setenv("LOTUSWATCH_WEBHOOK_SECRET", private_value)
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "WebhookNotificationSender",
        lambda: (_ for _ in ()).throw(AssertionError("provider must not be created")),
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            "--notify",
            "webhook",
            "--notify-on",
            "medium",
            "--notification-dry-run",
            *database_arguments(database_path),
        ],
    )
    output = plain_output(result)

    assert result.exit_code == 0
    assert output.index(str(CURRENT_RUN_ID)) < output.index("Notifications")
    assert "NOTIFICATION DRY RUN" in output
    assert "LW-TEST-001" in output
    assert "[bold]Synthetic title[/bold]" in output
    assert "webhook: DRY RUN (provider request not sent)" in output
    assert private_value not in output


def test_cli_delivers_multiple_channels_in_cli_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    calls: list[NotificationChannel] = []
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: monitoring_result(
            [],
            [finding("LW-TEST-001", Severity.HIGH)],
        ),
    )
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "TelegramNotificationSender",
        lambda: FakeSender(NotificationChannel.TELEGRAM, calls),
    )
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "WebhookNotificationSender",
        lambda: FakeSender(NotificationChannel.WEBHOOK, calls),
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            "--notify",
            "telegram",
            "--notify",
            "webhook",
            "--notify-on",
            "medium",
            *database_arguments(database_path),
        ],
    )
    output = compact_output(result)

    assert result.exit_code == 0
    assert calls == [NotificationChannel.TELEGRAM, NotificationChannel.WEBHOOK]
    assert output.index("telegram: DELIVERED") < output.index("webhook: DELIVERED")


def test_cli_missing_provider_configuration_returns_three_after_stored_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    selected_result = monitoring_result(
        [],
        [finding("LW-TEST-001", Severity.HIGH)],
    )
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: selected_result,
    )
    monkeypatch.delenv("LOTUSWATCH_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("LOTUSWATCH_WEBHOOK_SECRET", raising=False)

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            "--notify",
            "webhook",
            "--notify-on",
            "medium",
            *database_arguments(database_path),
        ],
    )
    output = compact_output(result)

    assert result.exit_code == 3
    assert str(CURRENT_RUN_ID) in output
    assert "webhook: CONFIGURATION ERROR" in output
    assert "stored run was preserved" in output


def test_cli_delivery_failure_returns_three_and_preserves_stored_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    store = SQLiteMonitoringStore(database_path)
    store.initialize()
    profile = store.create_target(
        MonitoredTarget.create(
            name="production",
            original_target="example.com",
            normalized_url=TARGET,
            target_id=PROFILE_ID,
            created_at=BASELINE_TIME,
        )
    )
    selected_result = monitoring_result(
        [],
        [finding("LW-TEST-001", Severity.HIGH)],
        profile=profile,
    )
    assert selected_result.baseline_run is not None
    store.save_scan_run(selected_result.baseline_run)
    store.save_scan_run(selected_result.stored_run)
    calls: list[NotificationChannel] = []
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: selected_result,
    )
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "WebhookNotificationSender",
        lambda: FakeSender(
            NotificationChannel.WEBHOOK,
            calls,
            status=NotificationDeliveryStatus.CONFIGURATION_ERROR,
        ),
    )
    monkeypatch.setattr(
        lotuswatch.notifications.monitoring,
        "TelegramNotificationSender",
        lambda: FakeSender(NotificationChannel.TELEGRAM, calls),
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            "--notify",
            "webhook",
            "--notify",
            "telegram",
            "--notify-on",
            "medium",
            *database_arguments(database_path),
        ],
    )
    output = compact_output(result)

    assert result.exit_code == 3
    assert calls == [NotificationChannel.WEBHOOK, NotificationChannel.TELEGRAM]
    assert output.index(str(CURRENT_RUN_ID)) < output.index(
        "webhook: CONFIGURATION ERROR"
    )
    assert "telegram: DELIVERED" in output
    assert "stored run was preserved" in output

    history = runner.invoke(
        app,
        [
            "monitor",
            "history",
            "production",
            *database_arguments(database_path),
        ],
    )
    shown = runner.invoke(
        app,
        [
            "monitor",
            "show",
            str(CURRENT_RUN_ID),
            *database_arguments(database_path),
        ],
    )
    assert history.exit_code == 0
    assert str(CURRENT_RUN_ID) in compact_output(history)
    assert shown.exit_code == 0


def test_cli_controlled_notification_orchestration_error_returns_three(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "monitoring.db"
    selected_result = monitoring_result(
        [],
        [finding("LW-TEST-001", Severity.HIGH)],
    )
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_run",
        lambda *_args, **_kwargs: selected_result,
    )
    monkeypatch.setattr(
        lotuswatch.monitoring_cli,
        "execute_monitoring_notifications",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            NotificationDeliveryError("private notification detail")
        ),
    )

    result = runner.invoke(
        app,
        [
            "monitor",
            "run",
            "production",
            "--notify",
            "webhook",
            "--notify-on",
            "medium",
            *database_arguments(database_path),
        ],
    )
    output = compact_output(result)

    assert result.exit_code == 3
    assert str(CURRENT_RUN_ID) in output
    assert "stored run was preserved" in output
    assert "private notification detail" not in output
    assert "Traceback" not in output
