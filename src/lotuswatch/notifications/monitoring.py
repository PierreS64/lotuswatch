from collections.abc import Sequence
from dataclasses import dataclass

from lotuswatch.exceptions import NotificationDeliveryError
from lotuswatch.models import (
    MAX_NOTIFICATION_CHANNELS,
    NotificationChannel,
    NotificationDeliveryBatch,
    NotificationSelection,
    Severity,
)
from lotuswatch.monitoring import MonitoringExecutionResult
from lotuswatch.notifications.delivery import (
    NotificationSender,
    SecretProvider,
    deliver_notification_channels,
)
from lotuswatch.notifications.policy import select_monitoring_notification
from lotuswatch.notifications.telegram import TelegramNotificationSender
from lotuswatch.notifications.webhook import WebhookNotificationSender


@dataclass(frozen=True, slots=True)
class MonitoringNotificationExecution:
    """Policy selection and optional delivery for one stored monitoring run."""

    selection: NotificationSelection
    channels: tuple[NotificationChannel, ...]
    threshold: Severity
    dry_run: bool
    delivery: NotificationDeliveryBatch | None

    @property
    def delivery_required(self) -> bool:
        return self.selection.event is not None and not self.dry_run

    @property
    def has_delivery_failures(self) -> bool:
        return self.delivery is not None and self.delivery.has_failures


def execute_monitoring_notifications(
    result: MonitoringExecutionResult,
    channels: Sequence[NotificationChannel],
    threshold: Severity,
    *,
    dry_run: bool = False,
    secrets: SecretProvider | None = None,
    senders: Sequence[NotificationSender] | None = None,
) -> MonitoringNotificationExecution:
    """Select and optionally deliver notifications after a stored monitoring run."""

    validated_channels = _validated_channels(channels)
    if not isinstance(threshold, Severity):
        raise NotificationDeliveryError("Notification threshold is invalid.")
    if not isinstance(dry_run, bool):
        raise NotificationDeliveryError("Notification dry-run state is invalid.")

    selection = select_monitoring_notification(result, threshold)
    if selection.event is None or dry_run:
        return MonitoringNotificationExecution(
            selection=selection,
            channels=validated_channels,
            threshold=threshold,
            dry_run=dry_run,
            delivery=None,
        )

    selected_senders = (
        _default_senders(validated_channels)
        if senders is None
        else _validated_senders(senders, validated_channels)
    )
    delivery = deliver_notification_channels(
        selection.event,
        selected_senders,
        secrets=secrets,
    )
    return MonitoringNotificationExecution(
        selection=selection,
        channels=validated_channels,
        threshold=threshold,
        dry_run=False,
        delivery=delivery,
    )


def _validated_channels(
    channels: Sequence[NotificationChannel],
) -> tuple[NotificationChannel, ...]:
    if not isinstance(channels, Sequence) or isinstance(channels, (str, bytes)):
        raise NotificationDeliveryError("Notification channels must be a sequence.")
    if not 1 <= len(channels) <= MAX_NOTIFICATION_CHANNELS:
        raise NotificationDeliveryError(
            f"Notification channel count must be between 1 and "
            f"{MAX_NOTIFICATION_CHANNELS}."
        )

    validated: list[NotificationChannel] = []
    observed: set[NotificationChannel] = set()
    for channel in channels:
        if not isinstance(channel, NotificationChannel):
            raise NotificationDeliveryError("Notification channel is invalid.")
        if channel in observed:
            raise NotificationDeliveryError(
                "Notification channels contain a duplicate selection."
            )
        observed.add(channel)
        validated.append(channel)
    return tuple(validated)


def _default_senders(
    channels: tuple[NotificationChannel, ...],
) -> tuple[NotificationSender, ...]:
    factories = {
        NotificationChannel.WEBHOOK: WebhookNotificationSender,
        NotificationChannel.TELEGRAM: TelegramNotificationSender,
    }
    return tuple(factories[channel]() for channel in channels)


def _validated_senders(
    senders: Sequence[NotificationSender],
    channels: tuple[NotificationChannel, ...],
) -> tuple[NotificationSender, ...]:
    if not isinstance(senders, Sequence) or isinstance(senders, (str, bytes)):
        raise NotificationDeliveryError("Notification senders must be a sequence.")
    if len(senders) != len(channels):
        raise NotificationDeliveryError(
            "Notification senders do not match the selected channels."
        )
    validated = tuple(senders)
    for sender, channel in zip(validated, channels, strict=True):
        if not isinstance(sender, NotificationSender):
            raise NotificationDeliveryError("Notification sender is invalid.")
        try:
            sender_channel = sender.channel
        except Exception as exc:
            raise NotificationDeliveryError(
                "Notification sender channel is invalid."
            ) from exc
        if sender_channel is not channel:
            raise NotificationDeliveryError(
                "Notification sender order does not match selected channels."
            )
    return validated


__all__ = [
    "MonitoringNotificationExecution",
    "execute_monitoring_notifications",
]
