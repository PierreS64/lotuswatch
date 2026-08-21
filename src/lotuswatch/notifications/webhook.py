import hashlib
import hmac
import ipaddress
import json
import math
import re
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

import httpx
from pydantic import ValidationError

from lotuswatch.exceptions import NotificationConfigurationError
from lotuswatch.models import (
    NotificationAttemptOutcome,
    NotificationChannel,
    NotificationDeliveryResult,
    NotificationDeliveryStatus,
    NotificationDiagnosticCode,
    NotificationEvent,
    NotificationRetryPolicy,
    NotificationTimeouts,
)
from lotuswatch.notifications.delivery import (
    MAX_NOTIFICATION_SECRET_LENGTH,
    SecretProvider,
    execute_notification_attempts,
)

WEBHOOK_URL_ENVIRONMENT_VARIABLE = "LOTUSWATCH_WEBHOOK_URL"
WEBHOOK_SECRET_ENVIRONMENT_VARIABLE = "LOTUSWATCH_WEBHOOK_SECRET"
WEBHOOK_CONTENT_TYPE = "application/vnd.lotuswatch.notification+json; version=1.0"
WEBHOOK_EVENT_HEADER = "X-LotusWatch-Event-ID"
WEBHOOK_SCHEMA_HEADER = "X-LotusWatch-Notification-Schema"
WEBHOOK_SIGNATURE_HEADER = "X-LotusWatch-Signature"
WEBHOOK_SIGNATURE_VERSION = "v1"
MAX_WEBHOOK_URL_LENGTH = 4_096
MAX_WEBHOOK_PAYLOAD_BYTES = 64 * 1_024

_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_SIGNATURE_PATTERN = re.compile(r"^v1=[0-9a-f]{64}$")
_RETRYABLE_SERVER_STATUSES = {500, 502, 503, 504}
_LOCAL_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


@dataclass(frozen=True, slots=True)
class _WebhookConfiguration:
    url: str
    signing_secret: str | None


class WebhookNotificationSender:
    """Deliver minimal notification events to one locally configured webhook."""

    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        timeouts: NotificationTimeouts | None = None,
        retry_policy: NotificationRetryPolicy | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if transport is not None and not isinstance(transport, httpx.BaseTransport):
            raise NotificationConfigurationError(
                "Webhook transport configuration is invalid."
            )
        if not callable(sleep):
            raise NotificationConfigurationError(
                "Webhook backoff configuration is invalid."
            )
        self._transport = transport
        self._timeouts = _validated_timeouts(
            NotificationTimeouts() if timeouts is None else timeouts
        )
        self._retry_policy = _validated_retry_policy(
            NotificationRetryPolicy() if retry_policy is None else retry_policy
        )
        self._sleep = sleep

    @property
    def channel(self) -> NotificationChannel:
        return NotificationChannel.WEBHOOK

    def deliver(
        self,
        event: NotificationEvent,
        *,
        secrets: SecretProvider,
    ) -> NotificationDeliveryResult:
        try:
            body = serialize_webhook_event(event)
            configuration = _load_configuration(secrets)
            headers = _webhook_headers(
                event,
                body,
                signing_secret=configuration.signing_secret,
            )
        except NotificationConfigurationError:
            return self._terminal_result(
                event,
                NotificationDeliveryStatus.CONFIGURATION_ERROR,
                NotificationDiagnosticCode.CONFIGURATION_INVALID,
            )

        try:
            client = httpx.Client(
                transport=self._transport,
                timeout=httpx.Timeout(
                    connect=self._timeouts.connect_seconds,
                    read=self._timeouts.read_seconds,
                    write=self._timeouts.write_seconds,
                    pool=self._timeouts.pool_seconds,
                ),
                follow_redirects=False,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
                trust_env=False,
            )
        except Exception:  # noqa: BLE001 - sanitize HTTP client construction failures.
            return self._terminal_result(
                event,
                NotificationDeliveryStatus.ERROR,
                NotificationDiagnosticCode.UNEXPECTED_FAILURE,
            )

        def operation(_: int) -> NotificationAttemptOutcome:
            client.cookies.clear()
            try:
                with client.stream(
                    "POST",
                    configuration.url,
                    content=body,
                    headers=headers,
                ) as response:
                    return _response_outcome(response)
            except httpx.TimeoutException:
                return NotificationAttemptOutcome(
                    status=NotificationDeliveryStatus.TIMEOUT,
                    retryable=True,
                    diagnostic=NotificationDiagnosticCode.REQUEST_TIMED_OUT,
                )
            except httpx.TransportError:
                return NotificationAttemptOutcome(
                    status=NotificationDeliveryStatus.CONNECTION_ERROR,
                    retryable=True,
                    diagnostic=NotificationDiagnosticCode.CONNECTION_FAILED,
                )

        try:
            return execute_notification_attempts(
                self.channel,
                event,
                operation,
                retry_policy=self._retry_policy,
                sleep=self._sleep,
            )
        finally:
            with suppress(Exception):
                client.close()

    def _terminal_result(
        self,
        event: NotificationEvent,
        status: NotificationDeliveryStatus,
        diagnostic: NotificationDiagnosticCode,
    ) -> NotificationDeliveryResult:
        return execute_notification_attempts(
            self.channel,
            event,
            lambda _: NotificationAttemptOutcome(
                status=status,
                diagnostic=diagnostic,
            ),
            retry_policy=self._retry_policy,
            sleep=self._sleep,
        )


def serialize_webhook_event(event: NotificationEvent) -> bytes:
    """Serialize one validated event into deterministic bounded JSON bytes."""

    if not isinstance(event, NotificationEvent):
        raise NotificationConfigurationError("Webhook event is invalid.")
    try:
        validated = NotificationEvent.model_validate(event.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationConfigurationError("Webhook event is invalid.") from exc
    body = json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(body) > MAX_WEBHOOK_PAYLOAD_BYTES:
        raise NotificationConfigurationError("Webhook payload exceeds its size limit.")
    return body


def sign_webhook_payload(body: bytes, secret: str) -> str:
    """Return the versioned HMAC-SHA256 signature for exact payload bytes."""

    body = _validated_body(body)
    secret = _validated_signing_secret(secret)
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"{WEBHOOK_SIGNATURE_VERSION}={digest}"


def verify_webhook_signature(body: bytes, signature: str, secret: str) -> bool:
    """Verify a webhook signature using constant-time digest comparison."""

    body = _validated_body(body)
    secret = _validated_signing_secret(secret)
    if (
        not isinstance(signature, str)
        or _SIGNATURE_PATTERN.fullmatch(signature) is None
    ):
        return False
    expected = sign_webhook_payload(body, secret)
    return hmac.compare_digest(expected, signature)


def validate_webhook_url(value: str) -> str:
    """Validate one explicit operator-configured HTTPS webhook endpoint."""

    if not isinstance(value, str) or not value or len(value) > MAX_WEBHOOK_URL_LENGTH:
        raise NotificationConfigurationError("Webhook URL is invalid.")
    if value != value.strip() or any(character.isspace() for character in value):
        raise NotificationConfigurationError("Webhook URL is invalid.")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise NotificationConfigurationError("Webhook URL is invalid.") from exc
    if parsed.scheme.casefold() != "https" or not parsed.netloc:
        raise NotificationConfigurationError("Webhook URL must use HTTPS.")
    if parsed.username is not None or parsed.password is not None:
        raise NotificationConfigurationError(
            "Webhook URL cannot contain embedded credentials."
        )
    if parsed.fragment:
        raise NotificationConfigurationError("Webhook URL cannot contain a fragment.")
    if port not in {None, 443}:
        raise NotificationConfigurationError("Webhook URL port is unsupported.")
    _validate_webhook_host(parsed)
    return value


def _validate_webhook_host(parsed: SplitResult) -> None:
    hostname = parsed.hostname
    if hostname is None:
        raise NotificationConfigurationError("Webhook URL host is invalid.")
    normalized = hostname.casefold().rstrip(".")
    if not normalized or len(normalized) > 253:
        raise NotificationConfigurationError("Webhook URL host is invalid.")
    if normalized == "localhost" or normalized.endswith(_LOCAL_HOST_SUFFIXES):
        raise NotificationConfigurationError("Webhook URL host is not public.")

    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        try:
            ascii_hostname = normalized.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise NotificationConfigurationError(
                "Webhook URL host is invalid."
            ) from exc
        labels = ascii_hostname.split(".")
        if len(labels) < 2 or any(
            _HOST_LABEL_PATTERN.fullmatch(label) is None for label in labels
        ):
            raise NotificationConfigurationError("Webhook URL host is invalid.")
        return

    if not address.is_global:
        raise NotificationConfigurationError("Webhook URL address is not public.")


def _load_configuration(secrets: SecretProvider) -> _WebhookConfiguration:
    if not isinstance(secrets, SecretProvider):
        raise NotificationConfigurationError("Webhook secret provider is invalid.")
    try:
        url_value = secrets.get_secret(
            WEBHOOK_URL_ENVIRONMENT_VARIABLE,
            max_length=MAX_WEBHOOK_URL_LENGTH,
        )
        signing_secret = secrets.get_secret(
            WEBHOOK_SECRET_ENVIRONMENT_VARIABLE,
            required=False,
            max_length=MAX_NOTIFICATION_SECRET_LENGTH,
        )
    except Exception as exc:
        raise NotificationConfigurationError(
            "Webhook environment configuration is invalid."
        ) from exc
    assert url_value is not None
    return _WebhookConfiguration(
        url=validate_webhook_url(url_value),
        signing_secret=signing_secret,
    )


def _webhook_headers(
    event: NotificationEvent,
    body: bytes,
    *,
    signing_secret: str | None,
) -> dict[str, str]:
    headers = {
        "Content-Type": WEBHOOK_CONTENT_TYPE,
        "User-Agent": "LotusWatch-Notification/1.0",
        WEBHOOK_EVENT_HEADER: str(event.event_id),
        WEBHOOK_SCHEMA_HEADER: event.notification_schema_version,
    }
    if signing_secret is not None:
        headers[WEBHOOK_SIGNATURE_HEADER] = sign_webhook_payload(
            body,
            signing_secret,
        )
    return headers


def _response_outcome(response: httpx.Response) -> NotificationAttemptOutcome:
    status = response.status_code
    if 200 <= status < 300:
        return NotificationAttemptOutcome(status=NotificationDeliveryStatus.DELIVERED)
    if status == 429:
        return NotificationAttemptOutcome(
            status=NotificationDeliveryStatus.PROVIDER_REJECTED,
            retryable=True,
            retry_after_seconds=_retry_after_seconds(
                response.headers.get("Retry-After")
            ),
            diagnostic=NotificationDiagnosticCode.PROVIDER_REJECTED,
        )
    if status in _RETRYABLE_SERVER_STATUSES:
        return NotificationAttemptOutcome(
            status=NotificationDeliveryStatus.PROVIDER_REJECTED,
            retryable=True,
            diagnostic=NotificationDiagnosticCode.PROVIDER_REJECTED,
        )
    return NotificationAttemptOutcome(
        status=NotificationDeliveryStatus.PROVIDER_REJECTED,
        diagnostic=NotificationDiagnosticCode.PROVIDER_REJECTED,
    )


def _retry_after_seconds(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        seconds = float(value)
    except ValueError:
        return None
    if not math.isfinite(seconds) or seconds < 0:
        return None
    return min(seconds, 60.0)


def _validated_body(body: bytes) -> bytes:
    if not isinstance(body, bytes):
        raise NotificationConfigurationError("Webhook payload must be bytes.")
    if len(body) > MAX_WEBHOOK_PAYLOAD_BYTES:
        raise NotificationConfigurationError("Webhook payload exceeds its size limit.")
    return body


def _validated_signing_secret(secret: str) -> str:
    if (
        not isinstance(secret, str)
        or not secret.strip()
        or len(secret) > MAX_NOTIFICATION_SECRET_LENGTH
    ):
        raise NotificationConfigurationError("Webhook signing secret is invalid.")
    return secret


def _validated_timeouts(timeouts: NotificationTimeouts) -> NotificationTimeouts:
    if not isinstance(timeouts, NotificationTimeouts):
        raise NotificationConfigurationError(
            "Webhook timeout configuration is invalid."
        )
    try:
        return NotificationTimeouts.model_validate(timeouts.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationConfigurationError(
            "Webhook timeout configuration is invalid."
        ) from exc


def _validated_retry_policy(
    policy: NotificationRetryPolicy,
) -> NotificationRetryPolicy:
    if not isinstance(policy, NotificationRetryPolicy):
        raise NotificationConfigurationError("Webhook retry configuration is invalid.")
    try:
        return NotificationRetryPolicy.model_validate(policy.model_dump(mode="python"))
    except ValidationError as exc:
        raise NotificationConfigurationError(
            "Webhook retry configuration is invalid."
        ) from exc


__all__ = [
    "MAX_WEBHOOK_PAYLOAD_BYTES",
    "MAX_WEBHOOK_URL_LENGTH",
    "WEBHOOK_CONTENT_TYPE",
    "WEBHOOK_EVENT_HEADER",
    "WEBHOOK_SCHEMA_HEADER",
    "WEBHOOK_SECRET_ENVIRONMENT_VARIABLE",
    "WEBHOOK_SIGNATURE_HEADER",
    "WEBHOOK_SIGNATURE_VERSION",
    "WEBHOOK_URL_ENVIRONMENT_VARIABLE",
    "WebhookNotificationSender",
    "serialize_webhook_event",
    "sign_webhook_payload",
    "validate_webhook_url",
    "verify_webhook_signature",
]
