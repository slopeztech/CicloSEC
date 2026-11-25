"""PostgreSQL transaction fencing for all Celery provider deliveries."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextvars import ContextVar
from functools import wraps
from typing import Any
from uuid import NAMESPACE_URL, UUID, uuid5

from celery.exceptions import Reject, Retry
from django.db import DatabaseError, connection, transaction
from django.utils import timezone
from kombu.exceptions import KombuError
from redis.exceptions import RedisError

from ciclosec.intelligence.models import ManualSyncRequest, ProviderTaskAttempt
from ciclosec.intelligence.providers import ProviderSyncError

logger = logging.getLogger(__name__)

PROVIDER_LOCKS = {"nvd": 1, "osv": 2, "github_advisories": 3, "cisa_kev": 4, "epss": 5}
LOCK_NAMESPACE = 1129530179
PUBLICATION_ERRORS = (KombuError, RedisError, OSError)
PROVIDER_LOCK_HELD: ContextVar[bool] = ContextVar("intelligence_provider_lock_held", default=False)


def _manual_task_id(value: Any) -> UUID | None:
    try:
        return UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        return None


def coordinated_provider(provider: str) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Serialize and deduplicate Celery deliveries in one database transaction."""

    def decorate(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapped(task: Any, *args: Any, **kwargs: Any) -> Any:
            task_id = task.request.id
            if task_id is None:
                # Direct .run() is not a Celery delivery.
                return func(task, *args, **kwargs)
            if connection.vendor != "postgresql":
                raise RuntimeError("Intelligence workers require PostgreSQL coordination.")
            if not isinstance(task_id, str) or not 1 <= len(task_id) <= 255:
                raise ValueError("Invalid intelligence task ID.")
            attempt = task.request.retries
            deferred_error = None
            result = None
            try:
                with transaction.atomic(durable=True):
                    with connection.cursor() as cursor:
                        cursor.execute(
                            "SELECT pg_advisory_xact_lock(%s, %s)",
                            [LOCK_NAMESPACE, PROVIDER_LOCKS[provider]],
                        )
                    lookup = {"provider": provider, "task_id": task_id, "attempt": attempt}
                    if ProviderTaskAttempt.objects.filter(**lookup).exists():
                        return {"provider": provider, "status": "duplicate"}
                    lock_context = PROVIDER_LOCK_HELD.set(True)
                    try:
                        try:
                            result = func(task, *args, **kwargs)
                        except (ProviderSyncError, Retry, Reject) as error:
                            deferred_error = error
                    finally:
                        PROVIDER_LOCK_HELD.reset(lock_context)
                    ProviderTaskAttempt.objects.create(**lookup)
            except Exception:
                # The transaction rolled back, including any in-transaction task state.
                try:
                    manual_id = _manual_task_id(task_id)
                    if manual_id is not None:
                        ManualSyncRequest.objects.filter(
                            task_id=manual_id,
                            attempt=attempt,
                            claim_token=getattr(task.request, "ciclosec_claim_token", None),
                            status__in=[
                                "dispatching",
                                "queued",
                                "uncertain",
                                "running",
                                "retrying",
                            ],
                        ).update(status="failed", updated_at=timezone.now())
                except DatabaseError:
                    logger.error("Could not record intelligence task failure for %s", provider)
                raise
            if deferred_error is not None:
                raise deferred_error
            return result

        return wrapped

    return decorate


def publish_after_commit(
    task: Any, target: Any, *, action: str, payload: dict[str, Any] | None = None, **kwargs: Any
) -> None:
    """Publish after data commits; preserve an explicit sanitized delivery warning."""
    task_id = task.request.id
    provider = target.name
    if action == "continuation" and task_id:
        kwargs["task_id"] = str(uuid5(NAMESPACE_URL, f"ciclosec:{task_id}:{task.request.retries}"))
    manual_id = _manual_task_id(task_id)
    if manual_id is not None:
        ManualSyncRequest.objects.filter(task_id=manual_id).update(
            delivery_error="followup_delivery_pending", updated_at=timezone.now()
        )

    def publish() -> None:
        try:
            if action == "reevaluation":
                target.delay()
            else:
                target.apply_async(**kwargs)
        except PUBLICATION_ERRORS:
            logger.error("Intelligence %s delivery could not be confirmed for %s", action, provider)
            if payload is not None:
                payload["delivery_error"] = "followup_delivery_uncertain"
            if manual_id is not None:
                try:
                    ManualSyncRequest.objects.filter(task_id=manual_id).update(
                        delivery_error="followup_delivery_uncertain", updated_at=timezone.now()
                    )
                except DatabaseError:
                    logger.error("Could not record intelligence delivery warning")
        else:
            if manual_id is not None:
                try:
                    ManualSyncRequest.objects.filter(
                        task_id=manual_id, delivery_error="followup_delivery_pending"
                    ).update(delivery_error="", updated_at=timezone.now())
                except DatabaseError:
                    logger.error("Could not record intelligence delivery confirmation")

    if task_id is None:
        publish()
    else:
        transaction.on_commit(publish)
