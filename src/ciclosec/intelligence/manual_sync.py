"""Tracking for explicit, manually requested provider synchronization."""

from __future__ import annotations

import logging
from functools import wraps
from typing import Any
from uuid import UUID, uuid4

from celery.exceptions import Reject, Retry
from django.db import connection
from django.utils import timezone
from kombu.exceptions import KombuError
from redis.exceptions import RedisError

from ciclosec.intelligence.coordination import PROVIDER_LOCK_HELD
from ciclosec.intelligence.models import ManualSyncRequest

logger = logging.getLogger(__name__)


def _task_id(task: Any) -> UUID | None:
    try:
        return UUID(str(task.request.id))
    except (ValueError, TypeError, AttributeError):
        return None


def retry_manual_sync(task: Any, *, exc: Exception, countdown: int) -> Any:
    """Reserve the next attempt before Celery publishes its retry message."""
    task_id = _task_id(task)
    if task_id is None:
        return task.retry(exc=exc, countdown=countdown)
    attempt = task.request.retries
    requests = ManualSyncRequest.objects.filter(task_id=task_id)
    claim_token = getattr(task.request, "ciclosec_claim_token", None)
    if claim_token is not None:
        requests = requests.filter(claim_token=claim_token)
    tracked = requests.filter(status=ManualSyncRequest.Status.RUNNING, attempt=attempt).update(
        status=ManualSyncRequest.Status.RETRYING,
        attempt=attempt + 1,
        updated_at=timezone.now(),
    )
    try:
        return task.retry(exc=exc, countdown=countdown)
    except Retry:
        raise
    except (Reject, KombuError, RedisError, OSError):
        logger.error("Intelligence retry delivery could not be confirmed")
        if tracked:
            requests.filter(status=ManualSyncRequest.Status.RETRYING, attempt=attempt + 1).update(
                status=ManualSyncRequest.Status.UNCERTAIN, updated_at=timezone.now()
            )
        raise


def track_manual_sync(func: Any) -> Any:
    """Track only tasks reserved by the manual API; leave other callers untouched."""

    @wraps(func)
    def wrapped(task: Any, *args: Any, **kwargs: Any) -> Any:
        task_id = _task_id(task)
        if task_id is None:
            return func(task, *args, **kwargs)

        requests = ManualSyncRequest.objects.filter(task_id=task_id)
        if not requests.exists():
            return func(task, *args, **kwargs)
        attempt = task.request.retries
        statuses = [
            ManualSyncRequest.Status.DISPATCHING,
            ManualSyncRequest.Status.QUEUED,
            ManualSyncRequest.Status.UNCERTAIN,
            ManualSyncRequest.Status.RETRYING,
        ]
        if PROVIDER_LOCK_HELD.get():
            # The provider transaction owns the advisory lock. Commit the claim
            # separately so monitoring can observe a long-running import.
            statuses.append(ManualSyncRequest.Status.RUNNING)
            claim_token = uuid4()
            status_connection = connection.copy()
            try:
                table = status_connection.ops.quote_name(ManualSyncRequest._meta.db_table)
                with status_connection.cursor() as cursor:
                    cursor.execute(
                        f"UPDATE {table} SET status = %s, claim_token = %s, updated_at = %s, "
                        "attempt = %s WHERE task_id = %s AND "
                        "((attempt = %s AND status = ANY(%s)) OR "
                        "(status = %s AND attempt = %s))",
                        [
                            "running",
                            claim_token,
                            timezone.now(),
                            attempt,
                            task_id,
                            attempt,
                            statuses,
                            "running",
                            attempt - 1,
                        ],
                    )
                    claimed = cursor.rowcount
            finally:
                status_connection.close()
            if claimed:
                task.request.ciclosec_claim_token = claim_token
                requests = requests.filter(claim_token=claim_token)
        else:
            claimed = requests.filter(attempt=attempt, status__in=statuses).update(
                status=ManualSyncRequest.Status.RUNNING, updated_at=timezone.now()
            )
        if not claimed:
            return {"status": "duplicate"}
        try:
            result = func(task, *args, **kwargs)
        except Retry:
            raise
        except Exception:
            requests.filter(status=ManualSyncRequest.Status.RUNNING, attempt=attempt).update(
                status=ManualSyncRequest.Status.FAILED, updated_at=timezone.now()
            )
            raise
        outcome = result.get("status")
        if outcome not in {
            ManualSyncRequest.Status.SUCCEEDED,
            ManualSyncRequest.Status.PARTIAL,
            ManualSyncRequest.Status.FAILED,
        }:
            outcome = ManualSyncRequest.Status.FAILED
        requests.filter(status=ManualSyncRequest.Status.RUNNING, attempt=attempt).update(
            status=outcome, updated_at=timezone.now()
        )
        return result

    return wrapped
