"""Staff-only manual synchronization reservations and dispatch."""

from __future__ import annotations

import logging
from typing import Any
from uuid import uuid4

from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, connection, transaction
from django.utils import timezone

from ciclosec.intelligence import tasks
from ciclosec.intelligence.coordination import PUBLICATION_ERRORS
from ciclosec.intelligence.models import AdvisoryRecord, ManualSyncRequest

PROVIDER_TASKS: dict[str, Any] = {
    AdvisoryRecord.Provider.NVD: tasks.sync_nvd_task,
    AdvisoryRecord.Provider.OSV: tasks.sync_osv_task,
    AdvisoryRecord.Provider.GITHUB: tasks.sync_github_advisories_task,
    AdvisoryRecord.Provider.CISA_KEV: tasks.sync_cisa_kev_task,
    AdvisoryRecord.Provider.EPSS: tasks.sync_epss_task,
}
logger = logging.getLogger(__name__)
ACTIVE_STATUSES = [
    ManualSyncRequest.Status.DISPATCHING,
    ManualSyncRequest.Status.QUEUED,
    ManualSyncRequest.Status.UNCERTAIN,
    ManualSyncRequest.Status.RUNNING,
    ManualSyncRequest.Status.RETRYING,
]


class ManualSyncUnavailable(RuntimeError):
    """The database cannot safely reserve manual synchronizations."""


class ManualSyncConfirmationRequired(ValueError):
    """The operation requires an explicit boolean confirmation."""


def _authorize(actor: Any) -> None:
    if not (
        getattr(actor, "is_authenticated", False)
        and getattr(actor, "is_active", False)
        and getattr(actor, "is_staff", False)
    ):
        raise PermissionDenied("An active authenticated staff user is required.")


def _result(
    provider: str, reservation: ManualSyncRequest | None, *, duplicate: bool
) -> dict[str, Any]:
    state = reservation.status if reservation else "conflict"
    error = (
        {
            "uncertain": "delivery_uncertain",
            "failed": "task_failed",
            "conflict": "reservation_conflict",
        }.get(state)
        or (reservation.delivery_error if reservation else "")
        or None
    )
    return {
        "provider": provider,
        "id": reservation.pk if reservation else None,
        "task_id": str(reservation.task_id) if reservation else None,
        "status": state,
        "duplicate": duplicate,
        "error": error,
    }


def request_manual_sync(*, actor: Any, confirm: Any) -> dict[str, Any]:
    """Reserve and dispatch each provider; ambiguous delivery remains reserved.

    Must be called outside an existing transaction so reservations are committed
    before a broker can deliver the tasks.
    """
    _authorize(actor)
    if confirm is not True:
        raise ManualSyncConfirmationRequired("Explicit confirmation is required.")
    if connection.vendor != "postgresql" or not connection.features.supports_partial_indexes:
        raise ManualSyncUnavailable(
            "The database cannot enforce manual synchronization reservations."
        )

    reservations: list[tuple[str, ManualSyncRequest | None, bool]] = []
    with transaction.atomic(durable=True):
        for provider in PROVIDER_TASKS:
            try:
                with transaction.atomic():
                    created = ManualSyncRequest.objects.create(
                        provider=provider,
                        task_id=uuid4(),
                        status=ManualSyncRequest.Status.DISPATCHING,
                    )
                reservations.append((provider, created, False))
            except IntegrityError:
                existing = ManualSyncRequest.objects.filter(
                    provider=provider, status__in=ACTIVE_STATUSES
                ).first()
                if existing is None:
                    # The conflicting reservation may have finished while being read.
                    reservations.append((provider, None, True))
                else:
                    reservations.append((provider, existing, True))

    for provider, reservation, duplicate in reservations:
        if duplicate or reservation is None:
            continue
        try:
            PROVIDER_TASKS[provider].apply_async(task_id=str(reservation.task_id))
        except PUBLICATION_ERRORS:
            # A send exception does not prove that the broker rejected the message.
            logger.error("Intelligence task delivery could not be confirmed for %s", provider)
            state = ManualSyncRequest.Status.UNCERTAIN
        else:
            state = ManualSyncRequest.Status.QUEUED
        ManualSyncRequest.objects.filter(
            pk=reservation.pk, status=ManualSyncRequest.Status.DISPATCHING
        ).update(status=state, updated_at=timezone.now())

    results = []
    for provider, reservation, duplicate in reservations:
        if reservation is not None:
            reservation.refresh_from_db()
        results.append(_result(provider, reservation, duplicate=duplicate))
    return {"providers": results}


def get_manual_sync_status(*, actor: Any) -> dict[str, Any]:
    """Return the last observed manual task for each provider, without raw errors."""
    _authorize(actor)
    results = []
    for provider in PROVIDER_TASKS:
        reservation = ManualSyncRequest.objects.filter(provider=provider).order_by("-id").first()
        if reservation is None:
            results.append(
                {
                    "provider": provider,
                    "id": None,
                    "task_id": None,
                    "status": "never_requested",
                    "duplicate": False,
                    "error": None,
                }
            )
        else:
            results.append(_result(provider, reservation, duplicate=False))
    return {"providers": results}
