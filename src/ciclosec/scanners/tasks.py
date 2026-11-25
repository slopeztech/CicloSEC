"""Celery task entry points for repository scanning."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from celery import shared_task
from celery.exceptions import Reject

from ciclosec.common.settings_service import get_effective_config
from ciclosec.findings.models import Finding
from ciclosec.scanners.services import (
    ScanAlreadyClaimed,
    ScanCapacityExceeded,
    scan_registered_container_image,
    scan_registered_repository,
)
from ciclosec.scans.models import ScanRun
from ciclosec.scans.services import record_uncertain_dispatch

logger = logging.getLogger(__name__)


def _run_scan(task: Any, scan_run_id: int, scanner: Callable[[int], ScanRun]) -> dict[str, object]:
    try:
        scan_run = scanner(scan_run_id)
        disposition = "claimed"
    except ScanCapacityExceeded as error:
        logger.info("Scan %s: waiting for scan capacity", scan_run_id)
        try:
            raise task.retry(exc=error, countdown=10) from error
        except Reject:
            logger.error("Scan %s: retry delivery could not be confirmed", scan_run_id)
            record_uncertain_dispatch(scan_run_id)
            raise Reject("Scan retry delivery could not be confirmed", requeue=False) from None
    except ScanAlreadyClaimed as error:
        scan_run = error.scan
        disposition = "already_claimed"
        logger.warning(
            "Scan %s: duplicate delivery ignored; recorded state is %s",
            scan_run.pk,
            scan_run.status,
        )
    finding_count = Finding.objects.filter(scan_run=scan_run).count()
    terminal_statuses = {
        ScanRun.Status.SUCCEEDED,
        ScanRun.Status.PARTIAL,
        ScanRun.Status.FAILED,
        ScanRun.Status.CANCELLED,
    }
    notification_config = get_effective_config().notifications
    if (
        disposition == "claimed"
        and scan_run.status in terminal_statuses
        and notification_config.enabled
        and any(channel.type == "console" for channel in notification_config.channels)
    ):
        logger.info(
            "scan_finished scan_id=%s status=%s finding_count=%s",
            scan_run.pk,
            scan_run.status,
            finding_count,
        )
    return {
        "scan_run_id": scan_run.pk,
        "status": scan_run.status,
        "finding_count": finding_count,
        "disposition": disposition,
    }


@shared_task(
    bind=True,
    name="ciclosec.scanners.tasks.scan_repository_task",
    acks_late=True,
    max_retries=None,
)  # type: ignore[untyped-decorator]
def scan_repository_task(self: Any, scan_run_id: int) -> dict[str, object]:
    """Scan a queued repository run and return its durable final status."""
    return _run_scan(self, scan_run_id, scan_registered_repository)


@shared_task(
    bind=True,
    name="ciclosec.scanners.tasks.scan_container_image_task",
    acks_late=True,
    max_retries=None,
)  # type: ignore[untyped-decorator]
def scan_container_image_task(self: Any, scan_run_id: int) -> dict[str, object]:
    """Scan a queued container-image run using only the local Docker daemon."""
    return _run_scan(self, scan_run_id, scan_registered_container_image)


@shared_task(name="ciclosec.scanners.tasks.process_scan_schedules_task")  # type: ignore[untyped-decorator]
def process_scan_schedules_task() -> None:
    """Reconcile explicitly enabled scan schedules."""
    from ciclosec.scans.scheduling import process_schedules

    process_schedules()
