"""Opt-in scheduling, bounded by the same admission rules as manual scans."""

import hashlib
import json
import logging
from datetime import timedelta
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils import timezone
from rest_framework.exceptions import ValidationError

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.common.config import duration_seconds
from ciclosec.common.settings_service import get_effective_config
from ciclosec.scans.api.serializers import ScanRunSerializer
from ciclosec.scans.models import ScanRun, ScanSchedule
from ciclosec.scans.services import (
    ActiveScanError,
    RepositoryScannerNetworkNotAuthorized,
    ScanQueueFullError,
    create_scan_for_locked_asset,
    dispatch_scan,
)

logger = logging.getLogger(__name__)


def repository_snapshot(repository: Repository) -> dict[str, Any]:
    return {
        "kind": Asset.Kind.REPOSITORY,
        "id": repository.pk,
        "provider": repository.provider,
        "owner": repository.owner,
        "repository": repository.repository_name,
        "ref": repository.ref,
        "credential_env": repository.credential_env or settings.CICLOSEC_CONFIG.github.token_env,
        "revision": repository.source_revision,
    }


def image_snapshot(image: ContainerImage) -> dict[str, Any]:
    return {
        "kind": Asset.Kind.CONTAINER_IMAGE,
        "id": image.pk,
        "reference": image.image_reference,
        "revision": image.source_revision,
    }


def source_snapshot(asset: Asset) -> dict[str, Any]:
    ScanRunSerializer().validate_asset(asset)
    try:
        if asset.kind == Asset.Kind.REPOSITORY:
            return repository_snapshot(asset.repository)
        return image_snapshot(asset.container_image)
    except (Repository.DoesNotExist, ContainerImage.DoesNotExist) as error:
        raise ValidationError("The scan source is no longer configured.") from error


def source_fingerprint(source: dict[str, Any]) -> str:
    encoded = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def pause_reason(schedule: ScanSchedule) -> str:
    if schedule.paused_reason:
        return schedule.paused_reason
    last_scan = schedule.last_scan
    if (
        schedule.activated_at is None
        or last_scan is None
        or last_scan.asset_id != schedule.asset_id
    ):
        return "inconsistent"
    if ScanRun.objects.filter(
        asset_id=schedule.asset_id,
        created_at__gte=schedule.activated_at,
        status__in=[ScanRun.Status.FAILED, ScanRun.Status.PARTIAL],
    ).exists():
        return "scan_failed_or_partial"
    if last_scan.status == ScanRun.Status.CANCELLED:
        return "scan_cancelled"
    if last_scan.status not in ScanRun.Status.values:
        return "inconsistent"
    if last_scan.status == ScanRun.Status.SUCCEEDED and last_scan.finished_at is None:
        return "inconsistent"
    return ""


def describe_schedule(asset: Asset) -> dict[str, Any]:
    schedule = ScanSchedule.objects.filter(asset=asset).first()
    try:
        source = source_snapshot(asset)
    except ValidationError:
        source = None
    result: dict[str, Any] = {
        "source": source,
        "source_fingerprint": source_fingerprint(source) if source is not None else None,
    }
    if schedule is None or not schedule.enabled:
        return {**result, "status": "disabled", "last_scan_id": None}
    reason = pause_reason(schedule)
    if not reason:
        if source is None:
            reason = "invalid_source"
        elif source != schedule.source_snapshot:
            reason = "source_changed"
    return {
        **result,
        "status": "paused" if reason else "enabled",
        "reason": reason or None,
        "last_scan_id": schedule.last_scan_id,
    }


def dispatch_scheduled_scan(scan: ScanRun) -> bool:
    from ciclosec.scanners.tasks import scan_container_image_task, scan_repository_task

    send = (
        scan_container_image_task.delay
        if scan.asset.kind == Asset.Kind.CONTAINER_IMAGE
        else scan_repository_task.delay
    )
    return dispatch_scan(scan.pk, send)


def process_schedule(asset_id: int) -> None:
    """Reconcile a single schedule; multiple pollers serialize on its asset."""
    with transaction.atomic():
        asset = Asset.objects.select_for_update().get(pk=asset_id)
        schedule = ScanSchedule.objects.select_for_update().get(asset=asset)
        if not schedule.enabled or schedule.paused_reason:
            return
        if ScanRun.objects.filter(
            asset=asset, status__in=[ScanRun.Status.QUEUED, ScanRun.Status.RUNNING]
        ).exists():
            return
        reason = pause_reason(schedule)
        if not reason:
            try:
                current_source = source_snapshot(asset)
            except ValidationError:
                reason = "invalid_source"
            else:
                if current_source != schedule.source_snapshot:
                    reason = "source_changed"
        if reason:
            schedule.paused_reason = reason
            schedule.save(update_fields=["paused_reason"])
            logger.warning("Scheduled scans for asset %s paused: %s", asset.pk, reason)
            return
        latest = (
            ScanRun.objects.filter(
                asset=asset,
                status=ScanRun.Status.SUCCEEDED,
                finished_at__gte=schedule.activated_at,
            )
            .order_by("-finished_at", "-pk")
            .first()
        )
        if latest is None or latest.finished_at is None:
            schedule.paused_reason = "inconsistent"
            schedule.save(update_fields=["paused_reason"])
            logger.error("Scheduled scans for asset %s have inconsistent history", asset.pk)
            return
        key = "repositories" if asset.kind == Asset.Kind.REPOSITORY else "container_images"
        interval = duration_seconds(get_effective_config().scanning.schedules.get(key, "24h"))
        if latest.finished_at + timedelta(seconds=interval) > timezone.now():
            return
        try:
            scan = create_scan_for_locked_asset(asset)
        except (ActiveScanError, ScanQueueFullError):
            return
        except RepositoryScannerNetworkNotAuthorized:
            schedule.paused_reason = "repository_network_disabled"
            schedule.save(update_fields=["paused_reason"])
            logger.warning(
                "Scheduled scans for asset %s paused: repository network disabled", asset.pk
            )
            return
        scan.metadata = {**scan.metadata, "scheduled_source": schedule.source_snapshot}
        scan.save(update_fields=["metadata"])
        schedule.last_scan = scan
        schedule.save(update_fields=["last_scan"])
        transaction.on_commit(lambda: dispatch_scheduled_scan(scan))


def process_schedules() -> None:
    for asset_id in (
        ScanSchedule.objects.filter(enabled=True, paused_reason="")
        .order_by("asset_id")
        .values_list("asset_id", flat=True)
        .iterator()
    ):
        process_schedule(asset_id)
