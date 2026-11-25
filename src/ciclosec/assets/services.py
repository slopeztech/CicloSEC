"""Asset source updates, summaries, and scan coverage."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from django.db import transaction
from django.db.models import OuterRef, Subquery
from django.utils import timezone

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.common.config import duration_seconds
from ciclosec.common.settings_service import get_effective_config
from ciclosec.scans.models import ScanRun

SourceStatus = Literal["matched", "changed", "unknown"]
_SOURCE_FIELDS = (
    "repository__id",
    "repository__provider",
    "repository__owner",
    "repository__repository_name",
    "repository__ref",
    "container_image__id",
    "container_image__image_reference",
    "container_image__source_revision",
)


def update_repository_source(
    repository: Repository,
    *,
    asset: Asset | None = None,
    provider: str | None = None,
    owner: str | None = None,
    repository_name: str | None = None,
    ref: str | None = None,
    credential_env: str | None = None,
) -> Repository:
    """Track every managed source change, including changes later reverted."""
    with transaction.atomic():
        repository = Repository.objects.select_for_update().get(pk=repository.pk)
        values = {
            "asset": repository.asset if asset is None else asset,
            "provider": repository.provider if provider is None else provider,
            "owner": repository.owner if owner is None else owner,
            "repository_name": (
                repository.repository_name if repository_name is None else repository_name
            ),
            "ref": repository.ref if ref is None else ref,
            "credential_env": repository.credential_env
            if credential_env is None
            else credential_env,
        }
        changed = [key for key, value in values.items() if getattr(repository, key) != value]
        if changed:
            for key in changed:
                setattr(repository, key, values[key])
            repository.source_revision += 1
            repository.save(update_fields=[*changed, "source_revision"])
        return repository


def update_container_image_source(
    image: ContainerImage,
    *,
    image_reference: str | None = None,
    asset: Asset | None = None,
) -> ContainerImage:
    """Update an image source without retaining a digest for an older revision."""
    with transaction.atomic():
        image = ContainerImage.objects.select_for_update().get(pk=image.pk)
        reference = image.image_reference if image_reference is None else image_reference
        asset = image.asset if asset is None else asset
        if image.image_reference != reference or image.asset_id != asset.pk:
            image.image_reference = reference
            image.asset = asset
            image.resolved_digest = ""
            image.digest_resolved_at = None
            image.source_revision += 1
            image.save(
                update_fields=[
                    "image_reference",
                    "asset",
                    "resolved_digest",
                    "digest_resolved_at",
                    "source_revision",
                ]
            )
        return image


def list_assets(*, limit: int, offset: int) -> dict[str, Any]:
    """Return a bounded page of registered asset metadata."""
    assets = Asset.objects.order_by("name", "id")
    total = assets.count()
    items = list(
        assets.values(
            "id",
            "name",
            "kind",
            "environment",
            "exposure",
            "enabled",
            "created_at",
        )[offset : offset + limit]
    )
    return {"total": total, "limit": limit, "offset": offset, "items": items}


def _source_coverage_status(asset: dict[str, Any], metadata: object) -> SourceStatus:
    if not isinstance(metadata, dict):
        return "unknown"
    if asset["kind"] == Asset.Kind.REPOSITORY:
        source = metadata.get("repository_source")
        fields = ("provider", "owner", "repository", "ref")
        if not isinstance(source, dict) or any(
            not isinstance(source.get(field), str) or not source[field] for field in fields
        ):
            return "unknown"
        if asset["repository__id"] is None:
            return "changed"
        actual = (
            asset["repository__provider"],
            asset["repository__owner"],
            asset["repository__repository_name"],
            asset["repository__ref"],
        )
        return "matched" if tuple(source[field] for field in fields) == actual else "changed"
    if asset["kind"] == Asset.Kind.CONTAINER_IMAGE:
        reference = metadata.get("image_reference")
        if not isinstance(reference, str) or not reference:
            return "unknown"
        if (
            asset["container_image__id"] is None
            or reference != asset["container_image__image_reference"]
        ):
            return "changed"
        revision = metadata.get("image_source_revision")
        if type(revision) is not int or revision < 0:
            return "unknown"
        return "matched" if revision == asset["container_image__source_revision"] else "changed"
    raise ValueError(f"Unsupported persisted asset kind: {asset['kind']}")


def get_scan_source_status(*, asset_id: int, metadata: object) -> SourceStatus:
    """Compare a scan's recorded source identity to the current asset source."""
    asset = Asset.objects.filter(pk=asset_id).values("kind", *_SOURCE_FIELDS).first()
    if asset is None:
        raise ValueError("Asset does not exist")
    return _source_coverage_status(asset, metadata)


def scan_source_status_for_asset(*, asset: Asset, metadata: object) -> SourceStatus:
    """Compare scan metadata using an asset with its source relations loaded."""
    data: dict[str, Any] = {"kind": asset.kind}
    if asset.kind == Asset.Kind.REPOSITORY:
        repository = getattr(asset, "repository", None)
        data["repository__id"] = repository.pk if repository is not None else None
        if repository is not None:
            data.update(
                {
                    "repository__provider": repository.provider,
                    "repository__owner": repository.owner,
                    "repository__repository_name": repository.repository_name,
                    "repository__ref": repository.ref,
                }
            )
    elif asset.kind == Asset.Kind.CONTAINER_IMAGE:
        image = getattr(asset, "container_image", None)
        data["container_image__id"] = image.pk if image is not None else None
        if image is not None:
            data["container_image__image_reference"] = image.image_reference
            data["container_image__source_revision"] = image.source_revision
    return _source_coverage_status(data, metadata)


def get_asset_coverage(*, now: datetime | None = None) -> dict[str, Any]:
    """Summarize the latest scan state for enabled, registered assets."""
    latest_runs = ScanRun.objects.filter(asset_id=OuterRef("pk")).order_by(
        "-created_at",
        "-pk",
    )
    assets = Asset.objects.filter(enabled=True).annotate(
        latest_status=Subquery(latest_runs.values("status")[:1]),
        latest_created_at=Subquery(latest_runs.values("created_at")[:1]),
        latest_finished_at=Subquery(latest_runs.values("finished_at")[:1]),
        latest_metadata=Subquery(latest_runs.values("metadata")[:1]),
    )
    current_time = now or timezone.now()
    scan_schedules = get_effective_config().scanning.schedules
    schedule_keys = {
        Asset.Kind.REPOSITORY: "repositories",
        Asset.Kind.CONTAINER_IMAGE: "container_images",
    }
    freshness_windows = {
        kind: duration_seconds(scan_schedules.get(schedule_key, "24h"))
        for kind, schedule_key in schedule_keys.items()
    }
    counts = {
        "current": 0,
        "partial": 0,
        "failed": 0,
        "in_progress": 0,
        "stale": 0,
        "never_scanned": 0,
        "source_changed": 0,
        "source_unknown": 0,
    }
    enabled_total = assets.count()
    for asset in assets.values(
        "kind",
        "latest_status",
        "latest_created_at",
        "latest_finished_at",
        "latest_metadata",
        *_SOURCE_FIELDS,
    ):
        status = asset["latest_status"]
        if status is None:
            counts["never_scanned"] += 1
            continue
        if status in {ScanRun.Status.QUEUED, ScanRun.Status.RUNNING}:
            counts["in_progress"] += 1
            continue
        if status in {ScanRun.Status.FAILED, ScanRun.Status.CANCELLED}:
            counts["failed"] += 1
            continue
        if status not in {ScanRun.Status.SUCCEEDED, ScanRun.Status.PARTIAL}:
            raise ValueError(f"Unsupported persisted scan status: {status}")
        source_status = _source_coverage_status(asset, asset["latest_metadata"])
        if source_status != "matched":
            counts[f"source_{source_status}"] += 1
            continue
        last_scan_at = asset["latest_finished_at"] or asset["latest_created_at"]
        if last_scan_at is None:
            raise ValueError("Completed scan is missing its timestamp")
        window = freshness_windows[asset["kind"]]
        is_current = (current_time - last_scan_at).total_seconds() <= window
        if not is_current:
            counts["stale"] += 1
        elif status == ScanRun.Status.PARTIAL:
            counts["partial"] += 1
        else:
            counts["current"] += 1

    return {
        "scope": "enabled_registered_assets",
        "total_registered": Asset.objects.count(),
        "enabled_total": enabled_total,
        "disabled_total": Asset.objects.filter(enabled=False).count(),
        "counts": counts,
        "freshness_windows_seconds": freshness_windows,
    }
