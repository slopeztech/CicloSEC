"""Read-only SBOM inventory queries."""

from __future__ import annotations

from typing import Any

from ciclosec.assets.models import Asset
from ciclosec.assets.services import get_scan_source_status
from ciclosec.inventory.models import ComponentOccurrence, SBOMDocument
from ciclosec.scans.models import ScanRun


def list_asset_components(
    *,
    asset_id: int,
    scan_run_id: int | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Return normalized component identities from one asset's selected SBOM."""
    if not Asset.objects.filter(pk=asset_id).exists():
        raise ValueError("Asset does not exist")
    if scan_run_id is not None:
        scan_run = ScanRun.objects.filter(pk=scan_run_id, asset_id=asset_id).first()
        if scan_run is None:
            raise ValueError("Scan run does not belong to the requested asset")
        document = (
            SBOMDocument.objects.filter(scan_run=scan_run)
            .select_related("scan_run")
            .order_by("-generated_at", "-id")
            .first()
        )
    else:
        document = (
            SBOMDocument.objects.filter(scan_run__asset_id=asset_id)
            .select_related("scan_run")
            .order_by("-scan_run__created_at", "-generated_at", "-id")
            .first()
        )

    occurrences = (
        ComponentOccurrence.objects.filter(sbom_document=document)
        .select_related("component")
        .order_by("component__name", "version", "id")
        if document is not None
        else ComponentOccurrence.objects.none()
    )
    total = occurrences.count()
    items = [
        {
            "component_id": occurrence.component_id,
            "name": occurrence.component.name,
            "ecosystem": occurrence.component.ecosystem,
            "component_type": occurrence.component.component_type,
            "version": occurrence.version,
            "relationship": occurrence.relationship,
            "scope": occurrence.scope,
        }
        for occurrence in occurrences[offset : offset + limit]
    ]
    return {
        "asset_id": asset_id,
        "scan_run_id": document.scan_run_id if document is not None else scan_run_id,
        "sbom_format": document.format if document is not None else None,
        "sbom_checksum_sha256": document.checksum_sha256 if document is not None else None,
        "sbom_generated_at": document.generated_at if document is not None else None,
        "source_status": (
            get_scan_source_status(asset_id=asset_id, metadata=document.scan_run.metadata)
            if document is not None
            else None
        ),
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": items,
    }
