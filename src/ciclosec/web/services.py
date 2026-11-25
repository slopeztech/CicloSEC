"""Read-only data assembly for the dashboard and its authenticated API."""

from __future__ import annotations

from typing import Any

from ciclosec.assets import services as asset_services
from ciclosec.findings import services as finding_services
from ciclosec.intelligence.models import AdvisoryRecord
from ciclosec.intelligence.services import get_source_freshness
from ciclosec.scans import services as scan_services

ASSET_PAGE_SIZE = 20
SCAN_PAGE_SIZE = 10
FINDING_PAGE_SIZE = 10


def get_dashboard_summary(
    *,
    asset_id: int | None = None,
    affected_status: str | None = None,
    assets_page: int = 1,
    scans_page: int = 1,
    findings_page: int = 1,
) -> dict[str, Any]:
    """Build a bounded dashboard summary without exposing raw scan/provider errors."""
    sources = []
    for provider in AdvisoryRecord.Provider.values:
        freshness = get_source_freshness(provider)
        sources.append(
            {
                "provider": freshness.provider,
                "status": freshness.status,
                "last_attempt_at": freshness.last_attempt_at,
                "last_success_at": freshness.last_success_at,
                "source_updated_at": freshness.source_updated_at,
            }
        )

    return {
        "coverage": asset_services.get_asset_coverage(),
        "assets": asset_services.list_assets(
            limit=ASSET_PAGE_SIZE,
            offset=(assets_page - 1) * ASSET_PAGE_SIZE,
        ),
        "scans": scan_services.list_scan_history(
            asset_id=asset_id,
            limit=SCAN_PAGE_SIZE,
            offset=(scans_page - 1) * SCAN_PAGE_SIZE,
        ),
        "findings": finding_services.list_finding_summaries(
            asset_id=asset_id,
            affected_status=affected_status,
            limit=FINDING_PAGE_SIZE,
            offset=(findings_page - 1) * FINDING_PAGE_SIZE,
        ),
        "sources": sources,
    }
