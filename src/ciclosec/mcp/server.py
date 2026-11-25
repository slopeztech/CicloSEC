"""Local MCP server for CicloSec queries and optional intelligence synchronization."""

from __future__ import annotations

import logging
import os
from typing import Annotated, Literal

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ciclosec.project.settings")

import django
from django.apps import apps

if not apps.ready:
    django.setup()

from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.db import DatabaseError
from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field, StrictBool

from ciclosec.assets import services as asset_services
from ciclosec.common.config import ConfigurationError, McpConfig
from ciclosec.common.models import ConfigurationState
from ciclosec.common.settings_service import get_effective_config
from ciclosec.findings import services as finding_services
from ciclosec.intelligence.manual_sync_service import (
    ManualSyncUnavailable,
    get_manual_sync_status,
    request_manual_sync,
)
from ciclosec.intelligence.models import AdvisoryRecord
from ciclosec.intelligence.services import get_source_freshness
from ciclosec.inventory import services as inventory_services
from ciclosec.mcp.schemas import (
    AssetCoverage,
    AssetPage,
    ComponentPage,
    FindingDecisionResult,
    FindingPage,
    ManualSyncResult,
    ScanRunPage,
    SourceFreshnessResult,
    SourceFreshnessSummary,
)
from ciclosec.scans import services as scan_services

logger = logging.getLogger(__name__)

server = MCPServer(
    "CicloSec",
    version="0.1.0",
    instructions=(
        "Local access to registered assets, SBOM components, scan history, findings, "
        "coverage, and intelligence freshness. An explicitly enabled, administrator-"
        "authenticated tool can request external intelligence synchronization. "
        "This server cannot start scans."
    ),
)
_READ_ONLY = ToolAnnotations(read_only_hint=True, open_world_hint=False)
_INTELLIGENCE_WRITE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=True,
)
_FINDING_DECISION_WRITE = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
PageLimit = Annotated[int, Field(ge=1, le=100, description="Maximum records to return.")]
PageOffset = Annotated[int, Field(ge=0, description="Number of records to skip.")]
AssetId = Annotated[int, Field(gt=0, description="Registered asset identifier.")]
ScanRunId = Annotated[int, Field(gt=0, description="Scan run identifier for the asset.")]
FindingId = Annotated[int, Field(gt=0, description="Persisted finding identifier.")]
FindingDecisionStatus = Literal[
    "open",
    "assigned",
    "accepted_risk",
    "false_positive",
    "closed",
]
AffectedStatus = Literal[
    "confirmed",
    "potential",
    "not_affected",
    "not_applicable",
    "pending_verification",
]


def _mcp_config() -> McpConfig:
    try:
        return get_effective_config().mcp
    except (DatabaseError, ConfigurationError, ConfigurationState.DoesNotExist):
        logger.error("MCP configuration storage or its contents are unavailable.")
        raise RuntimeError("MCP configuration is unavailable.") from None


def _intelligence_operator() -> AbstractBaseUser:
    if not _mcp_config().allow_intelligence_sync:
        raise PermissionError("MCP intelligence synchronization is disabled.")
    username = os.environ.get("CICLOSEC_MCP_ADMIN_USERNAME")
    password = os.environ.get("CICLOSEC_MCP_ADMIN_PASSWORD")
    if not username or not password:
        raise PermissionError("MCP administrator authentication is required.")
    user = authenticate(username=username, password=password)
    if user is None or not user.is_active or not user.is_staff:
        raise PermissionError("MCP administrator authentication failed.")
    return user


def _finding_decision_operator() -> AbstractBaseUser:
    if not _mcp_config().allow_finding_decisions:
        raise PermissionError("MCP human finding decisions are disabled.")
    username = os.environ.get("CICLOSEC_MCP_ADMIN_USERNAME")
    password = os.environ.get("CICLOSEC_MCP_ADMIN_PASSWORD")
    if not username or not password:
        raise PermissionError("MCP administrator authentication is required.")
    user = authenticate(username=username, password=password)
    if user is None or not user.is_active or not user.is_staff:
        raise PermissionError("MCP administrator authentication failed.")
    return user


@server.tool(annotations=_READ_ONLY)
def list_assets(limit: PageLimit = 50, offset: PageOffset = 0) -> AssetPage:
    """List registered assets without exposing repository credentials or source metadata."""
    return AssetPage.model_validate(asset_services.list_assets(limit=limit, offset=offset))


@server.tool(annotations=_READ_ONLY)
def get_asset_coverage() -> AssetCoverage:
    """Summarize scan recency for enabled assets registered in CicloSec."""
    return AssetCoverage.model_validate(asset_services.get_asset_coverage())


@server.tool(annotations=_READ_ONLY)
def list_scan_history(
    asset_id: AssetId | None = None,
    limit: PageLimit = 50,
    offset: PageOffset = 0,
) -> ScanRunPage:
    """List scan status and timing without returning raw output, errors, or metadata."""
    return ScanRunPage.model_validate(
        scan_services.list_scan_history(
            asset_id=asset_id,
            limit=limit,
            offset=offset,
        )
    )


@server.tool(annotations=_READ_ONLY)
def list_sbom_components(
    asset_id: AssetId,
    scan_run_id: ScanRunId | None = None,
    limit: PageLimit = 100,
    offset: PageOffset = 0,
) -> ComponentPage:
    """List normalized components from the latest SBOM or a selected asset scan."""
    return ComponentPage.model_validate(
        inventory_services.list_asset_components(
            asset_id=asset_id,
            scan_run_id=scan_run_id,
            limit=limit,
            offset=offset,
        )
    )


@server.tool(annotations=_READ_ONLY)
def list_findings(
    asset_id: AssetId | None = None,
    affected_status: AffectedStatus | None = None,
    limit: PageLimit = 50,
    offset: PageOffset = 0,
) -> FindingPage:
    """List redacted findings, correlation evidence, and risk explanations."""
    return FindingPage.model_validate(
        finding_services.list_finding_summaries(
            asset_id=asset_id,
            affected_status=affected_status,
            limit=limit,
            offset=offset,
        )
    )


@server.tool(annotations=_FINDING_DECISION_WRITE)
def review_finding(
    finding_id: FindingId,
    status: FindingDecisionStatus,
    reason: Annotated[str, Field(min_length=1, max_length=4000)],
    confirm: StrictBool,
    assignee_id: Annotated[int | None, Field(gt=0)] = None,
) -> FindingDecisionResult:
    """Record an auditable human finding decision after explicit confirmation."""
    if confirm is not True:
        raise ValueError("Explicit confirmation is required.")
    operator = _finding_decision_operator()
    assignee = None
    if assignee_id is not None:
        try:
            assignee = get_user_model().objects.get(pk=assignee_id, is_active=True)
        except get_user_model().DoesNotExist:
            raise ValueError("Assignee is not valid.") from None
    try:
        decision = finding_services.review_finding(
            finding_id=finding_id,
            status=status,
            reason=reason,
            actor=operator,
            assignee=assignee,
        )
    except finding_services.FindingDecisionError as error:
        raise ValueError(str(error)) from None
    except DatabaseError:
        raise RuntimeError("The human finding decision could not be recorded.") from None
    return FindingDecisionResult(
        finding_id=decision.finding_id,
        status=decision.status,
        assignee_id=decision.assignee_id,
        decided_by_id=decision.decided_by_id,
        reason=decision.reason,
    )


@server.tool(annotations=_READ_ONLY)
def get_intelligence_freshness() -> SourceFreshnessResult:
    """Report the current freshness state of each intelligence provider."""
    sources = []
    for provider in AdvisoryRecord.Provider.values:
        freshness = get_source_freshness(provider)
        sources.append(
            SourceFreshnessSummary(
                provider=freshness.provider,
                status=freshness.status,
                last_attempt_at=freshness.last_attempt_at,
                last_success_at=freshness.last_success_at,
                source_updated_at=freshness.source_updated_at,
            )
        )
    return SourceFreshnessResult(sources=sources)


@server.tool(annotations=_READ_ONLY)
def get_manual_intelligence_sync_status() -> ManualSyncResult:
    """Report manually requested intelligence synchronization status to an administrator."""
    operator = _intelligence_operator()
    try:
        return ManualSyncResult.model_validate(get_manual_sync_status(actor=operator))
    except DatabaseError:
        raise RuntimeError("Intelligence synchronization status is unavailable.") from None


@server.tool(annotations=_INTELLIGENCE_WRITE)
def request_intelligence_sync(confirm: StrictBool) -> ManualSyncResult:
    """Request external provider synchronization after explicit administrator confirmation."""
    if confirm is not True:
        raise ValueError("Explicit confirmation is required.")
    operator = _intelligence_operator()
    try:
        return ManualSyncResult.model_validate(request_manual_sync(actor=operator, confirm=True))
    except (DatabaseError, ManualSyncUnavailable):
        raise RuntimeError(
            "Intelligence synchronization is unavailable; inspect its status before retrying."
        ) from None


def main() -> None:
    """Serve the local MCP protocol over stdio."""
    mcp_config = _mcp_config()
    if not mcp_config.enabled:
        raise SystemExit("MCP server is disabled by local configuration.")
    if mcp_config.transport != "stdio":
        raise RuntimeError("CicloSec MCP supports only the local stdio transport.")
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
