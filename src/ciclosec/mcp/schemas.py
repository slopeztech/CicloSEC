"""Structured output models for CicloSec MCP tools."""

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict


class MCPOutput(BaseModel):
    """Reject undeclared fields from query-service results."""

    model_config = ConfigDict(extra="forbid")


class AssetSummary(MCPOutput):
    id: int
    name: str
    kind: str
    environment: str
    exposure: str
    enabled: bool
    created_at: datetime


class AssetPage(MCPOutput):
    total: int
    limit: int
    offset: int
    items: list[AssetSummary]


class CoverageCounts(MCPOutput):
    current: int
    partial: int
    failed: int
    in_progress: int
    stale: int
    never_scanned: int
    source_changed: int
    source_unknown: int


class AssetCoverage(MCPOutput):
    scope: str
    total_registered: int
    enabled_total: int
    disabled_total: int
    counts: CoverageCounts
    freshness_windows_seconds: dict[str, int]


class ScanRunSummary(MCPOutput):
    id: int
    asset_id: int
    asset_name: str
    scanner_name: str
    scanner_version: str
    status: str
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime
    duration_seconds: float | None
    warning_count: int
    has_error: bool


class ScanRunPage(MCPOutput):
    total: int
    limit: int
    offset: int
    items: list[ScanRunSummary]


class ComponentSummary(MCPOutput):
    component_id: int
    name: str
    ecosystem: str
    component_type: str
    version: str
    relationship: str
    scope: str


class ComponentPage(MCPOutput):
    asset_id: int
    scan_run_id: int | None
    sbom_format: str | None
    sbom_checksum_sha256: str | None
    sbom_generated_at: datetime | None
    source_status: Literal["matched", "changed", "unknown"] | None
    total: int
    limit: int
    offset: int
    items: list[ComponentSummary]


class CorrelationEvidence(MCPOutput):
    provider: str
    advisory_id: str
    source_status: str
    package: str
    ecosystem: str
    package_matches: bool | None
    version_result: bool | None


class RiskAssessmentSummary(MCPOutput):
    score: int | None
    level: str
    policy_version: str
    factors: dict[str, Any]
    explanation: str
    assessed_at: datetime


class FindingSummary(MCPOutput):
    id: int
    asset_id: int
    asset_name: str
    scan_run_id: int
    asset_source_status: Literal["matched", "changed", "unknown"]
    vulnerability_id: int | None
    canonical_id: str | None
    source: str
    kind: str
    external_id: str
    aliases: list[str]
    package_name: str
    package_version: str
    severity: str
    title: str
    source_path: str
    line_number: int | None
    affected_status: str
    confidence: str
    evaluated_at: datetime | None
    correlation_evidence: list[CorrelationEvidence]
    risk_assessment: RiskAssessmentSummary | None
    decision: dict[str, Any] | None = None
    decision_events: list[dict[str, Any]] = []


class FindingPage(MCPOutput):
    total: int
    limit: int
    offset: int
    items: list[FindingSummary]


class SourceFreshnessSummary(MCPOutput):
    provider: str
    status: str
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    source_updated_at: datetime | None


class SourceFreshnessResult(MCPOutput):
    sources: list[SourceFreshnessSummary]


class ManualSyncProvider(MCPOutput):
    provider: str
    id: int | None
    task_id: str | None
    status: str
    duplicate: bool
    error: str | None


class ManualSyncResult(MCPOutput):
    providers: list[ManualSyncProvider]


class FindingDecisionResult(MCPOutput):
    finding_id: int
    status: str
    assignee_id: int | None
    decided_by_id: int
    reason: str
