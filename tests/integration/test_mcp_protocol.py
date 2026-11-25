"""MCP protocol and stdio integration tests using the official Python SDK."""

import asyncio
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from django.conf import settings
from django.utils import timezone
from mcp.client import ClientSession
from mcp.client._memory import InMemoryTransport
from mcp.client.stdio import StdioServerParameters, stdio_client

from ciclosec.intelligence.services import SourceFreshness
from ciclosec.mcp import server as mcp_server

PROJECT_ROOT = Path(__file__).parents[2]
READ_ONLY_TOOLS = {
    "list_assets",
    "get_asset_coverage",
    "list_scan_history",
    "list_sbom_components",
    "list_findings",
    "get_intelligence_freshness",
}


def test_official_mcp_client_calls_read_only_tools_and_rejects_unsafe_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = timezone.now()
    asset_id = 42
    scan_id = 84

    def list_assets(*, limit: int, offset: int) -> dict[str, Any]:
        return {
            "total": 1,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": asset_id,
                    "name": "mcp-protocol-repository",
                    "kind": "repository",
                    "environment": "test",
                    "exposure": "unknown",
                    "enabled": True,
                    "created_at": now,
                }
            ],
        }

    def get_asset_coverage() -> dict[str, Any]:
        return {
            "scope": "enabled_registered_assets",
            "total_registered": 1,
            "enabled_total": 1,
            "disabled_total": 0,
            "counts": {
                "current": 1,
                "partial": 0,
                "failed": 0,
                "in_progress": 0,
                "stale": 0,
                "never_scanned": 0,
                "source_changed": 0,
                "source_unknown": 0,
            },
            "freshness_windows_seconds": {"repository": 86400},
        }

    def list_scan_history(*, asset_id: int | None, limit: int, offset: int) -> dict[str, Any]:
        return {
            "total": 1,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": scan_id,
                    "asset_id": asset_id,
                    "asset_name": "mcp-protocol-repository",
                    "scanner_name": "protocol-test",
                    "scanner_version": "1.0",
                    "status": "succeeded",
                    "started_at": now,
                    "finished_at": now,
                    "created_at": now,
                    "duration_seconds": 0.0,
                    "warning_count": 0,
                    "has_error": False,
                }
            ],
        }

    def list_components(
        *,
        asset_id: int,
        scan_run_id: int | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        if asset_id == 2_147_483_647:
            raise ValueError("Asset does not exist")
        return {
            "asset_id": asset_id,
            "scan_run_id": scan_id if scan_run_id is None else scan_run_id,
            "sbom_format": "cyclonedx",
            "sbom_checksum_sha256": "b" * 64,
            "sbom_generated_at": now,
            "source_status": "matched",
            "total": 2,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "component_id": 1,
                    "name": "Flask",
                    "ecosystem": "PyPI",
                    "component_type": "library",
                    "version": "3.0.0",
                    "relationship": "direct",
                    "scope": "required",
                },
                {
                    "component_id": 2,
                    "name": "Werkzeug",
                    "ecosystem": "PyPI",
                    "component_type": "library",
                    "version": "3.0.0",
                    "relationship": "transitive",
                    "scope": "required",
                },
            ],
        }

    def list_findings(
        *,
        asset_id: int | None,
        affected_status: str | None,
        limit: int,
        offset: int,
    ) -> dict[str, Any]:
        return {
            "total": 1,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": 99,
                    "asset_id": asset_id,
                    "asset_name": "mcp-protocol-repository",
                    "scan_run_id": scan_id,
                    "asset_source_status": "matched",
                    "vulnerability_id": 1,
                    "canonical_id": "CVE-2026-0099",
                    "source": "trivy",
                    "kind": "vulnerability",
                    "external_id": "CVE-2026-0099",
                    "aliases": [],
                    "package_name": "test-package",
                    "package_version": "1.0.0",
                    "severity": "HIGH",
                    "title": "Protocol test finding",
                    "source_path": "",
                    "line_number": None,
                    "affected_status": affected_status or "confirmed",
                    "confidence": "high",
                    "evaluated_at": now,
                    "correlation_evidence": [],
                    "risk_assessment": None,
                    "decision": None,
                    "decision_events": [],
                }
            ],
        }

    def get_source_freshness(provider: str) -> SourceFreshness:
        return SourceFreshness(
            provider=provider,
            status="unknown",
            last_attempt_at=None,
            last_success_at=None,
            source_updated_at=None,
            last_error="",
        )

    monkeypatch.setattr(mcp_server.asset_services, "list_assets", list_assets)
    monkeypatch.setattr(mcp_server.asset_services, "get_asset_coverage", get_asset_coverage)
    monkeypatch.setattr(mcp_server.scan_services, "list_scan_history", list_scan_history)
    monkeypatch.setattr(mcp_server.inventory_services, "list_asset_components", list_components)
    monkeypatch.setattr(mcp_server.finding_services, "list_finding_summaries", list_findings)
    monkeypatch.setattr(mcp_server, "get_source_freshness", get_source_freshness)
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "allow_intelligence_sync", False)
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "allow_finding_decisions", False)

    async def exercise_client() -> tuple[list[str], set[str], dict[str, Any], list[Any]]:
        async with InMemoryTransport(mcp_server.server) as streams:
            async with ClientSession(*streams) as client:
                await client.initialize()
                tools = await client.list_tools()
                tool_names = {tool.name for tool in tools.tools}
                read_only_tool_names = {
                    tool.name
                    for tool in tools.tools
                    if tool.annotations is not None and tool.annotations.read_only_hint
                }
                responses = {
                    "list_assets": await client.call_tool("list_assets", {"limit": 1, "offset": 0}),
                    "get_asset_coverage": await client.call_tool("get_asset_coverage", {}),
                    "list_scan_history": await client.call_tool(
                        "list_scan_history",
                        {"asset_id": asset_id, "limit": 10, "offset": 0},
                    ),
                    "list_sbom_components": await client.call_tool(
                        "list_sbom_components",
                        {"asset_id": asset_id, "limit": 10, "offset": 0},
                    ),
                    "list_findings": await client.call_tool(
                        "list_findings", {"asset_id": asset_id, "limit": 10, "offset": 0}
                    ),
                    "get_intelligence_freshness": await client.call_tool(
                        "get_intelligence_freshness", {}
                    ),
                }
                unsafe = [
                    await client.call_tool("list_assets", {"limit": 101}),
                    await client.call_tool("list_sbom_components", {"asset_id": 2_147_483_647}),
                    await client.call_tool("request_intelligence_sync", {"confirm": True}),
                    await client.call_tool(
                        "review_finding",
                        {
                            "finding_id": 2_147_483_647,
                            "status": "accepted_risk",
                            "reason": "Protocol test",
                            "confirm": True,
                        },
                    ),
                ]
                payloads = {
                    name: response.structured_content for name, response in responses.items()
                }
                return sorted(tool_names), read_only_tool_names, payloads, unsafe

    tool_names, read_only_tool_names, payloads, unsafe = asyncio.run(exercise_client())

    assert READ_ONLY_TOOLS <= set(tool_names)
    assert READ_ONLY_TOOLS <= read_only_tool_names
    assert "run_scan" not in tool_names
    assert all(payloads[name] is not None for name in READ_ONLY_TOOLS)
    assert payloads["list_assets"]["items"][0]["name"] == "mcp-protocol-repository"
    assert payloads["list_assets"]["limit"] == 1
    assert payloads["list_scan_history"]["items"][0]["id"] == scan_id
    assert payloads["list_sbom_components"]["total"] == 2
    assert payloads["list_findings"]["items"][0]["external_id"] == "CVE-2026-0099"
    assert payloads["get_intelligence_freshness"]["sources"]
    assert all(response.is_error for response in unsafe)


def test_stdio_entrypoint_is_discoverable_by_official_mcp_client(tmp_path: Path) -> None:
    example_config = PROJECT_ROOT / "config" / "ciclosec.yaml.example"
    config = yaml.safe_load(example_config.read_text(encoding="utf-8"))
    config["mcp"]["enabled"] = True
    config["mcp"]["allow_intelligence_sync"] = False
    config["mcp"]["allow_finding_decisions"] = False
    config_path = tmp_path / "mcp-test.yaml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    env = {
        "PYTHONPATH": str(PROJECT_ROOT / "src"),
        "CICLOSEC_CONFIG_PATH": str(config_path),
        "CICLOSEC_DJANGO_SECRET_KEY": "stdio-test-key-not-for-production",
        "CICLOSEC_DATABASE_URL": f"sqlite:///{(tmp_path / 'mcp.sqlite3').as_posix()}",
        "CICLOSEC_REDIS_URL": "redis://127.0.0.1:6379/0",
    }
    subprocess.run(
        [sys.executable, "manage.py", "migrate", "--noinput"],
        cwd=PROJECT_ROOT,
        env={**os.environ, **env},
        check=True,
        capture_output=True,
        text=True,
    )
    parameters = StdioServerParameters(
        command=sys.executable,
        args=["-m", "ciclosec.mcp.server"],
        cwd=PROJECT_ROOT,
        env=env,
    )

    async def discover_tools() -> set[str]:
        async with stdio_client(parameters) as streams:
            async with ClientSession(*streams) as client:
                await client.initialize()
                result = await client.list_tools()
                return {tool.name for tool in result.tools}

    assert READ_ONLY_TOOLS <= asyncio.run(discover_tools())
