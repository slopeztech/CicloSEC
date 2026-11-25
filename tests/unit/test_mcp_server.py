"""MCP tool registration and read-only contract tests."""

import asyncio

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import DatabaseError
from mcp.server.mcpserver.exceptions import ToolError

from ciclosec.mcp import server as mcp_server

pytestmark = pytest.mark.usefixtures("configuration_state")


def test_registered_tools_separate_queries_from_intelligence_write() -> None:
    tools = asyncio.run(mcp_server.server.list_tools())
    tools_by_name = {tool.name: tool for tool in tools}

    assert set(tools_by_name) == {
        "list_assets",
        "get_asset_coverage",
        "list_scan_history",
        "list_sbom_components",
        "list_findings",
        "get_intelligence_freshness",
        "get_manual_intelligence_sync_status",
        "request_intelligence_sync",
        "review_finding",
    }
    assert "run_scan" not in tools_by_name
    for tool in tools:
        assert tool.annotations is not None
        assert tool.annotations.read_only_hint is (
            tool.name not in {"request_intelligence_sync", "review_finding"}
        )
        assert tool.output_schema is not None
    assert tools_by_name["request_intelligence_sync"].annotations.open_world_hint is True


def test_main_requires_mcp_to_be_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "enabled", False)
    monkeypatch.setattr(
        mcp_server.server,
        "run",
        lambda **kwargs: pytest.fail("disabled MCP server must not run"),
    )

    with pytest.raises(SystemExit, match="MCP server is disabled"):
        mcp_server.main()


def test_main_uses_stdio_transport_when_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "enabled", True)
    transports: list[str] = []
    monkeypatch.setattr(
        mcp_server.server,
        "run",
        lambda *, transport: transports.append(transport),
    )

    mcp_server.main()

    assert transports == ["stdio"]


@pytest.mark.django_db
def test_mcp_intelligence_write_requires_enabled_authenticated_active_staff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = get_user_model().objects.create_user(
        username="mcp-admin", password="test-password", is_staff=True
    )
    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_USERNAME", "mcp-admin")
    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_PASSWORD", "test-password")
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "allow_intelligence_sync", False)
    with pytest.raises(PermissionError, match="disabled"):
        mcp_server._intelligence_operator()
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "allow_intelligence_sync", True)
    assert mcp_server._intelligence_operator().pk == user.pk

    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_PASSWORD", "wrong")
    with pytest.raises(PermissionError, match="authentication failed"):
        mcp_server._intelligence_operator()
    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_PASSWORD", "test-password")
    user.is_staff = False
    user.save(update_fields=["is_staff"])
    with pytest.raises(PermissionError, match="authentication failed"):
        mcp_server._intelligence_operator()
    user.is_staff = True
    user.is_active = False
    user.save(update_fields=["is_staff", "is_active"])
    with pytest.raises(PermissionError, match="authentication failed"):
        mcp_server._intelligence_operator()
    monkeypatch.delenv("CICLOSEC_MCP_ADMIN_PASSWORD")
    with pytest.raises(PermissionError, match="authentication is required"):
        mcp_server._intelligence_operator()


@pytest.mark.django_db
def test_mcp_intelligence_sync_requires_confirmation_and_uses_authenticated_staff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = get_user_model().objects.create_user(
        username="mcp-admin", password="test-password", is_staff=True
    )
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "allow_intelligence_sync", True)
    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_USERNAME", "mcp-admin")
    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_PASSWORD", "test-password")
    calls = []

    def submit(*, actor: object, confirm: bool) -> dict[str, object]:
        calls.append((actor, confirm))
        return {
            "providers": [
                {
                    "provider": "nvd",
                    "id": 1,
                    "task_id": "test-task",
                    "status": "queued",
                    "duplicate": False,
                    "error": None,
                }
            ]
        }

    monkeypatch.setattr(mcp_server, "request_manual_sync", submit)
    with pytest.raises(ValueError, match="confirmation"):
        mcp_server.request_intelligence_sync(confirm=False)
    assert calls == []
    result = mcp_server.request_intelligence_sync(confirm=True)
    assert calls == [(user, True)]
    assert result.providers[0].status == "queued"
    assert "test-password" not in result.model_dump_json()


@pytest.mark.django_db
def test_mcp_intelligence_sync_redacts_database_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    user = get_user_model().objects.create_user(username="mcp-admin", is_staff=True)
    monkeypatch.setattr(mcp_server, "_intelligence_operator", lambda: user)

    def fail(**kwargs: object) -> None:
        raise DatabaseError("internal-database-detail")

    monkeypatch.setattr(mcp_server, "request_manual_sync", fail)
    with pytest.raises(RuntimeError, match="inspect its status") as error:
        mcp_server.request_intelligence_sync(confirm=True)
    assert "internal-database-detail" not in str(error.value)


def test_mcp_protocol_rejects_non_boolean_confirmation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        mcp_server,
        "_intelligence_operator",
        lambda: pytest.fail("invalid confirmation must not authorize or send a request"),
    )
    with pytest.raises(ToolError, match="valid boolean"):
        asyncio.run(mcp_server.server.call_tool("request_intelligence_sync", {"confirm": "true"}))


@pytest.mark.django_db
def test_mcp_finding_review_requires_opt_in_confirmation_and_staff(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = get_user_model().objects.create_user(
        username="mcp-reviewer", password="test-password", is_staff=True
    )
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "allow_finding_decisions", False)
    with pytest.raises(PermissionError, match="disabled"):
        mcp_server._finding_decision_operator()

    monkeypatch.setattr(settings.CICLOSEC_CONFIG.mcp, "allow_finding_decisions", True)
    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_USERNAME", "mcp-reviewer")
    monkeypatch.setenv("CICLOSEC_MCP_ADMIN_PASSWORD", "test-password")
    calls = []

    class Decision:
        finding_id = 42
        status = "accepted_risk"
        assignee_id = None
        decided_by_id = user.pk
        reason = "Compensating controls"

    def submit(**kwargs: object) -> Decision:
        calls.append(kwargs)
        return Decision()

    monkeypatch.setattr(mcp_server.finding_services, "review_finding", submit)
    with pytest.raises(ValueError, match="confirmation"):
        mcp_server.review_finding(
            finding_id=42,
            status="accepted_risk",
            reason="Compensating controls",
            confirm=False,
        )
    assert calls == []

    result = mcp_server.review_finding(
        finding_id=42,
        status="accepted_risk",
        reason="Compensating controls",
        confirm=True,
    )
    assert calls[0]["finding_id"] == 42
    assert result.status == "accepted_risk"
