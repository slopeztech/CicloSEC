"""Persistence and authorization for administrator-managed settings."""

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import close_old_connections, connection, connections
from django.test import Client
from rest_framework.test import APIClient

from ciclosec.assets.models import Asset, Repository
from ciclosec.common.config import CicloSecConfig, ConfigurationError
from ciclosec.common.models import ConfigurationChange, ConfigurationState
from ciclosec.common.settings_service import (
    ConfigurationConflict,
    effective_config,
    update_configuration,
)

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("configuration_state")]


@pytest.fixture
def admin():
    return get_user_model().objects.create_superuser(username="settings-admin", password="test")


def test_changes_persist_as_overrides_and_are_audited(admin):
    base = CicloSecConfig()
    revision = update_configuration(
        actor=admin,
        changes={"scanning.execution.max_queued_scans": 10},
        expected_revision=0,
        confirm=True,
        base=base,
    )

    assert revision == 1
    assert effective_config(base).scanning.execution.max_queued_scans == 10
    assert base.scanning.execution.max_queued_scans == 50
    event = ConfigurationChange.objects.get()
    assert event.actor == admin
    assert event.key == "scanning.execution.max_queued_scans"
    assert event.old_value == 50
    assert event.new_value == 10


@pytest.mark.parametrize(
    "changes",
    [
        {"database.url_env": "CICLOSEC_SECRET"},
        {"scanning.execution.max_queued_scans": "private-input"},
        {"scanning.execution.allow_on_demand": "true"},
    ],
)
def test_invalid_or_noneditable_values_do_not_change_state(admin, changes):
    with pytest.raises(ConfigurationError) as error:
        update_configuration(
            actor=admin, changes=changes, expected_revision=0, confirm=True, base=CicloSecConfig()
        )
    assert "private-input" not in str(error.value)
    assert "CICLOSEC_SECRET" not in str(error.value)
    assert not ConfigurationChange.objects.exists()
    assert not ConfigurationState.objects.filter(revision__gt=0).exists()


def test_inactive_and_non_superusers_cannot_edit_or_skip_confirmation(admin):
    staff = get_user_model().objects.create_user(username="settings-staff", is_staff=True)
    for actor, confirm in ((staff, True), (admin, False)):
        with pytest.raises(PermissionDenied):
            update_configuration(
                actor=actor,
                changes={"scanning.execution.allow_on_demand": True},
                expected_revision=0,
                confirm=confirm,
                base=CicloSecConfig(),
            )
    admin.is_active = False
    admin.save(update_fields=["is_active"])
    with pytest.raises(PermissionDenied):
        update_configuration(
            actor=admin,
            changes={"scanning.execution.allow_on_demand": True},
            expected_revision=0,
            confirm=True,
            base=CicloSecConfig(),
        )
    assert not ConfigurationChange.objects.exists()


def test_stale_revision_is_rejected_without_overwriting_other_changes(admin):
    update_configuration(
        actor=admin,
        changes={"scanning.execution.max_queued_scans": 10},
        expected_revision=0,
        confirm=True,
        base=CicloSecConfig(),
    )
    with pytest.raises(ConfigurationConflict):
        update_configuration(
            actor=admin,
            changes={"scanning.execution.max_queued_scans": 20},
            expected_revision=0,
            confirm=True,
            base=CicloSecConfig(),
        )
    assert effective_config(CicloSecConfig()).scanning.execution.max_queued_scans == 10
    assert ConfigurationChange.objects.count() == 1


def test_unknown_persisted_option_is_not_ignored():
    ConfigurationState.objects.filter(pk=1).update(
        revision=1, overrides={"database.url_env": "SECRET"}
    )
    with pytest.raises(ConfigurationError):
        effective_config(CicloSecConfig())


def test_setting_interval_does_not_enable_an_unconfigured_provider(admin):
    update_configuration(
        actor=admin,
        changes={"intelligence.providers.nvd.refresh_interval": "12h"},
        expected_revision=0,
        confirm=True,
        base=CicloSecConfig(),
    )
    provider = effective_config(CicloSecConfig()).intelligence.providers["nvd"]
    assert provider.refresh_interval == "12h"
    assert provider.enabled is False


def test_missing_configuration_does_not_silently_fall_back():
    ConfigurationState.objects.filter(pk=1).delete()
    with pytest.raises(ConfigurationState.DoesNotExist):
        effective_config(CicloSecConfig())


def test_scan_admission_uses_persisted_network_authorization(admin, monkeypatch):
    base = CicloSecConfig()
    base.scanning.execution.allow_on_demand = True
    base.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", base)
    asset = Asset.objects.create(name="test repository", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    client = APIClient()
    client.force_authenticate(user=admin)
    update_configuration(
        actor=admin,
        changes={"scanning.execution.allow_repository_scanners_with_network": False},
        expected_revision=0,
        confirm=True,
        base=base,
    )

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 403
    assert response.data["code"] == "repository_scanner_network_not_authorized"
    assert not asset.scan_runs.exists()


def test_worker_rechecks_persisted_network_authorization(admin, monkeypatch):
    from ciclosec.scanners import services
    from ciclosec.scans.models import ScanRun

    base = CicloSecConfig()
    base.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", base)
    asset = Asset.objects.create(name="test repository", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    update_configuration(
        actor=admin,
        changes={"scanning.execution.allow_repository_scanners_with_network": False},
        expected_revision=0,
        confirm=True,
        base=base,
    )
    monkeypatch.setattr(
        services,
        "checkout_github_repository",
        lambda *args, **kwargs: pytest.fail("Worker must not access the repository"),
    )
    monkeypatch.setattr(services, "resolve_environment_value", lambda name: "test-token")

    result = services.scan_registered_repository(scan.pk)

    assert result.status == ScanRun.Status.FAILED
    assert "repository_scanner_network_not_authorized" in result.metadata["diagnostic_codes"]


@pytest.mark.parametrize(
    ("option", "operator"),
    [
        ("mcp.allow_intelligence_sync", "_intelligence_operator"),
        ("mcp.allow_finding_decisions", "_finding_decision_operator"),
    ],
)
def test_mcp_revocation_is_checked_before_authentication(admin, monkeypatch, option, operator):
    from ciclosec.mcp import server

    base = CicloSecConfig()
    base.mcp.allow_intelligence_sync = True
    base.mcp.allow_finding_decisions = True
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", base)
    monkeypatch.setattr(
        server, "authenticate", lambda **kwargs: pytest.fail("Revoked access must not authenticate")
    )
    update_configuration(
        actor=admin, changes={option: False}, expected_revision=0, confirm=True, base=base
    )

    with pytest.raises(PermissionError, match="disabled"):
        getattr(server, operator)()


@pytest.mark.parametrize("operator", ["_intelligence_operator", "_finding_decision_operator"])
def test_mcp_permission_check_redacts_configuration_database_errors(monkeypatch, operator):
    from django.db import DatabaseError

    from ciclosec.mcp import server

    def fail():
        raise DatabaseError("sensitive database detail")

    monkeypatch.setattr(server, "get_effective_config", fail)
    with pytest.raises(RuntimeError, match="configuration is unavailable") as error:
        getattr(server, operator)()
    assert "sensitive database detail" not in str(error.value)


def test_persisted_freshness_threshold_is_used(admin, monkeypatch):
    from datetime import timedelta

    from django.utils import timezone

    from ciclosec.intelligence.models import IntelligenceSource
    from ciclosec.intelligence.services import get_source_freshness

    base = CicloSecConfig()
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", base)
    now = timezone.now()
    IntelligenceSource.objects.create(provider="nvd", last_success_at=now - timedelta(hours=2))
    update_configuration(
        actor=admin,
        changes={"intelligence.stale_after": "1h"},
        expected_revision=0,
        confirm=True,
        base=base,
    )

    assert get_source_freshness("nvd", now=now).status == IntelligenceSource.Status.STALE


def test_settings_page_is_restricted_to_superusers(admin):
    client = Client()
    assert client.get("/settings/").status_code == 302
    staff = get_user_model().objects.create_user(username="settings-page-staff", is_staff=True)
    client.force_login(staff)
    assert client.get("/settings/").status_code == 403
    response = client.post("/settings/", {"option": "scanning.execution.allow_on_demand"})
    assert response.status_code == 403
    client.force_login(admin)
    response = client.get("/settings/")
    assert response.status_code == 200
    assert "Desconocido" in response.content.decode()
    assert "intelligence.providers.nvd.enabled" in response.content.decode()


def test_provider_forms_show_defaults_and_warn_about_manual_sync(admin, monkeypatch):
    from ciclosec.common.config import IntelligenceProviderConfig

    base = CicloSecConfig()
    base.intelligence.providers["nvd"] = IntelligenceProviderConfig(enabled=True)
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", base)
    client = Client()
    client.force_login(admin)

    response = client.get("/settings/")
    options = {item["key"]: item["form"] for item in response.context["provider_options"]}

    assert options["intelligence.providers.nvd.enabled"]["value"].value() == "true"
    assert options["intelligence.providers.nvd.refresh_interval"]["value"].value() == "6h"
    assert options["intelligence.providers.cisa_kev.enabled"]["value"].value() == "false"
    assert options["intelligence.providers.cisa_kev.refresh_interval"]["value"].value() == "1h"
    assert "no bloquea la sincronización manual" in response.content.decode()


def test_provider_schedule_changes_apply_only_to_the_next_beat_snapshot(admin, monkeypatch):
    from datetime import timedelta

    from ciclosec.project.celery import build_beat_schedule

    base = CicloSecConfig()
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", base)
    client = Client()
    client.force_login(admin)
    before = build_beat_schedule(base)

    def save(key, value, revision):
        prefix = key.replace(".", "-")
        return client.post(
            "/settings/",
            {
                "option": key,
                f"{prefix}-revision": str(revision),
                f"{prefix}-value": value,
                f"{prefix}-confirm": "on",
            },
        )

    interval = "intelligence.providers.nvd.refresh_interval"
    enabled = "intelligence.providers.nvd.enabled"
    assert save(interval, "12h", 0).status_code == 302
    assert "sync-nvd" not in build_beat_schedule(effective_config(base))
    assert save(enabled, "true", 1).status_code == 302
    after = build_beat_schedule(effective_config(base))
    assert "sync-nvd" not in before
    assert after["sync-nvd"]["schedule"] == timedelta(hours=12)
    assert list(ConfigurationChange.objects.order_by("revision").values_list("key", flat=True)) == [
        interval,
        enabled,
    ]


def test_provider_interval_that_beat_cannot_represent_is_rejected(admin, monkeypatch):
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", CicloSecConfig())
    client = Client()
    client.force_login(admin)
    key = "intelligence.providers.nvd.refresh_interval"
    prefix = key.replace(".", "-")
    response = client.post(
        "/settings/",
        {
            "option": key,
            f"{prefix}-revision": "0",
            f"{prefix}-value": "9999999999999999999d",
            f"{prefix}-confirm": "on",
        },
    )
    assert response.status_code == 400
    assert not ConfigurationChange.objects.exists()


def test_settings_page_shows_beat_observations_without_claiming_unseen_instances(admin):
    import uuid
    from datetime import timedelta

    from django.utils import timezone

    from ciclosec.common.models import BeatObservation

    now = timezone.now()
    ConfigurationState.objects.filter(pk=1).update(revision=2)
    active = BeatObservation.objects.create(id=uuid.uuid4(), revision=2, last_seen_at=now)
    pending = BeatObservation.objects.create(id=uuid.uuid4(), revision=1, last_seen_at=now)
    expired = BeatObservation.objects.create(
        id=uuid.uuid4(), revision=2, last_seen_at=now - timedelta(minutes=5)
    )
    future = BeatObservation.objects.create(
        id=uuid.uuid4(), revision=2, last_seen_at=now + timedelta(minutes=5)
    )
    client = Client()
    client.force_login(admin)
    response = client.get("/settings/")
    instances = {item["instance"].pk: item["status"] for item in response.context["beat_instances"]}

    assert instances == {
        active.pk: "matching",
        pending.pk: "pending",
        expired.pk: "unknown",
        future.pk: "unknown",
    }
    assert "otras instancias" in response.content.decode()


def test_settings_page_requires_csrf_confirmation_and_audits(admin, monkeypatch):
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", CicloSecConfig())
    client = Client(enforce_csrf_checks=True)
    client.force_login(admin)
    key = "scanning.execution.allow_on_demand"
    prefix = key.replace(".", "-")
    data = {"option": key, f"{prefix}-value": "true", f"{prefix}-revision": "0"}
    assert client.post("/settings/", data).status_code == 403
    client.get("/settings/")
    data["csrfmiddlewaretoken"] = client.cookies["csrftoken"].value
    assert client.post("/settings/", data).status_code == 400
    data[f"{prefix}-confirm"] = "on"
    assert client.post("/settings/", data).status_code == 302
    assert effective_config(settings.CICLOSEC_CONFIG).scanning.execution.allow_on_demand is True
    assert ConfigurationChange.objects.get().key == key
    assert client.post("/settings/", data).status_code == 409


def test_settings_page_rejects_unsupported_and_invalid_values(admin):
    client = Client()
    client.force_login(admin)
    assert client.post("/settings/", {"option": "mcp.allow_run_scan"}).status_code == 400
    key = "scanning.execution.max_queued_scans"
    prefix = key.replace(".", "-")
    response = client.post(
        "/settings/",
        {
            "option": key,
            f"{prefix}-revision": "0",
            f"{prefix}-value": "-1",
            f"{prefix}-confirm": "on",
        },
    )
    assert response.status_code == 400
    assert not ConfigurationChange.objects.exists()


def test_settings_page_reports_missing_state_without_falling_back(admin):
    client = Client()
    client.force_login(admin)
    ConfigurationState.objects.filter(pk=1).delete()
    assert client.get("/settings/").status_code == 503


def test_settings_page_shows_effective_default_for_missing_schedule(admin, monkeypatch):
    config = CicloSecConfig()
    config.scanning.schedules.clear()
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", config)
    client = Client()
    client.force_login(admin)
    response = client.get("/settings/")
    assert response.status_code == 200
    assert b'value="24h"' in response.content


def test_settings_page_does_not_claim_to_audit_unchanged_value(admin, monkeypatch):
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", CicloSecConfig())
    client = Client()
    client.force_login(admin)
    key = "scanning.execution.allow_on_demand"
    prefix = key.replace(".", "-")
    response = client.post(
        "/settings/",
        {
            "option": key,
            f"{prefix}-revision": "0",
            f"{prefix}-value": "false",
            f"{prefix}-confirm": "on",
        },
        follow=True,
    )
    assert "no se creó un evento de auditoría" in response.content.decode()
    assert not ConfigurationChange.objects.exists()


@pytest.mark.django_db(transaction=True)
def test_concurrent_updates_reject_stale_revisions():
    if connection.vendor != "postgresql":
        pytest.skip("PostgreSQL row locking is required")
    ConfigurationState.objects.update_or_create(pk=1, defaults={"revision": 0, "overrides": {}})
    actor = get_user_model().objects.create_superuser(username="concurrent-admin", password="test")
    barrier = threading.Barrier(2)

    def update(limit):
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                update_configuration(
                    actor=actor,
                    changes={"scanning.execution.max_queued_scans": limit},
                    expected_revision=0,
                    confirm=True,
                    base=CicloSecConfig(),
                )
                return "saved"
            except ConfigurationConflict:
                return "conflict"
        finally:
            connections["default"].close()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(update, (10, 20)))
    assert sorted(results) == ["conflict", "saved"]
    assert ConfigurationChange.objects.count() == 1
    assert ConfigurationState.objects.get(pk=1).revision == 1
