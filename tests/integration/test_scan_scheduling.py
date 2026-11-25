"""Opt-in scheduling and its authorization boundaries."""

import os
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from urllib.parse import urlparse

import pytest
from django.contrib.auth import get_user_model
from django.db import close_old_connections, connection, connections
from django.test import Client
from django.utils import timezone
from rest_framework.test import APIClient

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.assets.services import update_container_image_source
from ciclosec.common.config import CicloSecConfig
from ciclosec.scanners import services, tasks
from ciclosec.scans.models import ScanRun, ScanSchedule
from ciclosec.scans.scheduling import process_schedule

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.usefixtures("configuration_state"),
]


def test_beat_registers_opt_in_schedule_polling() -> None:
    from ciclosec.project.celery import app

    entry = app.conf.beat_schedule["process-scan-schedules"]
    assert entry["task"] == "ciclosec.scanners.tasks.process_scan_schedules_task"
    assert entry["schedule"] == timedelta(minutes=1)


def test_beat_loads_persisted_schedule_and_removes_disabled_entries(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from celery import Celery
    from celery.beat import Service
    from django.conf import settings

    from ciclosec.common.config import IntelligenceProviderConfig
    from ciclosec.common.models import ConfigurationState
    from ciclosec.project.celery import app

    base = CicloSecConfig()
    base.intelligence.providers["nvd"] = IntelligenceProviderConfig(
        enabled=True, refresh_interval="6h"
    )
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", base)
    test_app = Celery(
        "test-settings-beat", broker="memory://", backend="cache+memory://", set_as_current=False
    )
    test_app.conf.result_expires = None
    service = Service(
        app=test_app,
        scheduler_cls=app.conf.beat_scheduler,
        schedule_filename=str(tmp_path / "beat-schedule"),
    )
    scheduler = service.get_scheduler()
    try:
        assert scheduler.schedule["sync-nvd"].schedule.run_every == timedelta(hours=6)
        ConfigurationState.objects.filter(pk=1).update(
            revision=1,
            overrides={
                "intelligence.providers.nvd.enabled": False,
                "intelligence.providers.osv.enabled": True,
                "intelligence.providers.osv.refresh_interval": "3h",
            },
        )
        assert "sync-nvd" in scheduler.schedule
        assert "sync-osv" not in scheduler.schedule
    finally:
        scheduler.close()
    scheduler = service.get_scheduler()
    try:
        assert "sync-nvd" not in scheduler.schedule
        assert scheduler.schedule["sync-osv"].schedule.run_every == timedelta(hours=3)
        assert "process-scan-schedules" in scheduler.schedule
    finally:
        scheduler.close()


def test_beat_fails_closed_when_persisted_configuration_is_missing(tmp_path) -> None:
    from celery import Celery
    from celery.beat import Service

    from ciclosec.common.models import ConfigurationState
    from ciclosec.project.celery import app

    ConfigurationState.objects.filter(pk=1).delete()
    test_app = Celery(
        "test-missing-beat", broker="memory://", backend="cache+memory://", set_as_current=False
    )
    service = Service(
        app=test_app,
        scheduler_cls=app.conf.beat_scheduler,
        schedule_filename=str(tmp_path / "beat-schedule"),
    )
    with pytest.raises(ConfigurationState.DoesNotExist):
        service.get_scheduler()
    assert not list(tmp_path.iterdir())


def test_beat_reports_only_observed_ticks_and_keeps_startup_revision(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from celery import Celery
    from celery.beat import PersistentScheduler, Service

    from ciclosec.common.models import BeatObservation, ConfigurationState
    from ciclosec.project import beat
    from ciclosec.project.celery import app

    clock = [100.0]
    start = timezone.now()
    monkeypatch.setattr(beat, "monotonic", lambda: clock[0])
    monkeypatch.setattr(beat.timezone, "now", lambda: start + timedelta(seconds=clock[0] - 100))
    monkeypatch.setattr(PersistentScheduler, "tick", lambda *_a, **_kw: 1.0)
    test_app = Celery(
        "test-beat-heartbeat", broker="memory://", backend="cache+memory://", set_as_current=False
    )
    service = Service(
        app=test_app,
        scheduler_cls=app.conf.beat_scheduler,
        schedule_filename=str(tmp_path / "beat-schedule"),
    )
    scheduler = service.get_scheduler()
    try:
        assert not BeatObservation.objects.exists()
        assert scheduler.tick() == 1.0
        observation = BeatObservation.objects.get()
        assert observation.revision == 0
        first_seen = observation.last_seen_at
        ConfigurationState.objects.filter(pk=1).update(revision=1)
        clock[0] += 19
        scheduler.tick()
        observation.refresh_from_db()
        assert observation.last_seen_at == first_seen
        clock[0] += 2
        scheduler.tick()
        observation.refresh_from_db()
        assert observation.revision == 0
        assert observation.last_seen_at > first_seen
        assert BeatObservation.objects.count() == 1
    finally:
        scheduler.close()


def test_beat_does_not_dispatch_if_observation_cannot_be_recorded(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from celery import Celery
    from celery.beat import PersistentScheduler, Service
    from django.db import DatabaseError

    from ciclosec.common.models import BeatObservation
    from ciclosec.project.celery import app

    test_app = Celery(
        "test-beat-error", broker="memory://", backend="cache+memory://", set_as_current=False
    )
    service = Service(
        app=test_app,
        scheduler_cls=app.conf.beat_scheduler,
        schedule_filename=str(tmp_path / "beat-schedule"),
    )
    scheduler = service.get_scheduler()
    monkeypatch.setattr(
        BeatObservation.objects,
        "update_or_create",
        lambda **_kwargs: (_ for _ in ()).throw(DatabaseError("synthetic error")),
    )
    monkeypatch.setattr(
        PersistentScheduler,
        "tick",
        lambda *_a, **_kw: pytest.fail("Must not dispatch"),
    )
    try:
        with pytest.raises(DatabaseError):
            scheduler.tick()
    finally:
        scheduler.close()


def test_beat_scheduler_is_lazy_before_django_migrations(tmp_path) -> None:
    env = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "ciclosec.project.settings",
        "CICLOSEC_CONFIG_PATH": str(
            Path(__file__).resolve().parents[2] / "config" / "ciclosec.yaml.example"
        ),
        "CICLOSEC_DATABASE_URL": f"sqlite:///{(tmp_path / 'empty.sqlite3').as_posix()}",
        "CICLOSEC_GITHUB_TOKEN": "test-token",
    }
    script = """
import django
django.setup()
from celery.beat import Service
from ciclosec.project.celery import app
service = Service(app=app, scheduler_cls=app.conf.beat_scheduler)
service.get_scheduler(lazy=True)
print("lazy scheduler initialized")
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(tmp_path),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "lazy scheduler initialized" in result.stdout


def test_beat_loads_persisted_schedule_in_separate_process(tmp_path) -> None:
    env = {
        **os.environ,
        "DJANGO_SETTINGS_MODULE": "ciclosec.project.settings",
        "CICLOSEC_CONFIG_PATH": str(
            Path(__file__).resolve().parents[2] / "config" / "ciclosec.yaml.example"
        ),
        "CICLOSEC_DATABASE_URL": f"sqlite:///{(tmp_path / 'beat.sqlite3').as_posix()}",
        "CICLOSEC_GITHUB_TOKEN": "test-token",
    }
    setup = """
import django
django.setup()
from django.core.management import call_command
from ciclosec.common.models import ConfigurationState
call_command("migrate", verbosity=0, interactive=False)
ConfigurationState.objects.filter(pk=1).update(
    revision=1,
    overrides={"intelligence.providers.nvd.enabled": True,
               "intelligence.providers.nvd.refresh_interval": "2h"})
"""
    subprocess.run(
        [sys.executable, "-c", setup],
        cwd=str(tmp_path),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    load = """
import sys
import django
django.setup()
from datetime import timedelta
from celery.beat import Service
from celery.beat import PersistentScheduler
from ciclosec.common.models import BeatObservation
from ciclosec.project.celery import app
service = Service(app=app, scheduler_cls=app.conf.beat_scheduler, schedule_filename=sys.argv[1])
scheduler = service.get_scheduler()
try:
    assert scheduler.schedule["sync-nvd"].schedule.run_every == timedelta(hours=2)
    PersistentScheduler.tick = lambda self: 1.0
    scheduler.tick()
    assert BeatObservation.objects.get().revision == 1
    print("persisted schedule loaded")
finally:
    scheduler.close()
"""
    result = subprocess.run(
        [sys.executable, "-c", load, str(tmp_path / "beat-schedule")],
        cwd=str(tmp_path),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "persisted schedule loaded" in result.stdout
    verify = """
import django
django.setup()
from ciclosec.common.models import BeatObservation
observation = BeatObservation.objects.get()
assert observation.revision == 1
print("observation persisted")
"""
    observed = subprocess.run(
        [sys.executable, "-c", verify],
        cwd=str(tmp_path),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert "observation persisted" in observed.stdout


@pytest.fixture
def scheduling_case(monkeypatch: pytest.MonkeyPatch) -> tuple[Asset, APIClient, list[int]]:
    from django.conf import settings

    config = CicloSecConfig()
    config.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", config)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="admin", is_staff=True)
    client = APIClient()
    client.force_authenticate(user=user)
    sent: list[int] = []
    monkeypatch.setattr(tasks.scan_repository_task, "delay", sent.append)
    return asset, client, sent


def enable(client: APIClient, asset: Asset) -> object:
    url = f"/api/assets/{asset.pk}/scan-schedule/"
    current = client.get(url)
    fingerprint = current.data.get("source_fingerprint") if current.status_code == 200 else ""
    return client.post(
        url,
        {"enabled": True, "confirm": True, "source_fingerprint": fingerprint},
        format="json",
    )


def test_enable_requires_staff_confirmation_and_available_capacity(
    scheduling_case: tuple[Asset, APIClient, list[int]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.conf import settings

    asset, client, sent = scheduling_case
    url = f"/api/assets/{asset.pk}/scan-schedule/"
    user = get_user_model().objects.create_user(username="ordinary")
    client.force_authenticate(user=user)
    assert enable(client, asset).status_code == 403
    client.force_authenticate(user=None)
    assert client.post(url, {"enabled": True, "confirm": True}, format="json").status_code in (
        401,
        403,
    )
    admin = get_user_model().objects.get(username="admin")
    client.force_authenticate(user=admin)
    assert client.post(url, {"enabled": True}, format="json").status_code == 400
    active = ScanRun.objects.create(asset=asset, scanner_name="test")
    assert enable(client, asset).status_code == 409
    assert not ScanSchedule.objects.exists()
    active.status = ScanRun.Status.CANCELLED
    active.finished_at = timezone.now()
    active.save(update_fields=["status", "finished_at"])
    settings.CICLOSEC_CONFIG.scanning.execution.max_queued_scans = 1
    other = Asset.objects.create(name="busy", kind=Asset.Kind.REPOSITORY)
    queued = ScanRun.objects.create(asset=other, scanner_name="test")
    assert enable(client, asset).status_code == 429
    assert not ScanSchedule.objects.exists()
    assert sent == []
    queued.status = ScanRun.Status.CANCELLED
    queued.finished_at = timezone.now()
    queued.save(update_fields=["status", "finished_at"])
    response = enable(client, asset)
    assert response.status_code == 202
    assert sent == [response.data["scan_id"]]
    assert client.get(url).data["status"] == "enabled"
    assert enable(client, asset).status_code == 409


def test_interval_starts_at_completion_and_catches_up_only_once(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    asset, client, sent = scheduling_case
    response = enable(client, asset)
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    scan.status = ScanRun.Status.SUCCEEDED
    scan.finished_at = timezone.now()
    scan.save(update_fields=["status", "finished_at"])
    process_schedule(asset.pk)
    assert len(sent) == 1
    schedule = ScanSchedule.objects.get(asset=asset)
    schedule.activated_at = timezone.now() - timedelta(days=10)
    schedule.save(update_fields=["activated_at"])
    scan.finished_at = timezone.now() - timedelta(days=5)
    scan.save(update_fields=["finished_at"])
    process_schedule(asset.pk)
    process_schedule(asset.pk)
    assert len(sent) == 2
    assert ScanRun.objects.filter(asset=asset, status=ScanRun.Status.QUEUED).count() == 1
    assert ScanSchedule.objects.get(asset=asset).last_scan_id == sent[-1]


@pytest.mark.parametrize("status", [ScanRun.Status.FAILED, ScanRun.Status.PARTIAL])
def test_failures_pause_and_admin_can_explicitly_resume(
    scheduling_case: tuple[Asset, APIClient, list[int]], status: str
) -> None:
    asset, client, sent = scheduling_case
    response = enable(client, asset)
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    scan.status = status
    scan.finished_at = timezone.now()
    scan.save(update_fields=["status", "finished_at"])
    assert client.get(f"/api/assets/{asset.pk}/scan-schedule/").data["status"] == "paused"
    process_schedule(asset.pk)
    assert ScanSchedule.objects.get(asset=asset).paused_reason == "scan_failed_or_partial"
    assert len(sent) == 1
    resumed = enable(client, asset)
    assert resumed.status_code == 202
    assert len(sent) == 2


def test_source_change_blocks_queued_scan_and_requires_reauthorization(
    scheduling_case: tuple[Asset, APIClient, list[int]], monkeypatch: pytest.MonkeyPatch
) -> None:
    asset, client, sent = scheduling_case
    response = enable(client, asset)
    repository = Repository.objects.get(asset=asset)
    repository.owner = "changed"
    repository.save(update_fields=["owner"])
    assert client.get(f"/api/assets/{asset.pk}/scan-schedule/").data["status"] == "paused"
    assert enable(client, asset).status_code == 409
    monkeypatch.setattr(
        services, "checkout_github_repository", lambda *_args, **_kwargs: pytest.fail("checkout")
    )
    scan = services.scan_registered_repository(response.data["scan_id"])
    assert scan.status == ScanRun.Status.FAILED
    assert "scheduled_source_changed" in scan.metadata["diagnostic_codes"]
    process_schedule(asset.pk)
    assert ScanSchedule.objects.get(asset=asset).paused_reason
    assert len(sent) == 1
    assert enable(client, asset).status_code == 202
    assert len(sent) == 2


def test_missing_scanner_network_authorization_fails_and_pauses_scheduled_scan(
    scheduling_case: tuple[Asset, APIClient, list[int]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.conf import settings

    asset, client, sent = scheduling_case
    settings.CICLOSEC_CONFIG.scanning.execution.allow_repository_scanners_with_network = True
    response = enable(client, asset)
    assert response.status_code == 202
    settings.CICLOSEC_CONFIG.scanning.execution.allow_repository_scanners_with_network = False
    monkeypatch.setattr(
        services, "checkout_github_repository", lambda *_args, **_kwargs: pytest.fail("checkout")
    )

    scan = services.scan_registered_repository(response.data["scan_id"])
    assert scan.status == ScanRun.Status.FAILED
    assert scan.metadata["diagnostic_codes"] == ["repository_scanner_network_not_authorized"]
    assert client.get(f"/api/assets/{asset.pk}/scan-schedule/").data["status"] == "paused"
    process_schedule(asset.pk)
    assert ScanSchedule.objects.get(asset=asset).paused_reason == "scan_failed_or_partial"
    assert sent == [scan.pk]


def test_reverting_repository_changes_still_requires_authorization(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    asset, client, _sent = scheduling_case
    response = enable(client, asset)
    repository = Repository.objects.get(asset=asset)
    url = f"/api/repositories/{repository.pk}/"
    assert client.patch(url, {"owner": "changed"}, format="json").status_code == 200
    assert client.patch(url, {"owner": "example"}, format="json").status_code == 200
    repository.refresh_from_db()
    assert repository.source_revision == 2
    assert client.get(f"/api/assets/{asset.pk}/scan-schedule/").data["status"] == "paused"
    scan = services.scan_registered_repository(response.data["scan_id"])
    assert scan.status == ScanRun.Status.FAILED
    assert "scheduled_source_changed" in scan.metadata["diagnostic_codes"]


def test_authorization_rejects_source_changed_since_review(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    asset, client, sent = scheduling_case
    url = f"/api/assets/{asset.pk}/scan-schedule/"
    fingerprint = client.get(url).data["source_fingerprint"]
    repository = Repository.objects.get(asset=asset)
    assert (
        client.patch(
            f"/api/repositories/{repository.pk}/", {"owner": "changed"}, format="json"
        ).status_code
        == 200
    )
    response = client.post(
        url,
        {"enabled": True, "confirm": True, "source_fingerprint": fingerprint},
        format="json",
    )
    assert response.status_code == 409
    assert not ScanSchedule.objects.exists()
    assert not ScanRun.objects.exists()
    assert sent == []


def test_manual_failure_pauses_enabled_schedule(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    asset, client, sent = scheduling_case
    response = enable(client, asset)
    first = ScanRun.objects.get(pk=response.data["scan_id"])
    first.status = ScanRun.Status.SUCCEEDED
    first.finished_at = timezone.now()
    first.save(update_fields=["status", "finished_at"])
    ScanRun.objects.create(
        asset=asset, scanner_name="manual", status=ScanRun.Status.FAILED, finished_at=timezone.now()
    )
    process_schedule(asset.pk)
    assert ScanSchedule.objects.get(asset=asset).paused_reason == "scan_failed_or_partial"
    assert len(sent) == 1


def test_uncertain_initial_delivery_does_not_repeat(
    scheduling_case: tuple[Asset, APIClient, list[int]], monkeypatch: pytest.MonkeyPatch
) -> None:
    from kombu.exceptions import OperationalError

    asset, client, _sent = scheduling_case

    def fail(_scan_id: int) -> None:
        raise OperationalError("private broker details")

    monkeypatch.setattr(tasks.scan_repository_task, "delay", fail)
    response = enable(client, asset)
    assert response.status_code == 503
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    assert scan.metadata["dispatch_uncertain"] is True
    assert "private broker details" not in str(response.data)
    process_schedule(asset.pk)
    assert ScanRun.objects.filter(asset=asset).count() == 1


def test_scheduled_initial_dispatch_stays_pending_until_outer_commit(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    from django.db import transaction

    asset, client, sent = scheduling_case
    with transaction.atomic():
        response = enable(client, asset)
        assert response.status_code == 202
        scan = ScanRun.objects.get(pk=response.data["scan_id"])
        assert scan.metadata["initial_dispatch_pending"] is True
        assert scan.metadata["scheduled_source"]["owner"] == "example"
        assert sent == []
    scan.refresh_from_db()
    assert "initial_dispatch_pending" not in scan.metadata
    assert scan.metadata["scheduled_source"]["owner"] == "example"
    assert sent == [scan.pk]


def test_changed_image_source_is_not_scanned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.conf import settings

    config = CicloSecConfig.model_validate(
        {
            "docker": {
                "enabled": True,
                "allow_local_daemon": True,
                "images": [{"reference": "first:latest"}, {"reference": "second:latest"}],
            }
        }
    )
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", config)
    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    image = ContainerImage.objects.create(asset=asset, image_reference="first:latest")
    user = get_user_model().objects.create_user(username="admin-image", is_staff=True)
    client = APIClient()
    client.force_authenticate(user=user)
    sent: list[int] = []
    monkeypatch.setattr(tasks.scan_container_image_task, "delay", sent.append)
    response = enable(client, asset)
    assert response.status_code == 202
    update_container_image_source(image, image_reference="second:latest")
    monkeypatch.setattr(
        services, "resolve_local_docker_image", lambda *_args, **_kwargs: pytest.fail("docker")
    )
    scan = services.scan_registered_container_image(response.data["scan_id"])
    assert scan.status == ScanRun.Status.FAILED
    assert "scheduled_source_changed" in scan.metadata["diagnostic_codes"]


def test_disabling_does_not_cancel_queued_work_and_web_requires_staff(
    scheduling_case: tuple[Asset, APIClient, list[int]], client: Client
) -> None:
    asset, api, sent = scheduling_case
    response = enable(api, asset)
    scan_id = response.data["scan_id"]
    user = get_user_model().objects.create_user(username="viewer")
    client.force_login(user)
    assert client.post(f"/assets/{asset.pk}/schedule/", {"enabled": "false"}).status_code == 403
    assert "Habilitar programación" not in client.get(f"/assets/{asset.pk}/").content.decode()
    assert (
        api.post(
            f"/api/assets/{asset.pk}/scan-schedule/", {"enabled": False}, format="json"
        ).status_code
        == 200
    )
    assert ScanRun.objects.get(pk=scan_id).status == ScanRun.Status.QUEUED
    process_schedule(asset.pk)
    assert len(sent) == 1


def test_scheduled_cancellation_pauses_instead_of_retrying(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    asset, api, sent = scheduling_case
    response = enable(api, asset)
    scan_id = response.data["scan_id"]
    assert (
        api.post(
            f"/api/scans/{scan_id}/cancel-queued/", {"confirm": True}, format="json"
        ).status_code
        == 200
    )
    process_schedule(asset.pk)
    assert ScanSchedule.objects.get(asset=asset).paused_reason == "scan_cancelled"
    assert len(sent) == 1


def test_due_scan_waits_for_queue_capacity(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    from django.conf import settings

    asset, api, sent = scheduling_case
    response = enable(api, asset)
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    schedule = ScanSchedule.objects.get(asset=asset)
    schedule.activated_at = timezone.now() - timedelta(days=4)
    schedule.save(update_fields=["activated_at"])
    scan.status = ScanRun.Status.SUCCEEDED
    scan.finished_at = timezone.now() - timedelta(days=2)
    scan.save(update_fields=["status", "finished_at"])
    settings.CICLOSEC_CONFIG.scanning.execution.max_queued_scans = 1
    other = Asset.objects.create(name="busy", kind=Asset.Kind.REPOSITORY)
    occupied = ScanRun.objects.create(asset=other, scanner_name="test")
    process_schedule(asset.pk)
    assert len(sent) == 1
    occupied.status = ScanRun.Status.CANCELLED
    occupied.finished_at = timezone.now()
    occupied.save(update_fields=["status", "finished_at"])
    process_schedule(asset.pk)
    assert len(sent) == 2


def test_schedule_web_action_requires_csrf(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    asset, api, sent = scheduling_case
    user = get_user_model().objects.get(username="admin")
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    url = f"/assets/{asset.pk}/schedule/"
    assert client.post(url, {"enabled": "true", "confirm": "true"}).status_code == 403
    response = client.get(f"/assets/{asset.pk}/")
    assert "Habilitar programación" in response.content.decode()
    fingerprint = api.get(f"/api/assets/{asset.pk}/scan-schedule/").data["source_fingerprint"]
    csrf_token = client.cookies["csrftoken"].value
    assert (
        client.post(
            url,
            {"enabled": "true", "confirm": "true", "source_fingerprint": fingerprint},
            HTTP_X_CSRFTOKEN=csrf_token,
        ).status_code
        == 302
    )
    assert len(sent) == 1


def test_concurrent_schedule_pollers_create_one_scan(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    asset, client, sent = scheduling_case
    response = enable(client, asset)
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    schedule = ScanSchedule.objects.get(asset=asset)
    schedule.activated_at = timezone.now() - timedelta(days=4)
    schedule.save(update_fields=["activated_at"])
    scan.status = ScanRun.Status.SUCCEEDED
    scan.finished_at = timezone.now() - timedelta(days=2)
    scan.save(update_fields=["status", "finished_at"])
    barrier = threading.Barrier(2)

    def poll() -> None:
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            process_schedule(asset.pk)
        finally:
            connections["default"].close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        list(executor.map(lambda _: poll(), range(2)))
    assert len(sent) == 2
    assert ScanRun.objects.filter(asset=asset, status=ScanRun.Status.QUEUED).count() == 1


def test_schedule_rejects_activation_without_scanner_network_authorization(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    from django.conf import settings

    asset, client, sent = scheduling_case
    settings.CICLOSEC_CONFIG.scanning.execution.allow_repository_scanners_with_network = False

    response = enable(client, asset)

    assert response.status_code == 403
    assert response.data["code"] == "repository_scanner_network_not_authorized"
    assert not ScanRun.objects.filter(asset=asset).exists()
    assert not ScanSchedule.objects.filter(asset=asset).exists()
    assert sent == []


def test_due_schedule_pauses_if_scanner_network_authorization_is_removed(
    scheduling_case: tuple[Asset, APIClient, list[int]],
) -> None:
    from django.conf import settings

    asset, client, sent = scheduling_case
    response = enable(client, asset)
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    scan.status = ScanRun.Status.SUCCEEDED
    scan.finished_at = timezone.now() - timedelta(days=2)
    scan.save(update_fields=["status", "finished_at"])
    schedule = ScanSchedule.objects.get(asset=asset)
    schedule.activated_at = timezone.now() - timedelta(days=3)
    schedule.save(update_fields=["activated_at"])
    settings.CICLOSEC_CONFIG.scanning.execution.allow_repository_scanners_with_network = False

    process_schedule(asset.pk)

    schedule = ScanSchedule.objects.get(asset=asset)
    assert schedule.paused_reason == "repository_network_disabled"
    assert client.get(f"/api/assets/{asset.pk}/scan-schedule/").data["status"] == "paused"
    assert sent == [scan.pk]
    assert ScanRun.objects.filter(asset=asset).count() == 1
    settings.CICLOSEC_CONFIG.scanning.execution.allow_repository_scanners_with_network = True
    process_schedule(asset.pk)
    assert sent == [scan.pk]
    resumed = enable(client, asset)
    assert resumed.status_code == 202
    assert len(sent) == 2


def test_scheduled_dispatch_and_pause_with_isolated_celery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery import Celery
    from celery.contrib.testing.worker import start_worker
    from django.conf import settings

    from ciclosec.scanners.process import ScannerExecutionError
    from ciclosec.scans.scheduling import process_schedules

    redis_url = os.environ.get("CICLOSEC_TEST_REDIS_URL")
    if not redis_url or connection.vendor != "postgresql":
        pytest.skip("Requires isolated PostgreSQL and CICLOSEC_TEST_REDIS_URL")
    parsed = urlparse(redis_url)
    if parsed.scheme != "redis" or parsed.hostname != "127.0.0.1":
        pytest.fail("CICLOSEC_TEST_REDIS_URL must point to an isolated loopback Redis")
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", CicloSecConfig())
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset,
        owner="example",
        repository_name="repo",
        credential_env="TEST_SCHEDULE_TOKEN",
    )
    user = get_user_model().objects.create_user(username="celery-admin", is_staff=True)
    client = APIClient()
    client.force_authenticate(user=user)
    monkeypatch.setenv("TEST_SCHEDULE_TOKEN", "test-token")

    def failed_checkout(*_args: object, **_kwargs: object) -> None:
        raise ScannerExecutionError("simulated checkout failure")

    monkeypatch.setattr(services, "checkout_github_repository", failed_checkout)
    identifier = uuid.uuid4().hex
    queue = f"test-scheduling-{identifier}"
    app = Celery("ciclosec-schedule-test", broker=redis_url, backend=redis_url)

    @app.task(bind=True, name=f"test.schedule.scan.{identifier}")
    def scan_task(task: object, scan_id: int) -> dict[str, object]:
        return tasks._run_scan(task, scan_id, services.scan_registered_repository)

    @app.task(name=f"test.schedule.poll.{identifier}")
    def poll_task() -> None:
        process_schedules()

    submitted = []

    def submit(scan_id: int) -> None:
        submitted.append(scan_task.apply_async(args=(scan_id,), queue=queue))

    monkeypatch.setattr(tasks.scan_repository_task._get_current_object(), "delay", submit)
    try:
        response = enable(client, asset)
        assert response.status_code == 202
        assert len(submitted) == 1
        with start_worker(app, pool="solo", queues=[queue], perform_ping_check=False):
            outcome = submitted[0].get(timeout=15, disable_sync_subtasks=False)
            assert outcome["status"] == ScanRun.Status.FAILED
            poll_task.apply_async(queue=queue).get(timeout=15, disable_sync_subtasks=False)
    finally:
        app.close()
    assert ScanSchedule.objects.get(asset=asset).paused_reason == "scan_failed_or_partial"
    assert ScanRun.objects.filter(asset=asset).count() == 1
