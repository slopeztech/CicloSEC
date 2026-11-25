"""Offline recovery of scan records after the operator stops all workers."""

import io
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from threading import Barrier
from urllib.parse import urlparse

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import close_old_connections, connection
from django.utils import timezone

from ciclosec.assets.models import Asset
from ciclosec.scanners.services import ScanAlreadyClaimed, _start_scan
from ciclosec.scans.models import ScanRun
from ciclosec.scans.services import get_scan_queue_status, scan_diagnostic_messages

pytestmark = pytest.mark.django_db

CONFIRM = "--confirm-all-workers-and-scanners-stopped"


def test_offline_recovery_preserves_history_and_rejects_late_delivery() -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    started = timezone.now() - timedelta(hours=1)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.RUNNING,
        started_at=started,
        warnings=["existing warning"],
        metadata={"source": "original", "diagnostic_codes": ["unknown"]},
    )
    output = io.StringIO()
    assert get_scan_queue_status()["running_count"] == 1

    call_command(
        "recover_interrupted_scan", str(scan.pk), "--operator", "operator", CONFIRM, stdout=output
    )
    scan.refresh_from_db()

    assert scan.status == ScanRun.Status.FAILED
    assert get_scan_queue_status()["running_count"] == 0
    assert scan.started_at == started
    assert scan.finished_at is not None
    assert scan.warnings == ["existing warning"]
    assert scan.metadata["source"] == "original"
    assert scan.metadata["manual_recovery"]["operator"] == "operator"
    assert scan.metadata["diagnostic_codes"] == ["unknown", "manually_recovered"]
    assert any("operador" in message.lower() for message in scan_diagnostic_messages(scan))
    assert "no new scan" in output.getvalue().lower()
    with pytest.raises(ScanAlreadyClaimed):
        _start_scan(scan.pk, kind=Asset.Kind.REPOSITORY, scanner_name="test")
    with pytest.raises(CommandError):
        call_command("recover_interrupted_scan", str(scan.pk), "--operator", "operator", CONFIRM)
    assert ScanRun.objects.count() == 1


@pytest.mark.parametrize(
    ("status", "started", "finished", "metadata"),
    [
        (ScanRun.Status.QUEUED, True, False, {}),
        (ScanRun.Status.FAILED, True, True, {}),
        (ScanRun.Status.RUNNING, False, False, {}),
        (ScanRun.Status.RUNNING, True, True, {}),
        (ScanRun.Status.RUNNING, True, False, []),
        (ScanRun.Status.RUNNING, True, False, {"diagnostic_codes": "invalid"}),
        (ScanRun.Status.RUNNING, True, False, {"manual_recovery": {"operator": "old"}}),
    ],
)
def test_offline_recovery_rejects_inconsistent_records(
    status: str, started: bool, finished: bool, metadata: object
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=status,
        started_at=timezone.now() - timedelta(minutes=1) if started else None,
        finished_at=timezone.now() if finished else None,
        metadata=metadata,
    )
    with pytest.raises(CommandError):
        call_command("recover_interrupted_scan", str(scan.pk), "--operator", "operator", CONFIRM)
    scan.refresh_from_db()
    assert scan.status == status
    assert scan.metadata == metadata


def test_offline_recovery_requires_confirmation_and_operator() -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="test", status=ScanRun.Status.RUNNING, started_at=timezone.now()
    )
    for arguments in (
        (str(scan.pk), "--operator", "operator"),
        (str(scan.pk), "--operator", "   ", CONFIRM),
        (str(scan.pk), "--operator", "bad\nname", CONFIRM),
        (str(scan.pk), "--operator", "x" * 129, CONFIRM),
        (str(scan.pk), CONFIRM),
    ):
        with pytest.raises(CommandError):
            call_command("recover_interrupted_scan", *arguments)
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.RUNNING
    assert scan.finished_at is None


def test_offline_recovery_rejects_missing_scan_and_future_start() -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.RUNNING,
        started_at=timezone.now() + timedelta(days=1),
    )
    for scan_id in (scan.pk, scan.pk + 100):
        with pytest.raises(CommandError):
            call_command(
                "recover_interrupted_scan", str(scan_id), "--operator", "operator", CONFIRM
            )
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.RUNNING


@pytest.mark.django_db(transaction=True)
def test_offline_recovery_serializes_competing_operators() -> None:
    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="test", status=ScanRun.Status.RUNNING, started_at=timezone.now()
    )
    barrier = Barrier(2, timeout=10)

    def recover(operator: str) -> str:
        close_old_connections()
        try:
            barrier.wait()
            try:
                call_command(
                    "recover_interrupted_scan",
                    str(scan.pk),
                    "--operator",
                    operator,
                    CONFIRM,
                    stdout=io.StringIO(),
                )
            except CommandError:
                return "rejected"
            return "recovered"
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(recover, ["one", "two"]))

    assert sorted(results) == ["recovered", "rejected"]
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.FAILED
    assert scan.metadata["manual_recovery"]["operator"] in {"one", "two"}


@pytest.mark.django_db(transaction=True)
def test_recovered_scan_delivery_is_ignored_after_worker_restart() -> None:
    from celery import Celery
    from celery.contrib.testing.worker import start_worker

    from ciclosec.scanners import services, tasks

    redis_url = os.environ.get("CICLOSEC_TEST_REDIS_URL")
    if not redis_url or connection.vendor != "postgresql":
        pytest.skip("Requires isolated PostgreSQL and CICLOSEC_TEST_REDIS_URL")
    parsed_url = urlparse(redis_url)
    if parsed_url.scheme != "redis" or parsed_url.hostname != "127.0.0.1":
        pytest.fail("CICLOSEC_TEST_REDIS_URL must point to an isolated loopback Redis")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="test", status=ScanRun.Status.RUNNING, started_at=timezone.now()
    )
    app = Celery("ciclosec-isolated-recovery-test", broker=redis_url, backend=redis_url)
    identifier = uuid.uuid4().hex

    @app.task(bind=True, name=f"test.recovery.{identifier}", max_retries=None)
    def worker_task(task: object, scan_id: int) -> dict[str, object]:
        return tasks._run_scan(task, scan_id, services.scan_registered_repository)

    queue = f"test-recovery-{identifier}"
    try:
        result = worker_task.apply_async(args=(scan.pk,), queue=queue)
        call_command(
            "recover_interrupted_scan",
            str(scan.pk),
            "--operator",
            "operator",
            CONFIRM,
            stdout=io.StringIO(),
        )
        with start_worker(app, pool="solo", queues=[queue], perform_ping_check=False):
            outcome = result.get(timeout=15, disable_sync_subtasks=False)
    finally:
        app.close()

    assert outcome["disposition"] == "already_claimed"
    assert outcome["status"] == ScanRun.Status.FAILED
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.FAILED
    assert scan.metadata["manual_recovery"]["operator"] == "operator"
