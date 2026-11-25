"""PostgreSQL coordination tests; providers and broker are always stubbed."""

from threading import Event, Lock, Thread
from types import SimpleNamespace
from uuid import uuid4

import pytest
from celery.exceptions import Reject, Retry
from django.db import DatabaseError, connection, connections
from kombu.exceptions import OperationalError

from ciclosec.intelligence import coordination, tasks
from ciclosec.intelligence.coordination import coordinated_provider
from ciclosec.intelligence.manual_sync_service import get_manual_sync_status
from ciclosec.intelligence.models import IntelligenceSource, ManualSyncRequest, ProviderTaskAttempt
from ciclosec.intelligence.providers import ProviderSyncError, SyncOutcome

pytestmark = pytest.mark.django_db(transaction=True)


@pytest.fixture(autouse=True)
def postgresql_only():
    if connection.vendor != "postgresql":
        pytest.skip("Requires an isolated PostgreSQL test database")


def _request(task_id, retries=0):
    return SimpleNamespace(request=SimpleNamespace(id=task_id, retries=retries))


def test_manual_beat_retry_continuation_and_redelivery_are_serialized(monkeypatch):
    manual_id, beat_id, continuation_id = (str(uuid4()) for _ in range(3))
    ManualSyncRequest.objects.create(provider="osv", task_id=manual_id, status="queued")
    entered, release = Event(), Event()
    state_lock = Lock()
    active, max_active, calls = 0, 0, []
    errors = []

    def sync():
        nonlocal active, max_active
        with state_lock:
            active += 1
            max_active = max(max_active, active)
            calls.append(True)
            first = len(calls) == 1
        if first:
            entered.set()
            assert release.wait(10)
        with state_lock:
            active -= 1
        return SyncOutcome("osv", "succeeded", 1, coverage_complete=True)

    monkeypatch.setattr(tasks, "sync_osv", sync)
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: None)

    def worker(task_id, retries):
        try:
            tasks.sync_osv_task.push_request(id=task_id, retries=retries)
            try:
                tasks.sync_osv_task.run()
            finally:
                tasks.sync_osv_task.pop_request()
        except Exception as error:
            errors.append(error)
        finally:
            connections.close_all()

    first = Thread(target=worker, args=(manual_id, 0))
    first.start()
    others = []
    try:
        assert entered.wait(10)
        assert ManualSyncRequest.objects.get(task_id=manual_id).status == "running"
        for task_id, retries in (
            (manual_id, 0),
            (beat_id, 0),
            (beat_id, 1),
            (continuation_id, 0),
        ):
            thread = Thread(target=worker, args=(task_id, retries))
            thread.start()
            others.append(thread)
        assert not release.wait(0.5)
        assert calls == [True]
    finally:
        release.set()
        first.join(15)
        for thread in others:
            thread.join(15)
    assert not errors
    assert all(not thread.is_alive() for thread in [first, *others])
    assert max_active == 1 and len(calls) == 4
    assert ProviderTaskAttempt.objects.filter(provider="osv").count() == 4
    assert ManualSyncRequest.objects.get(task_id=manual_id).status == "succeeded"


def test_other_providers_can_run_in_parallel():
    entered, release, other_entered = Event(), Event(), Event()
    errors = []

    @coordinated_provider("nvd")
    def first(task):
        entered.set()
        assert release.wait(10)
        return {"status": "succeeded"}

    @coordinated_provider("epss")
    def other(task):
        other_entered.set()
        return {"status": "succeeded"}

    def run(func):
        try:
            func(_request(str(uuid4())))
        except Exception as error:
            errors.append(error)
        finally:
            connections.close_all()

    thread = Thread(target=run, args=(first,))
    thread.start()
    try:
        assert entered.wait(10)
        other_thread = Thread(target=run, args=(other,))
        other_thread.start()
        assert other_entered.wait(5)
        other_thread.join(10)
    finally:
        release.set()
        thread.join(10)
    assert not errors


def test_rollback_allows_redelivery_without_partial_database_writes():
    task = _request(str(uuid4()))
    calls = []

    @coordinated_provider("nvd")
    def run(task):
        calls.append(True)
        IntelligenceSource.objects.create(provider="nvd")
        if len(calls) == 1:
            raise RuntimeError("transaction must roll back")
        return {"status": "succeeded"}

    with pytest.raises(RuntimeError):
        run(task)
    assert not IntelligenceSource.objects.filter(provider="nvd").exists()
    assert not ProviderTaskAttempt.objects.filter(task_id=task.request.id).exists()
    assert run(task)["status"] == "succeeded"
    assert run(task)["status"] == "duplicate"
    assert len(calls) == 2


def test_lost_lock_connection_rolls_back_old_worker():
    entered, release = Event(), Event()
    backend_pid = []
    errors = []
    old_id, new_id = str(uuid4()), str(uuid4())

    @coordinated_provider("nvd")
    def old_worker(task):
        IntelligenceSource.objects.create(provider="nvd", status="unknown")
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_backend_pid()")
            backend_pid.append(cursor.fetchone()[0])
        entered.set()
        assert release.wait(10)
        IntelligenceSource.objects.filter(provider="nvd").update(status="stale")
        return {"status": "succeeded"}

    @coordinated_provider("nvd")
    def new_worker(task):
        IntelligenceSource.objects.create(provider="nvd", status="current")
        return {"status": "succeeded"}

    def run_old():
        try:
            old_worker(_request(old_id))
        except Exception as error:
            errors.append(error)
        finally:
            connections.close_all()

    thread = Thread(target=run_old)
    thread.start()
    try:
        assert entered.wait(10)
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_terminate_backend(%s)", [backend_pid[0]])
            assert cursor.fetchone()[0]
        assert new_worker(_request(new_id))["status"] == "succeeded"
    finally:
        release.set()
        thread.join(15)
    assert not thread.is_alive()
    assert len(errors) == 1 and isinstance(errors[0], DatabaseError)
    assert IntelligenceSource.objects.get(provider="nvd").status == "current"
    assert not ProviderTaskAttempt.objects.filter(task_id=old_id).exists()


def test_redelivery_recovers_manual_claim_without_stale_worker_overwrite(monkeypatch):
    task_id = str(uuid4())
    ManualSyncRequest.objects.create(provider="osv", task_id=task_id, status="queued")
    entered, release, completed = Event(), Event(), Event()
    backend_pid, errors, calls = [], [], []

    def sync():
        calls.append(True)
        if len(calls) == 1:
            IntelligenceSource.objects.create(provider="osv", status="unknown")
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pid.append(cursor.fetchone()[0])
            entered.set()
            assert release.wait(10)
            IntelligenceSource.objects.filter(provider="osv").update(status="stale")
        else:
            IntelligenceSource.objects.create(provider="osv", status="current")
        return SyncOutcome("osv", "succeeded", 1, coverage_complete=True)

    monkeypatch.setattr(tasks, "sync_osv", sync)
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: None)

    def worker():
        try:
            tasks.sync_osv_task.push_request(id=task_id, retries=0)
            try:
                tasks.sync_osv_task.run()
            finally:
                tasks.sync_osv_task.pop_request()
        except Exception as error:
            errors.append(error)
        finally:
            connections.close_all()
            completed.set()

    old = Thread(target=worker)
    old.start()
    newer = None
    try:
        assert entered.wait(10)
        assert ManualSyncRequest.objects.get(task_id=task_id).status == "running"
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_terminate_backend(%s)", [backend_pid[0]])
            assert cursor.fetchone()[0]
        newer = Thread(target=worker)
        newer.start()
        assert completed.wait(10)
        assert ManualSyncRequest.objects.get(task_id=task_id).status == "succeeded"
    finally:
        release.set()
        old.join(15)
        if newer is not None:
            newer.join(15)
    assert len(errors) == 1 and isinstance(errors[0], DatabaseError)
    assert ManualSyncRequest.objects.get(task_id=task_id).status == "succeeded"
    assert IntelligenceSource.objects.get(provider="osv").status == "current"


def test_celery_delivery_fails_closed_without_postgresql(monkeypatch):
    monkeypatch.setattr(connection, "vendor", "sqlite")
    called = []

    @coordinated_provider("nvd")
    def run(task):
        called.append(True)

    with pytest.raises(RuntimeError, match="require PostgreSQL"):
        run(_request(str(uuid4())))
    assert not called


def test_followup_delivery_failure_is_visible_after_commit(monkeypatch):
    task_id = str(uuid4())
    ManualSyncRequest.objects.create(provider="osv", task_id=task_id, status="queued")
    monkeypatch.setattr(
        tasks,
        "sync_osv",
        lambda: SyncOutcome("osv", "partial", 1, continue_bootstrap=True),
    )

    def fail(**kwargs):
        assert not connection.in_atomic_block
        raise OperationalError("private broker details")

    monkeypatch.setattr(tasks.sync_osv_task, "apply_async", fail)
    tasks.sync_osv_task.push_request(id=task_id, retries=0)
    try:
        result = tasks.sync_osv_task.run(batches_remaining=2)
    finally:
        tasks.sync_osv_task.pop_request()
    assert result["status"] == "partial"
    assert result["delivery_error"] == "followup_delivery_uncertain"
    reservation = ManualSyncRequest.objects.get(task_id=task_id)
    assert reservation.status == "partial"
    assert reservation.delivery_error == "followup_delivery_uncertain"


def test_followup_pending_is_visible_until_publication(monkeypatch):
    task_id = str(uuid4())
    ManualSyncRequest.objects.create(provider="osv", task_id=task_id, status="queued")
    callbacks = []
    monkeypatch.setattr(coordination.transaction, "on_commit", callbacks.append)
    monkeypatch.setattr(
        tasks, "sync_osv", lambda: SyncOutcome("osv", "partial", 1, continue_bootstrap=True)
    )
    sent = []
    monkeypatch.setattr(tasks.sync_osv_task, "apply_async", lambda **kwargs: sent.append(kwargs))
    tasks.sync_osv_task.push_request(id=task_id, retries=0)
    try:
        tasks.sync_osv_task.run(batches_remaining=2)
    finally:
        tasks.sync_osv_task.pop_request()
    actor = SimpleNamespace(is_authenticated=True, is_active=True, is_staff=True)
    result = get_manual_sync_status(actor=actor)
    osv = next(row for row in result["providers"] if row["provider"] == "osv")
    assert osv["status"] == "partial" and osv["error"] == "followup_delivery_pending"
    assert not sent and len(callbacks) == 1
    callbacks[0]()
    assert len(sent) == 1
    assert ManualSyncRequest.objects.get(task_id=task_id).delivery_error == ""


def test_retry_recovers_running_claim_after_lost_transaction(monkeypatch):
    task_id = str(uuid4())
    ManualSyncRequest.objects.create(provider="osv", task_id=task_id, status="running", attempt=0)
    monkeypatch.setattr(
        tasks, "sync_osv", lambda: SyncOutcome("osv", "succeeded", 1, coverage_complete=True)
    )
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: None)
    tasks.sync_osv_task.push_request(id=task_id, retries=1)
    try:
        assert tasks.sync_osv_task.run()["status"] == "succeeded"
    finally:
        tasks.sync_osv_task.pop_request()
    reservation = ManualSyncRequest.objects.get(task_id=task_id)
    assert reservation.status == "succeeded" and reservation.attempt == 1


@pytest.mark.parametrize(
    ("retry_error", "expected"), [(Retry(), "retrying"), (Reject(), "uncertain")]
)
def test_retry_delivery_state_is_committed(monkeypatch, retry_error, expected):
    task_id = str(uuid4())
    ManualSyncRequest.objects.create(provider="nvd", task_id=task_id, status="queued")

    def fail_sync():
        raise ProviderSyncError("temporary failure")

    def retry(**kwargs):
        raise retry_error

    monkeypatch.setattr(tasks, "sync_nvd", fail_sync)
    monkeypatch.setattr(tasks.sync_nvd_task, "retry", retry)
    tasks.sync_nvd_task.push_request(id=task_id, retries=0)
    try:
        with pytest.raises(type(retry_error)):
            tasks.sync_nvd_task.run()
    finally:
        tasks.sync_nvd_task.pop_request()
    reservation = ManualSyncRequest.objects.get(task_id=task_id)
    assert reservation.status == expected and reservation.attempt == 1
    assert ProviderTaskAttempt.objects.filter(task_id=task_id, attempt=0).exists()
