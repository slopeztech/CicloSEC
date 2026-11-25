"""Manual intelligence API tests with a stubbed broker and isolated database."""

from threading import Event, Thread
from types import SimpleNamespace

import pytest
from celery.exceptions import Reject, Retry
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import DatabaseError, IntegrityError, connection, connections, transaction
from kombu.exceptions import OperationalError
from rest_framework.test import APIClient

from ciclosec.intelligence import tasks
from ciclosec.intelligence.manual_sync import retry_manual_sync, track_manual_sync
from ciclosec.intelligence.manual_sync_service import (
    PROVIDER_TASKS,
    get_manual_sync_status,
    request_manual_sync,
)
from ciclosec.intelligence.models import ManualSyncRequest
from ciclosec.intelligence.providers import SyncOutcome

URL = "/api/intelligence/sync/"


@pytest.fixture
def staff(db):
    return get_user_model().objects.create_user(username="staff", is_staff=True)


@pytest.fixture
def client_for_staff(staff):
    client = APIClient()
    client.force_authenticate(staff)
    return client


@pytest.fixture
def broker_stub(monkeypatch):
    sent = []
    for provider, task in PROVIDER_TASKS.items():

        def send(*, task_id, provider=provider):
            sent.append((provider, task_id))

        monkeypatch.setattr(task, "apply_async", send)
    return sent


@pytest.mark.django_db(transaction=True)
def test_permissions_and_confirmation(staff, client_for_staff, broker_stub):
    assert APIClient().post(URL, {"confirm": True}, format="json").status_code in (401, 403)
    client = APIClient()
    client.force_authenticate(get_user_model().objects.create_user(username="nonstaff"))
    assert client.post(URL, {"confirm": True}, format="json").status_code == 403
    for data in ({}, {"confirm": False}, {"confirm": "true"}, {"confirm": 1}, []):
        assert client_for_staff.post(URL, data, format="json").status_code == 400
    assert not broker_stub
    assert not ManualSyncRequest.objects.exists()
    with pytest.raises(ValueError):
        request_manual_sync(actor=staff, confirm=1)
    with pytest.raises(PermissionDenied):
        request_manual_sync(actor=None, confirm=True)
    staff.is_active = False
    with pytest.raises(PermissionDenied):
        get_manual_sync_status(actor=staff)


@pytest.mark.django_db(transaction=True)
def test_post_get_and_duplicate(client_for_staff, broker_stub):
    before = client_for_staff.get(URL)
    assert all(p["status"] == "never_requested" for p in before.data["providers"])
    response = client_for_staff.post(URL, {"confirm": True}, format="json")
    assert response.status_code == 202
    rows = response.data["providers"]
    assert len(rows) == len(broker_stub) == 5
    assert all(p["status"] == "queued" and p["id"] and p["task_id"] for p in rows)
    assert {(p["provider"], p["task_id"]) for p in rows} == set(broker_stub)

    duplicate = client_for_staff.post(URL, {"confirm": True}, format="json")
    assert duplicate.status_code == 409
    assert len(broker_stub) == 5
    assert all(p["duplicate"] and p["status"] == "queued" for p in duplicate.data["providers"])
    assert client_for_staff.get(URL).data["providers"] == rows


@pytest.mark.django_db(transaction=True)
def test_uncertain_delivery_stays_reserved_and_hides_broker_error(
    client_for_staff, broker_stub, monkeypatch
):
    def fail(**kwargs):
        raise OperationalError("secret broker credential")

    monkeypatch.setattr(tasks.sync_nvd_task, "apply_async", fail)
    response = client_for_staff.post(URL, {"confirm": True}, format="json")
    assert response.status_code == 503
    item = next(p for p in response.data["providers"] if p["provider"] == "nvd")
    assert item["status"] == "uncertain"
    assert item["error"] == "delivery_uncertain"
    assert "secret" not in str(response.data)
    again = client_for_staff.post(URL, {"confirm": True}, format="json")
    assert again.status_code == 503
    assert len(broker_stub) == 4
    assert next(p for p in again.data["providers"] if p["provider"] == "nvd")["duplicate"]


@pytest.mark.django_db(transaction=True)
def test_worker_observation_and_redelivery(client_for_staff, broker_stub, monkeypatch):
    response = client_for_staff.post(URL, {"confirm": True}, format="json")
    row = next(p for p in response.data["providers"] if p["provider"] == "nvd")
    calls = []

    def sync():
        calls.append(True)
        return SyncOutcome("nvd", "partial", 1)

    monkeypatch.setattr(tasks, "sync_nvd", sync)
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: None)
    tasks.sync_nvd_task.push_request(id=row["task_id"], retries=0)
    try:
        tasks.sync_nvd_task.run()
    finally:
        tasks.sync_nvd_task.pop_request()
    status = next(p for p in client_for_staff.get(URL).data["providers"] if p["provider"] == "nvd")
    assert status["status"] == "partial"
    tasks.sync_nvd_task.push_request(id=row["task_id"], retries=0)
    try:
        tasks.sync_nvd_task.run()
    finally:
        tasks.sync_nvd_task.pop_request()
    assert calls == [True]
    new = client_for_staff.post(URL, {"confirm": True}, format="json")
    assert new.status_code == 409  # Other providers remain queued.
    nvd = next(p for p in new.data["providers"] if p["provider"] == "nvd")
    assert not nvd["duplicate"] and nvd["id"] != row["id"]
    assert len(broker_stub) == 6


@pytest.mark.django_db(transaction=True)
def test_retry_failure_and_concurrent_claim(client_for_staff, broker_stub):
    row = client_for_staff.post(URL, {"confirm": True}, format="json").data["providers"][0]
    task = SimpleNamespace(
        request=SimpleNamespace(id=row["task_id"], retries=0),
        retry=lambda **kwargs: (_ for _ in ()).throw(Retry()),
    )
    observed = []

    @track_manual_sync
    def running(task):
        observed.append(ManualSyncRequest.objects.get(pk=row["id"]).status)
        return {"status": "succeeded"}

    @track_manual_sync
    def retry(task):
        retry_manual_sync(task, exc=RuntimeError(), countdown=1)

    @track_manual_sync
    def fail(task):
        raise RuntimeError("sensitive exception")

    with pytest.raises(Retry):
        retry(task)
    assert ManualSyncRequest.objects.get(pk=row["id"]).status == "retrying"
    assert running(task) == {"status": "duplicate"}
    task.request.retries = 1
    with pytest.raises(RuntimeError):
        fail(task)
    assert ManualSyncRequest.objects.get(pk=row["id"]).status == "failed"
    assert running(task) == {"status": "duplicate"}
    assert observed == []


@pytest.mark.django_db(transaction=True)
def test_database_enforces_one_active_reservation(client_for_staff, broker_stub):
    from uuid import uuid4

    row = client_for_staff.post(URL, {"confirm": True}, format="json").data["providers"][0]
    with pytest.raises(IntegrityError), transaction.atomic():
        ManualSyncRequest.objects.create(
            provider=row["provider"], task_id=uuid4(), status=ManualSyncRequest.Status.RUNNING
        )


@pytest.mark.django_db(transaction=True)
def test_service_rejects_outer_transaction(staff, broker_stub):
    with transaction.atomic(), pytest.raises(RuntimeError):
        request_manual_sync(actor=staff, confirm=True)
    assert not broker_stub


@pytest.mark.django_db(transaction=True)
def test_service_rejects_database_without_partial_unique_indexes(staff, broker_stub, monkeypatch):
    monkeypatch.setattr(connection.features, "supports_partial_indexes", False)
    with pytest.raises(RuntimeError, match="cannot enforce"):
        request_manual_sync(actor=staff, confirm=True)
    assert not broker_stub


@pytest.mark.django_db(transaction=True)
def test_database_failure_is_sanitized(client_for_staff, broker_stub, monkeypatch):
    def fail(**kwargs):
        raise DatabaseError("sensitive database failure")

    monkeypatch.setattr("ciclosec.intelligence.api.request_manual_sync", fail)
    response = client_for_staff.post(URL, {"confirm": True}, format="json")
    assert response.status_code == 503
    assert "sensitive" not in str(response.data)
    assert not broker_stub


@pytest.mark.django_db(transaction=True)
def test_unexpected_publication_error_is_not_misreported_as_confirmation(
    staff, broker_stub, monkeypatch
):
    def fail(**kwargs):
        raise ValueError("unexpected publisher bug")

    monkeypatch.setattr(tasks.sync_nvd_task, "apply_async", fail)
    with pytest.raises(ValueError, match="publisher bug"):
        request_manual_sync(actor=staff, confirm=True)
    reservation = ManualSyncRequest.objects.get(provider="nvd")
    assert reservation.status == "dispatching"
    assert not broker_stub


@pytest.mark.django_db(transaction=True)
def test_session_auth_requires_csrf(staff, broker_stub):
    client = APIClient(enforce_csrf_checks=True)
    client.force_login(staff)
    assert client.post(URL, {"confirm": True}, format="json").status_code == 403
    assert not broker_stub


@pytest.mark.django_db(transaction=True)
def test_send_error_after_worker_completed_preserves_observed_state(
    client_for_staff, broker_stub, monkeypatch
):
    monkeypatch.setattr(
        tasks, "sync_nvd", lambda: SyncOutcome("nvd", "succeeded", 1, coverage_complete=True)
    )
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: None)

    def deliver_then_fail(*, task_id):
        tasks.sync_nvd_task.push_request(id=task_id, retries=0)
        try:
            tasks.sync_nvd_task.run()
        finally:
            tasks.sync_nvd_task.pop_request()
        raise OperationalError("sensitive broker failure")

    monkeypatch.setattr(tasks.sync_nvd_task, "apply_async", deliver_then_fail)
    response = client_for_staff.post(URL, {"confirm": True}, format="json")
    item = next(p for p in response.data["providers"] if p["provider"] == "nvd")
    assert response.status_code == 202
    assert item["status"] == "succeeded" and item["error"] is None


@pytest.mark.django_db(transaction=True)
def test_uncertain_retry_keeps_reservation(client_for_staff, broker_stub):
    row = client_for_staff.post(URL, {"confirm": True}, format="json").data["providers"][0]

    def failed_send(**kwargs):
        raise Reject("sensitive broker failure")

    task = SimpleNamespace(request=SimpleNamespace(id=row["task_id"], retries=0), retry=failed_send)

    @track_manual_sync
    def run(task):
        retry_manual_sync(task, exc=RuntimeError(), countdown=1)

    with pytest.raises(Reject):
        run(task)
    reservation = ManualSyncRequest.objects.get(pk=row["id"])
    assert reservation.status == "uncertain" and reservation.attempt == 1
    again = client_for_staff.post(URL, {"confirm": True}, format="json")
    assert again.status_code == 503
    assert next(p for p in again.data["providers"] if p["id"] == row["id"])["duplicate"]


@pytest.mark.django_db(transaction=True)
def test_overlapping_requests_share_committed_reservations(staff, broker_stub, monkeypatch):
    entered, release = Event(), Event()
    original_send = tasks.sync_nvd_task.apply_async

    def blocking_send(*, task_id):
        entered.set()
        assert release.wait(5)
        original_send(task_id=task_id)

    monkeypatch.setattr(tasks.sync_nvd_task, "apply_async", blocking_send)
    results = []
    errors = []

    def first_request():
        try:
            results.append(request_manual_sync(actor=staff, confirm=True))
        except Exception as error:
            errors.append(error)
        finally:
            connections.close_all()

    thread = Thread(target=first_request)
    thread.start()
    try:
        assert entered.wait(5)
        second = request_manual_sync(actor=staff, confirm=True)
        assert all(item["duplicate"] for item in second["providers"])
    finally:
        release.set()
        thread.join(timeout=10)
    assert not thread.is_alive() and not errors
    assert len(results) == 1 and len(broker_stub) == 5
    assert ManualSyncRequest.objects.count() == 5
