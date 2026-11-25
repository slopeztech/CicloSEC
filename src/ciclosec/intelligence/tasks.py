"""Celery tasks for scheduled intelligence synchronization."""

from __future__ import annotations

import random
from typing import Any

from celery import shared_task

from ciclosec.findings.tasks import reevaluate_findings_task
from ciclosec.intelligence.coordination import coordinated_provider, publish_after_commit
from ciclosec.intelligence.manual_sync import retry_manual_sync, track_manual_sync
from ciclosec.intelligence.providers import (
    ProviderSyncError,
    SyncOutcome,
    sync_cisa_kev,
    sync_epss,
    sync_github_advisories,
    sync_nvd,
    sync_osv,
)


def _task_retry_delay(retries: int) -> int:
    base = min(300, 2**retries)
    jitter = int(random.randint(0, max(1, base // 2)))
    return int(base + jitter)


def _outcome_payload(outcome: SyncOutcome) -> dict[str, Any]:
    return {
        "provider": outcome.provider,
        "status": outcome.status,
        "records_processed": outcome.records_processed,
        "coverage_complete": outcome.coverage_complete,
        "continue_bootstrap": outcome.continue_bootstrap,
    }


def _schedule_finding_reevaluation(
    outcome: SyncOutcome, task: Any = None, payload: dict[str, Any] | None = None
) -> None:
    if outcome.status in {"succeeded", "partial"} and not outcome.continue_bootstrap:
        if task is None:
            reevaluate_findings_task.delay()
        else:
            publish_after_commit(
                task, reevaluate_findings_task, action="reevaluation", payload=payload
            )


@shared_task(
    bind=True,
    name="ciclosec.intelligence.tasks.sync_cisa_kev_task",
    max_retries=5,
    acks_late=True,
)  # type: ignore[untyped-decorator]
@coordinated_provider("cisa_kev")
@track_manual_sync
def sync_cisa_kev_task(self: Any) -> dict[str, Any]:
    """Synchronize the complete KEV snapshot, retrying transient failures."""
    try:
        outcome = sync_cisa_kev()
    except ProviderSyncError as error:
        if self.request.retries >= self.max_retries:
            raise
        raise retry_manual_sync(
            self,
            exc=error,
            countdown=_task_retry_delay(self.request.retries),
        ) from error
    payload = _outcome_payload(outcome)
    _schedule_finding_reevaluation(outcome, self, payload)
    return payload


@shared_task(
    bind=True,
    name="ciclosec.intelligence.tasks.sync_osv_task",
    max_retries=5,
    acks_late=True,
)  # type: ignore[untyped-decorator]
@coordinated_provider("osv")
@track_manual_sync
def sync_osv_task(self: Any, batches_remaining: int = 1) -> dict[str, Any]:
    """Advance the OSV checkpoint with an explicitly bounded chain of batches."""
    if isinstance(batches_remaining, bool) or not isinstance(batches_remaining, int):
        raise ValueError("OSV batches_remaining must be an integer between 1 and 10")
    if not 1 <= batches_remaining <= 10:
        raise ValueError("OSV batches_remaining must be an integer between 1 and 10")
    try:
        outcome = sync_osv()
    except ProviderSyncError as error:
        if self.request.retries >= self.max_retries:
            raise
        raise retry_manual_sync(
            self,
            exc=error,
            countdown=_task_retry_delay(self.request.retries),
        ) from error

    payload = _outcome_payload(outcome)
    if outcome.continue_bootstrap and batches_remaining > 1:
        publish_after_commit(
            self,
            sync_osv_task,
            action="continuation",
            payload=payload,
            kwargs={"batches_remaining": batches_remaining - 1},
            countdown=2,
        )
    else:
        publish_after_commit(self, reevaluate_findings_task, action="reevaluation", payload=payload)
    return payload


@shared_task(
    bind=True,
    name="ciclosec.intelligence.tasks.sync_github_advisories_task",
    max_retries=5,
    acks_late=True,
)  # type: ignore[untyped-decorator]
@coordinated_provider("github_advisories")
@track_manual_sync
def sync_github_advisories_task(self: Any) -> dict[str, Any]:
    """Synchronize reviewed GitHub advisories, retrying transient failures."""
    try:
        outcome = sync_github_advisories()
    except ProviderSyncError as error:
        if self.request.retries >= self.max_retries:
            raise
        raise retry_manual_sync(
            self,
            exc=error,
            countdown=_task_retry_delay(self.request.retries),
        ) from error
    payload = _outcome_payload(outcome)
    _schedule_finding_reevaluation(outcome, self, payload)
    return payload


@shared_task(
    bind=True,
    name="ciclosec.intelligence.tasks.sync_nvd_task",
    max_retries=5,
    acks_late=True,
)  # type: ignore[untyped-decorator]
@coordinated_provider("nvd")
@track_manual_sync
def sync_nvd_task(self: Any) -> dict[str, Any]:
    """Synchronize NVD CVE changes, retrying transient failures."""
    try:
        outcome = sync_nvd()
    except ProviderSyncError as error:
        if self.request.retries >= self.max_retries:
            raise
        raise retry_manual_sync(
            self,
            exc=error,
            countdown=_task_retry_delay(self.request.retries),
        ) from error
    payload = _outcome_payload(outcome)
    _schedule_finding_reevaluation(outcome, self, payload)
    return payload


@shared_task(
    bind=True,
    name="ciclosec.intelligence.tasks.sync_epss_task",
    max_retries=5,
    acks_late=True,
)  # type: ignore[untyped-decorator]
@coordinated_provider("epss")
@track_manual_sync
def sync_epss_task(self: Any) -> dict[str, Any]:
    """Refresh EPSS scores for known CVEs and continue bounded batches."""
    try:
        outcome = sync_epss()
    except ProviderSyncError as error:
        if self.request.retries >= self.max_retries:
            raise
        raise retry_manual_sync(
            self,
            exc=error,
            countdown=_task_retry_delay(self.request.retries),
        ) from error

    payload = _outcome_payload(outcome)
    _schedule_finding_reevaluation(outcome, self, payload)
    if outcome.continue_bootstrap:
        publish_after_commit(
            self, sync_epss_task, action="continuation", payload=payload, countdown=2
        )
    return payload
