"""Provider tasks enqueue finding reevaluation after successful imports."""

import pytest

from ciclosec.intelligence import tasks
from ciclosec.intelligence.providers import SyncOutcome


@pytest.mark.parametrize(
    ("task_name", "sync_name", "provider"),
    [
        ("sync_cisa_kev_task", "sync_cisa_kev", "cisa_kev"),
        ("sync_osv_task", "sync_osv", "osv"),
        (
            "sync_github_advisories_task",
            "sync_github_advisories",
            "github_advisories",
        ),
        ("sync_nvd_task", "sync_nvd", "nvd"),
        ("sync_epss_task", "sync_epss", "epss"),
    ],
)
def test_provider_task_schedules_finding_reevaluation(
    monkeypatch: pytest.MonkeyPatch,
    task_name: str,
    sync_name: str,
    provider: str,
) -> None:
    outcome = SyncOutcome(
        provider=provider,
        status="succeeded",
        records_processed=1,
        coverage_complete=True,
    )
    scheduled: list[bool] = []
    monkeypatch.setattr(tasks, sync_name, lambda: outcome)
    monkeypatch.setattr(
        tasks.reevaluate_findings_task,
        "delay",
        lambda: scheduled.append(True),
    )

    result = getattr(tasks, task_name).run()

    assert result["provider"] == provider
    assert scheduled == [True]


@pytest.mark.parametrize(
    ("status", "continue_bootstrap", "expected_scheduled"),
    [
        ("succeeded", False, True),
        ("partial", False, True),
        ("partial", True, False),
        ("failed", False, False),
    ],
)
def test_reevaluation_is_scheduled_only_after_a_finished_sync(
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    continue_bootstrap: bool,
    expected_scheduled: bool,
) -> None:
    scheduled: list[bool] = []
    monkeypatch.setattr(
        tasks.reevaluate_findings_task,
        "delay",
        lambda: scheduled.append(True),
    )

    tasks._schedule_finding_reevaluation(
        SyncOutcome(
            provider="osv",
            status=status,
            records_processed=1,
            continue_bootstrap=continue_bootstrap,
        )
    )

    assert scheduled == ([True] if expected_scheduled else [])


def test_osv_partial_batch_does_not_schedule_automatic_continuation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        tasks,
        "sync_osv",
        lambda: SyncOutcome("osv", "partial", 200, continue_bootstrap=True),
    )
    scheduled: list[bool] = []
    monkeypatch.setattr(tasks.sync_osv_task, "apply_async", lambda **kwargs: scheduled.append(True))
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: scheduled.append(True))

    result = tasks.sync_osv_task.run()

    assert result["continue_bootstrap"]
    assert scheduled == [True]


def test_osv_continuation_is_explicitly_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        tasks,
        "sync_osv",
        lambda: SyncOutcome("osv", "partial", 200, continue_bootstrap=True),
    )
    scheduled: list[dict[str, object]] = []
    monkeypatch.setattr(
        tasks.sync_osv_task, "apply_async", lambda **kwargs: scheduled.append(kwargs)
    )
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: pytest.fail("too early"))

    tasks.sync_osv_task.run(batches_remaining=2)

    assert scheduled == [{"kwargs": {"batches_remaining": 1}, "countdown": 2}]
    with pytest.raises(ValueError, match="between 1 and 10"):
        tasks.sync_osv_task.run(batches_remaining=11)
