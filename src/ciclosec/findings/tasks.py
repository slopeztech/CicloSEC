"""Celery tasks for persisted finding correlation and risk assessment."""

from celery import shared_task

from ciclosec.findings.services import reevaluate_findings


@shared_task(  # type: ignore[untyped-decorator]
    name="ciclosec.findings.tasks.reevaluate_findings_task",
    acks_late=True,
)
def reevaluate_findings_task() -> int:
    """Reevaluate saved findings without invoking asset scanners."""
    return reevaluate_findings()
