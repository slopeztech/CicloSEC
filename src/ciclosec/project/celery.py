"""Celery application configuration."""

import os
from datetime import timedelta
from typing import Literal

from celery import Celery
from django.conf import settings

from ciclosec.common.config import CicloSecConfig, duration_seconds

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "ciclosec.project.settings")

app = Celery("ciclosec")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()
app.conf.imports = ("ciclosec.scanners.tasks", "ciclosec.intelligence.tasks")

schedule_entries: tuple[
    tuple[Literal["cisa_kev", "osv", "github_advisories", "nvd", "epss"], str, str],
    ...,
] = (
    ("cisa_kev", "1h", "ciclosec.intelligence.tasks.sync_cisa_kev_task"),
    ("osv", "6h", "ciclosec.intelligence.tasks.sync_osv_task"),
    (
        "github_advisories",
        "6h",
        "ciclosec.intelligence.tasks.sync_github_advisories_task",
    ),
    ("nvd", "6h", "ciclosec.intelligence.tasks.sync_nvd_task"),
    ("epss", "24h", "ciclosec.intelligence.tasks.sync_epss_task"),
)


def build_beat_schedule(config: CicloSecConfig) -> dict[str, dict[str, object]]:
    schedule: dict[str, dict[str, object]] = {
        "process-scan-schedules": {
            "task": "ciclosec.scanners.tasks.process_scan_schedules_task",
            "schedule": timedelta(minutes=1),
        }
    }
    for provider, default_interval, task_name in schedule_entries:
        provider_config = config.intelligence.providers.get(provider)
        if provider_config is not None and provider_config.enabled:
            interval = provider_config.refresh_interval or default_interval
            schedule[f"sync-{provider}"] = {
                "task": task_name,
                "schedule": timedelta(seconds=duration_seconds(interval)),
            }
    return schedule


app.conf.beat_schedule = build_beat_schedule(settings.CICLOSEC_CONFIG)
app.conf.beat_scheduler = "ciclosec.project.beat:ConfigurationScheduler"
app.conf.timezone = settings.TIME_ZONE
