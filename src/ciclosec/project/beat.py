"""Beat scheduler initialized from the persisted configuration."""

from time import monotonic
from typing import Any
from uuid import uuid4

from celery.beat import PersistentScheduler
from django.conf import settings
from django.utils import timezone

from ciclosec.project.celery import build_beat_schedule

HEARTBEAT_SECONDS = 20


class ConfigurationScheduler(PersistentScheduler):  # type: ignore[misc]
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        interval = kwargs.get("max_interval") or HEARTBEAT_SECONDS
        kwargs["max_interval"] = min(interval, HEARTBEAT_SECONDS)
        self.instance_id = uuid4()
        self.last_observation: float | None = None
        self.revision: int | None = None
        super().__init__(*args, **kwargs)

    def setup_schedule(self) -> None:
        from ciclosec.common.settings_service import configuration_snapshot

        revision, config = configuration_snapshot(settings.CICLOSEC_CONFIG)
        self.app.conf.beat_schedule = build_beat_schedule(config)
        super().setup_schedule()
        self.revision = revision

    def tick(self, *args: Any, **kwargs: Any) -> float:
        from ciclosec.common.models import BeatObservation

        now = monotonic()
        if self.last_observation is None or now - self.last_observation >= HEARTBEAT_SECONDS:
            if self.revision is None:
                raise RuntimeError("Beat scheduler configuration has not been initialized.")
            BeatObservation.objects.update_or_create(
                pk=self.instance_id,
                defaults={"revision": self.revision, "last_seen_at": timezone.now()},
            )
            self.last_observation = now
        return float(super().tick(*args, **kwargs))
