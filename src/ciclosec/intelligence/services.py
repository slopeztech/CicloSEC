"""Read-only intelligence source freshness queries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from django.utils import timezone

from ciclosec.common.config import duration_seconds
from ciclosec.common.settings_service import get_effective_config
from ciclosec.intelligence.models import IntelligenceSource


@dataclass(frozen=True)
class SourceFreshness:
    """Current freshness view for one configured intelligence provider."""

    provider: str
    status: str
    last_attempt_at: datetime | None
    last_success_at: datetime | None
    source_updated_at: datetime | None
    last_error: str


def get_source_freshness(provider: str, *, now: datetime | None = None) -> SourceFreshness:
    """Classify a source as unknown, current, stale, or unavailable."""
    source = IntelligenceSource.objects.filter(provider=provider).first()
    if source is None:
        return SourceFreshness(
            provider,
            IntelligenceSource.Status.UNKNOWN,
            None,
            None,
            None,
            "",
        )

    current_time = now or timezone.now()
    stale_after = duration_seconds(get_effective_config().intelligence.stale_after)
    if source.last_success_at is None:
        status = (
            IntelligenceSource.Status.UNAVAILABLE
            if source.status == IntelligenceSource.Status.UNAVAILABLE
            else IntelligenceSource.Status.UNKNOWN
        )
    elif (
        source.last_attempt_at is not None and source.last_attempt_at > source.last_success_at
    ) or (current_time - source.last_success_at).total_seconds() > stale_after:
        status = IntelligenceSource.Status.STALE
    else:
        status = IntelligenceSource.Status.CURRENT

    return SourceFreshness(
        provider,
        status,
        source.last_attempt_at,
        source.last_success_at,
        source.source_updated_at,
        source.last_error,
    )
