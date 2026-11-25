"""Validate, persist and audit explicitly permitted configuration overrides."""

from collections.abc import Mapping
from datetime import timedelta
from typing import Literal, TypedDict
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.utils import timezone
from pydantic import ValidationError

from ciclosec.common.config import CicloSecConfig, ConfigurationError, duration_seconds
from ciclosec.common.models import BeatObservation, ConfigurationChange, ConfigurationState

EDITABLE_OPTIONS = frozenset(
    {
        "application.timezone",
        "scanning.execution.timeout_seconds",
        "scanning.execution.max_concurrent_scans",
        "scanning.execution.max_queued_scans",
        "scanning.execution.allow_on_demand",
        "scanning.execution.allow_repository_scanners_with_network",
        "scanning.execution.repository_scanner_use_local_databases",
        "scanning.schedules.intelligence_default",
        "scanning.schedules.intelligence_full_reconciliation",
        "scanning.schedules.repositories",
        "scanning.schedules.container_images",
        "docker.enabled",
        "docker.allow_local_daemon",
        "intelligence.stale_after",
        "notifications.enabled",
        "mcp.enabled",
        "mcp.allow_run_scan",
        "mcp.allow_intelligence_sync",
        "mcp.allow_finding_decisions",
    }
    | {
        f"intelligence.providers.{provider}.{field}"
        for provider in ("nvd", "osv", "github_advisories", "cisa_kev", "epss")
        for field in ("enabled", "refresh_interval", "priority")
    }
)


class ConfigurationConflict(ConfigurationError):
    """The configuration was changed since it was presented to the operator."""


class BeatInstanceStatus(TypedDict):
    instance: BeatObservation
    status: Literal["matching", "pending", "unknown"]


def beat_instance_statuses(revision: int) -> list[BeatInstanceStatus]:
    """Summarize recent observations without inferring that a process is stopped."""
    now = timezone.now()
    cutoff = now - timedelta(seconds=90)
    result: list[BeatInstanceStatus] = []
    for instance in BeatObservation.objects.order_by("-last_seen_at")[:50]:
        if not cutoff <= instance.last_seen_at <= now or instance.revision > revision:
            status: Literal["matching", "pending", "unknown"] = "unknown"
        elif instance.revision == revision:
            status = "matching"
        else:
            status = "pending"
        result.append({"instance": instance, "status": status})
    return result


def _validated_config(base: CicloSecConfig, overrides: Mapping[str, object]) -> CicloSecConfig:
    if not isinstance(overrides, Mapping):
        raise ConfigurationError("Invalid persisted configuration overrides")
    data = base.model_dump(mode="python")
    for key, value in overrides.items():
        if key not in EDITABLE_OPTIONS:
            raise ConfigurationError("Configuration contains a non-editable field")
        parts = key.split(".")
        current = data
        for part in parts[:-1]:
            if part not in current:
                # An absent provider is disabled until explicitly enabled.
                current[part] = {"enabled": False}
            current = current[part]
        current[parts[-1]] = value
    try:
        result = CicloSecConfig.model_validate(data)
    except ValidationError as error:
        fields = sorted(
            ".".join(str(part) for part in item["loc"])
            for item in error.errors(include_input=False)
        )
        raise ConfigurationError(f"Invalid configuration fields: {', '.join(fields)}") from None
    for provider, provider_config in result.intelligence.providers.items():
        if provider_config.refresh_interval is not None:
            try:
                timedelta(seconds=duration_seconds(provider_config.refresh_interval))
            except (OverflowError, ValueError):
                raise ConfigurationError(
                    "Invalid configuration field: "
                    f"intelligence.providers.{provider}.refresh_interval"
                ) from None
    if "application.timezone" in overrides:
        try:
            ZoneInfo(result.application.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            raise ConfigurationError("Invalid configuration field: application.timezone") from None
    return result


def _value_at(config: CicloSecConfig, key: str) -> object:
    current: object = config.model_dump(mode="python")
    for part in key.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def configuration_snapshot(base: CicloSecConfig) -> tuple[int, CicloSecConfig]:
    """Read the revision and validated effective configuration from the same row."""
    state = ConfigurationState.objects.get(pk=1)
    return state.revision, _validated_config(base, state.overrides)


def effective_config(base: CicloSecConfig) -> CicloSecConfig:
    """Return a fresh validated snapshot; failures are not hidden."""
    return configuration_snapshot(base)[1]


def get_effective_config() -> CicloSecConfig:
    """Resolve the current configuration after Django's database is available."""
    return effective_config(settings.CICLOSEC_CONFIG)


def update_configuration(
    *,
    actor: AbstractBaseUser,
    changes: Mapping[str, object],
    expected_revision: int,
    confirm: bool,
    base: CicloSecConfig,
) -> int:
    """Apply one confirmed update with optimistic and database locking."""
    if confirm is not True:
        raise PermissionDenied("Explicit confirmation is required.")
    if not changes:
        raise ConfigurationError("At least one configuration field is required")
    with transaction.atomic():
        state = ConfigurationState.objects.select_for_update().get(pk=1)
        authorized = (
            get_user_model().objects.filter(pk=actor.pk, is_active=True, is_superuser=True).exists()
        )
        if not authorized:
            raise PermissionDenied("An active superuser is required.")
        if state.revision != expected_revision:
            raise ConfigurationConflict("Configuration changed; reload and try again.")
        before = _validated_config(base, state.overrides)
        merged = {**state.overrides, **changes}
        after = _validated_config(base, merged)
        changed_keys = [key for key in changes if _value_at(before, key) != _value_at(after, key)]
        if not changed_keys:
            return state.revision
        state.revision += 1
        state.overrides = merged
        state.save(update_fields=["revision", "overrides"])
        ConfigurationChange.objects.bulk_create(
            [
                ConfigurationChange(
                    revision=state.revision,
                    actor_id=actor.pk,
                    key=key,
                    old_value=_value_at(before, key),
                    new_value=_value_at(after, key),
                )
                for key in changed_keys
            ]
        )
        return state.revision
