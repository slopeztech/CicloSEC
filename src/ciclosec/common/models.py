"""Persistent administrator-managed configuration and audit history."""

import uuid

from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone


class ConfigurationState(models.Model):
    """Singleton holding explicit overrides and their revision."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)
    revision = models.PositiveBigIntegerField(default=0)
    overrides = models.JSONField(default=dict)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(id=1), name="configuration_state_singleton")
        ]


class ConfigurationChange(models.Model):
    """Audit entry for a validated configuration change."""

    revision = models.PositiveBigIntegerField()
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="+")
    key = models.CharField(max_length=128)
    old_value = models.JSONField(null=True)
    new_value = models.JSONField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)


class BeatObservation(models.Model):
    """Most recent scheduling tick reported by one Beat scheduler instance."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    revision = models.PositiveBigIntegerField()
    last_seen_at = models.DateTimeField(default=timezone.now, db_index=True)
