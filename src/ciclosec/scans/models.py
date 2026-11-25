"""Durable scan execution history."""

from django.db import models
from django.db.models import F, Q


class ScanConcurrencyGate(models.Model):
    """Singleton row used to serialize global scan capacity checks."""

    id = models.PositiveSmallIntegerField(primary_key=True, default=1, editable=False)

    class Meta:
        constraints = [
            models.CheckConstraint(condition=Q(id=1), name="scan_concurrency_gate_singleton")
        ]


class ScanRun(models.Model):
    """One attempt to analyze an asset with a named tool."""

    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class Diagnostic(models.TextChoices):
        ASSET_DISABLED = "asset_disabled"
        ASSET_KIND_MISMATCH = "asset_kind_mismatch"
        REPOSITORY_MISSING = "repository_missing"
        REPOSITORY_SCANNER_NETWORK_NOT_AUTHORIZED = "repository_scanner_network_not_authorized"
        CREDENTIAL_MISSING = "credential_missing"
        REPOSITORY_CHECKOUT_FAILED = "repository_checkout_failed"
        REPOSITORY_SBOM_FAILED = "repository_sbom_failed"
        SBOM_INVALID = "sbom_invalid"
        OSV_UNAVAILABLE = "osv_unavailable"
        TRIVY_UNAVAILABLE = "trivy_unavailable"
        OSV_VERSION_UNAVAILABLE = "osv_version_unavailable"
        TRIVY_VERSION_UNAVAILABLE = "trivy_version_unavailable"
        DEPENDABOT_UNAVAILABLE = "dependabot_unavailable"
        SCANNER_DATABASE_FRESHNESS_UNVERIFIED = "scanner_database_freshness_unverified"
        SCANNER_DATABASE_CACHE_UNAVAILABLE = "scanner_database_cache_unavailable"
        REPOSITORY_SOURCE_CHANGED = "repository_source_changed"
        IMAGE_SCANNING_DISABLED = "image_scanning_disabled"
        IMAGE_SOURCE_MISSING = "image_source_missing"
        IMAGE_NOT_ALLOWLISTED = "image_not_allowlisted"
        IMAGE_SBOM_FAILED = "image_sbom_failed"
        IMAGE_FINDINGS_UNAVAILABLE = "image_findings_unavailable"
        IMAGE_SOURCE_CHANGED = "image_source_changed"
        CORRELATION_UNAVAILABLE = "correlation_unavailable"
        MANUALLY_RECOVERED = "manually_recovered"
        SCHEDULED_SOURCE_CHANGED = "scheduled_source_changed"

    asset = models.ForeignKey(
        "assets.Asset",
        on_delete=models.PROTECT,
        related_name="scan_runs",
    )
    scanner_name = models.CharField(max_length=128)
    scanner_version = models.CharField(max_length=128, blank=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
    )
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error_summary = models.TextField(blank=True)
    warnings = models.JSONField(default=list, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [
            models.Index(fields=["asset", "status", "-created_at"]),
            models.Index(fields=["status", "-created_at"]),
        ]
        constraints = [
            models.CheckConstraint(
                condition=(
                    Q(finished_at__isnull=True)
                    | Q(started_at__isnull=True)
                    | Q(finished_at__gte=F("started_at"))
                ),
                name="scan_finished_after_start",
            )
        ]

    @property
    def duration_seconds(self) -> float | None:
        """Return elapsed seconds once both timestamps are present."""
        if self.started_at is None or self.finished_at is None:
            return None
        return (self.finished_at - self.started_at).total_seconds()

    def __str__(self) -> str:
        return f"{self.asset.name}: {self.scanner_name} ({self.status})"


class ScanSchedule(models.Model):
    """Explicit, per-asset authorization for recurring scans."""

    asset = models.OneToOneField(
        "assets.Asset", on_delete=models.CASCADE, related_name="scan_schedule"
    )
    enabled = models.BooleanField(default=False)
    activated_at = models.DateTimeField(null=True, blank=True)
    last_scan = models.ForeignKey(
        ScanRun, on_delete=models.PROTECT, null=True, blank=True, related_name="+"
    )
    paused_reason = models.CharField(max_length=32, blank=True)
    source_snapshot = models.JSONField(default=dict)
