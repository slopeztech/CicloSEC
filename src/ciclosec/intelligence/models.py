"""Common vulnerability identifiers and intelligence provenance."""

from django.db import models


class Vulnerability(models.Model):
    """Canonical vulnerability record shared across intelligence providers."""

    canonical_id = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    published_at = models.DateTimeField(null=True, blank=True)
    modified_at = models.DateTimeField(null=True, blank=True)
    merged_into = models.ForeignKey(
        "self",
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="merged_members",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["canonical_id"]
        constraints = [
            models.CheckConstraint(
                condition=~models.Q(pk=models.F("merged_into")),
                name="vulnerability_not_merged_into_self",
            )
        ]

    def __str__(self) -> str:
        return self.canonical_id


class VulnerabilityMerge(models.Model):
    """Auditable equivalence decision; original vulnerability rows remain intact."""

    canonical = models.ForeignKey(
        Vulnerability, on_delete=models.PROTECT, related_name="canonical_merges"
    )
    provider = models.CharField(max_length=32)
    evidence_id = models.CharField(max_length=255)
    identifiers = models.JSONField(default=list)
    sync_run = models.ForeignKey("SyncRun", on_delete=models.PROTECT, related_name="merges")
    created_at = models.DateTimeField(auto_now_add=True)
    references_recorded_at = models.DateTimeField(null=True, blank=True)
    reverted_at = models.DateTimeField(null=True, blank=True)
    reverted_by = models.CharField(max_length=255, blank=True)
    revert_reason = models.TextField(blank=True)


class VulnerabilityMergeMember(models.Model):
    """Original group membership before an equivalence decision."""

    merge = models.ForeignKey(VulnerabilityMerge, on_delete=models.PROTECT, related_name="members")
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.PROTECT)
    previous_root = models.ForeignKey(Vulnerability, on_delete=models.PROTECT, related_name="+")

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["merge", "vulnerability"], name="unique_vulnerability_merge_member"
            )
        ]


class VulnerabilityMergeReference(models.Model):
    """Reference ownership captured when an equivalence is committed."""

    merge = models.ForeignKey(
        VulnerabilityMerge, on_delete=models.PROTECT, related_name="references"
    )
    kind = models.CharField(max_length=16)
    object_id = models.PositiveBigIntegerField()
    vulnerability = models.ForeignKey(Vulnerability, on_delete=models.PROTECT)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["merge", "kind", "object_id"], name="unique_merge_reference"
            )
        ]


class VulnerabilityAlias(models.Model):
    """Provider or ecosystem identifier pointing at a canonical vulnerability."""

    class Namespace(models.TextChoices):
        CVE = "cve", "CVE"
        GHSA = "ghsa", "GitHub Security Advisory"
        OSV = "osv", "OSV"
        OTHER = "other", "Other"

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="aliases",
    )
    namespace = models.CharField(max_length=16, choices=Namespace.choices)
    identifier = models.CharField(max_length=255)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["namespace", "identifier"],
                name="unique_vulnerability_alias",
            )
        ]
        indexes = [models.Index(fields=["identifier"])]

    def __str__(self) -> str:
        return self.identifier


class AdvisoryRecord(models.Model):
    """Provider-specific record and provenance for a vulnerability."""

    class Provider(models.TextChoices):
        NVD = "nvd", "NVD"
        OSV = "osv", "OSV"
        GITHUB = "github_advisories", "GitHub Security Advisories"
        CISA_KEV = "cisa_kev", "CISA KEV"
        EPSS = "epss", "FIRST EPSS"

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name="advisory_records",
    )
    provider = models.CharField(max_length=32, choices=Provider.choices)
    external_id = models.CharField(max_length=255)
    source_url = models.URLField(max_length=2048, blank=True)
    source_modified_at = models.DateTimeField(null=True, blank=True)
    raw_record = models.JSONField(default=dict, blank=True)
    is_active = models.BooleanField(default=True)
    last_seen_sync_run = models.ForeignKey(
        "SyncRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="advisory_records",
    )
    retrieved_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "external_id"],
                name="unique_provider_advisory",
            )
        ]
        indexes = [
            models.Index(fields=["provider", "-retrieved_at"]),
            models.Index(fields=["vulnerability", "provider"]),
        ]

    def __str__(self) -> str:
        return f"{self.provider}:{self.external_id}"


class SyncRun(models.Model):
    """Auditable provider synchronization attempt and resumable checkpoint."""

    class Status(models.TextChoices):
        RUNNING = "running", "Running"
        SUCCEEDED = "succeeded", "Succeeded"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"

    class Mode(models.TextChoices):
        INCREMENTAL = "incremental", "Incremental"
        FULL = "full", "Full"

    provider = models.CharField(max_length=32, choices=AdvisoryRecord.Provider.choices)
    mode = models.CharField(max_length=16, choices=Mode.choices)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.RUNNING)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    records_fetched = models.PositiveIntegerField(default=0)
    records_processed = models.PositiveIntegerField(default=0)
    records_failed = models.PositiveIntegerField(default=0)
    cursor_before = models.JSONField(default=dict, blank=True)
    cursor_after = models.JSONField(default=dict, blank=True)
    error_summary = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [models.Index(fields=["provider", "-started_at"])]

    def __str__(self) -> str:
        return f"{self.provider} {self.started_at:%Y-%m-%d %H:%M:%S} ({self.status})"


class IntelligenceSource(models.Model):
    """Latest synchronization timestamps and freshness metadata per provider."""

    class Status(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        CURRENT = "current", "Current"
        STALE = "stale", "Stale"
        UNAVAILABLE = "unavailable", "Unavailable"

    provider = models.CharField(max_length=32, choices=AdvisoryRecord.Provider.choices, unique=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.UNKNOWN,
    )
    last_attempt_at = models.DateTimeField(null=True, blank=True)
    last_success_at = models.DateTimeField(null=True, blank=True)
    source_updated_at = models.DateTimeField(null=True, blank=True)
    confirmed_cursor = models.JSONField(default=dict, blank=True)
    last_error = models.TextField(blank=True)

    class Meta:
        ordering = ["provider"]

    def __str__(self) -> str:
        return f"{self.provider} ({self.status})"


class ManualSyncRequest(models.Model):
    """Reservation and observed execution state for a manually dispatched task."""

    class Status(models.TextChoices):
        DISPATCHING = "dispatching", "Dispatching"
        QUEUED = "queued", "Queued"
        UNCERTAIN = "uncertain", "Delivery uncertain"
        RUNNING = "running", "Running"
        RETRYING = "retrying", "Retrying"
        SUCCEEDED = "succeeded", "Succeeded"
        PARTIAL = "partial", "Partial"
        FAILED = "failed", "Failed"

    provider = models.CharField(max_length=32, choices=AdvisoryRecord.Provider.choices)
    task_id = models.UUIDField(unique=True)
    status = models.CharField(max_length=16, choices=Status.choices)
    attempt = models.PositiveIntegerField(default=0)
    delivery_error = models.CharField(max_length=40, blank=True)
    claim_token = models.UUIDField(null=True, blank=True)
    requested_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["provider"],
                condition=models.Q(
                    status__in=["dispatching", "queued", "uncertain", "running", "retrying"]
                ),
                name="unique_active_manual_intelligence_sync",
            )
        ]


class ProviderTaskAttempt(models.Model):
    """Committed Celery delivery attempts, used to reject redelivery."""

    provider = models.CharField(max_length=32, choices=AdvisoryRecord.Provider.choices)
    task_id = models.CharField(max_length=255)
    attempt = models.PositiveIntegerField()
    completed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "task_id", "attempt"],
                name="unique_intelligence_provider_task_attempt",
            )
        ]
