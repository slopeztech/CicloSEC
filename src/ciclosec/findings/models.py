"""Persisted scanner evidence associated with an asset and scan run."""

from django.conf import settings
from django.db import models


class Finding(models.Model):
    """A redacted, package-level vulnerability or secret-detection result."""

    class Source(models.TextChoices):
        OSV_SCANNER = "osv_scanner", "OSV-Scanner"
        TRIVY = "trivy", "Trivy"
        GITHUB_DEPENDABOT = "github_dependabot", "GitHub Dependabot"

    class Kind(models.TextChoices):
        VULNERABILITY = "vulnerability", "Vulnerability"
        SECRET = "secret", "Secret"

    class AffectedStatus(models.TextChoices):
        CONFIRMED = "confirmed", "Confirmed affected"
        POTENTIAL = "potential", "Potentially affected"
        NOT_AFFECTED = "not_affected", "Not affected"
        NOT_APPLICABLE = "not_applicable", "Not applicable"
        PENDING_VERIFICATION = "pending_verification", "Pending verification"

    class Confidence(models.TextChoices):
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        UNKNOWN = "unknown", "Unknown"

    scan_run = models.ForeignKey(
        "scans.ScanRun",
        on_delete=models.CASCADE,
        related_name="findings",
    )
    asset = models.ForeignKey(
        "assets.Asset",
        on_delete=models.CASCADE,
        related_name="findings",
    )
    component_occurrence = models.ForeignKey(
        "inventory.ComponentOccurrence",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    vulnerability = models.ForeignKey(
        "intelligence.Vulnerability",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    source = models.CharField(max_length=32, choices=Source.choices)
    kind = models.CharField(max_length=24, choices=Kind.choices)
    fingerprint = models.CharField(max_length=64)
    external_id = models.CharField(max_length=255, blank=True)
    package_name = models.CharField(max_length=512, blank=True)
    package_version = models.CharField(max_length=512, blank=True)
    severity = models.CharField(max_length=24, blank=True)
    title = models.CharField(max_length=1024, blank=True)
    affected_range = models.TextField(blank=True)
    fixed_version = models.CharField(max_length=512, blank=True)
    source_path = models.CharField(max_length=2048, blank=True)
    line_number = models.PositiveIntegerField(null=True, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    affected_status = models.CharField(
        max_length=24,
        choices=AffectedStatus.choices,
        default=AffectedStatus.PENDING_VERIFICATION,
    )
    confidence = models.CharField(
        max_length=16,
        choices=Confidence.choices,
        default=Confidence.UNKNOWN,
    )
    evaluated_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["severity", "external_id", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["scan_run", "fingerprint"],
                name="unique_scan_finding_fingerprint",
            )
        ]
        indexes = [
            models.Index(fields=["asset", "kind", "severity"]),
            models.Index(fields=["vulnerability", "source"]),
        ]

    def __str__(self) -> str:
        identifier = self.external_id or self.title or self.kind
        return f"{self.asset.name}: {identifier}"


class RiskAssessment(models.Model):
    """Versioned, explainable risk priority for one finding."""

    class Level(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFORMATIONAL = "informational", "Informational"
        UNKNOWN = "unknown", "Unknown"

    finding = models.OneToOneField(
        Finding,
        on_delete=models.CASCADE,
        related_name="risk_assessment",
    )
    score = models.PositiveSmallIntegerField(null=True, blank=True)
    level = models.CharField(
        max_length=16,
        choices=Level.choices,
        default=Level.UNKNOWN,
    )
    policy_version = models.CharField(max_length=32)
    factors = models.JSONField(default=dict, blank=True)
    explanation = models.TextField()
    assessed_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.CheckConstraint(
                condition=models.Q(score__isnull=True) | models.Q(score__lte=100),
                name="risk_assessment_score_at_most_100",
            )
        ]

    def __str__(self) -> str:
        return f"{self.finding}: {self.level} ({self.policy_version})"


class FindingDecision(models.Model):
    """Human review state kept separate from the technical finding result."""

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ASSIGNED = "assigned", "Assigned"
        ACCEPTED_RISK = "accepted_risk", "Accepted risk"
        FALSE_POSITIVE = "false_positive", "False positive"
        CLOSED = "closed", "Closed"

    finding = models.OneToOneField(
        Finding,
        on_delete=models.CASCADE,
        related_name="decision",
    )
    status = models.CharField(
        max_length=24,
        choices=Status.choices,
        default=Status.OPEN,
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )
    decided_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="+",
    )
    reason = models.TextField()
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)


class FindingDecisionEvent(models.Model):
    """Immutable audit history for a human finding decision."""

    finding = models.ForeignKey(
        Finding,
        on_delete=models.CASCADE,
        related_name="decision_events",
    )
    status = models.CharField(
        max_length=24,
        choices=FindingDecision.Status.choices,
    )
    assignee = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        null=True,
        blank=True,
        related_name="+",
    )
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name="+",
    )
    reason = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
