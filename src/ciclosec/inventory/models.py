"""Normalized SBOM documents, software components, and dependency edges."""

from django.db import models
from django.db.models import F, Q


class SBOMDocument(models.Model):
    """Validated CycloneDX or SPDX JSON attached to a completed asset scan."""

    class Format(models.TextChoices):
        CYCLONEDX = "cyclonedx", "CycloneDX"
        SPDX = "spdx", "SPDX"

    scan_run = models.ForeignKey(
        "scans.ScanRun",
        on_delete=models.PROTECT,
        related_name="sbom_documents",
    )
    format = models.CharField(max_length=16, choices=Format.choices)
    format_version = models.CharField(max_length=32)
    checksum_sha256 = models.CharField(max_length=64)
    generated_at = models.DateTimeField()
    component_count = models.PositiveIntegerField(default=0)
    root_component_refs = models.JSONField(default=list, blank=True)
    payload = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-generated_at", "-id"]
        constraints = [
            models.UniqueConstraint(
                fields=["scan_run", "format"],
                name="unique_scan_sbom_format",
            )
        ]
        indexes = [models.Index(fields=["format", "-generated_at"])]

    def __str__(self) -> str:
        return f"{self.scan_run}: {self.get_format_display()} {self.format_version}"


class Component(models.Model):
    """Normalized software package identity."""

    purl = models.CharField(max_length=2048, null=True, blank=True, unique=True)
    ecosystem = models.CharField(max_length=128, default="unknown")
    name = models.CharField(max_length=512)
    component_type = models.CharField(max_length=64, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["ecosystem", "name", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["ecosystem", "name"],
                condition=Q(purl__isnull=True),
                name="unique_component_without_purl",
            )
        ]
        indexes = [models.Index(fields=["ecosystem", "name"])]

    def __str__(self) -> str:
        return self.purl or f"{self.ecosystem}:{self.name}"


class ComponentOccurrence(models.Model):
    """A package version and location as observed in one SBOM."""

    class Relationship(models.TextChoices):
        DIRECT = "direct", "Direct"
        TRANSITIVE = "transitive", "Transitive"
        UNKNOWN = "unknown", "Unknown"

    sbom_document = models.ForeignKey(
        SBOMDocument,
        on_delete=models.CASCADE,
        related_name="occurrences",
    )
    component = models.ForeignKey(
        Component,
        on_delete=models.PROTECT,
        related_name="occurrences",
    )
    bom_ref = models.CharField(max_length=512)
    version = models.CharField(max_length=512, blank=True)
    relationship = models.CharField(
        max_length=16,
        choices=Relationship.choices,
        default=Relationship.UNKNOWN,
    )
    scope = models.CharField(max_length=64, blank=True)
    path = models.CharField(max_length=2048, blank=True)

    class Meta:
        ordering = ["component__name", "version", "id"]
        constraints = [
            models.UniqueConstraint(
                fields=["sbom_document", "bom_ref"],
                name="unique_sbom_component_reference",
            )
        ]
        indexes = [
            models.Index(fields=["component", "version"]),
            models.Index(fields=["sbom_document", "relationship"]),
        ]

    def __str__(self) -> str:
        return f"{self.component.name}@{self.version or 'unknown'}"


class ComponentDependency(models.Model):
    """A directed dependency edge between two occurrences in one SBOM."""

    sbom_document = models.ForeignKey(
        SBOMDocument,
        on_delete=models.CASCADE,
        related_name="dependencies",
    )
    source = models.ForeignKey(
        ComponentOccurrence,
        on_delete=models.CASCADE,
        related_name="outgoing_dependencies",
    )
    target = models.ForeignKey(
        ComponentOccurrence,
        on_delete=models.CASCADE,
        related_name="incoming_dependencies",
    )

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["sbom_document", "source", "target"],
                name="unique_sbom_dependency_edge",
            ),
            models.CheckConstraint(
                condition=~Q(source_id=F("target_id")),
                name="sbom_dependency_not_self_referential",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.source.bom_ref} -> {self.target.bom_ref}"
