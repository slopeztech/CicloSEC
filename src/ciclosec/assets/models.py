"""Registered CicloSec assets."""

import re

from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.db import models

ENVIRONMENT_VARIABLE_NAME = RegexValidator(
    regex=re.compile(r"^[A-Z_][A-Z0-9_]*$"),
    message="Use an environment variable name, not a credential value.",
)


class Asset(models.Model):
    """A technology asset registered for security monitoring."""

    class Kind(models.TextChoices):
        REPOSITORY = "repository", "Repository"
        CONTAINER_IMAGE = "container_image", "Container image"

    class Environment(models.TextChoices):
        PRODUCTION = "production", "Production"
        STAGING = "staging", "Staging"
        DEVELOPMENT = "development", "Development"
        TEST = "test", "Test"
        LOCAL = "local", "Local"
        UNKNOWN = "unknown", "Unknown"

    class Exposure(models.TextChoices):
        INTERNET_FACING = "internet_facing", "Internet facing"
        INTERNAL = "internal", "Internal"
        UNKNOWN = "unknown", "Unknown"

    id = models.BigAutoField(primary_key=True)
    name = models.CharField(max_length=255)
    kind = models.CharField(max_length=32, choices=Kind.choices)
    environment = models.CharField(
        max_length=16,
        choices=Environment.choices,
        default=Environment.UNKNOWN,
    )
    exposure = models.CharField(
        max_length=24,
        choices=Exposure.choices,
        default=Exposure.UNKNOWN,
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name", "id"]
        indexes = [
            models.Index(fields=["kind", "enabled"]),
            models.Index(fields=["environment", "exposure"]),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.get_kind_display()})"


class Repository(models.Model):
    """GitHub repository configuration linked to an asset."""

    class Provider(models.TextChoices):
        GITHUB = "github", "GitHub"

    asset = models.OneToOneField(
        Asset,
        on_delete=models.CASCADE,
        related_name="repository",
    )
    provider = models.CharField(
        max_length=16,
        choices=Provider.choices,
        default=Provider.GITHUB,
    )
    owner = models.CharField(max_length=255)
    repository_name = models.CharField(max_length=255)
    ref = models.CharField(max_length=255, default="main")
    credential_env = models.CharField(
        max_length=128,
        blank=True,
        validators=[ENVIRONMENT_VARIABLE_NAME],
    )
    source_revision = models.PositiveBigIntegerField(default=0)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["provider", "owner", "repository_name", "ref"],
                name="unique_repository_ref",
            )
        ]

    def clean(self) -> None:
        if self.asset_id and self.asset.kind != Asset.Kind.REPOSITORY:
            raise ValidationError({"asset": "Repository details require a repository asset."})
        super().clean()

    def __str__(self) -> str:
        return f"{self.owner}/{self.repository_name}@{self.ref}"


class ContainerImage(models.Model):
    """Container image reference and the digest last resolved for it."""

    asset = models.OneToOneField(
        Asset,
        on_delete=models.CASCADE,
        related_name="container_image",
    )
    image_reference = models.CharField(max_length=512, unique=True)
    resolved_digest = models.CharField(max_length=128, blank=True)
    digest_resolved_at = models.DateTimeField(null=True, blank=True)
    source_revision = models.PositiveBigIntegerField(default=0)

    def clean(self) -> None:
        if self.asset_id and self.asset.kind != Asset.Kind.CONTAINER_IMAGE:
            raise ValidationError({"asset": "Image details require a container image asset."})
        super().clean()

    def __str__(self) -> str:
        return self.image_reference
