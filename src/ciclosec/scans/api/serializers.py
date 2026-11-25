"""Serializers for requesting and reading repository scans."""

from typing import Any

from rest_framework import serializers

from ciclosec.assets.models import Asset, ContainerImage
from ciclosec.common.settings_service import get_effective_config
from ciclosec.scans.models import ScanRun


class ScanRunSerializer(serializers.ModelSerializer[ScanRun]):
    """Expose scan status while keeping execution metadata server-controlled."""

    class Meta:
        model = ScanRun
        fields = [
            "id",
            "asset",
            "scanner_name",
            "scanner_version",
            "status",
            "started_at",
            "finished_at",
            "error_summary",
            "warnings",
            "metadata",
            "created_at",
        ]
        read_only_fields = [
            "id",
            "scanner_name",
            "scanner_version",
            "status",
            "started_at",
            "finished_at",
            "error_summary",
            "warnings",
            "metadata",
            "created_at",
        ]

    def validate_asset(self, asset: Asset) -> Asset:
        if not asset.enabled:
            raise serializers.ValidationError("Only enabled assets can be scanned.")
        if asset.kind == Asset.Kind.REPOSITORY:
            if not hasattr(asset, "repository"):
                raise serializers.ValidationError(
                    "Repository source configuration is required before scanning."
                )
            return asset
        if asset.kind == Asset.Kind.CONTAINER_IMAGE:
            try:
                container_image = asset.container_image
            except ContainerImage.DoesNotExist:
                raise serializers.ValidationError(
                    "Container image source configuration is required before scanning."
                ) from None
            docker_config = get_effective_config().docker
            if not docker_config.enabled or not docker_config.allow_local_daemon:
                raise serializers.ValidationError(
                    "Local Docker image scanning is disabled by configuration."
                )
            if container_image.image_reference not in {
                image.reference for image in docker_config.images
            }:
                raise serializers.ValidationError("Container image reference is not allowlisted.")
            return asset
        raise serializers.ValidationError("This asset type cannot be scanned.")

    def create(self, validated_data: dict[str, Any]) -> ScanRun:
        asset = validated_data["asset"]
        return ScanRun.objects.create(
            asset=asset,
            scanner_name=(
                "container-image-security"
                if asset.kind == Asset.Kind.CONTAINER_IMAGE
                else "repository-security"
            ),
        )
