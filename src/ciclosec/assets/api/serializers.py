"""DRF serializers for assets and their initial source types."""

from typing import Any

from rest_framework import serializers

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.assets.services import update_container_image_source, update_repository_source
from ciclosec.scanners.adapters import validate_local_image_reference
from ciclosec.scanners.github import _validate_repository
from ciclosec.scanners.process import ScannerExecutionError


class AssetSerializer(serializers.ModelSerializer[Asset]):
    """Serialize a registered asset without exposing credential values."""

    class Meta:
        model = Asset
        fields = [
            "id",
            "name",
            "kind",
            "environment",
            "exposure",
            "enabled",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]

    def validate_kind(self, value: str) -> str:
        if self.instance is not None and value != self.instance.kind:
            raise serializers.ValidationError("The kind of a registered asset cannot be changed.")
        return value


class RepositorySerializer(serializers.ModelSerializer[Repository]):
    """Serialize a GitHub repository configuration."""

    class Meta:
        model = Repository
        fields = [
            "id",
            "asset",
            "provider",
            "owner",
            "repository_name",
            "ref",
            "credential_env",
        ]
        read_only_fields = ["id"]

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        asset = attrs.get("asset")
        if asset is None and self.instance is not None:
            asset = self.instance.asset
        if asset is not None and asset.kind != Asset.Kind.REPOSITORY:
            raise serializers.ValidationError(
                {"asset": "Repository details require a repository asset."}
            )
        owner = attrs.get("owner", self.instance.owner if self.instance else None)
        name = attrs.get(
            "repository_name", self.instance.repository_name if self.instance else None
        )
        ref = attrs.get("ref", self.instance.ref if self.instance else Repository().ref)
        if isinstance(owner, str) and isinstance(name, str) and isinstance(ref, str):
            try:
                _validate_repository(owner, name, ref)
            except ScannerExecutionError:
                raise serializers.ValidationError(
                    "Check the repository owner, name, and reference."
                ) from None
        return attrs

    def update(self, instance: Repository, validated_data: dict[str, Any]) -> Repository:
        return update_repository_source(instance, **validated_data)


class ContainerImageSerializer(serializers.ModelSerializer[ContainerImage]):
    """Serialize a container image reference and its resolved digest."""

    class Meta:
        model = ContainerImage
        fields = ["id", "asset", "image_reference", "resolved_digest", "digest_resolved_at"]
        read_only_fields = ["id", "resolved_digest", "digest_resolved_at"]

    def validate_image_reference(self, value: str) -> str:
        try:
            validate_local_image_reference(value)
        except ScannerExecutionError:
            raise serializers.ValidationError("The local image reference is invalid.") from None
        return value

    def validate(self, attrs: dict[str, Any]) -> dict[str, Any]:
        asset = attrs.get("asset")
        if asset is None and self.instance is not None:
            asset = self.instance.asset
        if asset is not None and asset.kind != Asset.Kind.CONTAINER_IMAGE:
            raise serializers.ValidationError(
                {"asset": "Image details require a container image asset."}
            )
        return attrs

    def update(self, instance: ContainerImage, validated_data: dict[str, Any]) -> ContainerImage:
        return update_container_image_source(instance, **validated_data)


class SBOMComponentsQuerySerializer(serializers.Serializer[dict[str, Any]]):
    """Validate bounded SBOM component query parameters."""

    scan_run_id = serializers.IntegerField(required=False, min_value=1)
    limit = serializers.IntegerField(default=100, min_value=1, max_value=100)
    offset = serializers.IntegerField(default=0, min_value=0)
