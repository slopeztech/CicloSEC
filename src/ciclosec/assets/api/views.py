"""Authenticated REST viewsets for registered assets."""

from collections.abc import Mapping
from typing import Any

from django.db import transaction
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet

from ciclosec.assets.api.serializers import (
    AssetSerializer,
    ContainerImageSerializer,
    RepositorySerializer,
    SBOMComponentsQuerySerializer,
)
from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.common.api_pagination import LimitOffsetListMixin
from ciclosec.inventory.services import list_asset_components
from ciclosec.scans.models import ScanRun, ScanSchedule
from ciclosec.scans.scheduling import (
    describe_schedule,
    dispatch_scheduled_scan,
    pause_reason,
    source_fingerprint,
    source_snapshot,
)
from ciclosec.scans.services import (
    ActiveScanError,
    RepositoryScannerNetworkNotAuthorized,
    ScanQueueFullError,
    create_scan_for_locked_asset,
)


class AssetViewSet(LimitOffsetListMixin, ModelViewSet[Asset]):
    """List and manage registered assets."""

    queryset = Asset.objects.all()
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]

    def filter_queryset(self, queryset: Any) -> Any:
        kind = self.request.query_params.get("kind")
        enabled = self.request.query_params.get("enabled")
        search = self.request.query_params.get("search")
        if kind in Asset.Kind.values:
            queryset = queryset.filter(kind=kind)
        if enabled in {"true", "false"}:
            queryset = queryset.filter(enabled=enabled == "true")
        if search:
            search = search.strip()[:200]
            if search:
                queryset = queryset.filter(name__icontains=search)
        return queryset.order_by("name", "id")

    @action(detail=True, methods=["get", "post"], url_path="scan-schedule")
    @method_decorator(never_cache)
    def scan_schedule(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        asset = self.get_object()
        if request.method == "GET":
            return Response(describe_schedule(asset))
        if not request.user.is_staff:
            raise PermissionDenied("Only administrators can change scan schedules.")
        data = request.data if isinstance(request.data, Mapping) else {}
        enabled = data.get("enabled")
        if not (isinstance(enabled, bool) or enabled in ("true", "false")):
            return Response({"detail": "A boolean enabled value is required."}, status=400)
        enabled = enabled is True or enabled == "true"
        if enabled and data.get("confirm") is not True and data.get("confirm") != "true":
            return Response({"detail": "Explicit confirmation is required."}, status=400)
        expected_source = data.get("source_fingerprint")
        if enabled and not isinstance(expected_source, str):
            return Response({"detail": "Review the source before authorizing it."}, status=400)
        dispatch_failed = False
        with transaction.atomic():
            asset = Asset.objects.select_for_update().get(pk=asset.pk)
            schedule = ScanSchedule.objects.select_for_update().filter(asset=asset).first()
            if not enabled:
                if schedule is not None:
                    schedule.enabled = False
                    schedule.save(update_fields=["enabled"])
                return Response({"status": "disabled"})
            source = source_snapshot(asset)
            if expected_source != source_fingerprint(source):
                return Response(
                    {"detail": "The source changed; review it before authorizing."}, status=409
                )
            if (
                schedule is not None
                and schedule.enabled
                and not pause_reason(schedule)
                and source == schedule.source_snapshot
            ):
                return Response({"detail": "The schedule is already enabled."}, status=409)
            try:
                scan = create_scan_for_locked_asset(asset)
            except ActiveScanError as error:
                return Response({"detail": str(error), "scan_id": error.scan_id}, status=409)
            except RepositoryScannerNetworkNotAuthorized as error:
                return Response(
                    {
                        "detail": str(error),
                        "code": ScanRun.Diagnostic.REPOSITORY_SCANNER_NETWORK_NOT_AUTHORIZED,
                    },
                    status=403,
                )
            except ScanQueueFullError:
                return Response({"detail": "The scan queue is full."}, status=429)
            activated_at = timezone.now()
            # The first scan must belong to this authorization window.
            scan.metadata = {**scan.metadata, "scheduled_source": source}
            scan.save(update_fields=["metadata"])
            if schedule is None:
                schedule = ScanSchedule(asset=asset)
            schedule.enabled = True
            schedule.activated_at = min(activated_at, scan.created_at)
            schedule.last_scan = scan
            schedule.paused_reason = ""
            schedule.source_snapshot = source
            schedule.save()

            def dispatch() -> None:
                nonlocal dispatch_failed
                dispatch_failed = not dispatch_scheduled_scan(scan)

            transaction.on_commit(dispatch)
        if dispatch_failed:
            return Response(
                {"detail": "Task delivery could not be confirmed.", "scan_id": scan.pk},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response({"status": "enabled", "scan_id": scan.pk}, status=202)

    @action(detail=True, methods=["get"], url_path="sbom")
    def sbom(self, request: Request, *args: Any, **kwargs: Any) -> Response:
        """Return normalized components from this asset's latest or selected SBOM."""
        asset = self.get_object()
        query = SBOMComponentsQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        scan_run_id = query.validated_data.get("scan_run_id")
        if scan_run_id is not None and not asset.scan_runs.filter(pk=scan_run_id).exists():
            raise ValidationError({"scan_run_id": "The scan run does not belong to this asset."})
        return Response(
            list_asset_components(
                asset_id=asset.pk,
                scan_run_id=scan_run_id,
                limit=query.validated_data["limit"],
                offset=query.validated_data["offset"],
            )
        )


class RepositoryViewSet(LimitOffsetListMixin, ModelViewSet[Repository]):
    """List and manage configured GitHub repositories."""

    queryset = Repository.objects.select_related("asset").all()
    serializer_class = RepositorySerializer
    permission_classes = [IsAuthenticated]

    def filter_queryset(self, queryset: Any) -> Any:
        search = self.request.query_params.get("search")
        if search:
            search = search.strip()[:200]
            if search:
                queryset = queryset.filter(owner__icontains=search) | queryset.filter(
                    repository_name__icontains=search
                )
        return queryset.order_by("owner", "repository_name", "id")


class ContainerImageViewSet(LimitOffsetListMixin, ModelViewSet[ContainerImage]):
    """List and manage configured container image references."""

    queryset = ContainerImage.objects.select_related("asset").all()
    serializer_class = ContainerImageSerializer
    permission_classes = [IsAuthenticated]

    def filter_queryset(self, queryset: Any) -> Any:
        search = self.request.query_params.get("search")
        if search:
            search = search.strip()[:200]
            if search:
                queryset = queryset.filter(image_reference__icontains=search)
        return queryset.order_by("image_reference", "id")
