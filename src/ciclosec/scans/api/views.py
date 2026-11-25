"""Authenticated API for requesting and viewing repository scans."""

from collections.abc import Mapping
from typing import Any

from django.conf import settings
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.exceptions import PermissionDenied
from rest_framework.mixins import CreateModelMixin, ListModelMixin, RetrieveModelMixin
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import GenericViewSet

from ciclosec.assets.models import Asset
from ciclosec.common.api_pagination import LimitOffsetListMixin
from ciclosec.common.settings_service import effective_config
from ciclosec.scanners.tasks import scan_container_image_task, scan_repository_task
from ciclosec.scans.api.serializers import ScanRunSerializer
from ciclosec.scans.models import ScanRun
from ciclosec.scans.services import (
    ActiveScanError,
    RepositoryScannerNetworkNotAuthorized,
    ScanQueueFullError,
    create_scan_for_locked_asset,
    dispatch_scan,
    get_scan_queue_status,
)


class ScanRunViewSet(
    LimitOffsetListMixin,
    CreateModelMixin,
    ListModelMixin,
    RetrieveModelMixin,
    GenericViewSet[ScanRun],
):
    """Request a scan when explicitly enabled and read its recorded result."""

    queryset = ScanRun.objects.select_related("asset").all()
    serializer_class = ScanRunSerializer
    permission_classes = [IsAuthenticated]
    http_method_names = ["get", "post", "head", "options"]

    def filter_queryset(self, queryset: Any) -> Any:
        asset_id = self.request.query_params.get("asset")
        scan_status = self.request.query_params.get("status")
        if asset_id:
            try:
                queryset = queryset.filter(asset_id=int(asset_id))
            except (TypeError, ValueError):
                return queryset.none()
        if scan_status in ScanRun.Status.values:
            queryset = queryset.filter(status=scan_status)
        return queryset.order_by("-created_at", "-id")

    @action(detail=False, methods=["get"], url_path="queue-status")
    @method_decorator(never_cache)
    def queue_status(self, request: Request) -> Response:
        return Response(get_scan_queue_status())

    def create(
        self,
        request: Request,
        *args: Any,
        **kwargs: Any,
    ) -> Response:
        if not effective_config(settings.CICLOSEC_CONFIG).scanning.execution.allow_on_demand:
            raise PermissionDenied("On-demand scans are disabled by local configuration.")
        serializer = ScanRunSerializer(data=request.data, context=self.get_serializer_context())
        serializer.is_valid(raise_exception=True)
        dispatch_failed = False
        with transaction.atomic():
            asset = Asset.objects.select_for_update().get(pk=serializer.validated_data["asset"].pk)
            serializer.validate_asset(asset)
            try:
                scan_run = create_scan_for_locked_asset(asset)
            except ActiveScanError as error:
                return Response(
                    {
                        "detail": "An active scan already exists for this asset.",
                        "scan_id": error.scan_id,
                    },
                    status=status.HTTP_409_CONFLICT,
                )
            except RepositoryScannerNetworkNotAuthorized as error:
                return Response(
                    {
                        "detail": str(error),
                        "code": ScanRun.Diagnostic.REPOSITORY_SCANNER_NETWORK_NOT_AUTHORIZED,
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
            except ScanQueueFullError:
                return Response(
                    {
                        "detail": (
                            "The scan queue is full; try again after a queued scan is processed."
                        )
                    },
                    status=status.HTTP_429_TOO_MANY_REQUESTS,
                )

            serializer.instance = scan_run

            def dispatch() -> None:
                nonlocal dispatch_failed
                send = (
                    scan_container_image_task.delay
                    if asset.kind == Asset.Kind.CONTAINER_IMAGE
                    else scan_repository_task.delay
                )
                dispatch_failed = not dispatch_scan(scan_run.pk, send)

            transaction.on_commit(dispatch)
        if dispatch_failed:
            return Response(
                {
                    "detail": (
                        "Task delivery could not be confirmed; inspect the scan before acting."
                    ),
                    "scan_id": scan_run.pk,
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        scan_run.refresh_from_db()
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED, headers=headers)

    @action(detail=True, methods=["post"], url_path="cancel-queued")
    def cancel_queued(self, request: Request, pk: str | None = None) -> Response:
        confirmation = request.data.get("confirm") if isinstance(request.data, Mapping) else None
        if confirmation is not True and confirmation != "true":
            return Response(
                {"detail": "Explicit confirmation is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        with transaction.atomic():
            scan = get_object_or_404(ScanRun.objects.select_for_update(), pk=pk)
            if scan.status != ScanRun.Status.QUEUED or scan.started_at is not None:
                return Response(
                    {"detail": "Only scans that have not started can be cancelled."},
                    status=status.HTTP_409_CONFLICT,
                )
            if not isinstance(scan.metadata, dict):
                raise ValueError(f"Scan {scan.pk} has invalid metadata")
            scan.status = ScanRun.Status.CANCELLED
            scan.finished_at = timezone.now()
            scan.metadata = {**scan.metadata, "cancelled_by_user_id": request.user.pk}
            scan.save(update_fields=["status", "finished_at", "metadata"])
        return Response({"id": scan.pk, "status": scan.status})
