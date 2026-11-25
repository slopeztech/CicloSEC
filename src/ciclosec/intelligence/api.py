"""Authenticated manual intelligence synchronization API."""

from collections.abc import Mapping

from django.db import DatabaseError
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import status
from rest_framework.parsers import JSONParser
from rest_framework.permissions import IsAdminUser
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from ciclosec.intelligence.manual_sync_service import (
    ManualSyncConfirmationRequired,
    ManualSyncUnavailable,
    get_manual_sync_status,
    request_manual_sync,
)


@method_decorator(never_cache, name="dispatch")
class ManualSyncView(APIView):
    permission_classes = [IsAdminUser]
    parser_classes = [JSONParser]

    def get(self, request: Request) -> Response:
        try:
            return Response(get_manual_sync_status(actor=request.user))
        except DatabaseError:
            return Response(
                {"detail": "Synchronization status is unavailable."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )

    def post(self, request: Request) -> Response:
        confirm = request.data.get("confirm") if isinstance(request.data, Mapping) else None
        try:
            result = request_manual_sync(actor=request.user, confirm=confirm)
        except ManualSyncConfirmationRequired:
            return Response(
                {"detail": "Explicit confirmation is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except (DatabaseError, ManualSyncUnavailable):
            return Response(
                {"detail": "Synchronization status is unavailable; inspect before retrying."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        providers = result["providers"]
        code: int
        if any(
            item["status"] == "uncertain"
            or item["error"] in {"followup_delivery_pending", "followup_delivery_uncertain"}
            for item in providers
        ):
            code = status.HTTP_503_SERVICE_UNAVAILABLE
        elif any(item["duplicate"] for item in providers):
            code = status.HTTP_409_CONFLICT
        else:
            code = status.HTTP_202_ACCEPTED
        return Response(result, status=code)
