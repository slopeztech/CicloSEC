"""Authenticated API for the bounded dashboard summary."""

from typing import Any

from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from ciclosec.findings.models import Finding
from ciclosec.web.services import get_dashboard_summary


class DashboardQuerySerializer(serializers.Serializer[dict[str, Any]]):
    """Validate optional dashboard filters."""

    asset_id = serializers.IntegerField(required=False, min_value=1)
    affected_status = serializers.ChoiceField(
        choices=Finding.AffectedStatus.choices,
        required=False,
    )
    assets_page = serializers.IntegerField(default=1, min_value=1)
    scans_page = serializers.IntegerField(default=1, min_value=1)
    findings_page = serializers.IntegerField(default=1, min_value=1)


@method_decorator(never_cache, name="dispatch")
class DashboardSummaryView(APIView):
    """Return bounded dashboard data to authenticated users only."""

    permission_classes = [IsAuthenticated]

    def get(self, request: Request) -> Response:
        query = DashboardQuerySerializer(data=request.query_params)
        query.is_valid(raise_exception=True)
        return Response(get_dashboard_summary(**query.validated_data))
