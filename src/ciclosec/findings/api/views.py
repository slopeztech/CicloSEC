"""Authenticated finding API."""

from typing import Any

from django.contrib.auth import get_user_model
from django.db.models import Q
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.viewsets import ReadOnlyModelViewSet

from ciclosec.common.api_pagination import LimitOffsetListMixin
from ciclosec.findings.api.serializers import FindingSerializer
from ciclosec.findings.models import Finding, FindingDecision
from ciclosec.findings.services import (
    FindingDecisionError,
    recent_decision_events_prefetch,
    review_finding,
)


class FindingViewSet(LimitOffsetListMixin, ReadOnlyModelViewSet[Finding]):
    """List and retrieve persisted scan findings."""

    queryset = (
        Finding.objects.select_related(
            "asset",
            "asset__repository",
            "asset__container_image",
            "scan_run",
            "component_occurrence__component",
            "vulnerability",
            "risk_assessment",
            "decision",
            "decision__assignee",
            "decision__decided_by",
        )
        .prefetch_related(recent_decision_events_prefetch())
        .all()
    )
    serializer_class = FindingSerializer
    permission_classes = [IsAuthenticated]

    def filter_queryset(self, queryset: Any) -> Any:
        asset_id = self.request.query_params.get("asset")
        affected_status = self.request.query_params.get("affected_status")
        finding_source = self.request.query_params.get("source")
        search = self.request.query_params.get("search")
        if asset_id:
            try:
                queryset = queryset.filter(asset_id=int(asset_id))
            except (TypeError, ValueError):
                return queryset.none()
        if affected_status in Finding.AffectedStatus.values:
            queryset = queryset.filter(affected_status=affected_status)
        if finding_source in Finding.Source.values:
            queryset = queryset.filter(source=finding_source)
        if search:
            search = search.strip()[:200]
            if search:
                queryset = queryset.filter(
                    Q(external_id__icontains=search) | Q(package_name__icontains=search)
                )
        return queryset.order_by("-created_at", "-id")

    @action(detail=True, methods=["post"], url_path="decision")
    def decision(self, request: Request, pk: int | None = None) -> Response:
        if not request.user.is_staff:
            return Response(
                {"detail": "Only administrators can review findings."},
                status=status.HTTP_403_FORBIDDEN,
            )
        human_status = request.data.get("status")
        reason = request.data.get("reason")
        assignee_id = request.data.get("assignee")
        if not isinstance(human_status, str) or human_status not in FindingDecision.Status.values:
            return Response({"detail": "Unsupported human review status."}, status=400)
        if not isinstance(reason, str):
            return Response({"detail": "A reason is required."}, status=400)
        assignee = None
        if assignee_id not in (None, ""):
            try:
                assignee = get_user_model().objects.get(pk=int(assignee_id), is_active=True)
            except (TypeError, ValueError, get_user_model().DoesNotExist):
                return Response({"detail": "Assignee is not valid."}, status=400)
        try:
            review_finding(
                finding_id=int(self.get_object().pk),
                status=human_status,
                reason=reason,
                actor=request.user,
                assignee=assignee,
            )
        except FindingDecisionError as error:
            return Response({"detail": str(error)}, status=400)
        return Response(FindingSerializer(self.get_object()).data, status=status.HTTP_200_OK)
