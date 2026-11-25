"""Read-only representation of scanner findings."""

from typing import Any

from rest_framework import serializers

from ciclosec.assets.services import scan_source_status_for_asset
from ciclosec.findings.models import (
    Finding,
    RiskAssessment,
)
from ciclosec.findings.services import recent_decision_events


class RiskAssessmentSerializer(serializers.ModelSerializer[RiskAssessment]):
    """Expose the factors and explanation behind a finding's priority."""

    class Meta:
        model = RiskAssessment
        fields = [
            "score",
            "level",
            "policy_version",
            "factors",
            "explanation",
            "assessed_at",
        ]
        read_only_fields = fields


class FindingSerializer(serializers.ModelSerializer[Finding]):
    """Expose normalized, redacted finding evidence."""

    risk_assessment = serializers.SerializerMethodField()
    decision = serializers.SerializerMethodField()
    decision_events = serializers.SerializerMethodField()
    asset_source_status = serializers.SerializerMethodField()

    def get_risk_assessment(self, instance: Finding) -> Any:
        assessment = getattr(instance, "risk_assessment", None)
        if assessment is None:
            return None
        return RiskAssessmentSerializer(assessment).data

    def get_asset_source_status(self, instance: Finding) -> str:
        return scan_source_status_for_asset(
            asset=instance.asset, metadata=instance.scan_run.metadata
        )

    def get_decision(self, instance: Finding) -> Any:
        decision = getattr(instance, "decision", None)
        if decision is None:
            return None
        return {
            "status": decision.status,
            "assignee_id": decision.assignee_id,
            "decided_by_id": decision.decided_by_id,
            "reason": decision.reason,
            "updated_at": decision.updated_at,
        }

    def get_decision_events(self, instance: Finding) -> list[dict[str, Any]]:
        return [
            {
                "status": event.status,
                "assignee_id": event.assignee_id,
                "actor_id": event.actor_id,
                "reason": event.reason,
                "created_at": event.created_at,
            }
            for event in recent_decision_events(instance)
        ]

    class Meta:
        model = Finding
        fields = [
            "id",
            "asset",
            "scan_run",
            "asset_source_status",
            "component_occurrence",
            "vulnerability",
            "source",
            "kind",
            "external_id",
            "package_name",
            "package_version",
            "severity",
            "title",
            "affected_range",
            "fixed_version",
            "source_path",
            "line_number",
            "evidence",
            "affected_status",
            "confidence",
            "evaluated_at",
            "risk_assessment",
            "decision",
            "decision_events",
            "created_at",
        ]
        read_only_fields = fields
