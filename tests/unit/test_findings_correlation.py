"""Finding correlation and explainable risk-priority tests."""

import json
from pathlib import Path
from typing import Any

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from ciclosec.assets.models import Asset
from ciclosec.findings.models import (
    Finding,
    FindingDecision,
    FindingDecisionEvent,
    RiskAssessment,
)
from ciclosec.findings.services import FindingDecisionError, reevaluate_findings, review_finding
from ciclosec.intelligence.models import (
    AdvisoryRecord,
    IntelligenceSource,
    Vulnerability,
    VulnerabilityAlias,
)
from ciclosec.inventory.models import ComponentOccurrence, SBOMDocument
from ciclosec.inventory.sbom import ingest_sbom
from ciclosec.scans.models import ScanRun

SBOM_FIXTURE = Path(__file__).parents[1] / "fixtures" / "sbom" / "cyclonedx-1.7.json"
pytestmark = pytest.mark.django_db


@pytest.fixture
def correlation_case() -> tuple[Finding, Vulnerability]:
    asset = Asset.objects.create(
        name="production-api",
        kind=Asset.Kind.REPOSITORY,
        environment=Asset.Environment.PRODUCTION,
        exposure=Asset.Exposure.INTERNET_FACING,
    )
    scan_run = ScanRun.objects.create(
        asset=asset,
        scanner_name="fixture-scanner",
        status=ScanRun.Status.SUCCEEDED,
    )
    sbom = ingest_sbom(
        scan_run,
        SBOMDocument.Format.CYCLONEDX,
        json.loads(SBOM_FIXTURE.read_text(encoding="utf-8")),
    )
    occurrence = ComponentOccurrence.objects.get(
        sbom_document=sbom,
        component__name="Flask",
    )
    vulnerability = Vulnerability.objects.create(canonical_id="CVE-2026-0001")
    VulnerabilityAlias.objects.create(
        vulnerability=vulnerability,
        namespace=VulnerabilityAlias.Namespace.CVE,
        identifier="CVE-2026-0001",
    )
    finding = Finding.objects.create(
        scan_run=scan_run,
        asset=asset,
        component_occurrence=occurrence,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="f" * 64,
        external_id="PYSEC-2026-1",
        package_name="Flask",
        package_version="2.2.0",
        evidence={"aliases": ["CVE-2026-0001"]},
    )
    return finding, vulnerability


def create_osv_record(
    vulnerability: Vulnerability,
    affected: list[dict[str, Any]],
) -> AdvisoryRecord:
    return AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.OSV,
        external_id="PYSEC-2026-1",
        raw_record={"affected": affected},
    )


def test_alias_relinking_and_risk_assessment_do_not_rerun_scanners(
    correlation_case: tuple[Finding, Vulnerability],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    finding, vulnerability = correlation_case
    create_osv_record(
        vulnerability,
        [
            {
                "package": {"ecosystem": "PyPI", "name": "Flask"},
                "versions": ["2.2.0"],
            }
        ],
    )
    AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.NVD,
        external_id="CVE-2026-0001",
        raw_record={
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 9.8}},
                ]
            }
        },
    )
    AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.EPSS,
        external_id="CVE-2026-0001",
        raw_record={"epss": 0.125, "percentile": 0.75},
    )
    AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.CISA_KEV,
        external_id="CVE-2026-0001",
        raw_record={},
    )
    for provider in AdvisoryRecord.Provider.values:
        IntelligenceSource.objects.update_or_create(
            provider=provider,
            defaults={"status": IntelligenceSource.Status.CURRENT},
        )
    monkeypatch.setattr(
        "ciclosec.scanners.services.run_osv_scanner",
        lambda *_args, **_kwargs: pytest.fail("correlation must not invoke scanners"),
    )
    monkeypatch.setattr(
        "ciclosec.scanners.services.run_trivy_findings",
        lambda *_args, **_kwargs: pytest.fail("correlation must not invoke scanners"),
    )

    assert reevaluate_findings() == 1

    finding.refresh_from_db()
    assessment = RiskAssessment.objects.get(finding=finding)
    assert finding.vulnerability_id == vulnerability.pk
    assert finding.affected_status == Finding.AffectedStatus.CONFIRMED
    assert finding.confidence == Finding.Confidence.HIGH
    assert assessment.score == 82
    assert assessment.level == RiskAssessment.Level.CRITICAL
    assert assessment.policy_version == "risk-v1"
    assert "CVSS" in assessment.explanation
    assert "Source freshness" in assessment.explanation
    assert assessment.factors["source_freshness"][AdvisoryRecord.Provider.EPSS] == "current"
    assert ScanRun.objects.count() == 1
    assert SBOMDocument.objects.count() == 1


def test_unsupported_version_syntax_remains_potential(
    correlation_case: tuple[Finding, Vulnerability],
) -> None:
    finding, vulnerability = correlation_case
    create_osv_record(
        vulnerability,
        [
            {
                "package": {"ecosystem": "PyPI", "name": "flask"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [{"introduced": "abc123"}, {"fixed": "def456"}],
                    }
                ],
            }
        ],
    )

    reevaluate_findings()

    finding.refresh_from_db()
    assert finding.affected_status == Finding.AffectedStatus.POTENTIAL
    assert finding.confidence == Finding.Confidence.LOW
    assert finding.risk_assessment.score is None
    assert finding.risk_assessment.level == RiskAssessment.Level.UNKNOWN


def test_exact_version_outside_advisory_scope_is_not_affected(
    correlation_case: tuple[Finding, Vulnerability],
) -> None:
    finding, vulnerability = correlation_case
    create_osv_record(
        vulnerability,
        [
            {
                "package": {"ecosystem": "PyPI", "name": "Flask"},
                "versions": ["2.2.5"],
            }
        ],
    )

    reevaluate_findings()

    finding.refresh_from_db()
    assert finding.affected_status == Finding.AffectedStatus.NOT_AFFECTED
    assert finding.confidence == Finding.Confidence.HIGH
    assert finding.risk_assessment.score is None


def test_nvd_cpe_evidence_does_not_confirm_package_applicability(
    correlation_case: tuple[Finding, Vulnerability],
) -> None:
    finding, vulnerability = correlation_case
    AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.NVD,
        external_id="CVE-2026-0001",
        raw_record={
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 7.5}},
                ]
            },
            "configurations": [{"nodes": []}],
        },
    )

    reevaluate_findings()

    finding.refresh_from_db()
    assert finding.affected_status == Finding.AffectedStatus.PENDING_VERIFICATION
    assert finding.confidence == Finding.Confidence.UNKNOWN
    assert finding.risk_assessment.score == 45
    assert "provisional" in finding.risk_assessment.explanation


def test_human_review_is_audited_and_does_not_change_technical_result(
    correlation_case: tuple[Finding, Vulnerability],
) -> None:
    finding, _vulnerability = correlation_case
    reevaluate_findings()
    finding.refresh_from_db()
    technical_status = finding.affected_status
    technical_confidence = finding.confidence
    actor = get_user_model().objects.create_user(username="reviewer", is_staff=True)
    assignee = get_user_model().objects.create_user(username="assignee")

    decision = review_finding(
        finding_id=finding.pk,
        status=FindingDecision.Status.ACCEPTED_RISK,
        reason="Reviewed with compensating controls",
        actor=actor,
        assignee=assignee,
    )

    finding.refresh_from_db()
    assert decision.status == FindingDecision.Status.ACCEPTED_RISK
    assert decision.assignee == assignee
    assert FindingDecisionEvent.objects.filter(finding=finding).count() == 1
    assert finding.affected_status == technical_status
    assert finding.confidence == technical_confidence
    reevaluate_findings(scan_run_id=finding.scan_run_id)
    finding.refresh_from_db()
    assert finding.decision.status == FindingDecision.Status.ACCEPTED_RISK


def test_human_review_requires_reason_and_assignee(
    correlation_case: tuple[Finding, Vulnerability],
) -> None:
    finding, _vulnerability = correlation_case
    actor = get_user_model().objects.create_user(username="reviewer-two", is_staff=True)

    with pytest.raises(FindingDecisionError, match="reason"):
        review_finding(
            finding_id=finding.pk,
            status=FindingDecision.Status.CLOSED,
            reason=" ",
            actor=actor,
        )
    with pytest.raises(FindingDecisionError, match="assignee"):
        review_finding(
            finding_id=finding.pk,
            status=FindingDecision.Status.ASSIGNED,
            reason="Needs investigation",
            actor=actor,
        )


def test_finding_api_exposes_read_only_correlation_and_risk(
    correlation_case: tuple[Finding, Vulnerability],
) -> None:
    finding, _vulnerability = correlation_case
    reevaluate_findings()
    user = get_user_model().objects.create_user(username="findings-api-test")
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.get(f"/api/findings/{finding.pk}/")

    assert response.status_code == 200
    assert response.data["affected_status"] == Finding.AffectedStatus.PENDING_VERIFICATION
    assert response.data["confidence"] == Finding.Confidence.UNKNOWN
    assert response.data["risk_assessment"]["score"] is None
    assert response.data["risk_assessment"]["level"] == RiskAssessment.Level.UNKNOWN


def test_finding_api_accepts_staff_decision_and_rejects_regular_user(
    correlation_case: tuple[Finding, Vulnerability],
) -> None:
    finding, _vulnerability = correlation_case
    staff = get_user_model().objects.create_user(username="staff-reviewer", is_staff=True)
    regular = get_user_model().objects.create_user(username="regular-reviewer")

    regular_client = APIClient()
    regular_client.force_authenticate(user=regular)
    denied = regular_client.post(
        f"/api/findings/{finding.pk}/decision/",
        {"status": FindingDecision.Status.CLOSED, "reason": "No longer applicable"},
        format="json",
    )
    assert denied.status_code == 403

    staff_client = APIClient()
    staff_client.force_authenticate(user=staff)
    response = staff_client.post(
        f"/api/findings/{finding.pk}/decision/",
        {"status": FindingDecision.Status.FALSE_POSITIVE, "reason": "Confirmed test fixture"},
        format="json",
    )
    assert response.status_code == 200
    assert response.data["decision"]["status"] == FindingDecision.Status.FALSE_POSITIVE
