"""Authentication, filtering, and redaction tests for the local dashboard."""

import json
from datetime import timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.test import Client
from django.utils import timezone
from django.utils.formats import date_format
from rest_framework.test import APIClient

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.findings.models import Finding, FindingDecision, RiskAssessment
from ciclosec.intelligence.manual_sync_service import ManualSyncConfirmationRequired
from ciclosec.intelligence.models import (
    AdvisoryRecord,
    IntelligenceSource,
    ManualSyncRequest,
    Vulnerability,
    VulnerabilityAlias,
)
from ciclosec.inventory.sbom import ingest_sbom
from ciclosec.scans.models import ScanRun

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("configuration_state")]


def test_dashboard_redirects_anonymous_users_to_login(client: Client) -> None:
    response = client.get("/")

    assert response.status_code == 302
    assert response.url == "/accounts/login/?next=/"
    login = client.get("/accounts/login/")
    assert login.status_code == 200
    assert b"dashboard.css" in login.content
    assert b"CicloSec" in login.content


@pytest.mark.parametrize(
    ("current", "old"),
    [
        ("/assets/", "/activos/"),
        ("/assets/new/", "/activos/nuevo/"),
        ("/findings/", "/hallazgos/"),
        ("/history/", "/historial/"),
        ("/intelligence/", "/inteligencia/"),
        ("/integrations/", "/integraciones/"),
    ],
)
def test_web_routes_use_english_without_spanish_aliases(
    client: Client, current: str, old: str
) -> None:
    client.force_login(get_user_model().objects.create_user(username="routes-user"))
    assert client.get(current).status_code == 200
    assert client.get(old).status_code == 404


def test_login_form_includes_csrf_token(client: Client) -> None:
    response = client.get("/accounts/login/")

    assert response.status_code == 200
    assert b'name="csrfmiddlewaretoken"' in response.content


def test_intelligence_update_requires_staff_confirmation_and_csrf(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = get_user_model().objects.create_user(username="intelligence-viewer")
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    response = client.get("/intelligence/")
    assert b"Actualizar todos" not in response.content
    token = response.cookies["csrftoken"].value
    assert (
        client.post(
            "/intelligence/update/", {"csrfmiddlewaretoken": token, "confirm": "true"}
        ).status_code
        == 403
    )

    user.is_staff = True
    user.save(update_fields=["is_staff"])
    response = client.get("/intelligence/")
    assert b"Actualizar todos" in response.content
    calls = []

    def submit(*, actor: object, confirm: bool) -> dict[str, object]:
        if not confirm:
            raise ManualSyncConfirmationRequired("confirmation required")
        calls.append(actor)
        return {
            "providers": [
                {"provider": "nvd", "status": "queued", "duplicate": False, "error": None},
                {"provider": "osv", "status": "uncertain", "duplicate": False, "error": None},
            ]
        }

    monkeypatch.setattr("ciclosec.web.pages.request_manual_sync", submit)
    assert client.post("/intelligence/update/", {"confirm": "true"}).status_code == 403
    response = client.post("/intelligence/update/", {"csrfmiddlewaretoken": token}, follow=True)
    assert "Confirma que deseas" in response.content.decode()
    assert calls == []
    response = client.post(
        "/intelligence/update/",
        {"csrfmiddlewaretoken": token, "confirm": "true"},
        follow=True,
    )
    assert calls == [user]
    assert "no se pudo confirmar" in response.content.decode()
    assert "Solicitudes enviadas" not in response.content.decode()


def test_intelligence_dashboard_exposes_uncertain_followup(client: Client) -> None:
    user = get_user_model().objects.create_user(username="intelligence-admin", is_staff=True)
    client.force_login(user)
    ManualSyncRequest.objects.create(
        provider=AdvisoryRecord.Provider.OSV,
        task_id=uuid4(),
        status=ManualSyncRequest.Status.PARTIAL,
        delivery_error="followup_delivery_uncertain",
    )

    response = client.get("/intelligence/")

    assert "envío posterior sin confirmar" in response.content.decode()


def test_intelligence_dashboard_does_not_hide_unexpected_errors(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = get_user_model().objects.create_user(username="intelligence-admin", is_staff=True)
    client.force_login(user)

    def fail(**kwargs: object) -> None:
        raise ValueError("unexpected publisher failure")

    monkeypatch.setattr("ciclosec.web.pages.request_manual_sync", fail)
    with pytest.raises(ValueError, match="unexpected publisher failure"):
        client.post("/intelligence/update/", {"confirm": "true"})


def test_authenticated_dashboard_shows_coverage_and_stale_source_status(client: Client) -> None:
    user = get_user_model().objects.create_user(username="dashboard-user", password="secret")
    client.force_login(user)
    last_success = timezone.now() - timedelta(days=3)
    IntelligenceSource.objects.create(
        provider=AdvisoryRecord.Provider.NVD,
        status=IntelligenceSource.Status.CURRENT,
        last_attempt_at=last_success,
        last_success_at=last_success,
    )

    response = client.get("/")

    assert response.status_code == 200
    assert b"Cobertura de escaneos" in response.content
    assert b"Solo incluye activos registrados y habilitados" in response.content
    assert b"Sin escanear" in response.content
    assert b"Frescura de fuentes" in response.content
    assert b"Desactualizada" in response.content
    assert b'href="/findings/">Ver hallazgos' in response.content
    assert 'aria-label="Cerrar sesión"'.encode() in response.content
    assert b"Saltar al contenido principal" in response.content
    assert b'id="main-content"' in response.content
    assert "no-store" in response["Cache-Control"]


def test_dashboard_severity_chart_uses_filtered_vulnerability_counts(client: Client) -> None:
    user = get_user_model().objects.create_user(username="severity-user", password="secret")
    client.force_login(user)
    asset = Asset.objects.create(name="severity-backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.SUCCEEDED,
        finished_at=timezone.now(),
        metadata={
            "repository_source": {
                "provider": "github",
                "owner": "example",
                "repository": "repo",
                "ref": "main",
            }
        },
    )
    for index, severity in enumerate(("critical", "high", "high", "medium", "low")):
        Finding.objects.create(
            scan_run=scan,
            asset=asset,
            source=Finding.Source.TRIVY,
            kind=Finding.Kind.VULNERABILITY,
            fingerprint=f"{index:064x}",
            external_id=f"CVE-2026-{index:04}",
            severity=severity,
        )
    Finding.objects.create(
        scan_run=scan,
        asset=asset,
        source=Finding.Source.TRIVY,
        kind=Finding.Kind.SECRET,
        fingerprint="f" * 64,
        severity="critical",
    )

    response = client.get("/", {"asset_id": str(asset.pk)})

    assert response.status_code == 200
    counts = {row["key"]: row["count"] for row in response.context["severity_rows"]}
    assert counts == {
        "critical": 1,
        "high": 2,
        "medium": 1,
        "low": 1,
        "unknown": 0,
    }
    assert response.context["coverage_percent"] == 100


def test_dashboard_and_api_show_unverified_and_changed_sources(client: Client) -> None:
    user = get_user_model().objects.create_user(username="coverage-source-user")
    client.force_login(user)
    changed = Asset.objects.create(name="changed", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=changed, owner="new", repository_name="repo")
    ScanRun.objects.create(
        asset=changed,
        scanner_name="test",
        status=ScanRun.Status.SUCCEEDED,
        finished_at=timezone.now(),
        metadata={
            "repository_source": {
                "provider": "github",
                "owner": "old",
                "repository": "repo",
                "ref": "main",
            }
        },
    )
    unknown = Asset.objects.create(name="unknown", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=unknown, owner="example", repository_name="legacy")
    ScanRun.objects.create(
        asset=unknown,
        scanner_name="test",
        status=ScanRun.Status.SUCCEEDED,
        finished_at=timezone.now(),
    )

    page = client.get("/")
    api = client.get("/api/dashboard/")

    assert page.status_code == 200
    assert "Fuente modificada o ausente" in page.content.decode()
    assert "Identidad desconocida" in page.content.decode()
    assert page.context["coverage_percent"] == 0
    assert api.status_code == 200
    assert api.json()["coverage"]["counts"]["source_changed"] == 1
    assert api.json()["coverage"]["counts"]["source_unknown"] == 1


def test_dashboard_filters_activity_and_rejects_invalid_values(client: Client) -> None:
    user = get_user_model().objects.create_user(username="filter-user", password="secret")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    Finding.objects.create(
        scan_run=scan,
        asset=asset,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="a" * 64,
        external_id="CVE-2026-0042",
        affected_status=Finding.AffectedStatus.CONFIRMED,
    )

    response = client.get(
        "/",
        {"asset_id": str(asset.pk), "affected_status": Finding.AffectedStatus.CONFIRMED},
    )
    invalid_response = client.get("/", {"asset_id": "not-an-integer"})

    assert response.status_code == 200
    assert b"CVE-2026-0042" in response.content
    assert invalid_response.status_code == 400
    assert b"Filtros no v" in invalid_response.content


def test_dashboard_paginates_all_lists_and_preserves_filters(client: Client) -> None:
    user = get_user_model().objects.create_user(username="pagination-user")
    client.force_login(user)
    assets = [
        Asset.objects.create(name=f"asset-{index:02}", kind=Asset.Kind.REPOSITORY)
        for index in range(21)
    ]
    for index in range(11):
        scan = ScanRun.objects.create(
            asset=assets[0],
            scanner_name="test",
            created_at=timezone.now() + timedelta(seconds=index),
        )
        Finding.objects.create(
            scan_run=scan,
            asset=assets[0],
            source=Finding.Source.OSV_SCANNER,
            kind=Finding.Kind.VULNERABILITY,
            fingerprint=f"{index:064x}",
            external_id=f"CVE-2026-{index:04}",
            affected_status=Finding.AffectedStatus.CONFIRMED,
        )

    response = client.get(
        "/",
        {
            "asset_id": str(assets[0].pk),
            "affected_status": Finding.AffectedStatus.CONFIRMED,
            "assets_page": "2",
            "scans_page": "2",
            "findings_page": "2",
        },
    )

    assert response.status_code == 200
    assert response.context["summary"]["assets"]["offset"] == 20
    assert response.context["summary"]["assets"]["items"][0]["name"] == "asset-20"
    assert response.context["summary"]["scans"]["offset"] == 10
    assert len(response.context["summary"]["scans"]["items"]) == 1
    assert response.context["summary"]["findings"]["offset"] == 10
    assert len(response.context["summary"]["findings"]["items"]) == 1
    assert response.context["asset_pagination"]["previous_url"].startswith("?")
    assert f"asset_id={assets[0].pk}" in response.context["finding_pagination"]["previous_url"]
    assert "affected_status=confirmed" in response.context["scan_pagination"]["previous_url"]
    assert "findings_page=2" in response.context["asset_pagination"]["previous_url"]


def test_dashboard_hides_manual_scan_form_when_configuration_disables_it(
    client: Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution,
        "allow_on_demand",
        False,
    )
    user = get_user_model().objects.create_user(username="manual-disabled-user")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")

    response = client.get("/")

    assert response.status_code == 200
    assert b"Deshabilitado por configuraci\xc3\xb3n" in response.content
    assert b"Solicitar escaneo" not in response.content


def test_dashboard_exposes_csrf_protected_manual_scan_form_when_enabled(
    client: Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    user = get_user_model().objects.create_user(username="manual-enabled-user")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution,
        "allow_on_demand",
        True,
    )
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution,
        "allow_repository_scanners_with_network",
        True,
    )

    response = client.get("/")

    assert response.status_code == 200
    assert f'action="/assets/{asset.pk}/scan/"'.encode() in response.content
    assert b'name="asset" value="' + str(asset.pk).encode() + b'"' in response.content
    assert b'name="csrfmiddlewaretoken"' in response.content
    assert b"Solicitar escaneo" in response.content


def test_dashboard_live_refresh_returns_only_the_server_rendered_panels(
    client: Client,
) -> None:
    user = get_user_model().objects.create_user(username="live-dashboard-user")
    client.force_login(user)

    response = client.get("/", HTTP_X_CICLOSEC_LIVE="dashboard")

    assert response.status_code == 200
    assert b'id="dashboard-live-content"' in response.content
    assert b'id="coverage-title"' in response.content
    assert b"<html" not in response.content


def test_dashboard_shows_actionable_historical_risks_and_recent_local_cves(client: Client) -> None:
    user = get_user_model().objects.create_user(username="insights-user")
    client.force_login(user)
    asset = Asset.objects.create(name="insight-asset", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    root = Vulnerability.objects.create(canonical_id="GHSA-example")
    member = Vulnerability.objects.create(
        canonical_id="CVE-member", merged_into=root, published_at=timezone.now()
    )
    VulnerabilityAlias.objects.create(
        vulnerability=member, namespace=VulnerabilityAlias.Namespace.CVE, identifier="CVE-2026-1111"
    )
    AdvisoryRecord.objects.create(
        vulnerability=root, provider=AdvisoryRecord.Provider.NVD, external_id="CVE-2026-1111"
    )
    IntelligenceSource.objects.create(
        provider=AdvisoryRecord.Provider.NVD,
        last_success_at=timezone.now() - timedelta(days=365),
    )
    other = Vulnerability.objects.create(canonical_id="other", published_at=timezone.now())
    VulnerabilityAlias.objects.create(
        vulnerability=other, namespace=VulnerabilityAlias.Namespace.CVE, identifier="CVE-2026-2222"
    )
    finding = Finding.objects.create(
        scan_run=scan,
        asset=asset,
        vulnerability=root,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="b" * 64,
        external_id="CVE-2026-1111",
    )
    RiskAssessment.objects.create(
        finding=finding, score=90, level=RiskAssessment.Level.CRITICAL, policy_version="test"
    )
    resolved = Finding.objects.create(
        scan_run=scan,
        asset=asset,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="c" * 64,
        external_id="resolved-priority",
    )
    RiskAssessment.objects.create(
        finding=resolved, score=80, level=RiskAssessment.Level.CRITICAL, policy_version="test"
    )
    FindingDecision.objects.create(
        finding=resolved, status=FindingDecision.Status.CLOSED, decided_by=user, reason="reviewed"
    )

    response = client.get("/", HTTP_X_CICLOSEC_LIVE="dashboard")

    assert response.status_code == 200
    content = response.content.decode()
    assert "Tareas urgentes" in content
    assert f'href="/findings/{finding.pk}/"' in content
    assert [row.pk for row in response.context["urgent_findings"]] == [finding.pk]
    assert "CVE-2026-1111" in content and "CVE-2026-2222" in content
    assert [row["identifier"] for row in response.context["recent_related_cves"]] == [
        "CVE-2026-1111"
    ]
    assert response.context["recent_related_cves"][0]["source_status"] == "Desactualizada"
    assert response.context["recent_related_cves"][0]["finding_id"] == finding.pk
    assert {row["identifier"] for row in response.context["recent_local_cves"]} == {
        "CVE-2026-1111",
        "CVE-2026-2222",
    }


def test_dashboard_urgent_findings_respect_decisions_and_asset_filter(client: Client) -> None:
    user = get_user_model().objects.create_user(username="urgent-user")
    client.force_login(user)
    asset = Asset.objects.create(name="first", kind=Asset.Kind.REPOSITORY)
    other = Asset.objects.create(name="second", kind=Asset.Kind.REPOSITORY)
    included = []
    for index, (owner, decision, level) in enumerate(
        [
            (asset, None, RiskAssessment.Level.HIGH),
            (asset, FindingDecision.Status.ASSIGNED, RiskAssessment.Level.CRITICAL),
            (asset, FindingDecision.Status.ACCEPTED_RISK, RiskAssessment.Level.HIGH),
            (asset, FindingDecision.Status.FALSE_POSITIVE, RiskAssessment.Level.CRITICAL),
            (asset, None, RiskAssessment.Level.LOW),
            (other, None, RiskAssessment.Level.HIGH),
        ]
    ):
        scan = ScanRun.objects.create(asset=owner, scanner_name="test")
        finding = Finding.objects.create(
            asset=owner,
            scan_run=scan,
            source=Finding.Source.OSV_SCANNER,
            kind=Finding.Kind.VULNERABILITY,
            fingerprint=f"{index:064x}",
        )
        RiskAssessment.objects.create(
            finding=finding,
            level=level,
            score=80 if level != RiskAssessment.Level.LOW else 10,
            policy_version="test",
        )
        if decision:
            FindingDecision.objects.create(
                finding=finding, status=decision, decided_by=user, reason="reviewed"
            )
        if index < 2:
            included.append(finding.pk)

    response = client.get("/", {"asset_id": asset.pk}, HTTP_X_CICLOSEC_LIVE="dashboard")

    assert response.status_code == 200
    assert {finding.pk for finding in response.context["urgent_findings"]} == set(included)


def test_dashboard_recent_cves_are_bounded_and_exclude_missing_dates(client: Client) -> None:
    client.force_login(get_user_model().objects.create_user(username="cve-list-user"))
    for index in range(7):
        vulnerability = Vulnerability.objects.create(
            canonical_id=f"CVE-2026-{index:04}",
            published_at=timezone.now() - timedelta(days=index),
        )
        VulnerabilityAlias.objects.create(
            vulnerability=vulnerability,
            namespace=VulnerabilityAlias.Namespace.CVE,
            identifier=vulnerability.canonical_id,
        )
    undated = Vulnerability.objects.create(canonical_id="CVE-undated")
    VulnerabilityAlias.objects.create(
        vulnerability=undated, namespace=VulnerabilityAlias.Namespace.CVE, identifier="CVE-undated"
    )

    response = client.get("/", HTTP_X_CICLOSEC_LIVE="dashboard")

    assert [row["identifier"] for row in response.context["recent_local_cves"]] == [
        f"CVE-2026-{index:04}" for index in range(5)
    ]
    assert response.context["recent_related_cves"] == []


def test_dashboard_live_scan_request_returns_json_and_refreshes_scan_status(
    client: Client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ciclosec.scans.api import views as scan_views

    user = get_user_model().objects.create_user(username="live-scan-user")
    client.force_login(user)
    asset = Asset.objects.create(name="live-backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="live-backend")
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)
    monkeypatch.setattr(scan_views.transaction, "on_commit", lambda callback: callback())
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True)
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution,
        "allow_repository_scanners_with_network",
        True,
    )

    response = client.post(
        f"/assets/{asset.pk}/scan/",
        {"asset": str(asset.pk)},
        HTTP_X_CICLOSEC_LIVE="dashboard",
    )

    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    assert response.json()["detail"] == f"Escaneo #{scan_id} solicitado."
    assert queued == [scan_id]

    refreshed = client.get("/", HTTP_X_CICLOSEC_LIVE="dashboard")

    assert refreshed.status_code == 200
    assert b"live-backend" in refreshed.content
    assert b"status--queued" in refreshed.content


def test_repository_scan_actions_explain_missing_network_authorization(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ciclosec.scans.api import views as scan_views

    user = get_user_model().objects.create_user(username="network-disabled-user", is_staff=True)
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")
    image = Asset.objects.create(name="local-image", kind=Asset.Kind.CONTAINER_IMAGE)
    execution = settings.CICLOSEC_CONFIG.scanning.execution
    monkeypatch.setattr(execution, "allow_on_demand", True)
    monkeypatch.setattr(execution, "allow_repository_scanners_with_network", False)
    monkeypatch.setattr(
        scan_views.scan_repository_task, "delay", lambda *_args: pytest.fail("unexpected dispatch")
    )

    dashboard = client.get("/")
    detail = client.get(f"/assets/{asset.pk}/")
    response = client.post(f"/assets/{asset.pk}/scan/", {"asset": str(asset.pk)}, follow=True)
    schedule_response = client.post(
        f"/assets/{asset.pk}/schedule/",
        {
            "enabled": "true",
            "confirm": "true",
            "source_fingerprint": detail.context["scan_schedule"]["source_fingerprint"],
        },
        follow=True,
    )

    for page in (dashboard, detail, response, schedule_response):
        assert page.status_code == 200
        assert "Autorización de red" in page.content.decode()
    assert "osv.dev nombres, versiones, ecosistemas y huellas" in dashboard.content.decode()
    assert f'action="/assets/{asset.pk}/scan/"' not in dashboard.content.decode()
    assert f'action="/assets/{asset.pk}/scan/"' not in detail.content.decode()
    assert f'action="/assets/{image.pk}/scan/"' in dashboard.content.decode()
    assert not ScanRun.objects.filter(asset=asset).exists()


def test_repository_scan_discloses_possible_network_data_before_actions(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = get_user_model().objects.create_user(username="network-aware", is_staff=True)
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")
    image = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    execution = settings.CICLOSEC_CONFIG.scanning.execution
    monkeypatch.setattr(execution, "allow_on_demand", True)
    monkeypatch.setattr(execution, "allow_repository_scanners_with_network", True)

    dashboard = client.get("/")
    detail = client.get(f"/assets/{asset.pk}/")
    image_detail = client.get(f"/assets/{image.pk}/")

    for page in (dashboard, detail):
        content = page.content.decode()
        assert page.status_code == 200
        assert "osv.dev nombres, versiones, ecosistemas y huellas" in content
        assert "deps.dev" in content
        assert "no envía código fuente" in content
        assert "registros OCI" in content
        assert "Maven Central" in content
        assert "check.trivy.dev" in content
        assert "token configurado" in content
        assert "no reenvía ese token" in content
        assert "Trivy" in content
        assert "no garantiza aislamiento de red" in content
    assert f'action="/assets/{asset.pk}/scan/"' in detail.content.decode()
    assert f'action="/assets/{asset.pk}/schedule/"' in detail.content.decode()
    assert "osv.dev nombres, versiones, ecosistemas y huellas" not in image_detail.content.decode()
    assert not ScanRun.objects.exists()


def test_repository_scan_discloses_local_database_mode_limits(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = get_user_model().objects.create_user(username="local-database-viewer", is_staff=True)
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")
    execution = settings.CICLOSEC_CONFIG.scanning.execution
    monkeypatch.setattr(execution, "repository_scanner_use_local_databases", True)

    dashboard = client.get("/")
    detail = client.get(f"/assets/{asset.pk}/")

    for page in (dashboard, detail):
        content = page.content.decode()
        assert page.status_code == 200
        assert "Modo de bases locales" in content
        assert "no verifica su antigüedad" in content
        assert "checkout del repositorio" in content
        assert "siguen usando GitHub" in content
        assert "no es un modo aislado" in content


def test_dashboard_api_requires_authentication() -> None:
    response = APIClient().get("/api/dashboard/")

    assert response.status_code in {401, 403}


def test_dashboard_api_is_filtered_and_omits_raw_errors() -> None:
    user = get_user_model().objects.create_user(username="api-dashboard-user")
    client = APIClient()
    client.force_authenticate(user=user)
    asset = Asset.objects.create(name="private-backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset,
        owner="example",
        repository_name="private-backend",
        credential_env="LOCAL_GITHUB_TOKEN",
    )
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.FAILED,
        error_summary="do-not-return-private-error",
        warnings=["private/path"],
        metadata={"credential": "do-not-return-secret"},
    )
    Finding.objects.create(
        scan_run=scan,
        asset=asset,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="b" * 64,
        external_id="CVE-2026-0043",
        affected_status=Finding.AffectedStatus.CONFIRMED,
    )
    IntelligenceSource.objects.create(
        provider=AdvisoryRecord.Provider.NVD,
        status=IntelligenceSource.Status.UNAVAILABLE,
        last_error="do-not-return-provider-error",
    )

    response = client.get(
        "/api/dashboard/",
        {
            "asset_id": str(asset.pk),
            "affected_status": Finding.AffectedStatus.CONFIRMED,
        },
    )
    response_body = repr(response.data)

    assert response.status_code == 200
    assert response.data["coverage"]["total_registered"] == 1
    assert response.data["findings"]["total"] == 1
    assert response.data["scans"]["items"][0]["has_error"] is True
    assert response.data["sources"][0]["status"] == IntelligenceSource.Status.UNAVAILABLE
    assert "credential_env" not in response_body
    assert "LOCAL_GITHUB_TOKEN" not in response_body
    assert "do-not-return-private-error" not in response_body
    assert "do-not-return-provider-error" not in response_body
    assert "do-not-return-secret" not in response_body
    assert "private/path" not in response_body
    assert "no-store" in response["Cache-Control"]


def test_dashboard_api_rejects_invalid_filters() -> None:
    user = get_user_model().objects.create_user(username="api-filter-user")
    client = APIClient()
    client.force_authenticate(user=user)

    invalid_asset_response = client.get("/api/dashboard/?asset_id=0")
    invalid_status_response = client.get("/api/dashboard/?affected_status=unknown")

    assert invalid_asset_response.status_code == 400
    assert invalid_status_response.status_code == 400


def test_dashboard_api_returns_requested_bounded_pages() -> None:
    user = get_user_model().objects.create_user(username="api-pagination-user")
    client = APIClient()
    client.force_authenticate(user=user)
    for index in range(21):
        Asset.objects.create(name=f"api-asset-{index:02}", kind=Asset.Kind.REPOSITORY)

    response = client.get("/api/dashboard/?assets_page=2")

    assert response.status_code == 200
    assert response.data["assets"]["total"] == 21
    assert response.data["assets"]["offset"] == 20
    assert len(response.data["assets"]["items"]) == 1
    assert response.data["assets"]["items"][0]["name"] == "api-asset-20"


@pytest.mark.parametrize(
    "path",
    [
        "/assets/",
        "/assets/new/",
        "/findings/",
        "/sbom/",
        "/history/",
        "/intelligence/",
        "/integrations/",
    ],
)
def test_workspace_pages_require_authentication_and_render(client: Client, path: str) -> None:
    assert client.get(path).status_code == 302
    user = get_user_model().objects.create_user(username="workspace-user")
    client.force_login(user)
    response = client.get(path)
    assert response.status_code == 200
    assert b'aria-current="page"' in response.content
    assert "no-store" in response["Cache-Control"]


def test_workspace_registers_and_edits_repository_without_exposing_credentials(
    client: Client,
) -> None:
    user = get_user_model().objects.create_user(username="asset-editor")
    client.force_login(user)
    data = {
        "name": "backend",
        "environment": "local",
        "exposure": "internal",
        "enabled": "on",
        "owner": "example",
        "repository_name": "backend",
        "ref": "main",
        "credential_env": "LOCAL_TOKEN",
    }

    response = client.post("/assets/new/?kind=repository", data)
    asset = Asset.objects.get(name="backend")
    repository = Repository.objects.get(asset=asset)
    assert response.url == f"/assets/{asset.pk}/"
    assert repository.credential_env == "LOCAL_TOKEN"
    assert b"LOCAL_TOKEN" not in client.get(response.url).content

    data["name"] = "backend actualizado"
    data["ref"] = "release"
    response = client.post(f"/assets/{asset.pk}/edit/", data)
    assert response.status_code == 302
    asset.refresh_from_db()
    repository.refresh_from_db()
    assert asset.name == "backend actualizado"
    assert repository.ref == "release"

    duplicate = client.post("/assets/new/?kind=repository", data)
    assert duplicate.status_code == 200
    assert "ya está registrada" in duplicate.content.decode()
    assert Asset.objects.count() == 1


def test_history_and_scan_detail_distinguish_request_and_start_times(client: Client) -> None:
    user = get_user_model().objects.create_user(username="scan-time-viewer")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    started = timezone.now() - timedelta(days=1)
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="test", status=ScanRun.Status.RUNNING, started_at=started
    )
    queued = ScanRun.objects.create(asset=asset, scanner_name="test")
    request_time = date_format(timezone.localtime(scan.created_at), "DATETIME_FORMAT")
    start_time = date_format(timezone.localtime(started), "DATETIME_FORMAT")

    history = client.get("/history/").content.decode()
    detail = client.get(f"/history/{scan.pk}/").content.decode()
    queued_detail = client.get(f"/history/{queued.pk}/").content.decode()

    assert "<th>Solicitado</th><th>Inicio</th>" in history
    assert f"<td>{request_time}</td><td>{start_time}</td>" in history
    queued_request_time = date_format(timezone.localtime(queued.created_at), "DATETIME_FORMAT")
    assert f"<td>{queued_request_time}</td><td>—</td>" in history
    assert f"<dt>Inicio</dt><dd>{start_time}</dd>" in detail
    assert "El estado en curso no confirma que el worker siga activo" in detail
    assert "<dt>Inicio</dt><dd>—</dd>" in queued_detail
    assert "El estado en curso no confirma que el worker siga activo" not in queued_detail


def test_scan_detail_displays_original_repository_source(client: Client) -> None:
    user = get_user_model().objects.create_user(username="history-source-viewer")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="repository-security",
        status=ScanRun.Status.PARTIAL,
        metadata={
            "repository_source": {
                "provider": "github",
                "owner": "original",
                "repository": "repo",
                "ref": "release/1",
            },
            "repository_source_changed": True,
            "private": "never-display-this",
        },
    )

    response = client.get(f"/history/{scan.pk}/")

    assert response.status_code == 200
    assert b"original/repo@release/1" in response.content
    assert "La fuente cambió durante el escaneo" in response.content.decode()
    assert b"never-display-this" not in response.content


@pytest.mark.parametrize(
    ("code", "message"),
    [
        ("asset_disabled", "El activo estaba deshabilitado"),
        ("credential_missing", "Falta la credencial de GitHub"),
        (
            "repository_scanner_network_not_authorized",
            "Los escáneres de repositorio que pueden usar la red no están autorizados",
        ),
        (
            "scanner_database_freshness_unverified",
            "CicloSec no pudo verificar su actualidad",
        ),
        ("repository_checkout_failed", "No se pudo acceder al repositorio"),
        ("dependabot_unavailable", "No se pudieron consultar las alertas de Dependabot"),
        ("image_not_allowlisted", "La imagen no está en la lista permitida"),
        ("image_source_changed", "La fuente de imagen cambió durante el escaneo"),
    ],
)
def test_scan_detail_shows_safe_diagnostic_messages(
    client: Client, code: str, message: str
) -> None:
    user = get_user_model().objects.create_user(username="diagnostic-user")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.PARTIAL,
        error_summary="secret-error-value",
        warnings=["secret-warning-value"],
        metadata={"diagnostic_codes": [code, "secret-code-value"]},
    )

    response = client.get(f"/history/{scan.pk}/")
    content = response.content.decode()

    assert response.status_code == 200
    assert message in content
    assert "secret-error-value" not in content
    assert "secret-warning-value" not in content
    assert "secret-code-value" not in content
    assert "No se dispone de una explicación detallada" in content


def test_scan_detail_distinguishes_empty_source_from_unavailable_source(client: Client) -> None:
    user = get_user_model().objects.create_user(username="source-results-viewer")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.PARTIAL,
        metadata={
            "source_results": {
                "osv_scanner": {"status": "available", "finding_count": 0},
                "trivy": {"status": "unavailable", "finding_count": None},
            },
            "scanner_database_freshness": "unverified",
            "diagnostic_codes": ["trivy_unavailable", "scanner_database_freshness_unverified"],
        },
    )

    content = client.get(f"/history/{scan.pk}/").content.decode()

    assert "OSV-Scanner" in content
    assert "0 hallazgos" in content
    assert "Trivy" in content
    assert "no disponible" in content
    assert "base local, fecha sin verificar" in content
    assert "CicloSec no pudo verificar su actualidad" in content


def test_scan_detail_explains_absent_historical_diagnostics(client: Client) -> None:
    user = get_user_model().objects.create_user(username="legacy-scan-viewer")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.FAILED,
        error_summary="private-error-value",
    )

    response = client.get(f"/history/{scan.pk}/")

    assert "No se dispone de una explicación detallada" in response.content.decode()
    assert b"private-error-value" not in response.content


@pytest.mark.parametrize("version", ["trivy: 1.2.3", ""])
def test_scan_detail_shows_recorded_or_unavailable_version(client: Client, version: str) -> None:
    user = get_user_model().objects.create_user(username="version-viewer")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", scanner_version=version)

    content = client.get(f"/history/{scan.pk}/").content.decode()

    assert (version or "No disponible") in content


@pytest.mark.parametrize("codes", ["private-code", [None, {"private": "secret-value"}], []])
def test_scan_detail_handles_malformed_diagnostics(client: Client, codes: object) -> None:
    user = get_user_model().objects.create_user(username="malformed-diagnostics")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.FAILED,
        metadata={"diagnostic_codes": codes},
    )

    response = client.get(f"/history/{scan.pk}/")

    assert response.status_code == 200
    assert "No se dispone de una explicación detallada" in response.content.decode()
    assert b"private-code" not in response.content
    assert b"secret-value" not in response.content


def test_workspace_creates_image_and_rejects_bad_repository_source(client: Client) -> None:
    user = get_user_model().objects.create_user(username="source-editor")
    client.force_login(user)
    image = client.post(
        "/assets/new/?kind=container_image",
        {
            "name": "image",
            "environment": "local",
            "exposure": "internal",
            "enabled": "on",
            "image_reference": "example:local",
        },
    )
    assert image.status_code == 302
    assert ContainerImage.objects.get().image_reference == "example:local"
    image_detail = client.get(image.url)
    assert b"example:local" in image_detail.content
    assert b"No configurada" not in image_detail.content
    source = ContainerImage.objects.get()
    source.resolved_digest = f"sha256:{'a' * 64}"
    source.digest_resolved_at = timezone.now()
    source.save(update_fields=["resolved_digest", "digest_resolved_at"])
    unchanged = client.post(
        f"/assets/{source.asset_id}/edit/",
        {
            "name": "image",
            "environment": "local",
            "exposure": "internal",
            "enabled": "on",
            "image_reference": "example:local",
        },
    )
    source.refresh_from_db()
    assert unchanged.status_code == 302
    assert source.resolved_digest == f"sha256:{'a' * 64}"
    assert source.digest_resolved_at is not None
    edited = client.post(
        f"/assets/{source.asset_id}/edit/",
        {
            "name": "image",
            "environment": "local",
            "exposure": "internal",
            "enabled": "on",
            "image_reference": "example:other",
        },
    )
    source.refresh_from_db()
    assert edited.status_code == 302
    assert source.image_reference == "example:other"
    assert source.resolved_digest == ""
    assert source.digest_resolved_at is None
    invalid_image = client.post(
        "/assets/new/?kind=container_image",
        {
            "name": "invalid-image",
            "environment": "local",
            "exposure": "internal",
            "image_reference": "--invalid",
        },
    )
    assert invalid_image.status_code == 200
    assert not Asset.objects.filter(name="invalid-image").exists()
    invalid = client.post(
        "/assets/new/?kind=repository",
        {
            "name": "invalid",
            "environment": "local",
            "exposure": "internal",
            "enabled": "on",
            "owner": "../invalid",
            "repository_name": "repo",
            "ref": "main",
            "credential_env": "not-a-variable",
        },
    )
    assert invalid.status_code == 200
    assert not Asset.objects.filter(name="invalid").exists()
    assert "referencia" in invalid.content.decode()


def test_workspace_scan_action_reuses_opt_in_and_redirects(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ciclosec.scans.api import views as scan_views

    user = get_user_model().objects.create_user(username="web-scan")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)
    monkeypatch.setattr(scan_views.transaction, "on_commit", lambda callback: callback())
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution, "allow_repository_scanners_with_network", True
    )
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", False)
    disabled = client.post(f"/assets/{asset.pk}/scan/", {"asset": asset.pk}, follow=True)
    assert "deshabilitados" in disabled.content.decode()
    assert not ScanRun.objects.exists()

    monkeypatch.setattr(settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True)
    response = client.post(f"/assets/{asset.pk}/scan/", {"asset": asset.pk})
    scan = ScanRun.objects.get(asset=asset)
    assert response.url == f"/history/{scan.pk}/"
    assert queued == [scan.pk]
    assert client.post(f"/assets/{asset.pk}/scan/", {"asset": 999}).status_code == 400


def test_workspace_explains_existing_scan_and_rejects_duplicate(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    user = get_user_model().objects.create_user(username="active-scan")
    client.force_login(user)
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", status=ScanRun.Status.RUNNING)

    detail = client.get(f"/assets/{asset.pk}/")
    assert "Ya hay un escaneo activo" in detail.content.decode()
    assert f"/history/{scan.pk}/".encode() in detail.content
    response = client.post(f"/assets/{asset.pk}/scan/", {"asset": asset.pk}, follow=True)
    assert "Ya hay un escaneo activo" in response.content.decode()
    assert ScanRun.objects.filter(asset=asset).count() == 1


def test_workspace_explains_full_queue(client: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    from ciclosec.common.config import CicloSecConfig

    user = get_user_model().objects.create_user(username="queue-operator")
    client.force_login(user)
    config = CicloSecConfig.model_validate(
        {"scanning": {"execution": {"allow_on_demand": True, "max_queued_scans": 1}}}
    )
    config.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", config)
    existing = Asset.objects.create(name="busy", kind=Asset.Kind.REPOSITORY)
    ScanRun.objects.create(asset=existing, scanner_name="test")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")

    response = client.post(f"/assets/{asset.pk}/scan/", {"asset": asset.pk}, follow=True)

    assert "La cola de escaneos está llena" in response.content.decode()
    assert not ScanRun.objects.filter(asset=asset).exists()


def test_scan_queue_status_is_global_and_redacts_internal_metadata(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ciclosec.common.config import CicloSecConfig

    user = get_user_model().objects.create_user(username="queue-observer")
    client.force_login(user)
    config = CicloSecConfig.model_validate(
        {"scanning": {"execution": {"max_queued_scans": 1, "max_concurrent_scans": 1}}}
    )
    monkeypatch.setattr(settings, "CICLOSEC_CONFIG", config)
    first = Asset.objects.create(name="first", kind=Asset.Kind.REPOSITORY)
    second = Asset.objects.create(name="second", kind=Asset.Kind.REPOSITORY)
    uncertain = ScanRun.objects.create(
        asset=first,
        scanner_name="test",
        metadata={"dispatch_uncertain": True, "private": "secret-sentinel"},
    )
    ScanRun.objects.create(
        asset=second,
        scanner_name="test",
        metadata={"dispatch_uncertain": "true", "private": "secret-sentinel"},
    )
    ScanRun.objects.create(
        asset=second,
        scanner_name="test",
        status=ScanRun.Status.RUNNING,
        metadata={"dispatch_uncertain": True},
    )
    ScanRun.objects.create(asset=second, scanner_name="test", status=ScanRun.Status.SUCCEEDED)

    response = client.get(f"/history/?asset_id={first.pk}")
    assert response.status_code == 200
    status = response.context["queue_status"]
    assert status == {
        "queued_count": 2,
        "queued_limit": 1,
        "running_count": 1,
        "running_limit": 1,
        "delivery_uncertain_count": 1,
        "queue_full": True,
    }
    content = response.content.decode()
    assert "Capacidad global de escaneos" in content
    assert "Envío sin confirmar" in content
    assert f"/history/{uncertain.pk}/" in content
    assert "secret-sentinel" not in content
    assert "No confirma el estado del broker ni del worker" in content
    assert "Tras una interrupción de Redis" in content
    unfiltered = client.get("/history/").content.decode()
    assert unfiltered.count("Envío sin confirmar") == 1

    api_client = APIClient()
    api_client.force_authenticate(user=user)
    api = api_client.get("/api/scans/queue-status/")
    assert api.status_code == 200
    assert api.data == status
    assert "no-store" in api["Cache-Control"]
    assert "secret-sentinel" not in str(api.data)


def test_scan_queue_status_handles_empty_and_freed_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ciclosec.common.config import CicloSecConfig

    user = get_user_model().objects.create_user(username="queue-viewer")
    client = APIClient()
    client.force_authenticate(user=user)
    monkeypatch.setattr(
        settings,
        "CICLOSEC_CONFIG",
        CicloSecConfig.model_validate({"scanning": {"execution": {"max_queued_scans": 1}}}),
    )
    endpoint = "/api/scans/queue-status/"
    empty = client.get(endpoint)
    assert empty.status_code == 200
    assert empty.data["queued_count"] == 0
    assert empty.data["queue_full"] is False
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    assert client.get(endpoint).data["queue_full"] is True
    assert (
        client.post(
            f"/api/scans/{scan.pk}/cancel-queued/", {"confirm": True}, format="json"
        ).status_code
        == 200
    )
    assert client.get(endpoint).data["queue_full"] is False
    client.force_authenticate(user=None)
    assert client.get(endpoint).status_code in (401, 403)


@pytest.mark.parametrize("key", ["dispatch_uncertain", "initial_dispatch_pending"])
@pytest.mark.parametrize("marker", [False, 1, "true", None, ["true"]])
def test_queue_uncertain_count_requires_json_boolean_true(key: str, marker: object) -> None:
    user = get_user_model().objects.create_user(username="queue-marker")
    client = APIClient()
    client.force_authenticate(user=user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    ScanRun.objects.create(asset=asset, scanner_name="test", metadata={key: marker})

    response = client.get("/api/scans/queue-status/")

    assert response.status_code == 200
    assert response.data["queued_count"] == 1
    assert response.data["delivery_uncertain_count"] == 0


@pytest.mark.django_db(transaction=True)
def test_unconfirmed_initial_dispatch_remains_visible_until_confirmed(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from django.db import transaction

    from ciclosec.scans.services import create_scan_for_locked_asset, dispatch_scan

    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution, "allow_repository_scanners_with_network", True
    )
    user = get_user_model().objects.create_user(username="pending-dispatch")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    with transaction.atomic():
        scan = create_scan_for_locked_asset(Asset.objects.select_for_update().get(pk=asset.pk))

    assert client.get("/history/").context["queue_status"]["delivery_uncertain_count"] == 1
    assert client.get(f"/history/{scan.pk}/").context["dispatch_uncertain"] is True
    assert dispatch_scan(scan.pk, lambda _scan_id: None)
    scan.refresh_from_db()
    assert "initial_dispatch_pending" not in scan.metadata
    assert client.get("/history/").context["queue_status"]["delivery_uncertain_count"] == 0


@pytest.mark.django_db(transaction=True)
def test_initial_confirmation_does_not_clear_a_later_uncertain_delivery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.db import transaction

    from ciclosec.scans.services import (
        create_scan_for_locked_asset,
        dispatch_scan,
        get_scan_queue_status,
        record_uncertain_dispatch,
    )

    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution, "allow_repository_scanners_with_network", True
    )
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    with transaction.atomic():
        scan = create_scan_for_locked_asset(Asset.objects.select_for_update().get(pk=asset.pk))
    assert dispatch_scan(scan.pk, record_uncertain_dispatch)
    scan.refresh_from_db()
    assert scan.metadata == {"dispatch_uncertain": True}
    assert get_scan_queue_status()["delivery_uncertain_count"] == 1


@pytest.mark.django_db(transaction=True)
def test_workspace_explains_uncertain_dispatch(
    client: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    from kombu.exceptions import OperationalError

    from ciclosec.scans.api import views as scan_views

    user = get_user_model().objects.create_user(username="uncertain-scan")
    client.force_login(user)
    monkeypatch.setattr(settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True)
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning.execution, "allow_repository_scanners_with_network", True
    )
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="backend")

    def fail_dispatch(_scan_id: int) -> None:
        raise OperationalError("private-broker-secret")

    monkeypatch.setattr(scan_views.scan_repository_task, "delay", fail_dispatch)
    response = client.post(f"/assets/{asset.pk}/scan/", {"asset": asset.pk}, follow=True)
    scan = ScanRun.objects.get(asset=asset)

    assert response.redirect_chain[-1][0] == f"/history/{scan.pk}/"
    assert "No se pudo confirmar el envío" in response.content.decode()
    assert "private-broker-secret" not in response.content.decode()
    assert scan.status == ScanRun.Status.QUEUED
    detail = client.get(f"/history/{scan.pk}/")
    assert "No se pudo confirmar el envío a la cola" in detail.content.decode()
    scan.status = ScanRun.Status.RUNNING
    scan.save(update_fields=["status"])
    detail = client.get(f"/history/{scan.pk}/")
    assert "No se pudo confirmar el envío a la cola" not in detail.content.decode()


def test_authenticated_user_cancels_only_queued_scan(client: Client) -> None:
    from ciclosec.scanners import tasks

    user = get_user_model().objects.create_user(username="cancel-operator")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    scan.metadata = {"dispatch_uncertain": True}
    scan.save(update_fields=["metadata"])

    detail = client.get(f"/history/{scan.pk}/")
    assert "Cancelar escaneo en cola" in detail.content.decode()
    unconfirmed = client.post(f"/history/{scan.pk}/cancel/", follow=True)
    assert "Confirma" in unconfirmed.content.decode()
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.QUEUED

    response = client.post(f"/history/{scan.pk}/cancel/", {"confirm": "true"}, follow=True)
    assert "Escaneo en cola cancelado" in response.content.decode()
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.CANCELLED
    assert scan.finished_at is not None
    assert scan.started_at is None
    assert scan.metadata["cancelled_by_user_id"] == user.pk
    assert scan.metadata["dispatch_uncertain"] is True
    assert tasks.scan_repository_task.run(scan.pk)["disposition"] == "already_claimed"
    assert "Cancelar escaneo en cola" not in client.get(f"/history/{scan.pk}/").content.decode()


@pytest.mark.parametrize(
    "scan_status",
    [
        ScanRun.Status.RUNNING,
        ScanRun.Status.SUCCEEDED,
        ScanRun.Status.FAILED,
        ScanRun.Status.CANCELLED,
    ],
)
def test_scan_cancellation_rejects_nonqueued_states(scan_status: str) -> None:
    user = get_user_model().objects.create_user(username="cancel-api")
    client = APIClient()
    client.force_authenticate(user=user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", status=scan_status)

    response = client.post(f"/api/scans/{scan.pk}/cancel-queued/", {"confirm": True}, format="json")

    assert response.status_code == 409
    scan.refresh_from_db()
    assert scan.status == scan_status
    assert scan.finished_at is None


def test_scan_cancellation_requires_authentication_and_confirmation() -> None:
    user = get_user_model().objects.create_user(username="cancel-api")
    client = APIClient()
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    assert client.post(
        f"/api/scans/{scan.pk}/cancel-queued/", {"confirm": True}, format="json"
    ).status_code in (401, 403)
    client.force_authenticate(user=user)
    assert client.post(f"/api/scans/{scan.pk}/cancel-queued/", {}, format="json").status_code == 400
    assert client.post(f"/api/scans/{scan.pk}/cancel-queued/", [], format="json").status_code == 400
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.QUEUED


def test_scan_cancellation_rejects_inconsistent_started_queue_state() -> None:
    user = get_user_model().objects.create_user(username="cancel-api")
    client = APIClient()
    client.force_authenticate(user=user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="test", status=ScanRun.Status.QUEUED, started_at=timezone.now()
    )
    response = client.post(f"/api/scans/{scan.pk}/cancel-queued/", {"confirm": True}, format="json")
    assert response.status_code == 409
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.QUEUED


def test_scan_cancellation_requires_csrf_for_session_authentication() -> None:
    user = get_user_model().objects.create_user(username="cancel-csrf")
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")

    response = client.post(f"/history/{scan.pk}/cancel/", {"confirm": "true"})

    assert response.status_code == 403
    api_client = APIClient(enforce_csrf_checks=True)
    api_client.force_login(user)
    assert (
        api_client.post(
            f"/api/scans/{scan.pk}/cancel-queued/", {"confirm": True}, format="json"
        ).status_code
        == 403
    )
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.QUEUED


def test_workspace_writes_require_csrf() -> None:
    user = get_user_model().objects.create_user(username="csrf-user")
    client = Client(enforce_csrf_checks=True)
    client.force_login(user)
    assert client.post("/assets/new/", {}).status_code == 403
    response = client.get("/assets/new/")
    token = response.cookies["csrftoken"].value
    saved = client.post(
        "/assets/new/",
        {
            "csrfmiddlewaretoken": token,
            "name": "csrf-repo",
            "environment": "local",
            "exposure": "internal",
            "enabled": "on",
            "owner": "example",
            "repository_name": "repo",
            "ref": "main",
            "credential_env": "",
        },
    )
    assert saved.status_code == 302
    assert Repository.objects.filter(asset__name="csrf-repo").exists()


def test_workspace_sbom_selects_scan_and_rejects_other_assets(client: Client) -> None:
    user = get_user_model().objects.create_user(username="sbom-user")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    other = Asset.objects.create(name="other", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", status=ScanRun.Status.SUCCEEDED)
    other_scan = ScanRun.objects.create(asset=other, scanner_name="test")
    fixture = Path(__file__).parents[1] / "fixtures" / "sbom" / "cyclonedx-1.7.json"
    ingest_sbom(scan, "cyclonedx", json.loads(fixture.read_text(encoding="utf-8")))

    response = client.get("/sbom/", {"asset": asset.pk, "scan_id": scan.pk})
    assert response.status_code == 200
    assert b"Flask" in response.content
    assert response.context["result"]["scan_run_id"] == scan.pk
    invalid = client.get("/sbom/", {"asset": asset.pk, "scan_id": other_scan.pk})
    assert invalid.status_code == 400
    assert "no pertenece" in invalid.content.decode()


@pytest.mark.parametrize(
    ("source", "expected_status", "notice"),
    [
        ("example", "matched", "La referencia coincide con la fuente registrada"),
        ("other", "changed", "El SBOM corresponde a una fuente diferente o ausente"),
        (None, "unknown", "No se puede verificar la fuente de este SBOM"),
    ],
)
def test_sbom_discloses_source_identity_for_ui_and_api(
    client: Client, source: str | None, expected_status: str, notice: str
) -> None:
    user = get_user_model().objects.create_user(username="sbom-source-user")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    metadata = (
        {
            "repository_source": {
                "provider": "github",
                "owner": source,
                "repository": "repo",
                "ref": "main",
            }
        }
        if source is not None
        else {}
    )
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="test", status=ScanRun.Status.SUCCEEDED, metadata=metadata
    )
    fixture = Path(__file__).parents[1] / "fixtures" / "sbom" / "cyclonedx-1.7.json"
    ingest_sbom(scan, "cyclonedx", json.loads(fixture.read_text(encoding="utf-8")))

    for query in ({"asset": asset.pk}, {"asset": asset.pk, "scan_id": scan.pk}):
        response = client.get("/sbom/", query)
        assert response.status_code == 200
        assert notice in response.content.decode()
        assert b"Flask" in response.content

    api = client.get(f"/api/assets/{asset.pk}/sbom/")
    assert api.status_code == 200
    assert api.json()["source_status"] == expected_status
    assert api.json()["scan_run_id"] == scan.pk


def test_workspace_finding_filter_detail_and_redaction(client: Client) -> None:
    user = get_user_model().objects.create_user(username="finding-user")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="test", warnings=["private/path"], error_summary="internal-secret"
    )
    finding = Finding.objects.create(
        scan_run=scan,
        asset=asset,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="a" * 64,
        external_id="CVE-2026-1234",
        package_name="example",
        evidence={"secret": "never-display-this"},
    )
    assert b"CVE-2026-1234" in client.get("/findings/", {"q": "example"}).content
    assert b"CVE-2026-1234" not in client.get("/findings/", {"q": "not-found"}).content
    assert b"CVE-2026-1234" in client.get("/findings/", {"scan_id": scan.pk}).content
    assert b"CVE-2026-1234" not in client.get("/findings/", {"scan_id": scan.pk + 1}).content
    assert client.get("/findings/", {"scan_id": "invalid"}).status_code == 400
    assert b"backend" in client.get("/history/", {"asset_id": asset.pk}).content
    assert client.get("/history/", {"asset_id": 0}).status_code == 400
    response = client.get(f"/findings/{finding.pk}/")
    assert response.status_code == 200
    assert b"never-display-this" not in response.content
    assert b"internal-secret" not in client.get(f"/history/{scan.pk}/").content


def test_findings_order_by_priority_before_pagination_and_keep_filters(client: Client) -> None:
    user = get_user_model().objects.create_user(username="priority-user")
    client.force_login(user)
    asset = Asset.objects.create(name="priority-asset", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    findings = []
    for index in range(27):
        finding = Finding.objects.create(
            asset=asset,
            scan_run=scan,
            source=Finding.Source.OSV_SCANNER,
            kind=Finding.Kind.VULNERABILITY,
            fingerprint=f"{index:064x}",
            external_id=f"priority-{index}",
        )
        findings.append(finding)
        if index != 26:
            RiskAssessment.objects.create(
                finding=finding,
                score=90 if index in (0, 1) else 10,
                level=RiskAssessment.Level.HIGH if index in (0, 1) else RiskAssessment.Level.LOW,
                policy_version="test",
            )

    response = client.get("/findings/", {"asset_id": asset.pk, "sort": "risk"})
    assert response.status_code == 200
    assert [row["finding"].pk for row in response.context["finding_rows"][:2]] == [
        findings[1].pk,
        findings[0].pk,
    ]
    assert "sort=risk" in response.context["pagination"]["next_url"]
    assert f"asset_id={asset.pk}" in response.context["pagination"]["next_url"]
    default = client.get("/findings/", {"asset_id": asset.pk})
    assert default.context["finding_rows"][0]["finding"].pk == findings[1].pk
    page_two = client.get("/findings/", {"asset_id": asset.pk, "sort": "risk", "page": 2})
    assert page_two.context["finding_rows"][-1]["finding"].pk == findings[26].pk
    assert "Desconocido" in page_two.content.decode()

    recent = client.get("/findings/", {"asset_id": asset.pk, "sort": "recent"})
    assert recent.context["finding_rows"][0]["finding"].pk == findings[26].pk
    assert client.get("/findings/", {"sort": "invalid"}).status_code == 400


@pytest.mark.parametrize(
    ("owner", "status", "label"),
    [
        ("example", "matched", "Fuente coincidente"),
        ("other", "changed", "Fuente modificada o ausente"),
        (None, "unknown", "Identidad desconocida"),
    ],
)
def test_finding_discloses_asset_source_identity(
    client: Client, owner: str | None, status: str, label: str
) -> None:
    user = get_user_model().objects.create_user(username="finding-source-user")
    client.force_login(user)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    metadata = (
        {
            "repository_source": {
                "provider": "github",
                "owner": owner,
                "repository": "repo",
                "ref": "main",
            }
        }
        if owner is not None
        else {}
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", metadata=metadata)
    finding = Finding.objects.create(
        scan_run=scan,
        asset=asset,
        source=Finding.Source.TRIVY,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="a" * 64,
        external_id="CVE-2026-1234",
    )

    for path in ("/", "/findings/", f"/findings/{finding.pk}/"):
        page = client.get(path)
        assert page.status_code == 200
        assert label in page.content.decode()
    detail = client.get(f"/api/findings/{finding.pk}/")
    assert detail.status_code == 200
    assert detail.json()["asset_source_status"] == status

    from ciclosec.mcp.server import list_findings

    mcp = list_findings(asset_id=asset.pk)
    assert mcp.items[0].asset_source_status == status


def test_finding_image_detects_a_reference_changed_and_restored(client: Client) -> None:
    from ciclosec.assets.services import update_container_image_source

    user = get_user_model().objects.create_user(username="image-finding-source")
    client.force_login(user)
    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    image = ContainerImage.objects.create(asset=asset, image_reference="example:local")
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="image",
        metadata={"image_reference": "example:local", "image_source_revision": 0},
    )
    finding = Finding.objects.create(
        scan_run=scan,
        asset=asset,
        source=Finding.Source.TRIVY,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="b" * 64,
    )
    update_container_image_source(image, image_reference="example:other")
    update_container_image_source(image, image_reference="example:local")

    response = client.get(f"/api/findings/{finding.pk}/")

    assert response.status_code == 200
    assert response.json()["asset_source_status"] == "changed"
