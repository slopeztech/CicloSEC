"""Authenticated server-rendered CicloSec dashboard."""

from typing import Any

from django import forms
from django.contrib.auth.decorators import login_required
from django.db.models import Count, Exists, F, OuterRef, Q, Subquery
from django.db.models.functions import Coalesce
from django.http import HttpRequest, HttpResponse, QueryDict
from django.shortcuts import render
from django.views.decorators.cache import never_cache

from ciclosec.assets.models import Asset
from ciclosec.common.settings_service import get_effective_config
from ciclosec.findings.models import Finding, FindingDecision, RiskAssessment
from ciclosec.intelligence.models import AdvisoryRecord, IntelligenceSource, VulnerabilityAlias
from ciclosec.scans.models import ScanRun
from ciclosec.web.services import (
    ASSET_PAGE_SIZE,
    FINDING_PAGE_SIZE,
    SCAN_PAGE_SIZE,
    get_dashboard_summary,
)


class DashboardFilterForm(forms.Form):
    """Filters for scan and finding tables."""

    asset_id = forms.IntegerField(
        label="ID del activo",
        min_value=1,
        required=False,
    )
    affected_status = forms.ChoiceField(
        label="Afectación",
        choices=(
            ("", "Todos"),
            (Finding.AffectedStatus.CONFIRMED, "Confirmada"),
            (Finding.AffectedStatus.POTENTIAL, "Potencial"),
            (Finding.AffectedStatus.NOT_AFFECTED, "No afectada"),
            (Finding.AffectedStatus.NOT_APPLICABLE, "No aplicable"),
            (Finding.AffectedStatus.PENDING_VERIFICATION, "Pendiente de verificar"),
        ),
        required=False,
    )
    assets_page = forms.IntegerField(min_value=1, initial=1, required=False)
    scans_page = forms.IntegerField(min_value=1, initial=1, required=False)
    findings_page = forms.IntegerField(min_value=1, initial=1, required=False)


_COVERAGE_ROWS = (
    ("current", "Reciente"),
    ("partial", "Parcial"),
    ("failed", "Fallido"),
    ("in_progress", "En curso"),
    ("stale", "Desactualizado"),
    ("source_changed", "Fuente modificada o ausente"),
    ("source_unknown", "Identidad desconocida"),
    ("never_scanned", "Sin escanear"),
)
_SEVERITY_ROWS = (
    ("critical", "Crítica"),
    ("high", "Alta"),
    ("medium", "Media"),
    ("low", "Baja"),
    ("unknown", "Sin clasificar"),
)
_SOURCE_STATUS_LABELS = {
    IntelligenceSource.Status.CURRENT: "Actualizada",
    IntelligenceSource.Status.STALE: "Desactualizada",
    IntelligenceSource.Status.UNAVAILABLE: "No disponible",
    IntelligenceSource.Status.UNKNOWN: "Desconocida",
}
_SCAN_STATUS_LABELS = {
    ScanRun.Status.QUEUED: "En cola",
    ScanRun.Status.RUNNING: "En curso",
    ScanRun.Status.SUCCEEDED: "Correcto",
    ScanRun.Status.PARTIAL: "Parcial",
    ScanRun.Status.FAILED: "Fallido",
    ScanRun.Status.CANCELLED: "Cancelado",
}
_AFFECTED_STATUS_LABELS = {
    Finding.AffectedStatus.CONFIRMED: "Confirmada",
    Finding.AffectedStatus.POTENTIAL: "Potencial",
    Finding.AffectedStatus.NOT_AFFECTED: "No afectada",
    Finding.AffectedStatus.NOT_APPLICABLE: "No aplicable",
    Finding.AffectedStatus.PENDING_VERIFICATION: "Pendiente de verificar",
}
_PROVIDER_LABELS = dict(AdvisoryRecord.Provider.choices)
_ASSET_KIND_LABELS = dict(Asset.Kind.choices)
_ASSET_ENVIRONMENT_LABELS = dict(Asset.Environment.choices)
_ASSET_EXPOSURE_LABELS = dict(Asset.Exposure.choices)
_INSIGHT_LIMIT = 5


def _dashboard_insights(
    *, asset_id: int | None, affected_status: str | None, sources: list[dict[str, Any]]
) -> dict[str, Any]:
    urgent = (
        Finding.objects.select_related("asset", "risk_assessment")
        .filter(
            risk_assessment__level__in=[RiskAssessment.Level.HIGH, RiskAssessment.Level.CRITICAL]
        )
        .filter(
            Q(decision__isnull=True)
            | Q(decision__status__in=[FindingDecision.Status.OPEN, FindingDecision.Status.ASSIGNED])
        )
    )
    if asset_id is not None:
        urgent = urgent.filter(asset_id=asset_id)
    if affected_status:
        urgent = urgent.filter(affected_status=affected_status)

    related_findings = Finding.objects.filter(
        Q(vulnerability_id=OuterRef("root_id"))
        | Q(vulnerability__merged_into_id=OuterRef("root_id"))
    ).order_by("-created_at", "-id")
    advisories = AdvisoryRecord.objects.filter(
        Q(vulnerability_id=OuterRef("root_id"))
        | Q(vulnerability__merged_into_id=OuterRef("root_id")),
        is_active=True,
    ).order_by("-retrieved_at", "-id")
    cves = (
        VulnerabilityAlias.objects.filter(namespace=VulnerabilityAlias.Namespace.CVE)
        .select_related("vulnerability")
        .annotate(
            root_id=Coalesce("vulnerability__merged_into_id", "vulnerability_id"),
            published=Coalesce(
                "vulnerability__published_at", "vulnerability__merged_into__published_at"
            ),
            has_finding=Exists(related_findings),
            related_finding_id=Subquery(related_findings.values("id")[:1]),
            provider=Subquery(advisories.values("provider")[:1]),
        )
        .filter(published__isnull=False)
        .order_by("-published", "-id")
    )
    freshness = {source["provider"]: source for source in sources}

    def cve_rows(related_only: bool) -> list[dict[str, Any]]:
        rows = []
        selected = cves.filter(has_finding=True) if related_only else cves
        for alias in selected[:_INSIGHT_LIMIT]:
            source = freshness.get(alias.provider)
            rows.append(
                {
                    "identifier": alias.identifier,
                    "finding_id": alias.related_finding_id,
                    "published_at": alias.published,
                    "provider_label": _PROVIDER_LABELS.get(alias.provider, alias.provider),
                    "source_status": (
                        _SOURCE_STATUS_LABELS.get(source["status"], source["status"])
                        if source
                        else "Desconocida"
                    ),
                    "last_success_at": source["last_success_at"] if source else None,
                }
            )
        return rows

    return {
        "urgent_findings": urgent.order_by(
            F("risk_assessment__score").desc(nulls_last=True), "-id"
        )[:_INSIGHT_LIMIT],
        "recent_related_cves": cve_rows(True),
        "recent_local_cves": cve_rows(False),
    }


def _page_navigation(
    request: HttpRequest,
    *,
    page_key: str,
    page: int,
    page_size: int,
    total: int,
) -> dict[str, int | str | None]:
    """Create bounded page links while preserving valid filters and other pages."""
    query = QueryDict("", mutable=True)
    for key in ("asset_id", "affected_status", "assets_page", "scans_page", "findings_page"):
        value = request.GET.get(key)
        if value:
            query[key] = value

    total_pages = max(1, (total + page_size - 1) // page_size)

    def page_url(target: int) -> str:
        page_query = query.copy()
        page_query[page_key] = str(target)
        return f"?{page_query.urlencode()}"

    return {
        "page": page,
        "total_pages": total_pages,
        "previous_url": page_url(page - 1) if page > 1 else None,
        "next_url": page_url(page + 1) if page * page_size < total else None,
    }


def _finding_severity_rows(
    *,
    asset_id: int | None,
    affected_status: str | None,
) -> list[dict[str, int | str]]:
    """Count vulnerability severities for the active dashboard filters."""
    findings = Finding.objects.filter(kind=Finding.Kind.VULNERABILITY)
    if asset_id is not None:
        findings = findings.filter(asset_id=asset_id)
    if affected_status is not None:
        findings = findings.filter(affected_status=affected_status)

    counts = {key: 0 for key, _label in _SEVERITY_ROWS}
    for row in findings.values("severity").annotate(total=Count("pk")):
        severity = (row["severity"] or "").casefold()
        key = severity if severity in counts and severity != "unknown" else "unknown"
        counts[key] += row["total"]

    maximum = max(counts.values(), default=0)
    return [
        {
            "key": key,
            "label": label,
            "count": counts[key],
            "percentage": round(counts[key] * 100 / maximum) if maximum else 0,
        }
        for key, label in _SEVERITY_ROWS
    ]


@never_cache
@login_required
def dashboard(request: HttpRequest) -> HttpResponse:
    """Render a read-only overview and reject malformed filters visibly."""
    filter_form = DashboardFilterForm(request.GET)
    if not filter_form.is_valid():
        return render(
            request,
            "web/dashboard.html",
            {"filter_form": filter_form, "active_nav": "dashboard"},
            status=400,
        )

    summary = get_dashboard_summary(
        asset_id=filter_form.cleaned_data["asset_id"],
        affected_status=filter_form.cleaned_data["affected_status"] or None,
        assets_page=filter_form.cleaned_data["assets_page"] or 1,
        scans_page=filter_form.cleaned_data["scans_page"] or 1,
        findings_page=filter_form.cleaned_data["findings_page"] or 1,
    )
    coverage = summary["coverage"]
    coverage_counts = coverage["counts"]
    enabled_total = coverage["enabled_total"]
    execution = get_effective_config().scanning.execution
    context = {
        "active_nav": "dashboard",
        "filter_form": filter_form,
        "summary": summary,
        **_dashboard_insights(
            asset_id=filter_form.cleaned_data["asset_id"],
            affected_status=filter_form.cleaned_data["affected_status"] or None,
            sources=summary["sources"],
        ),
        "manual_scans_enabled": execution.allow_on_demand,
        "repository_scanner_network_authorized": (execution.allow_repository_scanners_with_network),
        "repository_scanner_use_local_databases": (
            execution.repository_scanner_use_local_databases
        ),
        "has_repository_assets": any(
            asset["kind"] == Asset.Kind.REPOSITORY for asset in summary["assets"]["items"]
        ),
        "coverage_percent": (
            round(coverage_counts["current"] * 100 / enabled_total) if enabled_total else 0
        ),
        "coverage_metric_cards": [
            {
                "key": "registered",
                "label": "Registrados",
                "count": coverage["total_registered"],
            },
            {"key": "enabled", "label": "Habilitados", "count": enabled_total},
            {
                "key": "disabled",
                "label": "Deshabilitados",
                "count": coverage["disabled_total"],
            },
            *[
                {"key": key, "label": label, "count": coverage_counts[key]}
                for key, label in _COVERAGE_ROWS
            ],
        ],
        "severity_rows": _finding_severity_rows(
            asset_id=filter_form.cleaned_data["asset_id"],
            affected_status=filter_form.cleaned_data["affected_status"] or None,
        ),
        "asset_pagination": _page_navigation(
            request,
            page_key="assets_page",
            page=filter_form.cleaned_data["assets_page"] or 1,
            page_size=ASSET_PAGE_SIZE,
            total=summary["assets"]["total"],
        ),
        "scan_pagination": _page_navigation(
            request,
            page_key="scans_page",
            page=filter_form.cleaned_data["scans_page"] or 1,
            page_size=SCAN_PAGE_SIZE,
            total=summary["scans"]["total"],
        ),
        "finding_pagination": _page_navigation(
            request,
            page_key="findings_page",
            page=filter_form.cleaned_data["findings_page"] or 1,
            page_size=FINDING_PAGE_SIZE,
            total=summary["findings"]["total"],
        ),
        "source_rows": [
            {
                **source,
                "label": _PROVIDER_LABELS.get(source["provider"], source["provider"]),
                "status_label": _SOURCE_STATUS_LABELS.get(
                    source["status"],
                    source["status"],
                ),
            }
            for source in summary["sources"]
        ],
        "scan_rows": [
            {
                **scan,
                "status_label": _SCAN_STATUS_LABELS.get(scan["status"], scan["status"]),
            }
            for scan in summary["scans"]["items"]
        ],
        "finding_rows": [
            {
                **finding,
                "affected_status_label": _AFFECTED_STATUS_LABELS.get(
                    finding["affected_status"],
                    finding["affected_status"],
                ),
            }
            for finding in summary["findings"]["items"]
        ],
        "asset_rows": [
            {
                **asset,
                "kind_label": _ASSET_KIND_LABELS.get(asset["kind"], asset["kind"]),
                "environment_label": _ASSET_ENVIRONMENT_LABELS.get(
                    asset["environment"],
                    asset["environment"],
                ),
                "exposure_label": _ASSET_EXPOSURE_LABELS.get(
                    asset["exposure"],
                    asset["exposure"],
                ),
            }
            for asset in summary["assets"]["items"]
        ],
    }
    if request.headers.get("X-CicloSec-Live") == "dashboard":
        return render(request, "web/partials/dashboard_live_content.html", context)
    return render(request, "web/dashboard.html", context)
