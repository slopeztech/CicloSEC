"""Authenticated pages for managing and exploring registered assets."""

import logging
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.db import DatabaseError, IntegrityError, transaction
from django.db.models import BooleanField, Case, F, Q, Value, When
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods, require_POST

from ciclosec.assets.api.views import AssetViewSet
from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.assets.services import (
    scan_source_status_for_asset,
    update_container_image_source,
    update_repository_source,
)
from ciclosec.common.config import ConfigurationError
from ciclosec.common.models import ConfigurationState
from ciclosec.common.settings_service import (
    ConfigurationConflict,
    beat_instance_statuses,
    configuration_snapshot,
    get_effective_config,
    update_configuration,
)
from ciclosec.findings.models import Finding
from ciclosec.findings.services import FindingDecisionError, review_finding
from ciclosec.intelligence.manual_sync_service import (
    ManualSyncConfirmationRequired,
    ManualSyncUnavailable,
    get_manual_sync_status,
    request_manual_sync,
)
from ciclosec.intelligence.models import AdvisoryRecord, SyncRun
from ciclosec.intelligence.services import get_source_freshness
from ciclosec.inventory.services import list_asset_components
from ciclosec.project.celery import schedule_entries
from ciclosec.scans.api.serializers import ScanRunSerializer
from ciclosec.scans.api.views import ScanRunViewSet
from ciclosec.scans.models import ScanRun
from ciclosec.scans.scheduling import describe_schedule
from ciclosec.scans.services import (
    get_scan_queue_status,
    scan_diagnostic_messages,
    uncertain_dispatch_condition,
)
from ciclosec.web.forms import (
    PROVIDER_SCHEDULE_OPTIONS,
    SETTINGS_OPTIONS,
    AssetForm,
    AssetSearchForm,
    ConfigurationOptionForm,
    ContainerImageForm,
    FindingDecisionForm,
    FindingFilterForm,
    HistoryFilterForm,
    RepositoryForm,
    SBOMFilterForm,
)

PAGE_SIZE = 25
logger = logging.getLogger(__name__)


@never_cache
@login_required
@require_http_methods(["GET", "POST"])
def configuration(request: HttpRequest) -> HttpResponse:
    if not request.user.is_active or not request.user.is_superuser:
        raise PermissionDenied

    if request.method == "POST":
        key = request.POST.get("option", "")
        if key not in SETTINGS_OPTIONS:
            return HttpResponse("Opción de configuración no disponible.", status=400)
        form = ConfigurationOptionForm(
            request.POST, key=key, revision=0, value=None, prefix=key.replace(".", "-")
        )
        if not form.is_valid():
            return HttpResponse("Revisa el valor y confirma el cambio.", status=400)
        try:
            revision = update_configuration(
                actor=request.user,
                changes={key: form.cleaned_data["value"]},
                expected_revision=form.cleaned_data["revision"],
                confirm=form.cleaned_data["confirm"],
                base=settings.CICLOSEC_CONFIG,
            )
        except ConfigurationConflict:
            return HttpResponse("La configuración cambió; recarga la página.", status=409)
        except ConfigurationError:
            return HttpResponse("El valor no es válido para esta configuración.", status=400)
        except (DatabaseError, ConfigurationState.DoesNotExist):
            logger.error("Configuration storage is unavailable or missing its state.")
            return HttpResponse("La configuración no está disponible.", status=503)
        if revision == form.cleaned_data["revision"]:
            messages.info(request, "El valor no cambió; no se creó un evento de auditoría.")
        else:
            messages.success(request, "Cambio guardado y registrado en la auditoría.")
        return redirect("settings")

    try:
        revision, config = configuration_snapshot(settings.CICLOSEC_CONFIG)
        beat_instances = beat_instance_statuses(revision)
    except (DatabaseError, ConfigurationError, ConfigurationState.DoesNotExist):
        logger.error("Configuration storage or its contents are unavailable.")
        return HttpResponse("La configuración no está disponible.", status=503)
    values = config.model_dump(mode="python")
    forms: list[dict[str, object]] = []
    provider_forms: list[dict[str, object]] = []
    provider_intervals: dict[str, str] = {name: interval for name, interval, _ in schedule_entries}
    for key in SETTINGS_OPTIONS:
        if key in PROVIDER_SCHEDULE_OPTIONS:
            _, _, provider, field = key.split(".")
            provider_config = values["intelligence"]["providers"].get(provider, {})
            if field == "enabled":
                current: Any = provider_config.get("enabled", False)
            else:
                current = provider_config.get("refresh_interval") or provider_intervals[provider]
        else:
            current = values
            for part in key.split("."):
                if part in ("repositories", "container_images") and key.startswith(
                    "scanning.schedules."
                ):
                    current = current.get(part, "24h")
                else:
                    current = current[part]
        target = provider_forms if key in PROVIDER_SCHEDULE_OPTIONS else forms
        target.append(
            {
                "key": key,
                "form": ConfigurationOptionForm(
                    key=key, revision=revision, value=current, prefix=key.replace(".", "-")
                ),
            }
        )
    return render(
        request,
        "web/settings.html",
        {
            "active_nav": "settings",
            "revision": revision,
            "options": forms,
            "provider_options": provider_forms,
            "beat_instances": beat_instances,
        },
    )


def _page(request: HttpRequest, queryset: Any) -> Any:
    return Paginator(queryset, PAGE_SIZE).get_page(request.GET.get("page"))


def _page_links(request: HttpRequest, page: Any) -> dict[str, object]:
    def link(number: int) -> str:
        query = request.GET.copy()
        query["page"] = str(number)
        return f"?{query.urlencode()}"

    return {
        "page": page.number,
        "total_pages": page.paginator.num_pages,
        "previous_url": link(page.previous_page_number()) if page.has_previous() else None,
        "next_url": link(page.next_page_number()) if page.has_next() else None,
    }


@never_cache
@login_required
def assets(request: HttpRequest) -> HttpResponse:
    form = AssetSearchForm(request.GET)
    queryset = Asset.objects.order_by("name", "id")
    if form.is_valid() and form.cleaned_data["q"]:
        queryset = queryset.filter(name__icontains=form.cleaned_data["q"])
    page = _page(request, queryset)
    return render(
        request,
        "web/assets.html",
        {
            "active_nav": "assets",
            "page": page,
            "pagination": _page_links(request, page),
            "form": form,
        },
        status=200 if form.is_valid() else 400,
    )


@never_cache
@login_required
def asset_detail(request: HttpRequest, pk: int) -> HttpResponse:
    asset = get_object_or_404(Asset, pk=pk)
    scans = asset.scan_runs.order_by("-created_at", "-id")[:5]
    config = get_effective_config()
    manual_scans_enabled = config.scanning.execution.allow_on_demand
    scanner_network_authorized = (
        asset.kind != Asset.Kind.REPOSITORY
        or config.scanning.execution.allow_repository_scanners_with_network
    )
    scan_request = ScanRunSerializer(data={"asset": asset.pk})
    active_scan = (
        asset.scan_runs.filter(status__in=[ScanRun.Status.QUEUED, ScanRun.Status.RUNNING])
        .order_by("created_at", "id")
        .first()
    )
    return render(
        request,
        "web/asset_detail.html",
        {
            "active_nav": "assets",
            "asset": asset,
            "scans": scans,
            "manual_scans_enabled": manual_scans_enabled,
            "scanner_network_authorized": scanner_network_authorized,
            "repository_scanner_use_local_databases": (
                config.scanning.execution.repository_scanner_use_local_databases
            ),
            "active_scan": active_scan,
            "can_scan": (
                manual_scans_enabled
                and scanner_network_authorized
                and active_scan is None
                and scan_request.is_valid()
            ),
            "scan_schedule": describe_schedule(asset),
            "schedule_interval": config.scanning.schedules.get(
                "repositories" if asset.kind == Asset.Kind.REPOSITORY else "container_images", "24h"
            ),
        },
    )


@never_cache
@login_required
@require_POST
def change_scan_schedule(request: HttpRequest, pk: int) -> HttpResponse:
    response = AssetViewSet.as_view({"post": "scan_schedule"})(request, pk=str(pk))
    if response.status_code == 202:
        messages.success(request, "Programación habilitada y primer escaneo solicitado.")
    elif response.status_code == 200:
        messages.success(request, "Programación deshabilitada; no se cancelan escaneos activos.")
    elif response.status_code == 503:
        messages.error(request, "Programación habilitada, pero no se pudo confirmar el envío.")
    elif response.status_code == 409:
        messages.error(
            request,
            "La fuente cambió, ya existe un escaneo activo o la programación está habilitada.",
        )
    elif response.status_code == 429:
        messages.error(request, "La cola está llena; no se habilitó la programación.")
    elif response.status_code == 400:
        messages.error(request, "Revisa la confirmación y la configuración del activo.")
    elif (
        response.status_code == 403
        and response.data.get("code")
        == ScanRun.Diagnostic.REPOSITORY_SCANNER_NETWORK_NOT_AUTHORIZED
    ):
        messages.error(request, "Autorización de red para escáneres de repositorios deshabilitada.")
    else:
        return response
    return redirect("web-asset-detail", pk=pk)


@never_cache
@login_required
def asset_edit(request: HttpRequest, pk: int | None = None) -> HttpResponse:
    asset = get_object_or_404(Asset, pk=pk) if pk is not None else None
    kind = asset.kind if asset else request.GET.get("kind", Asset.Kind.REPOSITORY)
    if kind not in Asset.Kind.values:
        return HttpResponse("Tipo de activo no válido.", status=400)
    source: Repository | ContainerImage | None = None
    if asset:
        source = (
            Repository.objects.filter(asset=asset).first()
            if kind == Asset.Kind.REPOSITORY
            else ContainerImage.objects.filter(asset=asset).first()
        )
    data = request.POST if request.method == "POST" else None
    asset_form = AssetForm(data, instance=asset)
    form_class = RepositoryForm if kind == Asset.Kind.REPOSITORY else ContainerImageForm
    source_form = form_class(data, instance=source)
    asset_valid = asset_form.is_valid()
    source_valid = source_form.is_valid()
    if request.method == "POST" and asset_valid and source_valid:
        try:
            with transaction.atomic():
                saved_asset = asset_form.save(commit=False)
                saved_asset.kind = kind
                saved_asset.save()
                saved_source = source_form.save(commit=False)
                saved_source.asset = saved_asset
                if isinstance(saved_source, ContainerImage) and saved_source.pk:
                    update_container_image_source(
                        saved_source,
                        asset=saved_asset,
                        image_reference=saved_source.image_reference,
                    )
                elif isinstance(saved_source, Repository) and saved_source.pk:
                    update_repository_source(
                        saved_source,
                        asset=saved_asset,
                        provider=saved_source.provider,
                        owner=saved_source.owner,
                        repository_name=saved_source.repository_name,
                        ref=saved_source.ref,
                        credential_env=saved_source.credential_env,
                    )
                else:
                    saved_source.save()
        except IntegrityError:
            source_form.add_error(None, "No se pudo guardar el activo por un conflicto de datos.")
        else:
            messages.success(request, "Activo guardado correctamente.")
            return redirect("web-asset-detail", pk=saved_asset.pk)
    return render(
        request,
        "web/asset_form.html",
        {
            "active_nav": "assets",
            "asset": asset,
            "kind": kind,
            "asset_form": asset_form,
            "source_form": source_form,
        },
    )


@never_cache
@login_required
@require_POST
def request_scan(request: HttpRequest, pk: int) -> HttpResponse:
    asset = get_object_or_404(Asset, pk=pk)
    live_request = request.headers.get("X-CicloSec-Live") == "dashboard"
    if request.POST.get("asset") != str(pk):
        if live_request:
            return JsonResponse({"detail": "El activo indicado no coincide."}, status=400)
        return HttpResponse("El activo indicado no coincide.", status=400)
    response = ScanRunViewSet.as_view({"post": "create"})(request)
    if response.status_code == 202:
        scan_id = response.data["id"]
        detail = f"Escaneo #{scan_id} solicitado."
        if live_request:
            return JsonResponse({"detail": detail, "scan_id": scan_id}, status=202)
        messages.success(request, detail)
        return redirect("web-scan-detail", pk=response.data["id"])
    if response.status_code == 503:
        detail = "No se pudo confirmar el envío. Revisa el escaneo y el worker antes de actuar."
        if live_request:
            return JsonResponse(
                {"detail": detail, "scan_id": response.data["scan_id"]},
                status=503,
            )
        messages.error(
            request,
            detail,
        )
        return redirect("web-scan-detail", pk=response.data["scan_id"])
    if response.status_code == 403:
        if (
            response.data.get("code")
            == ScanRun.Diagnostic.REPOSITORY_SCANNER_NETWORK_NOT_AUTHORIZED
        ):
            detail = "Autorización de red para escáneres de repositorios deshabilitada."
        else:
            detail = "Los escaneos bajo demanda están deshabilitados."
    elif response.status_code == 409:
        detail = "Ya hay un escaneo activo para este activo. Consulta su historial."
    elif response.status_code == 429:
        detail = "La cola de escaneos está llena. Revisa el historial antes de reintentar."
    else:
        detail = (
            "No se pudo solicitar el escaneo. Comprueba que el activo y su fuente estén "
            "habilitados y autorizados en la configuración."
        )
    if live_request:
        payload: dict[str, object] = {"detail": detail}
        scan_id = response.data.get("scan_id")
        if scan_id is not None:
            payload["scan_id"] = scan_id
        return JsonResponse(payload, status=response.status_code)
    messages.error(request, detail)
    return redirect("web-asset-detail", pk=asset.pk)


@never_cache
@login_required
def findings(request: HttpRequest) -> HttpResponse:
    form = FindingFilterForm(request.GET)
    queryset = Finding.objects.select_related(
        "asset",
        "asset__repository",
        "asset__container_image",
        "scan_run",
        "vulnerability",
        "risk_assessment",
    )
    if form.is_valid():
        query = form.cleaned_data["q"]
        status = form.cleaned_data["status"]
        if query:
            queryset = queryset.filter(
                Q(external_id__icontains=query)
                | Q(package_name__icontains=query)
                | Q(asset__name__icontains=query)
            )
        if status:
            queryset = queryset.filter(affected_status=status)
        if form.cleaned_data["asset_id"]:
            queryset = queryset.filter(asset_id=form.cleaned_data["asset_id"])
        if form.cleaned_data["scan_id"]:
            queryset = queryset.filter(scan_run_id=form.cleaned_data["scan_id"])
    if form.is_valid() and form.cleaned_data["sort"] == "recent":
        queryset = queryset.order_by("-created_at", "-id")
    else:
        queryset = queryset.order_by(F("risk_assessment__score").desc(nulls_last=True), "-id")
    page = _page(request, queryset)
    return render(
        request,
        "web/findings.html",
        {
            "active_nav": "findings",
            "form": form,
            "page": page,
            "finding_rows": [
                {
                    "finding": finding,
                    "asset_source_status": scan_source_status_for_asset(
                        asset=finding.asset, metadata=finding.scan_run.metadata
                    ),
                }
                for finding in page
            ],
            "pagination": _page_links(request, page),
        },
        status=200 if form.is_valid() else 400,
    )


@never_cache
@login_required
def finding_detail(request: HttpRequest, pk: int) -> HttpResponse:
    finding = get_object_or_404(
        Finding.objects.select_related(
            "asset",
            "asset__repository",
            "asset__container_image",
            "scan_run",
            "vulnerability",
            "risk_assessment",
        ).prefetch_related("decision_events"),
        pk=pk,
    )
    decision = getattr(finding, "decision", None)
    initial = None
    if decision is not None:
        initial = {
            "status": decision.status,
            "assignee": decision.assignee_id,
            "reason": decision.reason,
        }
    return render(
        request,
        "web/finding_detail.html",
        {
            "active_nav": "findings",
            "finding": finding,
            "decision_form": FindingDecisionForm(initial=initial),
            "can_review": request.user.is_staff,
            "decision_events": finding.decision_events.select_related("actor", "assignee").order_by(
                "-created_at", "-id"
            )[:50],
            "asset_source_status": scan_source_status_for_asset(
                asset=finding.asset, metadata=finding.scan_run.metadata
            ),
        },
    )


@never_cache
@login_required
@require_POST
def review_finding_view(request: HttpRequest, pk: int) -> HttpResponse:
    if not request.user.is_staff:
        raise PermissionDenied("Only administrators can review findings.")
    finding = get_object_or_404(Finding, pk=pk)
    form = FindingDecisionForm(request.POST)
    if not form.is_valid():
        messages.error(request, "Revisa el estado, el responsable y el motivo.")
        return redirect("web-finding-detail", pk=finding.pk)
    try:
        review_finding(
            finding_id=finding.pk,
            status=form.cleaned_data["status"],
            reason=form.cleaned_data["reason"],
            actor=request.user,
            assignee=form.cleaned_data["assignee"],
        )
    except FindingDecisionError as error:
        messages.error(request, str(error))
        return redirect("web-finding-detail", pk=finding.pk)
    messages.success(request, "La decisión humana quedó registrada.")
    return redirect("web-finding-detail", pk=finding.pk)


@never_cache
@login_required
def sbom(request: HttpRequest) -> HttpResponse:
    form = SBOMFilterForm(request.GET or None)
    result = None
    pagination = None
    if form.is_valid():
        asset = form.cleaned_data["asset"]
        scan_id = form.cleaned_data["scan_id"]
        if scan_id and not asset.scan_runs.filter(pk=scan_id).exists():
            form.add_error("scan_id", "El escaneo no pertenece a este activo.")
        else:
            page_number = request.GET.get("page", "1")
            try:
                number = max(1, int(page_number))
            except ValueError:
                form.add_error(None, "La página indicada no es válida.")
            else:
                result = list_asset_components(
                    asset_id=asset.pk,
                    scan_run_id=scan_id,
                    limit=PAGE_SIZE,
                    offset=(number - 1) * PAGE_SIZE,
                )
                page = Paginator(range(result["total"]), PAGE_SIZE).get_page(number)
                if page.number != number:
                    result = list_asset_components(
                        asset_id=asset.pk,
                        scan_run_id=scan_id,
                        limit=PAGE_SIZE,
                        offset=(page.number - 1) * PAGE_SIZE,
                    )
                pagination = _page_links(request, page)
    return render(
        request,
        "web/sbom.html",
        {"active_nav": "sbom", "form": form, "result": result, "pagination": pagination},
        status=400 if form.is_bound and form.errors else 200,
    )


@never_cache
@login_required
def history(request: HttpRequest) -> HttpResponse:
    form = HistoryFilterForm(request.GET)
    queryset = (
        ScanRun.objects.select_related("asset")
        .annotate(
            delivery_uncertain=Case(
                When(uncertain_dispatch_condition(), then=Value(True)),
                default=Value(False),
                output_field=BooleanField(),
            )
        )
        .order_by("-created_at", "-id")
    )
    if form.is_valid() and form.cleaned_data["asset_id"]:
        queryset = queryset.filter(asset_id=form.cleaned_data["asset_id"])
    page = _page(request, queryset)
    return render(
        request,
        "web/history.html",
        {
            "active_nav": "history",
            "form": form,
            "page": page,
            "pagination": _page_links(request, page),
            "queue_status": get_scan_queue_status(),
        },
        status=200 if form.is_valid() else 400,
    )


@never_cache
@login_required
def scan_detail(request: HttpRequest, pk: int) -> HttpResponse:
    scan = get_object_or_404(ScanRun.objects.select_related("asset"), pk=pk)
    return render(
        request,
        "web/scan_detail.html",
        {
            "active_nav": "history",
            "scan": scan,
            "diagnostic_messages": scan_diagnostic_messages(scan),
            "dispatch_uncertain": (
                scan.status == ScanRun.Status.QUEUED
                and isinstance(scan.metadata, dict)
                and (
                    scan.metadata.get("dispatch_uncertain") is True
                    or scan.metadata.get("initial_dispatch_pending") is True
                )
            ),
        },
    )


@never_cache
@login_required
@require_POST
def cancel_queued_scan(request: HttpRequest, pk: int) -> HttpResponse:
    response = ScanRunViewSet.as_view({"post": "cancel_queued"})(request, pk=str(pk))
    if response.status_code == 200:
        messages.success(request, "Escaneo en cola cancelado. No se ha iniciado otro escaneo.")
    elif response.status_code == 400:
        messages.error(request, "Confirma que deseas cancelar el escaneo en cola.")
    elif response.status_code == 409:
        messages.error(request, "El escaneo ya no está en cola o podría haber comenzado.")
    else:
        return response
    return redirect("web-scan-detail", pk=pk)


@never_cache
@login_required
def intelligence(request: HttpRequest) -> HttpResponse:
    sources = [
        {"label": label, "freshness": get_source_freshness(provider)}
        for provider, label in AdvisoryRecord.Provider.choices
    ]
    runs = SyncRun.objects.order_by("-started_at", "-id")[:20]
    return render(
        request,
        "web/intelligence.html",
        {
            "active_nav": "intelligence",
            "sources": sources,
            "runs": runs,
            "manual_sync": (
                get_manual_sync_status(actor=request.user) if request.user.is_staff else None
            ),
        },
    )


@never_cache
@login_required
@require_POST
def request_intelligence_update(request: HttpRequest) -> HttpResponse:
    if not request.user.is_staff or not request.user.is_active:
        raise PermissionDenied
    try:
        result = request_manual_sync(
            actor=request.user, confirm=request.POST.get("confirm") == "true"
        )
    except ManualSyncConfirmationRequired:
        messages.error(request, "Confirma que deseas consultar las fuentes externas.")
    except (DatabaseError, ManualSyncUnavailable):
        messages.error(
            request, "No se pudo verificar la solicitud; revisa el estado antes de repetir."
        )
    else:
        providers = result["providers"]
        if any(
            item["status"] == "uncertain"
            or item["error"] in {"followup_delivery_pending", "followup_delivery_uncertain"}
            for item in providers
        ):
            messages.error(request, "Algún envío no se pudo confirmar; revisa el estado.")
        elif any(item["duplicate"] for item in providers):
            messages.warning(
                request,
                "Algunos proveedores ya tenían una solicitud activa; revisa el estado de cada uno.",
            )
        else:
            messages.success(request, "Solicitudes enviadas; revisa su progreso por proveedor.")
    return redirect("intelligence")


@never_cache
@login_required
def integrations(request: HttpRequest) -> HttpResponse:
    return render(
        request,
        "web/integrations.html",
        {"active_nav": "integrations", "mcp_enabled": get_effective_config().mcp.enabled},
    )
