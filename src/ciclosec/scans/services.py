"""Read-only scan history queries."""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import redis.exceptions
from django.db import connection, transaction
from django.db.models import CharField, Count, F, Func, Q, Value
from django.db.models.lookups import Exact
from django.db.transaction import TransactionManagementError
from kombu.exceptions import OperationalError

from ciclosec.assets.models import Asset
from ciclosec.common.settings_service import get_effective_config
from ciclosec.scans.models import ScanConcurrencyGate, ScanRun

logger = logging.getLogger(__name__)


class ActiveScanError(Exception):
    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        super().__init__("An active scan already exists for this asset.")


class ScanQueueFullError(Exception):
    pass


class RepositoryScannerNetworkNotAuthorized(Exception):
    def __init__(self) -> None:
        super().__init__("Repository scanners with possible network access are not authorized.")


_DIAGNOSTIC_MESSAGES: dict[str, str] = {
    ScanRun.Diagnostic.ASSET_DISABLED: "El activo estaba deshabilitado y el escaneo no se inició.",
    ScanRun.Diagnostic.ASSET_KIND_MISMATCH: (
        "El tipo de activo no corresponde al escaneo solicitado."
    ),
    ScanRun.Diagnostic.REPOSITORY_MISSING: "Falta configurar la fuente del repositorio.",
    ScanRun.Diagnostic.REPOSITORY_SCANNER_NETWORK_NOT_AUTHORIZED: (
        "Los escáneres de repositorio que pueden usar la red no están autorizados "
        "en la configuración del worker."
    ),
    ScanRun.Diagnostic.CREDENTIAL_MISSING: (
        "Falta la credencial de GitHub en el entorno del worker."
    ),
    ScanRun.Diagnostic.REPOSITORY_CHECKOUT_FAILED: (
        "No se pudo acceder al repositorio. Revisa la referencia, los permisos y la conexión."
    ),
    ScanRun.Diagnostic.REPOSITORY_SBOM_FAILED: "No se pudo generar el SBOM del repositorio.",
    ScanRun.Diagnostic.SBOM_INVALID: "El SBOM generado no superó la validación.",
    ScanRun.Diagnostic.OSV_UNAVAILABLE: "No se pudieron obtener resultados de OSV-Scanner.",
    ScanRun.Diagnostic.TRIVY_UNAVAILABLE: "No se pudieron obtener hallazgos de Trivy.",
    ScanRun.Diagnostic.OSV_VERSION_UNAVAILABLE: "No se pudo comprobar la versión de OSV-Scanner.",
    ScanRun.Diagnostic.TRIVY_VERSION_UNAVAILABLE: "No se pudo comprobar la versión de Trivy.",
    ScanRun.Diagnostic.DEPENDABOT_UNAVAILABLE: (
        "No se pudieron consultar las alertas de Dependabot. "
        "Revisa los permisos y su configuración."
    ),
    ScanRun.Diagnostic.SCANNER_DATABASE_FRESHNESS_UNVERIFIED: (
        "Se usaron bases locales de escáneres; CicloSec no pudo verificar su actualidad."
    ),
    ScanRun.Diagnostic.SCANNER_DATABASE_CACHE_UNAVAILABLE: (
        "Falta una base local configurada; el escáner no pudo usar cobertura local completa."
    ),
    ScanRun.Diagnostic.REPOSITORY_SOURCE_CHANGED: (
        "La fuente del repositorio cambió durante el escaneo; los resultados son históricos."
    ),
    ScanRun.Diagnostic.IMAGE_SCANNING_DISABLED: (
        "El análisis de imágenes locales no está habilitado en la configuración del worker."
    ),
    ScanRun.Diagnostic.IMAGE_SOURCE_MISSING: "Falta configurar la referencia de la imagen.",
    ScanRun.Diagnostic.IMAGE_NOT_ALLOWLISTED: "La imagen no está en la lista permitida.",
    ScanRun.Diagnostic.IMAGE_SBOM_FAILED: (
        "No se pudo generar el SBOM de la imagen. Revisa la imagen local y el acceso al daemon."
    ),
    ScanRun.Diagnostic.IMAGE_FINDINGS_UNAVAILABLE: (
        "No se pudieron obtener hallazgos de Trivy para la imagen."
    ),
    ScanRun.Diagnostic.IMAGE_SOURCE_CHANGED: (
        "La fuente de imagen cambió durante el escaneo; el digest anterior no se asignó a ella."
    ),
    ScanRun.Diagnostic.CORRELATION_UNAVAILABLE: (
        "No se pudieron correlacionar todos los hallazgos con la inteligencia disponible."
    ),
    ScanRun.Diagnostic.MANUALLY_RECOVERED: (
        "Un operador marcó el escaneo como interrumpido durante el mantenimiento; "
        "no se ha verificado la causa."
    ),
    ScanRun.Diagnostic.SCHEDULED_SOURCE_CHANGED: (
        "La fuente cambió respecto a la autorización de programación; no se inició su análisis."
    ),
}
_UNKNOWN_DIAGNOSTIC = (
    "No se dispone de una explicación detallada. Revisa los registros locales con cuidado."
)


def lock_scan_capacity_gate() -> None:
    """Serialize scan admission decisions within the caller's transaction."""
    if not connection.in_atomic_block:
        raise TransactionManagementError("Scan capacity requires a transaction")
    ScanConcurrencyGate.objects.get_or_create(pk=1)
    ScanConcurrencyGate.objects.select_for_update().get(pk=1)


def create_scan_for_locked_asset(asset: Asset) -> ScanRun:
    """Admit one scan while the caller holds the asset lock in a transaction."""
    if not connection.in_atomic_block:
        raise TransactionManagementError("Scan admission requires a transaction")
    active = (
        ScanRun.objects.filter(
            asset=asset, status__in=[ScanRun.Status.QUEUED, ScanRun.Status.RUNNING]
        )
        .order_by("created_at", "id")
        .first()
    )
    if active is not None:
        raise ActiveScanError(active.pk)
    execution = get_effective_config().scanning.execution
    if asset.kind == Asset.Kind.REPOSITORY and not execution.allow_repository_scanners_with_network:
        raise RepositoryScannerNetworkNotAuthorized()
    lock_scan_capacity_gate()
    if ScanRun.objects.filter(status=ScanRun.Status.QUEUED).count() >= execution.max_queued_scans:
        raise ScanQueueFullError("The scan queue is full.")
    return ScanRun.objects.create(
        asset=asset,
        scanner_name=(
            "container-image-security"
            if asset.kind == Asset.Kind.CONTAINER_IMAGE
            else "repository-security"
        ),
        metadata={"initial_dispatch_pending": True},
    )


def dispatch_scan(scan_id: int, send: Callable[[int], Any]) -> bool:
    """Dispatch after commit and record a delivery that could not be confirmed."""
    try:
        send(scan_id)
    except (OperationalError, redis.exceptions.RedisError, OSError):
        logger.error("Scan %s: task delivery could not be confirmed", scan_id)
        record_uncertain_dispatch(scan_id)
        return False
    with transaction.atomic():
        scan = ScanRun.objects.select_for_update().get(pk=scan_id)
        if not isinstance(scan.metadata, dict):
            raise ValueError(f"Scan {scan_id} has invalid metadata")
        if scan.metadata.get("initial_dispatch_pending") is True:
            scan.metadata = {**scan.metadata}
            del scan.metadata["initial_dispatch_pending"]
            scan.save(update_fields=["metadata"])
    return True


def record_uncertain_dispatch(scan_run_id: int) -> None:
    """Record uncertain delivery without changing a claimed scan."""
    with transaction.atomic():
        scan = ScanRun.objects.select_for_update().get(pk=scan_run_id)
        if scan.status != ScanRun.Status.QUEUED:
            return
        if not isinstance(scan.metadata, dict):
            raise ValueError(f"Scan {scan_run_id} has invalid metadata")
        scan.metadata = {**scan.metadata, "dispatch_uncertain": True}
        scan.save(update_fields=["metadata"])


def uncertain_dispatch_condition() -> Q:
    """Match queued scans with an unconfirmed initial or subsequent delivery."""
    if connection.vendor == "sqlite":

        def is_true(key: str) -> Q:
            json_type = Func(
                F("metadata"),
                Value(f"$.{key}"),
                function="JSON_TYPE",
                output_field=CharField(),
            )
            return Q(Exact(json_type, Value("true")))

        markers = is_true("dispatch_uncertain") | is_true("initial_dispatch_pending")
    else:
        markers = Q(metadata__dispatch_uncertain=True) | Q(metadata__initial_dispatch_pending=True)
    return Q(status=ScanRun.Status.QUEUED) & markers


def get_scan_queue_status() -> dict[str, int | bool]:
    """Return global recorded scan capacity, not broker or worker health."""
    counts = ScanRun.objects.aggregate(
        queued_count=Count("pk", filter=Q(status=ScanRun.Status.QUEUED)),
        running_count=Count("pk", filter=Q(status=ScanRun.Status.RUNNING)),
        delivery_uncertain_count=Count("pk", filter=uncertain_dispatch_condition()),
    )
    execution = get_effective_config().scanning.execution
    return {
        "queued_count": counts["queued_count"],
        "queued_limit": execution.max_queued_scans,
        "running_count": counts["running_count"],
        "running_limit": execution.max_concurrent_scans,
        "delivery_uncertain_count": counts["delivery_uncertain_count"],
        "queue_full": counts["queued_count"] >= execution.max_queued_scans,
    }


def scan_diagnostic_messages(scan: ScanRun) -> list[str]:
    """Return fixed, safe descriptions without exposing stored raw errors."""
    if scan.status not in {ScanRun.Status.FAILED, ScanRun.Status.PARTIAL}:
        return []
    codes = scan.metadata.get("diagnostic_codes") if isinstance(scan.metadata, dict) else None
    if not isinstance(codes, list) or not codes:
        return [_UNKNOWN_DIAGNOSTIC]
    messages = []
    for code in codes:
        message = _DIAGNOSTIC_MESSAGES.get(code) if isinstance(code, str) else None
        message = message or _UNKNOWN_DIAGNOSTIC
        if message not in messages:
            messages.append(message)
    return messages


def list_scan_history(
    *,
    asset_id: int | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Return bounded scan history without scanner output or metadata."""
    scans = ScanRun.objects.select_related("asset").order_by("-created_at", "-id")
    if asset_id is not None:
        scans = scans.filter(asset_id=asset_id)
    total = scans.count()
    items = []
    for scan in scans[offset : offset + limit]:
        warnings = scan.warnings
        if not isinstance(warnings, list):
            raise ValueError(f"Scan {scan.pk} has invalid warning metadata")
        items.append(
            {
                "id": scan.pk,
                "asset_id": scan.asset_id,
                "asset_name": scan.asset.name,
                "scanner_name": scan.scanner_name,
                "scanner_version": scan.scanner_version,
                "status": scan.status,
                "started_at": scan.started_at,
                "finished_at": scan.finished_at,
                "created_at": scan.created_at,
                "duration_seconds": scan.duration_seconds,
                "warning_count": len(warnings),
                "has_error": bool(scan.error_summary),
            }
        )
    return {"total": total, "limit": limit, "offset": offset, "items": items}
