"""Repository scan orchestration, SBOM ingestion, and finding persistence."""

from __future__ import annotations

import hashlib
import tempfile
from collections.abc import Iterable
from pathlib import Path

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.common.config import ConfigurationError, resolve_environment_value
from ciclosec.common.settings_service import get_effective_config
from ciclosec.findings.models import Finding
from ciclosec.findings.services import CorrelationError, reevaluate_findings
from ciclosec.intelligence.merging import MergeConflict, lock_alias_roots, root_id
from ciclosec.intelligence.models import Vulnerability, VulnerabilityAlias
from ciclosec.inventory.models import ComponentOccurrence
from ciclosec.inventory.sbom import SBOMValidationError, ingest_sbom, parse_sbom
from ciclosec.scanners.adapters import (
    NormalizedFinding,
    inspect_local_scanner_databases,
    resolve_local_docker_image,
    run_osv_scanner,
    run_trivy_findings,
    run_trivy_image_findings,
    run_trivy_image_sbom,
    run_trivy_sbom,
    scanner_version,
)
from ciclosec.scanners.github import checkout_github_repository, list_dependabot_alerts
from ciclosec.scanners.process import ScannerExecutionError
from ciclosec.scans.models import ScanRun
from ciclosec.scans.services import lock_scan_capacity_gate


class ScanAlreadyClaimed(ScannerExecutionError):
    """A scan was already claimed or completed by an earlier delivery."""

    def __init__(self, scan: ScanRun) -> None:
        super().__init__("Only queued scans can be started")
        self.scan = scan


class ScanCapacityExceeded(ScannerExecutionError):
    """The configured global scan capacity is currently occupied."""


def _component_occurrences(scan_run: ScanRun) -> dict[tuple[str, str], list[ComponentOccurrence]]:
    occurrences: dict[tuple[str, str], list[ComponentOccurrence]] = {}
    for occurrence in ComponentOccurrence.objects.filter(
        sbom_document__scan_run=scan_run
    ).select_related("component"):
        key = (occurrence.component.name.casefold(), occurrence.version.casefold())
        occurrences.setdefault(key, []).append(occurrence)
    return occurrences


def _resolve_vulnerability(identifiers: Iterable[str]) -> Vulnerability | None:
    aliases = list(
        VulnerabilityAlias.objects.filter(identifier__in=set(identifiers)).select_related(
            "vulnerability"
        )
    )
    try:
        lock_alias_roots(aliases)
    except MergeConflict as error:
        raise ScannerExecutionError(str(error)) from error
    vulnerability_ids = {root_id(alias.vulnerability) for alias in aliases}
    if len(vulnerability_ids) > 1:
        raise ScannerExecutionError("Scanner vulnerability identifiers conflict with intelligence")
    return aliases[0].vulnerability if aliases else None


def persist_findings(
    scan_run: ScanRun,
    findings: Iterable[NormalizedFinding],
) -> int:
    """Persist scanner findings without raw secret values or complete tool output."""
    if scan_run.status not in {ScanRun.Status.SUCCEEDED, ScanRun.Status.PARTIAL}:
        raise ScannerExecutionError("Findings require a completed or partial scan")
    occurrences = _component_occurrences(scan_run)
    created = 0
    with transaction.atomic():
        for item in findings:
            if item.kind == Finding.Kind.SECRET:
                occurrence = None
                vulnerability = None
            else:
                matches = occurrences.get(
                    (item.package_name.casefold(), item.package_version.casefold()),
                    [],
                )
                occurrence = matches[0] if len(matches) == 1 else None
                vulnerability = _resolve_vulnerability((item.external_id, *item.aliases))
            finding, was_created = Finding.objects.update_or_create(
                scan_run=scan_run,
                fingerprint=item.fingerprint,
                defaults={
                    "asset": scan_run.asset,
                    "component_occurrence": occurrence,
                    "vulnerability": vulnerability,
                    "source": item.source,
                    "kind": item.kind,
                    "external_id": item.external_id,
                    "package_name": item.package_name,
                    "package_version": item.package_version,
                    "severity": item.severity,
                    "title": item.title,
                    "affected_range": item.affected_range,
                    "fixed_version": item.fixed_version,
                    "source_path": item.source_path,
                    "line_number": item.line_number,
                    "evidence": {
                        **item.evidence,
                        **({"aliases": list(dict.fromkeys(item.aliases))} if item.aliases else {}),
                    },
                },
            )
            del finding
            created += int(was_created)
    return created


def _reevaluate_scan_findings(scan_run: ScanRun) -> None:
    if scan_run.status not in {ScanRun.Status.SUCCEEDED, ScanRun.Status.PARTIAL}:
        return
    try:
        reevaluate_findings(scan_run_id=scan_run.pk)
    except CorrelationError as error:
        scan_run.status = ScanRun.Status.PARTIAL
        scan_run.warnings = [*scan_run.warnings, f"Finding correlation unavailable: {error}"]
        _add_diagnostic(scan_run, ScanRun.Diagnostic.CORRELATION_UNAVAILABLE)
        scan_run.save(update_fields=["status", "warnings", "metadata"])


def _dependabot_finding(alert: dict[str, object]) -> NormalizedFinding:
    number = alert.get("number")
    dependency = alert.get("dependency")
    advisory = alert.get("security_advisory")
    if (
        not isinstance(number, int)
        or isinstance(number, bool)
        or not isinstance(dependency, dict)
        or not isinstance(advisory, dict)
    ):
        raise ScannerExecutionError("GitHub returned an invalid Dependabot alert")
    package_data = dependency.get("package")
    if not isinstance(package_data, dict):
        raise ScannerExecutionError("GitHub Dependabot alert has no package identity")
    package_name_value = package_data.get("name")
    ecosystem_value = package_data.get("ecosystem")
    identifier_value = advisory.get("cve_id") or advisory.get("ghsa_id")
    if not isinstance(package_name_value, str) or not package_name_value:
        raise ScannerExecutionError("GitHub Dependabot alert has incomplete advisory data")
    if not isinstance(ecosystem_value, str) or not ecosystem_value:
        raise ScannerExecutionError("GitHub Dependabot alert has incomplete advisory data")
    if not isinstance(identifier_value, str) or not identifier_value:
        raise ScannerExecutionError("GitHub Dependabot alert has incomplete advisory data")
    package_name = package_name_value
    ecosystem = ecosystem_value
    identifier = identifier_value
    summary = advisory.get("summary")
    vulnerability = alert.get("security_vulnerability")
    if not isinstance(vulnerability, dict):
        raise ScannerExecutionError("GitHub Dependabot alert has no vulnerability range")
    version_range = vulnerability.get("vulnerable_version_range")
    if not isinstance(version_range, str):
        raise ScannerExecutionError("GitHub Dependabot alert has an invalid affected range")
    first_patched = vulnerability.get("first_patched_version")
    fixed_version_value = (
        first_patched.get("identifier") if isinstance(first_patched, dict) else None
    )
    fixed_version = fixed_version_value if isinstance(fixed_version_value, str) else ""
    source_path = dependency.get("manifest_path")
    if not isinstance(source_path, str):
        source_path = ""
    external_id = identifier[:255]
    fingerprint = hashlib.sha256(f"github-dependabot:{number}".encode()).hexdigest()
    return NormalizedFinding(
        source="github_dependabot",
        kind=Finding.Kind.VULNERABILITY,
        fingerprint=fingerprint,
        external_id=external_id,
        package_name=package_name[:512],
        package_version="",
        severity=str(vulnerability.get("severity", "UNKNOWN")).upper()[:24],
        title=summary[:1024] if isinstance(summary, str) else external_id,
        affected_range=version_range[:4096],
        fixed_version=fixed_version[:512],
        source_path=source_path[:2048],
        line_number=None,
        evidence={"ecosystem": ecosystem[:128], "alert_number": number},
        aliases=(str(advisory.get("ghsa_id", "")),),
    )


def _add_diagnostic(scan_run: ScanRun, code: ScanRun.Diagnostic) -> None:
    if not isinstance(scan_run.metadata, dict):
        raise ScannerExecutionError("Scan metadata is invalid")
    codes = scan_run.metadata.get("diagnostic_codes", [])
    if not isinstance(codes, list) or any(not isinstance(item, str) for item in codes):
        raise ScannerExecutionError("Scan diagnostic metadata is invalid")
    if code not in codes:
        scan_run.metadata = {**scan_run.metadata, "diagnostic_codes": [*codes, code]}


def _record_failure(scan_run: ScanRun, message: str, code: ScanRun.Diagnostic) -> None:
    scan_run.status = ScanRun.Status.FAILED
    scan_run.finished_at = timezone.now()
    scan_run.error_summary = message[:1000]
    _add_diagnostic(scan_run, code)
    scan_run.save(update_fields=["status", "finished_at", "error_summary", "metadata"])


def _start_scan(scan_run_id: int, *, kind: str, scanner_name: str) -> ScanRun:
    with transaction.atomic():
        scan_run = ScanRun.objects.select_for_update().get(pk=scan_run_id)
        if scan_run.status != ScanRun.Status.QUEUED:
            if scan_run.status in ScanRun.Status.values:
                raise ScanAlreadyClaimed(scan_run)
            raise ScannerExecutionError("Only queued scans can be started")
        asset = Asset.objects.select_for_update().get(pk=scan_run.asset_id)
        scan_run.asset = asset
        if not asset.enabled:
            _record_failure(
                scan_run,
                "Asset is disabled; scan was not started",
                ScanRun.Diagnostic.ASSET_DISABLED,
            )
        elif asset.kind != kind:
            _record_failure(
                scan_run,
                "Asset type does not match the requested scan",
                ScanRun.Diagnostic.ASSET_KIND_MISMATCH,
            )
        else:
            lock_scan_capacity_gate()
            limit = get_effective_config().scanning.execution.max_concurrent_scans
            if ScanRun.objects.filter(status=ScanRun.Status.RUNNING).count() >= limit:
                raise ScanCapacityExceeded("Scan capacity is currently occupied")
            scan_run.scanner_name = scanner_name
            scan_run.status = ScanRun.Status.RUNNING
            scan_run.started_at = timezone.now()
            scan_run.save(update_fields=["scanner_name", "status", "started_at"])
        return scan_run


def _record_repository_source(scan_run: ScanRun, repository: Repository) -> None:
    scan_run.metadata = {
        **scan_run.metadata,
        "repository_source": {
            "provider": repository.provider,
            "owner": repository.owner,
            "repository": repository.repository_name,
            "ref": repository.ref,
        },
    }
    scan_run.save(update_fields=["metadata"])


def _repository_scanners_authorized(scan_run: ScanRun) -> bool:
    if get_effective_config().scanning.execution.allow_repository_scanners_with_network:
        return True
    _record_failure(
        scan_run,
        "Repository scanners with possible network access are not authorized by worker "
        "configuration (scanning.execution.allow_repository_scanners_with_network).",
        ScanRun.Diagnostic.REPOSITORY_SCANNER_NETWORK_NOT_AUTHORIZED,
    )
    return False


def _image_scanning_authorized(scan_run: ScanRun) -> bool:
    docker = get_effective_config().docker
    if docker.enabled and docker.allow_local_daemon:
        return True
    _record_failure(
        scan_run,
        "Local Docker image scanning is disabled by configuration",
        ScanRun.Diagnostic.IMAGE_SCANNING_DISABLED,
    )
    return False


def scan_repository_checkout(scan_run: ScanRun, root: Path) -> ScanRun:
    """Scan an already authorized local repository checkout."""
    if not root.resolve().is_dir():
        raise ScannerExecutionError("Repository checkout directory does not exist")
    scan_run = _start_scan(
        scan_run.pk, kind=Asset.Kind.REPOSITORY, scanner_name="repository-security"
    )
    if scan_run.status != ScanRun.Status.RUNNING:
        return scan_run
    if isinstance(scan_run.metadata, dict) and "scheduled_source" in scan_run.metadata:
        _record_failure(
            scan_run,
            "Scheduled scans require their authorized registered source",
            ScanRun.Diagnostic.SCHEDULED_SOURCE_CHANGED,
        )
        return scan_run
    repository = Repository.objects.filter(asset=scan_run.asset).first()
    if repository is not None:
        _record_repository_source(scan_run, repository)
    return _scan_repository_checkout(scan_run, root, repository)


def _scan_repository_checkout(
    scan_run: ScanRun, root: Path, repository: Repository | None
) -> ScanRun:
    if not _repository_scanners_authorized(scan_run):
        return scan_run
    config = get_effective_config().scanning.execution
    timeout_seconds = config.timeout_seconds
    use_local_databases = config.repository_scanner_use_local_databases

    warnings: list[str] = []
    normalized_findings: list[NormalizedFinding] = []
    source_results: dict[str, dict[str, int | str | None]] = {}
    local_database_status: dict[str, dict[str, object]] = {}
    if use_local_databases:
        local_database_status = inspect_local_scanner_databases(
            osv_cache_directory=(config.repository_scanner_osv_db_cache_directory),
            trivy_cache_directory=(config.repository_scanner_trivy_cache_directory),
        )
        unavailable = [
            name for name, status in local_database_status.items() if not status["available"]
        ]
        if unavailable:
            warnings.append(
                "Local scanner database cache unavailable: "
                + ", ".join(name for name in unavailable)
            )
            _add_diagnostic(
                scan_run,
                ScanRun.Diagnostic.SCANNER_DATABASE_CACHE_UNAVAILABLE,
            )
    if not _repository_scanners_authorized(scan_run):
        return scan_run
    try:
        if use_local_databases:
            sbom_result, sbom = run_trivy_sbom(
                root,
                timeout_seconds=timeout_seconds,
                offline=True,
                cache_directory=config.repository_scanner_trivy_cache_directory,
            )
        else:
            sbom_result, sbom = run_trivy_sbom(root, timeout_seconds=timeout_seconds)
    except (ScannerExecutionError, SBOMValidationError) as error:
        _record_failure(
            scan_run,
            f"Required SBOM scan failed: {error}",
            ScanRun.Diagnostic.REPOSITORY_SBOM_FAILED,
        )
        return scan_run

    try:
        parse_sbom("cyclonedx", sbom)
    except SBOMValidationError as error:
        _record_failure(
            scan_run, f"Generated SBOM failed validation: {error}", ScanRun.Diagnostic.SBOM_INVALID
        )
        return scan_run

    source_results["sbom"] = {"status": "available"}
    for source_key, scanner_name, runner in (
        ("osv_scanner", "OSV-Scanner", run_osv_scanner),
        ("trivy", "Trivy", run_trivy_findings),
    ):
        if not _repository_scanners_authorized(scan_run):
            return scan_run
        try:
            if use_local_databases:
                cache_directory = (
                    config.repository_scanner_osv_db_cache_directory
                    if source_key == "osv_scanner"
                    else config.repository_scanner_trivy_cache_directory
                )
                _result, findings = runner(
                    root,
                    timeout_seconds=timeout_seconds,
                    offline=True,
                    cache_directory=cache_directory,
                )
            else:
                _result, findings = runner(root, timeout_seconds=timeout_seconds)
            normalized_findings.extend(findings)
            source_results[source_key] = {
                "status": "available",
                "finding_count": len(findings),
            }
        except ScannerExecutionError as error:
            warnings.append(f"{scanner_name} scan unavailable: {error}")
            source_results[source_key] = {
                "status": "unavailable",
                "finding_count": None,
            }
            _add_diagnostic(
                scan_run,
                ScanRun.Diagnostic.OSV_UNAVAILABLE
                if source_key == "osv_scanner"
                else ScanRun.Diagnostic.TRIVY_UNAVAILABLE,
            )

    tool_versions: dict[str, str] = {}
    for executable in ("trivy", "osv-scanner"):
        if not _repository_scanners_authorized(scan_run):
            return scan_run
        try:
            tool_versions[executable] = scanner_version(
                executable,
                root,
                timeout_seconds=timeout_seconds,
            )
        except ScannerExecutionError as error:
            warnings.append(f"{executable} version unavailable: {error}")
            _add_diagnostic(
                scan_run,
                ScanRun.Diagnostic.TRIVY_VERSION_UNAVAILABLE
                if executable == "trivy"
                else ScanRun.Diagnostic.OSV_VERSION_UNAVAILABLE,
            )

    if repository is None:
        warnings.append("Dependabot alerts unavailable: repository configuration is missing")
        source_results["github_dependabot"] = {
            "status": "unavailable",
            "finding_count": None,
        }
        _add_diagnostic(scan_run, ScanRun.Diagnostic.DEPENDABOT_UNAVAILABLE)
    else:
        if not _repository_scanners_authorized(scan_run):
            return scan_run
        credential_name = repository.credential_env
        if not credential_name:
            credential_name = settings.CICLOSEC_CONFIG.github.token_env
        try:
            token = resolve_environment_value(credential_name)
            if not _repository_scanners_authorized(scan_run):
                return scan_run
            alerts = list_dependabot_alerts(
                repository.owner,
                repository.repository_name,
                token,
            )
            normalized_findings.extend(_dependabot_finding(alert) for alert in alerts)
            source_results["github_dependabot"] = {
                "status": "available",
                "finding_count": len(alerts),
            }
        except (ScannerExecutionError, ConfigurationError) as error:
            warnings.append(f"Dependabot alerts unavailable: {error}")
            source_results["github_dependabot"] = {
                "status": "unavailable",
                "finding_count": None,
            }
            _add_diagnostic(scan_run, ScanRun.Diagnostic.DEPENDABOT_UNAVAILABLE)

    if use_local_databases:
        warnings.append("Local scanner databases were used; their freshness could not be verified.")
        _add_diagnostic(
            scan_run,
            ScanRun.Diagnostic.SCANNER_DATABASE_FRESHNESS_UNVERIFIED,
        )

    if warnings:
        scan_run.status = ScanRun.Status.PARTIAL
        scan_run.warnings = warnings
    else:
        scan_run.status = ScanRun.Status.SUCCEEDED
    scan_run.finished_at = timezone.now()
    scan_run.scanner_version = "; ".join(
        f"{tool}: {version}" for tool, version in sorted(tool_versions.items())
    )[:128]
    scan_run.metadata = {
        **scan_run.metadata,
        "sbom_scanner": "trivy",
        "sbom_exit_code": sbom_result.returncode,
        "finding_count": len(normalized_findings),
        "secret_findings_redacted": True,
        "tool_versions": tool_versions,
        "source_results": source_results,
        "scanner_database_mode": "local_cache" if use_local_databases else "online",
        "scanner_database_freshness": "unverified" if use_local_databases else "not_recorded",
        "local_database_status": local_database_status,
    }

    try:
        with transaction.atomic():
            if (
                repository is not None
                and not Repository.objects.select_for_update()
                .filter(
                    pk=repository.pk,
                    asset_id=scan_run.asset_id,
                    provider=repository.provider,
                    owner=repository.owner,
                    repository_name=repository.repository_name,
                    ref=repository.ref,
                    credential_env=repository.credential_env,
                )
                .exists()
            ):
                scan_run.status = ScanRun.Status.PARTIAL
                scan_run.metadata["repository_source_changed"] = True
                _add_diagnostic(scan_run, ScanRun.Diagnostic.REPOSITORY_SOURCE_CHANGED)
                scan_run.warnings = [
                    *scan_run.warnings,
                    "Repository source changed during the scan; "
                    "results refer to the original source.",
                ]
            scan_run.save(
                update_fields=[
                    "status",
                    "finished_at",
                    "scanner_version",
                    "warnings",
                    "metadata",
                ]
            )
            ingest_sbom(scan_run, "cyclonedx", sbom)
            persist_findings(scan_run, normalized_findings)
    except SBOMValidationError as error:
        _record_failure(
            scan_run, f"Generated SBOM failed validation: {error}", ScanRun.Diagnostic.SBOM_INVALID
        )
    _reevaluate_scan_findings(scan_run)
    return scan_run


def scan_registered_repository(scan_run_id: int) -> ScanRun:
    """Download a configured GitHub snapshot and scan it in a temporary directory."""
    scan_run = _start_scan(
        scan_run_id, kind=Asset.Kind.REPOSITORY, scanner_name="repository-security"
    )
    if scan_run.status != ScanRun.Status.RUNNING:
        return scan_run
    try:
        repository = Repository.objects.get(asset=scan_run.asset)
    except Repository.DoesNotExist:
        _record_failure(
            scan_run,
            "Repository asset has no GitHub source configuration",
            ScanRun.Diagnostic.REPOSITORY_MISSING,
        )
        return scan_run
    if isinstance(scan_run.metadata, dict) and "scheduled_source" in scan_run.metadata:
        from ciclosec.scans.scheduling import repository_snapshot

        if scan_run.metadata["scheduled_source"] != repository_snapshot(repository):
            _record_failure(
                scan_run,
                "Scheduled repository source changed before execution",
                ScanRun.Diagnostic.SCHEDULED_SOURCE_CHANGED,
            )
            return scan_run
    _record_repository_source(scan_run, repository)
    if not _repository_scanners_authorized(scan_run):
        return scan_run
    credential_name = repository.credential_env
    if not credential_name:
        credential_name = settings.CICLOSEC_CONFIG.github.token_env
    try:
        token = resolve_environment_value(credential_name)
    except ConfigurationError as error:
        _record_failure(scan_run, str(error), ScanRun.Diagnostic.CREDENTIAL_MISSING)
        return scan_run

    with tempfile.TemporaryDirectory(prefix="ciclosec-scan-") as directory:
        root = Path(directory)
        if not _repository_scanners_authorized(scan_run):
            return scan_run
        try:
            checkout = checkout_github_repository(
                repository.owner,
                repository.repository_name,
                repository.ref,
                token,
                root,
            )
        except ScannerExecutionError as error:
            _record_failure(
                scan_run,
                f"Repository checkout failed: {error}",
                ScanRun.Diagnostic.REPOSITORY_CHECKOUT_FAILED,
            )
            return scan_run
        return _scan_repository_checkout(scan_run, checkout, repository)


def scan_registered_container_image(scan_run_id: int) -> ScanRun:
    """Scan an allowlisted image already present in the local Docker daemon."""
    scan_run = _start_scan(
        scan_run_id, kind=Asset.Kind.CONTAINER_IMAGE, scanner_name="container-image-security"
    )
    if scan_run.status != ScanRun.Status.RUNNING:
        return scan_run

    docker_config = get_effective_config().docker
    if not docker_config.enabled or not docker_config.allow_local_daemon:
        _record_failure(
            scan_run,
            "Local Docker image scanning is disabled by configuration",
            ScanRun.Diagnostic.IMAGE_SCANNING_DISABLED,
        )
        return scan_run
    try:
        container_image = ContainerImage.objects.get(asset=scan_run.asset)
    except ContainerImage.DoesNotExist:
        _record_failure(
            scan_run,
            "Container image has no configured image reference",
            ScanRun.Diagnostic.IMAGE_SOURCE_MISSING,
        )
        return scan_run
    if isinstance(scan_run.metadata, dict) and "scheduled_source" in scan_run.metadata:
        from ciclosec.scans.scheduling import image_snapshot

        if scan_run.metadata["scheduled_source"] != image_snapshot(container_image):
            _record_failure(
                scan_run,
                "Scheduled image source changed before execution",
                ScanRun.Diagnostic.SCHEDULED_SOURCE_CHANGED,
            )
            return scan_run
    allowed_references = {image.reference for image in docker_config.images}
    if container_image.image_reference not in allowed_references:
        _record_failure(
            scan_run,
            "Container image reference is not allowlisted",
            ScanRun.Diagnostic.IMAGE_NOT_ALLOWLISTED,
        )
        return scan_run

    timeout_seconds = get_effective_config().scanning.execution.timeout_seconds
    try:
        with tempfile.TemporaryDirectory(prefix="ciclosec-image-scan-") as directory:
            scan_root = Path(directory)
            if not _image_scanning_authorized(scan_run):
                return scan_run
            image_id = resolve_local_docker_image(
                container_image.image_reference,
                scan_root,
                timeout_seconds=timeout_seconds,
            )
            cache_dir = scan_root / "trivy-cache"
            if not _image_scanning_authorized(scan_run):
                return scan_run
            sbom_result, sbom = run_trivy_image_sbom(
                image_id,
                scan_root,
                cache_dir,
                timeout_seconds=timeout_seconds,
            )

            warnings: list[str] = []
            normalized_findings: tuple[NormalizedFinding, ...] = ()
            if not _image_scanning_authorized(scan_run):
                return scan_run
            try:
                _result, normalized_findings = run_trivy_image_findings(
                    image_id,
                    scan_root,
                    cache_dir,
                    timeout_seconds=timeout_seconds,
                )
            except ScannerExecutionError as error:
                warnings.append(f"Trivy image findings unavailable: {error}")
                _add_diagnostic(scan_run, ScanRun.Diagnostic.IMAGE_FINDINGS_UNAVAILABLE)

            tool_versions: dict[str, str] = {}
            try:
                tool_versions["trivy"] = scanner_version(
                    "trivy",
                    scan_root,
                    timeout_seconds=timeout_seconds,
                )
            except ScannerExecutionError as error:
                warnings.append(f"Trivy version unavailable: {error}")
                _add_diagnostic(scan_run, ScanRun.Diagnostic.TRIVY_VERSION_UNAVAILABLE)
    except (ScannerExecutionError, SBOMValidationError) as error:
        _record_failure(
            scan_run,
            f"Required local image SBOM scan failed: {error}",
            ScanRun.Diagnostic.IMAGE_SBOM_FAILED,
        )
        return scan_run

    scan_run.status = ScanRun.Status.PARTIAL if warnings else ScanRun.Status.SUCCEEDED
    scan_run.finished_at = timezone.now()
    scan_run.scanner_version = "; ".join(
        f"{tool}: {version}" for tool, version in sorted(tool_versions.items())
    )[:128]
    scan_run.warnings = warnings
    scan_run.metadata = {
        **scan_run.metadata,
        "image_reference": container_image.image_reference,
        "image_source_revision": container_image.source_revision,
        "image_digest": image_id,
        "image_source": "docker",
        "sbom_scanner": "trivy",
        "sbom_exit_code": sbom_result.returncode,
        "finding_count": len(normalized_findings),
        "secret_findings_redacted": True,
        "tool_versions": tool_versions,
    }

    try:
        with transaction.atomic():
            scan_run.save(
                update_fields=[
                    "status",
                    "finished_at",
                    "scanner_version",
                    "warnings",
                    "metadata",
                ]
            )
            ingest_sbom(scan_run, "cyclonedx", sbom)
            persist_findings(scan_run, normalized_findings)
            updated = ContainerImage.objects.filter(
                pk=container_image.pk,
                asset_id=scan_run.asset_id,
                image_reference=container_image.image_reference,
                source_revision=container_image.source_revision,
            ).update(resolved_digest=image_id, digest_resolved_at=scan_run.finished_at)
            if not updated:
                scan_run.status = ScanRun.Status.PARTIAL
                _add_diagnostic(scan_run, ScanRun.Diagnostic.IMAGE_SOURCE_CHANGED)
                scan_run.warnings = [
                    *scan_run.warnings,
                    "Image source changed during the scan; its digest was not updated.",
                ]
                scan_run.save(update_fields=["status", "warnings", "metadata"])
    except SBOMValidationError as error:
        _record_failure(
            scan_run,
            f"Generated image SBOM failed validation: {error}",
            ScanRun.Diagnostic.SBOM_INVALID,
        )
    _reevaluate_scan_findings(scan_run)
    return scan_run
