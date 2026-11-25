"""Trivy and OSV-Scanner invocations and normalized output parsing."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ciclosec.scanners.process import ProcessResult, ScannerExecutionError, run_process

DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024
SCANNER_EXIT_CODES = frozenset({0, 1})
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
IMAGE_ID_PATTERN = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")


@dataclass(frozen=True)
class NormalizedFinding:
    """Redacted, normalized scanner finding."""

    source: str
    kind: str
    fingerprint: str
    external_id: str
    package_name: str
    package_version: str
    severity: str
    title: str
    affected_range: str
    fixed_version: str
    source_path: str
    line_number: int | None
    evidence: dict[str, Any]
    aliases: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScanOutput:
    """All scanner outputs needed to persist one source scan."""

    sbom: dict[str, Any]
    findings: tuple[NormalizedFinding, ...]
    tool_versions: dict[str, str]
    warnings: tuple[str, ...]


def _decode_json(payload: bytes, *, scanner: str) -> dict[str, Any]:
    try:
        result = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ScannerExecutionError(f"{scanner} returned invalid JSON") from None
    if not isinstance(result, dict):
        raise ScannerExecutionError(f"{scanner} returned an invalid JSON document")
    return result


def _text(value: object, *, limit: int = 1024) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\x00", "")[:limit]


def _relative_path(value: object, root: Path) -> str:
    path_text = _text(value, limit=4096)
    if not path_text:
        return ""
    path = Path(path_text)
    try:
        resolved = (root / path).resolve() if not path.is_absolute() else path.resolve()
        return resolved.relative_to(root.resolve()).as_posix()[:2048]
    except (OSError, ValueError):
        return ""


def _safe_line(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    return None


def _severity(value: object) -> str:
    candidate = _text(value, limit=24).upper()
    return candidate if candidate in SEVERITIES else "UNKNOWN"


def _fingerprint(
    source: str,
    kind: str,
    external_id: str,
    package_name: str,
    package_version: str,
    source_path: str,
    line_number: int | None,
) -> str:
    identity = "\0".join(
        [
            source,
            kind,
            external_id,
            package_name,
            package_version,
            source_path,
            str(line_number or ""),
        ]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def _affected_ranges(vulnerability: Mapping[str, Any]) -> str:
    ranges: list[str] = []
    affected = vulnerability.get("affected", [])
    if not isinstance(affected, list):
        return ""
    for package in affected:
        if not isinstance(package, dict):
            continue
        ecosystem = (
            _text(package.get("package", {}).get("ecosystem"), limit=128)
            if isinstance(package.get("package"), dict)
            else ""
        )
        versions = package.get("versions", [])
        if isinstance(versions, list):
            for version in versions:
                text = _text(version, limit=256)
                if text:
                    ranges.append(f"{ecosystem}: {text}" if ecosystem else text)
        package_ranges = package.get("ranges", [])
        if not isinstance(package_ranges, list):
            continue
        for affected_range in package_ranges:
            if not isinstance(affected_range, dict):
                continue
            range_type = _text(affected_range.get("type"), limit=32)
            events = affected_range.get("events", [])
            if not isinstance(events, list):
                continue
            for event in events:
                if not isinstance(event, dict):
                    continue
                for event_name in ("introduced", "fixed", "last_affected", "limit"):
                    version = _text(event.get(event_name), limit=128)
                    if version:
                        prefix = f"{range_type} " if range_type else ""
                        ranges.append(f"{ecosystem}: {prefix}{event_name} {version}".strip())
    return "; ".join(dict.fromkeys(ranges))[:4096]


def _fixed_version(vulnerability: Mapping[str, Any]) -> str:
    affected = vulnerability.get("affected", [])
    if not isinstance(affected, list):
        return ""
    for package in affected:
        if not isinstance(package, dict):
            continue
        ranges = package.get("ranges", [])
        if not isinstance(ranges, list):
            continue
        for affected_range in ranges:
            if not isinstance(affected_range, dict):
                continue
            events = affected_range.get("events", [])
            if not isinstance(events, list):
                continue
            for event in events:
                if isinstance(event, dict) and isinstance(event.get("fixed"), str):
                    return _text(event["fixed"], limit=512)
    return ""


def parse_osv_output(payload: bytes, root: Path) -> tuple[NormalizedFinding, ...]:
    """Parse OSV-Scanner JSON without persisting advisory or source-code dumps."""
    document = _decode_json(payload, scanner="OSV-Scanner")
    results = document.get("results", [])
    if not isinstance(results, list):
        raise ScannerExecutionError("OSV-Scanner result list is invalid")
    findings: dict[str, NormalizedFinding] = {}
    for result in results:
        if not isinstance(result, dict):
            raise ScannerExecutionError("OSV-Scanner returned an invalid source result")
        source_data = result.get("source", {})
        source_path = _relative_path(
            source_data.get("path") if isinstance(source_data, dict) else "",
            root,
        )
        packages = result.get("packages", [])
        if not isinstance(packages, list):
            raise ScannerExecutionError("OSV-Scanner returned an invalid package list")
        for package_entry in packages:
            if not isinstance(package_entry, dict):
                raise ScannerExecutionError("OSV-Scanner returned an invalid package record")
            package = package_entry.get("package", {})
            if not isinstance(package, dict):
                raise ScannerExecutionError("OSV-Scanner returned an invalid package identity")
            package_name = _text(package.get("name"), limit=512)
            package_version = _text(package.get("version"), limit=512)
            ecosystem = _text(package.get("ecosystem"), limit=128)
            vulnerabilities = package_entry.get("vulnerabilities", [])
            if not isinstance(vulnerabilities, list):
                raise ScannerExecutionError("OSV-Scanner returned an invalid vulnerability list")
            for vulnerability in vulnerabilities:
                if not isinstance(vulnerability, dict):
                    raise ScannerExecutionError("OSV-Scanner returned an invalid vulnerability")
                external_id = _text(vulnerability.get("id"), limit=255)
                if not external_id:
                    raise ScannerExecutionError("OSV-Scanner finding has no vulnerability ID")
                aliases_value = vulnerability.get("aliases", [])
                if not isinstance(aliases_value, list):
                    aliases_value = []
                aliases = tuple(
                    dict.fromkeys(
                        alias[:255]
                        for alias in aliases_value
                        if isinstance(alias, str) and alias and len(alias) <= 255
                    )
                )
                summary = _text(vulnerability.get("summary"), limit=1024)
                details = _text(vulnerability.get("details"), limit=2048)
                fixed_version = _fixed_version(vulnerability)
                fingerprint = _fingerprint(
                    "osv_scanner",
                    "vulnerability",
                    external_id,
                    package_name,
                    package_version,
                    source_path,
                    None,
                )
                findings[fingerprint] = NormalizedFinding(
                    source="osv_scanner",
                    kind="vulnerability",
                    fingerprint=fingerprint,
                    external_id=external_id,
                    package_name=package_name,
                    package_version=package_version,
                    severity="UNKNOWN",
                    title=summary or external_id,
                    affected_range=_affected_ranges(vulnerability),
                    fixed_version=fixed_version,
                    source_path=source_path,
                    line_number=None,
                    evidence={
                        "ecosystem": ecosystem,
                        "source_type": _text(
                            source_data.get("type") if isinstance(source_data, dict) else "",
                            limit=32,
                        ),
                        "details": details,
                    },
                    aliases=aliases,
                )
    return tuple(findings.values())


def parse_trivy_output(payload: bytes, root: Path) -> tuple[NormalizedFinding, ...]:
    """Parse Trivy vulnerability and secret output while dropping all matched text."""
    document = _decode_json(payload, scanner="Trivy")
    results = document.get("Results", [])
    if results is None:
        results = []
    if not isinstance(results, list):
        raise ScannerExecutionError("Trivy result list is invalid")
    findings: dict[str, NormalizedFinding] = {}
    for result in results:
        if not isinstance(result, dict):
            raise ScannerExecutionError("Trivy returned an invalid target result")
        source_path = _relative_path(result.get("Target"), root)
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise ScannerExecutionError("Trivy returned an invalid vulnerability list")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ScannerExecutionError("Trivy returned an invalid vulnerability")
            external_id = _text(vulnerability.get("VulnerabilityID"), limit=255)
            if not external_id:
                raise ScannerExecutionError("Trivy finding has no vulnerability ID")
            package_name = _text(vulnerability.get("PkgName"), limit=512)
            package_version = _text(vulnerability.get("InstalledVersion"), limit=512)
            fixed_version = _text(vulnerability.get("FixedVersion"), limit=512)
            title = _text(vulnerability.get("Title"), limit=1024) or external_id
            purl_data = vulnerability.get("PkgIdentifier", {})
            purl = _text(purl_data.get("PURL"), limit=2048) if isinstance(purl_data, dict) else ""
            fingerprint = _fingerprint(
                "trivy",
                "vulnerability",
                external_id,
                package_name,
                package_version,
                source_path,
                None,
            )
            findings[fingerprint] = NormalizedFinding(
                source="trivy",
                kind="vulnerability",
                fingerprint=fingerprint,
                external_id=external_id,
                package_name=package_name,
                package_version=package_version,
                severity=_severity(vulnerability.get("Severity")),
                title=title,
                affected_range="",
                fixed_version=fixed_version,
                source_path=source_path,
                line_number=None,
                evidence={"package_url": purl},
            )

        secrets = result.get("Secrets")
        if secrets is None:
            secrets = []
        if not isinstance(secrets, list):
            raise ScannerExecutionError("Trivy returned an invalid secret finding list")
        for secret in secrets:
            if not isinstance(secret, dict):
                raise ScannerExecutionError("Trivy returned an invalid secret finding")
            rule_id = _text(secret.get("RuleID"), limit=255)
            title = _text(secret.get("Title"), limit=1024) or rule_id
            line_number = _safe_line(secret.get("StartLine"))
            fingerprint = _fingerprint(
                "trivy",
                "secret",
                rule_id,
                "",
                "",
                source_path,
                line_number,
            )
            findings[fingerprint] = NormalizedFinding(
                source="trivy",
                kind="secret",
                fingerprint=fingerprint,
                external_id=rule_id,
                package_name="",
                package_version="",
                severity=_severity(secret.get("Severity")),
                title=title,
                affected_range="",
                fixed_version="",
                source_path=source_path,
                line_number=line_number,
                evidence={"rule_id": rule_id},
            )
    return tuple(findings.values())


def _normalize_image_id(value: object) -> str:
    image_id = _text(value, limit=128)
    match = IMAGE_ID_PATTERN.fullmatch(image_id)
    if match is None:
        raise ScannerExecutionError("Docker returned an invalid local image ID")
    return f"sha256:{match.group(1).lower()}"


def validate_local_image_reference(image_reference: str) -> None:
    """Reject references that cannot safely be passed to Docker."""
    if (
        not image_reference
        or image_reference.startswith("-")
        or any(character.isspace() or ord(character) < 32 for character in image_reference)
    ):
        raise ScannerExecutionError("Docker image reference is invalid")


def resolve_local_docker_image(
    image_reference: str,
    root: Path,
    *,
    timeout_seconds: int,
) -> str:
    """Resolve a local Docker reference to its immutable image config digest."""
    validate_local_image_reference(image_reference)
    result = run_process(
        [
            "docker",
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image_reference,
        ],
        cwd=root.resolve(),
        timeout_seconds=timeout_seconds,
        max_output_bytes=1024,
    )
    try:
        output = result.stdout.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise ScannerExecutionError("Docker returned an invalid local image ID") from None
    return _normalize_image_id(output)


def parse_trivy_image_output(
    payload: bytes,
    root: Path,
    expected_image_id: str,
) -> tuple[NormalizedFinding, ...]:
    """Parse Trivy findings only when its report identifies the resolved image."""
    document = _decode_json(payload, scanner="Trivy image scan")
    metadata = document.get("Metadata")
    if not isinstance(metadata, dict):
        raise ScannerExecutionError("Trivy image result has no image metadata")
    actual_image_id = _normalize_image_id(metadata.get("ImageID"))
    if actual_image_id != _normalize_image_id(expected_image_id):
        raise ScannerExecutionError("Trivy scanned a different image than the resolved local image")
    return parse_trivy_output(payload, root)


def run_trivy_image_sbom(
    image_id: str,
    root: Path,
    cache_dir: Path,
    *,
    timeout_seconds: int,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[ProcessResult, dict[str, Any]]:
    """Generate a CycloneDX SBOM from an image available in the local Docker daemon."""
    resolved_image_id = _normalize_image_id(image_id)
    result = run_process(
        [
            "trivy",
            "image",
            "--image-src",
            "docker",
            "--cache-dir",
            str(cache_dir.resolve()),
            "--format",
            "cyclonedx",
            resolved_image_id,
        ],
        cwd=root.resolve(),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        allowed_exit_codes=SCANNER_EXIT_CODES,
    )
    return result, _decode_json(result.stdout, scanner="Trivy image SBOM")


def run_trivy_image_findings(
    image_id: str,
    root: Path,
    cache_dir: Path,
    *,
    timeout_seconds: int,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[ProcessResult, tuple[NormalizedFinding, ...]]:
    """Scan only the local Docker source and verify the resulting image identity."""
    resolved_image_id = _normalize_image_id(image_id)
    result = run_process(
        [
            "trivy",
            "image",
            "--image-src",
            "docker",
            "--cache-dir",
            str(cache_dir.resolve()),
            "--format",
            "json",
            "--scanners",
            "vuln,secret",
            resolved_image_id,
        ],
        cwd=root.resolve(),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        allowed_exit_codes=SCANNER_EXIT_CODES,
    )
    return result, parse_trivy_image_output(result.stdout, root.resolve(), resolved_image_id)


def run_osv_scanner(
    root: Path,
    *,
    timeout_seconds: int,
    offline: bool = False,
    cache_directory: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[ProcessResult, tuple[NormalizedFinding, ...]]:
    """Run OSV-Scanner in read-only source scan mode."""
    resolved_root = root.resolve()
    arguments = ["osv-scanner"]
    if offline:
        arguments.append("--offline")
    arguments.extend(
        [
            "scan",
            "source",
            "--recursive",
            "--format",
            "json",
            str(resolved_root),
        ]
    )
    result = run_process(
        arguments,
        cwd=resolved_root,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        allowed_exit_codes=SCANNER_EXIT_CODES,
        environment=(
            {"OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY": str(cache_directory)}
            if offline and cache_directory
            else None
        ),
    )
    return result, parse_osv_output(result.stdout, resolved_root)


def run_trivy_sbom(
    root: Path,
    *,
    timeout_seconds: int,
    offline: bool = False,
    cache_directory: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[ProcessResult, dict[str, Any]]:
    """Generate a CycloneDX SBOM from a local filesystem target."""
    resolved_root = root.resolve()
    arguments = ["trivy", "fs", "--format", "cyclonedx", "--include-dev-deps"]
    if offline:
        arguments.extend(_trivy_local_database_flags())
        if cache_directory:
            arguments.extend(["--cache-dir", str(cache_directory)])
    arguments.append(str(resolved_root))
    result = run_process(
        arguments,
        cwd=resolved_root,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        allowed_exit_codes=SCANNER_EXIT_CODES,
    )
    return result, _decode_json(result.stdout, scanner="Trivy SBOM")


def run_trivy_findings(
    root: Path,
    *,
    timeout_seconds: int,
    offline: bool = False,
    cache_directory: str | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> tuple[ProcessResult, tuple[NormalizedFinding, ...]]:
    """Run Trivy vulnerability and secret scanners on a local checkout."""
    resolved_root = root.resolve()
    arguments = ["trivy", "fs", "--format", "json", "--scanners", "vuln,secret"]
    if offline:
        arguments.extend(_trivy_local_database_flags())
        if cache_directory:
            arguments.extend(["--cache-dir", str(cache_directory)])
    arguments.append(str(resolved_root))
    result = run_process(
        arguments,
        cwd=resolved_root,
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        allowed_exit_codes=SCANNER_EXIT_CODES,
    )
    return result, parse_trivy_output(result.stdout, resolved_root)


def _trivy_local_database_flags() -> list[str]:
    return [
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--skip-version-check",
        "--disable-telemetry",
    ]


def inspect_local_scanner_databases(
    *,
    osv_cache_directory: str | None,
    trivy_cache_directory: str | None,
) -> dict[str, dict[str, object]]:
    """Report preloaded local database presence without downloading or updating."""
    result: dict[str, dict[str, object]] = {}

    if osv_cache_directory:
        cache = Path(osv_cache_directory).expanduser()
        osv_db = cache / "osv-scalibr"
        zip_count = (
            sum(1 for path in osv_db.rglob("*.zip") if path.is_file()) if osv_db.is_dir() else 0
        )
        result["osv_scanner"] = {
            "configured": True,
            "available": zip_count > 0,
            "cache_directory": str(cache),
            "ecosystem_archive_count": zip_count,
        }
    else:
        result["osv_scanner"] = {
            "configured": False,
            "available": False,
            "cache_directory": None,
            "ecosystem_archive_count": 0,
        }

    if trivy_cache_directory:
        cache = Path(trivy_cache_directory).expanduser()
        trivy_db = cache / "db" / "trivy.db"
        java_db = cache / "java-db" / "trivy-java.db"
        result["trivy"] = {
            "configured": True,
            "available": trivy_db.is_file(),
            "cache_directory": str(cache),
            "vulnerability_db": trivy_db.is_file(),
            "java_db": java_db.is_file(),
        }
    else:
        result["trivy"] = {
            "configured": False,
            "available": False,
            "cache_directory": None,
            "vulnerability_db": False,
            "java_db": False,
        }

    return result


def scanner_version(
    executable: str,
    root: Path,
    *,
    timeout_seconds: int,
    max_output_bytes: int = 4096,
) -> str:
    """Read one scanner version line without inheriting application secrets."""
    result = run_process(
        [executable, "--version"],
        cwd=root.resolve(),
        timeout_seconds=min(timeout_seconds, 30),
        max_output_bytes=max_output_bytes,
    )
    try:
        output = result.stdout.decode("utf-8")
    except UnicodeDecodeError:
        raise ScannerExecutionError(f"{executable} returned an invalid version response") from None
    version = next((line.strip() for line in output.splitlines() if line.strip()), "")
    if not version:
        raise ScannerExecutionError(f"{executable} returned an empty version")
    return version[:255]
