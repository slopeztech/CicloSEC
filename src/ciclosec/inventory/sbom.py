"""Validated CycloneDX/SPDX JSON import, normalization, storage, and export."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import defaultdict, deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonValidator
from django.db import transaction
from django.utils import timezone
from packageurl import PackageURL
from spdx_tools.spdx.model.actor import Actor, ActorType
from spdx_tools.spdx.model.document import CreationInfo, Document
from spdx_tools.spdx.model.package import (
    ExternalPackageRef,
    ExternalPackageRefCategory,
    Package,
)
from spdx_tools.spdx.model.relationship import Relationship, RelationshipType
from spdx_tools.spdx.model.spdx_no_assertion import SpdxNoAssertion
from spdx_tools.spdx.parser.error import SPDXParsingError
from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document
from spdx_tools.spdx.writer.write_anything import write_file

from ciclosec.inventory.models import (
    Component,
    ComponentDependency,
    ComponentOccurrence,
    SBOMDocument,
)
from ciclosec.scans.models import ScanRun

MAX_SBOM_SIZE_BYTES = 10 * 1024 * 1024
MAX_SBOM_COMPONENTS = 100_000
CYCLONEDX_SCHEMA_VERSIONS = {
    "1.0": SchemaVersion.V1_0,
    "1.1": SchemaVersion.V1_1,
    "1.2": SchemaVersion.V1_2,
    "1.3": SchemaVersion.V1_3,
    "1.4": SchemaVersion.V1_4,
    "1.5": SchemaVersion.V1_5,
    "1.6": SchemaVersion.V1_6,
    "1.7": SchemaVersion.V1_7,
}


class SBOMValidationError(ValueError):
    """Raised when an SBOM is invalid, unsupported, or exceeds limits."""


@dataclass(frozen=True)
class NormalizedComponent:
    """Package information normalized from one SBOM component entry."""

    bom_ref: str
    name: str
    version: str
    purl: str | None
    ecosystem: str
    component_type: str
    relationship: str
    scope: str
    path: str


@dataclass(frozen=True)
class ParsedSBOM:
    """Validated SBOM payload with normalized package and dependency data."""

    format: str
    format_version: str
    generated_at: datetime
    payload: dict[str, Any]
    components: tuple[NormalizedComponent, ...]
    root_component_refs: tuple[str, ...]
    dependencies: tuple[tuple[str, str], ...]


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SBOMValidationError("SBOM JSON contains a duplicate object key.")
        result[key] = value
    return result


def _canonicalize_payload(payload: str | bytes | Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise SBOMValidationError("SBOM JSON must be UTF-8 encoded.") from None

    if isinstance(payload, str):
        if len(payload.encode("utf-8")) > MAX_SBOM_SIZE_BYTES:
            raise SBOMValidationError("SBOM exceeds the maximum permitted size.")
        try:
            parsed = json.loads(payload, object_pairs_hook=_reject_duplicate_keys)
        except SBOMValidationError:
            raise
        except json.JSONDecodeError:
            raise SBOMValidationError("SBOM does not contain valid JSON.") from None
    elif isinstance(payload, Mapping):
        parsed = dict(payload)
    else:
        raise SBOMValidationError("SBOM payload must be a JSON object or UTF-8 JSON text.")

    if not isinstance(parsed, dict):
        raise SBOMValidationError("SBOM JSON root must be an object.")
    try:
        canonical_text = json.dumps(
            parsed,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError):
        raise SBOMValidationError("SBOM payload cannot be represented as valid JSON.") from None
    if len(canonical_text.encode("utf-8")) > MAX_SBOM_SIZE_BYTES:
        raise SBOMValidationError("SBOM exceeds the maximum permitted size.")
    return canonical_text, parsed


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return timezone.now()
        if timezone.is_naive(parsed):
            return timezone.make_aware(parsed, timezone=UTC)
        return parsed
    if isinstance(value, datetime):
        if timezone.is_naive(value):
            return timezone.make_aware(value, timezone=UTC)
        return value
    return timezone.now()


def _normalize_purl(value: Any) -> tuple[str | None, str]:
    if value is None:
        return None, "unknown"
    if not isinstance(value, str):
        raise SBOMValidationError("SBOM component package URL must be a string.")
    try:
        package_url = PackageURL.from_string(value)
    except ValueError:
        raise SBOMValidationError("SBOM contains an invalid package URL.") from None
    return package_url.to_string(), package_url.type


def _classify_components(
    components: list[dict[str, Any]],
    root_refs: set[str],
    dependencies: set[tuple[str, str]],
) -> tuple[NormalizedComponent, ...]:
    refs: set[str] = set()
    parsed_components: list[NormalizedComponent] = []
    for index, item in enumerate(components):
        name = item.get("name")
        if not isinstance(name, str) or not name.strip():
            raise SBOMValidationError("SBOM component is missing a valid name.")
        bom_ref = item.get("bom-ref") or item.get("SPDXID") or f"ciclosec-component-{index + 1}"
        if not isinstance(bom_ref, str) or not bom_ref:
            raise SBOMValidationError("SBOM component reference must be a non-empty string.")
        if bom_ref in refs:
            raise SBOMValidationError("SBOM contains duplicate component references.")
        refs.add(bom_ref)

        purl, ecosystem = _normalize_purl(item.get("purl"))
        parsed_components.append(
            NormalizedComponent(
                bom_ref=bom_ref,
                name=name.strip(),
                version=str(item.get("version") or ""),
                purl=purl,
                ecosystem=ecosystem,
                component_type=str(item.get("type") or item.get("primary_package_purpose") or ""),
                relationship=ComponentOccurrence.Relationship.UNKNOWN,
                scope=str(item.get("scope") or ""),
                path=str(item.get("path") or ""),
            )
        )

    if len(parsed_components) > MAX_SBOM_COMPONENTS:
        raise SBOMValidationError("SBOM exceeds the maximum permitted component count.")
    if not root_refs.issubset(refs):
        raise SBOMValidationError("SBOM root dependency references an unknown component.")
    for source_ref, target_ref in dependencies:
        if source_ref not in refs or target_ref not in refs:
            raise SBOMValidationError("SBOM dependency references an unknown component.")

    edges: dict[str, set[str]] = defaultdict(set)
    for source_ref, target_ref in dependencies:
        edges[source_ref].add(target_ref)
    directly_referenced = root_refs
    visited = set(directly_referenced)
    pending = deque(directly_referenced)
    while pending:
        current = pending.popleft()
        for target in edges[current]:
            if target not in visited:
                visited.add(target)
                pending.append(target)
    transitive_refs = visited - directly_referenced

    return tuple(
        NormalizedComponent(
            bom_ref=component.bom_ref,
            name=component.name,
            version=component.version,
            purl=component.purl,
            ecosystem=component.ecosystem,
            component_type=component.component_type,
            relationship=(
                ComponentOccurrence.Relationship.DIRECT
                if component.bom_ref in directly_referenced
                else ComponentOccurrence.Relationship.TRANSITIVE
                if component.bom_ref in transitive_refs
                else ComponentOccurrence.Relationship.UNKNOWN
            ),
            scope=component.scope,
            path=component.path,
        )
        for component in parsed_components
    )


def _parse_cyclonedx(
    canonical_text: str,
    payload: dict[str, Any],
) -> ParsedSBOM:
    if payload.get("bomFormat") != "CycloneDX":
        raise SBOMValidationError("SBOM format marker is not CycloneDX.")
    spec_version = payload.get("specVersion")
    schema_version = CYCLONEDX_SCHEMA_VERSIONS.get(str(spec_version))
    if schema_version is None:
        raise SBOMValidationError("CycloneDX specification version is not supported.")
    validation_error = JsonValidator(schema_version).validate_str(canonical_text)
    if validation_error is not None:
        raise SBOMValidationError("CycloneDX document does not conform to its JSON schema.")

    raw_components: list[dict[str, Any]] = []

    def collect_components(items: Any) -> None:
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                raise SBOMValidationError("CycloneDX component entry must be an object.")
            if item.get("type") not in {"file", "data"}:
                raw_components.append(item)
            collect_components(item.get("components", []))

    collect_components(payload.get("components", []))

    metadata = payload.get("metadata")
    root_component = metadata.get("component") if isinstance(metadata, dict) else None
    root_ref = root_component.get("bom-ref") if isinstance(root_component, dict) else None
    graph: dict[str, list[str]] = {}
    raw_dependencies = payload.get("dependencies", [])
    if isinstance(raw_dependencies, list):
        for dependency in raw_dependencies:
            if not isinstance(dependency, dict):
                raise SBOMValidationError("CycloneDX dependency entry must be an object.")
            source = dependency.get("ref")
            targets = dependency.get("dependsOn", [])
            if not isinstance(source, str) or not isinstance(targets, list):
                raise SBOMValidationError("CycloneDX dependency graph is malformed.")
            if not all(isinstance(target, str) for target in targets):
                raise SBOMValidationError("CycloneDX dependency target must be a string.")
            graph[source] = targets

    component_refs = {
        str(item.get("bom-ref")) for item in raw_components if isinstance(item.get("bom-ref"), str)
    }
    if root_ref is None:
        root_refs_raw = [
            target
            for source, targets in graph.items()
            if source not in component_refs
            for target in targets
        ]
    else:
        root_refs_raw = graph.get(root_ref, [])
    root_refs = set(root_refs_raw)
    if not root_refs.issubset(component_refs):
        raise SBOMValidationError("CycloneDX root dependency references an unknown component.")
    edges = {
        (source, target)
        for source, targets in graph.items()
        if source in component_refs
        for target in targets
    }
    parsed_components = _classify_components(raw_components, root_refs, edges)
    timestamp = metadata.get("timestamp") if isinstance(metadata, dict) else None
    return ParsedSBOM(
        format=SBOMDocument.Format.CYCLONEDX,
        format_version=str(spec_version),
        generated_at=_parse_timestamp(timestamp),
        payload=payload,
        components=parsed_components,
        root_component_refs=tuple(sorted(root_refs)),
        dependencies=tuple(sorted(edges)),
    )


def _spdx_package_purl(package: Package) -> str | None:
    purls = [
        external_ref.locator
        for external_ref in package.external_references
        if external_ref.reference_type.lower() == "purl"
        and external_ref.category == ExternalPackageRefCategory.PACKAGE_MANAGER
    ]
    if len(set(purls)) > 1:
        raise SBOMValidationError("SPDX package contains conflicting package URLs.")
    return purls[0] if purls else None


def _parse_spdx(canonical_text: str) -> ParsedSBOM:
    with TemporaryDirectory(prefix="ciclosec-sbom-") as directory:
        filename = Path(directory) / "document.spdx.json"
        filename.write_text(canonical_text, encoding="utf-8")
        try:
            document = parse_file(str(filename))
        except (SPDXParsingError, OSError, UnicodeDecodeError, ValueError):
            raise SBOMValidationError("SPDX document could not be parsed.") from None

    validation_messages = validate_full_spdx_document(document)
    if validation_messages:
        raise SBOMValidationError("SPDX document does not conform to its specification.")

    packages = list(document.packages)
    package_ids = {package.spdx_id for package in packages}
    components = [
        {
            "bom-ref": package.spdx_id,
            "name": package.name,
            "version": package.version or "",
            "purl": _spdx_package_purl(package),
            "primary_package_purpose": (
                package.primary_package_purpose.name.lower()
                if package.primary_package_purpose
                else ""
            ),
        }
        for package in packages
    ]
    root_refs: set[str] = set()
    edges: set[tuple[str, str]] = set()
    for relationship in document.relationships:
        source_ref = relationship.spdx_element_id
        target_ref = relationship.related_spdx_element_id
        if not isinstance(target_ref, str):
            continue
        if (
            source_ref == document.creation_info.spdx_id
            and relationship.relationship_type == RelationshipType.DESCRIBES
            and target_ref in package_ids
        ):
            root_refs.add(target_ref)
        elif (
            relationship.relationship_type == RelationshipType.DEPENDS_ON
            and source_ref in package_ids
            and target_ref in package_ids
        ):
            edges.add((source_ref, target_ref))

    parsed_components = _classify_components(components, root_refs, edges)
    return ParsedSBOM(
        format=SBOMDocument.Format.SPDX,
        format_version=document.creation_info.spdx_version,
        generated_at=_parse_timestamp(document.creation_info.created),
        payload=json.loads(canonical_text),
        components=parsed_components,
        root_component_refs=tuple(sorted(root_refs)),
        dependencies=tuple(sorted(edges)),
    )


def parse_sbom(
    sbom_format: str,
    payload: str | bytes | Mapping[str, Any],
) -> ParsedSBOM:
    """Validate and normalize a CycloneDX or SPDX JSON SBOM."""
    canonical_text, parsed = _canonicalize_payload(payload)
    if sbom_format == SBOMDocument.Format.CYCLONEDX:
        return _parse_cyclonedx(canonical_text, parsed)
    if sbom_format == SBOMDocument.Format.SPDX:
        return _parse_spdx(canonical_text)
    raise SBOMValidationError("SBOM format must be CycloneDX or SPDX.")


@transaction.atomic
def ingest_sbom(
    scan_run: ScanRun,
    sbom_format: str,
    payload: str | bytes | Mapping[str, Any],
) -> SBOMDocument:
    """Validate, persist, and normalize an SBOM for one scan execution."""
    if scan_run.status not in {ScanRun.Status.SUCCEEDED, ScanRun.Status.PARTIAL}:
        raise SBOMValidationError("An SBOM can only be attached to a succeeded or partial scan.")
    parsed = parse_sbom(sbom_format, payload)
    serialized = json.dumps(
        parsed.payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    document, _ = SBOMDocument.objects.update_or_create(
        scan_run=scan_run,
        format=parsed.format,
        defaults={
            "format_version": parsed.format_version,
            "checksum_sha256": hashlib.sha256(serialized).hexdigest(),
            "generated_at": parsed.generated_at,
            "component_count": len(parsed.components),
            "root_component_refs": list(parsed.root_component_refs),
            "payload": parsed.payload,
        },
    )
    document.occurrences.all().delete()
    occurrences_by_ref: dict[str, ComponentOccurrence] = {}

    for item in parsed.components:
        if item.purl:
            component, _ = Component.objects.get_or_create(
                purl=item.purl,
                defaults={
                    "ecosystem": item.ecosystem,
                    "name": item.name,
                    "component_type": item.component_type,
                },
            )
        else:
            component, _ = Component.objects.get_or_create(
                purl__isnull=True,
                ecosystem=item.ecosystem,
                name=item.name,
                defaults={"component_type": item.component_type},
            )
        occurrence = ComponentOccurrence.objects.create(
            sbom_document=document,
            component=component,
            bom_ref=item.bom_ref,
            version=item.version,
            relationship=item.relationship,
            scope=item.scope,
            path=item.path,
        )
        occurrences_by_ref[item.bom_ref] = occurrence

    ComponentDependency.objects.bulk_create(
        [
            ComponentDependency(
                sbom_document=document,
                source=occurrences_by_ref[source_ref],
                target=occurrences_by_ref[target_ref],
            )
            for source_ref, target_ref in parsed.dependencies
        ]
    )
    return document


def _cyclonedx_payload(document: SBOMDocument) -> dict[str, Any]:
    occurrences = list(document.occurrences.select_related("component").all())
    refs = {occurrence.bom_ref for occurrence in occurrences}
    root_ref = "ciclosec-root"
    while root_ref in refs:
        root_ref = f"{root_ref}-1"
    dependencies: dict[str, set[str]] = defaultdict(set)
    for root_component_ref in document.root_component_refs:
        if root_component_ref in refs:
            dependencies[root_ref].add(root_component_ref)
    for edge in document.dependencies.select_related("source", "target"):
        dependencies[edge.source.bom_ref].add(edge.target.bom_ref)

    components: list[dict[str, Any]] = []
    for occurrence in occurrences:
        component_payload: dict[str, Any] = {
            "type": "library",
            "bom-ref": occurrence.bom_ref,
            "name": occurrence.component.name,
        }
        if occurrence.version:
            component_payload["version"] = occurrence.version
        if occurrence.component.purl:
            component_payload["purl"] = occurrence.component.purl
        if occurrence.scope in {"required", "optional", "excluded"}:
            component_payload["scope"] = occurrence.scope
        components.append(component_payload)

    graph = [
        {"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(dependencies.items())
    ]
    graph.extend(
        {"ref": occurrence.bom_ref, "dependsOn": []}
        for occurrence in occurrences
        if occurrence.bom_ref not in dependencies
    )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timezone.now().isoformat().replace("+00:00", "Z"),
            "component": {
                "type": "application",
                "bom-ref": root_ref,
                "name": document.scan_run.asset.name,
            },
        },
        "components": components,
        "dependencies": graph,
    }


def _spdx_payload(document: SBOMDocument) -> dict[str, Any]:
    occurrences = list(document.occurrences.select_related("component").all())
    spdx_ids = {
        occurrence.bom_ref: f"SPDXRef-Component-{index + 1}"
        for index, occurrence in enumerate(occurrences)
    }
    packages: list[Package] = []
    for occurrence in occurrences:
        external_references = (
            [
                ExternalPackageRef(
                    ExternalPackageRefCategory.PACKAGE_MANAGER,
                    "purl",
                    occurrence.component.purl,
                )
            ]
            if occurrence.component.purl
            else []
        )
        packages.append(
            Package(
                spdx_id=spdx_ids[occurrence.bom_ref],
                name=occurrence.component.name,
                version=occurrence.version or None,
                download_location=SpdxNoAssertion(),
                files_analyzed=False,
                external_references=external_references,
            )
        )

    relationships = [
        Relationship(
            "SPDXRef-DOCUMENT",
            RelationshipType.DESCRIBES,
            spdx_ids[ref],
        )
        for ref in document.root_component_refs
        if ref in spdx_ids
    ]
    relationships.extend(
        Relationship(
            spdx_ids[edge.source.bom_ref],
            RelationshipType.DEPENDS_ON,
            spdx_ids[edge.target.bom_ref],
        )
        for edge in document.dependencies.select_related("source", "target")
        if edge.source.bom_ref in spdx_ids and edge.target.bom_ref in spdx_ids
    )
    created = document.generated_at
    if timezone.is_naive(created):
        created = timezone.make_aware(created, timezone=UTC)
    spdx_document = Document(
        creation_info=CreationInfo(
            spdx_version="SPDX-2.3",
            spdx_id="SPDXRef-DOCUMENT",
            name=document.scan_run.asset.name,
            document_namespace=f"https://ciclosec.local/spdx/{uuid.uuid4()}",
            creators=[Actor(ActorType.TOOL, "CicloSec")],
            created=created,
        ),
        packages=packages,
        relationships=relationships,
    )
    with TemporaryDirectory(prefix="ciclosec-sbom-") as directory:
        filename = Path(directory) / "document.spdx.json"
        write_file(spdx_document, str(filename))
        serialized_payload = json.loads(filename.read_text(encoding="utf-8"))
    if not isinstance(serialized_payload, dict):
        raise SBOMValidationError("SPDX serializer did not return a JSON object.")
    return serialized_payload


def export_sbom(document: SBOMDocument, sbom_format: str) -> str:
    """Serialize a stored SBOM as validated CycloneDX or SPDX JSON."""
    if sbom_format == document.format:
        payload = document.payload
    elif sbom_format == SBOMDocument.Format.CYCLONEDX:
        payload = _cyclonedx_payload(document)
    elif sbom_format == SBOMDocument.Format.SPDX:
        payload = _spdx_payload(document)
    else:
        raise SBOMValidationError("SBOM format must be CycloneDX or SPDX.")

    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    parse_sbom(sbom_format, serialized)
    return serialized
