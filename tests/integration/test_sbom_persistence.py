"""Persistence and interchange tests for SBOM inventory records."""

import hashlib
import json
from pathlib import Path

import pytest

from ciclosec.assets.models import Asset
from ciclosec.inventory.models import (
    Component,
    ComponentDependency,
    ComponentOccurrence,
    SBOMDocument,
)
from ciclosec.inventory.sbom import (
    SBOMValidationError,
    export_sbom,
    ingest_sbom,
    parse_sbom,
)
from ciclosec.scans.models import ScanRun

FIXTURES = Path(__file__).parents[1] / "fixtures" / "sbom"


@pytest.fixture
def successful_scan() -> ScanRun:
    asset = Asset.objects.create(name="sample-app", kind=Asset.Kind.REPOSITORY)
    return ScanRun.objects.create(
        asset=asset,
        scanner_name="fixture-scanner",
        scanner_version="1.0",
        status=ScanRun.Status.SUCCEEDED,
    )


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("sbom_format", "fixture"),
    [
        (SBOMDocument.Format.CYCLONEDX, "cyclonedx-1.7.json"),
        (SBOMDocument.Format.SPDX, "spdx-2.3.json"),
    ],
)
def test_ingestion_persists_components_edges_and_stable_checksum(
    successful_scan: ScanRun,
    sbom_format: str,
    fixture: str,
) -> None:
    payload = json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))

    document = ingest_sbom(successful_scan, sbom_format, payload)

    assert document.component_count == 2
    assert ComponentOccurrence.objects.filter(sbom_document=document).count() == 2
    assert ComponentDependency.objects.filter(sbom_document=document).count() == 1
    assert document.occurrences.get(relationship="direct").component.name == "Flask"
    assert document.occurrences.get(relationship="transitive").component.name == "Werkzeug"
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    assert document.checksum_sha256 == hashlib.sha256(canonical).hexdigest()


@pytest.mark.django_db
def test_reingestion_is_idempotent_for_one_scan_and_format(successful_scan: ScanRun) -> None:
    payload = json.loads((FIXTURES / "cyclonedx-1.7.json").read_text(encoding="utf-8"))

    first = ingest_sbom(successful_scan, SBOMDocument.Format.CYCLONEDX, payload)
    second = ingest_sbom(successful_scan, SBOMDocument.Format.CYCLONEDX, payload)

    assert first.pk == second.pk
    assert SBOMDocument.objects.filter(scan_run=successful_scan).count() == 1
    assert ComponentOccurrence.objects.filter(sbom_document=second).count() == 2
    assert Component.objects.count() == 2


@pytest.mark.django_db
def test_invalid_sbom_is_not_persisted(successful_scan: ScanRun) -> None:
    with pytest.raises(SBOMValidationError):
        ingest_sbom(
            successful_scan,
            SBOMDocument.Format.CYCLONEDX,
            {"bomFormat": "CycloneDX", "specVersion": "9.9"},
        )

    assert SBOMDocument.objects.count() == 0


@pytest.mark.django_db
def test_queued_scan_cannot_be_given_a_success_shaped_sbom() -> None:
    asset = Asset.objects.create(name="queued-app", kind=Asset.Kind.REPOSITORY)
    queued_scan = ScanRun.objects.create(asset=asset, scanner_name="fixture-scanner")
    payload = json.loads((FIXTURES / "cyclonedx-1.7.json").read_text(encoding="utf-8"))

    with pytest.raises(SBOMValidationError, match="succeeded or partial"):
        ingest_sbom(queued_scan, SBOMDocument.Format.CYCLONEDX, payload)

    assert SBOMDocument.objects.count() == 0


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("source_format", "source_fixture", "target_format"),
    [
        (
            SBOMDocument.Format.CYCLONEDX,
            "cyclonedx-1.7.json",
            SBOMDocument.Format.SPDX,
        ),
        (
            SBOMDocument.Format.SPDX,
            "spdx-2.3.json",
            SBOMDocument.Format.CYCLONEDX,
        ),
    ],
)
def test_export_converts_between_formats_and_preserves_packages_and_edges(
    successful_scan: ScanRun,
    source_format: str,
    source_fixture: str,
    target_format: str,
) -> None:
    payload = json.loads((FIXTURES / source_fixture).read_text(encoding="utf-8"))
    document = ingest_sbom(successful_scan, source_format, payload)

    exported = export_sbom(document, target_format)
    normalized = parse_sbom(target_format, exported)

    assert len(normalized.components) == 2
    assert len(normalized.dependencies) == 1
    assert {component.name for component in normalized.components} == {"Flask", "Werkzeug"}
    assert {component.relationship for component in normalized.components} == {
        ComponentOccurrence.Relationship.DIRECT,
        ComponentOccurrence.Relationship.TRANSITIVE,
    }
