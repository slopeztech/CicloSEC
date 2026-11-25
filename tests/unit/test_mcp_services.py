"""Read-only application-query service tests for MCP."""

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from django.conf import settings
from django.utils import timezone

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.assets.services import get_asset_coverage, list_assets
from ciclosec.findings.models import Finding, FindingDecisionEvent, RiskAssessment
from ciclosec.findings.services import list_finding_summaries
from ciclosec.intelligence.models import Vulnerability
from ciclosec.inventory.models import SBOMDocument
from ciclosec.inventory.sbom import ingest_sbom
from ciclosec.inventory.services import list_asset_components
from ciclosec.scans.models import ScanRun
from ciclosec.scans.services import list_scan_history

SBOM_FIXTURE = Path(__file__).parents[1] / "fixtures" / "sbom" / "cyclonedx-1.7.json"
pytestmark = pytest.mark.django_db


def _asset(name: str, *, enabled: bool = True) -> Asset:
    return Asset.objects.create(
        name=name,
        kind=Asset.Kind.REPOSITORY,
        enabled=enabled,
    )


def _scan(
    asset: Asset,
    status: str,
    *,
    now: datetime,
    age: timedelta = timedelta(),
) -> ScanRun:
    if status in {ScanRun.Status.SUCCEEDED, ScanRun.Status.PARTIAL, ScanRun.Status.FAILED}:
        finished_at = now - age
        return ScanRun.objects.create(
            asset=asset,
            scanner_name="test-scanner",
            status=status,
            started_at=finished_at - timedelta(minutes=1),
            finished_at=finished_at,
        )
    return ScanRun.objects.create(
        asset=asset,
        scanner_name="test-scanner",
        status=status,
    )


def test_asset_listing_omits_repository_credentials() -> None:
    asset = _asset("private-backend")
    Repository.objects.create(
        asset=asset,
        owner="example",
        repository_name="private-backend",
        credential_env="LOCAL_GITHUB_TOKEN",
    )

    result = list_assets(limit=10, offset=0)

    assert result["total"] == 1
    assert result["items"][0]["name"] == "private-backend"
    assert "credential_env" not in result["items"][0]


def test_asset_coverage_uses_enabled_registered_assets_and_configured_freshness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        settings.CICLOSEC_CONFIG.scanning,
        "schedules",
        {"repositories": "24h", "container_images": "24h"},
    )
    now = timezone.now()
    current = _asset("current")
    partial = _asset("partial")
    failed = _asset("failed")
    active = _asset("active")
    stale = _asset("stale")
    _asset("never")
    _asset("disabled", enabled=False)
    _scan(current, ScanRun.Status.SUCCEEDED, now=now, age=timedelta(hours=1))
    _scan(partial, ScanRun.Status.PARTIAL, now=now, age=timedelta(hours=2))
    _scan(failed, ScanRun.Status.FAILED, now=now)
    _scan(active, ScanRun.Status.RUNNING, now=now)
    _scan(stale, ScanRun.Status.SUCCEEDED, now=now, age=timedelta(days=2))
    for asset in (current, partial, stale):
        Repository.objects.create(asset=asset, owner="example", repository_name=asset.name)
        ScanRun.objects.filter(asset=asset).update(
            metadata={
                "repository_source": {
                    "provider": "github",
                    "owner": "example",
                    "repository": asset.name,
                    "ref": "main",
                }
            }
        )

    result = get_asset_coverage(now=now)

    assert result["scope"] == "enabled_registered_assets"
    assert result["total_registered"] == 7
    assert result["enabled_total"] == 6
    assert result["disabled_total"] == 1
    assert result["counts"] == {
        "current": 1,
        "partial": 1,
        "failed": 1,
        "in_progress": 1,
        "stale": 1,
        "never_scanned": 1,
        "source_changed": 0,
        "source_unknown": 0,
    }


@pytest.mark.parametrize(
    ("kind", "metadata", "missing_source", "expected"),
    [
        (
            "repository",
            {
                "repository_source": {
                    "provider": "github",
                    "owner": "example",
                    "repository": "repo",
                    "ref": "main",
                }
            },
            False,
            "current",
        ),
        (
            "repository",
            {
                "repository_source": {
                    "provider": "github",
                    "owner": "old",
                    "repository": "repo",
                    "ref": "main",
                }
            },
            False,
            "source_changed",
        ),
        (
            "repository",
            {
                "repository_source": {
                    "provider": "github",
                    "owner": "example",
                    "repository": "repo",
                    "ref": "main",
                }
            },
            True,
            "source_changed",
        ),
        ("repository", {}, False, "source_unknown"),
        ("repository", {"repository_source": {"owner": "example"}}, False, "source_unknown"),
        (
            "container_image",
            {"image_reference": "example:local", "image_source_revision": 2},
            False,
            "current",
        ),
        (
            "container_image",
            {"image_reference": "example:old", "image_source_revision": 2},
            False,
            "source_changed",
        ),
        (
            "container_image",
            {"image_reference": "example:local", "image_source_revision": 1},
            False,
            "source_changed",
        ),
        ("container_image", {"image_reference": "example:local"}, False, "source_unknown"),
        ("container_image", {"image_reference": "example:old"}, False, "source_changed"),
        (
            "container_image",
            {"image_reference": "example:local", "image_source_revision": True},
            False,
            "source_unknown",
        ),
        (
            "container_image",
            {"image_reference": "example:local", "image_source_revision": 2},
            True,
            "source_changed",
        ),
    ],
)
def test_coverage_identifies_changed_or_unverified_sources(
    kind: str, metadata: dict, missing_source: bool, expected: str
) -> None:
    asset = Asset.objects.create(name="asset", kind=kind)
    if not missing_source:
        if kind == Asset.Kind.REPOSITORY:
            Repository.objects.create(asset=asset, owner="example", repository_name="repo")
        else:
            ContainerImage.objects.create(
                asset=asset, image_reference="example:local", source_revision=2
            )
    ScanRun.objects.create(
        asset=asset,
        scanner_name="test",
        status=ScanRun.Status.SUCCEEDED,
        finished_at=timezone.now(),
        metadata=metadata,
    )

    counts = get_asset_coverage()["counts"]

    assert counts[expected] == 1
    assert sum(counts.values()) == 1


def test_mcp_coverage_exposes_new_source_states() -> None:
    from ciclosec.mcp.server import get_asset_coverage as mcp_asset_coverage

    asset = _asset("historical")
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    _scan(asset, ScanRun.Status.SUCCEEDED, now=timezone.now())

    coverage = mcp_asset_coverage()

    assert coverage.counts.current == 0
    assert coverage.counts.source_unknown == 1
    assert coverage.counts.source_changed == 0


def test_scan_history_does_not_return_error_text_or_execution_metadata() -> None:
    asset = _asset("backend")
    ScanRun.objects.create(
        asset=asset,
        scanner_name="test-scanner",
        status=ScanRun.Status.FAILED,
        error_summary="secret-token-must-not-leak",
        warnings=["private/path"],
        metadata={"image_reference": "private-registry"},
    )

    result = list_scan_history(asset_id=asset.pk, limit=10, offset=0)
    item = result["items"][0]

    assert item["has_error"] is True
    assert item["warning_count"] == 1
    assert "error_summary" not in item
    assert "warnings" not in item
    assert "metadata" not in item
    assert "secret-token-must-not-leak" not in repr(result)


def test_sbom_query_returns_latest_normalized_components_without_raw_purls() -> None:
    asset = _asset("backend")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    first_scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test-scanner",
        status=ScanRun.Status.SUCCEEDED,
    )
    ingest_sbom(first_scan, SBOMDocument.Format.CYCLONEDX, sbom)
    latest_scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="test-scanner",
        status=ScanRun.Status.SUCCEEDED,
    )
    latest_document = ingest_sbom(latest_scan, SBOMDocument.Format.CYCLONEDX, sbom)

    result = list_asset_components(
        asset_id=asset.pk,
        scan_run_id=None,
        limit=10,
        offset=0,
    )

    assert result["scan_run_id"] == latest_scan.pk
    assert result["sbom_checksum_sha256"] == latest_document.checksum_sha256
    assert result["total"] == 2
    assert result["source_status"] == "unknown"
    assert {item["name"] for item in result["items"]} == {"Flask", "Werkzeug"}
    assert all("purl" not in item and "path" not in item for item in result["items"])

    from ciclosec.mcp.server import list_sbom_components

    mcp_result = list_sbom_components(asset_id=asset.pk)
    assert mcp_result.source_status == "unknown"
    assert mcp_result.scan_run_id == latest_scan.pk


def test_sbom_image_source_status_tracks_revisions_and_preserves_history() -> None:
    from ciclosec.assets.services import update_container_image_source

    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    image = ContainerImage.objects.create(asset=asset, image_reference="example:local")
    scan = ScanRun.objects.create(
        asset=asset,
        scanner_name="image",
        status=ScanRun.Status.SUCCEEDED,
        metadata={"image_reference": "example:local", "image_source_revision": 0},
    )
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    ingest_sbom(scan, "cyclonedx", sbom)

    result = list_asset_components(asset_id=asset.pk, scan_run_id=None, limit=10, offset=0)
    assert result["source_status"] == "matched"

    update_container_image_source(image, image_reference="example:other")
    update_container_image_source(image, image_reference="example:local")
    result = list_asset_components(asset_id=asset.pk, scan_run_id=scan.pk, limit=10, offset=0)
    assert result["source_status"] == "changed"
    assert result["scan_run_id"] == scan.pk
    assert result["total"] == 2


def test_sbom_source_status_uses_the_selected_scan_not_latest_scan() -> None:
    asset = _asset("backend")
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    scans = []
    for owner in ("example", "other"):
        scan = ScanRun.objects.create(
            asset=asset,
            scanner_name="repository",
            status=ScanRun.Status.SUCCEEDED,
            metadata={
                "repository_source": {
                    "provider": "github",
                    "owner": owner,
                    "repository": "repo",
                    "ref": "main",
                }
            },
        )
        ingest_sbom(scan, "cyclonedx", sbom)
        scans.append(scan)

    latest = list_asset_components(asset_id=asset.pk, scan_run_id=None, limit=10, offset=0)
    selected = list_asset_components(asset_id=asset.pk, scan_run_id=scans[0].pk, limit=10, offset=0)

    assert latest["scan_run_id"] == scans[1].pk
    assert latest["source_status"] == "changed"
    assert selected["scan_run_id"] == scans[0].pk
    assert selected["source_status"] == "matched"


def test_sbom_without_document_has_no_source_status() -> None:
    asset = _asset("without-sbom")
    result = list_asset_components(asset_id=asset.pk, scan_run_id=None, limit=10, offset=0)

    assert result["source_status"] is None
    assert result["total"] == 0


def test_finding_query_returns_correlation_but_not_raw_scanner_evidence() -> None:
    asset = _asset("backend")
    scan_run = ScanRun.objects.create(asset=asset, scanner_name="test-scanner")
    vulnerability = Vulnerability.objects.create(canonical_id="CVE-2026-0010")
    finding = Finding.objects.create(
        scan_run=scan_run,
        asset=asset,
        vulnerability=vulnerability,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="a" * 64,
        external_id="CVE-2026-0010",
        evidence={
            "aliases": ["GHSA-1111-2222-3333"],
            "scanner_output": "raw-secret-value",
            "correlation": {
                "evidence": [
                    {
                        "provider": "osv",
                        "advisory_id": "OSV-2026-0010",
                        "source_status": "current",
                        "package": "flask",
                        "ecosystem": "PyPI",
                        "package_matches": True,
                        "version_result": True,
                    }
                ]
            },
        },
    )
    RiskAssessment.objects.create(
        finding=finding,
        score=40,
        level=RiskAssessment.Level.MEDIUM,
        policy_version="risk-v1",
        factors={"signals": [], "context": {"points": 0}},
        explanation="CVSS contributes to priority.",
    )

    result = list_finding_summaries(
        asset_id=asset.pk,
        affected_status=None,
        limit=10,
        offset=0,
    )

    item = result["items"][0]
    assert item["canonical_id"] == "CVE-2026-0010"
    assert item["aliases"] == ["GHSA-1111-2222-3333"]
    assert item["risk_assessment"]["score"] == 40
    assert item["correlation_evidence"][0]["version_result"] is True
    assert "scanner_output" not in item
    assert "raw-secret-value" not in repr(result)


def test_finding_source_status_does_not_add_queries_per_row(django_assert_num_queries) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.mcp.server import list_findings

    repo = _asset("repo")
    Repository.objects.create(asset=repo, owner="example", repository_name="repo")
    image = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    ContainerImage.objects.create(asset=image, image_reference="example:local")
    missing = _asset("missing")
    for index, asset in enumerate((repo, image, missing)):
        scan = ScanRun.objects.create(asset=asset, scanner_name="test")
        Finding.objects.create(
            asset=asset,
            scan_run=scan,
            source=Finding.Source.TRIVY,
            kind=Finding.Kind.VULNERABILITY,
            fingerprint=f"{index:064x}",
        )
    user = get_user_model().objects.create_user(username="finding-query-test")
    client = APIClient()
    client.force_authenticate(user=user)

    with django_assert_num_queries(3):
        response = list_findings()
    assert len(response.items) == 3
    with django_assert_num_queries(2):
        api_response = client.get("/api/findings/")
    assert api_response.status_code == 200
    assert len(api_response.data) == 3


def test_finding_event_history_is_bounded_per_finding_in_mcp_and_api() -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    user = get_user_model().objects.create_user(username="history-reader")
    asset = _asset("history")
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    findings = [
        Finding.objects.create(
            asset=asset,
            scan_run=scan,
            source=Finding.Source.TRIVY,
            kind=Finding.Kind.VULNERABILITY,
            fingerprint=f"{index:064x}",
        )
        for index in range(2)
    ]
    FindingDecisionEvent.objects.bulk_create(
        [
            FindingDecisionEvent(finding=finding, actor=user, status="open", reason=str(index))
            for finding in findings
            for index in range(52)
        ]
    )
    expected = [str(index) for index in range(51, 1, -1)]
    summaries = list_finding_summaries(asset_id=asset.pk, affected_status=None, limit=10, offset=0)
    client = APIClient()
    client.force_authenticate(user=user)
    response = client.get("/api/findings/")
    assert response.status_code == 200
    for item in summaries["items"]:
        assert [event["reason"] for event in item["decision_events"]] == expected
    for item in response.data:
        assert [event["reason"] for event in item["decision_events"]] == expected
