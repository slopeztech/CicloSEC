"""Reversible OSV equivalence and preserved-reference tests."""

import io
import json
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.core.management import call_command
from django.db import close_old_connections, connection, connections

from ciclosec.assets.models import Asset
from ciclosec.findings.models import Finding, RiskAssessment
from ciclosec.findings.services import reevaluate_findings
from ciclosec.intelligence import providers
from ciclosec.intelligence.merging import MergeConflict, reverse_merge
from ciclosec.intelligence.models import (
    AdvisoryRecord,
    SyncRun,
    Vulnerability,
    VulnerabilityAlias,
    VulnerabilityMerge,
    VulnerabilityMergeMember,
)
from ciclosec.scans.models import ScanRun

pytestmark = pytest.mark.django_db


@pytest.fixture
def merge_case() -> tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]]:
    cve = Vulnerability.objects.create(canonical_id="CVE-2026-1234")
    ghsa = Vulnerability.objects.create(canonical_id="GHSA-abcd-efgh-ijkl")
    for vulnerability, namespace in [
        (cve, VulnerabilityAlias.Namespace.CVE),
        (ghsa, VulnerabilityAlias.Namespace.GHSA),
    ]:
        VulnerabilityAlias.objects.create(
            vulnerability=vulnerability, namespace=namespace, identifier=vulnerability.canonical_id
        )
    AdvisoryRecord.objects.create(
        vulnerability=cve,
        provider=AdvisoryRecord.Provider.NVD,
        external_id=cve.canonical_id,
        raw_record={"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}},
    )
    AdvisoryRecord.objects.create(
        vulnerability=ghsa,
        provider=AdvisoryRecord.Provider.GITHUB,
        external_id=ghsa.canonical_id,
        raw_record={"vulnerabilities": []},
    )
    asset = Asset.objects.create(name="example", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test")
    finding = Finding.objects.create(
        asset=asset,
        scan_run=scan,
        vulnerability=ghsa,
        source=Finding.Source.OSV_SCANNER,
        kind=Finding.Kind.VULNERABILITY,
        fingerprint="f" * 64,
        external_id=ghsa.canonical_id,
    )
    run = SyncRun.objects.create(provider="osv", mode=SyncRun.Mode.FULL)
    record: dict[str, object] = {
        "id": cve.canonical_id,
        "aliases": [ghsa.canonical_id],
        "modified": "2026-11-20T12:00:00Z",
        "affected": [],
    }
    return cve, ghsa, finding, run, record


def test_osv_merge_and_reversal_preserve_references_and_recompute_risk(
    merge_case: tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]],
) -> None:
    cve, ghsa, finding, run, record = merge_case
    providers._upsert_osv_record(record, run)
    merge = VulnerabilityMerge.objects.get()
    cve.refresh_from_db()
    ghsa.refresh_from_db()
    finding.refresh_from_db()

    assert Vulnerability.objects.count() == 2
    assert finding.vulnerability_id == ghsa.pk
    assert VulnerabilityAlias.objects.get(identifier=ghsa.canonical_id).vulnerability_id == ghsa.pk
    assert AdvisoryRecord.objects.get(provider="github_advisories").vulnerability_id == ghsa.pk
    assert merge.references_recorded_at is not None
    assert set(merge.members.values_list("vulnerability_id", flat=True)) == {cve.pk, ghsa.pk}
    details = io.StringIO()
    call_command("vulnerability_merges", "--show", str(merge.pk), stdout=details)
    assert ghsa.canonical_id in details.getvalue()
    assert reevaluate_findings() == 1
    signals = RiskAssessment.objects.get(finding=finding).factors["signals"]
    assert any(signal["name"] == "cvss" for signal in signals)

    out = io.StringIO()
    call_command(
        "vulnerability_merges",
        "--reverse",
        str(merge.pk),
        "--operator",
        "test-operator",
        "--reason",
        "reviewed evidence",
        stdout=out,
    )
    merge.refresh_from_db()
    cve.refresh_from_db()
    ghsa.refresh_from_db()
    finding.refresh_from_db()
    assert merge.reverted_at is not None
    assert merge.reverted_by == "test-operator"
    assert cve.merged_into_id is None and ghsa.merged_into_id is None
    assert finding.vulnerability_id == ghsa.pk
    signals = RiskAssessment.objects.get(finding=finding).factors["signals"]
    assert not any(signal["name"] == "cvss" for signal in signals)
    with pytest.raises(providers.ProviderSyncError, match="previously reversed"):
        providers._upsert_osv_record(record, run)


def test_merge_detail_limits_members_without_omitting_reference_counts(
    merge_case: tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]],
) -> None:
    cve, _, _, run, record = merge_case
    providers._upsert_osv_record(record, run)
    merge = VulnerabilityMerge.objects.get()
    extra = Vulnerability.objects.bulk_create(
        [Vulnerability(canonical_id=f"extra-{i}", merged_into=cve) for i in range(100)]
    )
    VulnerabilityMergeMember.objects.bulk_create(
        [
            VulnerabilityMergeMember(merge=merge, vulnerability=item, previous_root=item)
            for item in extra
        ]
    )
    output = io.StringIO()
    call_command("vulnerability_merges", "--show", str(merge.pk), stdout=output)
    details = json.loads(output.getvalue())

    assert details["member_count"] == 102
    assert len(details["members"]) == 100
    assert details["references"]["alias"] == {"recorded": 2, "current": 2}


@pytest.mark.parametrize("kind", ["alias", "advisory", "finding"])
def test_reversal_rejects_new_references(
    merge_case: tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]],
    kind: str,
) -> None:
    cve, _, finding, run, record = merge_case
    providers._upsert_osv_record(record, run)
    merge = VulnerabilityMerge.objects.get()
    if kind == "alias":
        VulnerabilityAlias.objects.create(vulnerability=cve, namespace="other", identifier="NEW-1")
    elif kind == "advisory":
        AdvisoryRecord.objects.create(vulnerability=cve, provider="epss", external_id="NEW-1")
    else:
        Finding.objects.create(
            asset=finding.asset,
            scan_run=finding.scan_run,
            vulnerability=cve,
            source=finding.source,
            kind=finding.kind,
            fingerprint="a" * 64,
        )

    with pytest.raises(MergeConflict, match="references changed"):
        reverse_merge(merge.pk, operator="operator", reason="review")

    merge.refresh_from_db()
    assert merge.reverted_at is None


def test_unlinked_finding_accepts_aliases_in_same_group(
    merge_case: tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]],
) -> None:
    cve, ghsa, finding, run, record = merge_case
    finding.vulnerability = None
    finding.evidence = {"aliases": [cve.canonical_id, ghsa.canonical_id]}
    finding.save(update_fields=["vulnerability", "evidence"])
    providers._upsert_osv_record(record, run)

    assert reevaluate_findings() == 1
    finding.refresh_from_db()
    assert finding.vulnerability_id in {cve.pk, ghsa.pk}
    assert any(
        signal["name"] == "cvss"
        for signal in RiskAssessment.objects.get(finding=finding).factors["signals"]
    )
    with pytest.raises(MergeConflict, match="finding references changed"):
        reverse_merge(VulnerabilityMerge.objects.get().pk, operator="operator", reason="review")


def test_reversal_rolls_back_if_reevaluation_fails(
    merge_case: tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, ghsa, _, run, record = merge_case
    providers._upsert_osv_record(record, run)
    merge = VulnerabilityMerge.objects.get()

    def fail_reevaluation(**kwargs: object) -> int:
        raise RuntimeError("reevaluation failed")

    monkeypatch.setattr("ciclosec.findings.services.reevaluate_findings", fail_reevaluation)
    with pytest.raises(RuntimeError, match="reevaluation failed"):
        reverse_merge(merge.pk, operator="operator", reason="review")

    merge.refresh_from_db()
    ghsa.refresh_from_db()
    assert merge.reverted_at is None
    assert ghsa.merged_into_id == merge.canonical_id


def test_multiple_cves_remain_separate_for_review(
    merge_case: tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]],
) -> None:
    cve, ghsa, _, run, record = merge_case
    another = Vulnerability.objects.create(canonical_id="CVE-2026-9999")
    VulnerabilityAlias.objects.create(
        vulnerability=another, namespace="cve", identifier=another.canonical_id
    )
    record["aliases"] = [ghsa.canonical_id, another.canonical_id]

    with pytest.raises(providers.ProviderSyncError, match="multiple CVE"):
        providers._upsert_osv_record(record, run)

    cve.refresh_from_db()
    ghsa.refresh_from_db()
    assert cve.merged_into_id is None and ghsa.merged_into_id is None
    assert not VulnerabilityMerge.objects.exists()


def test_reverse_later_merge_before_earlier_merge(
    merge_case: tuple[Vulnerability, Vulnerability, Finding, SyncRun, dict[str, object]],
) -> None:
    cve, ghsa, _, run, record = merge_case
    providers._upsert_osv_record(record, run)
    first = VulnerabilityMerge.objects.get()
    extra = Vulnerability.objects.create(canonical_id="GHSA-mnop-qrst-uvwx")
    VulnerabilityAlias.objects.create(
        vulnerability=extra, namespace="ghsa", identifier=extra.canonical_id
    )
    record["aliases"] = [ghsa.canonical_id, extra.canonical_id]
    providers._upsert_osv_record(record, run)
    second = VulnerabilityMerge.objects.latest("pk")

    with pytest.raises(MergeConflict, match="later active merge"):
        reverse_merge(first.pk, operator="operator", reason="review")
    reverse_merge(second.pk, operator="operator", reason="review later evidence")
    reverse_merge(first.pk, operator="operator", reason="review earlier evidence")

    cve.refresh_from_db()
    ghsa.refresh_from_db()
    extra.refresh_from_db()
    assert all(v.merged_into_id is None for v in (cve, ghsa, extra))


@pytest.mark.django_db(transaction=True)
def test_concurrent_osv_reconciliation_does_not_duplicate_merges() -> None:
    if connection.vendor != "postgresql":
        pytest.skip("row-lock concurrency requires PostgreSQL")
    cve = Vulnerability.objects.create(canonical_id="CVE-2026-1234")
    ghsa = Vulnerability.objects.create(canonical_id="GHSA-abcd-efgh-ijkl")
    VulnerabilityAlias.objects.create(
        vulnerability=cve, namespace="cve", identifier=cve.canonical_id
    )
    VulnerabilityAlias.objects.create(
        vulnerability=ghsa, namespace="ghsa", identifier=ghsa.canonical_id
    )
    run_ids = [SyncRun.objects.create(provider="osv", mode=SyncRun.Mode.FULL).pk for _ in range(2)]
    barrier = Barrier(2)

    def reconcile(run_id: int) -> str:
        close_old_connections()
        try:
            run = SyncRun.objects.get(pk=run_id)
            barrier.wait(timeout=10)
            try:
                providers._upsert_osv_record(
                    {
                        "id": "CVE-2026-1234",
                        "aliases": ["GHSA-abcd-efgh-ijkl"],
                        "modified": "2026-11-20T12:00:00Z",
                    },
                    run,
                )
                return "succeeded"
            except providers.ProviderSyncError:
                return "retry"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(reconcile, run_ids))

    assert "succeeded" in results
    assert VulnerabilityMerge.objects.count() == 1
    assert Vulnerability.objects.count() == 2
    assert AdvisoryRecord.objects.filter(provider="osv").count() == 1
