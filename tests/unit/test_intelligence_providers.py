"""Provider synchronization and source freshness tests."""

import gzip
import io
import json
import socket
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request

import pytest

from ciclosec.intelligence import providers
from ciclosec.intelligence.models import (
    AdvisoryRecord,
    IntelligenceSource,
    SyncRun,
    Vulnerability,
    VulnerabilityAlias,
)
from ciclosec.intelligence.services import get_source_freshness

FIXTURES = Path(__file__).parents[1] / "fixtures" / "intelligence"
pytestmark = pytest.mark.django_db


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args: object, **kwargs: object) -> None:
        pytest.fail("Provider tests must not access the network")

    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)


@pytest.fixture
def osv_feed() -> bytes:
    return (FIXTURES / "osv-modified-id-v1.csv").read_bytes()


@pytest.fixture
def osv_records() -> dict[str, dict[str, object]]:
    return json.loads((FIXTURES / "osv-records-v1.json").read_text(encoding="utf-8"))


@pytest.fixture
def kev_catalog() -> dict[str, object]:
    return json.loads((FIXTURES / "cisa-kev-v1.json").read_text(encoding="utf-8"))


def cisa_payload_fetch(payload: bytes):
    def fake_fetch(url: str, *, max_bytes: int) -> bytes:
        assert url == providers.CISA_KEV_URL
        assert max_bytes == providers.MAX_CISA_BYTES
        return payload

    return fake_fetch


def github_advisory(ghsa_id: str, cve_id: str) -> dict[str, object]:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "identifiers": [
            {"type": "GHSA", "value": ghsa_id},
            {"type": "CVE", "value": cve_id},
        ],
        "summary": "A test vulnerability",
        "description": "A test advisory description",
        "severity": "high",
        "cvss_severities": {
            "cvss_v3": {"score": 8.1, "vector_string": "CVSS:3.1/AV:N/AC:L"},
            "cvss_v4": None,
        },
        "published_at": "2026-11-20T11:00:00Z",
        "updated_at": "2026-11-20T12:00:00Z",
        "withdrawn_at": None,
        "references": ["https://example.test/advisory"],
        "vulnerabilities": [
            {
                "package": {"ecosystem": "pip", "name": "example"},
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": {"identifier": "2.0.0"},
            }
        ],
        "credits": [{"user": {"login": "not-needed-for-correlation"}}],
    }


def nvd_cve_record(cve_id: str, *, status: str = "Analyzed") -> dict[str, object]:
    return {
        "id": cve_id,
        "published": "2026-11-20T11:00:00.000Z",
        "lastModified": "2026-11-20T12:00:00.000Z",
        "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "A test NVD description"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L",
                    },
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "operator": "OR",
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                                "versionStartIncluding": "1.0",
                                "versionEndExcluding": "2.0",
                            }
                        ],
                    }
                ]
            }
        ],
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
        "references": [
            {
                "url": "https://example.test/cve",
                "source": "nvd@nist.gov",
                "tags": ["Vendor Advisory"],
            }
        ],
    }


def epss_response(cve_ids: list[str]) -> bytes:
    rows = "".join(f"{cve_id},0.125000000,0.750000000\n" for cve_id in cve_ids)
    return gzip.compress(
        (
            "#model_version:v2026.06.15,score_date:2026-11-20T12:00:23Z\n"
            "cve,epss,percentile\n" + rows
        ).encode()
    )


def test_cisa_sync_is_idempotent_and_reconciles_removed_entries(
    monkeypatch: pytest.MonkeyPatch,
    kev_catalog: dict[str, object],
) -> None:
    payload = json.dumps(kev_catalog).encode("utf-8")

    def fake_fetch(url: str, *, max_bytes: int) -> bytes:
        assert url == providers.CISA_KEV_URL
        assert max_bytes == providers.MAX_CISA_BYTES
        return payload

    monkeypatch.setattr(providers, "fetch_url", fake_fetch)

    first = providers.sync_cisa_kev()
    providers.sync_cisa_kev()

    assert first.records_processed == 2
    assert AdvisoryRecord.objects.filter(provider=AdvisoryRecord.Provider.CISA_KEV).count() == 2
    assert (
        VulnerabilityAlias.objects.filter(
            namespace=VulnerabilityAlias.Namespace.CVE,
            identifier="CVE-2026-0001",
        ).count()
        == 1
    )

    reduced_catalog = dict(kev_catalog)
    reduced_catalog["count"] = 1
    reduced_catalog["vulnerabilities"] = kev_catalog["vulnerabilities"][:1]
    reduced_payload = json.dumps(reduced_catalog).encode("utf-8")
    monkeypatch.setattr(providers, "fetch_url", cisa_payload_fetch(reduced_payload))
    providers.sync_cisa_kev()

    removed = AdvisoryRecord.objects.get(
        provider=AdvisoryRecord.Provider.CISA_KEV,
        external_id="CVE-2026-0005",
    )
    assert not removed.is_active
    assert AdvisoryRecord.objects.filter(
        provider=AdvisoryRecord.Provider.CISA_KEV,
        external_id="CVE-2026-0001",
        is_active=True,
    ).exists()
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.CISA_KEV,
            status=SyncRun.Status.SUCCEEDED,
        ).count()
        == 3
    )


def test_github_advisory_sync_paginates_and_stores_sanitized_records(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(providers, "GITHUB_ADVISORY_PAGE_SIZE", 2)
    pages = {
        None: [
            github_advisory("GHSA-abcd-efgh-ijkl", "CVE-2026-1234"),
            github_advisory("GHSA-abcd-efgh-mnop", "CVE-2026-1235"),
        ],
        "cursor+value": [github_advisory("GHSA-abcd-efgh-qrst", "CVE-2026-1236")],
    }
    pages[None][0]["identifiers"] = None
    pages[None][0]["vulnerabilities"] = [
        {
            "package": {"ecosystem": "pip", "name": "example"},
            "vulnerable_version_range": "< 2.0.0",
            "first_patched_version": "2.0.0",
        }
    ]
    requested_cursors: list[str | None] = []

    def fake_fetch(
        url: str,
        *,
        max_bytes: int,
        headers: dict[str, str],
    ) -> providers.HttpResponse:
        assert url.startswith(providers.GITHUB_ADVISORIES_URL)
        assert max_bytes == providers.MAX_GITHUB_ADVISORY_BYTES
        assert headers["Accept"] == "application/vnd.github+json"
        assert headers["X-GitHub-Api-Version"] == "2026-03-10"
        query = parse_qs(urlsplit(url).query)
        cursor = query.get("after", [None])[0]
        requested_cursors.append(cursor)
        link = (
            '<https://api.github.com/advisories?after=cursor%2Bvalue>; rel="next"'
            if cursor is None
            else ""
        )
        return providers.HttpResponse(
            json.dumps(pages[cursor]).encode("utf-8"),
            200,
            {"Link": link},
        )

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    outcome = providers.sync_github_advisories()

    assert requested_cursors == [None, "cursor+value"]
    assert outcome.provider == AdvisoryRecord.Provider.GITHUB
    assert outcome.status == SyncRun.Status.SUCCEEDED
    assert not outcome.coverage_complete
    assert outcome.records_processed == 3
    assert AdvisoryRecord.objects.filter(provider=AdvisoryRecord.Provider.GITHUB).count() == 3
    record = AdvisoryRecord.objects.get(external_id="GHSA-abcd-efgh-ijkl")
    assert record.vulnerability.canonical_id == "CVE-2026-1234"
    assert record.raw_record["vulnerabilities"][0]["package"]["name"] == "example"
    assert record.raw_record["vulnerabilities"][0]["first_patched_version"] == {
        "identifier": "2.0.0"
    }
    assert "credits" not in record.raw_record
    assert not record.raw_record.get("credits")
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.GITHUB)
    assert source.confirmed_cursor["coverage_complete"] is False
    assert "modified_until" in source.confirmed_cursor
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.GITHUB,
            mode=SyncRun.Mode.FULL,
            status=SyncRun.Status.SUCCEEDED,
        ).count()
        == 1
    )


def test_github_advisory_incremental_sync_uses_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = IntelligenceSource.objects.create(
        provider=AdvisoryRecord.Provider.GITHUB,
        confirmed_cursor={
            "coverage_complete": False,
            "coverage_start": "2026-10-20T00:00:00+00:00",
            "modified_until": "2026-11-20T12:00:00.123456+00:00",
        },
    )
    requested_urls: list[str] = []

    def fake_fetch(
        url: str,
        *,
        max_bytes: int,
        headers: dict[str, str],
    ) -> providers.HttpResponse:
        del max_bytes, headers
        requested_urls.append(url)
        return providers.HttpResponse(b"[]", 200, {})

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    providers.sync_github_advisories()

    query = parse_qs(urlsplit(requested_urls[0]).query)
    assert "after" not in query
    assert query["modified"] == [">=2026-11-18T12:00:00Z"]
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.GITHUB,
            mode=SyncRun.Mode.INCREMENTAL,
            status=SyncRun.Status.SUCCEEDED,
        ).count()
        == 1
    )
    source.refresh_from_db()
    assert source.confirmed_cursor["coverage_start"] == "2026-10-20T00:00:00+00:00"


@pytest.mark.parametrize(
    "link",
    [
        '<https://example.test/advisories?after=next>; rel="next"',
        '<https://api.github.com/advisories?after=>; rel="next"',
        '<https://[invalid/advisories?after=next>; rel="next"',
    ],
)
def test_github_advisory_rejects_invalid_next_link(
    monkeypatch: pytest.MonkeyPatch, link: str
) -> None:
    def fake_fetch(url: str, *, max_bytes: int, headers: dict[str, str]) -> providers.HttpResponse:
        del url, max_bytes, headers
        return providers.HttpResponse(b"[]", 200, {"Link": link})

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    with pytest.raises(providers.ProviderSyncError, match="pagination"):
        providers.sync_github_advisories()
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.GITHUB)
    assert source.status == IntelligenceSource.Status.UNAVAILABLE
    assert source.confirmed_cursor == {}


def test_github_advisory_rejects_repeated_cursor(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_fetch(url: str, *, max_bytes: int, headers: dict[str, str]) -> providers.HttpResponse:
        del url, max_bytes, headers
        return providers.HttpResponse(
            b"[]",
            200,
            {"Link": '<https://api.github.com/advisories?after=same>; rel="next"'},
        )

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    with pytest.raises(providers.ProviderSyncError, match="pagination"):
        providers.sync_github_advisories()


def test_github_advisory_failure_does_not_advance_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = {
        "coverage_complete": False,
        "coverage_start": "2026-10-20T00:00:00+00:00",
        "modified_until": "2026-11-20T12:00:00+00:00",
    }
    source = IntelligenceSource.objects.create(
        provider=AdvisoryRecord.Provider.GITHUB,
        confirmed_cursor=cursor,
    )

    def fake_fetch(
        url: str,
        *,
        max_bytes: int,
        headers: dict[str, str],
    ) -> providers.HttpResponse:
        del url, max_bytes, headers
        return providers.HttpResponse(b'{"not":"a list"}', 200, {})

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    with pytest.raises(providers.ProviderSyncError, match="invalid list"):
        providers.sync_github_advisories()

    source.refresh_from_db()
    assert source.confirmed_cursor == cursor
    assert source.status == IntelligenceSource.Status.UNAVAILABLE
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.GITHUB,
            status=SyncRun.Status.FAILED,
        ).count()
        == 1
    )


def test_nvd_modified_windows_respect_api_maximum_span() -> None:
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = start + timedelta(days=121)

    windows = list(providers._nvd_modified_windows(start, end))

    assert len(windows) == 2
    assert windows[0] == (start, start + timedelta(days=120))
    assert windows[1] == (start + timedelta(days=120, seconds=1), end)


def test_nvd_response_timestamps_without_offsets_are_utc() -> None:
    cve = nvd_cve_record("CVE-2026-1234")
    cve["published"] = "2026-11-20T11:00:00.000"
    cve["lastModified"] = "2026-11-20T12:00:00.000"

    _, published, modified, _, record, _ = providers._sanitize_nvd_cve(cve)

    assert published == datetime(2026, 11, 20, 11, tzinfo=UTC)
    assert modified == datetime(2026, 11, 20, 12, tzinfo=UTC)
    assert record["lastModified"] == "2026-11-20T12:00:00+00:00"
    with pytest.raises(providers.ProviderSyncError, match="timezone-naive"):
        providers._parse_timestamp("2026-11-20T12:00:00", field="modified")


def test_nvd_sync_paginates_and_stores_cvss_and_cpe_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(providers, "NVD_RESULTS_PER_PAGE", 2)
    naive_cve = nvd_cve_record("CVE-2026-1234")
    naive_cve["published"] = "2026-11-20T11:00:00.000"
    naive_cve["lastModified"] = "2026-11-20T12:00:00.000"
    pages = {
        0: [
            {"cve": naive_cve},
            {"cve": nvd_cve_record("CVE-2026-1235", status="Rejected")},
        ],
        2: [{"cve": nvd_cve_record("CVE-2026-1236")}],
    }
    requested_offsets: list[int] = []
    delays: list[float] = []
    monkeypatch.setattr(providers.time, "sleep", delays.append)

    def fake_fetch(url: str, *, max_bytes: int) -> providers.HttpResponse:
        assert url.startswith(providers.NVD_CVE_API_URL)
        assert max_bytes == providers.MAX_NVD_PAGE_BYTES
        query = parse_qs(urlsplit(url).query)
        start_index = int(query["startIndex"][0])
        requested_offsets.append(start_index)
        total_results = 3
        return providers.HttpResponse(
            json.dumps(
                {
                    "resultsPerPage": 2 if start_index == 0 else 1,
                    "startIndex": start_index,
                    "totalResults": total_results,
                    "vulnerabilities": pages[start_index],
                }
            ).encode("utf-8"),
            200,
            {},
        )

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    outcome = providers.sync_nvd()

    assert requested_offsets == [0, 2]
    assert delays == [providers.NVD_REQUEST_INTERVAL_SECONDS]
    assert outcome.provider == AdvisoryRecord.Provider.NVD
    assert outcome.status == SyncRun.Status.SUCCEEDED
    assert not outcome.coverage_complete
    assert outcome.records_processed == 3
    record = AdvisoryRecord.objects.get(external_id="CVE-2026-1234")
    assert record.source_modified_at == datetime(2026, 11, 20, 12, tzinfo=UTC)
    assert record.raw_record["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] == 9.8
    assert (
        record.raw_record["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"]
        == "2.0"
    )
    rejected = AdvisoryRecord.objects.get(external_id="CVE-2026-1235")
    assert not rejected.is_active
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.NVD)
    assert source.confirmed_cursor["coverage_complete"] is False
    assert "modified_until" in source.confirmed_cursor
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.NVD,
            mode=SyncRun.Mode.FULL,
            status=SyncRun.Status.SUCCEEDED,
        ).count()
        == 1
    )


def test_nvd_invalid_page_preserves_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cursor = {
        "coverage_complete": False,
        "coverage_start": "2026-10-20T00:00:00+00:00",
        "modified_until": "2026-11-20T08:00:00+00:00",
    }
    source = IntelligenceSource.objects.create(
        provider=AdvisoryRecord.Provider.NVD,
        confirmed_cursor=cursor,
    )

    def fake_fetch(url: str, *, max_bytes: int) -> providers.HttpResponse:
        del url, max_bytes
        return providers.HttpResponse(
            json.dumps(
                {
                    "resultsPerPage": 1,
                    "startIndex": 1,
                    "totalResults": 1,
                    "vulnerabilities": [],
                }
            ).encode("utf-8"),
            200,
            {},
        )

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    with pytest.raises(providers.ProviderSyncError, match="pagination metadata"):
        providers.sync_nvd()

    source.refresh_from_db()
    assert source.confirmed_cursor == cursor
    assert source.status == IntelligenceSource.Status.UNAVAILABLE
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.NVD,
            status=SyncRun.Status.FAILED,
        ).count()
        == 1
    )


def test_epss_sync_resumes_batches_and_stores_latest_scores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(providers, "EPSS_BATCH_SIZE", 1)
    monkeypatch.setattr(providers, "EPSS_MAX_BATCHES_PER_RUN", 1)
    for cve_id in ("CVE-2026-1234", "CVE-2026-1235"):
        vulnerability = Vulnerability.objects.create(canonical_id=cve_id)
        VulnerabilityAlias.objects.create(
            vulnerability=vulnerability,
            namespace=VulnerabilityAlias.Namespace.CVE,
            identifier=cve_id,
        )
    requests: list[str] = []

    def fake_fetch(url: str, *, max_bytes: int) -> providers.HttpResponse:
        assert url == providers.EPSS_FEED_URL
        assert max_bytes == providers.MAX_EPSS_RESPONSE_BYTES
        requests.append(url)
        return providers.HttpResponse(
            epss_response(["CVE-2026-1234", "CVE-2026-1235", "CVE-2026-9999"]), 200, {}
        )

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    first = providers.sync_epss()
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.EPSS)
    source.refresh_from_db()
    assert first.status == SyncRun.Status.PARTIAL
    assert first.continue_bootstrap
    assert source.status == IntelligenceSource.Status.UNAVAILABLE
    assert source.confirmed_cursor["resume_after"] == "CVE-2026-1234"

    second = providers.sync_epss()

    assert second.status == SyncRun.Status.PARTIAL
    assert not second.continue_bootstrap
    assert not second.coverage_complete
    assert requests == [providers.EPSS_FEED_URL, providers.EPSS_FEED_URL]
    assert AdvisoryRecord.objects.filter(provider=AdvisoryRecord.Provider.EPSS).count() == 2
    score = AdvisoryRecord.objects.get(external_id="CVE-2026-1234")
    assert score.raw_record["epss"] == 0.125
    assert score.raw_record["percentile"] == 0.75
    source.refresh_from_db()
    assert source.status == IntelligenceSource.Status.UNAVAILABLE
    assert source.confirmed_cursor["resume_after"] is None
    assert "last_completed_at" in source.confirmed_cursor
    assert "unverified" in source.last_error
    run = SyncRun.objects.filter(provider=AdvisoryRecord.Provider.EPSS).latest("started_at")
    assert run.records_fetched == run.records_processed == 1
    assert "unverified" in run.error_summary
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.EPSS,
            status=SyncRun.Status.PARTIAL,
        ).count()
        == 2
    )


def test_epss_sync_retains_scores_missing_from_feed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vulnerability = Vulnerability.objects.create(canonical_id="CVE-2026-1234")
    VulnerabilityAlias.objects.create(
        vulnerability=vulnerability,
        namespace=VulnerabilityAlias.Namespace.CVE,
        identifier="CVE-2026-1234",
    )
    old_score = AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.EPSS,
        external_id="CVE-2026-1234",
        raw_record={"epss": 0.9},
    )

    def fake_fetch(url: str, *, max_bytes: int) -> providers.HttpResponse:
        del url, max_bytes
        return providers.HttpResponse(epss_response(["CVE-2026-9999"]), 200, {})

    monkeypatch.setattr(providers, "_fetch_response", fake_fetch)

    outcome = providers.sync_epss()

    old_score.refresh_from_db()
    assert old_score.is_active
    assert old_score.raw_record == {"epss": 0.9}
    assert outcome.status == SyncRun.Status.PARTIAL
    assert not outcome.coverage_complete
    assert not outcome.continue_bootstrap
    assert outcome.records_processed == 0


def test_epss_older_feed_does_not_replace_newer_score(monkeypatch: pytest.MonkeyPatch) -> None:
    vulnerability = Vulnerability.objects.create(canonical_id="CVE-2026-1234")
    VulnerabilityAlias.objects.create(
        vulnerability=vulnerability,
        namespace=VulnerabilityAlias.Namespace.CVE,
        identifier="CVE-2026-1234",
    )
    newer = datetime(2026, 11, 21, tzinfo=UTC)
    record = AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.EPSS,
        external_id="CVE-2026-1234",
        source_modified_at=newer,
        raw_record={"epss": 0.9},
    )
    monkeypatch.setattr(
        providers,
        "_fetch_response",
        lambda *args, **kwargs: providers.HttpResponse(epss_response(["CVE-2026-1234"]), 200, {}),
    )

    outcome = providers.sync_epss()

    record.refresh_from_db()
    assert record.source_modified_at == newer
    assert record.raw_record == {"epss": 0.9}
    assert outcome.records_processed == 0


def test_epss_response_rejects_out_of_range_probability() -> None:
    payload = gzip.compress(
        b"#model_version:v5,score_date:2026-11-20\ncve,epss,percentile\nCVE-2026-1234,1.1,0.75\n"
    )
    with pytest.raises(providers.ProviderSyncError, match="outside the valid range"):
        providers._parse_epss_feed(payload, requested_ids={"CVE-2026-1234"})


@pytest.mark.parametrize(
    "content",
    [
        b"invalid gzip",
        epss_response(["CVE-2026-1234"])[:-4],
        gzip.compress(b"cve,epss,percentile\nCVE-2026-1234,0.1,0.2\n"),
        gzip.compress(b"#model_version:v5,score_date:bad\ncve,epss,percentile\n"),
        gzip.compress(b"#model_version:v5,score_date:2026-11-20\nwrong,header\n"),
        epss_response([]),
        epss_response(["CVE-2026-1234", "CVE-2026-1234"]),
        gzip.compress(
            b"#model_version:v5,score_date:2026-11-20\ncve,epss,percentile\n"
            b"CVE-2026-1234,0.1,0.2\nCVE-2026-1235,nan,0.2\n"
        ),
        gzip.compress(
            b"#model_version:v5,score_date:2026-11-20\ncve,epss,percentile\n"
            b'CVE-2026-1234,0.1,0.2\n"unterminated'
        ),
    ],
)
def test_epss_malformed_feed_fails_before_updates(
    monkeypatch: pytest.MonkeyPatch, content: bytes
) -> None:
    vulnerability = Vulnerability.objects.create(canonical_id="CVE-2026-1234")
    VulnerabilityAlias.objects.create(
        vulnerability=vulnerability,
        namespace=VulnerabilityAlias.Namespace.CVE,
        identifier="CVE-2026-1234",
    )
    old_score = AdvisoryRecord.objects.create(
        vulnerability=vulnerability,
        provider=AdvisoryRecord.Provider.EPSS,
        external_id="CVE-2026-1234",
        raw_record={"epss": 0.9},
    )
    cursor = {"resume_after": None, "coverage_complete": False}
    source = IntelligenceSource.objects.create(
        provider=AdvisoryRecord.Provider.EPSS, confirmed_cursor=cursor
    )
    monkeypatch.setattr(
        providers,
        "_fetch_response",
        lambda *args, **kwargs: providers.HttpResponse(content, 200, {}),
    )

    with pytest.raises(providers.ProviderSyncError):
        providers.sync_epss()

    old_score.refresh_from_db()
    source.refresh_from_db()
    assert old_score.is_active and old_score.raw_record == {"epss": 0.9}
    assert source.confirmed_cursor == cursor
    run = SyncRun.objects.get(provider=AdvisoryRecord.Provider.EPSS)
    assert run.status == SyncRun.Status.FAILED
    assert run.records_processed == 0


def test_epss_enforces_compressed_decompressed_and_row_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = epss_response(["CVE-2026-1234", "CVE-2026-1235"])
    monkeypatch.setattr(providers, "MAX_EPSS_RESPONSE_BYTES", len(payload) - 1)
    with pytest.raises(providers.ProviderSyncError, match="compressed feed"):
        providers._parse_epss_feed(payload, requested_ids=set())
    monkeypatch.setattr(providers, "MAX_EPSS_RESPONSE_BYTES", len(payload))
    monkeypatch.setattr(providers, "MAX_EPSS_UNCOMPRESSED_BYTES", 10)
    with pytest.raises(providers.ProviderSyncError, match="decompressed feed"):
        providers._parse_epss_feed(payload, requested_ids=set())
    monkeypatch.setattr(providers, "MAX_EPSS_UNCOMPRESSED_BYTES", 10000)
    monkeypatch.setattr(providers, "MAX_EPSS_ROWS", 1)
    with pytest.raises(providers.ProviderSyncError, match="row limit"):
        providers._parse_epss_feed(payload, requested_ids=set())


@pytest.mark.parametrize(
    "target",
    [
        "http://epss.empiricalsecurity.com/epss_scores-2026-11-20.csv.gz",
        "https://evil.example/epss_scores-2026-11-20.csv.gz",
        "https://epss.empiricalsecurity.com@evil.example/epss_scores-2026-11-20.csv.gz",
        "https://epss.empiricalsecurity.com/epss_scores-2026-11-20.csv.gz?cve=CVE-2026-1234",
        "https://epss.empiricalsecurity.com/other",
    ],
)
def test_epss_rejects_unsafe_redirects(target: str) -> None:
    handler = providers._EPSSRedirectHandler()
    with pytest.raises(providers.ProviderSyncError, match="unsafe redirect"):
        handler.redirect_request(Request(providers.EPSS_FEED_URL), None, 302, "", {}, target)


def test_epss_accepts_dated_redirect() -> None:
    handler = providers._EPSSRedirectHandler()
    target = "https://epss.empiricalsecurity.com/epss_scores-2026-11-20.csv.gz"
    redirected = handler.redirect_request(
        Request(providers.EPSS_FEED_URL), None, 302, "", {}, target
    )
    assert redirected.full_url == target


def test_epss_http_request_has_no_local_data_and_rejects_short_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Length": "10"}

    class Opener:
        def open(self, request: Request, *, timeout: int) -> Response:
            assert request.full_url == providers.EPSS_FEED_URL
            assert request.get_method() == "GET"
            assert request.data is None
            assert "CVE-" not in str(request.headers)
            assert timeout == providers.HTTP_TIMEOUT_SECONDS
            return Response(b"short")

    monkeypatch.setattr(providers, "build_opener", lambda handler: Opener())
    with pytest.raises(providers.ProviderSyncError, match="incomplete content length"):
        providers._fetch_response(providers.EPSS_FEED_URL, max_bytes=100)


def test_epss_fetch_reads_and_filters_feed_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    payload = epss_response(["CVE-2026-1234", "CVE-2026-9999"])

    class Response(io.BytesIO):
        status = 200
        headers = {"Content-Length": str(len(payload))}

    class Opener:
        def open(self, request: Request, *, timeout: int) -> Response:
            assert request.full_url == providers.EPSS_FEED_URL
            assert request.data is None
            assert timeout == providers.HTTP_TIMEOUT_SECONDS
            return Response(payload)

    monkeypatch.setattr(providers, "build_opener", lambda handler: Opener())
    scores = providers._fetch_epss_scores({"CVE-2026-1234"})
    assert len(scores) == 1
    assert scores[0].identifier == "CVE-2026-1234"
    assert scores[0].scored_on.isoformat() == "2026-11-20"


def test_epss_download_has_wall_clock_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    moments = iter([0.0, 0.0, float(providers.EPSS_DOWNLOAD_TIMEOUT_SECONDS)])
    monkeypatch.setattr(providers.time, "monotonic", lambda: next(moments))
    with pytest.raises(providers.ProviderSyncError, match="time limit"):
        providers._read_epss_response(io.BytesIO(b"data"), 100)


def test_epss_no_local_aliases_never_fetches(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        providers, "_fetch_response", lambda *args, **kwargs: pytest.fail("unexpected network")
    )
    outcome = providers.sync_epss()
    assert outcome.status == SyncRun.Status.PARTIAL
    assert not outcome.coverage_complete
    assert not outcome.continue_bootstrap


@pytest.mark.django_db(transaction=True)
def test_epss_task_finished_partial_does_not_loop(monkeypatch: pytest.MonkeyPatch) -> None:
    from ciclosec.intelligence import tasks

    vulnerability = Vulnerability.objects.create(canonical_id="CVE-2026-1234")
    VulnerabilityAlias.objects.create(
        vulnerability=vulnerability,
        namespace=VulnerabilityAlias.Namespace.CVE,
        identifier="CVE-2026-1234",
    )
    monkeypatch.setattr(
        providers,
        "_fetch_response",
        lambda *args, **kwargs: providers.HttpResponse(epss_response(["CVE-2026-1234"]), 200, {}),
    )
    continuations: list[object] = []
    reevaluations: list[bool] = []
    monkeypatch.setattr(
        tasks.sync_epss_task, "apply_async", lambda **kwargs: continuations.append(kwargs)
    )
    monkeypatch.setattr(tasks.reevaluate_findings_task, "delay", lambda: reevaluations.append(True))

    result = tasks.sync_epss_task.run()

    assert result["status"] == "partial"
    assert not result["coverage_complete"] and not result["continue_bootstrap"]
    assert not continuations
    assert reevaluations == [True]


def test_epss_failure_on_resume_keeps_checkpoint_and_previous_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(providers, "EPSS_BATCH_SIZE", 1)
    monkeypatch.setattr(providers, "EPSS_MAX_BATCHES_PER_RUN", 1)
    for identifier in ("CVE-2026-1234", "CVE-2026-1235"):
        vulnerability = Vulnerability.objects.create(canonical_id=identifier)
        VulnerabilityAlias.objects.create(
            vulnerability=vulnerability,
            namespace=VulnerabilityAlias.Namespace.CVE,
            identifier=identifier,
        )
    monkeypatch.setattr(
        providers,
        "_fetch_response",
        lambda *args, **kwargs: providers.HttpResponse(
            epss_response(["CVE-2026-1234", "CVE-2026-1235"]), 200, {}
        ),
    )
    assert providers.sync_epss().continue_bootstrap
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.EPSS)
    checkpoint = source.confirmed_cursor.copy()
    monkeypatch.setattr(
        providers,
        "_fetch_response",
        lambda *args, **kwargs: providers.HttpResponse(b"truncated", 200, {}),
    )
    with pytest.raises(providers.ProviderSyncError):
        providers.sync_epss()
    source.refresh_from_db()
    assert source.confirmed_cursor == checkpoint
    assert AdvisoryRecord.objects.filter(
        provider=AdvisoryRecord.Provider.EPSS, external_id="CVE-2026-1234"
    ).exists()
    assert not AdvisoryRecord.objects.filter(
        provider=AdvisoryRecord.Provider.EPSS, external_id="CVE-2026-1235"
    ).exists()


@pytest.mark.parametrize("status", [206, 304, 500])
def test_epss_rejects_non_full_http_response(monkeypatch: pytest.MonkeyPatch, status: int) -> None:
    monkeypatch.setattr(
        providers,
        "_fetch_response",
        lambda *args, **kwargs: providers.HttpResponse(
            epss_response(["CVE-2026-1234"]), status, {}
        ),
    )
    with pytest.raises(providers.ProviderSyncError, match="HTTP"):
        providers._fetch_epss_scores({"CVE-2026-1234"})


def test_cisa_failure_preserves_cursor_and_marks_prior_data_stale(
    monkeypatch: pytest.MonkeyPatch,
    kev_catalog: dict[str, object],
) -> None:
    payload = json.dumps(kev_catalog).encode("utf-8")
    monkeypatch.setattr(providers, "fetch_url", cisa_payload_fetch(payload))
    providers.sync_cisa_kev()
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.CISA_KEV)
    old_cursor = source.confirmed_cursor
    old_success = source.last_success_at

    monkeypatch.setattr(providers, "fetch_url", cisa_payload_fetch(b'{"count": 0}'))
    with pytest.raises(providers.ProviderSyncError, match="metadata is invalid"):
        providers.sync_cisa_kev()

    source.refresh_from_db()
    assert source.confirmed_cursor == old_cursor
    assert source.last_success_at == old_success
    assert source.status == IntelligenceSource.Status.STALE
    assert (
        SyncRun.objects.filter(
            provider=AdvisoryRecord.Provider.CISA_KEV,
            status=SyncRun.Status.FAILED,
        ).count()
        == 1
    )


def test_osv_bootstrap_resumes_by_checkpoint_and_handles_withdrawn_records(
    monkeypatch: pytest.MonkeyPatch,
    osv_feed: bytes,
    osv_records: dict[str, dict[str, object]],
) -> None:
    del osv_feed
    items = [
        providers.ModifiedRecord(
            modified_at=datetime.fromisoformat(timestamp),
            ecosystem="PyPI",
            identifier=identifier,
        )
        for timestamp, identifier in [
            ("2026-11-20T12:00:00+00:00", "PYSEC-2026-1"),
            ("2026-11-20T11:00:00+00:00", "PYSEC-2026-2"),
            ("2026-11-20T10:00:00+00:00", "PYSEC-2026-3"),
            ("2026-11-19T10:00:00+00:00", "PYSEC-2026-4"),
        ]
    ]
    monkeypatch.setattr(providers, "_iter_modified_records", lambda since: iter(items))
    monkeypatch.setattr(
        providers,
        "_fetch_osv_record",
        lambda item: osv_records[item.identifier],
    )

    outcome = providers.sync_osv()

    assert outcome.status == SyncRun.Status.SUCCEEDED
    assert outcome.coverage_complete
    assert Vulnerability.objects.count() == 4
    assert AdvisoryRecord.objects.filter(provider=AdvisoryRecord.Provider.OSV).count() == 4
    withdrawn = AdvisoryRecord.objects.get(
        provider=AdvisoryRecord.Provider.OSV,
        external_id="PYSEC-2026-4",
    )
    assert not withdrawn.is_active
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.OSV)
    source.refresh_from_db()
    assert source.confirmed_cursor["coverage_complete"] is True
    assert source.status == IntelligenceSource.Status.CURRENT


def test_osv_batches_resume_across_equal_timestamps_and_reordered_feed(
    monkeypatch: pytest.MonkeyPatch,
    osv_records: dict[str, dict[str, object]],
) -> None:
    timestamp = datetime(2026, 11, 20, 12, tzinfo=UTC)
    items = [
        providers.ModifiedRecord(timestamp, "PyPI", f"PYSEC-2026-{index}") for index in range(1, 5)
    ]
    monkeypatch.setattr(providers, "OSV_MAX_RECORDS_PER_RUN", 2)
    monkeypatch.setattr(providers, "_iter_modified_records", lambda since: iter(items))
    fetched: list[str] = []

    def fetch(item: providers.ModifiedRecord) -> dict[str, object]:
        fetched.append(item.identifier)
        return osv_records[item.identifier]

    monkeypatch.setattr(providers, "_fetch_osv_record", fetch)
    first = providers.sync_osv()
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.OSV)
    assert first.status == SyncRun.Status.PARTIAL
    assert first.continue_bootstrap
    assert not first.coverage_complete
    assert source.last_success_at is None
    assert source.confirmed_cursor["coverage_complete"] is False
    assert len(source.confirmed_cursor["osv_resume"]["paths"]) == 2

    items[:] = [items[1], items[2], items[0], items[3]]
    second = providers.sync_osv()

    source.refresh_from_db()
    assert second.status == SyncRun.Status.SUCCEEDED
    assert not second.continue_bootstrap
    assert source.confirmed_cursor["osv_resume"] is None
    assert source.confirmed_cursor["coverage_complete"] is True
    assert len(fetched) == 4
    assert len(set(fetched)) == 4
    assert AdvisoryRecord.objects.filter(provider=AdvisoryRecord.Provider.OSV).count() == 4


def test_osv_failed_batch_rolls_back_and_keeps_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    osv_records: dict[str, dict[str, object]],
) -> None:
    timestamp = datetime(2026, 11, 20, 12, tzinfo=UTC)
    items = [
        providers.ModifiedRecord(timestamp, "PyPI", f"PYSEC-2026-{index}") for index in range(1, 4)
    ]
    monkeypatch.setattr(providers, "OSV_MAX_RECORDS_PER_RUN", 1)
    monkeypatch.setattr(providers, "_iter_modified_records", lambda since: iter(items))
    monkeypatch.setattr(providers, "_fetch_osv_record", lambda item: osv_records[item.identifier])
    providers.sync_osv()
    source = IntelligenceSource.objects.get(provider=AdvisoryRecord.Provider.OSV)
    checkpoint = source.confirmed_cursor
    monkeypatch.setattr(providers, "OSV_MAX_RECORDS_PER_RUN", 2)

    def fail_second(item: providers.ModifiedRecord) -> dict[str, object]:
        if item.identifier == "PYSEC-2026-3":
            raise providers.ProviderSyncError("test failure")
        return osv_records[item.identifier]

    monkeypatch.setattr(providers, "_fetch_osv_record", fail_second)
    with pytest.raises(providers.ProviderSyncError, match="test failure"):
        providers.sync_osv()

    source.refresh_from_db()
    assert source.confirmed_cursor == checkpoint
    assert AdvisoryRecord.objects.filter(provider=AdvisoryRecord.Provider.OSV).count() == 1
    assert SyncRun.objects.filter(provider="osv", status=SyncRun.Status.FAILED).exists()


def test_osv_recovers_updates_arriving_during_a_partial_window(
    monkeypatch: pytest.MonkeyPatch,
    osv_records: dict[str, dict[str, object]],
) -> None:
    timestamp = datetime(2026, 11, 20, 12, tzinfo=UTC)
    items = [
        providers.ModifiedRecord(timestamp, "PyPI", "PYSEC-2026-1"),
        providers.ModifiedRecord(timestamp - timedelta(minutes=1), "PyPI", "PYSEC-2026-2"),
    ]
    monkeypatch.setattr(providers, "OSV_MAX_RECORDS_PER_RUN", 1)
    monkeypatch.setattr(
        providers,
        "_iter_modified_records",
        lambda since: (i for i in items if i.modified_at >= since),
    )
    monkeypatch.setattr(providers, "_fetch_osv_record", lambda item: osv_records[item.identifier])

    assert providers.sync_osv().continue_bootstrap
    items.insert(
        0, providers.ModifiedRecord(timestamp + timedelta(minutes=1), "PyPI", "PYSEC-2026-3")
    )
    assert not providers.sync_osv().continue_bootstrap
    assert not AdvisoryRecord.objects.filter(external_id="PYSEC-2026-3").exists()
    assert providers.sync_osv().continue_bootstrap
    assert AdvisoryRecord.objects.filter(external_id="PYSEC-2026-3").exists()


def test_http_fetch_retries_rate_limit_using_retry_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    delays: list[float] = []

    def fake_urlopen(request: Request, *, timeout: int) -> object:
        nonlocal calls
        assert request.full_url == "https://feed.example.test"
        assert timeout == providers.HTTP_TIMEOUT_SECONDS
        del timeout
        calls += 1
        if calls == 1:
            raise HTTPError(
                "https://feed.example.test",
                429,
                "Too Many Requests",
                {"Retry-After": "0"},
                None,
            )
        return io.BytesIO(b"ok")

    monkeypatch.setattr(providers, "urlopen", fake_urlopen)
    monkeypatch.setattr(providers.time, "sleep", delays.append)

    assert providers.fetch_url("https://feed.example.test", max_bytes=10) == b"ok"
    assert calls == 2
    assert delays == [0.0]


def test_permanent_http_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0

    def fake_urlopen(request: Request, *, timeout: int) -> object:
        nonlocal calls
        assert request.full_url == "https://feed.example.test"
        assert timeout == providers.HTTP_TIMEOUT_SECONDS
        calls += 1
        raise HTTPError("https://feed.example.test", 404, "Not Found", {}, None)

    monkeypatch.setattr(providers, "urlopen", fake_urlopen)

    with pytest.raises(providers.ProviderSyncError, match="HTTP 404"):
        providers.fetch_url("https://feed.example.test", max_bytes=10)
    assert calls == 1


def test_source_freshness_distinguishes_unknown_unavailable_stale_and_current() -> None:
    now = datetime(2026, 11, 20, 12, 0, tzinfo=UTC)
    provider = AdvisoryRecord.Provider.OSV

    assert get_source_freshness(provider, now=now).status == IntelligenceSource.Status.UNKNOWN
    source = IntelligenceSource.objects.create(
        provider=provider,
        status=IntelligenceSource.Status.UNAVAILABLE,
        last_attempt_at=now - timedelta(minutes=5),
        last_error="temporary outage",
    )
    assert get_source_freshness(provider, now=now).status == IntelligenceSource.Status.UNAVAILABLE

    source.last_success_at = now - timedelta(minutes=30)
    source.last_attempt_at = now - timedelta(minutes=30)
    source.status = IntelligenceSource.Status.CURRENT
    source.save()
    assert get_source_freshness(provider, now=now).status == IntelligenceSource.Status.CURRENT

    source.last_attempt_at = now - timedelta(minutes=10)
    source.last_error = "rate limited"
    source.save()
    assert get_source_freshness(provider, now=now).status == IntelligenceSource.Status.STALE

    source.last_attempt_at = now - timedelta(hours=25)
    source.last_success_at = now - timedelta(hours=25)
    source.last_error = ""
    source.save()
    assert get_source_freshness(provider, now=now).status == IntelligenceSource.Status.STALE
