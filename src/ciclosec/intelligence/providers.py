"""OSV and CISA KEV feeds with durable checkpoints and source provenance."""

from __future__ import annotations

import csv
import gzip
import io
import json
import math
import random
import re
import time
import zlib
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from http.client import IncompleteRead
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

from django.db import transaction
from django.utils import timezone

from ciclosec.intelligence.merging import (
    MergeConflict,
    group_ids,
    lock_alias_roots,
    merge_osv_equivalents,
    record_merge_references,
    root_id,
)
from ciclosec.intelligence.models import (
    AdvisoryRecord,
    IntelligenceSource,
    SyncRun,
    Vulnerability,
    VulnerabilityAlias,
    VulnerabilityMerge,
)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OSV_MODIFIED_IDS_URL = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
OSV_RECORD_BASE_URL = "https://storage.googleapis.com/osv-vulnerabilities"
GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_FEED_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MAX_CISA_BYTES = 32 * 1024 * 1024
MAX_OSV_RECORD_BYTES = 4 * 1024 * 1024
MAX_OSV_ROWS = 5_000_000
MAX_GITHUB_ADVISORY_BYTES = 8 * 1024 * 1024
GITHUB_ADVISORY_PAGE_SIZE = 100
GITHUB_ADVISORY_MAX_PAGES = 1000
GITHUB_ADVISORY_INITIAL_LOOKBACK = timedelta(days=30)
GITHUB_ADVISORY_INCREMENTAL_OVERLAP = timedelta(days=2)
MAX_NVD_PAGE_BYTES = 32 * 1024 * 1024
NVD_RESULTS_PER_PAGE = 2000
NVD_MAX_PAGES = 100
NVD_MAX_MODIFIED_WINDOW = timedelta(days=120)
NVD_INITIAL_LOOKBACK = timedelta(days=30)
NVD_INCREMENTAL_OVERLAP = timedelta(hours=1)
NVD_REQUEST_INTERVAL_SECONDS = 6.1
MAX_EPSS_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_EPSS_UNCOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_EPSS_ROWS = 1_000_000
EPSS_BATCH_SIZE = 50
EPSS_MAX_BATCHES_PER_RUN = 100
OSV_RANGE_CHUNK_SIZE = 1024 * 1024
OSV_INITIAL_LOOKBACK = timedelta(days=30)
OSV_INCREMENTAL_OVERLAP = timedelta(hours=1)
OSV_MAX_RECORDS_PER_RUN = 200
OSV_MAX_BOUNDARY_PATHS = 100_000
HTTP_ATTEMPTS = 4
HTTP_TIMEOUT_SECONDS = 30
EPSS_DOWNLOAD_TIMEOUT_SECONDS = 120
CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,19}$")
GHSA_PATTERN = re.compile(r"^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$")


class ProviderSyncError(RuntimeError):
    """A provider response or record cannot be safely synchronized."""


@dataclass(frozen=True)
class SyncOutcome:
    """Summary of a provider run."""

    provider: str
    status: str
    records_processed: int
    coverage_complete: bool = False
    continue_bootstrap: bool = False


@dataclass(frozen=True)
class ModifiedRecord:
    """One OSV record reference from the modified-ID feed."""

    modified_at: datetime
    ecosystem: str
    identifier: str


@dataclass(frozen=True)
class EPSSRecord:
    """Validated current EPSS score for one CVE."""

    identifier: str
    score: float
    percentile: float
    scored_on: date


@dataclass(frozen=True)
class HttpResponse:
    """Bounded HTTP response body and the metadata needed to validate ranges."""

    body: bytes
    status: int
    headers: Mapping[str, str]


class _EPSSRedirectHandler(HTTPRedirectHandler):
    """Allow only public EPSS feed URLs on the original HTTPS host."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> Any:
        target = urlsplit(newurl)
        if (
            target.scheme != "https"
            or target.netloc != "epss.empiricalsecurity.com"
            or target.query
            or target.fragment
            or not re.fullmatch(
                r"/epss_scores-(?:current|[0-9]{4}-[0-9]{2}-[0-9]{2})\.csv\.gz",
                target.path,
            )
        ):
            raise ProviderSyncError("EPSS refused an unsafe redirect")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _retry_delay(attempt: int, retry_after: str | None = None) -> float:
    if retry_after is not None:
        try:
            return min(60.0, max(0.0, float(retry_after)))
        except ValueError:
            pass
    exponential = min(30.0, 2.0**attempt)
    return exponential + random.uniform(0.0, exponential / 2)


def _read_epss_response(response: Any, max_bytes: int) -> bytes:
    deadline = time.monotonic() + EPSS_DOWNLOAD_TIMEOUT_SECONDS
    body = bytearray()
    while True:
        if time.monotonic() >= deadline:
            raise ProviderSyncError("EPSS download exceeded the time limit")
        chunk = response.read1(min(65536, max_bytes + 1 - len(body)))
        if not isinstance(chunk, bytes):
            raise ProviderSyncError("Provider response body is not bytes")
        body.extend(chunk)
        if len(body) > max_bytes:
            raise ProviderSyncError("Provider response exceeded the configured size limit")
        if time.monotonic() >= deadline:
            raise ProviderSyncError("EPSS download exceeded the time limit")
        if not chunk:
            return bytes(body)


def _fetch_response(
    url: str,
    *,
    max_bytes: int,
    headers: Mapping[str, str] | None = None,
) -> HttpResponse:
    """Fetch a bounded response, retrying transient failures with jitter."""
    for attempt in range(HTTP_ATTEMPTS):
        request_headers = {
            "Accept": "application/json,text/csv;q=0.9,*/*;q=0.1",
            "User-Agent": "CicloSec-intelligence-sync/0.1",
        }
        if headers is not None:
            request_headers.update(headers)
        request = Request(
            url,
            headers=request_headers,
        )
        try:
            open_request = (
                build_opener(_EPSSRedirectHandler()).open if url == EPSS_FEED_URL else urlopen
            )
            with open_request(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
                response_body = (
                    _read_epss_response(response, max_bytes)
                    if url == EPSS_FEED_URL
                    else response.read(max_bytes + 1)
                )
            response_status = getattr(response, "status", 200)
            response_header_object = getattr(response, "headers", {})
            response_headers = (
                dict(response_header_object.items())
                if hasattr(response_header_object, "items")
                else {}
            )
            if not isinstance(response_body, bytes):
                raise ProviderSyncError("Provider response body is not bytes")
            if not isinstance(response_status, int):
                raise ProviderSyncError("Provider returned an invalid HTTP status")
            if len(response_body) > max_bytes:
                raise ProviderSyncError("Provider response exceeded the configured size limit")
            if url == EPSS_FEED_URL:
                length = response.headers.get("Content-Length")
                if length is not None and (
                    len(length) > 20 or not length.isdecimal() or int(length) != len(response_body)
                ):
                    raise ProviderSyncError("EPSS response has an incomplete content length")
                if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                    raise ProviderSyncError("EPSS returned an unexpected content encoding")
            return HttpResponse(response_body, response_status, response_headers)
        except HTTPError as error:
            if error.code not in {408, 425, 429, 500, 502, 503, 504}:
                error.close()
                raise ProviderSyncError(f"Provider returned HTTP {error.code}") from None
            if attempt + 1 == HTTP_ATTEMPTS:
                error.close()
                message = f"Provider returned HTTP {error.code} after retries"
                raise ProviderSyncError(message) from None
            retry_after = error.headers.get("Retry-After")
            error.close()
            time.sleep(_retry_delay(attempt, retry_after))
        except (TimeoutError, URLError, OSError, IncompleteRead):
            if attempt + 1 == HTTP_ATTEMPTS:
                raise ProviderSyncError("Provider request failed after retries") from None
            time.sleep(_retry_delay(attempt))
        except ValueError:
            raise ProviderSyncError("Provider returned an invalid response or redirect") from None
    raise ProviderSyncError("Provider request failed after retries")


def fetch_url(url: str, *, max_bytes: int) -> bytes:
    """Fetch the body of a bounded provider response."""
    return _fetch_response(url, max_bytes=max_bytes).body


def _parse_timestamp(value: str, *, field: str, naive_utc: bool = False) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ProviderSyncError(f"Provider record has an invalid {field} timestamp") from None
    if parsed.tzinfo is None and naive_utc:
        parsed = parsed.replace(tzinfo=UTC)
    if parsed.tzinfo is None:
        raise ProviderSyncError(f"Provider record has a timezone-naive {field} timestamp")
    return parsed.astimezone(UTC)


def _namespace(identifier: str, *, is_osv_primary: bool = False) -> str:
    if CVE_PATTERN.fullmatch(identifier):
        return VulnerabilityAlias.Namespace.CVE
    if identifier.startswith("GHSA-"):
        return VulnerabilityAlias.Namespace.GHSA
    if identifier.startswith("OSV-") or is_osv_primary:
        return VulnerabilityAlias.Namespace.OSV
    return VulnerabilityAlias.Namespace.OTHER


def _resolve_vulnerability(
    identifiers: list[str],
    *,
    description: str,
    published_at: datetime | None,
    modified_at: datetime | None,
    osv_primary_identifier: str | None = None,
    osv_run: SyncRun | None = None,
) -> Vulnerability:
    cve_ids = sorted(identifier for identifier in identifiers if CVE_PATTERN.fullmatch(identifier))
    canonical_id = cve_ids[0] if cve_ids else identifiers[0]
    namespaces = {
        _namespace(identifier, is_osv_primary=identifier == osv_primary_identifier)
        for identifier in identifiers
    }
    aliases = list(
        VulnerabilityAlias.objects.select_related("vulnerability").filter(
            namespace__in=namespaces,
            identifier__in=identifiers,
        )
    )
    existing = {alias.vulnerability_id: alias.vulnerability for alias in aliases}
    try:
        lock_alias_roots(aliases)
    except MergeConflict as error:
        raise ProviderSyncError(str(error)) from error
    roots = {root_id(vulnerability) for vulnerability in existing.values()}
    merged = len(roots) > 1
    if merged:
        if osv_primary_identifier is None or osv_run is None:
            raise ProviderSyncError("Provider record aliases map to conflicting vulnerabilities")
        try:
            merge_osv_equivalents(
                existing.values(),
                identifiers=identifiers,
                evidence_id=osv_primary_identifier,
                run=osv_run,
            )
        except MergeConflict as error:
            raise ProviderSyncError(str(error)) from error
    vulnerability = next(
        (alias.vulnerability for alias in aliases if alias.identifier == identifiers[0]),
        next(iter(existing.values()), None),
    )
    if vulnerability is None:
        vulnerability, _ = Vulnerability.objects.get_or_create(canonical_id=canonical_id)
    if merged:
        vulnerability.refresh_from_db()

    updates: list[str] = []
    if description and not vulnerability.description:
        vulnerability.description = description
        updates.append("description")
    if published_at and (
        vulnerability.published_at is None or published_at < vulnerability.published_at
    ):
        vulnerability.published_at = published_at
        updates.append("published_at")
    if modified_at and (
        vulnerability.modified_at is None or modified_at > vulnerability.modified_at
    ):
        vulnerability.modified_at = modified_at
        updates.append("modified_at")
    if updates:
        vulnerability.save(update_fields=updates)

    for identifier in dict.fromkeys(identifiers):
        alias, created = VulnerabilityAlias.objects.get_or_create(
            namespace=_namespace(
                identifier,
                is_osv_primary=identifier == osv_primary_identifier,
            ),
            identifier=identifier,
            defaults={"vulnerability": vulnerability},
        )
        if not created and alias.vulnerability_id != vulnerability.pk:
            if alias.vulnerability_id not in group_ids(vulnerability):
                raise ProviderSyncError(
                    "Provider record alias conflicts with existing intelligence"
                )
    return vulnerability


def _reference_url(record: Mapping[str, Any]) -> str:
    references = record.get("references", [])
    if not isinstance(references, list):
        return ""
    for reference in references:
        if isinstance(reference, dict):
            url = reference.get("url")
            if isinstance(url, str) and url.startswith(("https://", "http://")):
                return url[:2048]
    return ""


def _upsert_osv_record(record: dict[str, Any], run: SyncRun) -> None:
    identifier = record.get("id")
    if not isinstance(identifier, str) or not identifier or len(identifier) > 255:
        raise ProviderSyncError("OSV record has an invalid identifier")
    aliases = record.get("aliases", [])
    if not isinstance(aliases, list) or any(
        not isinstance(alias, str) or not alias or len(alias) > 255 for alias in aliases
    ):
        raise ProviderSyncError("OSV record has an invalid alias list")
    modified = record.get("modified")
    if not isinstance(modified, str):
        raise ProviderSyncError("OSV record is missing its modified timestamp")
    modified_at = _parse_timestamp(modified, field="modified")
    published = record.get("published")
    if published is not None and not isinstance(published, str):
        raise ProviderSyncError("OSV record has an invalid published timestamp")
    published_at = _parse_timestamp(published, field="published") if published else None
    description = record.get("details", "")
    if not isinstance(description, str):
        raise ProviderSyncError("OSV record has an invalid description")

    with transaction.atomic():
        vulnerability = _resolve_vulnerability(
            [identifier, *aliases],
            description=description,
            published_at=published_at,
            modified_at=modified_at,
            osv_primary_identifier=identifier,
            osv_run=run,
        )
        AdvisoryRecord.objects.update_or_create(
            provider=AdvisoryRecord.Provider.OSV,
            external_id=identifier,
            defaults={
                "vulnerability": vulnerability,
                "source_url": _reference_url(record),
                "source_modified_at": modified_at,
                "raw_record": record,
                "is_active": not bool(record.get("withdrawn")),
                "last_seen_sync_run": run,
            },
        )
        for merge in VulnerabilityMerge.objects.filter(
            sync_run=run, evidence_id=identifier, references_recorded_at__isnull=True
        ):
            record_merge_references(merge)


def _parse_modified_row(line: bytes) -> ModifiedRecord | None:
    if not line:
        return None
    try:
        text = line.decode("utf-8")
        row = next(csv.reader([text]))
    except (UnicodeDecodeError, csv.Error, StopIteration):
        raise ProviderSyncError("OSV modified-ID feed has a malformed row") from None
    if len(row) != 2:
        raise ProviderSyncError("OSV modified-ID feed has an invalid row")
    modified_at = _parse_timestamp(row[0], field="modified-ID")
    path = row[1].split("/")
    if (
        len(path) != 2
        or not path[0]
        or not path[1]
        or path[0] in {".", ".."}
        or path[1] in {".", ".."}
    ):
        raise ProviderSyncError("OSV modified-ID feed has an invalid record path")
    return ModifiedRecord(modified_at, path[0], path[1])


def _iter_modified_records(since: datetime) -> Iterator[ModifiedRecord]:
    offset = 0
    total_size: int | None = None
    etag: str | None = None
    carry = b""
    previous_timestamp: datetime | None = None
    row_count = 0

    while total_size is None or offset < total_size:
        requested_end = offset + OSV_RANGE_CHUNK_SIZE - 1
        request_headers = {"Range": f"bytes={offset}-{requested_end}"}
        if etag is not None:
            request_headers["If-Match"] = etag
        response = _fetch_response(
            OSV_MODIFIED_IDS_URL,
            max_bytes=OSV_RANGE_CHUNK_SIZE,
            headers=request_headers,
        )
        content_range = response.headers.get("Content-Range", "")
        match = re.fullmatch(r"bytes ([0-9]+)-([0-9]+)/([0-9]+)", content_range)
        if response.status != 206 or match is None:
            raise ProviderSyncError("OSV storage did not honor the modified-ID range request")
        start, end, response_total = (int(value) for value in match.groups())
        if start != offset or end < start or end >= response_total:
            raise ProviderSyncError("OSV storage returned an invalid content range")
        response_etag = response.headers.get("ETag")
        if not response_etag or (etag is not None and response_etag != etag):
            raise ProviderSyncError("OSV modified-ID feed changed during a range download")
        etag = response_etag
        total_size = response_total
        expected_length = end - start + 1
        if len(response.body) != expected_length:
            raise ProviderSyncError("OSV storage returned a truncated content range")
        offset = end + 1

        lines = (carry + response.body).split(b"\n")
        carry = lines.pop() or b""
        for line in lines:
            row_count += 1
            if row_count > MAX_OSV_ROWS:
                raise ProviderSyncError("OSV modified-ID feed exceeds the row limit")
            item = _parse_modified_row(line.rstrip(b"\r"))
            if item is None:
                continue
            if previous_timestamp is not None and item.modified_at > previous_timestamp:
                raise ProviderSyncError(
                    "OSV modified-ID feed is not reverse chronologically sorted"
                )
            previous_timestamp = item.modified_at
            if item.modified_at < since:
                return
            yield item

    if carry:
        row_count += 1
        if row_count > MAX_OSV_ROWS:
            raise ProviderSyncError("OSV modified-ID feed exceeds the row limit")
        item = _parse_modified_row(carry.rstrip(b"\r"))
        if item is not None:
            if previous_timestamp is not None and item.modified_at > previous_timestamp:
                raise ProviderSyncError(
                    "OSV modified-ID feed is not reverse chronologically sorted"
                )
            if item.modified_at >= since:
                yield item


def _osv_record_url(item: ModifiedRecord) -> str:
    ecosystem = quote(item.ecosystem, safe="")
    identifier = quote(item.identifier, safe="")
    return f"{OSV_RECORD_BASE_URL}/{ecosystem}/{identifier}.json"


def _fetch_osv_record(item: ModifiedRecord) -> dict[str, Any]:
    payload = fetch_url(_osv_record_url(item), max_bytes=MAX_OSV_RECORD_BYTES)
    try:
        record = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderSyncError("OSV returned invalid JSON for a modified record") from None
    if not isinstance(record, dict) or record.get("id") != item.identifier:
        raise ProviderSyncError("OSV record does not match its modified-ID entry")
    return record


def _start_sync(provider: str, mode: str) -> tuple[IntelligenceSource, SyncRun]:
    source, _ = IntelligenceSource.objects.get_or_create(provider=provider)
    cursor = dict(source.confirmed_cursor)
    run = SyncRun.objects.create(
        provider=provider,
        mode=mode,
        cursor_before=cursor,
    )
    source.last_attempt_at = run.started_at
    source.status = (
        IntelligenceSource.Status.STALE
        if source.last_success_at
        else IntelligenceSource.Status.UNKNOWN
    )
    source.save(update_fields=["last_attempt_at", "status"])
    return source, run


def _save_cursor(source_id: int, updates: Mapping[str, Any]) -> dict[str, Any]:
    with transaction.atomic():
        source = IntelligenceSource.objects.select_for_update().get(pk=source_id)
        cursor = dict(source.confirmed_cursor)
        cursor.update(updates)
        source.confirmed_cursor = cursor
        source.save(update_fields=["confirmed_cursor"])
    return cursor


def _finish_success(
    source: IntelligenceSource,
    run: SyncRun,
    *,
    records_fetched: int,
    records_processed: int,
    source_updated_at: datetime | None,
    cursor: Mapping[str, Any],
    partial: bool = False,
    coverage_complete: bool = False,
) -> SyncOutcome:
    finished_at = timezone.now()
    run.status = SyncRun.Status.PARTIAL if partial else SyncRun.Status.SUCCEEDED
    run.completed_at = finished_at
    run.records_fetched = records_fetched
    run.records_processed = records_processed
    run.cursor_after = dict(cursor)
    run.save(
        update_fields=[
            "status",
            "completed_at",
            "records_fetched",
            "records_processed",
            "cursor_after",
        ]
    )
    source.status = (
        (
            IntelligenceSource.Status.STALE
            if source.last_success_at
            else IntelligenceSource.Status.UNAVAILABLE
        )
        if partial
        else IntelligenceSource.Status.CURRENT
    )
    source.last_error = ""
    source.source_updated_at = source_updated_at
    if not partial:
        source.last_success_at = finished_at
    source.save(
        update_fields=[
            "status",
            "last_error",
            "source_updated_at",
            "last_success_at",
        ]
    )
    return SyncOutcome(
        provider=run.provider,
        status=run.status,
        records_processed=records_processed,
        coverage_complete=coverage_complete,
        continue_bootstrap=partial,
    )


def _finish_failure(
    source: IntelligenceSource,
    run: SyncRun,
    error: ProviderSyncError,
    *,
    records_fetched: int = 0,
    records_processed: int = 0,
) -> None:
    source.refresh_from_db(fields=["last_success_at", "confirmed_cursor"])
    finished_at = timezone.now()
    run.status = SyncRun.Status.FAILED
    run.completed_at = finished_at
    run.records_fetched = records_fetched
    run.records_processed = records_processed
    run.records_failed = 1
    run.cursor_after = dict(source.confirmed_cursor)
    run.error_summary = str(error)[:1000]
    run.save(
        update_fields=[
            "status",
            "completed_at",
            "records_fetched",
            "records_processed",
            "records_failed",
            "cursor_after",
            "error_summary",
        ]
    )
    source.status = (
        IntelligenceSource.Status.STALE
        if source.last_success_at
        else IntelligenceSource.Status.UNAVAILABLE
    )
    source.last_error = str(error)[:1000]
    source.save(update_fields=["status", "last_error"])


def _decode_json(payload: bytes, *, source_name: str) -> dict[str, Any]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderSyncError(f"{source_name} returned invalid JSON") from None
    if not isinstance(document, dict):
        raise ProviderSyncError(f"{source_name} returned an invalid document")
    return document


def _decode_json_list(payload: bytes, *, source_name: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ProviderSyncError(f"{source_name} returned invalid JSON") from None
    if not isinstance(document, list) or any(not isinstance(item, dict) for item in document):
        raise ProviderSyncError(f"{source_name} returned an invalid list")
    return document


def _github_advisory_url(modified_since: datetime, after: str | None) -> str:
    modified = modified_since.astimezone(UTC).replace(microsecond=0)
    parameters: dict[str, str | int] = {
        "type": "reviewed",
        "modified": f">={modified.isoformat().replace('+00:00', 'Z')}",
        "per_page": GITHUB_ADVISORY_PAGE_SIZE,
        "sort": "updated",
        "direction": "desc",
    }
    if after is not None:
        parameters["after"] = after
    return f"{GITHUB_ADVISORIES_URL}?{urlencode(parameters)}"


def _github_advisory_next_cursor(headers: Mapping[str, str]) -> str | None:
    link_header = next((value for key, value in headers.items() if key.lower() == "link"), "")
    next_cursor: str | None = None
    for link in link_header.split(","):
        target, separator, relation = link.strip().partition(";")
        if not separator or 'rel="next"' not in relation:
            continue
        if next_cursor is not None or not target.startswith("<") or not target.endswith(">"):
            raise ProviderSyncError("GitHub Advisories returned invalid pagination")
        try:
            parsed = urlsplit(target[1:-1])
        except ValueError:
            raise ProviderSyncError("GitHub Advisories returned invalid pagination") from None
        if (
            parsed.scheme != "https"
            or parsed.netloc != "api.github.com"
            or parsed.path != "/advisories"
            or parsed.fragment
        ):
            raise ProviderSyncError("GitHub Advisories returned invalid pagination")
        cursors = parse_qs(parsed.query, keep_blank_values=True).get("after", [])
        if len(cursors) != 1 or not cursors[0] or len(cursors[0]) > 2048:
            raise ProviderSyncError("GitHub Advisories returned invalid pagination")
        next_cursor = cursors[0]
    return next_cursor


def _sanitize_github_advisory(
    item: Mapping[str, Any],
) -> tuple[str, list[str], datetime, datetime, dict[str, Any]]:
    ghsa_id = item.get("ghsa_id")
    if not isinstance(ghsa_id, str) or not GHSA_PATTERN.fullmatch(ghsa_id):
        raise ProviderSyncError("GitHub advisory has an invalid GHSA identifier")

    identifiers = [ghsa_id]
    raw_identifiers: list[dict[str, str]] = []
    provider_identifiers = item.get("identifiers") or []
    if not isinstance(provider_identifiers, list):
        raise ProviderSyncError("GitHub advisory has an invalid identifier list")
    for identifier in provider_identifiers:
        if not isinstance(identifier, dict):
            raise ProviderSyncError("GitHub advisory has an invalid identifier")
        kind = identifier.get("type")
        value = identifier.get("value")
        if kind not in {"CVE", "GHSA"}:
            continue
        pattern = CVE_PATTERN if kind == "CVE" else GHSA_PATTERN
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise ProviderSyncError("GitHub advisory has an invalid vulnerability identifier")
        identifiers.append(value)
        raw_identifiers.append({"type": kind, "value": value})

    cve_id = item.get("cve_id")
    if cve_id is not None:
        if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
            raise ProviderSyncError("GitHub advisory has an invalid CVE identifier")
        identifiers.append(cve_id)

    summary = item.get("summary")
    description = item.get("description")
    if (
        not isinstance(summary, str)
        or not summary
        or len(summary) > 1024
        or (description is not None and not isinstance(description, str))
    ):
        raise ProviderSyncError("GitHub advisory has invalid descriptive fields")
    published_value = item.get("published_at")
    updated_value = item.get("updated_at")
    if not isinstance(published_value, str) or not isinstance(updated_value, str):
        raise ProviderSyncError("GitHub advisory is missing a timestamp")
    published_at = _parse_timestamp(published_value, field="published")
    updated_at = _parse_timestamp(updated_value, field="updated")
    withdrawn_value = item.get("withdrawn_at")
    if withdrawn_value is not None and not isinstance(withdrawn_value, str):
        raise ProviderSyncError("GitHub advisory has an invalid withdrawal timestamp")
    withdrawn_at = _parse_timestamp(withdrawn_value, field="withdrawn") if withdrawn_value else None

    vulnerabilities = item.get("vulnerabilities") or []
    if not isinstance(vulnerabilities, list):
        raise ProviderSyncError("GitHub advisory has an invalid package list")
    sanitized_vulnerabilities: list[dict[str, Any]] = []
    for vulnerability in vulnerabilities:
        if not isinstance(vulnerability, dict):
            raise ProviderSyncError("GitHub advisory has an invalid package entry")
        package = vulnerability.get("package")
        if package is not None and not isinstance(package, dict):
            raise ProviderSyncError("GitHub advisory has an invalid package")
        package_data: dict[str, str] | None = None
        if package is not None:
            package_data = {}
            for key in ("ecosystem", "name"):
                value = package.get(key)
                if value is not None:
                    if not isinstance(value, str):
                        raise ProviderSyncError("GitHub advisory has an invalid package")
                    package_data[key] = value
        version_range = vulnerability.get("vulnerable_version_range")
        if version_range is not None and not isinstance(version_range, str):
            raise ProviderSyncError("GitHub advisory has an invalid version range")
        patched = vulnerability.get("first_patched_version")
        if patched is not None and not isinstance(patched, (dict, str)):
            raise ProviderSyncError("GitHub advisory has an invalid patched version")
        patched_id = patched.get("identifier") if isinstance(patched, dict) else patched
        if patched_id is not None and not isinstance(patched_id, str):
            raise ProviderSyncError("GitHub advisory has an invalid patched version")
        sanitized_vulnerabilities.append(
            {
                "package": package_data,
                "vulnerable_version_range": version_range,
                "first_patched_version": {"identifier": patched_id}
                if patched_id is not None
                else None,
            }
        )

    severity = item.get("severity")
    if severity is not None and not isinstance(severity, str):
        raise ProviderSyncError("GitHub advisory has an invalid severity")
    cvss = item.get("cvss_severities")
    if cvss is not None and not isinstance(cvss, dict):
        raise ProviderSyncError("GitHub advisory has invalid CVSS metadata")
    safe_cvss: dict[str, dict[str, Any]] = {}
    if isinstance(cvss, dict):
        for key in ("cvss_v3", "cvss_v4"):
            metric = cvss.get(key)
            if metric is None:
                continue
            if not isinstance(metric, dict):
                raise ProviderSyncError("GitHub advisory has invalid CVSS metadata")
            score = metric.get("score")
            vector = metric.get("vector_string")
            if score is not None and (
                not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not 0 <= score <= 10
            ):
                raise ProviderSyncError("GitHub advisory has an invalid CVSS score")
            if vector is not None and not isinstance(vector, str):
                raise ProviderSyncError("GitHub advisory has an invalid CVSS vector")
            safe_cvss[key] = {"score": score, "vector_string": vector}

    references = item.get("references") or []
    if not isinstance(references, list) or any(not isinstance(value, str) for value in references):
        raise ProviderSyncError("GitHub advisory has invalid references")
    raw_record = {
        "ghsa_id": ghsa_id,
        "identifiers": raw_identifiers,
        "summary": summary,
        "description": description,
        "severity": severity,
        "cvss_severities": safe_cvss,
        "published_at": published_at.isoformat(),
        "updated_at": updated_at.isoformat(),
        "withdrawn_at": withdrawn_at.isoformat() if withdrawn_at else None,
        "references": [reference[:2048] for reference in references[:100]],
        "vulnerabilities": sanitized_vulnerabilities,
    }
    return ghsa_id, list(dict.fromkeys(identifiers)), published_at, updated_at, raw_record


def sync_github_advisories() -> SyncOutcome:
    """Synchronize reviewed GitHub advisories over a bounded incremental window."""
    now = timezone.now()
    source_cursor = (
        IntelligenceSource.objects.filter(provider=AdvisoryRecord.Provider.GITHUB)
        .values_list("confirmed_cursor", flat=True)
        .first()
        or {}
    )
    previous_until_value = source_cursor.get("modified_until")
    previous_until = (
        _parse_timestamp(previous_until_value, field="checkpoint")
        if isinstance(previous_until_value, str)
        else None
    )
    modified_since = (
        previous_until - GITHUB_ADVISORY_INCREMENTAL_OVERLAP
        if previous_until is not None
        else now - GITHUB_ADVISORY_INITIAL_LOOKBACK
    )
    mode = SyncRun.Mode.INCREMENTAL if previous_until is not None else SyncRun.Mode.FULL
    source, run = _start_sync(AdvisoryRecord.Provider.GITHUB, mode)
    records_fetched = 0
    records_processed = 0
    modified_timestamps: list[datetime] = []
    processed_ids: set[str] = set()
    seen_cursors: set[str] = set()
    after: str | None = None
    try:
        for _ in range(GITHUB_ADVISORY_MAX_PAGES):
            response = _fetch_response(
                _github_advisory_url(modified_since, after),
                max_bytes=MAX_GITHUB_ADVISORY_BYTES,
                headers={
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2026-03-10",
                },
            )
            if response.status != 200:
                raise ProviderSyncError(f"GitHub Advisories returned HTTP {response.status}")
            advisories = _decode_json_list(response.body, source_name="GitHub Advisories")
            if len(advisories) > GITHUB_ADVISORY_PAGE_SIZE:
                raise ProviderSyncError("GitHub Advisories exceeded the requested page size")
            records_fetched += len(advisories)
            for advisory in advisories:
                ghsa_id, identifiers, published_at, updated_at, raw_record = (
                    _sanitize_github_advisory(advisory)
                )
                modified_timestamps.append(updated_at)
                if ghsa_id in processed_ids:
                    continue
                with transaction.atomic():
                    vulnerability = _resolve_vulnerability(
                        identifiers,
                        description=raw_record["description"] or raw_record["summary"],
                        published_at=published_at,
                        modified_at=updated_at,
                    )
                    AdvisoryRecord.objects.update_or_create(
                        provider=AdvisoryRecord.Provider.GITHUB,
                        external_id=ghsa_id,
                        defaults={
                            "vulnerability": vulnerability,
                            "source_url": f"https://github.com/advisories/{ghsa_id}",
                            "source_modified_at": updated_at,
                            "raw_record": raw_record,
                            "is_active": raw_record["withdrawn_at"] is None,
                            "last_seen_sync_run": run,
                        },
                    )
                processed_ids.add(ghsa_id)
                records_processed += 1
            after = _github_advisory_next_cursor(response.headers)
            if after is None:
                break
            if after in seen_cursors:
                raise ProviderSyncError("GitHub Advisories returned repeated pagination")
            seen_cursors.add(after)
        else:
            raise ProviderSyncError("GitHub Advisories exceeded the page limit")

        cursor = _save_cursor(
            source.pk,
            {
                "coverage_complete": False,
                "coverage_start": source_cursor.get(
                    "coverage_start",
                    modified_since.isoformat(),
                ),
                "modified_until": now.isoformat(),
            },
        )
        newest = max(modified_timestamps) if modified_timestamps else None
        return _finish_success(
            source,
            run,
            records_fetched=records_fetched,
            records_processed=records_processed,
            source_updated_at=newest,
            cursor=cursor,
            coverage_complete=False,
        )
    except ProviderSyncError as error:
        _finish_failure(
            source,
            run,
            error,
            records_fetched=records_fetched,
            records_processed=records_processed,
        )
        raise


def _nvd_modified_windows(
    start: datetime,
    end: datetime,
) -> Iterator[tuple[datetime, datetime]]:
    if start.tzinfo is None or end.tzinfo is None or start > end:
        raise ProviderSyncError("NVD modified-date window is invalid")
    current = start.astimezone(UTC)
    window_end_limit = end.astimezone(UTC)
    while current <= window_end_limit:
        window_end = min(current + NVD_MAX_MODIFIED_WINDOW, window_end_limit)
        yield current, window_end
        current = window_end + timedelta(seconds=1)


def _nvd_request_url(start: datetime, end: datetime, start_index: int) -> str:
    query = urlencode(
        {
            "lastModStartDate": start.isoformat().replace("+00:00", "Z"),
            "lastModEndDate": end.isoformat().replace("+00:00", "Z"),
            "resultsPerPage": NVD_RESULTS_PER_PAGE,
            "startIndex": start_index,
        }
    )
    return f"{NVD_CVE_API_URL}?{query}"


def _validate_nvd_page(
    document: dict[str, Any],
    *,
    expected_start_index: int,
) -> tuple[int, list[dict[str, Any]]]:
    page_size = document.get("resultsPerPage")
    start_index = document.get("startIndex")
    total_results = document.get("totalResults")
    vulnerabilities = document.get("vulnerabilities")
    if (
        not isinstance(page_size, int)
        or isinstance(page_size, bool)
        or page_size < 0
        or page_size > NVD_RESULTS_PER_PAGE
        or not isinstance(start_index, int)
        or isinstance(start_index, bool)
        or start_index != expected_start_index
        or not isinstance(total_results, int)
        or isinstance(total_results, bool)
        or total_results < 0
        or not isinstance(vulnerabilities, list)
        or any(not isinstance(item, dict) for item in vulnerabilities)
        or len(vulnerabilities) > page_size
        or expected_start_index + len(vulnerabilities) > total_results
        or (total_results == 0 and vulnerabilities)
        or (total_results > 0 and expected_start_index >= total_results)
        or (expected_start_index < total_results and not vulnerabilities)
    ):
        raise ProviderSyncError("NVD CVE response has invalid pagination metadata")
    return total_results, vulnerabilities


def _sanitize_nvd_cve(
    cve: Mapping[str, Any],
) -> tuple[str, datetime, datetime, str, dict[str, Any], bool]:
    cve_id = cve.get("id")
    published_value = cve.get("published")
    modified_value = cve.get("lastModified")
    if not isinstance(cve_id, str) or not CVE_PATTERN.fullmatch(cve_id):
        raise ProviderSyncError("NVD record has an invalid CVE identifier")
    if not isinstance(published_value, str) or not isinstance(modified_value, str):
        raise ProviderSyncError("NVD record is missing a timestamp")
    # NVD specifies zero-offset UTC for all API response datetimes.
    published_at = _parse_timestamp(published_value, field="published", naive_utc=True)
    modified_at = _parse_timestamp(modified_value, field="last modified", naive_utc=True)

    raw_descriptions = cve.get("descriptions") or []
    if not isinstance(raw_descriptions, list):
        raise ProviderSyncError("NVD record has an invalid description list")
    descriptions: list[dict[str, str]] = []
    for description in raw_descriptions:
        if not isinstance(description, dict):
            raise ProviderSyncError("NVD record has an invalid description")
        language = description.get("lang")
        value = description.get("value")
        if not isinstance(language, str) or not isinstance(value, str):
            raise ProviderSyncError("NVD record has an invalid description")
        descriptions.append({"lang": language, "value": value})
    description = next(
        (item["value"] for item in descriptions if item["lang"] == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    raw_metrics = cve.get("metrics") or {}
    if not isinstance(raw_metrics, dict):
        raise ProviderSyncError("NVD record has invalid CVSS metrics")
    metrics: dict[str, list[dict[str, Any]]] = {}
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        raw_metric_entries = raw_metrics.get(metric_name) or []
        if not isinstance(raw_metric_entries, list):
            raise ProviderSyncError("NVD record has invalid CVSS metrics")
        safe_entries: list[dict[str, Any]] = []
        for entry in raw_metric_entries:
            if not isinstance(entry, dict):
                raise ProviderSyncError("NVD record has an invalid CVSS metric")
            cvss_data = entry.get("cvssData")
            if not isinstance(cvss_data, dict):
                raise ProviderSyncError("NVD record has an invalid CVSS metric")
            score = cvss_data.get("baseScore")
            severity = cvss_data.get("baseSeverity")
            vector = cvss_data.get("vectorString")
            if score is not None and (
                not isinstance(score, (int, float))
                or isinstance(score, bool)
                or not 0 <= score <= 10
            ):
                raise ProviderSyncError("NVD record has an invalid CVSS score")
            if severity is not None and not isinstance(severity, str):
                raise ProviderSyncError("NVD record has an invalid CVSS severity")
            if vector is not None and not isinstance(vector, str):
                raise ProviderSyncError("NVD record has an invalid CVSS vector")
            safe_entries.append(
                {
                    "type": entry.get("type"),
                    "cvssData": {
                        "baseScore": score,
                        "baseSeverity": severity,
                        "vectorString": vector,
                    },
                }
            )
        if safe_entries:
            metrics[metric_name] = safe_entries

    configurations = cve.get("configurations") or []
    weaknesses = cve.get("weaknesses") or []
    raw_references = cve.get("references") or []
    if (
        not isinstance(configurations, list)
        or any(not isinstance(item, dict) for item in configurations)
        or not isinstance(weaknesses, list)
        or any(not isinstance(item, dict) for item in weaknesses)
        or not isinstance(raw_references, list)
    ):
        raise ProviderSyncError("NVD record has invalid applicability metadata")
    references: list[dict[str, Any]] = []
    for reference in raw_references[:100]:
        if not isinstance(reference, dict):
            raise ProviderSyncError("NVD record has an invalid reference")
        url = reference.get("url")
        if not isinstance(url, str) or not url.startswith(("https://", "http://")):
            continue
        source = reference.get("source")
        tags = reference.get("tags") or []
        if source is not None and not isinstance(source, str):
            raise ProviderSyncError("NVD record has an invalid reference")
        if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
            raise ProviderSyncError("NVD record has an invalid reference")
        references.append({"url": url[:2048], "source": source, "tags": tags[:20]})

    status = cve.get("vulnStatus")
    if status is not None and not isinstance(status, str):
        raise ProviderSyncError("NVD record has an invalid vulnerability status")
    raw_record = {
        "id": cve_id,
        "published": published_at.isoformat(),
        "lastModified": modified_at.isoformat(),
        "vulnStatus": status,
        "descriptions": descriptions,
        "metrics": metrics,
        "configurations": configurations,
        "weaknesses": weaknesses,
        "references": references,
    }
    return (
        cve_id,
        published_at,
        modified_at,
        description,
        raw_record,
        status is None or status.casefold() != "rejected",
    )


def sync_nvd() -> SyncOutcome:
    """Synchronize NVD CVEs changed in a bounded window using offset pagination."""
    now = timezone.now().astimezone(UTC)
    source_cursor = (
        IntelligenceSource.objects.filter(provider=AdvisoryRecord.Provider.NVD)
        .values_list("confirmed_cursor", flat=True)
        .first()
        or {}
    )
    previous_until_value = source_cursor.get("modified_until")
    mode = SyncRun.Mode.INCREMENTAL if previous_until_value is not None else SyncRun.Mode.FULL
    source, run = _start_sync(AdvisoryRecord.Provider.NVD, mode)
    records_fetched = 0
    records_processed = 0
    request_count = 0
    processed_modified: dict[str, datetime] = {}
    modified_timestamps: list[datetime] = []
    try:
        if previous_until_value is None:
            modified_since = now - NVD_INITIAL_LOOKBACK
        elif isinstance(previous_until_value, str):
            modified_since = (
                _parse_timestamp(previous_until_value, field="checkpoint") - NVD_INCREMENTAL_OVERLAP
            )
        else:
            raise ProviderSyncError("NVD cursor has an invalid checkpoint")
        if modified_since > now:
            raise ProviderSyncError("NVD cursor is ahead of the system clock")

        coverage_start_value = source_cursor.get("coverage_start")
        if coverage_start_value is None:
            coverage_start = modified_since.isoformat()
        elif isinstance(coverage_start_value, str):
            _parse_timestamp(coverage_start_value, field="coverage start")
            coverage_start = coverage_start_value
        else:
            raise ProviderSyncError("NVD cursor has an invalid coverage start")

        for window_start, window_end in _nvd_modified_windows(modified_since, now):
            start_index = 0
            for _ in range(NVD_MAX_PAGES):
                if request_count:
                    time.sleep(NVD_REQUEST_INTERVAL_SECONDS)
                response = _fetch_response(
                    _nvd_request_url(window_start, window_end, start_index),
                    max_bytes=MAX_NVD_PAGE_BYTES,
                )
                request_count += 1
                if response.status != 200:
                    raise ProviderSyncError(f"NVD returned HTTP {response.status}")
                document = _decode_json(response.body, source_name="NVD")
                total_results, entries = _validate_nvd_page(
                    document,
                    expected_start_index=start_index,
                )
                records_fetched += len(entries)
                for entry in entries:
                    raw_cve = entry.get("cve")
                    if not isinstance(raw_cve, dict):
                        raise ProviderSyncError("NVD returned an invalid CVE record")
                    (
                        cve_id,
                        published_at,
                        modified_at,
                        description,
                        raw_record,
                        is_active,
                    ) = _sanitize_nvd_cve(raw_cve)
                    modified_timestamps.append(modified_at)
                    previous_modified = processed_modified.get(cve_id)
                    if previous_modified is not None and previous_modified >= modified_at:
                        continue
                    with transaction.atomic():
                        vulnerability = _resolve_vulnerability(
                            [cve_id],
                            description=description,
                            published_at=published_at,
                            modified_at=modified_at,
                        )
                        AdvisoryRecord.objects.update_or_create(
                            provider=AdvisoryRecord.Provider.NVD,
                            external_id=cve_id,
                            defaults={
                                "vulnerability": vulnerability,
                                "source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                                "source_modified_at": modified_at,
                                "raw_record": raw_record,
                                "is_active": is_active,
                                "last_seen_sync_run": run,
                            },
                        )
                    processed_modified[cve_id] = modified_at
                    records_processed += 1
                start_index += len(entries)
                if start_index >= total_results:
                    break
                if not entries:
                    raise ProviderSyncError("NVD returned an incomplete paginated response")
            else:
                raise ProviderSyncError("NVD exceeded the page limit")

        cursor = _save_cursor(
            source.pk,
            {
                "coverage_complete": False,
                "coverage_start": coverage_start,
                "modified_until": now.isoformat(),
            },
        )
        newest = max(modified_timestamps) if modified_timestamps else None
        return _finish_success(
            source,
            run,
            records_fetched=records_fetched,
            records_processed=records_processed,
            source_updated_at=newest,
            cursor=cursor,
            coverage_complete=False,
        )
    except ProviderSyncError as error:
        _finish_failure(
            source,
            run,
            error,
            records_fetched=records_fetched,
            records_processed=records_processed,
        )
        raise


def _iter_epss_cve_batches(after: str | None) -> Iterator[list[str]]:
    aliases = VulnerabilityAlias.objects.filter(
        namespace=VulnerabilityAlias.Namespace.CVE,
    )
    if after is not None:
        aliases = aliases.filter(identifier__gt=after)
    batch: list[str] = []
    for identifier in (
        aliases.order_by("identifier")
        .values_list(
            "identifier",
            flat=True,
        )
        .iterator(chunk_size=1000)
    ):
        if not CVE_PATTERN.fullmatch(identifier):
            raise ProviderSyncError("EPSS lookup found an invalid CVE alias")
        batch.append(identifier)
        if len(batch) == EPSS_BATCH_SIZE:
            yield batch
            batch = []
    if batch:
        yield batch


def _parse_epss_feed(payload: bytes, *, requested_ids: set[str]) -> list[EPSSRecord]:
    """Validate the bounded gzip CSV before using any locally matched scores.

    The feed has no independently verifiable row count; a valid gzip and CSV
    do not establish completeness, so missing scores must never be removed.
    """
    if len(payload) > MAX_EPSS_RESPONSE_BYTES:
        raise ProviderSyncError("EPSS compressed feed exceeded the size limit")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as archive:
            data = archive.read(MAX_EPSS_UNCOMPRESSED_BYTES + 1)
        if len(data) > MAX_EPSS_UNCOMPRESSED_BYTES:
            raise ProviderSyncError("EPSS decompressed feed exceeded the size limit")
        text = data.decode("utf-8")
    except (OSError, EOFError, UnicodeDecodeError, ValueError, zlib.error):
        raise ProviderSyncError("EPSS returned an invalid gzip or UTF-8 feed") from None

    lines = io.StringIO(text, newline="")
    metadata = lines.readline().strip()
    match = re.fullmatch(r"#model_version:([^,\s]+),score_date:([^,\s]+)", metadata)
    if not match:
        raise ProviderSyncError("EPSS returned invalid feed metadata")
    date_value = match.group(2)
    try:
        if len(date_value) == 10:
            scored_on = date.fromisoformat(date_value)
        else:
            timestamp = datetime.fromisoformat(date_value.replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                raise ValueError
            scored_on = timestamp.astimezone(UTC).date()
    except ValueError:
        raise ProviderSyncError("EPSS returned an invalid score date") from None

    reader = csv.reader(lines, strict=True)
    scores: list[EPSSRecord] = []
    seen: set[str] = set()
    try:
        if next(reader, None) != ["cve", "epss", "percentile"]:
            raise ProviderSyncError("EPSS returned an invalid CSV header")
        count = 0
        for row in reader:
            count += 1
            if count > MAX_EPSS_ROWS:
                raise ProviderSyncError("EPSS feed exceeded the row limit")
            if len(row) != 3 or not CVE_PATTERN.fullmatch(row[0]):
                raise ProviderSyncError("EPSS returned an invalid score record")
            identifier, score_value, percentile_value = row
            score = float(score_value)
            percentile = float(percentile_value)
            if (
                not math.isfinite(score)
                or not 0 <= score <= 1
                or not math.isfinite(percentile)
                or not 0 <= percentile <= 1
            ):
                raise ProviderSyncError("EPSS returned a score outside the valid range")
            if identifier in seen:
                raise ProviderSyncError("EPSS returned a duplicate CVE")
            seen.add(identifier)
            if identifier in requested_ids:
                scores.append(EPSSRecord(identifier, score, percentile, scored_on))
        if not count:
            raise ProviderSyncError("EPSS returned an empty feed")
    except (csv.Error, ValueError, OverflowError):
        raise ProviderSyncError("EPSS returned an invalid CSV score") from None
    return scores


def _fetch_epss_scores(requested_ids: set[str]) -> list[EPSSRecord]:
    response = _fetch_response(
        EPSS_FEED_URL,
        max_bytes=MAX_EPSS_RESPONSE_BYTES,
    )
    if response.status != 200:
        raise ProviderSyncError(f"EPSS returned HTTP {response.status}")
    return _parse_epss_feed(response.body, requested_ids=requested_ids)


def sync_epss() -> SyncOutcome:
    """Refresh local CVEs; feed completeness is unverified and absences are retained.

    A completed cursor means only that local aliases were visited, not that
    the feed had complete coverage. Continuation is needed only for more batches.
    """
    cursor_before = dict(
        IntelligenceSource.objects.filter(provider=AdvisoryRecord.Provider.EPSS)
        .values_list("confirmed_cursor", flat=True)
        .first()
        or {}
    )
    resume_after_value = cursor_before.get("resume_after")
    source, run = _start_sync(AdvisoryRecord.Provider.EPSS, SyncRun.Mode.FULL)
    records_fetched = 0
    records_processed = 0
    modified_dates: list[datetime] = []
    try:
        if EPSS_BATCH_SIZE < 1 or EPSS_MAX_BATCHES_PER_RUN < 1:
            raise ProviderSyncError("EPSS batch limits are invalid")
        if resume_after_value is None:
            resume_after = None
        elif isinstance(resume_after_value, str) and CVE_PATTERN.fullmatch(resume_after_value):
            resume_after = resume_after_value
        else:
            raise ProviderSyncError("EPSS cursor has an invalid resume checkpoint")

        batches: list[list[str]] = []
        has_more = False
        for batch in _iter_epss_cve_batches(resume_after):
            if len(batches) == EPSS_MAX_BATCHES_PER_RUN:
                has_more = True
                break
            batches.append(batch)
        requested_ids = {identifier for batch in batches for identifier in batch}
        scores = _fetch_epss_scores(requested_ids) if batches else []
        scores_by_id = {score.identifier: score for score in scores}
        cursor = cursor_before
        for batch in batches:
            batch_scores = [
                scores_by_id[identifier] for identifier in batch if identifier in scores_by_id
            ]
            aliases = {
                alias.identifier: alias
                for alias in VulnerabilityAlias.objects.select_related("vulnerability").filter(
                    namespace=VulnerabilityAlias.Namespace.CVE,
                    identifier__in=batch,
                )
            }
            if len(aliases) != len(batch):
                raise ProviderSyncError("EPSS CVE aliases changed during synchronization")

            with transaction.atomic():
                for score in batch_scores:
                    alias = aliases[score.identifier]
                    scored_at = datetime.combine(score.scored_on, datetime.min.time(), UTC)
                    modified_dates.append(scored_at)
                    existing = (
                        AdvisoryRecord.objects.select_for_update()
                        .filter(
                            provider=AdvisoryRecord.Provider.EPSS,
                            external_id=score.identifier,
                        )
                        .first()
                    )
                    if (
                        existing is not None
                        and existing.source_modified_at is not None
                        and existing.source_modified_at.astimezone(UTC).date() > score.scored_on
                    ):
                        modified_dates.append(existing.source_modified_at)
                        continue
                    AdvisoryRecord.objects.update_or_create(
                        provider=AdvisoryRecord.Provider.EPSS,
                        external_id=score.identifier,
                        defaults={
                            "vulnerability": alias.vulnerability,
                            "source_url": "https://www.first.org/epss/",
                            "source_modified_at": scored_at,
                            "raw_record": {
                                "cve": score.identifier,
                                "epss": score.score,
                                "percentile": score.percentile,
                                "date": score.scored_on.isoformat(),
                            },
                            "is_active": True,
                            "last_seen_sync_run": run,
                        },
                    )
                    records_processed += 1
            records_fetched += len(batch_scores)
            cursor = _save_cursor(
                source.pk,
                {
                    "coverage_complete": False,
                    "resume_after": batch[-1],
                },
            )

        if source.source_updated_at is not None:
            modified_dates.append(source.source_updated_at)
        newest = max(modified_dates) if modified_dates else None
        if not has_more:
            cursor = _save_cursor(
                source.pk,
                {
                    "coverage_complete": False,
                    "resume_after": None,
                    "last_completed_at": timezone.now().isoformat(),
                },
            )
        _finish_success(
            source,
            run,
            records_fetched=records_fetched,
            records_processed=records_processed,
            source_updated_at=newest,
            cursor=cursor,
            partial=True,
            coverage_complete=False,
        )
        reason = "EPSS feed completeness is unverified; absent scores are retained"
        SyncRun.objects.filter(pk=run.pk).update(error_summary=reason)
        IntelligenceSource.objects.filter(pk=source.pk).update(last_error=reason)
        return SyncOutcome(
            provider=run.provider,
            status=SyncRun.Status.PARTIAL,
            records_processed=records_processed,
            coverage_complete=False,
            continue_bootstrap=has_more,
        )
    except ProviderSyncError as error:
        _finish_failure(
            source,
            run,
            error,
            records_fetched=records_fetched,
            records_processed=records_processed,
        )
        raise


def _validate_kev_catalog(document: dict[str, Any]) -> tuple[str, datetime, list[dict[str, Any]]]:
    version = document.get("catalogVersion")
    released = document.get("dateReleased")
    vulnerabilities = document.get("vulnerabilities")
    count = document.get("count")
    if (
        not isinstance(version, str)
        or not version
        or not isinstance(released, str)
        or not isinstance(vulnerabilities, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(vulnerabilities)
    ):
        raise ProviderSyncError("CISA KEV catalog metadata is invalid")
    released_at = _parse_timestamp(released, field="catalog release")
    for item in vulnerabilities:
        if not isinstance(item, dict):
            raise ProviderSyncError("CISA KEV catalog contains an invalid entry")
        cve_id = item.get("cveID")
        required = (
            "vendorProject",
            "product",
            "vulnerabilityName",
            "dateAdded",
            "shortDescription",
            "requiredAction",
            "dueDate",
        )
        if (
            not isinstance(cve_id, str)
            or not CVE_PATTERN.fullmatch(cve_id)
            or any(not isinstance(item.get(key), str) or not item[key] for key in required)
        ):
            raise ProviderSyncError("CISA KEV catalog contains an invalid entry")
        try:
            date.fromisoformat(item["dateAdded"])
            date.fromisoformat(item["dueDate"])
        except ValueError:
            raise ProviderSyncError("CISA KEV catalog contains an invalid date") from None
    return version, released_at, vulnerabilities


def _kev_reference(item: Mapping[str, Any]) -> str:
    notes = item.get("notes", "")
    if not isinstance(notes, str):
        return ""
    match = re.search(r"https?://[^\s;]+", notes)
    return match.group(0)[:2048] if match else ""


def sync_cisa_kev() -> SyncOutcome:
    """Fetch and transactionally reconcile the complete CISA KEV snapshot."""
    source, run = _start_sync(AdvisoryRecord.Provider.CISA_KEV, SyncRun.Mode.FULL)
    try:
        payload = fetch_url(CISA_KEV_URL, max_bytes=MAX_CISA_BYTES)
        document = _decode_json(payload, source_name="CISA")
        version, released_at, entries = _validate_kev_catalog(document)
        cursor = {
            "catalog_version": version,
            "coverage_complete": True,
            "date_released": released_at.isoformat(),
        }
        processed = 0
        with transaction.atomic():
            for entry in entries:
                cve_id = entry["cveID"]
                added_at = datetime.combine(
                    date.fromisoformat(entry["dateAdded"]),
                    datetime.min.time(),
                    UTC,
                )
                vulnerability = _resolve_vulnerability(
                    [cve_id],
                    description=entry["shortDescription"],
                    published_at=None,
                    modified_at=added_at,
                )
                AdvisoryRecord.objects.update_or_create(
                    provider=AdvisoryRecord.Provider.CISA_KEV,
                    external_id=cve_id,
                    defaults={
                        "vulnerability": vulnerability,
                        "source_url": _kev_reference(entry),
                        "source_modified_at": added_at,
                        "raw_record": entry,
                        "is_active": True,
                        "last_seen_sync_run": run,
                    },
                )
                processed += 1
            AdvisoryRecord.objects.filter(
                provider=AdvisoryRecord.Provider.CISA_KEV,
                is_active=True,
            ).exclude(last_seen_sync_run=run).update(is_active=False)
            source.confirmed_cursor = cursor
            source.status = IntelligenceSource.Status.CURRENT
            source.last_success_at = timezone.now()
            source.source_updated_at = released_at
            source.last_error = ""
            source.save(
                update_fields=[
                    "confirmed_cursor",
                    "status",
                    "last_success_at",
                    "source_updated_at",
                    "last_error",
                ]
            )
        return _finish_success(
            source,
            run,
            records_fetched=len(entries),
            records_processed=processed,
            source_updated_at=released_at,
            cursor=cursor,
            coverage_complete=True,
        )
    except ProviderSyncError as error:
        _finish_failure(source, run, error)
        raise


def sync_osv() -> SyncOutcome:
    """Process one bounded batch of the recent OSV window."""
    source, run = _start_sync(
        AdvisoryRecord.Provider.OSV,
        SyncRun.Mode.INCREMENTAL,
    )
    try:
        with transaction.atomic():
            source = IntelligenceSource.objects.select_for_update().get(pk=source.pk)
            return _sync_osv_batch(source, run)
    except ProviderSyncError as error:
        _finish_failure(source, run, error)
        raise


def _sync_osv_batch(source: IntelligenceSource, run: SyncRun) -> SyncOutcome:
    cursor = dict(source.confirmed_cursor)
    if cursor.get("coverage_complete") is not True:
        run.mode = SyncRun.Mode.FULL
        run.save(update_fields=["mode"])

    coverage_start_value = cursor.get("coverage_start")
    coverage_start = (
        _parse_timestamp(coverage_start_value, field="coverage start")
        if isinstance(coverage_start_value, str)
        else timezone.now() - OSV_INITIAL_LOOKBACK
    )
    modified_since_value = cursor.get("modified_since")
    modified_since = (
        _parse_timestamp(modified_since_value, field="checkpoint")
        if isinstance(modified_since_value, str)
        else None
    )
    default_since = (
        modified_since - OSV_INCREMENTAL_OVERLAP
        if cursor.get("coverage_complete") is True and modified_since is not None
        else coverage_start
    )
    resume = cursor.get("osv_resume")
    if resume is not None and not isinstance(resume, dict):
        raise ProviderSyncError("OSV cursor has an invalid batch checkpoint")
    if resume:
        since_value = resume.get("since")
        boundary_value = resume.get("boundary")
        newest_value = resume.get("newest")
        paths = resume.get("paths")
        if (
            not isinstance(since_value, str)
            or not isinstance(boundary_value, str)
            or not isinstance(newest_value, str)
            or not isinstance(paths, list)
            or len(paths) > OSV_MAX_BOUNDARY_PATHS
            or any(not isinstance(path, str) for path in paths)
        ):
            raise ProviderSyncError("OSV cursor has an invalid batch checkpoint")
        since = _parse_timestamp(since_value, field="batch start")
        boundary = _parse_timestamp(boundary_value, field="batch boundary")
        newest = _parse_timestamp(newest_value, field="batch newest")
        boundary_paths = set(paths)
    else:
        since = default_since
        boundary = None
        newest = None
        boundary_paths = set()
    records_fetched = 0
    records_processed = 0
    processed_paths: set[str] = set()
    partial = False
    for item in _iter_modified_records(since):
        if newest is None:
            newest = item.modified_at
        path = f"{item.ecosystem}/{item.identifier}"
        if boundary is not None and (
            item.modified_at > boundary or (item.modified_at == boundary and path in boundary_paths)
        ):
            continue
        if path in processed_paths:
            continue
        if records_processed >= OSV_MAX_RECORDS_PER_RUN:
            partial = True
            break
        records_fetched += 1
        record = _fetch_osv_record(item)
        _upsert_osv_record(record, run)
        processed_paths.add(path)
        records_processed += 1
        if boundary != item.modified_at:
            boundary = item.modified_at
            boundary_paths = set()
        boundary_paths.add(path)
        if len(boundary_paths) > OSV_MAX_BOUNDARY_PATHS:
            raise ProviderSyncError("OSV batch boundary exceeds the checkpoint limit")

    checkpoint = (
        max(modified_since, newest)
        if modified_since is not None and newest is not None
        else newest or modified_since
    )
    cursor = _save_cursor(
        source.pk,
        {
            "coverage_complete": cursor.get("coverage_complete") is True if partial else True,
            "coverage_start": coverage_start.isoformat(),
            "modified_since": (modified_since.isoformat() if modified_since else None)
            if partial
            else (checkpoint or since).isoformat(),
            "osv_resume": {
                "since": since.isoformat(),
                "boundary": boundary.isoformat(),
                "newest": newest.isoformat(),
                "paths": sorted(boundary_paths),
            }
            if partial and boundary is not None and newest is not None
            else None,
        },
    )
    return _finish_success(
        source,
        run,
        records_fetched=records_fetched,
        records_processed=records_processed,
        source_updated_at=newest,
        cursor=cursor,
        partial=partial,
        coverage_complete=not partial,
    )
