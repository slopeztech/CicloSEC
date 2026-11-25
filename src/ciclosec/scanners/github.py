"""Read-only GitHub repository archive and Dependabot API integration."""

from __future__ import annotations

import json
import re
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from ciclosec.scanners.process import ScannerExecutionError

GITHUB_API = "https://api.github.com"
GITHUB_API_VERSION = "2026-03-10"
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_API_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ALERTS = 100_000
GITHUB_SLUG = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):  # type: ignore[no-untyped-def]
        return None


def _validate_repository(owner: str, repository: str, ref: str) -> None:
    if not GITHUB_SLUG.fullmatch(owner) or owner in {".", ".."}:
        raise ScannerExecutionError("GitHub repository owner is invalid")
    if not GITHUB_SLUG.fullmatch(repository) or repository in {".", ".."}:
        raise ScannerExecutionError("GitHub repository name is invalid")
    if not ref or len(ref) > 255 or "\x00" in ref or ref.startswith("-"):
        raise ScannerExecutionError("GitHub repository ref is invalid")


def _http_failure(
    operation: str,
    status: int,
    *,
    rate_remaining: str | None,
    retry_after: str | None,
) -> str:
    message = f"GitHub {operation} returned HTTP {status}"
    if status == 429 or (status == 403 and (rate_remaining == "0" or bool(retry_after))):
        return f"{message}; a rate limit may apply. Try again later."
    if status == 401:
        return f"{message}; check the configured credential."
    if status == 403:
        guidance = "check repository access and permissions"
        if operation == "Dependabot API":
            guidance += (
                "; for the Dependabot API, verify repository visibility, "
                "Dependabot alerts: read permission, and that Dependabot alerts are enabled"
            )
        return f"{message}; {guidance}."
    if status == 404:
        if operation == "archive request":
            return f"{message}; repository, ref, or access may not be found."
        return f"{message}; repository, alerts, or access may not be found."
    return message


def _request_archive_url(owner: str, repository: str, ref: str, token: str) -> str:
    _validate_repository(owner, repository, ref)
    if not token:
        raise ScannerExecutionError("GitHub read-only credential is not configured")
    api_url = (
        f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"
        f"/zipball/{quote(ref, safe='')}"
    )
    request = Request(
        api_url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
            "User-Agent": "CicloSec-repository-scan/0.1",
        },
    )
    try:
        opener = build_opener(_NoRedirect)
        with opener.open(request, timeout=30) as response:
            response.close()
            raise ScannerExecutionError("GitHub archive request did not redirect to an archive")
    except HTTPError as error:
        headers = error.headers
        location = headers.get("Location", "") if headers else ""
        status = error.code
        rate_remaining = headers.get("X-RateLimit-Remaining") if headers else None
        retry_after = headers.get("Retry-After") if headers else None
        error.close()
        if status != 302 or not location:
            message = _http_failure(
                "archive request", status, rate_remaining=rate_remaining, retry_after=retry_after
            )
            raise ScannerExecutionError(message) from None
        parsed = urlsplit(location)
        if (
            parsed.scheme != "https"
            or parsed.netloc.lower() != "codeload.github.com"
            or parsed.fragment
        ):
            raise ScannerExecutionError("GitHub archive redirect URL is not allowed") from None
        return location
    except (TimeoutError, URLError, OSError):
        raise ScannerExecutionError("GitHub archive request failed") from None


def _extract_archive(archive_path: Path, destination: Path) -> Path:
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile):
        raise ScannerExecutionError("GitHub returned an invalid repository archive") from None

    with archive:
        members = archive.infolist()
        if not members or len(members) > MAX_ARCHIVE_MEMBERS:
            raise ScannerExecutionError("GitHub repository archive exceeds the file limit")
        expanded_size = sum(member.file_size for member in members)
        if expanded_size > MAX_ARCHIVE_EXPANDED_BYTES:
            raise ScannerExecutionError("GitHub repository archive exceeds the expanded size limit")
        roots: set[str] = set()
        member_names: set[str] = set()
        for member in members:
            name = member.filename
            if "\\" in name or "\x00" in name:
                raise ScannerExecutionError("GitHub repository archive contains an invalid path")
            if name in member_names:
                raise ScannerExecutionError("GitHub repository archive contains duplicate paths")
            member_names.add(name)
            path = PurePosixPath(name)
            if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
                raise ScannerExecutionError("GitHub repository archive contains an invalid path")
            if len(path.parts) == 1 and not member.is_dir():
                raise ScannerExecutionError("GitHub repository archive has an invalid root")
            roots.add(path.parts[0])
            mode = member.external_attr >> 16
            file_type = mode & 0o170000
            if file_type and not (member.is_dir() or file_type == 0o100000):
                raise ScannerExecutionError("GitHub repository archive contains a special file")
        if len(roots) != 1:
            raise ScannerExecutionError("GitHub repository archive contains unexpected roots")

        extraction_root = destination.resolve()
        extracted_size = 0
        for member in members:
            path = PurePosixPath(member.filename)
            relative = Path(*path.parts[1:])
            if not relative.parts:
                continue
            target = (extraction_root / relative).resolve()
            try:
                target.relative_to(extraction_root)
            except ValueError:
                raise ScannerExecutionError(
                    "GitHub repository archive contains an invalid path"
                ) from None
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, target.open("wb") as output:
                copied = 0
                while chunk := source.read(64 * 1024):
                    copied += len(chunk)
                    extracted_size += len(chunk)
                    if copied > member.file_size or extracted_size > MAX_ARCHIVE_EXPANDED_BYTES:
                        raise ScannerExecutionError(
                            "GitHub repository archive exceeded its expanded size limit"
                        )
                    output.write(chunk)
                if copied != member.file_size:
                    raise ScannerExecutionError(
                        "GitHub repository archive contained a truncated file"
                    )
        return extraction_root


def checkout_github_repository(
    owner: str,
    repository: str,
    ref: str,
    token: str,
    destination: Path,
) -> Path:
    """Download and safely extract an authorized GitHub repository snapshot."""
    destination.mkdir(parents=True, exist_ok=True)
    location = _request_archive_url(owner, repository, ref, token)
    archive_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix="ciclosec-",
            suffix=".zip",
            dir=destination,
            delete=False,
        ) as archive_file:
            archive_path = Path(archive_file.name)
            request = Request(location, headers={"User-Agent": "CicloSec-repository-scan/0.1"})
            opener = build_opener(_NoRedirect())
            with opener.open(request, timeout=60) as response:
                content_length = response.headers.get("Content-Length")
                if content_length and int(content_length) > MAX_ARCHIVE_BYTES:
                    raise ScannerExecutionError(
                        "GitHub repository archive exceeds the download limit"
                    )
                downloaded = 0
                while chunk := response.read(64 * 1024):
                    downloaded += len(chunk)
                    if downloaded > MAX_ARCHIVE_BYTES:
                        raise ScannerExecutionError(
                            "GitHub repository archive exceeds the download limit"
                        )
                    archive_file.write(chunk)
        return _extract_archive(archive_path, destination)
    except HTTPError as error:
        status = error.code
        error.close()
        raise ScannerExecutionError(
            f"GitHub repository archive download returned HTTP {status}"
        ) from None
    except (TimeoutError, URLError, OSError, ValueError):
        raise ScannerExecutionError("GitHub repository archive download failed") from None
    finally:
        if archive_path is not None:
            archive_path.unlink(missing_ok=True)


def _decode_api_json(payload: bytes) -> list[dict[str, object]]:
    try:
        document = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ScannerExecutionError("GitHub returned invalid Dependabot JSON") from None
    if not isinstance(document, list) or any(not isinstance(item, dict) for item in document):
        raise ScannerExecutionError("GitHub returned an invalid Dependabot response")
    return document


def list_dependabot_alerts(owner: str, repository: str, token: str) -> list[dict[str, object]]:
    """Read all open Dependabot alerts for one repository with bounded pagination."""
    _validate_repository(owner, repository, "main")
    if not token:
        raise ScannerExecutionError("GitHub read-only credential is not configured")
    url = (
        f"{GITHUB_API}/repos/{quote(owner, safe='')}/{quote(repository, safe='')}"
        "/dependabot/alerts?state=open&per_page=100"
    )
    expected_path = urlsplit(url).path
    alerts: list[dict[str, object]] = []
    seen_urls: set[str] = set()
    opener = build_opener(_NoRedirect())
    while url:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.netloc.lower() != "api.github.com"
            or parsed.path != expected_path
            or parsed.fragment
        ):
            raise ScannerExecutionError("GitHub pagination link URL is not allowed")
        if url in seen_urls:
            raise ScannerExecutionError("GitHub returned a repeated pagination link")
        seen_urls.add(url)
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": GITHUB_API_VERSION,
                "User-Agent": "CicloSec-dependabot-sync/0.1",
            },
        )
        try:
            with opener.open(request, timeout=30) as response:
                payload = response.read(MAX_API_RESPONSE_BYTES + 1)
                link_header = response.headers.get("Link", "")
        except HTTPError as error:
            status = error.code
            headers = error.headers
            rate_remaining = headers.get("X-RateLimit-Remaining") if headers else None
            retry_after = headers.get("Retry-After") if headers else None
            error.close()
            raise ScannerExecutionError(
                _http_failure(
                    "Dependabot API", status, rate_remaining=rate_remaining, retry_after=retry_after
                )
            ) from None
        except (TimeoutError, URLError, OSError):
            raise ScannerExecutionError("GitHub Dependabot API request failed") from None
        if len(payload) > MAX_API_RESPONSE_BYTES:
            raise ScannerExecutionError("GitHub Dependabot response exceeded the size limit")
        alerts.extend(_decode_api_json(payload))
        if len(alerts) > MAX_ALERTS:
            raise ScannerExecutionError("GitHub Dependabot response exceeded the alert limit")
        next_url = ""
        for link in link_header.split(","):
            target, separator, relation = link.strip().partition(";")
            if separator and 'rel="next"' in relation:
                if not target.startswith("<") or not target.endswith(">"):
                    raise ScannerExecutionError("GitHub returned an invalid pagination link")
                next_url = target[1:-1]
                break
        url = next_url
    return alerts
