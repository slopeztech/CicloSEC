"""Scanner output parsing, process isolation, and finding persistence tests."""

import io
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request

import pytest
from django.db import close_old_connections, connection, connections, transaction

from ciclosec.assets.models import Asset, ContainerImage, Repository
from ciclosec.common.config import CicloSecConfig
from ciclosec.findings.models import Finding
from ciclosec.intelligence.models import Vulnerability, VulnerabilityAlias
from ciclosec.inventory.models import ComponentOccurrence
from ciclosec.inventory.sbom import ingest_sbom
from ciclosec.scanners import adapters, github, services
from ciclosec.scanners.process import (
    ProcessResult,
    ScannerExecutionError,
    run_process,
)
from ciclosec.scans.models import ScanConcurrencyGate, ScanRun

FIXTURES = Path(__file__).parents[1] / "fixtures" / "scanners"
SBOM_FIXTURE = Path(__file__).parents[1] / "fixtures" / "sbom" / "cyclonedx-1.7.json"
pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("configuration_state")]


@pytest.fixture(autouse=True)
def authorize_repository_scanners_for_existing_tests(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution,
        "allow_repository_scanners_with_network",
        True,
    )


@pytest.fixture
def osv_output() -> bytes:
    return (FIXTURES / "osv-scanner-v2.json").read_bytes()


@pytest.fixture
def trivy_output() -> bytes:
    return (FIXTURES / "trivy-results-v1.json").read_bytes()


def test_osv_scanner_output_is_normalized_with_range_and_source(
    tmp_path: Path,
    osv_output: bytes,
) -> None:
    findings = adapters.parse_osv_output(osv_output, tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.external_id == "PYSEC-2026-1"
    assert finding.aliases == ("CVE-2026-0001", "GHSA-1111-2222-3333")
    assert finding.package_name == "Flask"
    assert finding.package_version == "2.2.0"
    assert finding.fixed_version == "2.2.5"
    assert "introduced 0" in finding.affected_range
    assert "fixed 2.2.5" in finding.affected_range
    assert finding.source_path == "requirements.lock"
    assert finding.evidence["ecosystem"] == "PyPI"


def test_osv_output_discards_paths_outside_the_checkout(
    tmp_path: Path,
    osv_output: bytes,
) -> None:
    document = json.loads(osv_output)
    document["results"][0]["source"]["path"] = str(tmp_path.parent / "private.lock")

    findings = adapters.parse_osv_output(json.dumps(document).encode(), tmp_path)

    assert findings[0].source_path == ""


def test_trivy_secret_output_never_retains_matched_secret(
    tmp_path: Path,
    trivy_output: bytes,
) -> None:
    findings = adapters.parse_trivy_output(trivy_output, tmp_path)

    assert len(findings) == 2
    secret_finding = next(item for item in findings if item.kind == Finding.Kind.SECRET)
    serialized = repr(secret_finding)
    assert "SECRET_VALUE_SENTINEL" not in serialized
    assert secret_finding.source_path == "requirements.lock"
    assert secret_finding.line_number == 12
    assert secret_finding.evidence == {"rule_id": "generic-api-key"}


def test_local_database_scanner_commands_disable_scanner_network_requests(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def run_process_stub(arguments: list[str], **_kwargs: object) -> ProcessResult:
        commands.append(arguments)
        if arguments[0] == "osv-scanner":
            stdout = b'{"results":[]}'
        elif "--format" in arguments and arguments[arguments.index("--format") + 1] == "cyclonedx":
            stdout = b'{"bomFormat":"CycloneDX"}'
        else:
            stdout = b'{"Results":[]}'
        return ProcessResult(0, stdout, b"")

    monkeypatch.setattr(adapters, "run_process", run_process_stub)

    adapters.run_osv_scanner(tmp_path, timeout_seconds=30, offline=True)
    adapters.run_trivy_sbom(tmp_path, timeout_seconds=30, offline=True)
    adapters.run_trivy_findings(tmp_path, timeout_seconds=30, offline=True)

    assert "--offline" in commands[0]
    trivy_local_flags = {
        "--skip-db-update",
        "--skip-java-db-update",
        "--offline-scan",
        "--skip-version-check",
        "--disable-telemetry",
    }
    assert trivy_local_flags.issubset(commands[1])
    assert trivy_local_flags.issubset(commands[2])


def test_local_database_inspection_reports_missing_and_present_caches(tmp_path: Path) -> None:
    osv_cache = tmp_path / "osv"
    (osv_cache / "osv-scalibr" / "PyPI").mkdir(parents=True)
    (osv_cache / "osv-scalibr" / "PyPI" / "all.zip").write_bytes(b"fixture")
    trivy_cache = tmp_path / "trivy"
    (trivy_cache / "db").mkdir(parents=True)
    (trivy_cache / "db" / "trivy.db").write_bytes(b"fixture")

    status = adapters.inspect_local_scanner_databases(
        osv_cache_directory=str(osv_cache),
        trivy_cache_directory=str(trivy_cache),
    )

    assert status["osv_scanner"]["available"] is True
    assert status["osv_scanner"]["ecosystem_archive_count"] == 1
    assert status["trivy"]["available"] is True
    assert status["trivy"]["vulnerability_db"] is True
    assert status["trivy"]["java_db"] is False

    missing = adapters.inspect_local_scanner_databases(
        osv_cache_directory=str(tmp_path / "missing-osv"),
        trivy_cache_directory=str(tmp_path / "missing-trivy"),
    )
    assert missing["osv_scanner"]["available"] is False
    assert missing["trivy"]["available"] is False


def test_trivy_output_with_malformed_result_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ScannerExecutionError, match="invalid JSON"):
        adapters.parse_trivy_output(b"{", tmp_path)


@pytest.mark.parametrize("field", ["Vulnerabilities", "Secrets"])
@pytest.mark.parametrize("invalid", [False, 0, "", {}])
def test_trivy_rejects_non_list_finding_fields(tmp_path: Path, field: str, invalid: object) -> None:
    payload = json.dumps({"Results": [{field: invalid}]}).encode()
    with pytest.raises(ScannerExecutionError, match="invalid .* list"):
        adapters.parse_trivy_output(payload, tmp_path)


@pytest.mark.parametrize("field", ["Vulnerabilities", "Secrets"])
@pytest.mark.parametrize("empty", [None, []])
def test_trivy_accepts_empty_finding_fields(tmp_path: Path, field: str, empty: object) -> None:
    payload = json.dumps({"Results": [{field: empty}]}).encode()
    assert adapters.parse_trivy_output(payload, tmp_path) == ()


@pytest.mark.skipif(shutil.which("trivy") is None, reason="Trivy is not installed")
def test_repository_sbom_includes_development_and_runtime_dependencies(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    package = {
        "name": "example",
        "version": "1.0.0",
        "dependencies": {"example-runtime": "1.0.0"},
        "devDependencies": {"example-dev": "2.0.0"},
    }
    (tmp_path / "package.json").write_text(json.dumps(package), encoding="utf-8")
    (tmp_path / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "example",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "packages": {
                    "": package,
                    "node_modules/example-runtime": {"version": "1.0.0"},
                    "node_modules/example-dev": {"version": "2.0.0", "dev": True},
                },
            }
        ),
        encoding="utf-8",
    )

    def run_without_telemetry(arguments: list[str], **kwargs: object) -> ProcessResult:
        return run_process(
            [*arguments[:-1], "--disable-telemetry", "--skip-version-check", arguments[-1]],
            **kwargs,
        )

    monkeypatch.setattr(adapters, "run_process", run_without_telemetry)
    _, sbom = adapters.run_trivy_sbom(tmp_path, timeout_seconds=30)
    components = {(item["name"], item.get("version")) for item in sbom["components"]}

    assert ("example-runtime", "1.0.0") in components
    assert ("example-dev", "2.0.0") in components
    asset = Asset.objects.create(name="sbom-test", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", status=ScanRun.Status.SUCCEEDED)
    document = ingest_sbom(scan, "cyclonedx", sbom)
    occurrences = set(
        ComponentOccurrence.objects.filter(sbom_document=document).values_list(
            "component__name", "version"
        )
    )
    assert ("example-runtime", "1.0.0") in occurrences
    assert ("example-dev", "2.0.0") in occurrences


def test_local_docker_resolution_returns_a_normalized_immutable_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    commands: list[list[str]] = []

    def fake_run_process(arguments: list[str], **_kwargs: object) -> ProcessResult:
        commands.append(arguments)
        return ProcessResult(0, b"sha256:" + b"A" * 64 + b"\n", b"")

    monkeypatch.setattr(adapters, "run_process", fake_run_process)

    image_id = adapters.resolve_local_docker_image(
        "ciclosec:test",
        tmp_path,
        timeout_seconds=5,
    )

    assert image_id == f"sha256:{'a' * 64}"
    assert commands == [["docker", "image", "inspect", "--format", "{{.Id}}", "ciclosec:test"]]


def test_trivy_image_findings_are_limited_to_docker_and_match_image_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    trivy_output: bytes,
) -> None:
    image_id = f"sha256:{'a' * 64}"
    document = json.loads(trivy_output)
    document["Metadata"] = {"ImageID": image_id}
    commands: list[list[str]] = []

    def fake_run_process(arguments: list[str], **_kwargs: object) -> ProcessResult:
        commands.append(arguments)
        return ProcessResult(0, json.dumps(document).encode(), b"")

    monkeypatch.setattr(adapters, "run_process", fake_run_process)

    _result, findings = adapters.run_trivy_image_findings(
        image_id,
        tmp_path,
        tmp_path / "trivy-cache",
        timeout_seconds=5,
    )

    assert len(findings) == 2
    assert commands[0][0:4] == ["trivy", "image", "--image-src", "docker"]
    assert commands[0][-1] == image_id


def test_trivy_image_parser_rejects_a_different_image_id(
    tmp_path: Path,
    trivy_output: bytes,
) -> None:
    document = json.loads(trivy_output)
    document["Metadata"] = {"ImageID": f"sha256:{'b' * 64}"}

    with pytest.raises(ScannerExecutionError, match="different image"):
        adapters.parse_trivy_image_output(
            json.dumps(document).encode(),
            tmp_path,
            f"sha256:{'a' * 64}",
        )


def test_process_runner_executes_without_shell_and_bounds_output(tmp_path: Path) -> None:
    result = run_process(
        [
            sys.executable,
            "-c",
            "import os; print(os.environ.get('CICLOSEC_TEST_GITHUB_TOKEN', 'absent'))",
        ],
        cwd=tmp_path,
        timeout_seconds=5,
        max_output_bytes=256,
    )
    assert result.stdout.strip() == b"absent"

    with pytest.raises(ScannerExecutionError, match="output exceeded"):
        run_process(
            [sys.executable, "-c", "print('x' * 10000)"],
            cwd=tmp_path,
            timeout_seconds=5,
            max_output_bytes=32,
        )


def test_process_runner_enforces_timeout(tmp_path: Path) -> None:
    with pytest.raises(ScannerExecutionError, match="time limit"):
        run_process(
            [sys.executable, "-c", "import time; time.sleep(2)"],
            cwd=tmp_path,
            timeout_seconds=1,
            max_output_bytes=64,
        )


def test_process_runner_accepts_exact_limit_on_both_streams(tmp_path: Path) -> None:
    result = run_process(
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.buffer.write(b'x' * 32); sys.stderr.buffer.write(b'y' * 32)",
        ],
        cwd=tmp_path,
        timeout_seconds=5,
        max_output_bytes=32,
    )
    assert result.stdout == b"x" * 32
    assert result.stderr == b"y" * 32


def test_process_runner_preserves_arguments_and_exit_codes(tmp_path: Path) -> None:
    argument = "a value with spaces"
    result = run_process(
        [
            sys.executable,
            "-c",
            "import sys; print(sys.argv[1]); sys.stderr.write('warning'); sys.exit(1)",
            argument,
        ],
        cwd=tmp_path,
        timeout_seconds=5,
        max_output_bytes=256,
        allowed_exit_codes=frozenset({0, 1}),
    )
    assert result.returncode == 1
    assert result.stdout.decode().strip() == argument
    assert result.stderr == b"warning"
    with pytest.raises(ScannerExecutionError, match="status 1"):
        run_process(
            [sys.executable, "-c", "import sys; sys.exit(1)"],
            cwd=tmp_path,
            timeout_seconds=5,
            max_output_bytes=256,
        )


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_process_runner_detects_small_overflow_before_process_exit(
    tmp_path: Path, stream: str
) -> None:
    script = (
        f"import sys, time; sys.{stream}.buffer.write(b'x' * 33); "
        f"sys.{stream}.flush(); time.sleep(10)"
    )
    with pytest.raises(ScannerExecutionError, match="output exceeded"):
        run_process(
            [sys.executable, "-c", script],
            cwd=tmp_path,
            timeout_seconds=2,
            max_output_bytes=32,
        )


def test_process_runner_reports_output_read_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ciclosec.scanners import process

    read = os.read

    def fail_reader(fd: int, count: int) -> bytes:
        if threading.current_thread() is not threading.main_thread():
            raise OSError("private details")
        return read(fd, count)

    monkeypatch.setattr(process.os, "read", fail_reader)
    with pytest.raises(ScannerExecutionError, match="output could not be read") as error:
        run_process(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=tmp_path,
            timeout_seconds=2,
            max_output_bytes=32,
        )
    assert "private details" not in str(error.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree isolation")
@pytest.mark.parametrize("overflow", [False, True])
def test_process_runner_stops_inherited_windows_descendants(tmp_path: Path, overflow: bool) -> None:
    marker = tmp_path / "descendant-survived"
    child = (
        "import pathlib, sys, time; time.sleep(3); pathlib.Path(sys.argv[1]).write_text('alive')"
    )
    parent = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
    )
    if overflow:
        parent += "sys.stdout.write('x' * 33); sys.stdout.flush(); time.sleep(10)"
    else:
        parent += "sys.exit(0)"
    expected_error = "output exceeded" if overflow else "time limit"
    with pytest.raises(ScannerExecutionError, match=expected_error):
        run_process(
            [sys.executable, "-c", parent, child, str(marker)],
            cwd=tmp_path,
            timeout_seconds=1,
            max_output_bytes=32,
        )
    time.sleep(3.2)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree isolation")
def test_process_runner_fails_closed_when_job_assignment_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ciclosec.scanners.windows_job import WindowsJob

    marker = tmp_path / "scanner-started"

    def reject_job(_job: WindowsJob, _process: object) -> None:
        raise OSError("private operating system detail")

    monkeypatch.setattr(WindowsJob, "assign", reject_job)
    with pytest.raises(ScannerExecutionError, match="Windows process job") as error:
        run_process(
            [
                sys.executable,
                "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).touch()",
                str(marker),
            ],
            cwd=tmp_path,
            timeout_seconds=5,
            max_output_bytes=32,
        )
    assert "private operating system detail" not in str(error.value)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree isolation")
def test_process_runner_closes_detached_stream_descendants_on_success(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    child = (
        "import pathlib, sys, time; time.sleep(2); pathlib.Path(sys.argv[1]).write_text('alive')"
    )
    parent = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); print('ok')"
    )
    result = run_process(
        [sys.executable, "-c", parent, child, str(marker)],
        cwd=tmp_path,
        timeout_seconds=5,
        max_output_bytes=32,
    )
    assert result.stdout.strip() == b"ok"
    time.sleep(2.2)
    assert not marker.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree isolation")
def test_process_runner_does_not_stop_unrelated_process(tmp_path: Path) -> None:
    marker = tmp_path / "independent-process"
    sibling = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import pathlib,sys,time; time.sleep(2); pathlib.Path(sys.argv[1]).touch()",
            str(marker),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with pytest.raises(ScannerExecutionError, match="time limit"):
            run_process(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cwd=tmp_path,
                timeout_seconds=1,
                max_output_bytes=32,
            )
        assert sibling.wait(timeout=5) == 0
        assert marker.exists()
    finally:
        if sibling.poll() is None:
            sibling.kill()
            sibling.wait()


@pytest.mark.skipif(os.name != "nt" and sys.platform != "linux", reason="Process-tree isolation")
def test_process_runner_stops_isolated_process_if_reader_cannot_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "scanner-survived"

    def fail_start(_thread: threading.Thread) -> None:
        raise RuntimeError("thread unavailable")

    monkeypatch.setattr(threading.Thread, "start", fail_start)
    with pytest.raises(RuntimeError, match="thread unavailable"):
        run_process(
            [
                sys.executable,
                "-c",
                "import pathlib,sys,time; time.sleep(2); pathlib.Path(sys.argv[1]).touch()",
                str(marker),
            ],
            cwd=tmp_path,
            timeout_seconds=5,
            max_output_bytes=32,
        )
    time.sleep(2.2)
    assert not marker.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process-group isolation")
@pytest.mark.parametrize("overflow", [False, True])
def test_process_runner_stops_inherited_linux_descendants(tmp_path: Path, overflow: bool) -> None:
    marker = tmp_path / "descendant-survived"
    child = (
        "import pathlib, sys, time; time.sleep(3); pathlib.Path(sys.argv[1]).write_text('alive')"
    )
    parent = (
        "import subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
    )
    if overflow:
        parent += "sys.stdout.write('x' * 33); sys.stdout.flush(); time.sleep(10)"
    else:
        parent += "sys.exit(0)"
    expected_error = "output exceeded" if overflow else "time limit"
    with pytest.raises(ScannerExecutionError, match=expected_error):
        run_process(
            [sys.executable, "-c", parent, child, str(marker)],
            cwd=tmp_path,
            timeout_seconds=1,
            max_output_bytes=32,
        )
    time.sleep(3.2)
    assert not marker.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process-group isolation")
def test_process_runner_preserves_unrelated_linux_process(tmp_path: Path) -> None:
    marker = tmp_path / "independent-process"
    sibling = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import pathlib,sys,time; time.sleep(2); pathlib.Path(sys.argv[1]).touch()",
            str(marker),
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        with pytest.raises(ScannerExecutionError, match="time limit"):
            run_process(
                [sys.executable, "-c", "import time; time.sleep(10)"],
                cwd=tmp_path,
                timeout_seconds=1,
                max_output_bytes=32,
            )
        assert sibling.wait(timeout=5) == 0
        assert marker.exists()
    finally:
        if sibling.poll() is None:
            sibling.kill()
            sibling.wait()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux process-group isolation")
def test_process_runner_closes_linux_descendants_with_closed_streams(tmp_path: Path) -> None:
    marker = tmp_path / "descendant-survived"
    child = (
        "import pathlib, sys, time; time.sleep(2); pathlib.Path(sys.argv[1]).write_text('alive')"
    )
    parent = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]], "
        "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); print('ok')"
    )
    result = run_process(
        [sys.executable, "-c", parent, child, str(marker)],
        cwd=tmp_path,
        timeout_seconds=5,
        max_output_bytes=32,
    )
    assert result.stdout.strip() == b"ok"
    time.sleep(2.2)
    assert not marker.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process-group isolation")
def test_linux_group_does_not_signal_after_child_is_reaped(monkeypatch: pytest.MonkeyPatch) -> None:
    from ciclosec.scanners import linux_process

    calls: list[int] = []

    def already_reaped(*_args: object) -> None:
        raise ChildProcessError("child already reaped")

    monkeypatch.setattr(linux_process.os, "waitid", already_reaped)
    monkeypatch.setattr(linux_process.os, "killpg", lambda pid, _signal: calls.append(pid))
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    process.wait()
    with pytest.raises(OSError, match="ownership could not be verified"):
        linux_process.terminate_group(process)
    assert calls == []


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process-group isolation")
def test_linux_group_reports_signal_failure_and_retries_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ciclosec.scanners import linux_process

    killpg = os.killpg
    calls = 0

    def fail_once(pid: int, sig: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("private operating system detail")
        killpg(pid, sig)

    monkeypatch.setattr(linux_process.os, "killpg", fail_once)
    with pytest.raises(ScannerExecutionError, match="group could not be stopped") as error:
        run_process(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            cwd=tmp_path,
            timeout_seconds=1,
            max_output_bytes=32,
        )
    assert calls == 2
    assert "private operating system detail" not in str(error.value)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux process-group isolation")
def test_process_runner_bounds_wait_for_escaped_descendant(tmp_path: Path) -> None:
    marker = tmp_path / "escaped-finished"
    child = "import pathlib, sys, time; time.sleep(4); pathlib.Path(sys.argv[1]).touch()"
    parent = (
        "import subprocess, sys; "
        "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]], "
        "start_new_session=True)"
    )
    started = time.monotonic()
    try:
        with pytest.raises(ScannerExecutionError, match="streams remained open"):
            run_process(
                [sys.executable, "-c", parent, child, str(marker)],
                cwd=tmp_path,
                timeout_seconds=1,
                max_output_bytes=32,
            )
        assert time.monotonic() - started < 4
    finally:
        deadline = time.monotonic() + 6
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
    assert marker.exists()


def test_github_archive_request_uses_zipball_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_urls: list[str] = []
    location = "https://codeload.github.com/slopeztech/Ares2/legacy.zip/refs/heads/main"
    headers = Message()
    headers["Location"] = location

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> None:
            requested_urls.append(request.full_url)
            raise HTTPError(request.full_url, 302, "Found", headers, None)

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())

    archive_url = github._request_archive_url("slopeztech", "Ares2", "main", "test-token")

    assert requested_urls == ["https://api.github.com/repos/slopeztech/Ares2/zipball/main"]
    assert archive_url == location


@pytest.mark.parametrize(
    "location",
    [
        "https://codeload.github.com@untrusted.example/archive",
        "https://user@codeload.github.com/archive",
        "https://codeload.github.com:443/archive",
        "https://codeload.github.com/archive#fragment",
    ],
)
def test_github_archive_rejects_untrusted_redirect_url(
    monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    headers = Message()
    headers["Location"] = location

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> None:
            raise HTTPError(request.full_url, 302, "Found", headers, None)

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())
    with pytest.raises(ScannerExecutionError, match="redirect.*not allowed"):
        github._request_archive_url("example", "repo", "main", "SECRET_SENTINEL")


def test_github_archive_download_rejects_further_redirects_and_cleans_up(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    location = "https://codeload.github.com/example/repo/legacy.zip/main?secret=SECRET_SENTINEL"
    monkeypatch.setattr(github, "_request_archive_url", lambda *_args: location)
    requested: list[Request] = []
    headers = Message()
    headers["Location"] = "https://untrusted.example/collect"

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> None:
            requested.append(request)
            raise HTTPError(request.full_url, 302, "SECRET_SENTINEL", headers, None)

    def opener(*handlers: object) -> FakeOpener:
        assert any(isinstance(handler, github._NoRedirect) for handler in handlers)
        return FakeOpener()

    monkeypatch.setattr(github, "build_opener", opener)
    with pytest.raises(ScannerExecutionError, match="HTTP 302") as error:
        github.checkout_github_repository("example", "repo", "main", "SECRET_SENTINEL", tmp_path)
    assert len(requested) == 1
    assert requested[0].full_url == location
    assert not requested[0].has_header("Authorization")
    assert "SECRET_SENTINEL" not in str(error.value)
    assert list(tmp_path.iterdir()) == []


def test_github_archive_download_extracts_without_forwarding_token(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    location = "https://codeload.github.com/example/repo/legacy.zip/main"
    monkeypatch.setattr(github, "_request_archive_url", lambda *_args: location)
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("repo-main/requirements.txt", "example==1.0\n")

    class FakeResponse(io.BytesIO):
        headers: Message

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> FakeResponse:
            assert request.full_url == location
            assert not request.has_header("Authorization")
            response = FakeResponse(archive.getvalue())
            response.headers = Message()
            return response

    def opener(*handlers: object) -> FakeOpener:
        assert any(isinstance(handler, github._NoRedirect) for handler in handlers)
        return FakeOpener()

    monkeypatch.setattr(github, "build_opener", opener)
    result = github.checkout_github_repository(
        "example", "repo", "main", "SECRET_SENTINEL", tmp_path
    )
    assert (result / "requirements.txt").read_text(encoding="utf-8") == "example==1.0\n"
    assert list(tmp_path.glob("*.zip")) == []


@pytest.mark.parametrize("operation", ["archive", "dependabot"])
@pytest.mark.parametrize(
    ("status", "headers", "expected"),
    [
        (401, {}, "credential"),
        (403, {}, "permissions"),
        (403, {"X-RateLimit-Remaining": "0"}, "rate limit"),
        (403, {"Retry-After": "30"}, "rate limit"),
        (404, {}, "may not be found"),
        (429, {}, "rate limit"),
        (500, {}, "HTTP 500"),
    ],
)
def test_github_errors_report_safe_actionable_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    status: int,
    headers: dict[str, str],
    expected: str,
) -> None:
    response_headers = Message()
    for name, value in headers.items():
        response_headers[name] = value
    response_headers["X-Untrusted"] = "SECRET_SENTINEL"

    def fail(request: Request, **_kwargs: object) -> None:
        raise HTTPError(
            request.full_url,
            status,
            "SECRET_SENTINEL",
            response_headers,
            io.BytesIO(b"SECRET_SENTINEL"),
        )

    class FakeOpener:
        open = staticmethod(fail)

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())

    with pytest.raises(ScannerExecutionError) as error:
        if operation == "archive":
            github._request_archive_url("example", "repo", "main", "SECRET_SENTINEL")
        else:
            github.list_dependabot_alerts("example", "repo", "SECRET_SENTINEL")

    message = str(error.value)
    assert f"HTTP {status}" in message
    assert expected in message
    assert "SECRET_SENTINEL" not in message
    if status == 403 and not headers:
        assert "disabled" not in message


def test_dependabot_refuses_redirects_without_forwarding_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers = Message()
    headers["Location"] = "https://untrusted.example/collect"
    requested = []

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> None:
            requested.append(request.full_url)
            raise HTTPError(request.full_url, 302, "redirect", headers, None)

    def opener(*handlers: object) -> FakeOpener:
        assert any(isinstance(handler, github._NoRedirect) for handler in handlers)
        request = Request(
            "https://api.github.com/repos/example/repo/dependabot/alerts",
            headers={"Authorization": "Bearer SECRET_SENTINEL"},
        )
        handler = next(handler for handler in handlers if isinstance(handler, github._NoRedirect))
        assert (
            handler.redirect_request(request, None, 302, "redirect", headers, headers["Location"])
            is None
        )
        return FakeOpener()

    monkeypatch.setattr(github, "build_opener", opener)

    with pytest.raises(ScannerExecutionError, match="HTTP 302") as error:
        github.list_dependabot_alerts("example", "repo", "SECRET_SENTINEL")
    assert len(requested) == 1
    assert "SECRET_SENTINEL" not in str(error.value)


@pytest.mark.parametrize(
    "next_url",
    [
        "https://user@api.github.com/repos/example/repo/dependabot/alerts?page=2",
        "https://api.github.com:443/repos/example/repo/dependabot/alerts?page=2",
        "https://api.github.com/repos/example/repo/dependabot/alerts?page=2#fragment",
    ],
)
def test_dependabot_rejects_untrusted_pagination_url(
    monkeypatch: pytest.MonkeyPatch, next_url: str
) -> None:
    requests = []

    class FakeResponse(io.BytesIO):
        headers: Message

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> FakeResponse:
            requests.append(request.full_url)
            response = FakeResponse(b"[]")
            response.headers = Message()
            response.headers["Link"] = f'<{next_url}>; rel="next"'
            return response

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())
    with pytest.raises(ScannerExecutionError, match="pagination link URL is not allowed"):
        github.list_dependabot_alerts("example", "repo", "SECRET_SENTINEL")
    assert len(requests) == 1


def test_dependabot_accepts_valid_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    requests = []

    class FakeResponse(io.BytesIO):
        headers: Message

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> FakeResponse:
            requests.append(request.full_url)
            response = FakeResponse(b'[{"number": 1}]')
            response.headers = Message()
            if len(requests) == 1:
                response.headers["Link"] = (
                    "<https://api.github.com/repos/example/repo/dependabot/alerts"
                    '?page=2>; rel="next"'
                )
            return response

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())
    assert len(github.list_dependabot_alerts("example", "repo", "SECRET_SENTINEL")) == 2
    assert len(requests) == 2


@pytest.mark.parametrize("entrypoint", ["registered", "checkout", "task"])
def test_repository_scans_fail_closed_without_network_authorization(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, entrypoint: str
) -> None:
    from ciclosec.scanners import tasks
    from ciclosec.scans.services import scan_diagnostic_messages

    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution,
        "allow_repository_scanners_with_network",
        False,
    )
    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution,
        "repository_scanner_use_local_databases",
        True,
    )
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")

    def unexpected_call(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Unauthorized repository scan attempted external or scanner access")

    monkeypatch.setattr(services, "resolve_environment_value", unexpected_call)
    monkeypatch.setattr(services, "checkout_github_repository", unexpected_call)
    monkeypatch.setattr(services, "run_trivy_sbom", unexpected_call)
    monkeypatch.setattr(services, "run_trivy_findings", unexpected_call)
    monkeypatch.setattr(services, "run_osv_scanner", unexpected_call)
    monkeypatch.setattr(services, "list_dependabot_alerts", unexpected_call)
    if entrypoint == "registered":
        result = services.scan_registered_repository(scan.pk)
    elif entrypoint == "checkout":
        result = services.scan_repository_checkout(scan, tmp_path)
    else:
        outcome = tasks.scan_repository_task.run(scan.pk)
        assert outcome["status"] == ScanRun.Status.FAILED
        result = scan

    result.refresh_from_db()
    assert result.status == ScanRun.Status.FAILED
    assert result.metadata["diagnostic_codes"] == ["repository_scanner_network_not_authorized"]
    assert "not authorized" in result.error_summary
    assert any("no están autorizados" in message for message in scan_diagnostic_messages(result))
    assert not result.sbom_documents.exists()


@pytest.mark.parametrize(
    "revoke_after",
    [
        "credentials",
        "checkout",
        "sbom",
        "osv",
        "trivy",
        "trivy_version",
        "osv_version",
        "dependabot_credentials",
    ],
)
def test_repository_scan_rechecks_revocation_between_external_operations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, revoke_after: str
) -> None:
    from django.contrib.auth import get_user_model

    from ciclosec.common.settings_service import update_configuration

    config = CicloSecConfig()
    config.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(services.settings, "CICLOSEC_CONFIG", config)
    admin = get_user_model().objects.create_superuser(username="revocation-admin", password="test")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    calls: list[str] = []

    def operation(name: str, result: object) -> object:
        calls.append(name)
        if name == revoke_after:
            update_configuration(
                actor=admin,
                changes={"scanning.execution.allow_repository_scanners_with_network": False},
                expected_revision=0,
                confirm=True,
                base=config,
            )
        return result

    monkeypatch.setattr(
        services,
        "resolve_environment_value",
        lambda *_a: operation(
            "dependabot_credentials" if "credentials" in calls else "credentials", "test-token"
        ),
    )
    monkeypatch.setattr(
        services, "checkout_github_repository", lambda *_a: operation("checkout", tmp_path)
    )
    monkeypatch.setattr(
        services,
        "run_trivy_sbom",
        lambda *_a, **_k: operation("sbom", (ProcessResult(0, b"", b""), sbom)),
    )
    monkeypatch.setattr(
        services,
        "run_osv_scanner",
        lambda *_a, **_k: operation("osv", (ProcessResult(0, b"", b""), ())),
    )
    monkeypatch.setattr(
        services,
        "run_trivy_findings",
        lambda *_a, **_k: operation("trivy", (ProcessResult(0, b"", b""), ())),
    )
    monkeypatch.setattr(
        services,
        "scanner_version",
        lambda exe, *_a, **_k: operation(
            "osv_version" if exe == "osv-scanner" else "trivy_version", "test"
        ),
    )
    monkeypatch.setattr(services, "list_dependabot_alerts", lambda *_a: operation("dependabot", []))

    result = services.scan_registered_repository(scan.pk)

    assert result.status == ScanRun.Status.FAILED
    assert calls[-1] == revoke_after
    assert "repository_scanner_network_not_authorized" in result.metadata["diagnostic_codes"]
    assert not result.sbom_documents.exists()


@pytest.mark.parametrize("revoke_after", ["inspect", "sbom"])
def test_image_scan_rechecks_docker_permission_between_external_operations(
    monkeypatch: pytest.MonkeyPatch, revoke_after: str
) -> None:
    from django.contrib.auth import get_user_model

    from ciclosec.common.settings_service import update_configuration

    config = CicloSecConfig.model_validate(
        {
            "docker": {
                "enabled": True,
                "allow_local_daemon": True,
                "images": [{"reference": "ciclosec:fixture"}],
            }
        }
    )
    monkeypatch.setattr(services.settings, "CICLOSEC_CONFIG", config)
    admin = get_user_model().objects.create_superuser(username="image-revocation", password="test")
    asset = Asset.objects.create(name="image", kind=Asset.Kind.CONTAINER_IMAGE)
    image = ContainerImage.objects.create(asset=asset, image_reference="ciclosec:fixture")
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    calls: list[str] = []

    def operation(name: str, result: object) -> object:
        calls.append(name)
        if name == revoke_after:
            update_configuration(
                actor=admin,
                changes={"docker.allow_local_daemon": False},
                expected_revision=0,
                confirm=True,
                base=config,
            )
        return result

    monkeypatch.setattr(
        services,
        "resolve_local_docker_image",
        lambda *_a, **_k: operation("inspect", f"sha256:{'a' * 64}"),
    )
    monkeypatch.setattr(
        services,
        "run_trivy_image_sbom",
        lambda *_a, **_k: operation("sbom", (ProcessResult(0, b"", b""), sbom)),
    )
    monkeypatch.setattr(
        services,
        "run_trivy_image_findings",
        lambda *_a, **_k: operation("findings", (ProcessResult(0, b"", b""), ())),
    )

    result = services.scan_registered_container_image(scan.pk)

    assert result.status == ScanRun.Status.FAILED
    assert calls[-1] == revoke_after
    assert "image_scanning_disabled" in result.metadata["diagnostic_codes"]
    assert not result.sbom_documents.exists()
    image.refresh_from_db()
    assert not image.resolved_digest


@pytest.mark.parametrize("failure", ["missing", "invalid"])
def test_repository_scan_stops_if_configuration_becomes_unavailable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failure: str
) -> None:
    from ciclosec.common.config import ConfigurationError
    from ciclosec.common.models import ConfigurationState

    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))

    def sbom_then_damage_config(*_args: object, **_kwargs: object) -> tuple[ProcessResult, dict]:
        if failure == "missing":
            ConfigurationState.objects.filter(pk=1).delete()
        else:
            ConfigurationState.objects.filter(pk=1).update(overrides={"database.url_env": "secret"})
        return ProcessResult(0, b"", b""), sbom

    monkeypatch.setattr(services, "run_trivy_sbom", sbom_then_damage_config)
    monkeypatch.setattr(
        services,
        "run_osv_scanner",
        lambda *_a, **_k: pytest.fail("No scanner may start without valid configuration"),
    )
    expected_error = ConfigurationState.DoesNotExist if failure == "missing" else ConfigurationError
    with pytest.raises(expected_error):
        services.scan_repository_checkout(scan, tmp_path)
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.RUNNING
    assert not scan.sbom_documents.exists()


def test_repository_scan_fails_without_credential_before_checkout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="MISSING_TEST_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    monkeypatch.delenv("MISSING_TEST_TOKEN", raising=False)

    def unexpected_checkout(*_args: object, **_kwargs: object) -> None:
        pytest.fail("Checkout must not be attempted without a credential")

    monkeypatch.setattr(services, "checkout_github_repository", unexpected_checkout)
    result = services.scan_registered_repository(scan.pk)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.FAILED
    assert "MISSING_TEST_TOKEN" in result.error_summary
    assert result.metadata["diagnostic_codes"] == ["credential_missing"]
    assert result.metadata["repository_source"] == {
        "provider": "github",
        "owner": "example",
        "repository": "repo",
        "ref": "main",
    }


@pytest.mark.parametrize("change", ["none", "owner", "ref", "credential", "asset", "delete"])
def test_repository_scan_keeps_original_source_when_configuration_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, change: str
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    other_asset = Asset.objects.create(name="other", kind=Asset.Kind.REPOSITORY)
    source = Repository.objects.create(
        asset=asset,
        owner="example",
        repository_name="repo",
        ref="main",
        credential_env="ORIGINAL_TEST_TOKEN",
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setenv("ORIGINAL_TEST_TOKEN", "ORIGINAL_SECRET_SENTINEL")
    monkeypatch.setenv("OTHER_TEST_TOKEN", "OTHER_SECRET_SENTINEL")
    calls: list[tuple[str, str, str]] = []

    def checkout(owner: str, repository: str, ref: str, token: str, root: Path) -> Path:
        assert (owner, repository, ref, token) == (
            "example",
            "repo",
            "main",
            "ORIGINAL_SECRET_SENTINEL",
        )
        if change == "owner":
            Repository.objects.filter(pk=source.pk).update(owner="different")
        elif change == "ref":
            Repository.objects.filter(pk=source.pk).update(ref="other")
        elif change == "credential":
            Repository.objects.filter(pk=source.pk).update(credential_env="OTHER_TEST_TOKEN")
        elif change == "asset":
            Repository.objects.filter(pk=source.pk).update(asset=other_asset)
        elif change == "delete":
            Repository.objects.filter(pk=source.pk).delete()
        return root

    def dependabot(owner: str, repository: str, token: str) -> list:
        calls.append((owner, repository, token))
        return []

    monkeypatch.setattr(services, "checkout_github_repository", checkout)
    monkeypatch.setattr(services, "list_dependabot_alerts", dependabot)
    monkeypatch.setattr(
        services, "run_trivy_sbom", lambda *_a, **_k: (ProcessResult(0, b"", b""), sbom)
    )
    monkeypatch.setattr(
        services, "run_osv_scanner", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(
        services, "run_trivy_findings", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(services, "scanner_version", lambda *_a, **_k: "1.0")

    result = services.scan_registered_repository(scan.pk)

    result.refresh_from_db()
    assert calls == [("example", "repo", "ORIGINAL_SECRET_SENTINEL")]
    assert result.status == (
        ScanRun.Status.SUCCEEDED if change == "none" else ScanRun.Status.PARTIAL
    )
    assert result.sbom_documents.count() == 1
    assert result.metadata["repository_source"] == {
        "provider": "github",
        "owner": "example",
        "repository": "repo",
        "ref": "main",
    }
    assert "SECRET_SENTINEL" not in json.dumps(result.metadata)
    if change != "none":
        assert any("source changed" in warning for warning in result.warnings)
        assert result.metadata["repository_source_changed"] is True
        assert "repository_source_changed" in result.metadata["diagnostic_codes"]
    else:
        assert "repository_source_changed" not in result.metadata


@pytest.mark.parametrize("kind", [Asset.Kind.REPOSITORY, Asset.Kind.CONTAINER_IMAGE])
def test_queued_scan_for_disabled_asset_does_not_access_its_source(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    asset = Asset.objects.create(name="disabled", kind=kind)
    if kind == Asset.Kind.REPOSITORY:
        Repository.objects.create(
            asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
        )
    else:
        ContainerImage.objects.create(asset=asset, image_reference="ciclosec:fixture")
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    Asset.objects.filter(pk=asset.pk).update(enabled=False)
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        services.settings,
        "CICLOSEC_CONFIG",
        CicloSecConfig.model_validate(
            {
                "docker": {
                    "enabled": True,
                    "allow_local_daemon": True,
                    "images": [{"reference": "ciclosec:fixture"}],
                }
            }
        ),
    )

    def unexpected_access(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A disabled asset must not access the source")

    monkeypatch.setattr(services, "checkout_github_repository", unexpected_access)
    monkeypatch.setattr(services, "resolve_local_docker_image", unexpected_access)
    if kind == Asset.Kind.REPOSITORY:
        result = services.scan_registered_repository(scan.pk)
    else:
        result = services.scan_registered_container_image(scan.pk)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.FAILED
    assert result.started_at is None
    assert result.finished_at is not None
    assert "disabled" in result.error_summary
    assert result.metadata["diagnostic_codes"] == ["asset_disabled"]


def test_repository_scan_marks_running_before_checkout_and_finishes_after_disable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")

    def checkout(*_args: object, **_kwargs: object) -> Path:
        scan.refresh_from_db()
        assert scan.status == ScanRun.Status.RUNNING
        assert scan.started_at is not None
        Asset.objects.filter(pk=asset.pk).update(enabled=False)
        return tmp_path

    monkeypatch.setattr(services, "checkout_github_repository", checkout)
    monkeypatch.setattr(
        services, "run_trivy_sbom", lambda *_a, **_k: (ProcessResult(0, b"", b""), sbom)
    )
    monkeypatch.setattr(
        services, "run_osv_scanner", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(
        services, "run_trivy_findings", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(services, "scanner_version", lambda *_a, **_k: "1.0")
    monkeypatch.setattr(services, "list_dependabot_alerts", lambda *_a: [])

    result = services.scan_registered_repository(scan.pk)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.SUCCEEDED
    assert result.sbom_documents.count() == 1
    asset.refresh_from_db()
    assert asset.enabled is False


def test_already_running_repository_scan_cannot_be_started_twice() -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(
        asset=asset, scanner_name="repository-security", status=ScanRun.Status.RUNNING
    )

    with pytest.raises(ScannerExecutionError, match="Only queued scans"):
        services.scan_registered_repository(scan.pk)

    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.RUNNING


def test_scan_capacity_blocks_only_new_running_scans(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution, "max_concurrent_scans", 1
    )
    first_asset = Asset.objects.create(name="first", kind=Asset.Kind.REPOSITORY)
    second_asset = Asset.objects.create(name="second", kind=Asset.Kind.REPOSITORY)
    first = ScanRun.objects.create(asset=first_asset, scanner_name="queued")
    second = ScanRun.objects.create(asset=second_asset, scanner_name="queued")

    services._start_scan(first.pk, kind=Asset.Kind.REPOSITORY, scanner_name="repository-security")
    with pytest.raises(ScannerExecutionError, match="capacity"):
        services._start_scan(
            second.pk, kind=Asset.Kind.REPOSITORY, scanner_name="repository-security"
        )
    second.refresh_from_db()
    assert second.status == ScanRun.Status.QUEUED
    assert second.started_at is None

    first.refresh_from_db()
    first.status = ScanRun.Status.SUCCEEDED
    first.save(update_fields=["status"])
    result = services._start_scan(
        second.pk, kind=Asset.Kind.REPOSITORY, scanner_name="repository-security"
    )
    assert result.status == ScanRun.Status.RUNNING


@pytest.mark.parametrize("kind", [Asset.Kind.REPOSITORY, Asset.Kind.CONTAINER_IMAGE])
def test_task_waits_and_retries_when_capacity_is_full(
    monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    from celery.exceptions import Retry

    from ciclosec.scanners import tasks

    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution, "max_concurrent_scans", 1
    )
    existing_asset = Asset.objects.create(name="busy", kind=Asset.Kind.REPOSITORY)
    ScanRun.objects.create(asset=existing_asset, scanner_name="test", status=ScanRun.Status.RUNNING)
    asset = Asset.objects.create(name="waiting", kind=kind)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    task = (
        tasks.scan_repository_task
        if kind == Asset.Kind.REPOSITORY
        else tasks.scan_container_image_task
    )
    retries: list[tuple[object, int]] = []

    def retry(*, exc: object, countdown: int) -> None:
        retries.append((exc, countdown))
        raise Retry()

    monkeypatch.setattr(task, "retry", retry)
    with pytest.raises(Retry):
        task.run(scan.pk)
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.QUEUED
    assert len(retries) == 1
    assert isinstance(retries[0][0], services.ScanCapacityExceeded)
    assert retries[0][1] == 10


def test_retry_delivery_failure_marks_scan_uncertain_without_leaking_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from celery.exceptions import Reject

    from ciclosec.scanners import tasks

    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution, "max_concurrent_scans", 1
    )
    existing_asset = Asset.objects.create(name="busy", kind=Asset.Kind.REPOSITORY)
    ScanRun.objects.create(asset=existing_asset, scanner_name="test", status=ScanRun.Status.RUNNING)
    asset = Asset.objects.create(name="waiting", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")

    def failed_retry(*, exc: object, countdown: int) -> None:
        raise Reject("private-broker-secret", requeue=False)

    monkeypatch.setattr(tasks.scan_repository_task, "retry", failed_retry)
    with pytest.raises(Reject) as error:
        tasks.scan_repository_task.run(scan.pk)
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.QUEUED
    assert scan.metadata["dispatch_uncertain"] is True
    assert "private-broker-secret" not in str(error.value)
    assert "private-broker-secret" not in caplog.text


def test_disabled_asset_fails_even_when_scan_capacity_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution, "max_concurrent_scans", 1
    )
    existing_asset = Asset.objects.create(name="busy", kind=Asset.Kind.REPOSITORY)
    ScanRun.objects.create(asset=existing_asset, scanner_name="test", status=ScanRun.Status.RUNNING)
    asset = Asset.objects.create(name="disabled", kind=Asset.Kind.REPOSITORY, enabled=False)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    result = services._start_scan(scan.pk, kind=Asset.Kind.REPOSITORY, scanner_name="test")
    assert result.status == ScanRun.Status.FAILED
    assert result.metadata["diagnostic_codes"] == ["asset_disabled"]


@pytest.mark.django_db(transaction=True)
def test_concurrent_scan_claims_respect_the_global_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution, "max_concurrent_scans", 1
    )
    first = Asset.objects.create(name="first", kind=Asset.Kind.REPOSITORY)
    second = Asset.objects.create(name="second", kind=Asset.Kind.REPOSITORY)
    scans = [
        ScanRun.objects.create(asset=first, scanner_name="queued"),
        ScanRun.objects.create(asset=second, scanner_name="queued"),
    ]
    barrier = threading.Barrier(2)

    def claim(scan_id: int) -> str:
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            try:
                return services._start_scan(
                    scan_id, kind=Asset.Kind.REPOSITORY, scanner_name="repository-security"
                ).status
            except services.ScanCapacityExceeded:
                return "capacity"
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = list(executor.map(claim, [scan.pk for scan in scans]))
    assert sorted(outcomes) == ["capacity", ScanRun.Status.RUNNING]
    assert ScanRun.objects.filter(status=ScanRun.Status.RUNNING).count() == 1
    assert ScanRun.objects.filter(status=ScanRun.Status.QUEUED).count() == 1


@pytest.mark.parametrize("kind", [Asset.Kind.REPOSITORY, Asset.Kind.CONTAINER_IMAGE])
@pytest.mark.parametrize(
    "scan_status",
    [
        ScanRun.Status.RUNNING,
        ScanRun.Status.SUCCEEDED,
        ScanRun.Status.PARTIAL,
        ScanRun.Status.FAILED,
        ScanRun.Status.CANCELLED,
    ],
)
def test_redelivered_task_reports_existing_state_without_restarting(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    scan_status: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from ciclosec.scanners import tasks

    asset = Asset.objects.create(name="backend", kind=kind)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", status=scan_status)

    def unexpected_access(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A redelivered task must not access the source")

    monkeypatch.setattr(services, "checkout_github_repository", unexpected_access)
    monkeypatch.setattr(services, "resolve_local_docker_image", unexpected_access)
    task = (
        tasks.scan_repository_task
        if kind == Asset.Kind.REPOSITORY
        else tasks.scan_container_image_task
    )
    result = task.run(scan.pk)

    assert result == {
        "scan_run_id": scan.pk,
        "status": scan_status,
        "finding_count": 0,
        "disposition": "already_claimed",
    }
    scan.refresh_from_db()
    assert scan.status == scan_status
    assert scan.started_at is None
    assert "duplicate delivery ignored" in caplog.text


def test_redelivered_task_does_not_hide_missing_or_invalid_scan() -> None:
    from ciclosec.scanners import tasks

    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="test", status="invalid")

    with pytest.raises(ScannerExecutionError, match="Only queued scans"):
        tasks.scan_repository_task.run(scan.pk)
    with pytest.raises(ScanRun.DoesNotExist):
        tasks.scan_repository_task.run(scan.pk + 1000)


@pytest.mark.django_db(transaction=True)
def test_two_deliveries_only_start_one_repository_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from ciclosec.scanners import tasks

    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")
    started = threading.Event()
    release = threading.Event()
    barrier = threading.Barrier(2)
    calls: list[int] = []

    def checkout(*_args: object, **_kwargs: object) -> Path:
        calls.append(1)
        started.set()
        if not release.wait(10):
            pytest.fail("Timed out waiting to release the simulated checkout")
        raise ScannerExecutionError("simulated checkout failure")

    monkeypatch.setattr(services, "checkout_github_repository", checkout)

    def deliver() -> dict[str, object]:
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return tasks.scan_repository_task.run(scan.pk)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(deliver) for _ in range(2)]
        try:
            assert started.wait(10)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not any(f.done() for f in futures):
                time.sleep(0.02)
            assert any(f.done() for f in futures)
        finally:
            release.set()
        results = [f.result(timeout=10) for f in futures]

    assert calls == [1]
    assert {result["disposition"] for result in results} == {"claimed", "already_claimed"}
    assert (
        next(result for result in results if result["disposition"] == "already_claimed")["status"]
        == ScanRun.Status.RUNNING
    )
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.FAILED


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("same_task_id", [False, True])
def test_two_celery_workers_do_not_repeat_a_delivered_scan(
    monkeypatch: pytest.MonkeyPatch,
    same_task_id: bool,
) -> None:
    from celery import Celery
    from celery.contrib.testing.worker import start_worker

    from ciclosec.scanners import tasks

    redis_url = os.environ.get("CICLOSEC_TEST_REDIS_URL")
    if not redis_url or connection.vendor != "postgresql":
        pytest.skip("Requires isolated PostgreSQL and CICLOSEC_TEST_REDIS_URL")
    parsed_url = urlparse(redis_url)
    if parsed_url.scheme != "redis" or parsed_url.hostname != "127.0.0.1":
        pytest.fail("CICLOSEC_TEST_REDIS_URL must point to an isolated loopback Redis")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")
    started = threading.Event()
    release = threading.Event()
    calls: list[int] = []

    def checkout(*_args: object, **_kwargs: object) -> Path:
        calls.append(1)
        started.set()
        if not release.wait(30):
            pytest.fail("Timed out waiting to release the simulated checkout")
        raise ScannerExecutionError("simulated checkout failure")

    monkeypatch.setattr(services, "checkout_github_repository", checkout)
    app = Celery("ciclosec-isolated-redelivery-test", broker=redis_url, backend=redis_url)
    identifier = uuid.uuid4().hex

    @app.task(bind=True, name=f"test.scan.{identifier}", max_retries=None)
    def worker_task(task: object, scan_id: int) -> dict[str, object]:
        return tasks._run_scan(task, scan_id, services.scan_registered_repository)

    first_queue = f"test-first-{identifier}"
    second_queue = f"test-second-{identifier}"
    try:
        with (
            start_worker(app, pool="solo", queues=[first_queue], perform_ping_check=False),
            start_worker(app, pool="solo", queues=[second_queue], perform_ping_check=False),
        ):
            try:
                first = worker_task.apply_async(
                    args=(scan.pk,), queue=first_queue, task_id=identifier
                )
                assert started.wait(15)
                second = worker_task.apply_async(
                    args=(scan.pk,),
                    queue=second_queue,
                    task_id=identifier if same_task_id else uuid.uuid4().hex,
                )
                duplicate = second.get(timeout=15, disable_sync_subtasks=False)
                assert duplicate["disposition"] == "already_claimed"
                assert duplicate["status"] == ScanRun.Status.RUNNING
            finally:
                release.set()
            if not same_task_id:
                original = first.get(timeout=15, disable_sync_subtasks=False)
                assert original["disposition"] == "claimed"
                assert original["status"] == ScanRun.Status.FAILED
            else:
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    scan.refresh_from_db()
                    if scan.status == ScanRun.Status.FAILED:
                        break
                    time.sleep(0.05)
                assert scan.status == ScanRun.Status.FAILED
    finally:
        app.close()

    assert calls == [1]
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.FAILED


@pytest.mark.django_db(transaction=True)
def test_worker_retries_after_capacity_becomes_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery import Celery
    from celery.contrib.testing.worker import start_worker

    from ciclosec.scanners import tasks

    redis_url = os.environ.get("CICLOSEC_TEST_REDIS_URL")
    if not redis_url or connection.vendor != "postgresql":
        pytest.skip("Requires isolated PostgreSQL and CICLOSEC_TEST_REDIS_URL")
    parsed_url = urlparse(redis_url)
    if parsed_url.scheme != "redis" or parsed_url.hostname != "127.0.0.1":
        pytest.fail("CICLOSEC_TEST_REDIS_URL must point to an isolated loopback Redis")
    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution, "max_concurrent_scans", 1
    )
    existing_asset = Asset.objects.create(name="busy", kind=Asset.Kind.REPOSITORY)
    existing = ScanRun.objects.create(
        asset=existing_asset, scanner_name="test", status=ScanRun.Status.RUNNING
    )
    asset = Asset.objects.create(name="waiting", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")

    def fail_checkout(*_args: object, **_kwargs: object) -> None:
        raise ScannerExecutionError("simulated checkout failure")

    monkeypatch.setattr(services, "checkout_github_repository", fail_checkout)
    app = Celery("ciclosec-isolated-capacity-test", broker=redis_url, backend=redis_url)
    identifier = uuid.uuid4().hex

    @app.task(bind=True, name=f"test.capacity.{identifier}", max_retries=None)
    def worker_task(task: object, scan_id: int) -> dict[str, object]:
        return tasks._run_scan(task, scan_id, services.scan_registered_repository)

    queue = f"test-capacity-{identifier}"
    try:
        with start_worker(app, pool="solo", queues=[queue], perform_ping_check=False):
            result = worker_task.apply_async(args=(scan.pk,), queue=queue)
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and result.state != "RETRY":
                time.sleep(0.05)
            assert result.state == "RETRY"
            scan.refresh_from_db()
            assert scan.status == ScanRun.Status.QUEUED
            existing.status = ScanRun.Status.SUCCEEDED
            existing.save(update_fields=["status"])
            outcome = result.get(timeout=25, disable_sync_subtasks=False)
            assert outcome["disposition"] == "claimed"
            assert outcome["status"] == ScanRun.Status.FAILED
    finally:
        app.close()


@pytest.mark.django_db(transaction=True)
def test_cancelled_scan_delivery_is_ignored_by_celery_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery import Celery
    from celery.contrib.testing.worker import start_worker
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scanners import tasks

    redis_url = os.environ.get("CICLOSEC_TEST_REDIS_URL")
    if not redis_url or connection.vendor != "postgresql":
        pytest.skip("Requires isolated PostgreSQL and CICLOSEC_TEST_REDIS_URL")
    parsed_url = urlparse(redis_url)
    if parsed_url.scheme != "redis" or parsed_url.hostname != "127.0.0.1":
        pytest.fail("CICLOSEC_TEST_REDIS_URL must point to an isolated loopback Redis")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    user = get_user_model().objects.create_user(username="cancel-operator")
    client = APIClient()
    client.force_authenticate(user=user)

    def unexpected_access(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A cancelled scan must not access the source")

    monkeypatch.setattr(services, "checkout_github_repository", unexpected_access)
    app = Celery("ciclosec-isolated-cancellation-test", broker=redis_url, backend=redis_url)
    identifier = uuid.uuid4().hex

    @app.task(bind=True, name=f"test.cancel.{identifier}", max_retries=None)
    def worker_task(task: object, scan_id: int) -> dict[str, object]:
        return tasks._run_scan(task, scan_id, services.scan_registered_repository)

    queue = f"test-cancel-{identifier}"
    try:
        result = worker_task.apply_async(args=(scan.pk,), queue=queue)
        response = client.post(
            f"/api/scans/{scan.pk}/cancel-queued/", {"confirm": True}, format="json"
        )
        assert response.status_code == 200
        with start_worker(app, pool="solo", queues=[queue], perform_ping_check=False):
            outcome = result.get(timeout=15, disable_sync_subtasks=False)
    finally:
        app.close()

    assert outcome["disposition"] == "already_claimed"
    assert outcome["status"] == ScanRun.Status.CANCELLED
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.CANCELLED
    assert scan.started_at is None


@pytest.mark.django_db(transaction=True)
def test_scan_start_waits_for_concurrent_asset_disable() -> None:
    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    started = threading.Event()
    worker_pid: list[int] = []

    def claim() -> ScanRun:
        close_old_connections()
        try:
            with connections["default"].cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                worker_pid.append(cursor.fetchone()[0])
            started.set()
            return services._start_scan(
                scan.pk, kind=Asset.Kind.REPOSITORY, scanner_name="repository-security"
            )
        finally:
            connections["default"].close()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            locked_asset = Asset.objects.select_for_update().get(pk=asset.pk)
            locked_asset.enabled = False
            locked_asset.save(update_fields=["enabled"])
            future = executor.submit(claim)
            assert started.wait(5)
            deadline = time.monotonic() + 5
            wait_type = None
            while time.monotonic() < deadline:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                        [worker_pid[0]],
                    )
                    row = cursor.fetchone()
                wait_type = row[0] if row else None
                if wait_type == "Lock":
                    break
                time.sleep(0.02)
            assert wait_type == "Lock"
        result = future.result(timeout=5)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.FAILED
    assert result.started_at is None
    assert "disabled" in result.error_summary


@pytest.mark.django_db(transaction=True)
def test_cancellation_wins_against_a_blocked_worker() -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scanners import tasks

    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    user = get_user_model().objects.create_user(username="cancel-operator")
    client = APIClient()
    client.force_authenticate(user=user)
    started = threading.Event()
    worker_pid: list[int] = []

    def deliver() -> dict[str, object]:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                worker_pid.append(cursor.fetchone()[0])
            started.set()
            return tasks.scan_repository_task.run(scan.pk)
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            ScanRun.objects.select_for_update().get(pk=scan.pk)
            future = executor.submit(deliver)
            assert started.wait(5)
            deadline = time.monotonic() + 5
            wait_type = None
            while time.monotonic() < deadline:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                        [worker_pid[0]],
                    )
                    row = cursor.fetchone()
                wait_type = row[0] if row else None
                if wait_type == "Lock":
                    break
                time.sleep(0.02)
            assert wait_type == "Lock"
            response = client.post(
                f"/api/scans/{scan.pk}/cancel-queued/", {"confirm": True}, format="json"
            )
            assert response.status_code == 200
        outcome = future.result(timeout=5)

    assert outcome["disposition"] == "already_claimed"
    assert outcome["status"] == ScanRun.Status.CANCELLED
    scan.refresh_from_db()
    assert scan.status == ScanRun.Status.CANCELLED
    assert scan.started_at is None


def test_repository_scan_records_archive_access_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "SECRET_SENTINEL")

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> None:
            raise HTTPError(request.full_url, 404, "SECRET_SENTINEL", Message(), None)

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())
    result = services.scan_registered_repository(scan.pk)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.FAILED
    assert "HTTP 404" in result.error_summary
    assert "ref" in result.error_summary
    assert "access" in result.error_summary
    assert "SECRET_SENTINEL" not in result.error_summary
    assert result.metadata["repository_source"]["owner"] == "example"
    assert result.metadata["repository_source"]["ref"] == "main"


def test_repository_scan_records_rejected_archive_download_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "SECRET_SENTINEL")
    monkeypatch.setattr(
        github,
        "_request_archive_url",
        lambda *_args: "https://codeload.github.com/example/repo?secret=SECRET_SENTINEL",
    )
    headers = Message()
    headers["Location"] = "https://untrusted.example/collect"

    class FakeOpener:
        def open(self, request: Request, timeout: int) -> None:
            raise HTTPError(request.full_url, 302, "SECRET_SENTINEL", headers, None)

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())
    result = services.scan_registered_repository(scan.pk)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.FAILED
    assert "HTTP 302" in result.error_summary
    assert "SECRET_SENTINEL" not in result.error_summary
    assert result.sbom_documents.count() == 0


def test_dependabot_denial_keeps_scan_partial_and_preserves_sbom(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "SECRET_SENTINEL")
    monkeypatch.setattr(
        services, "run_trivy_sbom", lambda *_a, **_k: (ProcessResult(0, b"", b""), sbom)
    )
    monkeypatch.setattr(
        services, "run_osv_scanner", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(
        services, "run_trivy_findings", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(services, "scanner_version", lambda *_a, **_k: "1.0")

    def deny(request: Request, **_kwargs: object) -> None:
        raise HTTPError(request.full_url, 403, "SECRET_SENTINEL", Message(), None)

    class FakeOpener:
        open = staticmethod(deny)

    monkeypatch.setattr(github, "build_opener", lambda *_handlers: FakeOpener())
    result = services.scan_repository_checkout(scan, tmp_path)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.PARTIAL
    assert result.sbom_documents.count() == 1
    assert "HTTP 403" in result.warnings[0]
    assert "permissions" in result.warnings[0]
    assert "SECRET_SENTINEL" not in result.warnings[0]
    assert "Dependabot alerts: read" in result.warnings[0]
    assert "Dependabot alerts are enabled" in result.warnings[0]
    assert "dependabot_unavailable" in result.metadata["diagnostic_codes"]
    assert result.metadata["source_results"]["github_dependabot"] == {
        "status": "unavailable",
        "finding_count": None,
    }


def test_github_archive_extraction_rejects_path_traversal(tmp_path: Path) -> None:
    archive_path = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("repo-main/../../escape.txt", "not allowed")

    with pytest.raises(ScannerExecutionError, match="invalid path"):
        github._extract_archive(archive_path, tmp_path / "extract")

    assert not (tmp_path / "escape.txt").exists()


def test_github_archive_extraction_accepts_expected_repository_layout(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "safe.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("repo-main/", "")
        archive.writestr("repo-main/requirements.txt", "Flask==2.2.0\n")

    extracted = github._extract_archive(archive_path, tmp_path / "extract")

    assert (extracted / "requirements.txt").read_text(encoding="utf-8") == "Flask==2.2.0\n"


def test_scan_persists_sbom_and_redacted_findings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    osv_output: bytes,
    trivy_output: bytes,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset,
        owner="ciclogreen",
        repository_name="backend",
        credential_env="CICLOSEC_TEST_GITHUB_TOKEN",
    )
    scan_run = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    vulnerability = Vulnerability.objects.create(canonical_id="CVE-2026-0001")
    VulnerabilityAlias.objects.create(
        vulnerability=vulnerability,
        namespace=VulnerabilityAlias.Namespace.CVE,
        identifier="CVE-2026-0001",
    )
    monkeypatch.setenv("CICLOSEC_TEST_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        services,
        "run_trivy_sbom",
        lambda *_args, **_kwargs: (ProcessResult(0, b"", b""), sbom),
    )
    monkeypatch.setattr(
        services,
        "run_osv_scanner",
        lambda *_args, **_kwargs: (
            ProcessResult(0, osv_output, b""),
            adapters.parse_osv_output(osv_output, tmp_path),
        ),
    )
    monkeypatch.setattr(
        services,
        "run_trivy_findings",
        lambda *_args, **_kwargs: (
            ProcessResult(0, trivy_output, b""),
            adapters.parse_trivy_output(trivy_output, tmp_path),
        ),
    )
    monkeypatch.setattr(services, "list_dependabot_alerts", lambda *_args: [])
    monkeypatch.setattr(
        services,
        "scanner_version",
        lambda executable, *_args, **_kwargs: f"{executable} 1.0.0",
    )

    result = services.scan_repository_checkout(scan_run, tmp_path)

    assert result.status == ScanRun.Status.SUCCEEDED
    assert result.sbom_documents.count() == 1
    assert result.findings.count() == 3
    assert result.metadata["source_results"] == {
        "sbom": {"status": "available"},
        "osv_scanner": {"status": "available", "finding_count": 1},
        "trivy": {"status": "available", "finding_count": 2},
        "github_dependabot": {"status": "available", "finding_count": 0},
    }
    secret_finding = result.findings.get(kind=Finding.Kind.SECRET)
    assert "SECRET_VALUE_SENTINEL" not in json.dumps(secret_finding.evidence)
    osv_finding = result.findings.get(source=Finding.Source.OSV_SCANNER)
    assert osv_finding.component_occurrence is not None
    assert osv_finding.component_occurrence.component.name == "Flask"
    assert osv_finding.vulnerability_id == vulnerability.pk


def test_local_scanner_databases_always_produce_partial_unverified_coverage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset,
        owner="example",
        repository_name="backend",
        credential_env="TEST_GITHUB_TOKEN",
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        services.settings.CICLOSEC_CONFIG.scanning.execution,
        "repository_scanner_use_local_databases",
        True,
    )
    offline_options: list[bool] = []

    def local_sbom(*_args: object, offline: bool = False, **_kwargs: object):
        offline_options.append(offline)
        return ProcessResult(0, b"", b""), sbom

    def local_scanner(*_args: object, offline: bool = False, **_kwargs: object):
        offline_options.append(offline)
        return ProcessResult(0, b"", b""), ()

    monkeypatch.setattr(services, "run_trivy_sbom", local_sbom)
    monkeypatch.setattr(services, "run_osv_scanner", local_scanner)
    monkeypatch.setattr(services, "run_trivy_findings", local_scanner)
    monkeypatch.setattr(services, "list_dependabot_alerts", lambda *_args: [])
    monkeypatch.setattr(
        services, "scanner_version", lambda executable, *_a, **_k: f"{executable} 1.0"
    )

    result = services.scan_repository_checkout(scan, tmp_path)

    assert result.status == ScanRun.Status.PARTIAL
    assert result.metadata["scanner_database_mode"] == "local_cache"
    assert result.metadata["scanner_database_freshness"] == "unverified"
    assert "scanner_database_freshness_unverified" in result.metadata["diagnostic_codes"]
    assert "freshness could not be verified" in " ".join(result.warnings)
    assert "scanner_database_cache_unavailable" in result.metadata["diagnostic_codes"]
    assert result.metadata["local_database_status"]["osv_scanner"]["available"] is False
    assert result.metadata["local_database_status"]["trivy"]["available"] is False
    assert offline_options == [True, True, True]


def test_scanner_partial_result_keeps_sbom_and_warnings(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset,
        owner="ciclogreen",
        repository_name="backend",
        credential_env="CICLOSEC_TEST_GITHUB_TOKEN",
    )
    scan_run = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setenv("CICLOSEC_TEST_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        services,
        "run_trivy_sbom",
        lambda *_args, **_kwargs: (ProcessResult(0, b"", b""), sbom),
    )

    def fail_osv(*_args: object, **_kwargs: object) -> None:
        raise ScannerExecutionError("Required scanner is unavailable: osv-scanner")

    monkeypatch.setattr(services, "run_osv_scanner", fail_osv)
    monkeypatch.setattr(
        services,
        "run_trivy_findings",
        lambda *_args, **_kwargs: (ProcessResult(0, b'{"Results":[]}', b""), ()),
    )
    monkeypatch.setattr(services, "list_dependabot_alerts", lambda *_args: [])
    monkeypatch.setattr(
        services,
        "scanner_version",
        lambda executable, *_args, **_kwargs: f"{executable} 1.0.0",
    )

    result = services.scan_repository_checkout(scan_run, tmp_path)

    assert result.status == ScanRun.Status.PARTIAL
    assert result.sbom_documents.count() == 1
    assert result.warnings == [
        "OSV-Scanner scan unavailable: Required scanner is unavailable: osv-scanner"
    ]
    assert result.metadata["source_results"]["osv_scanner"] == {
        "status": "unavailable",
        "finding_count": None,
    }
    assert result.metadata["source_results"]["trivy"] == {
        "status": "available",
        "finding_count": 0,
    }
    result.refresh_from_db()
    assert result.metadata["diagnostic_codes"] == ["osv_unavailable"]


def test_malformed_trivy_findings_make_repository_scan_partial(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, osv_output: bytes
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        services, "run_trivy_sbom", lambda *_a, **_k: (ProcessResult(0, b"", b""), sbom)
    )
    monkeypatch.setattr(
        services,
        "run_osv_scanner",
        lambda *_a, **_k: (
            ProcessResult(0, osv_output, b""),
            adapters.parse_osv_output(osv_output, tmp_path),
        ),
    )
    monkeypatch.setattr(
        adapters,
        "run_process",
        lambda *_a, **_k: ProcessResult(0, b'{"Results":[{"Vulnerabilities":false}]}', b""),
    )
    monkeypatch.setattr(services, "scanner_version", lambda *_a, **_k: "1.0")
    monkeypatch.setattr(services, "list_dependabot_alerts", lambda *_a: [])

    result = services.scan_repository_checkout(scan, tmp_path)

    result.refresh_from_db()
    assert result.status == ScanRun.Status.PARTIAL
    assert result.sbom_documents.count() == 1
    assert result.findings.filter(source=Finding.Source.OSV_SCANNER).count() == 1
    assert "Trivy scan unavailable: Trivy returned an invalid vulnerability list" in result.warnings
    assert "trivy_unavailable" in result.metadata["diagnostic_codes"]
    assert result.metadata["source_results"]["trivy"] == {
        "status": "unavailable",
        "finding_count": None,
    }


def test_diagnostics_survive_multiple_warnings_and_correlation_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(
        services, "run_trivy_sbom", lambda *_a, **_k: (ProcessResult(0, b"", b""), sbom)
    )

    def fail_scanner(*_args: object, **_kwargs: object) -> None:
        raise ScannerExecutionError("private scanner error")

    def fail_correlation(*_args: object, **_kwargs: object) -> None:
        raise services.CorrelationError("private correlation error")

    monkeypatch.setattr(services, "run_osv_scanner", fail_scanner)
    monkeypatch.setattr(services, "run_trivy_findings", fail_scanner)
    monkeypatch.setattr(services, "scanner_version", lambda *_a, **_k: "1.0")
    monkeypatch.setattr(services, "reevaluate_findings", fail_correlation)

    services.scan_repository_checkout(scan, tmp_path)
    scan.refresh_from_db()

    assert scan.status == ScanRun.Status.PARTIAL
    assert scan.sbom_documents.count() == 1
    assert scan.metadata["diagnostic_codes"] == [
        "osv_unavailable",
        "trivy_unavailable",
        "dependabot_unavailable",
        "correlation_unavailable",
    ]


def test_invalid_generated_sbom_stops_before_optional_scans(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(
        asset=asset, owner="example", repository_name="repo", credential_env="TEST_GITHUB_TOKEN"
    )
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    monkeypatch.setenv("TEST_GITHUB_TOKEN", "test-token")
    monkeypatch.setattr(
        services,
        "run_trivy_sbom",
        lambda *_a, **_k: (ProcessResult(0, b"", b""), {"bomFormat": "CycloneDX"}),
    )

    def unexpected_call(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A failed required SBOM must not trigger optional scans")

    monkeypatch.setattr(services, "run_osv_scanner", unexpected_call)
    monkeypatch.setattr(services, "run_trivy_findings", unexpected_call)
    monkeypatch.setattr(services, "list_dependabot_alerts", unexpected_call)
    monkeypatch.setattr(services, "scanner_version", unexpected_call)

    result = services.scan_repository_checkout(scan, tmp_path)
    result.refresh_from_db()

    assert result.status == ScanRun.Status.FAILED
    assert result.metadata["diagnostic_codes"] == ["sbom_invalid"]
    assert "Generated SBOM failed validation" in result.error_summary
    assert not result.sbom_documents.exists()


def test_invalid_sbom_preserves_diagnostics_after_rollback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    scan = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    monkeypatch.setattr(
        services, "run_trivy_sbom", lambda *_a, **_k: (ProcessResult(0, b"", b""), sbom)
    )
    monkeypatch.setattr(
        services, "run_osv_scanner", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(
        services, "run_trivy_findings", lambda *_a, **_k: (ProcessResult(0, b"", b""), ())
    )
    monkeypatch.setattr(services, "scanner_version", lambda *_a, **_k: "1.0")

    def fail_ingestion(*_args: object, **_kwargs: object) -> None:
        raise services.SBOMValidationError("private validation error")

    monkeypatch.setattr(services, "ingest_sbom", fail_ingestion)
    services.scan_repository_checkout(scan, tmp_path)
    scan.refresh_from_db()

    assert scan.status == ScanRun.Status.FAILED
    assert scan.sbom_documents.count() == 0
    assert scan.metadata["diagnostic_codes"] == ["dependabot_unavailable", "sbom_invalid"]


@pytest.mark.parametrize("source_change", ["none", "different", "restore"])
def test_local_container_image_scan_persists_sbom_findings_and_digest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    trivy_output: bytes,
    source_change: str,
) -> None:
    from ciclosec.assets.services import get_asset_coverage, update_container_image_source

    image_reference = "ciclosec:fixture"
    image_id = f"sha256:{'a' * 64}"
    asset = Asset.objects.create(name="local-image", kind=Asset.Kind.CONTAINER_IMAGE)
    container_image = ContainerImage.objects.create(
        asset=asset,
        image_reference=image_reference,
    )
    scan_run = ScanRun.objects.create(asset=asset, scanner_name="queued")
    sbom = json.loads(SBOM_FIXTURE.read_text(encoding="utf-8"))
    config = CicloSecConfig.model_validate(
        {
            "docker": {
                "enabled": True,
                "allow_local_daemon": True,
                "images": [{"reference": image_reference}],
            }
        }
    )
    monkeypatch.setattr(services.settings, "CICLOSEC_CONFIG", config)
    monkeypatch.setattr(
        services,
        "resolve_local_docker_image",
        lambda *_args, **_kwargs: image_id,
    )

    def run_image_sbom(*_args: object, **_kwargs: object) -> tuple[ProcessResult, dict]:
        if source_change != "none":
            update_container_image_source(container_image, image_reference="ciclosec:other")
            if source_change == "restore":
                update_container_image_source(container_image, image_reference=image_reference)
        return ProcessResult(0, b"", b""), sbom

    monkeypatch.setattr(services, "run_trivy_image_sbom", run_image_sbom)
    monkeypatch.setattr(
        services,
        "run_trivy_image_findings",
        lambda *_args, **_kwargs: (
            ProcessResult(0, trivy_output, b""),
            adapters.parse_trivy_output(trivy_output, tmp_path),
        ),
    )
    monkeypatch.setattr(
        services,
        "scanner_version",
        lambda *_args, **_kwargs: "Trivy 0.1.0",
    )

    result = services.scan_registered_container_image(scan_run.pk)

    container_image.refresh_from_db()
    assert result.status == (
        ScanRun.Status.SUCCEEDED if source_change == "none" else ScanRun.Status.PARTIAL
    )
    assert result.sbom_documents.count() == 1
    assert result.findings.count() == 2
    if source_change == "none":
        assert container_image.resolved_digest == image_id
        assert container_image.digest_resolved_at is not None
    else:
        assert container_image.resolved_digest == ""
        assert container_image.digest_resolved_at is None
        assert "Image source changed during the scan" in result.warnings[0]
        assert "image_source_changed" in result.metadata["diagnostic_codes"]
    assert result.metadata["image_reference"] == image_reference
    assert result.metadata["image_source_revision"] == 0
    counts = get_asset_coverage()["counts"]
    assert counts["current" if source_change == "none" else "source_changed"] == 1
    assert result.metadata["image_source"] == "docker"
    assert result.metadata["image_digest"] == image_id
    secret_finding = result.findings.get(kind=Finding.Kind.SECRET)
    assert "SECRET_VALUE_SENTINEL" not in json.dumps(secret_finding.evidence)


def test_local_container_image_scan_rejects_non_allowlisted_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    asset = Asset.objects.create(name="local-image", kind=Asset.Kind.CONTAINER_IMAGE)
    ContainerImage.objects.create(asset=asset, image_reference="unlisted:latest")
    scan_run = ScanRun.objects.create(asset=asset, scanner_name="queued")
    config = CicloSecConfig.model_validate(
        {
            "docker": {
                "enabled": True,
                "allow_local_daemon": True,
                "images": [{"reference": "approved:latest"}],
            }
        }
    )
    monkeypatch.setattr(services.settings, "CICLOSEC_CONFIG", config)

    result = services.scan_registered_container_image(scan_run.pk)

    assert result.status == ScanRun.Status.FAILED
    assert "not allowlisted" in result.error_summary


def test_local_container_image_scan_fails_when_docker_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    image_reference = "ciclosec:fixture"
    asset = Asset.objects.create(name="local-image", kind=Asset.Kind.CONTAINER_IMAGE)
    container_image = ContainerImage.objects.create(
        asset=asset,
        image_reference=image_reference,
    )
    scan_run = ScanRun.objects.create(asset=asset, scanner_name="queued")
    config = CicloSecConfig.model_validate(
        {
            "docker": {
                "enabled": True,
                "allow_local_daemon": True,
                "images": [{"reference": image_reference}],
            }
        }
    )
    monkeypatch.setattr(services.settings, "CICLOSEC_CONFIG", config)

    def fail_inspection(*_args: object, **_kwargs: object) -> str:
        raise ScannerExecutionError("Docker daemon is unavailable")

    monkeypatch.setattr(services, "resolve_local_docker_image", fail_inspection)

    result = services.scan_registered_container_image(scan_run.pk)

    container_image.refresh_from_db()
    assert result.status == ScanRun.Status.FAILED
    assert "Docker daemon is unavailable" in result.error_summary
    assert container_image.resolved_digest == ""
    assert result.sbom_documents.count() == 0


def test_scan_request_requires_local_on_demand_opt_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    config = CicloSecConfig.model_validate({"scanning": {"execution": {"allow_on_demand": False}}})
    monkeypatch.setattr(services.settings, "CICLOSEC_CONFIG", config)

    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="ciclogreen", repository_name="backend")
    user = get_user_model().objects.create_user(username="scan-test")
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 403


def test_scan_request_rejects_repository_without_network_authorization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution,
        "allow_repository_scanners_with_network",
        False,
    )
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    client = APIClient()
    client.force_authenticate(user=get_user_model().objects.create_user(username="no-network"))
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 403
    assert response.data["code"] == "repository_scanner_network_not_authorized"
    assert not ScanRun.objects.filter(asset=asset).exists()
    assert queued == []


@pytest.mark.parametrize("kind", [Asset.Kind.REPOSITORY, Asset.Kind.CONTAINER_IMAGE])
def test_scan_request_rejects_disabled_asset(monkeypatch: pytest.MonkeyPatch, kind: str) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    config = CicloSecConfig.model_validate({"scanning": {"execution": {"allow_on_demand": True}}})
    monkeypatch.setattr(services.settings, "CICLOSEC_CONFIG", config)
    asset = Asset.objects.create(name="disabled", kind=kind, enabled=False)
    user = get_user_model().objects.create_user(username="disabled-scan-test")
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 400
    assert not ScanRun.objects.exists()


def test_scan_request_queues_an_allowlisted_local_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    image_reference = "ciclosec:fixture"
    config = CicloSecConfig.model_validate(
        {
            "scanning": {"execution": {"allow_on_demand": True}},
            "docker": {
                "enabled": True,
                "allow_local_daemon": True,
                "images": [{"reference": image_reference}],
            },
        }
    )
    monkeypatch.setattr(scan_views.settings, "CICLOSEC_CONFIG", config)
    queued_scan_ids: list[int] = []
    monkeypatch.setattr(
        scan_views.scan_container_image_task,
        "delay",
        lambda scan_run_id: queued_scan_ids.append(scan_run_id),
    )
    monkeypatch.setattr(
        scan_views.transaction,
        "on_commit",
        lambda callback: callback(),
    )
    asset = Asset.objects.create(name="local-image", kind=Asset.Kind.CONTAINER_IMAGE)
    ContainerImage.objects.create(asset=asset, image_reference=image_reference)
    user = get_user_model().objects.create_user(username="image-scan-test")
    client = APIClient()
    client.force_authenticate(user=user)

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 202
    assert response.data["scanner_name"] == "container-image-security"
    assert queued_scan_ids == [response.data["id"]]


@pytest.mark.parametrize("existing_status", [ScanRun.Status.QUEUED, ScanRun.Status.RUNNING])
def test_scan_request_rejects_an_existing_active_scan(
    monkeypatch: pytest.MonkeyPatch, existing_status: str
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    existing = ScanRun.objects.create(asset=asset, scanner_name="test", status=existing_status)
    user = get_user_model().objects.create_user(username="duplicate-scan")
    client = APIClient()
    client.force_authenticate(user=user)
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 409
    assert response.data["scan_id"] == existing.pk
    assert ScanRun.objects.filter(asset=asset).count() == 1
    assert queued == []


def test_scan_request_allows_new_scan_after_completion(monkeypatch: pytest.MonkeyPatch) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    monkeypatch.setattr(scan_views.transaction, "on_commit", lambda callback: callback())
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    ScanRun.objects.create(asset=asset, scanner_name="test", status=ScanRun.Status.FAILED)
    user = get_user_model().objects.create_user(username="new-scan")
    client = APIClient()
    client.force_authenticate(user=user)
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 202
    assert queued == [response.data["id"]]


def test_scan_request_rejects_full_default_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    monkeypatch.setattr(scan_views.transaction, "on_commit", lambda callback: callback())
    old_asset = Asset.objects.create(name="existing", kind=Asset.Kind.REPOSITORY)
    ScanRun.objects.bulk_create([ScanRun(asset=old_asset, scanner_name="test") for _ in range(50)])
    asset = Asset.objects.create(name="new", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="queue-full")
    client = APIClient()
    client.force_authenticate(user=user)
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 429
    assert not ScanRun.objects.filter(asset=asset).exists()
    assert queued == []


def test_queue_capacity_counts_only_queued_and_is_released_after_cancel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    config = CicloSecConfig.model_validate(
        {"scanning": {"execution": {"allow_on_demand": True, "max_queued_scans": 1}}}
    )
    config.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(scan_views.settings, "CICLOSEC_CONFIG", config)
    monkeypatch.setattr(scan_views.transaction, "on_commit", lambda callback: callback())
    asset = Asset.objects.create(name="existing", kind=Asset.Kind.REPOSITORY)
    pending = ScanRun.objects.create(asset=asset, scanner_name="test")
    ScanRun.objects.create(asset=asset, scanner_name="test", status=ScanRun.Status.RUNNING)
    new_asset = Asset.objects.create(name="new", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=new_asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="queue-release")
    client = APIClient()
    client.force_authenticate(user=user)
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)

    assert client.post("/api/scans/", {"asset": new_asset.pk}, format="json").status_code == 429
    assert (
        client.post(
            f"/api/scans/{pending.pk}/cancel-queued/", {"confirm": True}, format="json"
        ).status_code
        == 200
    )
    response = client.post("/api/scans/", {"asset": new_asset.pk}, format="json")

    assert response.status_code == 202
    assert queued == [response.data["id"]]


def test_duplicate_scan_conflict_is_preserved_when_queue_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    config = CicloSecConfig.model_validate(
        {"scanning": {"execution": {"allow_on_demand": True, "max_queued_scans": 1}}}
    )
    config.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(scan_views.settings, "CICLOSEC_CONFIG", config)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    pending = ScanRun.objects.create(asset=asset, scanner_name="test")
    client = APIClient()
    client.force_authenticate(user=get_user_model().objects.create_user(username="queue-duplicate"))

    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 409
    assert response.data["scan_id"] == pending.pk


@pytest.mark.django_db(transaction=True)
def test_simultaneous_requests_respect_configured_queue_capacity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    config = CicloSecConfig.model_validate(
        {"scanning": {"execution": {"allow_on_demand": True, "max_queued_scans": 1}}}
    )
    config.scanning.execution.allow_repository_scanners_with_network = True
    monkeypatch.setattr(scan_views.settings, "CICLOSEC_CONFIG", config)
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)
    assets = [Asset.objects.create(name=f"asset-{i}", kind=Asset.Kind.REPOSITORY) for i in range(2)]
    for i, asset in enumerate(assets):
        Repository.objects.create(asset=asset, owner="example", repository_name=f"repo-{i}")
    user = get_user_model().objects.create_user(username="concurrent-queue")
    barrier = threading.Barrier(2)
    worker_pids: list[int] = []

    def request_scan(asset_id: int) -> int:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                worker_pids.append(cursor.fetchone()[0])
            client = APIClient()
            client.force_authenticate(user=user)
            barrier.wait(timeout=10)
            return client.post("/api/scans/", {"asset": asset_id}, format="json").status_code
        finally:
            connections.close_all()

    ScanConcurrencyGate.objects.get_or_create(pk=1)
    with ThreadPoolExecutor(max_workers=2) as pool:
        with transaction.atomic():
            ScanConcurrencyGate.objects.select_for_update().get(pk=1)
            futures = [pool.submit(request_scan, asset.pk) for asset in assets]
            deadline = time.monotonic() + 10
            blocked = 0
            while time.monotonic() < deadline:
                if len(worker_pids) == 2:
                    with connection.cursor() as cursor:
                        cursor.execute("SELECT pg_stat_clear_snapshot()")
                        cursor.execute(
                            "SELECT count(*) FROM pg_stat_activity "
                            "WHERE pid IN (%s, %s) AND wait_event_type = 'Lock'",
                            worker_pids,
                        )
                        blocked = cursor.fetchone()[0]
                    if blocked == 2:
                        break
                time.sleep(0.02)
            assert blocked == 2
        statuses = [future.result(timeout=10) for future in futures]

    assert sorted(statuses) == [202, 429]
    assert ScanRun.objects.filter(status=ScanRun.Status.QUEUED).count() == 1
    assert len(queued) == 1


@pytest.mark.django_db(transaction=True)
def test_simultaneous_scan_requests_for_same_asset_are_serialized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="concurrent-scan")
    barrier = threading.Barrier(2)

    def request_scan() -> tuple[int, int]:
        close_old_connections()
        try:
            client = APIClient()
            client.force_authenticate(user=user)
            barrier.wait(timeout=10)
            response = client.post("/api/scans/", {"asset": asset.pk}, format="json")
            return response.status_code, response.data.get("id", response.data.get("scan_id"))
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _i: request_scan(), range(2)))

    assert sorted(status for status, _scan_id in results) == [202, 409]
    assert results[0][1] == results[1][1]
    assert ScanRun.objects.filter(asset=asset).count() == 1
    assert queued == [results[0][1]]


@pytest.mark.django_db(transaction=True)
def test_scan_request_waits_for_asset_lock_before_checking_active_scans(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    if connection.vendor != "postgresql":
        pytest.skip("Row locking requires PostgreSQL")
    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )

    def unexpected_dispatch(*_args: object, **_kwargs: object) -> None:
        pytest.fail("A duplicate scan must not be dispatched")

    monkeypatch.setattr(scan_views.scan_repository_task, "delay", unexpected_dispatch)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="waiting-scan")
    started = threading.Event()
    worker_pid: list[int] = []

    def request_scan() -> tuple[int, int]:
        close_old_connections()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                worker_pid.append(cursor.fetchone()[0])
            client = APIClient()
            client.force_authenticate(user=user)
            started.set()
            response = client.post("/api/scans/", {"asset": asset.pk}, format="json")
            return response.status_code, response.data["scan_id"]
        finally:
            connections.close_all()

    with ThreadPoolExecutor(max_workers=1) as executor:
        with transaction.atomic():
            Asset.objects.select_for_update().get(pk=asset.pk)
            future = executor.submit(request_scan)
            assert started.wait(5)
            deadline = time.monotonic() + 5
            wait_type = None
            while time.monotonic() < deadline:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT pg_stat_clear_snapshot()")
                    cursor.execute(
                        "SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s",
                        [worker_pid[0]],
                    )
                    row = cursor.fetchone()
                wait_type = row[0] if row else None
                if wait_type == "Lock":
                    break
                time.sleep(0.02)
            assert wait_type == "Lock"
            existing = ScanRun.objects.create(asset=asset, scanner_name="test")
        result = future.result(timeout=5)

    assert result == (409, existing.pk)
    assert ScanRun.objects.filter(asset=asset).count() == 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("commit", [True, False])
def test_scan_task_is_sent_only_after_transaction_commit(
    monkeypatch: pytest.MonkeyPatch, commit: bool
) -> None:
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    queued: list[int] = []
    monkeypatch.setattr(scan_views.scan_repository_task, "delay", queued.append)
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="transactional-scan")
    client = APIClient()
    client.force_authenticate(user=user)

    with transaction.atomic():
        response = client.post("/api/scans/", {"asset": asset.pk}, format="json")
        assert response.status_code == 202
        assert queued == []
        if not commit:
            transaction.set_rollback(True)

    assert queued == ([response.data["id"]] if commit else [])
    assert ScanRun.objects.filter(asset=asset).count() == int(commit)


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("worker_started", [False, True])
@pytest.mark.parametrize("kind", [Asset.Kind.REPOSITORY, Asset.Kind.CONTAINER_IMAGE])
def test_scan_dispatch_failure_is_uncertain_without_overwriting_worker_state(
    monkeypatch: pytest.MonkeyPatch,
    worker_started: bool,
    kind: str,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from django.contrib.auth import get_user_model
    from kombu.exceptions import OperationalError
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings,
        "CICLOSEC_CONFIG",
        CicloSecConfig.model_validate(
            {
                "scanning": {
                    "execution": {
                        "allow_on_demand": True,
                        "allow_repository_scanners_with_network": True,
                    }
                },
                "docker": {
                    "enabled": True,
                    "allow_local_daemon": True,
                    "images": [{"reference": "ciclosec:fixture"}],
                },
            }
        ),
    )
    asset = Asset.objects.create(name="backend", kind=kind)
    if kind == Asset.Kind.REPOSITORY:
        Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    else:
        ContainerImage.objects.create(asset=asset, image_reference="ciclosec:fixture")
    user = get_user_model().objects.create_user(username="broker-failure")
    client = APIClient()
    client.force_authenticate(user=user)

    def fail_dispatch(scan_id: int) -> None:
        if worker_started:
            services._start_scan(scan_id, kind=kind, scanner_name="test")
        raise OperationalError("private-broker-secret")

    task = (
        scan_views.scan_repository_task
        if kind == Asset.Kind.REPOSITORY
        else scan_views.scan_container_image_task
    )
    monkeypatch.setattr(task, "delay", fail_dispatch)
    response = client.post("/api/scans/", {"asset": asset.pk}, format="json")

    assert response.status_code == 503
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    assert scan.status == (ScanRun.Status.RUNNING if worker_started else ScanRun.Status.QUEUED)
    assert scan.metadata.get("dispatch_uncertain") is (None if worker_started else True)
    assert "private-broker-secret" not in str(response.data)
    assert "private-broker-secret" not in caplog.text
    assert client.post("/api/scans/", {"asset": asset.pk}, format="json").status_code == 409


@pytest.mark.django_db(transaction=True)
def test_deferred_dispatch_failure_is_recorded_after_outer_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from django.contrib.auth import get_user_model
    from kombu.exceptions import OperationalError
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="deferred-broker-failure")
    client = APIClient()
    client.force_authenticate(user=user)

    def fail_dispatch(_scan_id: int) -> None:
        raise OperationalError("private-broker-secret")

    monkeypatch.setattr(scan_views.scan_repository_task, "delay", fail_dispatch)
    with transaction.atomic():
        response = client.post("/api/scans/", {"asset": asset.pk}, format="json")
        assert response.status_code == 202
        assert ScanRun.objects.get(pk=response.data["id"]).metadata == {
            "initial_dispatch_pending": True
        }
    scan = ScanRun.objects.get(pk=response.data["id"])
    assert scan.status == ScanRun.Status.QUEUED
    assert scan.metadata["dispatch_uncertain"] is True


@pytest.mark.django_db(transaction=True)
def test_unreachable_local_broker_records_uncertain_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from celery import Celery
    from django.contrib.auth import get_user_model
    from rest_framework.test import APIClient

    from ciclosec.scans.api import views as scan_views

    monkeypatch.setattr(
        scan_views.settings.CICLOSEC_CONFIG.scanning.execution, "allow_on_demand", True
    )
    asset = Asset.objects.create(name="backend", kind=Asset.Kind.REPOSITORY)
    Repository.objects.create(asset=asset, owner="example", repository_name="repo")
    user = get_user_model().objects.create_user(username="unreachable-broker")
    client = APIClient()
    client.force_authenticate(user=user)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as unavailable:
        unavailable.bind(("127.0.0.1", 0))
        port = unavailable.getsockname()[1]
        app = Celery("isolated-broker-test", broker=f"redis://127.0.0.1:{port}/0")
        try:
            monkeypatch.setattr(
                scan_views.scan_repository_task,
                "delay",
                lambda scan_id: app.send_task(
                    "ciclosec.scanners.tasks.scan_repository_task",
                    args=(scan_id,),
                    retry=False,
                ),
            )
            response = client.post("/api/scans/", {"asset": asset.pk}, format="json")
        finally:
            app.close()

    assert response.status_code == 503
    scan = ScanRun.objects.get(pk=response.data["scan_id"])
    assert scan.status == ScanRun.Status.QUEUED
    assert scan.metadata["dispatch_uncertain"] is True
