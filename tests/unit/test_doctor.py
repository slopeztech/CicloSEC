"""Safe diagnostics for local services."""

import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import MagicMock

import pytest
import redis
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import DatabaseError

from ciclosec.common.management.commands import ciclosec_doctor as doctor
from ciclosec.scanners.process import ScannerExecutionError


@pytest.mark.parametrize(("configured", "expected"), [(None, 3), (10, 10)])
def test_postgresql_probe_bounds_connection_without_overriding_configuration(
    monkeypatch: pytest.MonkeyPatch, configured: int | None, expected: int
) -> None:
    db = MagicMock()
    db.vendor = "postgresql"
    options = {} if configured is None else {"connect_timeout": configured}
    db.settings_dict = {"OPTIONS": options}

    def connect() -> MagicMock:
        assert options["connect_timeout"] == expected
        cursor = MagicMock()
        cursor.__enter__.return_value.fetchone.return_value = (1,)
        return cursor

    db.cursor.side_effect = connect
    monkeypatch.setattr(doctor, "connection", db)

    assert doctor._database()
    assert options == ({} if configured is None else {"connect_timeout": configured})


def test_web_probe_uses_an_allowed_host_header() -> None:
    class LoginHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/accounts/login/" and self.headers.get("Host") == "127.0.0.1":
                self.send_response(200)
            else:
                self.send_response(400)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), LoginHandler)
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        assert doctor._web("127.0.0.1", server.server_port)
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


@pytest.fixture
def healthy(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, int]]:
    web_calls: list[tuple[str, int]] = []
    monkeypatch.setattr(doctor, "_database", lambda: True)
    monkeypatch.setattr(doctor, "_migrations_pending", lambda: False)
    monkeypatch.setattr(doctor, "_broker", lambda: True)
    monkeypatch.setattr(doctor, "_worker", lambda: True)
    monkeypatch.setattr(doctor, "_web", lambda host, port: web_calls.append((host, port)) or True)
    monkeypatch.setattr(
        doctor,
        "get_scan_queue_status",
        lambda: {
            "queued_count": 2,
            "queued_limit": 10,
            "running_count": 1,
            "running_limit": 4,
            "delivery_uncertain_count": 1,
            "queue_full": False,
        },
    )
    monkeypatch.setattr(
        doctor,
        "list_scan_history",
        lambda **_kwargs: {
            "total": 2,
            "limit": 5,
            "offset": 0,
            "items": [
                {
                    "id": 18,
                    "status": "failed",
                    "has_error": True,
                    "asset_name": "private-repository",
                },
                {
                    "id": 17,
                    "status": "succeeded",
                    "has_error": False,
                    "asset_name": "private-repository",
                },
            ],
        },
    )
    monkeypatch.setattr(doctor, "scanner_version", lambda *args, **kwargs: "test version")
    return web_calls


@pytest.mark.parametrize(
    ("mode", "host", "port"),
    [("native", "127.0.0.1", 8009), ("docker", "web", 8000)],
)
def test_diagnostics_report_all_checks_without_claiming_beat_is_running(
    healthy: list[tuple[str, int]],
    mode: str,
    host: str,
    port: int,
) -> None:
    output = io.StringIO()
    call_command(
        "ciclosec_doctor",
        mode=mode,
        web_port=port,
        min_free_mib=0,
        as_json=True,
        stdout=output,
    )
    checks = {item["name"]: item for item in json.loads(output.getvalue())["checks"]}

    assert healthy == [(host, port)]
    assert all(
        checks[name]["status"] == "ok"
        for name in ("configuration", "disk", "database", "migrations", "redis", "worker", "web")
    )
    assert checks["trivy"]["status"] == checks["osv-scanner"]["status"] == "ok"
    assert checks["beat"]["status"] == "unknown"
    expected_count = len(doctor.app.conf.beat_schedule)
    assert f"Hay {expected_count} tarea(s) periódica(s) en el YAML base" in checks["beat"]["detail"]
    if mode == "docker":
        assert "docker compose --profile scheduler ps beat" in checks["beat"]["detail"]
    else:
        assert "proceso y los logs de Celery Beat" in checks["beat"]["detail"]
    assert checks["scanner_scope"]["status"] == "info"
    assert checks["scan_queue"]["status"] == "info"
    assert "entregas inciertas: 1" in checks["scan_queue"]["detail"]
    assert checks["scan_history"]["status"] == "info"
    assert "#18 failed (fallo registrado)" in checks["scan_history"]["detail"]
    assert "private-repository" not in output.getvalue()


@pytest.mark.parametrize(
    ("mode", "instruction"),
    [
        ("docker", "docker compose --profile scheduler ps beat"),
        ("native", "proceso y los logs de Celery Beat"),
    ],
)
def test_beat_diagnostic_reports_configuration_and_mode_specific_probe(
    mode: str, instruction: str
) -> None:
    check = doctor._beat_check(mode, scheduled_task_count=2)

    assert check["status"] == "unknown"
    assert "Hay 2 tarea(s) periódica(s)" in check["detail"]
    assert instruction in check["detail"]


def test_beat_is_not_required_without_periodic_tasks() -> None:
    check = doctor._beat_check("native", scheduled_task_count=0)

    assert check["status"] == "info"
    assert "Beat no es necesario" in check["detail"]


def test_unavailable_database_and_broker_are_sanitized_and_skip_dependent_probes(
    healthy: list[tuple[str, int]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def database_failure() -> bool:
        raise DatabaseError("credential-sentinel")

    def broker_failure() -> bool:
        raise redis.exceptions.ConnectionError("credential-sentinel")

    def unexpected_call() -> bool:
        pytest.fail("A dependent probe must not run when its prerequisite failed")

    monkeypatch.setattr(doctor, "_database", database_failure)
    monkeypatch.setattr(doctor, "_broker", broker_failure)
    monkeypatch.setattr(doctor, "_migrations_pending", unexpected_call)
    monkeypatch.setattr(doctor, "_worker", unexpected_call)
    output = io.StringIO()
    with pytest.raises(CommandError):
        call_command("ciclosec_doctor", mode="docker", min_free_mib=0, as_json=True, stdout=output)
    checks = {item["name"]: item for item in json.loads(output.getvalue())["checks"]}

    assert "credential-sentinel" not in output.getvalue()
    assert checks["database"]["status"] == checks["redis"]["status"] == "error"
    assert checks["migrations"]["status"] == checks["worker"]["status"] == "unknown"
    assert checks["scan_queue"]["status"] == checks["scan_history"]["status"] == "unknown"
    assert checks["web"]["status"] == "ok"


def test_partial_failures_are_reported_without_exposing_scanner_errors(
    healthy: list[tuple[str, int]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(doctor, "_migrations_pending", lambda: True)
    monkeypatch.setattr(doctor, "_worker", lambda: False)
    monkeypatch.setattr(doctor, "_web", lambda *_args: False)

    def missing_scanner(*args: object, **kwargs: object) -> str:
        raise ScannerExecutionError("credential-sentinel")

    monkeypatch.setattr(doctor, "scanner_version", missing_scanner)
    output = io.StringIO()
    with pytest.raises(CommandError):
        call_command("ciclosec_doctor", mode="native", min_free_mib=0, as_json=True, stdout=output)
    checks = {item["name"]: item for item in json.loads(output.getvalue())["checks"]}

    for name in ("migrations", "worker", "web", "trivy", "osv-scanner"):
        assert checks[name]["status"] == "error"
    assert "credential-sentinel" not in output.getvalue()


def test_queue_and_history_failures_are_sanitized(
    healthy: list[tuple[str, int]], monkeypatch: pytest.MonkeyPatch
) -> None:
    def queue_failure() -> dict[str, int | bool]:
        raise DatabaseError("queue-credential-sentinel")

    def history_failure(**_kwargs: object) -> dict[str, object]:
        raise ValueError("history-data-sentinel")

    monkeypatch.setattr(doctor, "get_scan_queue_status", queue_failure)
    monkeypatch.setattr(doctor, "list_scan_history", history_failure)
    output = io.StringIO()
    with pytest.raises(CommandError):
        call_command(
            "ciclosec_doctor",
            mode="native",
            min_free_mib=0,
            as_json=True,
            stdout=output,
        )
    checks = {item["name"]: item for item in json.loads(output.getvalue())["checks"]}

    assert checks["scan_queue"]["status"] == "error"
    assert checks["scan_history"]["status"] == "error"
    assert "queue-credential-sentinel" not in output.getvalue()
    assert "history-data-sentinel" not in output.getvalue()


@pytest.mark.parametrize(
    "options",
    [{"web_port": 0}, {"web_port": 65536}, {"min_free_mib": -1}],
)
def test_invalid_probe_limits_are_rejected(options: dict[str, int]) -> None:
    with pytest.raises(CommandError):
        call_command("ciclosec_doctor", mode="native", **options)
