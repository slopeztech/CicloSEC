"""Worker and Redis restarts using disposable, locally published services.

Run with CICLOSEC_TEST_WORKER_RESTART=1 and local Docker images postgres:16-alpine
and redis:7-alpine. The test never connects to configured application services.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import subprocess
import sys
import time
import uuid
import warnings
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[2]
FILE = Path(__file__).resolve()
TASK = "ciclosec.scanners.tasks.scan_repository_task"


def _helper() -> None:
    import django

    from ciclosec.common import config

    # Never inherit database/broker environment-variable names from user configuration.
    config.load_config = lambda _path: config.CicloSecConfig()
    django.setup()
    from django.core.management import call_command

    if sys.argv[1] == "setup":
        from ciclosec.assets.models import Asset, Repository
        from ciclosec.scans.models import ScanRun

        call_command("migrate", interactive=False, verbosity=0)
        asset = Asset.objects.create(name="isolated-restart-test", kind=Asset.Kind.REPOSITORY)
        Repository.objects.create(
            asset=asset,
            owner="not-accessed",
            repository_name="not-accessed",
            credential_env="CICLOSEC_TEST_TOKEN",
        )
        scan = ScanRun.objects.create(
            asset=asset, scanner_name="test", metadata={"original": "preserved"}
        )
        print(scan.pk)
    elif sys.argv[1] == "recover":
        call_command(
            "recover_interrupted_scan",
            sys.argv[2],
            "--operator",
            "test-operator",
            *sys.argv[3:],
        )
    elif sys.argv[1] == "cancel":
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIClient

        user = get_user_model().objects.create_user(username="isolated-operator", is_staff=True)
        client = APIClient()
        client.force_authenticate(user=user)
        response = client.post(
            f"/api/scans/{sys.argv[2]}/cancel-queued/",
            {"confirm": True},
            format="json",
            HTTP_HOST="localhost",
        )
        assert response.status_code == 200, response.content
        print(json.dumps({"response": response.data, "user_id": user.pk}))
    elif sys.argv[1] == "worker":
        from redis import Redis

        from ciclosec.scanners import services

        redis = Redis.from_url(os.environ["CICLOSEC_REDIS_URL"])

        def blocked_source(*_args: object, **_kwargs: object) -> None:
            redis.incr("test:source-calls")
            while True:
                time.sleep(1)

        # No checkout, scanner, network request, or temporary directory is created.
        services.checkout_github_repository = blocked_source
        services.tempfile = SimpleNamespace(
            TemporaryDirectory=lambda **_kwargs: contextlib.nullcontext(str(ROOT))
        )
        from ciclosec.project.celery import app

        app.worker_main(
            [
                "worker",
                "--pool=solo",
                "--concurrency=1",
                "--loglevel=WARNING",
                "--without-gossip",
                "--without-mingle",
                "--without-heartbeat",
                "--queues",
                os.environ["CICLOSEC_TEST_QUEUE"],
            ]
        )
    else:
        raise ValueError("unknown helper")


def _stop(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        process.kill()
    process.wait(timeout=15)
    assert process.poll() is not None


def _wait_for(predicate: Callable[[], bool], *, seconds: float = 45) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("Timed out waiting for isolated worker or service")


@pytest.mark.skipif(
    os.environ.get("CICLOSEC_TEST_WORKER_RESTART") != "1",
    reason="opt in to disposable local Docker services with CICLOSEC_TEST_WORKER_RESTART=1",
)
@pytest.mark.parametrize("scenario", ["worker", "redis"])
def test_isolated_restart_and_manual_recovery(scenario: str) -> None:
    import psycopg
    from celery import Celery
    from redis import Redis
    from redis.exceptions import RedisError

    def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["docker", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=check,
            timeout=60,
        )

    context = docker("context", "show").stdout.strip()
    endpoint = docker(
        "context", "inspect", context, "--format", "{{.Endpoints.docker.Host}}"
    ).stdout.strip()
    if not (endpoint.startswith("npipe:") or endpoint.startswith("unix:")):
        pytest.skip("Docker endpoint must be a local named pipe or Unix socket")
    for image in ("postgres:16-alpine", "redis:7-alpine"):
        if docker("--context", context, "image", "inspect", image, check=False).returncode:
            pytest.skip(f"Local Docker image missing: {image}")

    identifier = uuid.uuid4().hex
    prefix = f"ciclosec-restart-{identifier}"
    network_name = ""
    names = [f"{prefix}-pg", f"{prefix}-redis"]
    containers: list[str] = []
    network_id = ""
    processes: list[subprocess.Popen[bytes]] = []
    app = None
    redis = None
    cleanup_errors = []

    def dc(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return docker("--context", context, *args, check=check)

    def discover(kind: str, name: str) -> str:
        result = dc(kind, "inspect", name, "--format", "{{.Id}}", check=False)
        return result.stdout.strip() if result.returncode == 0 else ""

    def helper(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(FILE), *args],
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=check,
            timeout=90,
        )

    try:

        def port_for(container: str, port: str) -> int | None:
            result = dc("port", container, f"{port}/tcp", check=False)
            if result.returncode:
                return None
            output = result.stdout.strip()
            host, published = output.rsplit(":", 1)
            assert host == "127.0.0.1"
            return int(published)

        for internal in (True, False):
            network_name = f"{prefix}-{'internal' if internal else 'bridge'}"
            args = ["network", "create"]
            if internal:
                args.append("--internal")
            network_id = dc(*args, network_name).stdout.strip()
            for name, image, port, extra, command in (
                (
                    names[0],
                    "postgres:16-alpine",
                    "5432",
                    ["-e", "POSTGRES_PASSWORD=isolated-test", "-e", "POSTGRES_DB=isolated_test"],
                    [],
                ),
                (
                    names[1],
                    "redis:7-alpine",
                    "6379",
                    [],
                    ["redis-server", "--save", "", "--appendonly", "no"],
                ),
            ):
                container = dc(
                    "create",
                    "--pull",
                    "never",
                    "--name",
                    name,
                    "--network",
                    network_id,
                    "-p",
                    f"127.0.0.1::{port}",
                    *extra,
                    image,
                    *command,
                ).stdout.strip()
                containers.append(container)
                dc("start", container)

            db_port = port_for(containers[0], "5432")
            redis_port = port_for(containers[1], "6379")

            def ports_respond(
                db_port: int | None = db_port, redis_port: int | None = redis_port
            ) -> bool:
                if db_port is None or redis_port is None:
                    return False
                try:
                    for port in (db_port, redis_port):
                        with socket.create_connection(("127.0.0.1", port), timeout=1):
                            pass
                    return True
                except OSError:
                    return False

            try:
                if db_port is None or redis_port is None:
                    raise AssertionError("Docker did not publish both loopback ports")
                _wait_for(ports_respond, seconds=25)
                break
            except AssertionError:
                if not internal:
                    raise
                warnings.warn(
                    "Docker --internal network has no usable loopback ports; "
                    "falling back to a dedicated bridge with loopback-only publication",
                    RuntimeWarning,
                    stacklevel=2,
                )
                for container in reversed(containers):
                    dc("rm", "-f", "-v", container)
                containers.clear()
                dc("network", "rm", network_id)
                network_id = ""

        assert db_port is not None and redis_port is not None
        db_url = f"postgresql://postgres:isolated-test@127.0.0.1:{db_port}/isolated_test"
        redis_url = f"redis://127.0.0.1:{redis_port}/0"
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith(("CICLOSEC_", "CELERY_", "PG", "REDIS_"))
        }
        env.update(
            {
                "CICLOSEC_DATABASE_URL": db_url,
                "CICLOSEC_REDIS_URL": redis_url,
                "CICLOSEC_DJANGO_SECRET_KEY": "isolated-test-secret",
                "CICLOSEC_TEST_TOKEN": "unused",
                "CICLOSEC_TEST_QUEUE": f"test-restart-{identifier}",
                "CICLOSEC_CONFIG_PATH": str(ROOT / "config" / "ciclosec.yaml"),
                "DJANGO_SETTINGS_MODULE": "ciclosec.project.settings",
                "PYTHONPATH": str(ROOT / "src"),
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        redis = Redis.from_url(redis_url, socket_connect_timeout=1, socket_timeout=1)

        def ready() -> bool:
            try:
                with psycopg.connect(db_url, connect_timeout=1):
                    return bool(redis.ping())
            except (psycopg.Error, RedisError, OSError):
                return False

        _wait_for(ready)
        scan_id = int(helper("setup").stdout.strip())

        def row() -> tuple:
            with psycopg.connect(db_url, connect_timeout=2) as conn:
                return conn.execute(
                    "SELECT status, started_at, finished_at, metadata, error_summary "
                    "FROM scans_scanrun WHERE id = %s",
                    (scan_id,),
                ).fetchone()

        app = Celery("restart-test", broker=redis_url, backend=redis_url)
        app.conf.update(broker_connection_retry_on_startup=False, task_publish_retry=False)
        queue = env["CICLOSEC_TEST_QUEUE"]
        if scenario == "redis":
            assert not processes
            assert redis.config_get("save")["save"] == ""
            assert redis.config_get("appendonly")["appendonly"] == "no"
            before = row()
            assert before[0] == "queued" and before[1] is None and before[2] is None
            assert redis.llen(queue) == 0
            result = app.send_task(TASK, args=[scan_id], queue=queue)
            assert redis.llen(queue) == 1
            message = json.loads(redis.lindex(queue, 0))
            assert message["headers"]["id"] == result.id
            assert message["headers"]["task"] == TASK
            assert json.loads(base64.b64decode(message["body"]))[0] == [scan_id]
            assert row() == before
            assert redis.get("test:source-calls") is None

            def started_at(container: str) -> str:
                return dc("inspect", container, "--format", "{{.State.StartedAt}}").stdout.strip()

            pg_started, redis_started = map(started_at, containers)
            app.close()
            app = None
            redis.close()
            assert dc("restart", containers[1]).stdout.strip() == containers[1]
            assert started_at(containers[1]) != redis_started
            assert started_at(containers[0]) == pg_started
            redis_port = port_for(containers[1], "6379")
            assert redis_port is not None
            redis = Redis.from_url(
                f"redis://127.0.0.1:{redis_port}/0", socket_connect_timeout=1, socket_timeout=1
            )
            try:
                _wait_for(ready, seconds=20)
            except AssertionError as error:
                state = dc("inspect", containers[1], "--format", "{{json .State}}").stdout
                logs = dc("logs", containers[1], check=False)
                raise AssertionError(
                    f"Redis not ready after restart: {state}; {logs.stdout}; {logs.stderr}"
                ) from error
            assert redis.config_get("save")["save"] == ""
            assert redis.config_get("appendonly")["appendonly"] == "no"
            assert redis.llen(queue) == 0
            assert redis.get("test:source-calls") is None
            assert row() == before
            assert not processes
            cancelled = json.loads(helper("cancel", str(scan_id)).stdout)
            assert cancelled["response"] == {"id": scan_id, "status": "cancelled"}
            after = row()
            assert after[0] == "cancelled" and after[1] is None and after[2] is not None
            assert after[3]["original"] == "preserved"
            assert after[3]["cancelled_by_user_id"] == cancelled["user_id"]
            assert redis.llen(queue) == 0
            assert redis.get("test:source-calls") is None
            assert not processes
            return

        app.send_task(TASK, args=[scan_id], queue=queue)

        def start_worker() -> subprocess.Popen[bytes]:
            process = subprocess.Popen(
                [sys.executable, str(FILE), "worker"],
                cwd=ROOT,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            processes.append(process)
            return process

        first = start_worker()

        def source_started() -> bool:
            assert first.poll() is None, "worker exited before entering simulated source"
            return redis.get("test:source-calls") == b"1" and row()[0] == "running"

        _wait_for(source_started)
        before = row()
        assert before[1] is not None and before[2] is None
        _stop(first)
        assert all(process.poll() is not None for process in processes)
        assert row() == before  # A dead worker is not an automatic recovery mechanism.
        denied = helper("recover", str(scan_id), check=False)
        assert denied.returncode != 0
        assert row() == before
        helper("recover", str(scan_id), "--confirm-all-workers-and-scanners-stopped")
        recovered = row()
        assert recovered[0] == "failed"
        assert recovered[1] == before[1] and recovered[2] is not None
        assert recovered[3]["original"] == "preserved"
        assert recovered[3]["manual_recovery"] == {
            "operator": "test-operator",
            "confirmed_all_workers_and_scanners_stopped": True,
        }
        assert "manually_recovered" in recovered[3]["diagnostic_codes"]
        assert recovered[4]

        # Publish a deterministic duplicate; Redis visibility/redelivery timing is not assumed.
        duplicate = app.send_task(TASK, args=[scan_id], queue=queue)
        second = start_worker()
        result = duplicate.get(timeout=45)
        assert second.poll() is None
        assert result["disposition"] == "already_claimed"
        assert result["status"] == "failed"
        assert result["scan_run_id"] == scan_id
        assert redis.get("test:source-calls") == b"1"
        assert row() == recovered
        with psycopg.connect(db_url) as conn:
            assert conn.execute("SELECT COUNT(*) FROM scans_scanrun").fetchone()[0] == 1
    finally:
        for process in reversed(processes):
            try:
                _stop(process)
            except Exception as error:
                cleanup_errors.append(f"worker {process.pid}: {error}")
        for client in (app, redis):
            if client is not None:
                try:
                    client.close()
                except Exception as error:
                    cleanup_errors.append(f"client: {error}")
        for name in names:
            try:
                container = discover("container", name)
                if container and container not in containers:
                    containers.append(container)
            except Exception as error:
                cleanup_errors.append(f"discover container {name}: {error}")
        for container in reversed(containers):
            try:
                removed = dc("rm", "-f", "-v", container, check=False)
                if removed.returncode:
                    cleanup_errors.append(f"container {container}: {removed.stderr.strip()}")
            except Exception as error:
                cleanup_errors.append(f"container {container}: {error}")
        try:
            if not network_id:
                network_id = discover("network", network_name)
            if network_id:
                removed = dc("network", "rm", network_id, check=False)
                if removed.returncode:
                    cleanup_errors.append(f"network {network_id}: {removed.stderr.strip()}")
        except Exception as error:
            cleanup_errors.append(f"network {network_id or network_name}: {error}")
        assert not cleanup_errors, "; ".join(cleanup_errors)


if __name__ == "__main__":
    _helper()
