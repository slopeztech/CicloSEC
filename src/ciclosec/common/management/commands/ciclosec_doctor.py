"""Read-only local service diagnostics."""

import json
import shutil
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import redis
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError, CommandParser
from django.db import DatabaseError, connection
from django.db.migrations.executor import MigrationExecutor
from kombu.exceptions import OperationalError

from ciclosec.project.celery import app
from ciclosec.scanners.adapters import inspect_local_scanner_databases, scanner_version
from ciclosec.scanners.process import ScannerExecutionError
from ciclosec.scans.services import get_scan_queue_status, list_scan_history


def _database() -> bool:
    options = connection.settings_dict["OPTIONS"]
    added_timeout = connection.vendor == "postgresql" and "connect_timeout" not in options
    if added_timeout:
        options["connect_timeout"] = 3
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            return bool(cursor.fetchone() == (1,))
    finally:
        if added_timeout:
            del options["connect_timeout"]


def _migrations_pending() -> bool:
    executor = MigrationExecutor(connection)
    return bool(executor.migration_plan(executor.loader.graph.leaf_nodes()))


def _broker() -> bool:
    client = redis.Redis.from_url(
        settings.CELERY_BROKER_URL,
        socket_connect_timeout=3,
        socket_timeout=3,
    )
    try:
        return bool(client.ping())
    finally:
        client.close()


def _worker() -> bool:
    return bool(app.control.inspect(timeout=3).ping())


def _beat_check(mode: str, scheduled_task_count: int) -> dict[str, str]:
    if scheduled_task_count == 0:
        return {
            "name": "beat",
            "status": "info",
            "detail": "No hay tareas periódicas configuradas; Beat no es necesario.",
        }
    beat_check = (
        "Comprueba `docker compose --profile scheduler ps beat`."
        if mode == "docker"
        else "Comprueba el proceso y los logs de Celery Beat."
    )
    return {
        "name": "beat",
        "status": "unknown",
        "detail": (
            f"Hay {scheduled_task_count} tarea(s) periódica(s) en el YAML base, "
            "sin consultar las sobrescrituras persistidas; "
            f"pero el proceso Beat no se verifica desde este comando. {beat_check}"
        ),
    }


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _web(host: str, port: int) -> bool:
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    request = Request(f"http://{host}:{port}/accounts/login/", headers={"Host": "127.0.0.1"})
    with opener.open(request, timeout=3) as response:
        return int(response.status) == 200


class Command(BaseCommand):
    help = "Comprueba los servicios locales sin iniciar tareas ni modificar datos."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("--mode", choices=("native", "docker"), required=True)
        parser.add_argument("--web-port", type=int, default=8000)
        parser.add_argument("--min-free-mib", type=int, default=1024)
        parser.add_argument("--json", action="store_true", dest="as_json")

    def handle(self, *args: object, **options: object) -> None:
        mode = options["mode"]
        port = options["web_port"]
        minimum = options["min_free_mib"]
        if not isinstance(mode, str) or mode not in ("native", "docker"):
            raise CommandError("--mode debe ser native o docker")
        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise CommandError("--web-port debe estar entre 1 y 65535")
        if not isinstance(minimum, int) or minimum < 0:
            raise CommandError("--min-free-mib debe ser cero o un entero positivo")
        host = "web" if mode == "docker" else "127.0.0.1"
        checks: list[dict[str, str]] = []

        def add(name: str, ok: bool, success: str, failure: str) -> None:
            checks.append(
                {
                    "name": name,
                    "status": "ok" if ok else "error",
                    "detail": success if ok else failure,
                }
            )

        add("configuration", True, "Configuración cargada.", "")
        try:
            available_mib = shutil.disk_usage(Path.cwd()).free // (1024 * 1024)
            add(
                "disk",
                available_mib >= minimum,
                f"Sistema de archivos del proceso: {available_mib} MiB disponibles.",
                f"Solo hay {available_mib} MiB disponibles; el mínimo es {minimum} MiB.",
            )
        except OSError:
            add("disk", False, "", "No se puede comprobar el espacio del proceso.")

        try:
            database_ok = _database()
        except (DatabaseError, OSError):
            database_ok = False
        add(
            "database",
            database_ok,
            "La base de datos configurada responde.",
            "Base de datos no disponible o credenciales inválidas; revisa servicio y "
            "configuración.",
        )
        if database_ok:
            try:
                queue = get_scan_queue_status()
            except DatabaseError:
                add(
                    "scan_queue",
                    False,
                    "",
                    "No se puede consultar el estado registrado de la cola.",
                )
            else:
                checks.append(
                    {
                        "name": "scan_queue",
                        "status": "info",
                        "detail": (
                            f"En cola: {queue['queued_count']}/{queue['queued_limit']}; "
                            f"en ejecución: {queue['running_count']}/"
                            f"{queue['running_limit']}; "
                            f"entregas inciertas: {queue['delivery_uncertain_count']}; "
                            f"cola llena: {'sí' if queue['queue_full'] else 'no'}."
                        ),
                    }
                )
            try:
                history = list_scan_history(asset_id=None, limit=5, offset=0)
            except (DatabaseError, ValueError):
                add(
                    "scan_history",
                    False,
                    "",
                    "No se puede consultar el historial reciente de escaneos.",
                )
            else:
                summaries = []
                for scan in history["items"]:
                    summary = f"#{scan['id']} {scan['status']}"
                    if scan["has_error"]:
                        summary += " (fallo registrado)"
                    summaries.append(summary)
                detail = "; ".join(summaries) if summaries else "No hay escaneos registrados."
                checks.append(
                    {
                        "name": "scan_history",
                        "status": "info",
                        "detail": f"Últimos escaneos: {detail}",
                    }
                )
            try:
                migrations_ok = not _migrations_pending()
            except (DatabaseError, OSError):
                migrations_ok = False
            add(
                "migrations",
                migrations_ok,
                "No hay migraciones pendientes.",
                "Migraciones pendientes o no verificables; revisa manage.py migrate --plan.",
            )
        else:
            checks.append(
                {
                    "name": "migrations",
                    "status": "unknown",
                    "detail": "Base de datos no disponible.",
                }
            )
            checks.extend(
                [
                    {
                        "name": "scan_queue",
                        "status": "unknown",
                        "detail": "Base de datos no disponible.",
                    },
                    {
                        "name": "scan_history",
                        "status": "unknown",
                        "detail": "Base de datos no disponible.",
                    },
                ]
            )

        try:
            broker_ok = _broker()
        except (redis.exceptions.RedisError, OSError, ValueError):
            broker_ok = False
        add(
            "redis",
            broker_ok,
            "El broker Redis configurado responde.",
            "Redis no disponible o configuración inválida; revisa el servicio.",
        )
        if broker_ok:
            try:
                worker_ok = _worker()
            except (OperationalError, redis.exceptions.RedisError, OSError):
                worker_ok = False
            add(
                "worker",
                worker_ok,
                "Responde un worker Celery del broker configurado.",
                "Ningún worker responde; revisa el proceso y la configuración del broker.",
            )
        else:
            checks.append({"name": "worker", "status": "unknown", "detail": "Redis no disponible."})

        try:
            web_ok = _web(host, port)
        except (HTTPError, URLError, TimeoutError, OSError):
            web_ok = False
        add(
            "web",
            web_ok,
            "La página de inicio de sesión responde.",
            "Página de inicio de sesión no disponible; revisa el proceso web y el puerto.",
        )
        for executable in ("trivy", "osv-scanner"):
            try:
                version = scanner_version(executable, Path.cwd(), timeout_seconds=5)
            except ScannerExecutionError:
                add(
                    executable,
                    False,
                    "",
                    f"{executable} no disponible en este proceso; revisa la instalación "
                    "del worker.",
                )
            else:
                add(executable, True, version, "")

        execution = settings.CICLOSEC_CONFIG.scanning.execution
        if execution.repository_scanner_use_local_databases:
            local_status = inspect_local_scanner_databases(
                osv_cache_directory=execution.repository_scanner_osv_db_cache_directory,
                trivy_cache_directory=execution.repository_scanner_trivy_cache_directory,
            )
            for name, status in local_status.items():
                available = bool(status["available"])
                detail = (
                    f"Base local disponible en {status['cache_directory']}."
                    if available
                    else "Base local no disponible; configura o precarga su directorio."
                )
                add(
                    f"{name}_local_database",
                    available,
                    detail,
                    detail,
                )
        else:
            checks.append(
                {
                    "name": "local_scanner_databases",
                    "status": "info",
                    "detail": "Modo de bases locales desactivado.",
                }
            )

        checks.append(_beat_check(mode, len(app.conf.beat_schedule)))
        checks.append(
            {
                "name": "scanner_scope",
                "status": "info",
                "detail": "Los escáneres se comprueban en este proceso, no en todos los workers.",
            }
        )
        if options["as_json"]:
            self.stdout.write(json.dumps({"checks": checks}, ensure_ascii=False))
        else:
            for check in checks:
                self.stdout.write(f"{check['status'].upper():7} {check['name']}: {check['detail']}")
        if any(check["status"] == "error" for check in checks):
            raise CommandError("El diagnóstico detectó servicios no disponibles o inválidos.")
