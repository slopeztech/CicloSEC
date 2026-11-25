"""Local, advisory resource estimates; never configures or enforces limits."""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import re
import shutil
import sys
from pathlib import Path, PurePosixPath
from typing import TypedDict


class Estimate(TypedDict):
    observed: float | int | None
    suggested_per_scan: float | int | None
    unit: str
    confidence: str
    detail: str


def _read(path: Path) -> str:
    return path.read_text(encoding="ascii").strip()


def _unescape_mount(value: str) -> str:
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def _cgroup_directories() -> list[Path]:
    """Resolve the current v2 cgroup and all visible ancestors, or fail closed."""
    groups = _read(Path("/proc/self/cgroup")).splitlines()
    paths = [line[3:] for line in groups if line.startswith("0::")]
    if len(paths) != 1:
        raise ValueError("cgroup v2 unavailable")
    group = PurePosixPath(paths[0])
    if not group.is_absolute() or ".." in group.parts:
        raise ValueError("invalid cgroup")
    for line in _read(Path("/proc/self/mountinfo")).splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        if not separator or not right.startswith("cgroup2 ") or len(fields) < 5:
            continue
        root = PurePosixPath(_unescape_mount(fields[3]))
        mount = Path(_unescape_mount(fields[4]))
        try:
            relative = group.relative_to(root)
        except ValueError:
            continue
        current = mount.joinpath(*relative.parts)
        result = [current]
        while current != mount:
            current = current.parent
            result.append(current)
        return result
    raise ValueError("cgroup v2 mount unavailable")


def _cgroup_bounds(directories: list[Path]) -> tuple[float | None, int | None]:
    cpu: float | None = None
    memory: int | None = None
    for directory in directories:
        quota, period = _read(directory / "cpu.max").split()
        period_value = int(period)
        if period_value <= 0:
            raise ValueError("invalid CPU period")
        if quota != "max":
            quota_value = int(quota)
            if quota_value <= 0:
                raise ValueError("invalid CPU quota")
            value = quota_value / period_value
            cpu = value if cpu is None else min(cpu, value)
        maximum = _read(directory / "memory.max")
        if maximum != "max":
            limit = int(maximum)
            usage = int(_read(directory / "memory.current"))
            if limit < 0 or usage < 0:
                raise ValueError("invalid memory limit")
            available = max(0, limit - usage)
            memory = available if memory is None else min(memory, available)
    return cpu, memory


def _v1_directories(controller: str) -> list[Path]:
    memberships = []
    for line in _read(Path("/proc/self/cgroup")).splitlines():
        parts = line.split(":", 2)
        if len(parts) == 3 and controller in parts[1].split(","):
            memberships.append(parts[2])
    if len(memberships) != 1:
        raise ValueError("cgroup v1 membership unavailable")
    group = PurePosixPath(memberships[0])
    if not group.is_absolute() or ".." in group.parts:
        raise ValueError("invalid cgroup")
    for line in _read(Path("/proc/self/mountinfo")).splitlines():
        left, separator, right = line.partition(" - ")
        fields = left.split()
        mount_fields = right.split()
        if (
            not separator
            or len(fields) < 5
            or len(mount_fields) < 3
            or mount_fields[0] != "cgroup"
            or controller not in mount_fields[2].split(",")
        ):
            continue
        root = PurePosixPath(_unescape_mount(fields[3]))
        mount = Path(_unescape_mount(fields[4]))
        try:
            relative = group.relative_to(root)
        except ValueError:
            continue
        current = mount.joinpath(*relative.parts)
        result = [current]
        while current != mount:
            current = current.parent
            result.append(current)
        return result
    raise ValueError("cgroup v1 mount unavailable")


def _v1_bounds() -> tuple[float | None, int | None]:
    cpu: float | None = None
    memory: int | None = None
    for directory in _v1_directories("cpu"):
        quota = int(_read(directory / "cpu.cfs_quota_us"))
        period = int(_read(directory / "cpu.cfs_period_us"))
        if quota == 0 or quota < -1 or period <= 0:
            raise ValueError("invalid CPU quota")
        if quota != -1:
            value = quota / period
            cpu = value if cpu is None else min(cpu, value)
    for directory in _v1_directories("memory"):
        limit = int(_read(directory / "memory.limit_in_bytes"))
        usage = int(_read(directory / "memory.usage_in_bytes"))
        if limit < 0 or usage < 0:
            raise ValueError("invalid memory limit")
        available = max(0, limit - usage)
        memory = available if memory is None else min(memory, available)
    return cpu, memory


def _linux_memory_available() -> int:
    for line in _read(Path("/proc/meminfo")).splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[0] == "MemAvailable:" and fields[2] == "kB":
            value = int(fields[1]) * 1024
            if value >= 0:
                return value
    raise ValueError("available memory unavailable")


def _windows_memory_available() -> int:
    class MemoryStatus(ctypes.Structure):
        _fields_ = [
            ("length", ctypes.c_ulong),
            ("memory_load", ctypes.c_ulong),
            ("total_physical", ctypes.c_ulonglong),
            ("available_physical", ctypes.c_ulonglong),
            ("total_page_file", ctypes.c_ulonglong),
            ("available_page_file", ctypes.c_ulonglong),
            ("total_virtual", ctypes.c_ulonglong),
            ("available_virtual", ctypes.c_ulonglong),
            ("available_extended_virtual", ctypes.c_ulonglong),
        ]

    status = MemoryStatus()
    status.length = ctypes.sizeof(status)
    if not getattr(ctypes, "windll").kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):  # noqa: B009
        raise OSError("memory query failed")
    return int(status.available_physical)


def _estimate(value: float | int | None, fraction: float, unit: str, detail: str) -> Estimate:
    suggestion: float | int | None = None
    if value is not None and value > 0:
        suggestion = round(value * fraction, 3) if unit == "cpu" else int(value * fraction)
        if suggestion <= 0:
            suggestion = None
    return {
        "observed": value,
        "suggested_per_scan": suggestion,
        "unit": unit,
        "confidence": "uncertain",
        "detail": detail,
    }


def collect(path: Path) -> dict[str, object]:
    """Inspect this process only. Suggestions are not capacity or safety guarantees."""
    system = sys.platform
    cpu: float | None = None
    memory: int | None = None
    disk: int | None = None
    notes: list[str] = []
    try:
        count = os.cpu_count()
        if system.startswith("linux") and hasattr(os, "sched_getaffinity"):
            count = len(os.sched_getaffinity(0))
        if count is not None and count > 0:
            cpu = float(count)
    except OSError:
        notes.append("No se pudo consultar la afinidad de CPU.")
    try:
        if system.startswith("linux"):
            memory = _linux_memory_available()
        elif system == "win32":
            memory = _windows_memory_available()
        else:
            notes.append("Plataforma sin medición de memoria implementada.")
    except (OSError, ValueError, AttributeError):
        notes.append("No se pudo medir la memoria disponible.")
    if system.startswith("linux"):
        try:
            try:
                cpu_limit, memory_limit = _cgroup_bounds(_cgroup_directories())
                version = "v2"
            except (OSError, ValueError, OverflowError):
                cpu_limit, memory_limit = _v1_bounds()
                version = "v1"
            if cpu_limit is not None:
                cpu = min(cpu, cpu_limit) if cpu is not None else cpu_limit
            if memory_limit is not None:
                memory = min(memory, memory_limit) if memory is not None else memory_limit
            notes.append(
                f"Se consultaron límites cgroup {version} visibles, incluidos sus padres; "
                "otros límites o padres ocultos pueden existir."
            )
        except (OSError, ValueError, OverflowError):
            notes.append(
                "Cgroup no verificable o incompleto: CPU y memoria pueden superar "
                "el presupuesto real del contenedor."
            )
    elif system == "win32":
        notes.append(
            "Límites de Windows Job Object y otros límites del contenedor no verificados; "
            "CPU y memoria pueden superar el presupuesto real."
        )
    else:
        notes.append("Límites del entorno no verificados.")
    try:
        if not path.is_dir():
            raise OSError("not a directory")
        disk = shutil.disk_usage(path).free
    except OSError:
        notes.append("No se pudo medir el espacio en el directorio solicitado.")
    return {
        "platform": system,
        "resources": {
            "cpu": _estimate(cpu, 0.5, "cpu", "Afinidad o CPU lógica; 50 % para un escaneo."),
            "memory": _estimate(
                memory, 0.25, "bytes", "Memoria disponible estimada; 25 % para un escaneo."
            ),
            "disk": _estimate(
                disk, 0.1, "bytes", "Espacio libre del sistema de archivos; 10 % por escaneo."
            ),
        },
        "notes": notes,
        "warning": (
            "Estimaciones inciertas y orientativas, no límites seguros ni reservas. "
            "No se aplica ni configura ningún límite; no se han inspeccionado otros workers. "
            "La concurrencia, cuotas, cargas y recursos pueden cambiar."
        ),
        "enforcement": "not_implemented",
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Estima recursos locales sin configurar límites ni ejecutar escaneos."
    )
    parser.add_argument(
        "--path", type=Path, default=Path.cwd(), help="Directorio del sistema de archivos a medir"
    )
    args = parser.parse_args(argv)
    print(json.dumps(collect(args.path), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
