"""Bounded subprocess execution for external security scanners."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from ciclosec.scanners.linux_process import has_exited, terminate_group
from ciclosec.scanners.windows_job import WindowsJob, start_windows_process


class ScannerExecutionError(RuntimeError):
    """An external scanner could not be run safely or returned invalid output."""


@dataclass(frozen=True)
class ProcessResult:
    """Captured scanner output with its return code."""

    returncode: int
    stdout: bytes
    stderr: bytes


def _scanner_environment(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    environment = {
        name: os.environ[name]
        for name in ("PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "USERPROFILE", "HOME")
        if name in os.environ
    }
    environment["NO_COLOR"] = "1"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    if extra:
        environment.update(extra)
    return environment


def _read_bounded(
    stream: BinaryIO,
    output: bytearray,
    *,
    limit: int,
    overflow: threading.Event,
    read_failed: threading.Event,
) -> None:
    try:
        while chunk := os.read(stream.fileno(), 64 * 1024):
            remaining = limit + 1 - len(output)
            if remaining > 0:
                output.extend(chunk[:remaining])
            if len(output) > limit:
                overflow.set()
                return
    except OSError:
        read_failed.set()
    finally:
        try:
            stream.close()
        except OSError:
            read_failed.set()


def run_process(
    arguments: Sequence[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    max_output_bytes: int,
    allowed_exit_codes: frozenset[int] = frozenset({0}),
    environment: Mapping[str, str] | None = None,
) -> ProcessResult:
    """Run a fixed scanner argument vector without a shell or inherited secrets."""
    if not arguments or any(
        not isinstance(argument, str) or "\x00" in argument for argument in arguments
    ):
        raise ScannerExecutionError("Scanner command arguments are invalid")
    if timeout_seconds <= 0 or max_output_bytes <= 0:
        raise ScannerExecutionError("Scanner limits must be positive")
    working_directory = cwd.resolve()
    if not working_directory.is_dir():
        raise ScannerExecutionError("Scanner target directory does not exist")
    executable = shutil.which(arguments[0])
    if executable is None:
        raise ScannerExecutionError(f"Required scanner is unavailable: {Path(arguments[0]).name}")

    job: WindowsJob | None = None
    linux_group = sys.platform == "linux"
    try:
        if os.name == "nt":
            process, job = start_windows_process(
                [executable, *arguments[1:]],
                cwd=working_directory,
                env=_scanner_environment(environment),
            )
        else:
            process = subprocess.Popen(
                [executable, *arguments[1:]],
                cwd=working_directory,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                env=_scanner_environment(environment),
                start_new_session=linux_group,
            )
    except OSError:
        if os.name == "nt":
            raise ScannerExecutionError(
                f"Could not start scanner in a Windows process job: {Path(arguments[0]).name}"
            ) from None
        raise ScannerExecutionError(f"Could not start scanner: {Path(arguments[0]).name}") from None

    if process.stdout is None or process.stderr is None:
        if job is not None:
            job.close()
        elif linux_group:
            terminate_group(process)
        else:
            process.kill()
        process.wait()
        raise ScannerExecutionError("Scanner output streams could not be opened")

    stdout = bytearray()
    stderr = bytearray()
    overflow = threading.Event()
    read_failed = threading.Event()
    readers = [
        threading.Thread(
            target=_read_bounded,
            args=(process.stdout, stdout),
            kwargs={"limit": max_output_bytes, "overflow": overflow, "read_failed": read_failed},
            daemon=True,
        ),
        threading.Thread(
            target=_read_bounded,
            args=(process.stderr, stderr),
            kwargs={"limit": max_output_bytes, "overflow": overflow, "read_failed": read_failed},
            daemon=True,
        ),
    ]
    started_readers: list[threading.Thread] = []
    linux_stopped = False

    def stop_process() -> None:
        nonlocal linux_stopped
        if job is not None:
            job.close()
        elif linux_group:
            try:
                terminate_group(process)
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                raise ScannerExecutionError("Scanner process group could not be stopped") from None
            linux_stopped = True
        else:
            process.kill()
        if not linux_group:
            process.wait()
        reader_deadline = time.monotonic() + 2 if linux_group else None
        for reader in started_readers:
            remaining = (
                max(0.0, reader_deadline - time.monotonic())
                if reader_deadline is not None
                else None
            )
            reader.join(timeout=remaining)
        if linux_group and any(reader.is_alive() for reader in started_readers):
            raise ScannerExecutionError("Scanner output streams remained open after group cleanup")

    try:
        for reader in readers:
            reader.start()
            started_readers.append(reader)
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                exited = has_exited(process) if linux_group else process.poll() is not None
            except OSError:
                raise ScannerExecutionError(
                    "Scanner process ownership could not be verified"
                ) from None
            if exited and (
                not (job is not None or linux_group)
                or not any(reader.is_alive() for reader in readers)
            ):
                break
            if overflow.is_set() or read_failed.is_set():
                stop_process()
                if read_failed.is_set():
                    raise ScannerExecutionError("Scanner output could not be read")
                raise ScannerExecutionError("Scanner output exceeded the configured size limit")
            if time.monotonic() >= deadline:
                stop_process()
                raise ScannerExecutionError("Scanner exceeded the configured time limit")
            time.sleep(0.05)

        for reader in readers:
            reader.join()
        if read_failed.is_set():
            raise ScannerExecutionError("Scanner output could not be read")
        if overflow.is_set():
            raise ScannerExecutionError("Scanner output exceeded the configured size limit")
        if linux_group:
            stop_process()
        if process.returncode is None:
            raise ScannerExecutionError("Scanner did not return an exit status")
        result = ProcessResult(process.returncode, bytes(stdout), bytes(stderr))
        if result.returncode not in allowed_exit_codes:
            raise ScannerExecutionError(
                f"Scanner exited with status {result.returncode}: {Path(arguments[0]).name}"
            )
        return result
    finally:
        if job is not None:
            job.close()
            process.wait()
        elif linux_group:
            if not linux_stopped:
                stop_process()
        elif process.poll() is None:
            process.kill()
            process.wait()
