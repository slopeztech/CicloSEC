"""Start scanner processes inside a Windows job before they can spawn children."""

from __future__ import annotations

import ctypes
import subprocess
import sys
from collections.abc import Sequence
from ctypes import wintypes
from pathlib import Path


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_ulonglong)
        for name in (
            "ReadOperationCount",
            "WriteOperationCount",
            "OtherOperationCount",
            "ReadTransferCount",
            "WriteTransferCount",
            "OtherTransferCount",
        )
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


_WRAPPER = (
    "import subprocess, sys\n"
    "if sys.stdin.buffer.read(1) != b'1': sys.exit(125)\n"
    "sys.stdin.close()\n"
    "try:\n"
    "    child = subprocess.Popen(sys.argv[1:], stdin=subprocess.DEVNULL, close_fds=True)\n"
    "except OSError:\n"
    "    sys.exit(126)\n"
    "sys.exit(child.wait())\n"
)


class WindowsJob:
    """Own a job that terminates its assigned processes when closed."""

    _kernel32: ctypes.CDLL
    _handle: int | None

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise OSError("Windows process jobs are unavailable on this platform")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self._kernel32.CreateJobObjectW.restype = wintypes.HANDLE
        self._kernel32.SetInformationJobObject.argtypes = [
            wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            wintypes.DWORD,
        ]
        self._kernel32.SetInformationJobObject.restype = wintypes.BOOL
        self._kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self._kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
        self._kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self._kernel32.CloseHandle.restype = wintypes.BOOL
        self._handle = self._kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise OSError("Could not create scanner process job")
        limits = _ExtendedLimitInformation()
        limits.BasicLimitInformation.LimitFlags = 0x2000
        if not self._kernel32.SetInformationJobObject(
            self._handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)
        ):
            self.close()
            raise OSError("Could not configure scanner process job")

    def assign(self, process: subprocess.Popen[bytes]) -> None:
        # CPython retains this handle until the child is reaped, preventing PID reuse.
        handle = getattr(process, "_handle")  # noqa: B009
        if not self._kernel32.AssignProcessToJobObject(self._handle, int(handle)):
            raise OSError("Could not assign scanner process job")

    def close(self) -> None:
        if self._handle:
            handle = self._handle
            if not self._kernel32.CloseHandle(handle):
                raise OSError("Could not close scanner process job")
            self._handle = None


def start_windows_process(
    arguments: Sequence[str], *, cwd: Path, env: dict[str, str]
) -> tuple[subprocess.Popen[bytes], WindowsJob]:
    """Start a gated wrapper, attach it to the job, then release the scanner."""
    job = WindowsJob()
    process: subprocess.Popen[bytes] | None = None
    ready = False
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", _WRAPPER, *arguments],
            cwd=cwd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            env=env,
        )
        job.assign(process)
        if process.stdin is None:
            raise OSError("Could not open scanner startup gate")
        process.stdin.write(b"1")
        process.stdin.close()
        ready = True
        return process, job
    finally:
        if not ready:
            try:
                if process is not None:
                    process.kill()
                    process.wait()
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if stream is not None:
                            stream.close()
            finally:
                job.close()
