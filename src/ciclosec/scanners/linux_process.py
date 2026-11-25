"""Process-group operations that retain the Linux group leader until cleanup."""

import os
import signal
import subprocess
import sys


def has_exited(process: subprocess.Popen[bytes]) -> bool:
    """Observe the child without releasing its PID before group termination."""
    if sys.platform != "linux":
        raise OSError("Linux process groups are unavailable on this platform")
    try:
        return os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except ChildProcessError as error:
        raise OSError("Scanner process ownership could not be verified") from error


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    """Signal only the session created for this still-owned child."""
    if sys.platform != "linux":
        raise OSError("Linux process groups are unavailable on this platform")
    has_exited(process)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
