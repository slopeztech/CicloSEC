"""Install the pinned Trivy and OSV-Scanner releases into the active Python environment."""

from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sysconfig
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

TRIVY_VERSION = "0.76.2"
OSV_SCANNER_VERSION = "2.7.1"
DOWNLOAD_TIMEOUT_SECONDS = 180
USER_AGENT = "CicloSec dependency installer"


def release_asset_names(
    system: str | None = None,
    machine: str | None = None,
) -> tuple[str, str, str]:
    """Return the Trivy archive, OSV binary, and Trivy executable for this platform."""
    detected_system = system or platform.system()
    detected_machine = (machine or platform.machine()).lower()
    architecture = {
        "amd64": "amd64",
        "x64": "amd64",
        "x86_64": "amd64",
        "arm64": "arm64",
        "aarch64": "arm64",
    }.get(detected_machine)
    if architecture is None:
        raise ValueError(f"Unsupported scanner architecture: {detected_machine}")

    if detected_system == "Windows":
        if architecture != "amd64":
            raise ValueError("Windows scanner installation currently supports AMD64 only")
        return (
            f"trivy_{TRIVY_VERSION}_windows-64bit.zip",
            "osv-scanner_windows_amd64.exe",
            "trivy.exe",
        )

    if detected_system == "Linux":
        trivy_architecture = "64bit" if architecture == "amd64" else "ARM64"
        osv_architecture = architecture
        trivy_os_name = "Linux"
        osv_os_name = "linux"
    elif detected_system == "Darwin":
        trivy_architecture = "64bit" if architecture == "amd64" else "ARM64"
        osv_architecture = architecture
        trivy_os_name = "macOS"
        osv_os_name = "darwin"
    else:
        raise ValueError(f"Unsupported scanner operating system: {detected_system}")

    return (
        f"trivy_{TRIVY_VERSION}_{trivy_os_name}-{trivy_architecture}.tar.gz",
        f"osv-scanner_{osv_os_name}_{osv_architecture}",
        "trivy",
    )


def expected_sha256(manifest: bytes, filename: str) -> str:
    """Find one exact filename entry in a standard SHA-256 manifest."""
    matches: list[str] = []
    for line in manifest.decode("utf-8").splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[-1].lstrip("*") == filename:
            digest = fields[0].lower()
            valid_digest = len(digest) == 64 and all(
                character in "0123456789abcdef" for character in digest
            )
            if not valid_digest:
                raise ValueError(f"Invalid SHA-256 entry for {filename}")
            matches.append(digest)
    if len(matches) != 1:
        raise ValueError(f"Expected one SHA-256 entry for {filename}, found {len(matches)}")
    return matches[0]


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        with destination.open("wb") as target:
            shutil.copyfileobj(response, target)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _has_expected_version(path: Path, version: str) -> bool:
    if not path.is_file():
        return False
    try:
        result = subprocess.run(
            [str(path), "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except OSError:
        return False
    return result.returncode == 0 and version in (result.stdout + result.stderr)


def _copy_archive_executable(archive_path: Path, binary_name: str, destination: Path) -> None:
    if archive_path.suffix == ".zip":
        with zipfile.ZipFile(archive_path) as archive:
            matches = [
                member
                for member in archive.infolist()
                if PurePosixPath(member.filename).name == binary_name and not member.is_dir()
            ]
            if len(matches) != 1:
                raise ValueError(f"Expected one {binary_name} in {archive_path.name}")
            with archive.open(matches[0]) as source, destination.open("wb") as target:
                shutil.copyfileobj(source, target)
        return

    with tarfile.open(archive_path, mode="r:gz") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if PurePosixPath(member.name).name == binary_name and member.isfile()
        ]
        if len(matches) != 1:
            raise ValueError(f"Expected one {binary_name} in {archive_path.name}")
        source: BinaryIO | None = archive.extractfile(matches[0])
        if source is None:
            raise ValueError(f"Could not read {binary_name} from {archive_path.name}")
        with source, destination.open("wb") as target:
            shutil.copyfileobj(source, target)


def _install(
    repository: str,
    version: str,
    asset_name: str,
    checksum_name: str,
    target: Path,
    archive_binary_name: str | None = None,
) -> None:
    if _has_expected_version(target, version):
        print(f"{target.name} {version} is already installed at {target}")
        return

    base_url = f"https://github.com/{repository}/releases/download/v{version}"
    with tempfile.TemporaryDirectory(prefix="ciclosec-scanner-") as temporary_directory:
        temporary = Path(temporary_directory)
        checksum_path = temporary / checksum_name
        asset_path = temporary / asset_name
        _download(f"{base_url}/{checksum_name}", checksum_path)
        _download(f"{base_url}/{asset_name}", asset_path)

        expected = expected_sha256(checksum_path.read_bytes(), asset_name)
        if _sha256(asset_path) != expected:
            raise ValueError(f"SHA-256 verification failed for {asset_name}")

        executable = temporary / (archive_binary_name or f"{target.name}.binary")
        if archive_binary_name is not None:
            _copy_archive_executable(asset_path, archive_binary_name, executable)
        else:
            executable = asset_path

        target.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix=f".{target.name}-", dir=target.parent) as staged:
            staged_target = Path(staged) / target.name
            shutil.copyfile(executable, staged_target)
            if os.name != "nt":
                staged_target.chmod(0o755)
            result = subprocess.run(
                [str(staged_target), "--version"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            version_output = result.stdout + result.stderr
            if version not in version_output:
                raise RuntimeError(f"{target.name} did not report the expected version {version}")
            staged_target.replace(target)

    print(f"Installed {target.name} {version} at {target}")


def install_scanners() -> None:
    trivy_asset, osv_asset, trivy_executable = release_asset_names()
    scripts_directory = Path(sysconfig.get_path("scripts"))
    executable_suffix = ".exe" if os.name == "nt" else ""

    _install(
        "aquasecurity/trivy",
        TRIVY_VERSION,
        trivy_asset,
        f"trivy_{TRIVY_VERSION}_checksums.txt",
        scripts_directory / f"trivy{executable_suffix}",
        archive_binary_name=trivy_executable,
    )
    _install(
        "google/osv-scanner",
        OSV_SCANNER_VERSION,
        osv_asset,
        "osv-scanner_SHA256SUMS",
        scripts_directory / f"osv-scanner{executable_suffix}",
    )


if __name__ == "__main__":
    install_scanners()
