"""Cross-platform scanner release selection and checksum parsing tests."""

import hashlib
import subprocess
from pathlib import Path
from urllib.error import URLError

import pytest
from scripts import install_scanners
from scripts.install_scanners import expected_sha256, release_asset_names


@pytest.mark.parametrize(
    ("system", "machine", "trivy_asset", "osv_asset", "trivy_executable"),
    [
        (
            "Windows",
            "AMD64",
            "trivy_0.76.2_windows-64bit.zip",
            "osv-scanner_windows_amd64.exe",
            "trivy.exe",
        ),
        (
            "Linux",
            "x86_64",
            "trivy_0.76.2_Linux-64bit.tar.gz",
            "osv-scanner_linux_amd64",
            "trivy",
        ),
        (
            "Linux",
            "aarch64",
            "trivy_0.76.2_Linux-ARM64.tar.gz",
            "osv-scanner_linux_arm64",
            "trivy",
        ),
        (
            "Darwin",
            "arm64",
            "trivy_0.76.2_macOS-ARM64.tar.gz",
            "osv-scanner_darwin_arm64",
            "trivy",
        ),
    ],
)
def test_release_assets_support_platforms(
    system: str,
    machine: str,
    trivy_asset: str,
    osv_asset: str,
    trivy_executable: str,
) -> None:
    assert release_asset_names(system, machine) == (
        trivy_asset,
        osv_asset,
        trivy_executable,
    )


def test_release_assets_reject_unsupported_architectures() -> None:
    with pytest.raises(ValueError, match="Unsupported scanner architecture"):
        release_asset_names("Linux", "riscv64")


def test_release_assets_reject_windows_arm64() -> None:
    with pytest.raises(ValueError, match="Windows scanner installation"):
        release_asset_names("Windows", "arm64")


def test_expected_sha256_matches_only_the_requested_asset() -> None:
    manifest = (
        b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  other.zip\n"
        b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789  *trivy.zip\n"
    )

    assert expected_sha256(manifest, "trivy.zip") == (
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    )


def test_expected_sha256_requires_one_valid_entry() -> None:
    with pytest.raises(ValueError, match="found 0"):
        expected_sha256(b"0123456789abcdef  other.zip\n", "trivy.zip")


@pytest.mark.parametrize(
    ("failure", "error"),
    [
        ("download", URLError),
        ("checksum", ValueError),
        ("version", RuntimeError),
        ("execution", subprocess.CalledProcessError),
        ("timeout", subprocess.TimeoutExpired),
    ],
)
def test_failed_scanner_update_preserves_existing_executable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str, error: type[Exception]
) -> None:
    target = tmp_path / "scanner.exe"
    target.write_bytes(b"previous executable")
    asset = b"new executable"
    digest = hashlib.sha256(asset).hexdigest()

    def download(url: str, destination: Path) -> None:
        if failure == "download" and url.endswith("scanner.exe"):
            raise URLError("download failed")
        if url.endswith("checksums.txt"):
            expected = "0" * 64 if failure == "checksum" else digest
            destination.write_text(f"{expected}  scanner.exe\n", encoding="utf-8")
        else:
            destination.write_bytes(asset)

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        if failure == "execution":
            raise subprocess.CalledProcessError(1, command)
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, 30)
        return subprocess.CompletedProcess(command, 0, "wrong version", "")

    monkeypatch.setattr(install_scanners, "_download", download)
    monkeypatch.setattr(install_scanners, "_has_expected_version", lambda *_args: False)
    monkeypatch.setattr(install_scanners.subprocess, "run", run)

    with pytest.raises(error):
        install_scanners._install("example/scanner", "1.0", "scanner.exe", "checksums.txt", target)

    assert target.read_bytes() == b"previous executable"
    assert list(tmp_path.iterdir()) == [target]


def test_scanner_update_verifies_staged_binary_on_target_filesystem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "scanner.exe"
    target.write_bytes(b"previous executable")
    asset = b"new executable"
    digest = hashlib.sha256(asset).hexdigest()

    def download(url: str, destination: Path) -> None:
        if url.endswith("checksums.txt"):
            destination.write_text(f"{digest}  scanner.exe\n", encoding="utf-8")
        else:
            destination.write_bytes(asset)

    def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        staged = Path(command[0])
        assert staged != target
        assert staged.is_relative_to(target.parent)
        assert staged.read_bytes() == asset
        assert target.read_bytes() == b"previous executable"
        return subprocess.CompletedProcess(command, 0, "scanner 1.0", "")

    monkeypatch.setattr(install_scanners, "_download", download)
    monkeypatch.setattr(install_scanners, "_has_expected_version", lambda *_args: False)
    monkeypatch.setattr(install_scanners.subprocess, "run", run)

    install_scanners._install("example/scanner", "1.0", "scanner.exe", "checksums.txt", target)

    assert target.read_bytes() == asset
    assert list(tmp_path.iterdir()) == [target]
