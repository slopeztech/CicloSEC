"""Tests for safe, strict CicloSec configuration loading."""

from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlsplit

import pytest
import yaml
from dotenv import dotenv_values

from ciclosec.common.config import (
    CicloSecConfig,
    ConfigurationError,
    duration_seconds,
    load_config,
    resolve_environment_value,
)

CONFIG_FIXTURE = Path(__file__).parents[2] / "config" / "ciclosec.yaml.example"


def test_native_example_database_uses_the_compose_loopback_address() -> None:
    root = Path(__file__).parents[2]
    env = dotenv_values(root / ".env.example", interpolate=False)
    database_url = env["CICLOSEC_DATABASE_URL"]
    assert database_url is not None
    host = urlsplit(database_url).hostname
    assert host is not None
    compose = yaml.safe_load((root / "docker-compose.yml").read_text(encoding="utf-8"))
    postgres_binding = compose["services"]["postgres"]["ports"][0].split(":", 1)[0]

    assert ip_address(host).is_loopback
    assert ip_address(host) == ip_address(postgres_binding)


def test_example_configuration_loads_with_documented_defaults() -> None:
    config = load_config(CONFIG_FIXTURE)

    assert config.application.environment == "local"
    assert config.docker.allow_local_daemon is False
    assert config.mcp.allow_run_scan is False
    assert config.mcp.allow_intelligence_sync is False
    assert config.mcp.allow_finding_decisions is False
    assert config.scanning.execution.allow_repository_scanners_with_network is False
    assert config.scanning.execution.repository_scanner_use_local_databases is False
    assert config.scanning.execution.repository_scanner_osv_db_cache_directory is None
    assert config.scanning.execution.repository_scanner_trivy_cache_directory is None


def test_unknown_configuration_fields_are_rejected_without_echoing_values(
    tmp_path: Path,
) -> None:
    secret_value = "must-not-appear-in-errors"
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text(
        f"application:\n  unexpected: {secret_value}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError) as error:
        load_config(config_file)

    assert "application.unexpected" in str(error.value)
    assert secret_value not in str(error.value)


def test_invalid_schedule_is_rejected(tmp_path: Path) -> None:
    config_file = tmp_path / "invalid-schedule.yaml"
    config_file.write_text(
        "scanning:\n  schedules:\n    repositories: soon\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match="scanning.schedules.repositories"):
        load_config(config_file)


def test_non_utf8_configuration_is_reported_without_contents(tmp_path: Path) -> None:
    config_file = tmp_path / "invalid-encoding.yaml"
    config_file.write_bytes(b"\xff\xfe")

    with pytest.raises(ConfigurationError, match="not valid UTF-8"):
        load_config(config_file)


def test_environment_reference_returns_value_without_logging_it() -> None:
    value = resolve_environment_value(
        "CICLOSEC_GITHUB_TOKEN",
        {"CICLOSEC_GITHUB_TOKEN": "local-test-token"},
    )

    assert value == "local-test-token"


def test_missing_environment_reference_does_not_expose_secret() -> None:
    with pytest.raises(ConfigurationError, match="Required environment variable"):
        resolve_environment_value("CICLOSEC_GITHUB_TOKEN", {})


def test_empty_configuration_uses_safe_defaults() -> None:
    config = CicloSecConfig.model_validate({})

    assert config.application.name == "CicloSec"
    assert config.infrastructure.enabled is False
    assert config.scanning.execution.allow_repository_scanners_with_network is False
    assert config.scanning.execution.repository_scanner_use_local_databases is False
    assert config.scanning.execution.repository_scanner_osv_db_cache_directory is None
    assert config.scanning.execution.repository_scanner_trivy_cache_directory is None


def test_repository_scanner_network_authorization_requires_boolean(tmp_path: Path) -> None:
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text(
        'scanning:\n  execution:\n    allow_repository_scanners_with_network: "true"\n',
        encoding="utf-8",
    )
    with pytest.raises(
        ConfigurationError, match="scanning.execution.allow_repository_scanners_with_network"
    ):
        load_config(config_file)


def test_repository_scanner_local_database_setting_requires_boolean(tmp_path: Path) -> None:
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text(
        'scanning:\n  execution:\n    repository_scanner_use_local_databases: "true"\n',
        encoding="utf-8",
    )
    with pytest.raises(
        ConfigurationError,
        match="scanning.execution.repository_scanner_use_local_databases",
    ):
        load_config(config_file)


@pytest.mark.parametrize("value", [0, -1, True, "2"])
def test_invalid_scan_queue_limit_is_rejected(tmp_path: Path, value: object) -> None:
    config_file = tmp_path / "invalid.yaml"
    config_file.write_text(
        yaml.safe_dump({"scanning": {"execution": {"max_queued_scans": value}}}),
        encoding="utf-8",
    )
    with pytest.raises(ConfigurationError, match="scanning.execution.max_queued_scans"):
        load_config(config_file)


@pytest.mark.parametrize(
    ("value", "expected"),
    [("30s", 30), ("15m", 900), ("6h", 21600), ("7d", 604800)],
)
def test_duration_seconds_converts_valid_provider_intervals(value: str, expected: int) -> None:
    assert duration_seconds(value) == expected


def test_duration_seconds_rejects_unvalidated_values() -> None:
    with pytest.raises(ConfigurationError, match="positive s, m, h, or d"):
        duration_seconds("0h")
