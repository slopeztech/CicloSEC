"""Strict YAML configuration loading with secret-safe errors."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError

Duration = Annotated[str, StringConstraints(pattern=r"^[1-9][0-9]*(s|m|h|d)$")]
EnvironmentName = Annotated[str, StringConstraints(pattern=r"^[A-Z_][A-Z0-9_]*$")]
_ENVIRONMENT_PATTERN = re.compile(r"^[A-Z_][A-Z0-9_]*$")


class ConfigurationError(ValueError):
    """Raised when CicloSec configuration is missing or invalid."""


class StrictModel(BaseModel):
    """Base model that rejects unknown configuration keys and coercion."""

    model_config = ConfigDict(extra="forbid", strict=True)


class ApplicationConfig(StrictModel):
    name: str = "CicloSec"
    environment: Literal["local", "test", "production"] = "local"
    timezone: str = "Europe/Madrid"


class DatabaseConfig(StrictModel):
    url_env: EnvironmentName = "CICLOSEC_DATABASE_URL"


class TaskQueueConfig(StrictModel):
    broker_url_env: EnvironmentName = "CICLOSEC_REDIS_URL"
    result_backend_url_env: EnvironmentName = "CICLOSEC_REDIS_URL"


class ScanExecutionConfig(StrictModel):
    timeout_seconds: int = Field(default=900, gt=0, le=86400)
    max_concurrent_scans: int = Field(default=2, gt=0, le=64)
    max_queued_scans: int = Field(default=50, gt=0)
    allow_on_demand: bool = False
    allow_repository_scanners_with_network: bool = False
    repository_scanner_use_local_databases: bool = False
    repository_scanner_osv_db_cache_directory: str | None = None
    repository_scanner_trivy_cache_directory: str | None = None


class ScanningConfig(StrictModel):
    schedules: dict[str, Duration] = Field(
        default_factory=lambda: {
            "intelligence_default": "6h",
            "intelligence_full_reconciliation": "7d",
            "repositories": "24h",
            "container_images": "24h",
        }
    )
    execution: ScanExecutionConfig = Field(default_factory=ScanExecutionConfig)


class GitHubRepositoryConfig(StrictModel):
    owner: str = Field(min_length=1)
    name: str = Field(min_length=1)
    ref: str = "main"


class GitHubConfig(StrictModel):
    enabled: bool = True
    token_env: EnvironmentName = "CICLOSEC_GITHUB_TOKEN"
    repositories: list[GitHubRepositoryConfig] = Field(default_factory=list)


class DockerImageConfig(StrictModel):
    reference: str = Field(min_length=1)


class DockerConfig(StrictModel):
    enabled: bool = False
    allow_local_daemon: bool = False
    images: list[DockerImageConfig] = Field(default_factory=list)


class LinuxServerConfig(StrictModel):
    name: str = Field(min_length=1)
    host: str = Field(min_length=1)
    user: str = Field(min_length=1)
    ssh_key_env: EnvironmentName


class InfrastructureConfig(StrictModel):
    enabled: bool = False
    servers: list[LinuxServerConfig] = Field(default_factory=list)


class IntelligenceProviderConfig(StrictModel):
    enabled: bool = True
    refresh_interval: Duration | None = None
    priority: bool = False


class IntelligenceConfig(StrictModel):
    stale_after: Duration = "24h"
    providers: dict[
        Literal["nvd", "osv", "github_advisories", "cisa_kev", "epss"],
        IntelligenceProviderConfig,
    ] = Field(default_factory=dict)


class NotificationChannelConfig(StrictModel):
    type: Literal["console"]


class NotificationsConfig(StrictModel):
    enabled: bool = True
    channels: list[NotificationChannelConfig] = Field(default_factory=list)


class McpConfig(StrictModel):
    enabled: bool = False
    transport: Literal["stdio"] = "stdio"
    allow_run_scan: bool = False
    allow_intelligence_sync: bool = False
    allow_finding_decisions: bool = False


class CicloSecConfig(StrictModel):
    """Validated application configuration."""

    application: ApplicationConfig = Field(default_factory=ApplicationConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    tasks: TaskQueueConfig = Field(default_factory=TaskQueueConfig)
    scanning: ScanningConfig = Field(default_factory=ScanningConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    infrastructure: InfrastructureConfig = Field(default_factory=InfrastructureConfig)
    intelligence: IntelligenceConfig = Field(default_factory=IntelligenceConfig)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)
    mcp: McpConfig = Field(default_factory=McpConfig)


def load_config(path: Path) -> CicloSecConfig:
    """Load UTF-8 YAML and validate it without echoing input values in errors."""
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError:
        raise ConfigurationError(f"Cannot read configuration file: {path.name}") from None
    except UnicodeDecodeError:
        raise ConfigurationError(f"Configuration file is not valid UTF-8: {path.name}") from None

    try:
        raw_config = yaml.safe_load(contents)
    except yaml.YAMLError:
        raise ConfigurationError(f"Invalid YAML in configuration file: {path.name}") from None

    try:
        return CicloSecConfig.model_validate(raw_config)
    except ValidationError as error:
        fields = sorted(
            ".".join(str(part) for part in item["loc"])
            for item in error.errors(include_input=False)
        )
        field_summary = ", ".join(fields)
        raise ConfigurationError(
            f"Invalid configuration fields in {path.name}: {field_summary}"
        ) from None


def duration_seconds(value: str) -> int:
    """Convert a validated duration such as ``6h`` to seconds."""
    match = re.fullmatch(r"([1-9][0-9]*)(s|m|h|d)", value)
    if match is None:
        raise ConfigurationError("Duration must use a positive s, m, h, or d value")
    amount = int(match.group(1))
    multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
    return amount * multiplier


def resolve_environment_value(name: str, environ: Mapping[str, str] | None = None) -> str:
    """Resolve a secret/config value by environment variable name."""
    if not _ENVIRONMENT_PATTERN.fullmatch(name):
        raise ConfigurationError("Environment variable reference has an invalid name")

    environment = os.environ if environ is None else environ
    value = environment.get(name)
    if not value:
        raise ConfigurationError(f"Required environment variable is not set: {name}")
    return value
