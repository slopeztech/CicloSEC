# CicloSec

CicloSec is a local-first security monitoring platform for registered software
assets. It records CycloneDX/SPDX inventories, scans authorized GitHub
repositories and local Docker images, correlates findings with vulnerability
intelligence, and exposes authenticated API/dashboard queries plus a local MCP
server that is read-only by default.

## Project status

The repository contains working asset and SBOM APIs, Trivy/OSV-Scanner
integrations, local-image scanning, intelligence synchronization, explainable
finding risk, a bounded dashboard, and MCP query tools.

- Acceptance with a private GitHub repository and Dependabot is still pending.
- NVD/GitHub intelligence and EPSS coverage is intentionally partial.
- The dashboard/API phase is in progress.
- Persistent settings are partial; the reader/operator/administrator permission
  matrix and full English/Spanish localization are not implemented yet.
- Authenticated users currently have broader write access than the planned
  reader role. Do not grant accounts to users who are not trusted to operate
  the local installation.
- Production deployment is **not ready**: the Compose application profile is
  for local development only, and production Django/web settings are incomplete.

## Get started

Run the automatic bootstrap from the repository root:

```powershell
.\scripts\setup.ps1
```

```bash
bash scripts/setup.sh
```

Native setup (`.\scripts\setup.ps1` or `bash scripts/setup.sh`) installs the
Python runtime, locked project dependencies, and verified Trivy/OSV-Scanner
binaries into the project environment, then prepares local configuration and
starts PostgreSQL/Redis through Docker Compose. Docker setup
(`.\scripts\setup.ps1 -Docker` or `bash scripts/setup.sh --docker`) builds the
app image with its dependencies and starts web/worker in containers.
Docker Desktop/Engine with Compose is the only host prerequisite. The scripts
never overwrite an existing `.env` or `config/ciclosec.yaml`.

Use the [implementation guide](docs/IMPLEMENTATION.md) for repository
registration, scan workflow, and production-readiness details.
Follow the [roadmap](docs/roadmap.md) for verified steps toward complete local
use and production readiness.
The [development guide](docs/DEVELOPMENT.md) covers architecture-specific
details and quality checks.

The supported run mode today is local development. Keep the web server bound
to `127.0.0.1`; never commit `.env`, GitHub tokens, database passwords, or
Django secret keys. The Compose worker mounts the Docker socket, which grants
powerful access to the host daemon; use it only in a trusted local environment.

## Documentation

- [Implementation and testing guide](docs/IMPLEMENTATION.md)
- [Roadmap: local use and production readiness](docs/roadmap.md)
- [Detailed local execution roadmap](roadmap2.md)
- [Development and operations](docs/DEVELOPMENT.md)
- [Local API](docs/API.md)
- [Architecture](docs/ARCHITECTURE.md)
- [MCP tools](docs/MCP.md)
- [Architecture decision](docs/ADR/0001-modular-monolith.md)

## Quality checks

```powershell
uv sync --locked
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy src/ciclosec
uv run mkdocs build --strict
```

## Before publishing

The ignore rules exclude local configuration, environment files, private keys,
databases, backups, logs, and generated artifacts; they are not a guarantee
that every sensitive file is covered. Never force-add ignored files. Before
staging or publishing, review `git status --short --untracked-files=all`,
inspect the exact staged changes with `git diff --cached`, and run a local
secret scanner on both the staged content and any existing Git history. Do not
send private code, scans, or secrets to an external scanning service.

Review examples, fixtures, logs and documentation for credentials and private
asset data even if they are not ignored. Git ignore rules do not remove files
already tracked or prevent someone from adding a secret to source code. If a
credential was ever exposed, revoke or rotate it and address the exposure;
deleting the current file alone does not remove it from Git history.
No project license has been selected yet; decide the distribution terms
before publishing if you intend others to reuse the code.
