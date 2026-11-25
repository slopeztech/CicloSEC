# Development

For the full local walkthrough—including registering a repository, configuring
GitHub access, requesting a scan, and checking its results—see the
[implementation guide](IMPLEMENTATION.md). Production is not ready for public
exposure; its concrete blockers and rollout gates are documented there.

## Requirements

- Docker Desktop or Docker Engine with Compose
- PowerShell 5.1+ on Windows, or Bash on Linux/macOS

## Automatic local setup

Native setup installs `uv` if needed, provisions Python 3.12, syncs the locked
Python dependencies, and installs the pinned Trivy and OSV-Scanner release
binaries into the project virtual environment. It creates local configuration
only when it does not already exist, generates local secrets, starts
PostgreSQL/Redis, applies migrations, and runs Django's configuration check.

On Windows:

```powershell
.\scripts\setup.ps1
```

On Linux/macOS:

```bash
bash scripts/setup.sh
```

The scripts require a running Docker daemon for PostgreSQL and Redis. To build
and run the web app and worker in containers instead:

```powershell
.\scripts\setup.ps1 -Docker
```

```bash
bash scripts/setup.sh --docker
```

Docker mode installs Python dependencies and both scanners in the image and
starts the local app stack; only Docker Desktop/Engine with Compose is installed
on the host. The local web server binds to loopback. Neither mode enables
on-demand scans or configures a GitHub token. The image includes
development/test tools and is not suitable for production.

## Run locally after native setup

Create a local Django account:

```powershell
uv run python manage.py createsuperuser
```

Start the web app:

```powershell
uv run python manage.py runserver 127.0.0.1:8000
```

Run the Celery worker in another terminal. On Windows, use the `solo` pool:

```powershell
uv run celery -A ciclosec.project.celery:app worker --loglevel INFO --pool solo
```

The Windows worker executes one task at a time and may not respond to control
pings while busy. On Linux and macOS, use the default pool:

```bash
uv run celery -A ciclosec.project.celery:app worker --loglevel INFO
```

Run one Beat process per environment; duplicate schedulers can enqueue duplicate
provider work. The native-mode command is:

```powershell
uv run celery -A ciclosec.project.celery:app beat --loglevel INFO
```

For Docker mode, create a local Django account with
`docker compose exec web python manage.py createsuperuser`. The optional Celery
Beat scheduler is not started by default because it contacts external
intelligence providers; start one instance deliberately with
`docker compose --profile scheduler up -d beat`.

The database contains an administrator-settings revision and audit table.
Active superusers can edit a limited set of connected options at `/settings/`;
each change requires CSRF protection and confirmation, checks its revision,
and is audited. Scan admission and worker
execution, scan schedules and coverage, intelligence freshness, console
notifications, and MCP startup and write permissions read validated database
overrides over the YAML configuration. Missing or invalid settings fail rather
than silently reverting to YAML. At startup, the default Beat scheduler reads a
validated database snapshot before opening its schedule file; if that read fails,
Beat does not start. Provider enablement and intervals are fixed until Beat is
restarted. A running Beat can still dispatch its previous schedule after a
change or database outage; stop or restart it manually after checking active
jobs. Changing Beat's scheduler class bypasses this integration. The settings
page exposes provider scheduling and intervals, not a global network or
provider-disable switch. Manual intelligence synchronization still requests all
providers regardless of these settings, and disabling a schedule does not
cancel queued, running, or retrying tasks. Enabling a schedule can lead to
external requests when Beat is running. An absent provider remains disabled
when only its interval is changed.
The settings page shows up to 50 Beat scheduler observations. Each updated Beat
records a random instance ID, its startup override revision, and a timestamp
while ticking, at most once every 20 seconds. An observation older than 90
seconds, a future timestamp, or an unexpected revision is unknown, not proof
that a process is stopped. A recent observation confirms only an earlier tick;
it does not discover uninstrumented instances or verify their YAML base.
Revision comparisons are conservative: any subsequent global setting change
shows the instance as pending, even if it did not alter Beat's schedule. Refresh
the page to recompute statuses. If a heartbeat write fails, that scheduler tick
fails before dispatch; an outage immediately after a heartbeat can still allow
dispatch until the next check. Observations are not automatically deleted.
Web, worker, and external MCP revision reporting and other options remain
unimplemented. Do not rely on this partial integration for settings that are not
listed here.
The page does not manage accounts or languages. It never contains credentials
or restarts services.

## Scan completion notifications

The configured `console` channel logs a short summary when a claimed scan
reaches a terminal state. The summary contains only the scan ID, final status,
and finding count. Duplicate task deliveries do not emit another completion
notification. Enable it with `notifications.enabled: true` and a
`notifications.channels` entry of `type: console` in `config/ciclosec.yaml`.

This is best-effort application logging, not durable delivery: it has no
separate retry or delivery history and does not provide email or webhooks.
Notification logging does not change the scan result.

The web development server binds to loopback only. PostgreSQL and Redis ports
in Compose are also bound to loopback. The defaults are `5433` and `6380` to
avoid collisions with existing local services; override them in `.env` if
needed.

## Asset API

The authenticated API manages assets and their repository or container-image
configuration at `/api/assets/`, `/api/repositories/`, and
`/api/container-images/`. Create a Django user with
`uv run python manage.py createsuperuser` before using the API. Keep the
development server bound to loopback; the API is not intended for public
exposure.

Repository configuration is stored in the database, not bootstrapped from the
`github.repositories` YAML example. The scanner uses `credential_env` on the
repository record, or the environment variable named by `github.token_env`.
In Docker Compose, `.env` is injected only into the worker so the GitHub token
is not exposed to the web, migration, or Beat containers.

The PostgreSQL named volume persists when containers stop. Changing
`POSTGRES_PASSWORD` after the volume has been initialized does not rotate the
database role password. Preserve the volume when it contains useful data;
change the database role deliberately rather than deleting the volume to
resolve a password mismatch.

## Dashboard and read-only APIs

After applying migrations, create a local Django user with
`uv run python manage.py createsuperuser`, then open `http://127.0.0.1:8000/`
and sign in. Dashboard queries require authentication; scan requests are shown
only when explicitly enabled and use the authenticated scan API. The dashboard
is designed for the loopback-only development server. There is no public
registration or anonymous dashboard access.

Web routes use English paths: `/assets/`, `/findings/`, `/history/`,
`/intelligence/`, and `/integrations/`. The former Spanish paths are no longer
available; update bookmarks and integrations that use them. API routes remain
unchanged.

`GET /api/dashboard/` returns bounded coverage, asset, scan-history, finding,
and intelligence-source summaries. It accepts optional `asset_id` and
`affected_status` filters plus `assets_page`, `scans_page`, and
`findings_page` page numbers. The dashboard shows at most 20 assets and the 10
most recent scans and findings per page; navigation preserves active filters.
Each API page includes its total.
`GET /api/assets/{id}/sbom/` returns normalized, paginated components from the
latest SBOM; use `scan_run_id` to select an earlier scan. The default page size
is 100 and the maximum is 100. SBOM responses omit raw package URLs and source
paths. These endpoints require authentication and do not return raw scan or
provider error text. When `scanning.execution.allow_on_demand` is enabled, the
dashboard offers a CSRF-protected scan request for enabled assets; repository
and local-image safety checks remain enforced by the scan API.

The home page shows up to five high- or critical-risk findings without a
closed, accepted-risk, or false-positive decision. These are historical
findings, not a guarantee of current exposure; the dashboard filters apply.
Recent CVEs are taken from locally synchronized intelligence and shown both
overall and when linked to a finding, including links through merged
vulnerability groups. Publication dates must be known, and source freshness
is shown for an associated advisory. These lists are not filtered by the
dashboard filters and do not claim complete coverage of all published CVEs.

The findings page defaults to descending risk score, with unscored findings
last and a stable ID tie-breaker. Users can select newest-first instead; both
orders apply before pagination and preserve filters. The home page refreshes
automatically every 10 seconds while visible; if keyboard focus is inside the
live content, replacement is deferred until focus leaves it.

## Repository scans

The setup scripts install checksum-verified Trivy and OSV-Scanner releases into
the project environment or application image, so the worker inherits both
executables on `PATH`. Their pinned versions are maintained in
`scripts/install_scanners.py`. The repository workflow uses Trivy to generate a
CycloneDX SBOM and scan for vulnerabilities and secrets; OSV-Scanner provides
an additional source scan. The worker records tool versions and normalized
findings rather than complete scanner output. Secret findings retain the rule,
file path, and line number, but not matched values or source lines.
Completed repository scans also record `metadata.source_results` for the SBOM,
OSV-Scanner, Trivy, and GitHub Dependabot. Each source is marked available or
unavailable; successful sources include a finding count, including zero. This
does not attest to local database freshness or network isolation.

Repository snapshots and Dependabot alerts are read from GitHub. Configure a
fine-grained token locally through the environment variable named by
`github.token_env` (default: `CICLOSEC_GITHUB_TOKEN`) or a repository's
`credential_env`. Grant only **Contents: read** and **Dependabot alerts: read**
for the authorized repository. Never put the token in source control or send
it in chat. GitHub snapshots are downloaded to temporary storage and removed
after the scan. Dependabot requests reject redirects and pagination links
outside the expected GitHub API endpoint; a rejection leaves the scan partial.
The archive download accepts the initial GitHub API redirect only to
`codeload.github.com`, without forwarding the token, and rejects subsequent
redirects. A rejection fails the checkout.

Repository scans do not provide a fully offline workflow: retrieving a
registered repository and querying Dependabot still require GitHub access. To
avoid scanner-side network requests, set
`scanning.execution.repository_scanner_use_local_databases: true`. OSV-Scanner
then uses its `--offline` mode, which requires a previously populated local
database. Trivy skips vulnerability/Java database updates, package-identification
requests, version checks, and telemetry. A missing local database can make a
source unavailable or fail required SBOM generation. CicloSec always marks a
completed scan partial because it does not verify database freshness. The mode
is not a network sandbox.

Configure `repository_scanner_osv_db_cache_directory` and
`repository_scanner_trivy_cache_directory` to explicit preloaded cache paths.
The worker diagnostic command reports whether the OSV ecosystem archives and
Trivy vulnerability database are present. It does not download or update
databases and does not claim that detected files are current.

With the setting disabled, the pinned OSV-Scanner 2.7.1 documentation says it
sends package names, versions, ecosystems and file hashes to `osv.dev`;
dependency resolution may also query `deps.dev` and package registries. It says
source code is not sent. Trivy 0.76.2 may download vulnerability and Java
databases from OCI registries, query Maven Central for Java package
identification, and contact `check.trivy.dev` for telemetry and update checks.
These are documented destinations, not a guarantee that every network request
has been measured. GitHub API requests include the configured token and
repository identity; the archive download from `codeload.github.com` does not
forward the token.
See the pinned [OSV-Scanner privacy](https://github.com/google/osv-scanner/blob/v2.7.1/README.md#data-sources-and-privacy),
[Trivy connectivity](https://github.com/aquasecurity/trivy/blob/v0.76.2/docs/guide/advanced/air-gap.md)
and [Trivy telemetry](https://github.com/aquasecurity/trivy/blob/v0.76.2/docs/guide/advanced/telemetry.md)
documentation.

The setting
`scanning.execution.allow_repository_scanners_with_network` defaults to
`false`. When disabled in the web process, new repository scan and schedule
requests return HTTP 403 with code `repository_scanner_network_not_authorized`.
When a due repository schedule is processed, it pauses and requires explicit
resumption if the setting is disabled. Updated workers check this permission
before checkout, each scanner invocation, version checks and Dependabot access.
They also recheck Docker permissions before each local image inspection or image
scan. If authorization has been revoked, the scan fails with its corresponding
diagnostic and partial outputs are not persisted. This global repository opt-in
applies to every repository handled by the process.

This setting authorizes execution; it is not a firewall, does not verify
destinations or prevent transmission, and does not apply to image scans or
other network traffic. The local-database option only changes OSV-Scanner and
Trivy; it does not make repository checkout or Dependabot offline. Update and
configure the web process, Beat and **every** worker consistently. Updated
processes resolve this permission from the database, but the web process cannot
verify that every instance is updated. Checks cannot interrupt an operation
already started or eliminate the race between a check and an external call;
individual HTTP requests within a running operation are not independently
checked. Restarting workers does not undo network access by already running
processes. If configuration storage becomes unavailable during a scan, the
worker propagates the error and does not start the next checked operation; the
scan may remain marked running. Follow the [manual recovery procedure](IMPLEMENTATION.md)
only after all workers and scanner processes have stopped.

On-demand scan requests are disabled by default. To enable them, set
`scanning.execution.allow_on_demand: true` in the local
`config/ciclosec.yaml`, then start the web process and Celery worker. An
authenticated `POST /api/scans/` with an asset ID queues a repository scan;
`GET /api/scans/` and `GET /api/findings/` expose recorded results. Only use
this workflow for repositories you are authorized to scan. A scan is marked
partial when an optional scanner or Dependabot lookup is unavailable; a
required Trivy SBOM failure marks it failed. Malformed Trivy vulnerability or
secret list fields make the repository scan partial rather than reporting
zero findings; the SBOM and results from other sources are retained.
The generated SBOM is validated before starting optional scanners or fetching
Dependabot alerts. An invalid SBOM fails the scan without starting those
steps; generating the SBOM itself may still use the network.

## Intelligence synchronization

The GitHub Advisories provider reads reviewed global advisories from GitHub's
public API and does not require a GitHub token. The first run imports advisories
modified in the preceding 30 days; later runs use an overlapping two-day
modified-date window. This is intentionally reported as recent coverage, not a
complete historical GitHub Advisory Database import. Provider runs are
scheduled by Celery using `intelligence.providers.github_advisories` in the
local configuration.

The NVD provider uses the public CVE API without an API key, requests modified
records in windows capped at 120 days, and pauses between requests to respect
the unauthenticated rate limit. Its initial and incremental windows cover
recently modified records only; they do not represent a full historical NVD
import. Configure its schedule with `intelligence.providers.nvd`.

The EPSS provider downloads the public feed without transmitting the locally
known CVE identifiers, then matches scores for those identifiers locally. It
processes at most 100 batches of 50 identifiers per run and resumes the
remainder through Celery. Missing scores are retained and feed completeness
is unverified. Coverage is limited to known CVEs, not the global CVE catalog.

After provider synchronization, CicloSec reevaluates persisted findings and
their linked SBOM occurrences without invoking asset scanners. Package-level
OSV and GitHub advisory evidence is used for applicability. NVD CPE entries
contribute CVSS signals but are not treated as package matches. Exact OSV
versions and simple numeric dotted version ranges are evaluated; unsupported
ecosystems, version syntax, or missing versions remain potential or pending
verification rather than being marked affected.

Risk priorities use policy `risk-v1`: CVSS contributes up to 40 points,
EPSS up to 20, CISA KEV adds 25, internet exposure adds 10, and production
environment adds 5, capped at 100. Levels are critical (80+), high (60–79),
medium (35–59), low (15–34), and informational (below 15). No usable CVSS,
EPSS, or KEV signal produces an unknown score, not a low-risk score. Findings
that are not affected or not applicable do not receive a risk score. The
explanation and factors expose the policy version and freshness of every
intelligence source; scores based on unconfirmed applicability are provisional.
The read-only `/api/findings/` endpoint includes affected status, confidence,
evaluation time, and the risk assessment.

## Local container image scans

Image scans are disabled unless all of the following are true in the local
`config/ciclosec.yaml`: `scanning.execution.allow_on_demand`,
`docker.enabled`, and `docker.allow_local_daemon` are enabled, and the exact
image reference is listed under `docker.images`. The image must already exist
in the local Docker daemon. CicloSec resolves its immutable Docker image ID,
then asks Trivy to use only the `docker` image source; it does not pull from or
scan remote registries. Trivy vulnerability-database updates may still use the
network.

The scan records the Docker image ID (`sha256` digest) alongside the
configured tag, so tag changes do not replace the identity of the scanned
content. Trivy's temporary cache is removed after the scan. Use the
authenticated `POST /api/scans/` endpoint with the container-image asset ID
to queue the scan. A missing local image, disabled daemon access, or an image
reference outside the allowlist fails closed.

## Quality checks

```powershell
uv run pytest
uv run ruff check
uv run ruff format --check
uv run mypy src/ciclosec
uv run pre-commit run --all-files
uv run mkdocs build --strict
```

In Docker mode, the same tools are available in the local app image. Run checks
with `docker compose exec web uv run --no-sync ...`; direct output/cache
directories to `/tmp` when a tool needs to write files.

For local container-image scans, the worker image includes the Docker CLI and
Compose mounts `/var/run/docker.sock` only into the worker. The worker process
retains its non-root `ciclosec` identity and the application still requires
`docker.enabled`, `docker.allow_local_daemon`, and an exact
`docker.images[].reference` allowlist entry. Mounting the daemon socket grants
daemon-level capability; it must be limited to a dedicated worker.

`uv.lock` records the resolved dependency set. Run `uv lock` after intentional
dependency changes and commit the updated lock file.

The local MCP server is available through `uv run ciclosec-mcp`; it is read-only
by default, with optional administrator-authenticated intelligence synchronization.
see the [MCP guide](MCP.md) for its tool list and host configuration.
