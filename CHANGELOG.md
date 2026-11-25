# Changelog

## Unreleased

- Add audited, confirmed administrator settings overrides and Beat startup
  revision observations, with unknown states for unverified instances.
- Add provider schedule controls that do not block manual sync or queued work.
- Add live dashboard refresh, prioritized findings, contextual guidance and
  locally available recent CVE and urgent-finding summaries.
- Download the public EPSS feed without sending locally known CVE identifiers;
  retain absent scores and report coverage as unverified.
- Add an administrator-confirmed intelligence refresh via dashboard and API,
  and an explicitly enabled, administrator-authenticated MCP write tool.
- Provide uncertain local resource estimates without enforcing resource limits.
- Mark initial scan delivery as unconfirmed before transaction commit, so a
  crash before publishing remains visible for manual review.
- Show recorded scanner versions and warn that queued messages may be lost
  after a Redis interruption even when initial delivery was confirmed.
- Bound Linux scanner process groups and pipe cleanup; descendants that
  escape the group remain outside this control.
- Run Windows scanner processes in a job object, terminating associated
  descendants on completion or limit violations.
- Detect scanner output-limit violations promptly and report pipe read errors
  without exposing internal details.
- Add opt-in per-asset scan schedules with staff authorization, failure pauses,
  source-change protection and shared queue/concurrency limits.
- Add an offline manual recovery command for interrupted scans, requiring
  operator confirmation that all workers and scanner processes are stopped.
- Distinguish requested and actual scan start times in History and warn that
  a running status does not establish worker health.
- Show global recorded scan capacity and uncertain deliveries in History and
  an authenticated, non-cacheable API; these are not broker or worker health.
- Bound queued scan admission with configurable `max_queued_scans`, returning
  HTTP 429 when the limit is reached.
- Allow authenticated users to explicitly cancel unstarted queued scans;
  preserve their history and reject later deliveries in updated workers.
- Coordinate scan starts across PostgreSQL workers using the configured
  concurrency limit, with delayed retries and uncertain-delivery reporting.
- Ignore duplicate scan-task deliveries after the run is claimed, reporting
  the recorded scan status without restarting it.
- Report uncertain broker delivery without exposing internal errors or
  overwriting a running scan; retain its ID and queued status for inspection.
- Reject duplicate active scan requests per asset with HTTP 409 and link to
  the existing run in the dashboard; serialize requests on PostgreSQL.
- Show fixed, safe explanations for failed and partial scans in the dashboard,
  with a generic fallback for older or unknown diagnostics.
- Show each finding's asset-source identity status in dashboard, API, and MCP;
  clarify that finding and severity counts include history.
- Show the selected SBOM's source identity status in dashboard, API, and MCP
  without hiding historical inventory.
- Distinguish changed or missing scan sources from unverified historical
  identities in dashboard, API, and MCP coverage; record image source revisions.
- Preserve repository source identity across checkout and Dependabot, flag
  source changes during scans, and show the original source in scan details.
- Reject queued scans for assets disabled before execution, and claim scan
  runs transactionally before accessing their sources.
- Provide sanitized GitHub archive and Dependabot HTTP diagnostics without
  treating ambiguous access failures as confirmed causes.
- Validate repository and image sources consistently across API and dashboard,
  prevent asset kind changes, and display image sources in asset details.
- Invalidate image digests on source changes and prevent in-flight scans from
  assigning an older source's digest; this requires an assets migration and
  upgrading all workers with the web application.
- Add authenticated responsive pages for asset management, findings, SBOM,
  scan history, intelligence freshness, and API/MCP access.
- Fix GitHub advisory synchronization for second-precision dates,
  cursor-based pagination, and string-valued patched versions.
- Accept NVD response timestamps without an explicit UTC offset.
- Bound OSV imports to resumable batches with explicitly limited continuation.
- Reconcile OSV aliases with auditable, reversible identity groups while
  retaining original vulnerability, advisory, alias, and finding references.
- Add cross-platform native and Docker setup scripts that install Python
  dependencies and checksum-verified Trivy/OSV-Scanner binaries automatically.
- Preserve existing scanner binaries if an update fails validation and stage
  replacements on the destination filesystem.
- Add a read-only local diagnostic command for core services and scanner availability.
- Use an IPv4 loopback database address for new native installations and document
  the serial Celery pool required for Windows workers.
- Initialize the CicloSec modular Django project and local development tooling.
- Add strict YAML configuration validation and secret-safe environment lookup.
- Add asset, scan, vulnerability, and SBOM inventory models with CycloneDX/SPDX
  validation, conversion, persistence, and dependency relationships.
- Add authenticated API endpoints for assets, repository sources, and
  container-image sources.
- Add CISA KEV and OSV intelligence synchronization with durable checkpoints,
  reconciliation, bounded HTTP retries, Celery schedules, and freshness status.
- Add incremental synchronization of reviewed GitHub global security advisories
  with bounded pagination, overlap checkpoints, and sanitized stored records.
- Add incremental NVD CVE synchronization with bounded modified-date windows,
  offset pagination, request pacing, and persisted CVSS/CPE evidence.
- Add bounded, resumable EPSS score refreshes for CVEs already known to CicloSec.
- Add authorized GitHub repository scanning with Trivy SBOM/vulnerability/
  secret detection, OSV-Scanner, Dependabot alerts, and persisted redacted
  findings.
- Include supported development dependencies in repository SBOMs; their
  production or development scope may remain unknown.
- Add opt-in local Docker image scanning with Trivy, immutable image-ID
  tracking, an explicit image allowlist, and temporary-cache cleanup.
- Add package-aware finding correlation, alias relinking, versioned risk
  assessments, and reevaluation after scans or intelligence updates without
  rerunning scanners.
- Add a local stdio MCP server with bounded, structured, read-only tools for
  assets, coverage, SBOM components, scan history, findings, and source freshness.
  Startup requires the explicit `mcp.enabled: true` configuration opt-in.
- Add an authenticated local dashboard, a bounded dashboard summary API, and
  paginated normalized SBOM component queries.
- Add a dashboard scan-request form that remains hidden unless on-demand
  scanning is explicitly enabled and submits through the authenticated scan API.
- Add bounded dashboard pagination for assets, scan history, and findings,
  retaining active filters across page navigation.
- Rewrite project documentation to match the implemented runtime and add a
  step-by-step local runbook plus gated Linux/Compose production-readiness plan.
- Add a gated MVP checklist for local setup, authorized GitHub scanning,
  Dependabot, SBOM verification, and troubleshooting.
