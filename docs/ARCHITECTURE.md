# Architecture

## Current runtime

CicloSec is implemented as a modular Django monolith. PostgreSQL is the durable
store; Celery workers run scans and intelligence synchronization through Redis.
Locally, Compose provides PostgreSQL and Redis; Django and the worker may run
either on the host or in the development Compose application profile. Beat is
an optional, separately started scheduler. The Compose application profile is
not production-ready.

The Django modules separate project configuration, shared configuration,
assets, scans, inventory/SBOM, scanners, intelligence, findings/risk,
server-rendered web/API, and MCP. Integrations are application adapters, not
independently deployed microservices.

The inventory layer validates CycloneDX JSON (specification versions 1.0–1.7)
with `cyclonedx-python-lib` and SPDX 2.2/2.3 JSON with `spdx-tools`.
`packageurl-python` normalizes package URLs. These standards libraries are
runtime dependencies because importing,
normalizing, and exporting verified SBOMs is part of the application behavior.
SBOM JSON is stored with its scan record, canonical SHA-256 checksum, package
occurrences, and dependency edges.

The two background workflows remain distinct:

1. Asset analysis creates a scan record and a versioned SBOM.
2. Intelligence synchronization updates provider records and reevaluates
   findings against saved SBOMs without automatically rerunning scanners.

Repository scans use Trivy for CycloneDX generation and vulnerability/secret
detection, OSV-Scanner for an independent source scan, and GitHub's read-only
API for authorized repository snapshots and Dependabot alerts. Repository
assets are registered through the authenticated API; a YAML list does not
bootstrap database records. The scanner adapters retain normalized evidence
only; secret values and complete scanner outputs are not persisted. On-demand
execution is disabled unless explicitly enabled in local configuration.
Repository SBOM generation requests development dependencies where Trivy
supports them; CycloneDX output may not identify their scope, and unresolved
manifests can still produce an incomplete inventory. Trivy's vulnerability
scan options are unchanged.

Container image scans require explicit local-daemon opt-in and an exact
allowlisted image reference. They resolve the local Docker image ID before
analysis and pass that immutable ID to Trivy with `--image-src docker`,
preventing fallback to a remote registry. The resolved ID is stored with the
image asset and scan metadata. Trivy's per-scan cache lives in a temporary
directory that is removed after execution. Access to a Docker daemon is
privileged and is not recommended as a production worker default.

Intelligence synchronization is provider-specific and auditable. CISA KEV is
reconciled as a complete snapshot; OSV uses the public modified-ID feed with
HTTP ranges, an overlapping incremental checkpoint, and a maximum of 200 record
downloads per batch. A timestamp and the processed paths at that timestamp
preserve progress even if equal-timestamp entries are reordered. The record
updates and checkpoint commit together. One task runs one batch by default;
an explicit chain may contain at most 10 batches. Incomplete windows remain
partial, and a later incremental run picks up updates received during the
window. Each batch rereads the index from its beginning, so large windows can
still take substantial bandwidth and time; this does not establish historical
coverage. GitHub reviewed advisories use
the public global-advisories API with a 30-day initial window and a two-day
overlap for incremental updates. Their stored records omit contributor
metadata. This GitHub window does not claim complete historical coverage.
NVD CVEs use the modified-date API with offset pagination, windows no wider
than 120 days, a 30-day initial lookback, and a one-hour overlap. Requests are
paced for the unauthenticated API limit. This also reports recent coverage
rather than a complete NVD history. EPSS downloads the public feed without
sending locally known CVE identifiers, then matches it against local aliases
in bounded batches with resumable checkpoints. Missing scores are retained and
feed completeness is unverified; this does not establish global CVE coverage.
Provider successes and failures are stored separately so stale or unavailable
sources cannot be presented as current.

OSV-declared aliases can reconcile existing identities without deleting
vulnerabilities or moving their aliases, advisories, or findings. Each
decision stores its provider, source record, sync run, previous group
membership, and a snapshot of reference ownership. Correlation combines
active advisories across the group while preserving original API identifiers.
Multiple CVEs or previously reversed equivalences require review rather than
an automatic merge. Reversal is transactional, rejects changed references or
later active merges, and reevaluates affected findings. This audit trail is
stored in the application database; it is not a tamper-proof external log.

The implementation and phase gates are defined in the [roadmap](roadmap.md).
The architectural choice is recorded in
[ADR 0001](ADR/0001-modular-monolith.md). For setup and the current production
readiness boundary, see the [implementation guide](IMPLEMENTATION.md).
