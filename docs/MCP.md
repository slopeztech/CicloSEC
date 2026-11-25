# MCP server

CicloSec provides a local Model Context Protocol server using the
official [MCP Python SDK](https://py.sdk.modelcontextprotocol.io/). The server
uses the `stdio` transport; it does not open a network listener or change the
Django routes in `project/urls.py`.

## Run

Complete the [local implementation setup](IMPLEMENTATION.md), set
`mcp.enabled: true` in `config/ciclosec.yaml`, then run:

```powershell
uv run ciclosec-mcp
```

Configure an MCP host to launch that command with the CicloSec repository as
its working directory and the required environment variables. The server reads
the same local configuration and environment variables as Django. `stdout` is
reserved for MCP protocol messages; diagnostics are sent to `stderr`.

## Read-only tools

- `list_assets`: paginated asset identities and operational context; no
  repository credential settings are returned.
- `get_asset_coverage`: recent scan-state counts scoped to enabled assets
  registered in CicloSec, with the configured scan freshness windows.
  `source_changed` counts completed scans whose recorded source differs from
  the current configuration or whose source is missing; `source_unknown`
  counts completed scans without enough recorded identity to verify it.
  Neither counts as current. A matching branch or tag does not prove that its
  underlying content is unchanged.
- `list_scan_history`: paginated status/timing summaries, without scan error
  text, warnings, raw output, or execution metadata.
- `list_sbom_components`: normalized component identities from the latest SBOM
  or a selected scan; includes the SBOM checksum but not its raw document,
  package URL qualifiers, or file paths. `source_status` is `matched`,
  `changed`, or `unknown` relative to the current source, or `null` when
  there is no SBOM. Matching a branch or tag does not verify its content.
- `list_findings`: redacted findings, correlation evidence, and risk
  explanations. `asset_source_status` compares the recorded scan source to
  the current configuration (`matched`, `changed`, or `unknown`). Results
  include history, and a matching source does not prove a finding is current.
- `get_intelligence_freshness`: provider freshness states and timestamps,
  without provider error text or credentials.

Paginated tools accept a maximum of 100 records per call. Tools are annotated
as read-only and use structured input/output schemas. There is deliberately no
scan execution tool, shell access, arbitrary filesystem access, or
configuration-editing tool.

## Protocol verification

Run the focused protocol checks with:

```powershell
uv run --no-sync pytest tests/integration/test_mcp_protocol.py -q
```

The tests use the official MCP Python SDK client. They verify initialization
and tool discovery against a child server over `stdio`, then call the six
read-only tools through the SDK protocol transport with deterministic service
fixtures. They also check pagination bounds, missing assets, and that write
tools remain disabled. These checks do not contact external providers or
exercise live repository data; service redaction and API behavior are covered
separately by the service tests.

## Optional intelligence synchronization

The write tool `request_intelligence_sync` is disabled by default. To enable
it, set `mcp.allow_intelligence_sync: true` and provide
`CICLOSEC_MCP_ADMIN_USERNAME` and `CICLOSEC_MCP_ADMIN_PASSWORD` in the MCP
server process environment. The account must be active and have Django staff
privileges. Do not commit credentials or expose them to untrusted processes.
The MCP host has access to every capability enabled on its server process.

Call the tool with `{"confirm": true}` to explicitly request contact with the
external providers. It returns an individual state for each provider, not a
guarantee that synchronization finished or that historical coverage is
complete. `get_manual_intelligence_sync_status` reports the latest manual
request per provider and requires the same enabled setting and authentication.
An uncertain delivery must be investigated before retrying; it does not prove
that the broker rejected the task. This write tool is marked as having external
effects; all other tools are read-only.

## Human finding decisions

The write tool `review_finding` is disabled by default. Enable
`mcp.allow_finding_decisions: true` and provide
`CICLOSEC_MCP_ADMIN_USERNAME` and `CICLOSEC_MCP_ADMIN_PASSWORD` with the staff
credentials used by the MCP server. The tool requires `confirm: true`, a
finding ID, a status (`open`, `assigned`, `accepted_risk`, `false_positive`,
or `closed`), and a reason. It may accept an active user's `assignee_id`.

The decision is recorded as an immutable audit event and remains separate from
the technical affected status and risk assessment. The REST API exposes the
same operation through `POST /api/findings/{id}/decision/` for staff users.
Neither interface reruns scanners or overwrites scanner findings.
