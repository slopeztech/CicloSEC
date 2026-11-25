# CicloSec

CicloSec monitors registered software assets, stores normalized SBOMs, scans
authorized repositories and local container images, and correlates findings
with vulnerability intelligence.

## Start here

- Follow the [implementation guide](IMPLEMENTATION.md) for local setup,
  registering repositories, running scans, and production-readiness gates.
- Use the [roadmap](roadmap.md) for the gated path to complete local use and
  production readiness.
- Read the [architecture](ARCHITECTURE.md) for modules and data flow.
- Use the [development guide](DEVELOPMENT.md) for project checks and technical
  behavior.
- Configure the [local MCP server](MCP.md) for agent queries and optional
  administrator-authorized intelligence synchronization.

> **Deployment status:** local development is supported. Production deployment
> is not ready yet; the implementation guide lists the required blockers.
