# ADR 0001: Modular monolith for the local MVP

- **Status:** Accepted
- **Date:** 2026-11-20

## Context

CicloSec needs a local web application, API, scheduled work, scanner adapters,
intelligence providers, and an MCP server. These capabilities share domain data
and must remain operable without a hosted SaaS dependency. Splitting them into
microservices at the outset would add deployment and consistency costs before
their boundaries are validated.

## Decision

Use Django as a modular monolith with PostgreSQL as the durable store, Celery
workers for asynchronous work, Redis as broker/result backend, and Docker
Compose for local infrastructure. Keep scanner/provider integrations behind
Python interfaces. Expose the web server on loopback by default.

## Consequences

- A local installation has a small operational footprint.
- Domain boundaries can be tested before any component is separated.
- Long-running scans remain asynchronous and have explicit lifecycle state.
- If scaling later requires separate processes, module contracts provide
  extraction boundaries without requiring microservices now.
