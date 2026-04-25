# Enormity Sidecar Ownership

The sidecar is an Enormity-owned API layer that extends the OEM CloudPatrol
deployment without modifying every OEM endpoint.

## Purpose

- Provide Enormity Nexus APIs.
- Provide KPM reporting and PDF generation.
- Provide operational health, audit, cache, alert, device, and patrol APIs.
- Provide a stable innovation layer for MySTI evidence.

## Ownership Boundary

The sidecar is Enormity-owned. It reads CloudPatrol data and adds Enormity
business logic, but it does not claim ownership of OEM CloudPatrol internals.

## Current Runtime

- Entry point: `server.js`
- KPM engine: `kpm-engine.js`
- PM2 config: `ecosystem.config.js`
- Smoke test: `scripts/smoke-test.sh`
- API contract: `openapi.yaml`

## Refactor Target

The sidecar should progressively move toward:

- `src/app.js`
- `src/db/pool.js`
- `src/middleware/auth.js`
- `src/middleware/rateLimit.js`
- `src/routes/health.js`
- `src/routes/patrol.js`
- `src/routes/reports.js`
- `src/routes/devices.js`
- `src/routes/alerts.js`
- `src/services/kpmService.js`
- `src/services/auditService.js`
- `src/services/cacheService.js`
- `src/utils/response.js`

Do this incrementally. Do not perform a high-risk one-shot split of
`server.js` during production hardening.
