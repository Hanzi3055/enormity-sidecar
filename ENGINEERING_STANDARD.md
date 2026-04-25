# Enormity Sidecar Engineering Standard

## API Contract

- Every success response uses `{ success: true, data, timestamp }`.
- Every error response uses `{ success: false, error, timestamp }`.
- Protected APIs require JWT unless explicitly documented as public.
- Public APIs must not expose infrastructure internals.

## Database

- Use the shared query wrapper.
- Every query must have timeout protection.
- Use parameterized SQL whenever MySQL supports it.
- For MySQL syntax positions that cannot be parameterized, inline only
  validated/bounded integers.

## Operations

- `node --check server.js` must pass before PM2 restart.
- `scripts/smoke-test.sh` must pass after deployment.
- PM2 should run exactly one sidecar process.
- Health must include DB/Redis state without leaking secrets.

## Evidence

- Keep `openapi.yaml` current.
- Keep `ENDPOINT_LIST.txt` current for MySTI evidence.
- Keep README live URLs and verification commands current.
