# Enormity Nexus Sidecar API Specification

Base URL: `https://nexus.enormity.tech`

Authentication:
- Public: `/api/enormity/health`, `/api/enormity/status/overview`, `/api/enormity/status/containers`, `/api/enormity/docs`
- JWT required: all other `/api/enormity/*` routes

## Token

### `POST /api/enormity/auth/token`
- Auth: API key in body
- Body:
  - `apiKey: string`
- Response:
  - `token`
  - `tokenType`
  - `expiresInSeconds`

## Health

### `GET /api/enormity/health`
- Auth: none
- Purpose: service health, DB connectivity, Node runtime status
- Data source: sidecar process + MySQL ping

### `GET /api/enormity/status/overview`
- Auth: none
- Purpose: public status page summary
- Data source: `historydatas`, `SHOW PROCEDURE STATUS`, `SHOW FULL TABLES`, Enormity tables

### `GET /api/enormity/status/containers`
- Auth: none
- Purpose: docker runtime snapshot for the status page
- Data source: `docker ps --format`

## Patrol

### `GET /api/enormity/patrol/summary`
- Auth: JWT
- Query:
  - `companyId?: int`
  - `date?: YYYY-MM-DD`
- Cache: `patrol:summary:{companyId}:{date}` for 5 minutes
- Response fields:
  - `totalScans`
  - `activeGuards`
  - `activeSites`
  - `hourlyBreakdown`
  - `topGuards`
  - `topSites`
- Data source: `historydatas`
- KPM support: daily operational summary

### `GET /api/enormity/patrol/live`
- Auth: JWT
- Purpose: latest raw patrol records
- Data source: `historydatas`

### `GET /api/enormity/patrol/missed`
- Auth: JWT
- Query:
  - `companyId: int`
  - `date?: YYYY-MM-DD`
- Data source: `CALL sp_missed_checkpoints(?, ?)`
- KPM support: missed patrol review

## Operations / Analytics

### `GET /api/enormity/operations/live`
- Auth: JWT
- Query:
  - `companyId?: int`
- Data source: `v_live_operations`
- Purpose: real-time live guard/device status

### `GET /api/enormity/analytics/heatmap`
- Auth: JWT
- Query:
  - `companyId?: int`
  - `days?: int (1-90)`
- Data source: `historydatas`

### `GET /api/enormity/analytics/anomalies`
- Auth: JWT
- Query:
  - `companyId: int`
  - `date?: YYYY-MM-DD`
- Data source: `CALL sp_anomaly_detection(?, ?)`
- KPM support: operational exception review

### `GET /api/enormity/analytics/compliance`
- Auth: JWT
- Query:
  - `companyId: int`
  - `month?: int (1-12)`
  - `year?: int (>=2000)`
- Cache: `compliance:{companyId}:{month}:{year}` for 5 minutes
- Data source: `CALL sp_company_compliance_report(?, ?, ?)`
- KPM support: monthly compliance rollup

## Guards

### `GET /api/enormity/guards/efficiency`
- Auth: JWT
- Query:
  - `companyId?: int`
  - `date?: YYYY-MM-DD`
- Cache: `efficiency:{companyId}:{date}` for 5 minutes
- Data source: `historydatas`

### `GET /api/enormity/guards/streaks`
- Auth: JWT
- Query:
  - `companyId?: int`
- Data source: `enormity_guard_streaks`

## Devices

### `GET /api/enormity/devices/status`
- Auth: JWT
- Query:
  - `companyId?: int`
- Data source: `readers`

## Alerts

### `POST /api/enormity/alerts/:id/acknowledge`
- Auth: JWT
- Path:
  - `id: int`
- Purpose: acknowledge critical escalations
- Data source:
  - `enormity_escalations`
  - `enormity_audit_log`

## Reports

### `GET /api/enormity/reports/pkk2/pdf`
### `GET /api/enormity/reports/pkk3/pdf`
### `GET /api/enormity/reports/pkk4/pdf`
### `GET /api/enormity/reports/bundle/pdf`
- Auth: JWT
- Query:
  - `companyId?: int`
  - `date?: YYYY-MM-DD`
  - `month?: int`
  - `year?: int`
- Data sources:
  - `sp_company_compliance_report`
  - `historydatas`
  - `guards`
  - `readers`
- KPM support:
  - PKK 2 compliance summary
  - PKK 3 attendance
  - PKK 4 patrol record

## Cache

### `GET /api/enormity/cache/stats`
- Auth: JWT
- Purpose: Redis cache visibility
- Data source: Redis on `127.0.0.1:16379`

## Errors

- `400` invalid input
- `401` missing or invalid JWT
- `404` route not found
- `500` internal failure

Response shape:

```json
{
  "success": false,
  "error": {
    "message": "Failed to fetch compliance report."
  },
  "timestamp": "2026-04-23T14:00:00.000Z"
}
```
