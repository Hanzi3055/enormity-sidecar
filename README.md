# Enormity Sidecar API

In-house Node.js API layer for the Enormity Nexus Guard Tour Patrol Management System.

## Overview
JWT-authenticated REST API serving analytics, KPM compliance reports, and real-time patrol data from the Enormity Nexus production database.

## Endpoints
- `POST /api/enormity/auth/token` — JWT authentication
- `GET  /api/enormity/health` — Service health check
- `GET  /api/enormity/patrol/summary` — Daily patrol statistics
- `GET  /api/enormity/patrol/live` — Live patrol feed
- `GET  /api/enormity/guards/efficiency` — Guard efficiency scores
- `GET  /api/enormity/devices/status` — Fleet health monitoring
- `GET  /api/enormity/nexus/dashboard` — Tenant-scoped direct database dashboard
- `GET  /api/enormity/nexus/live-map` — Tenant-scoped direct map telemetry
- `POST /api/enormity/nexus/realtime-ticket` — Single-use authenticated WebSocket ticket
- `GET  /api/enormity/analytics/heatmap` — Hourly scan heatmap
- `GET  /api/enormity/reports/pkk2/pdf` — KPM PKK 2 Manpower Report PDF
- `GET  /api/enormity/reports/pkk3/pdf` — KPM PKK 3 Attendance Report PDF
- `GET  /api/enormity/reports/pkk4/pdf` — KPM PKK 4 Patrol Report PDF
- `GET  /api/enormity/reports/bundle/pdf` — All KPM reports as ZIP

## Tech Stack
- Node.js 24 + Express
- MySQL 8.4.3 (read-only via enormity_reader user)
- JWT authentication (jsonwebtoken)
- Rate limiting (express-rate-limit)
- Security headers (helmet)
- PDF generation (pdfkit)
- Process manager: PM2

## Production
- Live at: https://nexus.enormity.tech/api/enormity/
- Server: Alibaba Cloud ECS (CentOS Linux)
- Developed by: Enormity Resources (KT0537537-A)

## Malaysian KPM Compliance
This API generates PKK 2, PKK 3, and PKK 4 reports formatted for the Malaysian Ministry of Education (Kementerian Pendidikan Malaysia) school security compliance requirements.

## MRANTI / MySTI Evidence - Application #845123

### What this repository contains
This repository contains the Enormity-owned Node.js sidecar API for the live Enormity Nexus / CloudPatrol deployment. It provides the professional API layer, JWT authentication, KPM report generation endpoints, Redis-backed caching, WebSocket integration, health/status endpoints, and MySQL analytics access over the OEM CloudPatrol database.

### How it relates to MySTI #845123
The sidecar is the in-house innovation layer that turns OEM patrol records into KPM-ready management APIs, live operations dashboards, device health reporting, guard analytics, audit logging, and MRANTI-verifiable demo/status surfaces.

### Key files
- `server.js` - Express API, JWT auth, rate limits, health/status, analytics, reports, WebSocket support, and audit logging.
- `kpm-engine.js` - PKK 2, PKK 3, PKK 4, bundle, and daily scorecard PDF generation logic.
- `openapi.yaml` - Machine-readable API documentation source.
- `ecosystem.config.js` - PM2 production process definition for sidecar and healer.
- `.env.example` - Safe configuration template with no production secrets.

### Nexus V2 direct-data boundary

Nexus V2 supplies the company code only from its server-side session. The sidecar resolves that code to one numeric company ID, and every dashboard, alert, device, guard, department, and map query applies that scope in SQL. Company WebSocket clients receive only events carrying the same company ID. Tickets are short-lived, single-use, stored as hashes, and never exposed to browser JavaScript. Biometric templates and credentials are excluded from these endpoints.

### Live verification URLs
- `https://nexus.enormity.tech/api/enormity/health`
- `https://nexus.enormity.tech/api/enormity/docs`
- `https://nexus.enormity.tech/api/enormity/docs.json`
- `https://enormity.tech/demo`
- `https://portal.enormity.tech/api/enormity/health`

### Line count summary
- `server.js`: 1,729 lines
- `kpm-engine.js`: 238 lines
- `ecosystem.config.js`: 39 lines
- Integrated OEM UI module: 3,598 lines at `/opt/CloudPatrol/appFile/web/ROOT/WEB-INF/classes/static/enormity-integrated.js`

### Current hardening evidence
- Public health route is sanitized.
- Infrastructure diagnostics are JWT-protected.
- Public, auth, and protected route rate limits are split.
- Redis cache stats use `INFO memory` and `INFO stats`, not blocking key scans.
- Startup validation checks required configuration, database connectivity, and Redis connectivity before accepting traffic.
