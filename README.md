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
- `GET  /api/enormity/analytics/heatmap` — Hourly scan heatmap
- `GET  /api/enormity/reports/pkk2/pdf` — KPM PKK 2 Manpower Report PDF
- `GET  /api/enormity/reports/pkk3/pdf` — KPM PKK 3 Attendance Report PDF
- `GET  /api/enormity/reports/pkk4/pdf` — KPM PKK 4 Patrol Report PDF
- `GET  /api/enormity/reports/bundle/pdf` — All KPM reports as ZIP

## Tech Stack
- Node.js 16 + Express
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
