# Enormity Nexus Performance Report

Date: 2026-04-23

## Method

Measured from the host using local loopback requests and direct MySQL procedure calls inside the `cloudpatrol-db` container.

## HTTP Benchmarks

| Target | HTTP | TTFB | Total |
|---|---:|---:|---:|
| `GET http://127.0.0.1:3100/api/enormity/health` | `200` | `0.001s` | `0.001s` |
| `GET http://127.0.0.1:3100/api/enormity/status/overview` | `200` | `0.042s` | `0.042s` |
| `GET http://127.0.0.1:5050/api/statistic_overview` | `401` | `0.089s` | `0.089s` |

Note:
- The OEM comparison route currently returns `401` from the local unauthenticated curl context, so this measures gateway latency only, not payload generation time.
- Protected Enormity routes are live, but this sandbox session could not complete a reliable authenticated curl benchmark end-to-end without leaking credentials into shell state. Public route timings were captured instead.

## Procedure Timings

Measured with `SELECT NOW(6)` before and after the live calls.

### `sp_company_compliance_report(1, MONTH(CURDATE()), YEAR(CURDATE()))`
- Start: `2026-04-23 22:54:28.660551`
- End: `2026-04-23 22:54:28.661798`
- Approx duration: `0.001247s`

### `sp_anomaly_detection(1, CURDATE())`
- Start: `2026-04-23 22:54:28.661855`
- End: `2026-04-23 22:54:28.662757`
- Approx duration: `0.000902s`

## Observations

- The public status overview is comfortably sub-50ms on loopback.
- The health endpoint is effectively instantaneous.
- The new compliance and anomaly procedures execute in under 2ms on the current production dataset for company `1`.
- Further benchmarking should be repeated externally through `https://nexus.enormity.tech` with a real JWT to capture TLS and proxy overhead for protected routes.
