require('dotenv').config();

const express = require('express');
const helmet = require('helmet');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');
const Redis = require('ioredis');
const axios = require('axios');
const kpmEngine = require('./kpm-engine');
const { canReceiveRealtimeEvent, normalizeCompanyId, normalizeRealtimeScope } = require('./realtime-scope');

process.on('uncaughtException', (err) => {
  console.error('[Enormity] Uncaught exception:', err && err.message, err && err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[Enormity] Unhandled rejection at:', promise, 'reason:', reason);
});

const app = express();
const startedAt = Date.now();
const SERVICE_VERSION = '3.2.0';
const SERVICE_BUILD_DATE = '2026-07-17';
const PORT = Number(process.env.PORT || 3100);
const WS_PORT = Number(process.env.WS_PORT || 3101);
const BIND_HOST = String(process.env.SIDECAR_BIND_HOST || '127.0.0.1').trim();
const JWT_SECRET = String(process.env.JWT_SECRET || '').trim();
const VALID_API_KEYS = String(process.env.ENORMITY_API_KEYS || '').split(',').map((key) => key.trim()).filter(Boolean);
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || process.env.TELEGRAM_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || process.env.TELEGRAM_CHAT || '';
// Writes are opt-in. A missing or misspelled environment value must never
// make a read-oriented Core release start mutating CloudPatrol state.
const BACKGROUND_WRITES_ENABLED = process.env.ENORMITY_BACKGROUND_WRITES_ENABLED === '1';
const ASSISTANT_METRIC_TOOLS = new Set([
  'attendance_summary',
  'shift_summary',
  'patrol_completion_summary',
  'omissions_summary',
  'fingerprint_metadata',
]);
const READ_ONLY_POST_PATHS = new Set([
  '/api/enormity/nexus/realtime-ticket',
  '/api/enormity/nexus/v2/locations/search',
  '/api/enormity/nexus/v2/assistant/metrics',
  '/api/enormity/nexus/v2/biometrics/metadata',
  '/api/enormity/nexus/v2/contracts/query',
]);
const NEXUS_DIRECT_CONTRACTS = new Map([
  ['dept-tree-list', 'departments'],
  ['dept-tree-site', 'departments'],
  ['dept-tree-guard', 'departments'],
  ['dept-tree-user', 'departments'],
  ['dept-tree-plan', 'departments'],
  ['dept-tree-event', 'departments'],
  ['sites-by-dept', 'sites_checkpoints'],
  ['guards-by-dept', 'guards'],
  ['guards-all', 'guards'],
  ['attendance-config', 'shifts'],
]);
const NEXUS_COMMAND_AREAS = new Set([
  'tenant-company', 'sites-checkpoints', 'guards', 'guard-enrollment', 'duty',
  'clocking-history', 'patrol-plans', 'download-parameters', 'events',
  'content-notice-voice', 'address-book', 'receipts', 'talk-groups', 'users',
  'roles', 'devices', 'device-registration', 'cards-licenses', 'mobile-apps',
  'database-backups',
]);
const NEXUS_BIOMETRIC_OPERATIONS = new Set(['save', 'rename', 'link', 'unlink', 'delete']);

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is required for Enormity sidecar startup.');
}

if (VALID_API_KEYS.length === 0) {
  throw new Error('ENORMITY_API_KEYS must contain at least one API key.');
}

const QUERY_TIMEOUT_MS = Number(process.env.MYSQL_QUERY_TIMEOUT_MS || 10000);
const POOL_CONFIG = {
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 10000,
};
const poolStats = { acquired: 0, released: 0, created: 0, destroyed: 0, enqueued: 0, timedOut: 0 };
const RETRYABLE_DB_ERRORS = new Set([
  'ECONNRESET',
  'PROTOCOL_CONNECTION_LOST',
]);

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 13306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'cloudpatrol',
  waitForConnections: POOL_CONFIG.waitForConnections,
  connectionLimit: POOL_CONFIG.connectionLimit,
  queueLimit: POOL_CONFIG.queueLimit,
  connectTimeout: POOL_CONFIG.connectTimeout,
  timezone: 'local',
  dateStrings: false,
});

// Dedicated database roles are also fail-safe by default. Disposable local
// schema probes may explicitly use 0; production Compose always sets 1.
const NEXUS_DB_IDENTITY_STRICT = process.env.NEXUS_DB_IDENTITY_STRICT !== '0';
const nexusDbRoles = ['query', 'command', 'identity', 'biometric'];
const nexusDbIdentityConfig = Object.fromEntries(nexusDbRoles.map((role) => [role, nexusRoleCredentials(role)]));
const nexusQueryCredentials = nexusDbIdentityConfig.query;
const nexusQueryPool = mysql.createPool({
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 13306),
  user: nexusQueryCredentials.configured ? nexusQueryCredentials.user : (process.env.MYSQL_USER || 'root'),
  password: nexusQueryCredentials.configured ? nexusQueryCredentials.password : (process.env.MYSQL_PASSWORD || ''),
  database: process.env.MYSQL_DATABASE || 'cloudpatrol',
  waitForConnections: true,
  connectionLimit: Number(process.env.NEXUS_QUERY_MYSQL_POOL_LIMIT || 6),
  queueLimit: 0,
  connectTimeout: 10000,
  timezone: 'local',
  dateStrings: false,
});
const nexusRolePools = new Map([['query', nexusQueryPool]]);

function nexusRoleCredentials(role) {
  const prefix = `NEXUS_${String(role).toUpperCase()}_MYSQL`;
  const user = String(process.env[`${prefix}_USER`] || '').trim();
  const passwordFile = String(process.env[`${prefix}_PASSWORD_FILE`] || '').trim();
  let password = String(process.env[`${prefix}_PASSWORD`] || '');
  if (passwordFile) {
    if (!path.isAbsolute(passwordFile)) throw new Error(`${prefix}_PASSWORD_FILE must be absolute.`);
    const bytes = fs.readFileSync(passwordFile);
    if (bytes.byteLength < 16 || bytes.byteLength > 4096) throw new Error(`${prefix}_PASSWORD_FILE has an invalid size.`);
    password = bytes.toString('utf8').trim();
  }
  return { user, password, configured: Boolean(user && password) };
}

function nexusDbIdentityStatus() {
  const users = nexusDbRoles.map((role) => nexusDbIdentityConfig[role].user).filter(Boolean);
  const allConfigured = nexusDbRoles.every((role) => nexusDbIdentityConfig[role].configured);
  return {
    strict: NEXUS_DB_IDENTITY_STRICT,
    allConfigured,
    distinctUsers: users.length === nexusDbRoles.length && new Set(users).size === nexusDbRoles.length,
    roles: Object.fromEntries(nexusDbRoles.map((role) => [role, { configured: nexusDbIdentityConfig[role].configured }])),
  };
}

function requireNexusDbIdentity(role) {
  if (!NEXUS_DB_IDENTITY_STRICT) return;
  const status = nexusDbIdentityStatus();
  if (!nexusDbIdentityConfig[role]?.configured || !status.distinctUsers) {
    const error = new Error(`The dedicated Nexus ${role} database identity is not ready.`);
    error.status = 503;
    error.code = 'E_DB_IDENTITY';
    throw error;
  }
}

function nexusPoolForRole(role) {
  requireNexusDbIdentity(role);
  if (nexusRolePools.has(role)) return nexusRolePools.get(role);
  const credentials = nexusDbIdentityConfig[role];
  if (!credentials?.configured) {
    const error = new Error(`The dedicated Nexus ${role} database identity is not configured.`);
    error.status = 503;
    error.code = 'E_DB_IDENTITY';
    throw error;
  }
  const rolePool = mysql.createPool({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 13306),
    user: credentials.user,
    password: credentials.password,
    database: process.env.MYSQL_DATABASE || 'cloudpatrol',
    waitForConnections: true,
    connectionLimit: Number(process.env[`NEXUS_${role.toUpperCase()}_MYSQL_POOL_LIMIT`] || 3),
    queueLimit: 0,
    connectTimeout: 10000,
    timezone: 'local',
    dateStrings: false,
  });
  nexusRolePools.set(role, rolePool);
  return rolePool;
}

async function withNexusTransaction(role, callback) {
  if (role !== 'command' && role !== 'identity' && role !== 'biometric') {
    throw Object.assign(new Error('Invalid Nexus transaction role.'), { status: 500, code: 'E_DB_ROLE' });
  }
  const connection = await nexusPoolForRole(role).getConnection();
  try {
    await connection.query('SET TRANSACTION ISOLATION LEVEL READ COMMITTED');
    await connection.beginTransaction();
    const result = await callback(connection);
    await connection.commit();
    return result;
  } catch (error) {
    try { await connection.rollback(); } catch (_) {}
    throw error;
  } finally {
    connection.release();
  }
}

pool.on('connection', (connection) => {
  poolStats.created += 1;
  console.log(`[Enormity] MySQL pool connection created threadId=${connection.threadId}`);
  connection.on('end', () => {
    poolStats.destroyed += 1;
    console.log(`[Enormity] MySQL pool connection ended threadId=${connection.threadId}`);
  });
  connection.on('error', (err) => {
    console.error(`[Enormity] MySQL pool connection error threadId=${connection.threadId}:`, err.message);
  });
});
pool.on('acquire', (connection) => {
  poolStats.acquired += 1;
  console.log(`[Enormity] MySQL pool acquire threadId=${connection.threadId}`);
});
pool.on('release', (connection) => {
  poolStats.released += 1;
  console.log(`[Enormity] MySQL pool release threadId=${connection.threadId}`);
});
pool.on('enqueue', () => {
  poolStats.enqueued += 1;
  console.warn('[Enormity] MySQL pool enqueue waiting for free connection');
});

const redis = new Redis({
  host: process.env.REDIS_HOST || '127.0.0.1',
  port: Number(process.env.REDIS_PORT || 16379),
  lazyConnect: true,
  maxRetriesPerRequest: 1,
  enableOfflineQueue: false,
});
let redisReady = false;
const cacheCounters = { hits: 0, misses: 0 };
const patrolStatsCache = { key: null, data: null, timestamp: 0 };
const PATROL_STATS_TTL_MS = 30 * 1000;
const REPORT_ARCHIVE_ROOT = process.env.KPM_ARCHIVE_ROOT || '/opt/enormity-sidecar/reports/archive';
const REALTIME_TICKET_TTL_MS = 30 * 1000;
const REALTIME_TICKET_LIMIT = 1000;
const realtimeTickets = new Map();
const notifiedEscalations = new Set();
let shuttingDown = false;
let acceptingRequests = true;
let inFlightRequests = 0;
const intervalHandles = [];

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet());
app.use(express.json({ limit: '1mb' }));

function rateLimitKey(req) {
  return ipKeyGenerator(clientIp(req));
}

const publicLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: rateLimitKey,
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  // A standalone Next build has several isolated server bundles, each with a
  // process-local token cache. Allow one exchange per bundle while retaining
  // a strict per-IP ceiling for the high-entropy service key.
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: rateLimitKey,
});

const protectedLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.enormityAuth?.subject || rateLimitKey(req),
});

app.use((req, res, next) => {
  if (!acceptingRequests) {
    return fail(res, 503, 'Service is shutting down. Try again shortly.', null, 'E_SHUTDOWN');
  }
  inFlightRequests += 1;
  res.on('finish', () => { inFlightRequests = Math.max(0, inFlightRequests - 1); });
  res.on('close', () => { if (!res.writableEnded) inFlightRequests = Math.max(0, inFlightRequests - 1); });
  const start = process.hrtime.bigint();
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);
  res.setHeader('X-Powered-By', 'Enormity Tech Solutions');
  res.setHeader('X-API-Version', '2.0.0');
  const originalEnd = res.end;
  res.end = function patchedEnd(...args) {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    if (!res.headersSent) {
      res.setHeader('X-Response-Time', `${durationMs.toFixed(2)}ms`);
    }
    return originalEnd.apply(this, args);
  };
  next();
});

app.use((req, res, next) => {
  const start = process.hrtime.bigint();
  res.on('finish', () => {
    const durationMs = Number(process.hrtime.bigint() - start) / 1e6;
    console.log(`${req.method} ${req.originalUrl} ${res.statusCode} ${durationMs.toFixed(1)}ms`);
    auditRequest(req, res, durationMs).catch((err) => {
      console.error('audit log failed:', err.message);
    });
  });
  next();
});

function timestamp() {
  return new Date().toISOString();
}

function ok(res, data, status = 200) {
  return res.status(status).json({ success: true, data, timestamp: timestamp() });
}

function fail(res, status, message, details, code) {
  const payload = { success: false, error: { message }, timestamp: timestamp() };
  if (code) payload.error.code = code;
  if (details) payload.error.details = details;
  return res.status(status).json(payload);
}

function handleRouteError(res, route, err, fallbackMessage) {
  console.error(`[Enormity] ${route} error:`, err && err.message, err && err.stack ? err.stack : '');
  if (err && err.code === 'QUERY_TIMEOUT') {
    return fail(res, 503, 'Database query timed out. Try again shortly.', fallbackMessage || err.message, 'QUERY_TIMEOUT');
  }
  if (err && err.status && err.status < 500) {
    return fail(res, err.status, fallbackMessage || err.message, err.message, err.code || 'E400');
  }
  return fail(res, 500, 'Internal server error', fallbackMessage || 'Request failed.', 'E001');
}

function parsePositiveInt(value, fallback, max) {
  const parsed = Number.parseInt(String(value || ''), 10);
  const safe = Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
  return max ? Math.min(safe, max) : safe;
}

function nexusDomainSourceMode(domain) {
  const suffix = String(domain || '').toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  const key = `NEXUS_DOMAIN_SOURCE_${suffix}`;
  const value = String(process.env[key] || 'direct').trim().toLowerCase();
  if (value !== 'direct' && value !== 'compare' && value !== 'oem') {
    throw Object.assign(new Error(`${key} must be direct, compare, or oem.`), { status: 503, code: 'E_SOURCE_MODE' });
  }
  return value;
}

function validateNexusSourceModes(env = process.env) {
  for (const [key, raw] of Object.entries(env)) {
    if (!key.startsWith('NEXUS_DOMAIN_SOURCE_')) continue;
    const value = String(raw || '').trim().toLowerCase();
    if (value !== 'direct' && value !== 'compare' && value !== 'oem') {
      throw new Error(`${key} must be direct, compare, or oem.`);
    }
  }
}

function setNexusDirectSourceHeaders(res, domain) {
  res.setHeader('X-Nexus-Data-Source', 'cloudpatrol-mysql-direct');
  res.setHeader('X-Nexus-Source-Mode', nexusDomainSourceMode(domain));
  res.setHeader('Cache-Control', 'private, no-store');
}

function requireDirectReadMode(res, domain) {
  if (nexusDomainSourceMode(domain) !== 'oem') return true;
  fail(res, 503, `The ${domain} direct-read domain is disabled while its source mode is OEM.`, null, 'E_SOURCE_MODE');
  return false;
}

function safeAssistantSearch(value) {
  const text = String(value || '').normalize('NFKC').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim();
  return text.length >= 2 && text.length <= 80 ? text : '';
}

function assistantEntityType(value) {
  const type = String(value || '').trim().toLowerCase();
  return type === 'guard' || type === 'device' || type === 'site' ? type : 'any';
}

function assistantDateRange(body) {
  const today = todayString();
  const from = String(body?.dateFrom || today).trim();
  const to = String(body?.dateTo || from).trim();
  if (!isExactAssistantDate(from) || !isExactAssistantDate(to)) {
    throw Object.assign(new Error('dateFrom and dateTo must use YYYY-MM-DD.'), { status: 400, code: 'E_DATE' });
  }
  const fromMs = Date.parse(`${from}T00:00:00Z`);
  const toMs = Date.parse(`${to}T00:00:00Z`);
  if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || toMs < fromMs || toMs - fromMs > 366 * 86400000) {
    throw Object.assign(new Error('The date range must be valid, ordered, and no longer than 366 days.'), { status: 400, code: 'E_DATE' });
  }
  return { from, to };
}

function isExactAssistantDate(value) {
  if (!/^20\d{2}-\d{2}-\d{2}$/.test(value)) return false;
  const date = new Date(`${value}T00:00:00.000Z`);
  return Number.isFinite(date.getTime()) && date.toISOString().slice(0, 10) === value;
}

function optionalPositiveInt(value, label) {
  if (value === undefined || value === null || value === '') return null;
  const parsed = normalizeCompanyId(value);
  if (!parsed) throw Object.assign(new Error(`${label} must be a positive integer.`), { status: 400, code: 'E_FILTER' });
  return parsed;
}

function directContractFilters(body) {
  const source = body && typeof body === 'object' && !Array.isArray(body.filters) && body.filters && typeof body.filters === 'object'
    ? body.filters
    : {};
  const forbidden = Object.keys(source).some((key) => /^(?:company|companyid|companycode|tenant|tenantid|tenantcode)$/i.test(key));
  if (forbidden) throw Object.assign(new Error('Tenant scope cannot be supplied in contract filters.'), { status: 400, code: 'E_SCOPE' });
  const valueFor = (...keys) => {
    for (const key of keys) if (source[key] !== undefined && source[key] !== null && source[key] !== '') return source[key];
    return null;
  };
  return {
    deptId: optionalPositiveInt(valueFor('DeptID', 'DeptId', 'deptId'), 'DeptID'),
    guardId: optionalPositiveInt(valueFor('GuardID', 'guardId', 'guardid'), 'GuardID'),
    limit: parsePositiveInt(body?.limit, 500, 1000),
  };
}

async function queryDirectContract(contractId, companyId, filters) {
  if (contractId.startsWith('dept-tree-')) {
    const rows = await nexusQuery(
      `SELECT d.DEPTID,
              d.DEPTNAME,
              d.DEPTSN,
              d.DEPTCODE,
              d.VALID,
              d.PARENTDEPTID,
              d.COMPANYID,
              d.TIMEZONE,
              COUNT(*) OVER() AS __nexus_total
         FROM depts d
        WHERE d.COMPANYID = ?
          AND IFNULL(d.VALID, 1) <> 0
        ORDER BY d.DEPTSN, d.DEPTID
        LIMIT ${filters.limit}`,
      [companyId]
    );
    return contractRows(rows);
  }
  if (contractId === 'sites-by-dept') {
    const rows = await nexusQuery(
      `SELECT s.SITEID,
              s.SITENAME,
              s.SITESN,
              s.SITECODE,
              s.SITETYPE,
              s.LONGITUDE,
              s.LATITUDE,
              s.ERRORSPAN,
              s.TAG,
              s.DEPTID,
              d.DEPTNAME,
              d.COMPANYID,
              COUNT(*) OVER() AS __nexus_total
         FROM sites s
         JOIN depts d ON d.DEPTID = s.DEPTID
        WHERE d.COMPANYID = ?
          AND (? IS NULL OR s.DEPTID = ?)
        ORDER BY s.SITESN, s.SITEID
        LIMIT ${filters.limit}`,
      [companyId, filters.deptId, filters.deptId]
    );
    return contractRows(rows);
  }
  if (contractId === 'guards-by-dept' || contractId === 'guards-all') {
    const rows = await nexusQuery(
      `SELECT g.GUARDID,
              g.GUARDNAME,
              g.GUARDSN,
              g.GUARDCODE,
              g.TELEPHONE,
              g.TAG,
              g.avatar,
              g.DEPTID,
              g.guardtype,
              d.DEPTNAME,
              d.COMPANYID,
              COUNT(*) OVER() AS __nexus_total
         FROM guards g
         JOIN depts d ON d.DEPTID = g.DEPTID
        WHERE d.COMPANYID = ?
          AND (? IS NULL OR g.DEPTID = ?)
          AND (? IS NULL OR g.GUARDID = ?)
        ORDER BY g.GUARDSN, g.GUARDID
        LIMIT ${filters.limit}`,
      [companyId, contractId === 'guards-all' ? null : filters.deptId, contractId === 'guards-all' ? null : filters.deptId, filters.guardId, filters.guardId]
    );
    return contractRows(rows);
  }
  if (contractId === 'attendance-config') {
    const rows = await nexusQuery(
      `SELECT wc.id,
              wc.companyid AS COMPANYID,
              wc.deptid AS DEPTID,
              wc.category,
              wc.begintime,
              wc.endtime,
              wc.gotoworksiteid,
              wc.gooffworksiteid,
              wc.workhour,
              wc.guardcount,
              d.DEPTNAME,
              COUNT(*) OVER() AS __nexus_total
         FROM worktimeconfig wc
    LEFT JOIN depts d ON d.DEPTID = wc.deptid AND d.COMPANYID = wc.companyid
        WHERE wc.companyid = ?
          AND (? IS NULL OR wc.deptid = ?)
        ORDER BY wc.deptid, wc.category, wc.id
        LIMIT ${filters.limit}`,
      [companyId, filters.deptId, filters.deptId]
    );
    return contractRows(rows);
  }
  throw Object.assign(new Error('Direct contract is not registered.'), { status: 404, code: 'E_CONTRACT' });
}

function contractRows(rows) {
  const total = Number(rows[0]?.__nexus_total || 0);
  return {
    total,
    rows: rows.map((row) => Object.fromEntries(Object.entries(row).filter(([key]) => key !== '__nexus_total'))),
  };
}

async function searchGuardLocations(companyId, search) {
  return nexusQuery(
    `WITH candidates AS (
       SELECT g.GUARDID AS entityId,
              g.GUARDNAME AS entityName,
              g.GUARDCODE AS entityCode
         FROM guards g
         JOIN depts d ON d.DEPTID = g.DEPTID
        WHERE d.COMPANYID = ?
          AND (INSTR(LOWER(g.GUARDNAME), LOWER(?)) > 0 OR INSTR(LOWER(g.GUARDCODE), LOWER(?)) > 0)
        ORDER BY CASE WHEN LOWER(g.GUARDNAME) = LOWER(?) OR LOWER(g.GUARDCODE) = LOWER(?) THEN 0 ELSE 1 END,
                 g.GUARDNAME,
                 g.GUARDID
        LIMIT 6
     ), latest AS (
       SELECT r.GUARDID AS entityId,
              r.LONGITUDE AS longitude,
              r.LATITUDE AS latitude,
              r.HAPPENTIME AS observedAt,
              ROW_NUMBER() OVER (PARTITION BY r.GUARDID ORDER BY r.HAPPENTIME DESC, r.ID DESC) AS rn
         FROM realdatas r
         JOIN depts d ON d.DEPTID = r.DEPTID
         JOIN candidates c ON c.entityId = r.GUARDID
        WHERE d.COMPANYID = ?
     )
     SELECT 'guard' AS entityType,
            c.entityId,
            c.entityName,
            c.entityCode,
            l.longitude,
            l.latitude,
            l.observedAt,
            'patrol-observation' AS source
       FROM candidates c
  LEFT JOIN latest l ON l.entityId = c.entityId AND l.rn = 1`,
    [companyId, search, search, search, search, companyId]
  );
}

async function searchDeviceLocations(companyId, search) {
  return nexusQuery(
    `WITH candidates AS (
       SELECT r.READERID AS entityId,
              COALESCE(NULLIF(r.NAME, ''), r.READERCODE) AS entityName,
              r.READERCODE AS entityCode
         FROM readers r
        WHERE r.COMPANYID = ?
          AND r.DELETED = 0
          AND (INSTR(LOWER(COALESCE(r.NAME, '')), LOWER(?)) > 0 OR INSTR(LOWER(r.READERCODE), LOWER(?)) > 0)
        ORDER BY CASE WHEN LOWER(COALESCE(r.NAME, '')) = LOWER(?) OR LOWER(r.READERCODE) = LOWER(?) THEN 0 ELSE 1 END,
                 entityName,
                 r.READERID
        LIMIT 6
     ), latest AS (
       SELECT c.entityId,
              rd.LONGITUDE AS longitude,
              rd.LATITUDE AS latitude,
              rd.HAPPENTIME AS observedAt,
              ROW_NUMBER() OVER (PARTITION BY c.entityId ORDER BY rd.HAPPENTIME DESC, rd.ID DESC) AS rn
         FROM candidates c
         JOIN realdatas rd ON rd.READERCODE = c.entityCode
         JOIN depts d ON d.DEPTID = rd.DEPTID
        WHERE d.COMPANYID = ?
     )
     SELECT 'device' AS entityType,
            c.entityId,
            c.entityName,
            c.entityCode,
            l.longitude,
            l.latitude,
            l.observedAt,
            'device-patrol-observation' AS source
       FROM candidates c
  LEFT JOIN latest l ON l.entityId = c.entityId AND l.rn = 1`,
    [companyId, search, search, search, search, companyId]
  );
}

async function searchSiteLocations(companyId, search) {
  return nexusQuery(
    `WITH candidates AS (
       SELECT s.SITEID AS entityId,
              s.SITENAME AS entityName,
              s.SITECODE AS entityCode,
              s.LONGITUDE AS configuredLongitude,
              s.LATITUDE AS configuredLatitude
         FROM sites s
         JOIN depts d ON d.DEPTID = s.DEPTID
        WHERE d.COMPANYID = ?
          AND (INSTR(LOWER(s.SITENAME), LOWER(?)) > 0 OR INSTR(LOWER(s.SITECODE), LOWER(?)) > 0)
        ORDER BY CASE WHEN LOWER(s.SITENAME) = LOWER(?) OR LOWER(s.SITECODE) = LOWER(?) THEN 0 ELSE 1 END,
                 s.SITENAME,
                 s.SITEID
        LIMIT 6
     ), latest AS (
       SELECT r.SITEID AS entityId,
              r.LONGITUDE AS longitude,
              r.LATITUDE AS latitude,
              r.HAPPENTIME AS observedAt,
              ROW_NUMBER() OVER (PARTITION BY r.SITEID ORDER BY r.HAPPENTIME DESC, r.ID DESC) AS rn
         FROM realdatas r
         JOIN depts d ON d.DEPTID = r.DEPTID
         JOIN candidates c ON c.entityId = r.SITEID
        WHERE d.COMPANYID = ?
     )
     SELECT 'site' AS entityType,
            c.entityId,
            c.entityName,
            c.entityCode,
            COALESCE(l.longitude, c.configuredLongitude) AS longitude,
            COALESCE(l.latitude, c.configuredLatitude) AS latitude,
            l.observedAt,
            CASE WHEN l.entityId IS NULL THEN 'site-configuration' ELSE 'patrol-observation' END AS source
       FROM candidates c
  LEFT JOIN latest l ON l.entityId = c.entityId AND l.rn = 1`,
    [companyId, search, search, search, search, companyId]
  );
}

function normalizeAssistantLocation(row) {
  const entityType = assistantEntityType(row?.entityType);
  const entityId = normalizeCompanyId(row?.entityId);
  const name = String(row?.entityName || '').replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120);
  if (entityType === 'any' || !entityId || !name) return null;
  let latitude = row.latitude === null || row.latitude === undefined ? null : Number(row.latitude);
  let longitude = row.longitude === null || row.longitude === undefined ? null : Number(row.longitude);
  if (!Number.isFinite(latitude) || latitude < -90 || latitude > 90) latitude = null;
  if (!Number.isFinite(longitude) || longitude < -180 || longitude > 180) longitude = null;
  if (latitude === 0 && longitude === 0) {
    latitude = null;
    longitude = null;
  }
  if (latitude === null || longitude === null) {
    latitude = null;
    longitude = null;
  }
  const observedDate = row.observedAt ? new Date(row.observedAt) : null;
  const observedAt = observedDate && Number.isFinite(observedDate.getTime()) ? observedDate.toISOString() : null;
  return {
    entityType,
    entityId: String(entityId),
    name,
    latitude,
    longitude,
    source: String(row.source || 'unknown').slice(0, 80),
    observedAt,
  };
}

function numericFields(row, fields) {
  return Object.fromEntries(fields.map((field) => [field, Math.max(0, Number(row?.[field] || 0))]));
}

async function countFilesWithSuffix(root, suffix, limit) {
  let count = 0;
  const pending = [root];
  while (pending.length && count < limit) {
    const directory = pending.pop();
    const entries = await fs.promises.readdir(directory, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.isDirectory()) pending.push(path.join(directory, entry.name));
      else if (entry.isFile() && entry.name.endsWith(suffix)) count += 1;
      if (count >= limit) break;
    }
  }
  return count;
}

function optionalCompanyId(value) {
  const text = String(value || '').trim();
  if (!text) return null;
  const parsed = parsePositiveInt(text, 0);
  return parsed || null;
}

function todayString() {
  const now = new Date();
  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

function validateDateParam(dateValue) {
  const date = dateValue || todayString();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
    const err = new Error('Invalid date format. Expected YYYY-MM-DD.');
    err.status = 400;
    throw err;
  }
  return date;
}

function nexusDateTime(value, fallback) {
  const text = String(value || fallback || '').trim();
  const match = text.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})$/);
  if (!match) {
    const err = new Error('Invalid date-time format. Expected YYYY-MM-DD HH:mm:ss.');
    err.status = 400;
    throw err;
  }
  const parts = match.slice(1).map(Number);
  const date = new Date(Date.UTC(parts[0], parts[1] - 1, parts[2], parts[3], parts[4], parts[5]));
  if (
    date.getUTCFullYear() !== parts[0]
    || date.getUTCMonth() + 1 !== parts[1]
    || date.getUTCDate() !== parts[2]
    || date.getUTCHours() !== parts[3]
    || date.getUTCMinutes() !== parts[4]
    || date.getUTCSeconds() !== parts[5]
  ) {
    const err = new Error('Invalid date-time value.');
    err.status = 400;
    throw err;
  }
  return text.replace('T', ' ');
}

function dateRange(date) {
  return [`${date} 00:00:00`, `${date} 23:59:59`];
}

function currentMonthYear() {
  const now = new Date();
  return { month: now.getMonth() + 1, year: now.getFullYear() };
}

function formatUptime(totalSeconds) {
  const seconds = Math.max(0, Math.floor(Number(totalSeconds) || 0));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h ${minutes}m`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function memoryMb(value) {
  return `${Math.round(Number(value || 0) / 1024 / 1024)}MB`;
}

function monthDateRange(month, year) {
  const safeMonth = Math.max(1, Math.min(12, Number(month) || 1));
  const safeYear = Math.max(2000, Number(year) || new Date().getFullYear());
  const monthStart = new Date(safeYear, safeMonth - 1, 1);
  const monthEnd = new Date(safeYear, safeMonth, 0);
  const formatDate = (value) => `${value.getFullYear()}-${String(value.getMonth() + 1).padStart(2, '0')}-${String(value.getDate()).padStart(2, '0')}`;
  return {
    start: `${formatDate(monthStart)} 00:00:00`,
    end: `${formatDate(monthEnd)} 23:59:59`,
    daysInMonth: monthEnd.getDate(),
  };
}

function gradeFromCompliance(rate) {
  const numericRate = Number(rate || 0);
  if (numericRate >= 90) return 'A';
  if (numericRate >= 80) return 'B';
  if (numericRate >= 70) return 'C';
  if (numericRate >= 60) return 'D';
  return 'F';
}

function companyWhere(companyId, alias) {
  if (!companyId) return { clause: '', params: [] };
  const column = alias ? `${alias}.COMPANYID` : 'COMPANYID';
  return { clause: ` AND ${column} = ?`, params: [companyId] };
}

function poolHealthSnapshot() {
  const rawPool = pool.pool || {};
  const all = rawPool._allConnections?.length || 0;
  const idle = rawPool._freeConnections?.length || 0;
  const waiting = rawPool._connectionQueue?.length || 0;
  return {
    config: POOL_CONFIG,
    activeConnections: Math.max(0, all - idle),
    idleConnections: idle,
    totalConnections: all,
    waitingRequests: waiting,
    counters: { ...poolStats },
  };
}

function isRetryableDbError(err) {
  return RETRYABLE_DB_ERRORS.has(err && err.code);
}

async function executeQueryOnce(sql, params = []) {
  let connection;
  let timedOut = false;
  const started = Date.now();
  const timeout = setTimeout(() => {
    timedOut = true;
    poolStats.timedOut += 1;
    console.error(`[Enormity] MySQL query timed out after ${QUERY_TIMEOUT_MS}ms: ${String(sql).slice(0, 220)}`);
    if (connection && typeof connection.destroy === 'function') {
      connection.destroy();
    }
  }, QUERY_TIMEOUT_MS);
  try {
    connection = await pool.getConnection();
    const [rows] = await connection.execute({ sql, timeout: QUERY_TIMEOUT_MS }, params);
    return rows;
  } catch (err) {
    if (timedOut || /timeout/i.test(err.message || '')) {
      err.code = 'QUERY_TIMEOUT';
      err.status = 503;
      err.message = `Database query exceeded ${QUERY_TIMEOUT_MS}ms timeout`;
    }
    throw err;
  } finally {
    clearTimeout(timeout);
    if (connection && !timedOut) {
      try { connection.release(); } catch (_) {}
    }
    const duration = Date.now() - started;
    if (duration > 1000) {
      console.warn(`[Enormity] Slow MySQL query ${duration}ms: ${String(sql).slice(0, 220)}`);
    }
  }
}

async function query(sql, params = []) {
  try {
    return await executeQueryOnce(sql, params);
  } catch (err) {
    if (!isRetryableDbError(err)) throw err;
    console.warn(`[Enormity] MySQL transient connection error ${err.code}; retrying once.`);
    return executeQueryOnce(sql, params);
  }
}

async function nexusQuery(sql, params = []) {
  requireNexusDbIdentity('query');
  let connection;
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    if (connection && typeof connection.destroy === 'function') connection.destroy();
  }, QUERY_TIMEOUT_MS);
  try {
    connection = await nexusQueryPool.getConnection();
    const [rows] = await connection.execute({ sql, timeout: QUERY_TIMEOUT_MS }, params);
    return rows;
  } catch (error) {
    if (timedOut || /timeout/i.test(error.message || '')) {
      error.code = 'QUERY_TIMEOUT';
      error.status = 503;
      error.message = `Nexus query exceeded ${QUERY_TIMEOUT_MS}ms timeout`;
    }
    throw error;
  } finally {
    clearTimeout(timeout);
    if (connection && !timedOut) {
      try { connection.release(); } catch (_) {}
    }
  }
}

function firstResultSet(rows) {
  return Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
}

async function ensureRedis() {
  if (redisReady) return true;
  try {
    await redis.connect();
    redisReady = true;
    return true;
  } catch (err) {
    redisReady = false;
    return false;
  }
}

async function getCachedJson(key) {
  if (!await ensureRedis()) return null;
  try {
    const value = await redis.get(key);
    if (!value) {
      cacheCounters.misses += 1;
      return null;
    }
    cacheCounters.hits += 1;
    return JSON.parse(value);
  } catch (_) {
    cacheCounters.misses += 1;
    return null;
  }
}

async function setCachedJson(key, ttlSeconds, value) {
  if (!await ensureRedis()) return;
  try {
    await redis.set(key, JSON.stringify(value), 'EX', ttlSeconds);
  } catch (_) {}
}

async function sendCached(res, key, ttlSeconds, producer) {
  const cached = await getCachedJson(key);
  if (cached) {
    res.setHeader('X-Cache', 'HIT');
    return ok(res, cached);
  }
  const data = await producer();
  res.setHeader('X-Cache', redisReady ? 'MISS' : 'BYPASS');
  await setCachedJson(key, ttlSeconds, data);
  return ok(res, data);
}

async function checkDatabase() {
  const rows = await query('SELECT 1 AS ok');
  return rows[0] && rows[0].ok === 1;
}

async function getDatabaseHealth() {
  const start = Date.now();
  const connected = await checkDatabase();
  return { connected, latencyMs: Date.now() - start };
}

async function getRedisHealth() {
  const start = Date.now();
  const connected = await ensureRedis();
  if (!connected) {
    return { connected: false, latencyMs: null };
  }
  try {
    await redis.ping();
    return { connected: true, latencyMs: Date.now() - start };
  } catch (_) {
    redisReady = false;
    return { connected: false, latencyMs: null };
  }
}

async function getPatrolStats(date) {
  const [start, end] = dateRange(date);
  const rows = await query(
    `SELECT
        (SELECT COUNT(*) FROM historydatas) AS totalRecords,
        SUM(CASE WHEN HAPPENTIME BETWEEN ? AND ? THEN 1 ELSE 0 END) AS todayRecords,
        COUNT(DISTINCT CASE WHEN HAPPENTIME BETWEEN ? AND ? THEN GUARDID END) AS activeGuards
       FROM historydatas`,
    [start, end, start, end]
  );
  return {
    totalRecords: Number(rows[0]?.totalRecords || 0),
    todayRecords: Number(rows[0]?.todayRecords || 0),
    activeGuards: Number(rows[0]?.activeGuards || 0),
  };
}

async function getCachedPatrolStats(date) {
  const now = Date.now();
  if (patrolStatsCache.key === date && patrolStatsCache.data && now - patrolStatsCache.timestamp < PATROL_STATS_TTL_MS) {
    return { ...patrolStatsCache.data, cached: true, cacheAgeSeconds: Math.round((now - patrolStatsCache.timestamp) / 1000) };
  }
  const data = await getPatrolStats(date);
  patrolStatsCache.key = date;
  patrolStatsCache.data = data;
  patrolStatsCache.timestamp = now;
  return { ...data, cached: false, cacheAgeSeconds: 0 };
}

let auditReady = false;

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return String(forwarded).split(',')[0].trim();
  return req.ip || req.socket?.remoteAddress || 'unknown';
}

async function ensureAuditTable() {
  if (auditReady) return;
  try {
    await query(`CREATE TABLE IF NOT EXISTS enormity_audit_log (
      id BIGINT PRIMARY KEY AUTO_INCREMENT,
      event_type VARCHAR(64) NOT NULL,
      company_code VARCHAR(128) NULL,
      user_name VARCHAR(128) NULL,
      ip_address VARCHAR(64) NULL,
      success TINYINT(1) NULL,
      reason VARCHAR(255) NULL,
      endpoint VARCHAR(255) NULL,
      request_params JSON NULL,
      response_code INT NULL,
      response_time_ms INT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);
    const alters = [
      'ADD COLUMN endpoint VARCHAR(255) NULL',
      'ADD COLUMN request_params JSON NULL',
      'ADD COLUMN response_code INT NULL',
      'ADD COLUMN response_time_ms INT NULL',
    ];
    for (const alter of alters) {
      try { await query(`ALTER TABLE enormity_audit_log ${alter}`); } catch (err) { if (!/Duplicate column/i.test(err.message)) throw err; }
    }
  } catch (err) {
    if (!/command denied|CREATE command denied|ALTER command denied/i.test(err.message)) throw err;
  }
  auditReady = true;
}

async function auditRequest(req, res, durationMs) {
  if (!BACKGROUND_WRITES_ENABLED) return;
  if (!req.originalUrl.startsWith('/api/enormity/')) return;
  try {
    await ensureAuditTable();
    const params = JSON.stringify({ query: sanitizeAuditBody(req.query || {}), body: sanitizeAuditBody(req.body || {}) });
    await query(
      `INSERT INTO enormity_audit_log (event_type, user_name, ip_address, success, reason, endpoint, request_params, response_code, response_time_ms, created_at)
       VALUES (?, ?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?, NOW())`,
      [
        req.enormityAuth ? 'sidecar_authenticated_request' : 'sidecar_public_request',
        req.enormityAuth?.subject || null,
        clientIp(req),
        res.statusCode < 400 ? 1 : 0,
        res.statusCode < 400 ? null : 'request_failed',
        req.originalUrl.split('?')[0],
        params,
        res.statusCode,
        Math.round(durationMs)
      ]
    );
  } catch (err) {
    if (!/command denied|INSERT command denied/i.test(err.message)) throw err;
  }
}

let lastAuditCleanupDate = '';
async function cleanupAuditLogs(force = false) {
  const now = new Date();
  const today = now.toISOString().slice(0, 10);
  const due = force || (now.getHours() === 3 && now.getMinutes() === 0);
  if (!due || (!force && lastAuditCleanupDate === today)) return;
  lastAuditCleanupDate = today;
  try {
    const result = await query('DELETE FROM enormity_audit_log WHERE created_at < DATE_SUB(NOW(), INTERVAL 90 DAY)');
    console.log(`[Enormity] audit cleanup completed olderThan=90d affectedRows=${result.affectedRows || 0}`);
  } catch (err) {
    console.error('[Enormity] audit cleanup failed:', err.message);
  }
}

function sanitizeAuditBody(body) {
  if (Array.isArray(body)) return body.slice(0, 50).map(sanitizeAuditBody);
  if (!body || typeof body !== 'object') return typeof body === 'string' ? body.slice(0, 500) : body;
  return Object.fromEntries(Object.entries(body).map(([key, value]) => {
    if (/api.?key|password|token|secret|credential|query|question|latitude|longitude|coordinate|finger|biometric|template|feather/i.test(key)) {
      return [key, '[redacted]'];
    }
    return [key, sanitizeAuditBody(value)];
  }));
}

function authenticateJwt(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return fail(res, 401, 'Missing bearer token.');
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'enormity-sidecar', audience: 'nexus-core' });
    req.enormityAuth = decoded;
    return next();
  } catch (err) {
    return fail(res, 401, 'Invalid or expired bearer token.', err.message);
  }
}

function signAccessToken(subject = 'nexus-portal', scope = 'api:enormity nexus:query nexus:realtime') {
  return jwt.sign({ subject, scope }, JWT_SECRET, {
    expiresIn: '10m',
    issuer: 'enormity-sidecar',
    audience: 'nexus-core',
    jwtid: crypto.randomUUID(),
  });
}

function requireApiKey(req, res) {
  const rawApiKey = String(req.body?.apiKey || '').trim();
  const providedKeys = rawApiKey.split(',').map((item) => item.trim()).filter(Boolean);
  const matchedKey = providedKeys.find((candidate) => VALID_API_KEYS.includes(candidate));
  if (!matchedKey) {
    return fail(res, 401, 'Invalid API key.');
  }
  const subject = String(req.body?.client || 'nexus-portal').trim();
  if (!/^[a-z0-9._:-]{3,80}$/i.test(subject)) return fail(res, 400, 'Invalid service client identifier.');
  const token = signAccessToken(subject);
  return ok(res, { token, tokenType: 'Bearer', expiresIn: 600, expiresInSeconds: 600 });
}

function realtimeTicketDigest(ticket) {
  return crypto.createHash('sha256').update(String(ticket || '')).digest('hex');
}

function cleanupRealtimeTickets(now = Date.now()) {
  for (const [digest, ticket] of realtimeTickets) {
    if (!ticket || ticket.expiresAt <= now) realtimeTickets.delete(digest);
  }
  while (realtimeTickets.size >= REALTIME_TICKET_LIMIT) {
    const oldest = realtimeTickets.keys().next().value;
    if (!oldest) break;
    realtimeTickets.delete(oldest);
  }
}

function issueRealtimeTicket(scope, subject) {
  cleanupRealtimeTickets();
  const ticket = crypto.randomBytes(32).toString('base64url');
  realtimeTickets.set(realtimeTicketDigest(ticket), {
    companyId: scope.companyId,
    global: scope.global,
    subject: String(subject || 'nexus-server').slice(0, 120),
    expiresAt: Date.now() + REALTIME_TICKET_TTL_MS,
  });
  return ticket;
}

function consumeRealtimeTicket(ticket) {
  const normalized = String(ticket || '').trim();
  if (!/^[A-Za-z0-9_-]{40,80}$/.test(normalized)) return null;
  const digest = realtimeTicketDigest(normalized);
  const record = realtimeTickets.get(digest) || null;
  realtimeTickets.delete(digest);
  if (!record || record.expiresAt <= Date.now()) return null;
  return record;
}


app.get('/api/enormity/health', publicLimiter, async (req, res) => {
  try {
    const [databaseHealth, redisHealth] = await Promise.all([
      getDatabaseHealth(),
      getRedisHealth(),
    ]);
    const memoryUsage = process.memoryUsage();
    const uptimeSeconds = Math.floor(process.uptime());
    return ok(res, {
      service: 'enormity-sidecar',
      version: SERVICE_VERSION,
      environment: process.env.NODE_ENV || 'production',
      uptimeSeconds,
      uptimeHuman: formatUptime(uptimeSeconds),
      memory: {
        rss: memoryMb(memoryUsage.rss),
        heapUsed: memoryMb(memoryUsage.heapUsed),
        heapTotal: memoryMb(memoryUsage.heapTotal),
      },
      database: {
        connected: databaseHealth.connected,
        latencyMs: databaseHealth.latencyMs,
        pool: poolHealthSnapshot(),
        nexusIdentities: nexusDbIdentityStatus(),
      },
      redis: {
        connected: redisHealth.connected,
        latencyMs: redisHealth.latencyMs,
      },
      node: process.version,
      timestamp: timestamp(),
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/health', err, 'Database health check failed.');
  }
});

app.get('/api/enormity/health/db', authenticateJwt, protectedLimiter, async (req, res) => {
  try {
    const [[sizeRow], [statusRow], tables, enormityTables, procedures, triggers, views, [activityRow]] = await Promise.all([
      query(`SELECT ROUND(SUM(data_length + index_length) / 1024 / 1024, 2) AS dbSizeMb FROM information_schema.TABLES WHERE table_schema = DATABASE()`),
      query(`SHOW GLOBAL STATUS LIKE 'Uptime'`),
      query(`SELECT 'historydatas' AS tableName, COUNT(*) AS rowCount FROM historydatas
             UNION ALL SELECT 'alarmdatas', COUNT(*) FROM alarmdatas
             UNION ALL SELECT 'guards', COUNT(*) FROM guards
             UNION ALL SELECT 'sites', COUNT(*) FROM sites`),
      query(`SELECT 'enormity_audit_log' AS tableName, COUNT(*) AS rowCount FROM enormity_audit_log
             UNION ALL SELECT 'enormity_escalations', COUNT(*) FROM enormity_escalations
             UNION ALL SELECT 'enormity_guard_streaks', COUNT(*) FROM enormity_guard_streaks`),
      query(`SHOW PROCEDURE STATUS WHERE Db = DATABASE() AND Name LIKE 'sp\\_%'`),
      query(`SHOW TRIGGERS FROM cloudpatrol`),
      query(`SHOW FULL TABLES WHERE Table_type = 'VIEW' AND Tables_in_cloudpatrol LIKE 'v\\_%'`),
      query(`SELECT
               SUM(CASE WHEN HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 1 HOUR) THEN 1 ELSE 0 END) AS scansLastHour,
               SUM(CASE WHEN DATE(HAPPENTIME) = CURDATE() THEN 1 ELSE 0 END) AS scansToday,
               (SELECT COUNT(*) FROM alarmdatas WHERE DATE(HAPPENTIME) = CURDATE()) AS alarmsToday
             FROM historydatas`)
    ]);

    const tableCounts = {};
    tables.forEach((row) => { tableCounts[row.tableName] = Number(row.rowCount || 0); });
    const enormityCounts = {};
    enormityTables.forEach((row) => { enormityCounts[row.tableName] = Number(row.rowCount || 0); });

    const [databaseHealth, redisHealth, patrolStats] = await Promise.all([
      getDatabaseHealth(),
      getRedisHealth(),
      getCachedPatrolStats(todayString()),
    ]);

    return ok(res, {
      database: {
        connected: databaseHealth.connected,
        host: process.env.MYSQL_HOST || '127.0.0.1',
        port: Number(process.env.MYSQL_PORT || 13306),
        database: process.env.MYSQL_DATABASE || 'cloudpatrol',
        latencyMs: databaseHealth.latencyMs,
        pool: poolHealthSnapshot(),
      },
      redis: redisHealth,
      patrolStats,
      tables: tableCounts,
      enormityTables: enormityCounts,
      procedures: procedures.map((row) => row.Name),
      triggers: triggers.map((row) => row.Trigger),
      views: views.map((row) => Object.values(row)[0]),
      recentActivity: {
        scansLastHour: Number(activityRow.scansLastHour || 0),
        scansToday: Number(activityRow.scansToday || 0),
        alarmsToday: Number(activityRow.alarmsToday || 0),
      },
      dbSize: `${Number(sizeRow.dbSizeMb || 0).toFixed(2)} MB`,
      uptime: `${Math.round(Number(statusRow.Value || 0) / 3600)} hours`,
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/health/db', err, 'Failed to build database health report.');
  }
});

app.get('/api/enormity/status/overview', authenticateJwt, protectedLimiter, async (req, res) => {
  const date = todayString();
  const [start, end] = dateRange(date);
  try {
    const [totals, procedures, views, tables] = await Promise.all([
      query(
        `SELECT COUNT(*) AS totalScans,
                COUNT(DISTINCT GUARDID) AS activeGuards,
                COUNT(DISTINCT SITEID) AS activeSites
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?`,
        [start, end]
      ),
      query(`SHOW PROCEDURE STATUS WHERE Db = DATABASE() AND Name LIKE 'sp\\_%'`),
      query(`SHOW FULL TABLES WHERE Table_type = 'VIEW' AND Tables_in_cloudpatrol LIKE 'v\\_%'`),
      query(`SELECT TABLE_NAME AS tableName, TABLE_ROWS AS rowCount
               FROM information_schema.TABLES
              WHERE TABLE_SCHEMA = DATABASE()
                AND TABLE_NAME LIKE 'enormity\\_%'
              ORDER BY TABLE_NAME`),
    ]);
    return ok(res, {
      date,
      scansToday: Number(totals[0]?.totalScans || 0),
      activeGuards: Number(totals[0]?.activeGuards || 0),
      activeSites: Number(totals[0]?.activeSites || 0),
      procedures: procedures.map((row) => row.Name),
      views: views.map((row) => Object.values(row)[0]),
      tables: tables.map((row) => row.tableName),
      tableRows: tables.map((row) => ({
        tableName: row.tableName,
        rowCount: Number(row.rowCount || 0),
      })),
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/status/overview', err, 'Failed to build status overview.');
  }
});

app.get('/api/enormity/status/containers', authenticateJwt, protectedLimiter, async (req, res) => {
  try {
    const inventoryPath = String(process.env.CONTAINER_STATUS_FILE || '/run/enormity/container-status.tsv');
    const output = await fs.promises.readFile(inventoryPath, 'utf8');
    const rows = output.trim().split('\n').filter(Boolean).slice(0, 500).map((line) => {
      const parts = line.split('\t');
      return { name: parts[0] || '', status: parts[1] || '', ports: parts[2] || '' };
    });
    return ok(res, { rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/status/containers', err, 'Failed to read docker container status.');
  }
});

app.post('/api/enormity/auth/token', authLimiter, requireApiKey);
app.post('/api/enormity/auth/refresh', authLimiter, authenticateJwt, (req, res) => {
  const current = req.enormityAuth || {};
  const token = signAccessToken(current.subject || 'nexus-portal', current.scope || 'api:enormity nexus:query nexus:realtime');
  return ok(res, { token, tokenType: 'Bearer', expiresIn: 600, expiresInSeconds: 600 });
});

app.get('/api/enormity/docs.json', authenticateJwt, protectedLimiter, (req, res) => {
  const specPath = path.join(__dirname, 'openapi.yaml');
  if (!fs.existsSync(specPath)) return fail(res, 404, 'OpenAPI specification has not been generated yet.');
  return ok(res, { format: 'yaml', content: fs.readFileSync(specPath, 'utf8') });
});

app.get('/api/enormity/docs', authenticateJwt, protectedLimiter, (req, res) => {
  const specPath = path.join(__dirname, 'openapi.yaml');
  if (!fs.existsSync(specPath)) return fail(res, 404, 'OpenAPI specification has not been generated yet.');
  res.type('text/yaml');
  return res.send(fs.readFileSync(specPath, 'utf8'));
});

app.get('/api/enormity/company/list', authenticateJwt, protectedLimiter, async (req, res) => {
  try {
    const rows = await query(
      `SELECT COMPANYID AS id,
              COMPANYNAME AS companyName,
              COMPANYCODE AS companyCode
        FROM companys
        WHERE (IFNULL(IS_Effective, 0) <> 0 OR ENDDATE >= NOW())
        ORDER BY COMPANYNAME ASC`
    );
    return ok(res, rows);
  } catch (err) {
    return handleRouteError(res, '/api/enormity/company/list', err, 'Failed to fetch company list.');
  }
});

app.get('/api/enormity/version', authenticateJwt, protectedLimiter, async (req, res) => {
  try {
    const routeCount = app._router.stack.filter((layer) => layer.route).length;
    const [procedures] = await query(`SELECT COUNT(*) AS totalStoredProcedures FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE()`);
    const totalJavaClasses = await countFilesWithSuffix(
      '/opt/CloudPatrol/appFile/web/ROOT/WEB-INF/classes/com/tour',
      '.class',
      100000
    ).catch(() => 0);
    return ok(res, {
      version: SERVICE_VERSION,
      buildDate: SERVICE_BUILD_DATE,
      totalEndpoints: routeCount,
      totalJavaClasses,
      totalStoredProcedures: Number(procedures.totalStoredProcedures || 0),
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/version', err, 'Failed to build version payload.');
  }
});

app.use('/api/enormity', authenticateJwt, protectedLimiter);
app.use('/api/enormity', (req, res, next) => {
  if (BACKGROUND_WRITES_ENABLED || req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const pathOnly = String(req.originalUrl || '').split('?')[0];
  if (req.method === 'POST' && READ_ONLY_POST_PATHS.has(pathOnly)) return next();
  return fail(res, 503, 'This sidecar release is read-only; no mutation was attempted.', null, 'E_WRITES_DISABLED');
});

// Nexus-only live-data boundary. The browser never calls these endpoints
// directly. Nexus resolves the company code stored in its server-side session,
// then sends only the resulting numeric companyId on subsequent requests.
app.get('/api/enormity/nexus/tenant-scope', async (req, res) => {
  try {
    const companyCode = String(req.query.companyCode || '').trim();
    if (!companyCode || companyCode.length > 100 || /[\u0000-\u001f\u007f]/.test(companyCode)) {
      return fail(res, 400, 'A valid companyCode is required.');
    }
    const rows = await query(
      `SELECT COMPANYID AS companyId
         FROM companys
        WHERE LOWER(COMPANYCODE) = LOWER(?)
        ORDER BY COMPANYID
        LIMIT 2`,
      [companyCode]
    );
    if (rows.length !== 1) {
      return fail(res, rows.length ? 409 : 404, rows.length ? 'Company code is not unique.' : 'Company scope was not found.');
    }
    return ok(res, { companyId: Number(rows[0].companyId) });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/nexus/tenant-scope', err, 'Failed to resolve Nexus tenant scope.');
  }
});

app.get('/api/enormity/nexus/dashboard', async (req, res) => {
  try {
    const scope = normalizeRealtimeScope(req.query);
    const companyId = scope.companyId;
    const companyFor = (column) => scope.global ? { clause: '', params: [] } : { clause: ` AND ${column} = ?`, params: [companyId] };
    const deptScope = companyFor('d.COMPANYID');
    const historyScope = companyFor('COMPANYID');
    const readerScope = companyFor('COMPANYID');
    const logScope = companyFor('COMPANYID');
    const alarmScope = companyFor('COMPANYID');
    const noticeScope = companyFor('companyid');

    const [overviewRows, activityRows, deviceRows, logRows, alarmTotalRows, alarmRows, noticeTotalRows, noticeRows] = await Promise.all([
      query(
        `SELECT
           (SELECT COUNT(*) FROM sites s JOIN depts d ON d.DEPTID = s.DEPTID WHERE 1=1${deptScope.clause}) AS siteTotal,
           (SELECT COUNT(*) FROM guards g JOIN depts d ON d.DEPTID = g.DEPTID WHERE 1=1${deptScope.clause}) AS guardTotal,
           (SELECT COUNT(*) FROM plans p JOIN depts d ON d.DEPTID = p.DEPTID WHERE 1=1${deptScope.clause}) AS planTotal,
           (SELECT COUNT(*) FROM plans p JOIN depts d ON d.DEPTID = p.DEPTID WHERE p.ENDDATE < NOW()${deptScope.clause}) AS planExpired,
           (SELECT COUNT(*) FROM readers WHERE DELETED = 0${readerScope.clause}) AS deviceTotal,
           (SELECT COUNT(*) FROM readers WHERE DELETED = 0 AND LASTTIME >= DATE_SUB(NOW(), INTERVAL 120 MINUTE)${readerScope.clause}) AS deviceOnline,
           (SELECT COUNT(*) FROM depts d WHERE 1=1${deptScope.clause}) AS departmentTotal`,
        [...deptScope.params, ...deptScope.params, ...deptScope.params, ...deptScope.params, ...readerScope.params, ...readerScope.params, ...deptScope.params]
      ),
      query(
        `SELECT COUNT(DISTINCT SITEID) AS sitesUsed,
                COUNT(DISTINCT GUARDID) AS guardsUsed,
                COUNT(*) AS scans30Days,
                MAX(HAPPENTIME) AS lastScan
           FROM historydatas
          WHERE HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 30 DAY)${historyScope.clause}`,
        historyScope.params
      ),
      query(
        `SELECT READERID AS id,
                READERCODE AS readerCode,
                NAME AS name,
                COMPANYID AS companyId,
                LASTTIME AS lastTime,
                ENDDATE AS licenceExpiry,
                CASE WHEN LASTTIME >= DATE_SUB(NOW(), INTERVAL 120 MINUTE) THEN 'ONLINE' ELSE 'OFFLINE' END AS status
           FROM readers
          WHERE DELETED = 0${readerScope.clause}
          ORDER BY LASTTIME DESC, READERID DESC
          LIMIT 1000`,
        readerScope.params
      ),
      query(
        `SELECT LOGID AS logid,
                OPERATEFORM AS operateform,
                LOGCONTENT AS logcontent,
                OPERATERANK AS operaterank,
                OPERATETIME AS operatetime,
                USERNAME AS username,
                READERCODE AS readercode,
                IPADDRESS AS ipaddress,
                COMPANYID AS companyId
           FROM logs
          WHERE DELETED = 0${logScope.clause}
          ORDER BY OPERATETIME DESC, LOGID DESC
          LIMIT 10`,
        logScope.params
      ),
      query(
        `SELECT COUNT(*) AS total
           FROM alarmdatas
          WHERE HAPPENTIME >= CURDATE()
            AND HAPPENTIME < DATE_ADD(CURDATE(), INTERVAL 1 DAY)${alarmScope.clause}`,
        alarmScope.params
      ),
      query(
        `SELECT ID AS id,
                COMPANYID AS companyId,
                ALARMTYPE AS alarmtype,
                ALARMINFO AS alarminfo,
                DEPTNAME AS deptname,
                SITENAME AS sitename,
                GUARDNAME AS guardname,
                READERCODE AS readercode,
                HAPPENTIME AS happentime,
                LONGITUDE AS longitude,
                LATITUDE AS latitude
           FROM alarmdatas
          WHERE HAPPENTIME >= CURDATE()
            AND HAPPENTIME < DATE_ADD(CURDATE(), INTERVAL 1 DAY)${alarmScope.clause}
          ORDER BY HAPPENTIME DESC, ID DESC
          LIMIT 200`,
        alarmScope.params
      ),
      query(`SELECT COUNT(*) AS total FROM notices WHERE 1=1${noticeScope.clause}`, noticeScope.params),
      query(
        `SELECT id,
                title,
                content,
                sendstatus,
                sendtime,
                createtime,
                companyid AS companyId
           FROM notices
          WHERE 1=1${noticeScope.clause}
          ORDER BY createtime DESC, id DESC
          LIMIT 20`,
        noticeScope.params
      ),
    ]);

    const overview = overviewRows[0] || {};
    const activity = activityRows[0] || {};
    const sitesUsed = Number(activity.sitesUsed || 0);
    const guardsUsed = Number(activity.guardsUsed || 0);
    const siteTotal = Number(overview.siteTotal || 0);
    const guardTotal = Number(overview.guardTotal || 0);
    const deviceTotal = Number(overview.deviceTotal || 0);
    const deviceOnline = Number(overview.deviceOnline || 0);
    return ok(res, {
      scope: { kind: scope.global ? 'global' : 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'enormity-sidecar', realtime: 'authenticated-websocket' },
      generatedAt: timestamp(),
      overview: {
        site: { total: siteTotal, used: sitesUsed, unused: Math.max(0, siteTotal - sitesUsed) },
        guard: { total: guardTotal, used: guardsUsed, unused: Math.max(0, guardTotal - guardsUsed) },
        plan: { total: Number(overview.planTotal || 0), expired: Number(overview.planExpired || 0) },
        device: { total: deviceTotal, used: deviceOnline, unused: Math.max(0, deviceTotal - deviceOnline) },
      },
      summaries: {
        departments: Number(overview.departmentTotal || 0),
        guards: guardTotal,
        devices: deviceTotal,
        devicesOnline: deviceOnline,
        devicesOffline: Math.max(0, deviceTotal - deviceOnline),
        scans30Days: Number(activity.scans30Days || 0),
        lastScan: activity.lastScan || null,
      },
      logs: { total: logRows.length, rows: logRows },
      alarms: { total: Number(alarmTotalRows[0]?.total || 0), rows: alarmRows },
      notices: { total: Number(noticeTotalRows[0]?.total || 0), rows: noticeRows },
      devices: { total: deviceTotal, rows: deviceRows },
    });
  } catch (err) {
    const status = /companyId|company scope|either global/i.test(err.message || '') ? 400 : 500;
    if (status === 400) return fail(res, status, err.message);
    return handleRouteError(res, '/api/enormity/nexus/dashboard', err, 'Failed to load direct Nexus dashboard data.');
  }
});

app.get('/api/enormity/nexus/logs', async (req, res) => {
  try {
    const scope = normalizeRealtimeScope(req.query);
    const companyId = scope.companyId;
    const current = parsePositiveInt(req.query.current, 1, 10000);
    const pageSize = parsePositiveInt(req.query.pageSize, 10, 100);
    const beginTime = nexusDateTime(req.query.BeginTime, '1970-01-01 00:00:00');
    const endTime = nexusDateTime(req.query.EndTime, '2999-12-31 23:59:59');
    const where = [`DELETED = 0`, `OPERATETIME BETWEEN ? AND ?`];
    const params = [beginTime, endTime];
    if (!scope.global) {
      where.push('COMPANYID = ?');
      params.push(companyId);
    }
    const offset = (current - 1) * pageSize;
    const [totalRows, rows] = await Promise.all([
      query(`SELECT COUNT(*) AS total FROM logs WHERE ${where.join(' AND ')}`, params),
      query(
        `SELECT LOGID AS logid,
                OPERATEFORM AS operateform,
                LOGCONTENT AS logcontent,
                OPERATERANK AS operaterank,
                OPERATETIME AS operatetime,
                USERNAME AS username,
                READERCODE AS readercode,
                IPADDRESS AS ipaddress,
                COMPANYID AS companyId
           FROM logs
          WHERE ${where.join(' AND ')}
          ORDER BY OPERATETIME DESC, LOGID DESC
          LIMIT ${pageSize} OFFSET ${offset}`,
        params
      ),
    ]);
    return ok(res, {
      scope: { kind: scope.global ? 'global' : 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'enormity-sidecar' },
      generatedAt: timestamp(),
      total: Number(totalRows[0]?.total || 0),
      rows,
    });
  } catch (err) {
    const status = /companyId|company scope|either global|date-time/i.test(err.message || '') ? 400 : 500;
    if (status === 400) return fail(res, status, err.message);
    return handleRouteError(res, '/api/enormity/nexus/logs', err, 'Failed to load direct Nexus logs.');
  }
});

app.get('/api/enormity/nexus/departments', async (req, res) => {
  try {
    const scope = normalizeRealtimeScope(req.query);
    const companyId = scope.companyId;
    const companyClause = scope.global ? '' : ' AND d.COMPANYID = ?';
    const rows = await query(
      `SELECT d.DEPTID AS id,
              d.DEPTNAME AS label,
              d.PARENTDEPTID AS parentId,
              d.DEPTCODE AS code,
              d.DEPTSN AS sortOrder,
              d.COMPANYID AS companyId
         FROM depts d
        WHERE IFNULL(d.VALID, 1) <> 0${companyClause}
        ORDER BY d.DEPTSN, d.DEPTID`,
      scope.global ? [] : [companyId]
    );
    return ok(res, {
      scope: { kind: scope.global ? 'global' : 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'enormity-sidecar' },
      generatedAt: timestamp(),
      total: rows.length,
      rows,
    });
  } catch (err) {
    const status = /companyId|company scope|either global/i.test(err.message || '') ? 400 : 500;
    if (status === 400) return fail(res, status, err.message);
    return handleRouteError(res, '/api/enormity/nexus/departments', err, 'Failed to load direct Nexus departments.');
  }
});

app.get('/api/enormity/nexus/guards', async (req, res) => {
  try {
    const scope = normalizeRealtimeScope(req.query);
    const companyId = scope.companyId;
    const rawDeptId = String(req.query.deptId || '').trim();
    const rawGuardId = String(req.query.guardId || '').trim();
    const deptId = rawDeptId ? normalizeCompanyId(rawDeptId) : null;
    const guardId = rawGuardId ? normalizeCompanyId(rawGuardId) : null;
    if ((rawDeptId && !deptId) || (rawGuardId && !guardId)) return fail(res, 400, 'deptId and guardId must be positive integers.');

    const conditions = ['1=1'];
    const params = [];
    if (!scope.global) {
      conditions.push('d.COMPANYID = ?');
      params.push(companyId);
    }
    if (deptId) {
      conditions.push('g.DEPTID = ?');
      params.push(deptId);
    }
    if (guardId) {
      conditions.push('g.GUARDID = ?');
      params.push(guardId);
    }

    const rows = await query(
      `SELECT g.GUARDID AS id,
              g.GUARDCODE AS code,
              g.GUARDNAME AS name,
              g.DEPTID AS departmentId,
              d.DEPTNAME AS department,
              g.TELEPHONE AS phone,
              g.guardtype AS guardType,
              d.COMPANYID AS companyId,
              COUNT(DISTINCT fi.ID) AS fingerprintCount
         FROM guards g
         JOIN depts d ON d.DEPTID = g.DEPTID
    LEFT JOIN fingerinfo fi ON fi.GUARDID = g.GUARDID AND fi.COMPANYID = d.COMPANYID
        WHERE ${conditions.join(' AND ')}
        GROUP BY g.GUARDID, g.GUARDCODE, g.GUARDNAME, g.DEPTID, d.DEPTNAME, g.TELEPHONE, g.guardtype, d.COMPANYID
        ORDER BY d.DEPTSN, g.GUARDNAME, g.GUARDID
        LIMIT 2000`,
      params
    );

    let activity = [];
    if (guardId && rows.length === 1) {
      const activityConditions = ['h.GUARDID = ?', 'h.HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 7 DAY)'];
      const activityParams = [guardId];
      if (!scope.global) {
        activityConditions.push('h.COMPANYID = ?');
        activityParams.push(companyId);
      }
      activity = await query(
        `SELECT h.ID AS id,
                h.COMPANYID AS companyId,
                h.SITENAME AS site,
                h.EVENTINFO AS event,
                h.HAPPENTIME AS timestamp,
                h.READERCODE AS readerCode,
                h.STATUS AS status
           FROM historydatas h
          WHERE ${activityConditions.join(' AND ')}
          ORDER BY h.HAPPENTIME DESC, h.ID DESC
          LIMIT 8`,
        activityParams
      );
    }

    return ok(res, {
      scope: { kind: scope.global ? 'global' : 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'enormity-sidecar' },
      generatedAt: timestamp(),
      total: rows.length,
      rows,
      activity,
    });
  } catch (err) {
    const status = /companyId|company scope|either global/i.test(err.message || '') ? 400 : 500;
    if (status === 400) return fail(res, status, err.message);
    return handleRouteError(res, '/api/enormity/nexus/guards', err, 'Failed to load direct Nexus guards.');
  }
});

app.get('/api/enormity/nexus/alerts/unacknowledged', async (req, res) => {
  try {
    const scope = normalizeRealtimeScope(req.query);
    const companyId = scope.companyId;
    const rows = await query(
      `SELECT COUNT(*) AS total
         FROM enormity_escalations
        WHERE requiresAck = 1${scope.global ? '' : ' AND companyid = ?'}`,
      scope.global ? [] : [companyId]
    );
    return ok(res, {
      scope: { kind: scope.global ? 'global' : 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'enormity-sidecar' },
      generatedAt: timestamp(),
      total: Number(rows[0]?.total || 0),
    });
  } catch (err) {
    const status = /companyId|company scope|either global/i.test(err.message || '') ? 400 : 500;
    if (status === 400) return fail(res, status, err.message);
    return handleRouteError(res, '/api/enormity/nexus/alerts/unacknowledged', err, 'Failed to count direct Nexus alerts.');
  }
});

app.get('/api/enormity/nexus/live-map', async (req, res) => {
  try {
    const scope = normalizeRealtimeScope(req.query);
    const companyId = scope.companyId;
    const condition = (column) => scope.global ? { clause: '', params: [] } : { clause: ` AND ${column} = ?`, params: [companyId] };
    const deptScope = condition('d.COMPANYID');
    const alarmScope = condition('a.COMPANYID');
    const mapScope = condition('m.COMPANYID');
    const enclosureScope = condition('e.COMPANYID');
    const [realData, alarmData, mapData, enclosureDevices, enclosures] = await Promise.all([
      query(
        `WITH ranked AS (
           SELECT r.ID AS id,
                  r.DEPTID AS deptId,
                  r.DEPTNAME AS deptName,
                  r.GUARDID AS guardId,
                  r.GUARDNAME AS guardName,
                  r.SITEID AS siteId,
                  r.SITENAME AS siteName,
                  r.READERCODE AS readerCode,
                  r.EVENTINFO AS eventInfo,
                  r.HAPPENTIME AS operateTime,
                  r.LONGITUDE AS longitude,
                  r.LATITUDE AS latitude,
                  d.COMPANYID AS companyId,
                  ROW_NUMBER() OVER (PARTITION BY r.READERCODE ORDER BY r.HAPPENTIME DESC, r.ID DESC) AS rn
             FROM realdatas r
             JOIN depts d ON d.DEPTID = r.DEPTID
            WHERE 1=1${deptScope.clause}
         )
         SELECT * FROM ranked WHERE rn = 1 ORDER BY operateTime DESC, id DESC LIMIT 250`,
        deptScope.params
      ),
      query(
        `SELECT a.ID AS id,
                a.COMPANYID AS companyId,
                a.DEPTID AS deptId,
                a.DEPTNAME AS deptName,
                a.GUARDID AS guardId,
                a.GUARDNAME AS guardName,
                a.SITEID AS siteId,
                a.SITENAME AS siteName,
                a.READERCODE AS readerCode,
                a.ALARMTYPE AS alarmType,
                a.ALARMINFO AS alarmInfo,
                a.HAPPENTIME AS operateTime,
                a.LONGITUDE AS longitude,
                a.LATITUDE AS latitude,
                'alarm' AS status
           FROM alarmdatas a
          WHERE a.HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 72 HOUR)${alarmScope.clause}
          ORDER BY a.HAPPENTIME DESC, a.ID DESC
          LIMIT 100`,
        alarmScope.params
      ),
      query(
        `SELECT m.ID AS id,
                m.COMPANYID AS companyId,
                m.DEPTID AS deptId,
                m.SITEID AS siteId,
                m.SITENAME AS siteName,
                m.HAPPENTIME AS operateTime,
                m.LONGITUDE AS longitude,
                m.LATITUDE AS latitude,
                m.ARRIVED AS arrived,
                'site' AS status
           FROM mapdatas m
          WHERE 1=1${mapScope.clause}
          ORDER BY COALESCE(m.HAPPENTIME, m.ENDTIME) DESC, m.ID DESC
          LIMIT 200`,
        mapScope.params
      ),
      query(
        `SELECT eu.ID AS id,
                e.COMPANYID AS companyId,
                eu.DEVICECODE AS readerCode,
                eu.STATE AS state,
                eu.LASTTIME AS operateTime,
                eu.ALARMED AS alarmed,
                eu.LONGITUDE AS longitude,
                eu.LATITUDE AS latitude,
                e.ENCLOSURENAME AS enclosureName
           FROM enclosureuser eu
           JOIN enclosure e ON e.ID = eu.ENCLOUSUREID
          WHERE 1=1${enclosureScope.clause}
          ORDER BY eu.LASTTIME DESC, eu.ID DESC
          LIMIT 500`,
        enclosureScope.params
      ),
      query(
        `SELECT e.ID AS id,
                e.COMPANYID AS companyId,
                e.ENCLOSURENAME AS enclosureName,
                e.ALARMTYPE AS alarmType,
                ep.POINTSTRING AS pointString
           FROM enclosure e
      LEFT JOIN enclosurepoints ep ON ep.enclosureid = e.ID
          WHERE 1=1${enclosureScope.clause}
          ORDER BY e.ID
          LIMIT 500`,
        enclosureScope.params
      ),
    ]);
    return ok(res, {
      scope: { kind: scope.global ? 'global' : 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'enormity-sidecar' },
      generatedAt: timestamp(),
      realData,
      alarmData,
      mapData,
      enclosureDevices,
      enclosures,
    });
  } catch (err) {
    const status = /companyId|company scope|either global/i.test(err.message || '') ? 400 : 500;
    if (status === 400) return fail(res, status, err.message);
    return handleRouteError(res, '/api/enormity/nexus/live-map', err, 'Failed to load direct Nexus map data.');
  }
});

// Nexus Core V2 read contracts are internal-only (the service is loopback
// bound) and require the service JWT installed above. The public browser never
// supplies companyId: the Nexus portal derives it from its authenticated
// server-side session before calling this boundary.
app.post('/api/enormity/nexus/v2/locations/search', async (req, res) => {
  try {
    if (!requireDirectReadMode(res, 'locations')) return;
    const companyId = normalizeCompanyId(req.body?.companyId);
    const search = safeAssistantSearch(req.body?.query);
    const entityType = assistantEntityType(req.body?.entityType);
    if (!companyId) return fail(res, 400, 'A positive server-derived companyId is required.');
    if (!search) return fail(res, 400, 'A location search between 2 and 80 characters is required.');

    const searches = [];
    if (entityType === 'any' || entityType === 'guard') searches.push(searchGuardLocations(companyId, search));
    if (entityType === 'any' || entityType === 'device') searches.push(searchDeviceLocations(companyId, search));
    if (entityType === 'any' || entityType === 'site') searches.push(searchSiteLocations(companyId, search));
    const rows = (await Promise.all(searches)).flat();
    const normalizedSearch = search.toLocaleLowerCase('en');
    const matches = rows
      .map(normalizeAssistantLocation)
      .filter(Boolean)
      .sort((left, right) => {
        const leftExact = left.name.toLocaleLowerCase('en') === normalizedSearch ? 0 : 1;
        const rightExact = right.name.toLocaleLowerCase('en') === normalizedSearch ? 0 : 1;
        if (leftExact !== rightExact) return leftExact - rightExact;
        return Date.parse(right.observedAt || '') - Date.parse(left.observedAt || '') || left.name.localeCompare(right.name);
      });

    setNexusDirectSourceHeaders(res, 'locations');
    return ok(res, {
      scope: { kind: 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'nexus-core-v2' },
      generatedAt: timestamp(),
      ambiguous: matches.length > 1,
      truncated: matches.length > 5,
      totalMatches: Math.min(matches.length, 6),
      matches: matches.slice(0, 5),
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/nexus/v2/locations/search', err, 'Failed to search same-company locations.');
  }
});

app.post('/api/enormity/nexus/v2/assistant/metrics', async (req, res) => {
  try {
    if (!requireDirectReadMode(res, 'assistant_metrics')) return;
    const companyId = normalizeCompanyId(req.body?.companyId);
    if (!companyId) return fail(res, 400, 'A positive server-derived companyId is required.');
    const range = assistantDateRange(req.body || {});
    const requested = Array.isArray(req.body?.tools)
      ? [...new Set(req.body.tools.map((value) => String(value || '').trim()).filter((value) => ASSISTANT_METRIC_TOOLS.has(value)))].slice(0, 2)
      : [];
    if (!requested.length) return fail(res, 400, 'One or two allowlisted metric tools are required.');

    const result = {};
    await Promise.all(requested.map(async (tool) => {
      if (tool === 'attendance_summary') {
        const rows = await nexusQuery(
          `SELECT COUNT(*) AS records,
                  COUNT(DISTINCT guardid) AS guards,
                  SUM(CASE WHEN gotoworkdatetime IS NOT NULL THEN 1 ELSE 0 END) AS clockIns,
                  SUM(CASE WHEN gooffworkdatetime IS NOT NULL THEN 1 ELSE 0 END) AS clockOuts,
                  SUM(CASE WHEN gotoworkdatetime IS NOT NULL AND gooffworkdatetime IS NOT NULL THEN 1 ELSE 0 END) AS completeRecords
             FROM worktimerecords
            WHERE companyid = ?
              AND dataofdate >= ?
              AND dataofdate < DATE_ADD(?, INTERVAL 1 DAY)`,
          [companyId, range.from, range.to]
        );
        const row = rows[0] || {};
        result.attendance = numericFields(row, ['records', 'guards', 'clockIns', 'clockOuts', 'completeRecords']);
      } else if (tool === 'shift_summary') {
        const rows = await nexusQuery(
          `SELECT COUNT(*) AS configuredShifts,
                  COUNT(DISTINCT deptid) AS departments,
                  SUM(CASE WHEN UPPER(category) = 'A' THEN 1 ELSE 0 END) AS earlyShifts,
                  SUM(CASE WHEN UPPER(category) = 'B' THEN 1 ELSE 0 END) AS nightShifts,
                  COALESCE(SUM(guardcount), 0) AS expectedGuards
             FROM worktimeconfig
            WHERE companyid = ?`,
          [companyId]
        );
        result.shifts = numericFields(rows[0] || {}, ['configuredShifts', 'departments', 'earlyShifts', 'nightShifts', 'expectedGuards']);
      } else if (tool === 'patrol_completion_summary' || tool === 'omissions_summary') {
        const rows = await nexusQuery(
          `SELECT COUNT(*) AS patrolRounds,
                  COALESCE(SUM(PLANCOUNT), 0) AS plannedCheckpoints,
                  COALESCE(SUM(ARRIVEDCOUNT), 0) AS arrivedCheckpoints,
                  COALESCE(SUM(OMITCOUNT), 0) AS omittedCheckpoints,
                  SUM(CASE WHEN COALESCE(OMITCOUNT, 0) = 0 THEN 1 ELSE 0 END) AS completeRounds,
                  SUM(CASE WHEN COALESCE(OMITCOUNT, 0) > 0 THEN 1 ELSE 0 END) AS incompleteRounds
             FROM tourdatas
            WHERE COMPANYID = ?
              AND BEGINTIME >= ?
              AND BEGINTIME < DATE_ADD(?, INTERVAL 1 DAY)`,
          [companyId, range.from, range.to]
        );
        result.patrol = numericFields(rows[0] || {}, ['patrolRounds', 'plannedCheckpoints', 'arrivedCheckpoints', 'omittedCheckpoints', 'completeRounds', 'incompleteRounds']);
      } else if (tool === 'fingerprint_metadata') {
        const rows = await nexusQuery(
          `SELECT COUNT(DISTINCT fi.ID) AS enrolledFingerprints,
                  COUNT(DISTINCT fi.GUARDID) AS enrolledGuards,
                  COUNT(DISTINCT rf.READERCODE) AS linkedReaders
             FROM fingerinfo fi
        LEFT JOIN readerfinger rf
               ON rf.COMPANYID = fi.COMPANYID
              AND rf.GUARDID = fi.GUARDID
              AND rf.FINGERID = fi.FINGERID
            WHERE fi.COMPANYID = ?`,
          [companyId]
        );
        result.fingerprints = numericFields(rows[0] || {}, ['enrolledFingerprints', 'enrolledGuards', 'linkedReaders']);
      }
    }));

    setNexusDirectSourceHeaders(res, 'assistant_metrics');
    return ok(res, {
      scope: { kind: 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'nexus-core-v2' },
      generatedAt: timestamp(),
      dateFrom: range.from,
      dateTo: range.to,
      metrics: result,
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/nexus/v2/assistant/metrics', err, 'Failed to load same-company assistant metrics.');
  }
});

app.post('/api/enormity/nexus/v2/contracts/query', async (req, res) => {
  try {
    const companyId = normalizeCompanyId(req.body?.companyId);
    const contractId = String(req.body?.contractId || '').trim().toLowerCase();
    const domain = NEXUS_DIRECT_CONTRACTS.get(contractId);
    if (!companyId) return fail(res, 400, 'A positive server-derived companyId is required.');
    if (!domain) return fail(res, 404, 'Direct contract is not registered.', null, 'E_CONTRACT');
    if (!requireDirectReadMode(res, domain)) return;
    const filters = directContractFilters(req.body || {});
    const result = await queryDirectContract(contractId, companyId, filters);
    setNexusDirectSourceHeaders(res, domain);
    return ok(res, {
      scope: { kind: 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'nexus-core-v2' },
      generatedAt: timestamp(),
      contractId,
      total: result.total,
      rows: result.rows,
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/nexus/v2/contracts/query', err, 'Failed to load the same-company direct contract.');
  }
});

app.post('/api/enormity/nexus/v2/biometrics/metadata', async (req, res) => {
  try {
    if (!requireDirectReadMode(res, 'fingerprint_metadata')) return;
    const companyId = normalizeCompanyId(req.body?.companyId);
    const guardId = req.body?.guardId === undefined || req.body?.guardId === null || req.body?.guardId === ''
      ? null
      : normalizeCompanyId(req.body.guardId);
    if (!companyId) return fail(res, 400, 'A positive server-derived companyId is required.');
    if (req.body?.guardId !== undefined && req.body?.guardId !== null && req.body?.guardId !== '' && !guardId) {
      return fail(res, 400, 'guardId must be a positive integer.');
    }

    const rows = await nexusQuery(
      `SELECT fi.ID AS internalId,
              fi.GUARDID AS guardId,
              COALESCE(NULLIF(fi.FINGERNAME, ''), 'Fingerprint') AS label,
              COALESCE(NULLIF(r.NAME, ''), 'Linked reader') AS readerName,
              CASE WHEN rf.ID IS NULL THEN 0 ELSE 1 END AS linked
         FROM fingerinfo fi
         JOIN guards g ON g.GUARDID = fi.GUARDID
         JOIN depts d ON d.DEPTID = g.DEPTID AND d.COMPANYID = fi.COMPANYID
    LEFT JOIN readerfinger rf
           ON rf.COMPANYID = fi.COMPANYID
          AND rf.GUARDID = fi.GUARDID
          AND rf.FINGERID = fi.FINGERID
    LEFT JOIN readers r
           ON r.COMPANYID = fi.COMPANYID
          AND r.READERCODE = rf.READERCODE
        WHERE fi.COMPANYID = ?
          AND (? IS NULL OR fi.GUARDID = ?)
        ORDER BY fi.GUARDID, fi.FINGERSN, fi.ID
        LIMIT 1000`,
      [companyId, guardId, guardId]
    );
    const grouped = new Map();
    for (const row of rows) {
      const reference = crypto.createHmac('sha256', JWT_SECRET)
        .update(`fingerprint-metadata\0${companyId}\0${row.guardId}\0${row.internalId}`)
        .digest('base64url')
        .slice(0, 32);
      const current = grouped.get(reference) || {
        reference,
        label: String(row.label || 'Fingerprint').slice(0, 120),
        enrolled: true,
        readers: [],
        enrolledAt: null,
        updatedAt: null,
      };
      if (Number(row.linked) === 1 && row.readerName) {
        const readerName = String(row.readerName).slice(0, 120);
        if (!current.readers.includes(readerName)) current.readers.push(readerName);
      }
      grouped.set(reference, current);
    }
    const records = [...grouped.values()].slice(0, 500);
    setNexusDirectSourceHeaders(res, 'fingerprint_metadata');
    return ok(res, {
      scope: { kind: 'company', companyId },
      provenance: { source: 'cloudpatrol-mysql', adapter: 'nexus-core-v2' },
      generatedAt: timestamp(),
      total: records.length,
      records,
      redaction: 'metadata-only',
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/nexus/v2/biometrics/metadata', err, 'Failed to load same-company fingerprint metadata.');
  }
});

// Direct commands are registered domain by domain. An unregistered handler is
// never retried through OEM. This endpoint remains behind the global write
// lock until the matching domain, database grants, and exact release are
// certified.
app.post('/api/enormity/nexus/v2/commands/:area/:operation', async (req, res) => {
  const area = String(req.params.area || '').trim().toLowerCase();
  const operation = String(req.params.operation || '').trim().toLowerCase();
  if (!NEXUS_COMMAND_AREAS.has(area) || !/^[a-z][a-z0-9-]{1,63}$/.test(operation)) {
    return fail(res, 404, 'Nexus command handler is not registered.', null, 'E_COMMAND_HANDLER');
  }
  try {
    requireNexusDbIdentity('command');
  } catch (error) {
    return handleRouteError(res, '/api/enormity/nexus/v2/commands', error, 'The direct command database identity is unavailable.');
  }
  return fail(res, 501, 'This direct command handler is not installed; no OEM fallback was attempted.', { area, operation }, 'E_COMMAND_HANDLER');
});

app.post('/api/enormity/nexus/v2/biometrics/:operation', async (req, res) => {
  const operation = String(req.params.operation || '').trim().toLowerCase();
  if (!NEXUS_BIOMETRIC_OPERATIONS.has(operation)) return fail(res, 404, 'Biometric operation is not registered.', null, 'E_BIOMETRIC_OPERATION');
  const releaseSha = String(process.env.NEXUS_RELEASE_GIT_SHA || '').trim();
  const releaseId = String(process.env.NEXUS_RELEASE_ID || '').trim();
  const certified = process.env.NEXUS_BIOMETRIC_WRITES_ENABLED === '1'
    && process.env.NEXUS_BIOMETRIC_CERTIFICATION_STATUS === 'PASS'
    && /^[a-f0-9]{40}$/i.test(releaseSha)
    && releaseSha === String(process.env.NEXUS_BIOMETRIC_CERTIFIED_GIT_SHA || '').trim()
    && releaseId
    && releaseId === String(process.env.NEXUS_BIOMETRIC_CERTIFIED_RELEASE_ID || '').trim();
  if (!certified) return fail(res, 423, 'Fingerprint writes are locked until physical certification is bound to this exact release.', null, 'E_BIOMETRIC_LOCKED');
  try {
    requireNexusDbIdentity('biometric');
  } catch (error) {
    return handleRouteError(res, '/api/enormity/nexus/v2/biometrics', error, 'The biometric database identity is unavailable.');
  }
  return fail(res, 501, 'The certified biometric handler is not installed; no OEM fallback was attempted.', null, 'E_BIOMETRIC_HANDLER');
});

app.post('/api/enormity/nexus/realtime-ticket', (req, res) => {
  try {
    const scope = normalizeRealtimeScope(req.body || {});
    const ticket = issueRealtimeTicket(scope, req.enormityAuth?.subject);
    res.setHeader('Cache-Control', 'no-store');
    return ok(res, {
      ticket,
      expiresInSeconds: Math.floor(REALTIME_TICKET_TTL_MS / 1000),
      scope: { kind: scope.global ? 'global' : 'company', companyId: scope.companyId },
    });
  } catch (err) {
    return fail(res, 400, err.message || 'Invalid realtime scope.');
  }
});

app.get('/api/enormity/mobile/dashboard', async (req, res) => {
  try {
    const date = validateDateParam(req.query.date);
    const companyId = optionalCompanyId(req.query.companyId);
    const [start, end] = dateRange(date);
    const company = companyWhere(companyId);
    const [stats, alerts] = await Promise.all([
      query(
        `SELECT COUNT(*) AS scans,
                COUNT(DISTINCT GUARDID) AS guards,
                COUNT(DISTINCT SITEID) AS sites,
                MAX(HAPPENTIME) AS lastScan
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`,
        [start, end, ...company.params]
      ),
      query(
        `SELECT COUNT(*) AS activeAlerts
           FROM enormity_escalations
          WHERE requiresAck = 1${companyId ? ' AND companyid = ?' : ''}`,
        companyId ? [companyId] : []
      ),
    ]);
    return ok(res, {
      date,
      companyId,
      scansToday: Number(stats[0]?.scans || 0),
      activeGuards: Number(stats[0]?.guards || 0),
      activeSites: Number(stats[0]?.sites || 0),
      activeAlerts: Number(alerts[0]?.activeAlerts || 0),
      lastScan: stats[0]?.lastScan || null,
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/mobile/dashboard', err, 'Failed to build mobile dashboard.');
  }
});

app.get('/api/enormity/mobile/guard/:id/today', async (req, res) => {
  try {
    const guardId = parsePositiveInt(req.params.id, 0);
    if (!guardId) return fail(res, 400, 'guard id is required.');
    const date = validateDateParam(req.query.date);
    const [start, end] = dateRange(date);
    const [summary, sites] = await Promise.all([
      query(
        `SELECT GUARDID AS guardId,
                GUARDNAME AS guardName,
                COUNT(*) AS scans,
                COUNT(DISTINCT SITEID) AS sites,
                MIN(HAPPENTIME) AS firstScan,
                MAX(HAPPENTIME) AS lastScan
           FROM historydatas
          WHERE GUARDID = ?
            AND HAPPENTIME BETWEEN ? AND ?
          GROUP BY GUARDID, GUARDNAME`,
        [guardId, start, end]
      ),
      query(
        `SELECT SITEID AS siteId, SITENAME AS siteName, COUNT(*) AS scans, MAX(HAPPENTIME) AS lastScan
           FROM historydatas
          WHERE GUARDID = ?
            AND HAPPENTIME BETWEEN ? AND ?
          GROUP BY SITEID, SITENAME
          ORDER BY lastScan DESC
          LIMIT 20`,
        [guardId, start, end]
      ),
    ]);
    return ok(res, { date, guardId, summary: summary[0] || { guardId, scans: 0, sites: 0 }, sites });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/mobile/guard/:id/today', err, 'Failed to build mobile guard summary.');
  }
});

app.post('/api/enormity/mobile/sos', async (req, res) => {
  try {
    const guardId = parsePositiveInt(req.body?.guardId, 0);
    const siteId = parsePositiveInt(req.body?.siteId, 0);
    const message = String(req.body?.message || 'Mobile SOS').slice(0, 180);
    if (!guardId || !siteId) return fail(res, 400, 'guardId and siteId are required.');
    const [guards, sites] = await Promise.all([
      query(`SELECT g.GUARDID, g.GUARDNAME, g.DEPTID, d.DEPTNAME, d.DEPTSN, d.DEPTCODE, d.COMPANYID
               FROM guards g LEFT JOIN depts d ON d.DEPTID = g.DEPTID
              WHERE g.GUARDID = ? LIMIT 1`, [guardId]),
      query(`SELECT SITEID, SITENAME, SITESN, SITECODE, LONGITUDE, LATITUDE
               FROM sites WHERE SITEID = ? LIMIT 1`, [siteId]),
    ]);
    const guard = guards[0];
    const site = sites[0];
    if (!guard || !site) return fail(res, 404, 'Guard or site not found.');
    const companyId = optionalCompanyId(req.body?.companyId) || Number(guard.COMPANYID || 0);
    const result = await query(
      `INSERT INTO alarmdatas
        (COMPANYID, DEPTID, DEPTNAME, DEPTSN, DEPTCODE, GUARDID, GUARDNAME, SITEID, SITENAME, SITESN, SITECODE,
         BEGINTIME, ENDTIME, ALARMTYPE, ALARMINFO, READERCODE, HAPPENTIME, INSTANTDATA, LONGITUDE, LATITUDE, PUSHED, MOBILEMEDIA)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), 1, ?, 'MOBILE', NOW(), 1, ?, ?, 0, 'MOBILE')`,
      [
        companyId,
        guard.DEPTID || 0,
        guard.DEPTNAME || '',
        guard.DEPTSN || 0,
        guard.DEPTCODE || '',
        guard.GUARDID,
        guard.GUARDNAME || '',
        site.SITEID,
        site.SITENAME || '',
        site.SITESN || 0,
        site.SITECODE || '',
        message,
        site.LONGITUDE || 0,
        site.LATITUDE || 0,
      ]
    );
    const alarmId = result.insertId;
    await query(
      `INSERT IGNORE INTO enormity_escalations
        (alarm_id, companyid, alarm_type, guard_name, site_name, severity, status, requiresAck, created_at)
       VALUES (?, ?, 1, ?, ?, 'CRITICAL', 'ACTIVE', 1, NOW())`,
      [alarmId, companyId, guard.GUARDNAME || '', site.SITENAME || '']
    );
    sendTelegramAlert({ escalationId: alarmId, guardName: guard.GUARDNAME, siteName: site.SITENAME, companyId, createdAt: timestamp() })
      .catch((err) => console.error('telegram mobile sos failed:', err.message));
    return ok(res, { alarmId, companyId, severity: 'CRITICAL', status: 'ACTIVE' }, 201);
  } catch (err) {
    return handleRouteError(res, '/api/enormity/mobile/sos', err, 'Failed to create mobile SOS.');
  }
});

app.get('/api/enormity/mobile/sites/:companyId', async (req, res) => {
  try {
    const companyId = parsePositiveInt(req.params.companyId, 0);
    const limit = parsePositiveInt(req.query.limit, 50, 80);
    if (!companyId) return fail(res, 400, 'companyId is required.');
    const rows = await query(
      `SELECT s.SITEID AS id,
              s.SITENAME AS name,
              s.SITECODE AS code,
              s.LONGITUDE AS lng,
              s.LATITUDE AS lat
         FROM sites s
         JOIN depts d ON d.DEPTID = s.DEPTID
        WHERE d.COMPANYID = ?
        ORDER BY s.SITENAME ASC
        LIMIT ${limit}`,
      [companyId]
    );
    return ok(res, { companyId, limit, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/mobile/sites/:companyId', err, 'Failed to fetch mobile site list.');
  }
});

app.get('/api/enormity/stats/realtime', async (req, res) => {
  try {
    const [rows, cacheStats] = await Promise.all([
      query(
        `SELECT SUM(HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)) AS scansLastMinute,
                SUM(HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 1 HOUR)) AS scansLastHour
           FROM historydatas
          WHERE HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 1 HOUR)`
      ),
      (async () => {
        const total = cacheCounters.hits + cacheCounters.misses;
        return total ? Number(((cacheCounters.hits / total) * 100).toFixed(2)) : 0;
      })(),
    ]);
    return ok(res, {
      scansLastMinute: Number(rows[0]?.scansLastMinute || 0),
      scansLastHour: Number(rows[0]?.scansLastHour || 0),
      activeWebSocketClients: wss.clients.size,
      cacheHitRate: cacheStats,
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/stats/realtime', err, 'Failed to build realtime stats.');
  }
});

app.get('/api/enormity/audit/logs', async (req, res) => {
  try {
    const days = parsePositiveInt(req.query.days, 7, 90);
    const limit = parsePositiveInt(req.query.limit, 100, 500);
    const eventType = String(req.query.eventType || '').trim();
    const params = [];
    let sql = `SELECT id, event_type, endpoint, user_name, ip_address, success, response_code, response_time_ms, reason, created_at
                 FROM enormity_audit_log
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL ${days} DAY)`;
    if (eventType) {
      sql += ' AND event_type = ?';
      params.push(eventType);
    }
    sql += ` ORDER BY created_at DESC LIMIT ${limit}`;
    const rows = await query(sql, params);
    return ok(res, rows.map((row) => ({
      id: row.id,
      eventType: row.event_type,
      endpoint: row.endpoint,
      userName: row.user_name,
      ipAddress: row.ip_address,
      success: row.success === null ? null : Boolean(row.success),
      responseCode: row.response_code,
      responseTimeMs: row.response_time_ms,
      notes: row.reason,
      createdAt: row.created_at,
    })));
  } catch (err) {
    return handleRouteError(res, '/api/enormity/audit/logs', err, 'Failed to fetch audit logs.');
  }
});

app.get('/api/enormity/patrol/summary', async (req, res) => {
  try {
    const date = validateDateParam(req.query.date);
    const companyId = optionalCompanyId(req.query.companyId);
    const cacheKey = `patrol:summary:${companyId || 'all'}:${date}`;
    const cached = await getCachedJson(cacheKey);
    if (cached) {
      res.setHeader('X-Cache', 'HIT');
      return ok(res, cached);
    }
    const [start, end] = dateRange(date);
    const company = companyWhere(companyId);
    const scheduleParams = [date];
    let expectedScansSql = `SELECT COUNT(*) AS expectedScans
                              FROM schedules s
                              INNER JOIN plans p ON p.PLANID = s.PLANID
                              INNER JOIN depts d ON d.DEPTID = p.DEPTID
                             WHERE DATE(?) BETWEEN DATE(p.BEGINDATE) AND DATE(p.ENDDATE)`;
    if (companyId) {
      expectedScansSql += ' AND d.COMPANYID = ?';
      scheduleParams.push(companyId);
    }

    const [totals, hourlyRows, topGuards, topSites, scanWindow, expectedRows] = await Promise.all([
      query(
        `SELECT COUNT(*) AS totalScans,
                COUNT(DISTINCT GUARDID) AS activeGuards,
                COUNT(DISTINCT SITEID) AS activeSites
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`,
        [start, end, ...company.params]
      ),
      query(
        `SELECT HOUR(HAPPENTIME) AS hour, COUNT(*) AS count
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}
          GROUP BY HOUR(HAPPENTIME)
          ORDER BY hour`,
        [start, end, ...company.params]
      ),
      query(
        `SELECT GUARDID AS guardId, GUARDNAME AS guardName, COUNT(*) AS count
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}
          GROUP BY GUARDID, GUARDNAME
          ORDER BY count DESC
          LIMIT 5`,
        [start, end, ...company.params]
      ),
      query(
        `SELECT SITEID AS siteId, SITENAME AS siteName, COUNT(*) AS count
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}
          GROUP BY SITEID, SITENAME
          ORDER BY count DESC
          LIMIT 5`,
        [start, end, ...company.params]
      ),
      query(
        `SELECT MIN(HAPPENTIME) AS firstScanTime,
                MAX(HAPPENTIME) AS lastScanTime
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`,
        [start, end, ...company.params]
      ),
      query(expectedScansSql, scheduleParams),
    ]);

    const hourlyMap = new Map(hourlyRows.map((row) => [Number(row.hour), Number(row.count)]));
    const hourlyBreakdown = Array.from({ length: 24 }, (_, hour) => ({
      hour,
      count: hourlyMap.get(hour) || 0,
    }));
    const peakHourRow = hourlyBreakdown.reduce((best, current) => (
      current.count > best.count ? current : best
    ), { hour: null, count: -1 });
    const totalScans = Number(totals[0].totalScans || 0);
    const activeGuards = Number(totals[0].activeGuards || 0);
    const activeSites = Number(totals[0].activeSites || 0);
    const expectedScans = Number(expectedRows[0]?.expectedScans || 0);

    const payload = {
      date,
      companyId: companyId || null,
      totalScans,
      activeGuards,
      activeSites,
      expectedScans: expectedScans || null,
      complianceRate: expectedScans > 0 ? Number(((totalScans / expectedScans) * 100).toFixed(2)) : null,
      peakHour: peakHourRow.count >= 0 ? peakHourRow.hour : null,
      firstScanTime: scanWindow[0]?.firstScanTime || null,
      lastScanTime: scanWindow[0]?.lastScanTime || null,
      avgScansPerGuard: activeGuards > 0 ? Number((totalScans / activeGuards).toFixed(2)) : 0,
      hourlyBreakdown,
      topGuards: topGuards.map((row) => ({
        guardId: row.guardId,
        guardName: row.guardName,
        count: Number(row.count),
      })),
      topSites: topSites.map((row) => ({
        siteId: row.siteId,
        siteName: row.siteName,
        count: Number(row.count),
      })),
    };
    res.setHeader('X-Cache', redisReady ? 'MISS' : 'BYPASS');
    await setCachedJson(cacheKey, 300, payload);
    return ok(res, payload);
  } catch (err) {
    return handleRouteError(res, '/api/enormity/patrol/summary', err, 'Failed to build patrol summary.');
  }
});

app.get('/api/enormity/patrol/live', async (req, res) => {
  try {
    const rows = await query(
      `SELECT ID AS id,
              COMPANYID AS companyId,
              GUARDID AS guardId,
              GUARDNAME AS guardName,
              SITEID AS siteId,
              SITENAME AS siteName,
              HAPPENTIME AS timestamp,
              LATITUDE AS latitude,
              LONGITUDE AS longitude,
              READERCODE AS deviceCode,
              EVENTINFO AS eventInfo,
              STATUS AS status
         FROM historydatas
        ORDER BY HAPPENTIME DESC
        LIMIT 50`
    );

    return ok(res, rows.map((row) => ({
      id: row.id,
      companyId: row.companyId,
      guardId: row.guardId,
      guardName: row.guardName,
      siteId: row.siteId,
      siteName: row.siteName,
      timestamp: row.timestamp,
      latitude: row.latitude === null ? null : Number(row.latitude),
      longitude: row.longitude === null ? null : Number(row.longitude),
      deviceCode: row.deviceCode,
      eventInfo: row.eventInfo,
      status: row.status,
    })));
  } catch (err) {
    return handleRouteError(res, '/api/enormity/patrol/live', err, 'Failed to fetch live patrol records.');
  }
});

app.get('/api/enormity/guards/efficiency', async (req, res) => {
  try {
    const date = validateDateParam(req.query.date);
    const companyId = req.query.companyId || '';
    const cacheKey = `efficiency:${companyId || 'all'}:${date}`;
    const cached = await getCachedJson(cacheKey);
    if (cached) {
      res.setHeader('X-Cache', 'HIT');
      return ok(res, cached);
    }
    const [start, end] = dateRange(date);
    const company = companyWhere(companyId);

    const rows = await query(
      `SELECT GUARDID AS guardId,
              GUARDNAME AS guardName,
              COUNT(*) AS scansToday,
              COUNT(DISTINCT SITEID) AS sitesPatrolled,
              COUNT(DISTINCT HOUR(HAPPENTIME)) AS activeHours,
              MAX(HAPPENTIME) AS lastSeen
         FROM historydatas
        WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}
        GROUP BY GUARDID, GUARDNAME
        ORDER BY scansToday DESC`,
      [start, end, ...company.params]
    );

    const payload = rows.map((row) => {
      const scansToday = Number(row.scansToday || 0);
      const activeHours = Number(row.activeHours || 0);
      const sitesPatrolled = Number(row.sitesPatrolled || 0);
      const avgScansPerHour = activeHours > 0 ? scansToday / activeHours : 0;
      const scanScore = Math.min(scansToday / 24, 1) * 45;
      const hourScore = Math.min(activeHours / 8, 1) * 35;
      const siteScore = Math.min(sitesPatrolled / 10, 1) * 20;

      return {
        guardId: row.guardId,
        guardName: row.guardName,
        scansToday,
        avgScansPerHour: Number(avgScansPerHour.toFixed(2)),
        lastSeen: row.lastSeen,
        sitesPatrolled,
        efficiencyScore: Math.round(scanScore + hourScore + siteScore),
      };
    });
    res.setHeader('X-Cache', redisReady ? 'MISS' : 'BYPASS');
    await setCachedJson(cacheKey, 300, payload);
    return ok(res, payload);
  } catch (err) {
    return handleRouteError(res, '/api/enormity/guards/efficiency', err, 'Failed to compute guard efficiency.');
  }
});

app.get('/api/enormity/devices/status', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const company = companyWhere(companyId);
    const rows = await query(
      `SELECT READERCODE AS readerCode,
              COMPANYID AS companyId,
              LASTCONTENT AS lastContent,
              LASTTIME AS lastTime,
              ENDDATE AS licenceExpiry,
              TIMESTAMPDIFF(MINUTE, LASTTIME, NOW()) AS minutesSinceLastSeen
         FROM readers
        WHERE DELETED = 0${company.clause}
        ORDER BY LASTTIME DESC`,
      company.params
    );

    return ok(res, rows.map((row) => ({
      readerCode: row.readerCode,
      companyId: row.companyId,
      lastContent: row.lastContent,
      lastTime: row.lastTime,
      status: Number(row.minutesSinceLastSeen) <= 120 ? 'ONLINE' : 'OFFLINE',
      licenceExpiry: row.licenceExpiry,
    })));
  } catch (err) {
    return handleRouteError(res, '/api/enormity/devices/status', err, 'Failed to fetch device status.');
  }
});

app.get('/api/enormity/analytics/heatmap', async (req, res) => {
  try {
    const days = parsePositiveInt(req.query.days, 7, 90);
    const companyId = req.query.companyId || '';
    const company = companyWhere(companyId);
    const rows = await query(
      `SELECT DATE(HAPPENTIME) AS date,
              HOUR(HAPPENTIME) AS hour,
              COUNT(*) AS count
         FROM historydatas
        WHERE HAPPENTIME >= DATE_SUB(CURDATE(), INTERVAL ? DAY)${company.clause}
        GROUP BY DATE(HAPPENTIME), HOUR(HAPPENTIME)
        ORDER BY date, hour`,
      [days - 1, ...company.params]
    );

    return ok(res, rows.map((row) => ({
      date: row.date instanceof Date ? row.date.toISOString().slice(0, 10) : String(row.date).slice(0, 10),
      hour: Number(row.hour),
      count: Number(row.count),
    })));
  } catch (err) {
    return handleRouteError(res, '/api/enormity/analytics/heatmap', err, 'Failed to build analytics heatmap.');
  }
});

app.get('/api/enormity/patrol/missed', async (req, res) => {
  try {
    const companyId = parsePositiveInt(req.query.companyId, 1);
    const date = validateDateParam(req.query.date);
    const rows = firstResultSet(await query('CALL sp_missed_checkpoints(?, ?)', [companyId, date]));
    return ok(res, { companyId, date, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/patrol/missed', err, 'Failed to fetch missed checkpoint analysis.');
  }
});

app.get('/api/enormity/analytics/anomalies', async (req, res) => {
  try {
    const companyId = parsePositiveInt(req.query.companyId, 1);
    const date = validateDateParam(req.query.date);
    const rows = firstResultSet(await query('CALL sp_anomaly_detection(?, ?)', [companyId, date]));
    return ok(res, { companyId, date, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/analytics/anomalies', err, 'Failed to fetch anomaly analysis.');
  }
});

app.get('/api/enormity/analytics/compliance', async (req, res) => {
  try {
    const companyId = parsePositiveInt(req.query.companyId, 1);
    const { month: currentMonth, year: currentYear } = currentMonthYear();
    const month = parsePositiveInt(req.query.month, currentMonth, 12);
    const year = parsePositiveInt(req.query.year, currentYear, 2100);
    if (year < 2000) return fail(res, 400, 'Invalid year.');
    const cacheKey = `compliance:${companyId}:${month}:${year}`;
    return sendCached(res, cacheKey, 300, async () => {
      const rows = firstResultSet(await query('CALL sp_company_compliance_report(?, ?, ?)', [companyId, month, year]));
      return { companyId, month, year, rows };
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/analytics/compliance', err, 'Failed to fetch compliance report.');
  }
});

app.get('/api/enormity/guards/streaks', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const company = companyWhere(companyId);
    const rows = await query(
      `SELECT companyid AS companyId,
              guardid AS guardId,
              guard_name AS guardName,
              current_streak AS currentStreak,
              longest_streak AS longestStreak,
              last_patrol_date AS lastPatrolDate,
              updated_at AS updatedAt
         FROM enormity_guard_streaks
        WHERE 1=1${company.clause}
        ORDER BY current_streak DESC, longest_streak DESC, updated_at DESC
        LIMIT 10`,
      company.params
    );
    return ok(res, { companyId: companyId || null, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/guards/streaks', err, 'Failed to fetch guard streaks.');
  }
});

app.get('/api/enormity/guards/leaderboard', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const { month, year } = parseMonthYear(req);
    const limit = parsePositiveInt(req.query.limit, 10, 100);
    const rows = firstResultSet(await query('CALL sp_guard_leaderboard_monthly(?, ?, ?)', [companyId, month, year]));
    return ok(res, { companyId, month, year, limit, rows: rows.slice(0, limit) });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/guards/leaderboard', err, 'Failed to fetch monthly guard leaderboard.');
  }
});

app.get('/api/enormity/guards/idle', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const params = [];
    let sql = `SELECT g.GUARDID AS guardId,
                      g.GUARDNAME AS guardName,
                      d.COMPANYID AS companyId,
                      g.DEPTID AS deptId
                 FROM guards g
            LEFT JOIN depts d ON d.DEPTID = g.DEPTID
                WHERE g.GUARDID NOT IN (
                        SELECT DISTINCT GUARDID
                          FROM historydatas
                         WHERE DATE(HAPPENTIME) = CURDATE()
                           AND GUARDID IS NOT NULL
                     )`;
    if (companyId) {
      sql += ' AND d.COMPANYID = ?';
      params.push(companyId);
    }
    sql += ' ORDER BY g.GUARDNAME ASC LIMIT 200';
    const rows = await query(sql, params);
    return ok(res, { companyId, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/guards/idle', err, 'Failed to fetch idle guards.');
  }
});

app.get('/api/enormity/guards/history', async (req, res) => {
  try {
    const guardId = parsePositiveInt(req.query.guardId, 0);
    if (!guardId) return fail(res, 400, 'guardId is required.');
    const days = parsePositiveInt(req.query.days, 30, 90);
    const rows = await query(
      `SELECT DATE(HAPPENTIME) AS patrolDate,
              COUNT(*) AS scans
         FROM historydatas
        WHERE GUARDID = ?
          AND HAPPENTIME >= DATE_SUB(CURDATE(), INTERVAL ? DAY)
        GROUP BY DATE(HAPPENTIME)
        ORDER BY patrolDate DESC`,
      [guardId, days]
    );
    return ok(res, { guardId, days, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/guards/history', err, 'Failed to fetch guard scan history.');
  }
});

app.get('/api/enormity/sites/coverage', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const date = validateDateParam(req.query.date);
    const rows = firstResultSet(await query('CALL sp_site_patrol_coverage(?, ?)', [companyId, date]));
    return ok(res, { companyId, date, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/sites/coverage', err, 'Failed to fetch site patrol coverage.');
  }
});

app.get('/api/enormity/sites/top-missed', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const days = parsePositiveInt(req.query.days, 30, 90);
    const params = [days];
    let sql = `SELECT SITEID AS siteId,
                      SITENAME AS siteName,
                      COUNT(*) AS missedCount,
                      MAX(HAPPENTIME) AS lastMissed,
                      CASE
                        WHEN COUNT(*) >= 10 THEN 'CRITICAL'
                        WHEN COUNT(*) >= 5 THEN 'HIGH'
                        WHEN COUNT(*) >= 2 THEN 'MEDIUM'
                        ELSE 'LOW'
                      END AS severity
                 FROM alarmdatas
                WHERE ALARMTYPE = 3
                  AND HAPPENTIME >= DATE_SUB(NOW(), INTERVAL ? DAY)`;
    if (companyId) {
      sql += ' AND COMPANYID = ?';
      params.push(companyId);
    }
    sql += ' GROUP BY SITEID, SITENAME ORDER BY missedCount DESC, lastMissed DESC LIMIT 20';
    const rows = await query(sql, params);
    return ok(res, { companyId, days, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/sites/top-missed', err, 'Failed to fetch top missed sites.');
  }
});

app.get('/api/enormity/reports/scorecard', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const date = validateDateParam(req.query.date);
    const rows = firstResultSet(await query('CALL sp_daily_kpm_scorecard(?, ?)', [companyId, date]));
    return ok(res, { companyId, date, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/reports/scorecard', err, 'Failed to fetch daily KPM scorecard.');
  }
});

app.get('/api/enormity/kpm/contract-score', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const { month: currentMonth, year: currentYear } = currentMonthYear();
    const month = parsePositiveInt(req.query.month, currentMonth, 12);
    const year = parsePositiveInt(req.query.year, currentYear, 2100);
    const { start, end, daysInMonth } = monthDateRange(month, year);
    const company = companyWhere(companyId);
    const [patrol, manpower, devices] = await Promise.all([
      query(`SELECT COUNT(*) AS scans, COUNT(DISTINCT SITEID) AS sitesVisited, COUNT(DISTINCT DATE(HAPPENTIME)) AS activeDays
               FROM historydatas
              WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`, [start, end, ...company.params]),
      query(`SELECT COUNT(DISTINCT GUARDID) AS activeGuards
               FROM historydatas
              WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`, [start, end, ...company.params]),
      query(`SELECT COUNT(*) AS totalDevices,
                    SUM(CASE WHEN ENDDATE >= CURDATE() THEN 1 ELSE 0 END) AS validDevices,
                    SUM(CASE WHEN ENDDATE < CURDATE() THEN 1 ELSE 0 END) AS expiredDevices
               FROM readers
              WHERE DELETED = 0${company.clause}`, company.params),
    ]);
    const scans = Number(patrol[0]?.scans || 0);
    const activeDays = Number(patrol[0]?.activeDays || 0);
    const activeGuards = Number(manpower[0]?.activeGuards || 0);
    const totalDevices = Number(devices[0]?.totalDevices || 0);
    const validDevices = Number(devices[0]?.validDevices || 0);
    const patrolFrequencyScore = Math.min(100, Math.round((activeDays / daysInMonth) * 100));
    const manpowerScore = Math.min(100, Math.round((activeGuards / Math.max(Number(patrol[0]?.sitesVisited || 0), 1)) * 100));
    const deviceScore = totalDevices ? Math.round((validDevices / totalDevices) * 100) : 0;
    const overallScore = Number(((patrolFrequencyScore * 0.4) + (manpowerScore * 0.35) + (deviceScore * 0.25)).toFixed(2));
    const findings = [];
    const recommendations = [];
    if (patrolFrequencyScore < 80) { findings.push('Patrol frequency below target.'); recommendations.push('Increase scheduled patrol completion and missed-site follow-up.'); }
    if (manpowerScore < 80) { findings.push('Manpower coverage below target.'); recommendations.push('Review guard allocation against active patrol sites.'); }
    if (deviceScore < 90) { findings.push('Device licence or validity risk detected.'); recommendations.push('Prioritise reader renewal and maintenance.'); }
    return ok(res, {
      companyId,
      month,
      year,
      patrolFrequencyScore,
      manpowerScore,
      deviceScore,
      overallScore,
      grade: gradeFromCompliance(overallScore),
      findings,
      recommendations,
      evidence: { scans, activeDays, activeGuards, totalDevices, validDevices, expiredDevices: Number(devices[0]?.expiredDevices || 0) },
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/kpm/contract-score', err, 'Failed to build KPM contract score.');
  }
});

app.get('/api/enormity/devices/expiring', async (req, res) => {
  try {
    const days = parsePositiveInt(req.query.days, 30, 365);
    const companyId = optionalCompanyId(req.query.companyId);
    const params = [days];
    let sql = `SELECT readerCode, readerName, companyName, licenceExpiry, daysRemaining, licenceStatus
                 FROM v_device_licence_status
                WHERE daysRemaining <= ?`;
    if (companyId) {
      sql += ' AND companyId = ?';
      params.push(companyId);
    }
    sql += ' ORDER BY daysRemaining ASC, readerCode ASC';
    const rows = await query(sql, params);
    return ok(res, { companyId, days, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/devices/expiring', err, 'Failed to fetch expiring devices.');
  }
});

app.get('/api/enormity/alarms/summary', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const days = parsePositiveInt(req.query.days, 30, 90);
    const params = [days];
    let sql = `SELECT companyId, companyName, alarmDate, alarmType, alarmTypeName, alarmCount, resolvedCount, pendingCount
                 FROM v_alarm_summary
                WHERE alarmDate >= DATE_SUB(CURDATE(), INTERVAL ? DAY)`;
    if (companyId) {
      sql += ' AND companyId = ?';
      params.push(companyId);
    }
    sql += ' ORDER BY alarmDate DESC, alarmCount DESC LIMIT 200';
    const rows = await query(sql, params);
    return ok(res, { companyId, days, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/alarms/summary', err, 'Failed to fetch alarm summary.');
  }
});

app.get('/api/enormity/operations/live', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const company = companyWhere(companyId);
    const rows = await query(
      `SELECT history_id AS historyId,
              companyid AS companyId,
              deptid AS deptId,
              deptname AS deptName,
              guardid AS guardId,
              guardname AS guardName,
              siteid AS siteId,
              sitename AS siteName,
              sitecode AS siteCode,
              readercode AS readerCode,
              imei,
              last_scan_time AS lastScanTime,
              longitude,
              latitude,
              status,
              minutes_since_scan AS minutesSinceScan
         FROM v_live_operations
        WHERE 1=1${company.clause}
        ORDER BY last_scan_time DESC
        LIMIT 500`,
      company.params
    );
    return ok(res, { companyId: companyId || null, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/operations/live', err, 'Failed to fetch live operations.');
  }
});

app.get('/api/enormity/cache/stats', async (req, res) => {
  try {
    const connected = await ensureRedis();
    if (!connected) return ok(res, { connected: false, hitRate: 0, memoryUsed: null, totalCommands: 0 });
    const total = cacheCounters.hits + cacheCounters.misses;
    const [memoryInfo, statsInfo] = await Promise.all([
      redis.info('memory'),
      redis.info('stats'),
    ]);
    const parseInfo = (text) => String(text).split('\n').reduce((acc, line) => {
      const idx = line.indexOf(':');
      if (idx > 0) acc[line.slice(0, idx)] = line.slice(idx + 1).trim();
      return acc;
    }, {});
    const memory = parseInfo(memoryInfo);
    const stats = parseInfo(statsInfo);
    return ok(res, {
      connected: true,
      hits: cacheCounters.hits,
      misses: cacheCounters.misses,
      hitRate: total ? Number(((cacheCounters.hits / total) * 100).toFixed(2)) : 0,
      memoryUsed: memory.used_memory_human || null,
      memoryPeak: memory.used_memory_peak_human || null,
      totalCommands: Number(stats.total_commands_processed || 0),
      keyspaceHits: Number(stats.keyspace_hits || 0),
      keyspaceMisses: Number(stats.keyspace_misses || 0),
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/cache/stats', err, 'Failed to read Redis cache stats.');
  }
});

app.get('/api/enormity/alerts/unacknowledged', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const limit = parsePositiveInt(req.query.limit, 100, 500);
    const params = [];
    let sql = `SELECT escalation_id AS id,
                      alarm_type AS alarmType,
                      severity AS escalationLevel,
                      companyid AS companyId,
                      guard_name AS guardName,
                      site_name AS siteName,
                      created_at AS createdAt,
                      TIMESTAMPDIFF(MINUTE, created_at, NOW()) AS minutesOpen
                 FROM enormity_escalations
                WHERE requiresAck = 1`;
    if (companyId) {
      sql += ' AND companyid = ?';
      params.push(companyId);
    }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);
    const rows = await query(sql, params);
    return ok(res, { companyId, limit, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/alerts/unacknowledged', err, 'Failed to fetch unacknowledged alerts.');
  }
});

app.get('/api/enormity/alerts/active', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const params = [];
    let sql = `SELECT escalation_id AS id,
                      alarm_id AS alarmId,
                      companyid AS companyId,
                      alarm_type AS alarmType,
                      guard_name AS guardName,
                      site_name AS siteName,
                      severity,
                      status,
                      created_at AS createdAt,
                      TIMESTAMPDIFF(MINUTE, created_at, NOW()) AS minutesOpen
                 FROM enormity_escalations
                WHERE requiresAck = 1
                  AND status = 'ACTIVE'`;
    if (companyId) {
      sql += ' AND companyid = ?';
      params.push(companyId);
    }
    sql += ' ORDER BY severity = "CRITICAL" DESC, created_at DESC LIMIT 200';
    const rows = await query(sql, params);
    return ok(res, { companyId, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/alerts/active', err, 'Failed to fetch active alerts.');
  }
});

app.get('/api/enormity/alerts/history', async (req, res) => {
  try {
    const days = parsePositiveInt(req.query.days, 30, 365);
    const companyId = optionalCompanyId(req.query.companyId);
    const params = [days];
    let sql = `SELECT escalation_id AS id,
                      alarm_id AS alarmId,
                      companyid AS companyId,
                      alarm_type AS alarmType,
                      guard_name AS guardName,
                      site_name AS siteName,
                      severity,
                      status,
                      created_at AS createdAt,
                      acknowledged_at AS acknowledgedAt,
                      acknowledged_by AS acknowledgedBy,
                      resolved_at AS resolvedAt
                 FROM enormity_escalations
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
                  AND (requiresAck = 0 OR status IN ('ACKNOWLEDGED','RESOLVED'))`;
    if (companyId) {
      sql += ' AND companyid = ?';
      params.push(companyId);
    }
    sql += ' ORDER BY COALESCE(acknowledged_at, resolved_at, created_at) DESC LIMIT 500';
    const rows = await query(sql, params);
    return ok(res, { companyId, days, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/alerts/history', err, 'Failed to fetch alert history.');
  }
});

app.post('/api/enormity/alerts/:id/acknowledge', async (req, res) => {
  try {
    const id = parsePositiveInt(req.params.id, 0);
    if (!id) return fail(res, 400, 'Invalid escalation id.');
    const acknowledgedBy = req.enormityAuth?.subject || req.body?.acknowledgedBy || 'nexus-api';
    await query(
      `UPDATE enormity_escalations
          SET requiresAck = 0,
              status = 'RESOLVED',
              acknowledged_at = NOW(),
              resolved_at = NOW(),
              acknowledged_by = ?
        WHERE escalation_id = ?`,
      [acknowledgedBy, id]
    );
    await query(
      `INSERT INTO enormity_audit_log (event_type, user_name, endpoint, request_params, response_code, created_at)
       VALUES ('alert_acknowledged', ?, '/api/enormity/alerts/:id/acknowledge', CAST(? AS JSON), 200, NOW())`,
      [acknowledgedBy, JSON.stringify({ escalationId: id })]
    );
    return ok(res, { escalationId: id, acknowledgedBy });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/alerts/:id/acknowledge', err, 'Failed to acknowledge escalation.');
  }
});


async function companyName(companyId) {
  if (!companyId) return 'Enormity Client';
  try {
    const rows = await query('SELECT COMPANYNAME AS companyName FROM companys WHERE COMPANYID = ? LIMIT 1', [companyId]);
    return rows[0]?.companyName || `Company ${companyId}`;
  } catch (_) {
    return `Company ${companyId}`;
  }
}

async function activeCompanies() {
  return query(
    `SELECT COMPANYID AS companyId,
            COMPANYNAME AS companyName,
            COMPANYCODE AS companyCode
      FROM companys
      WHERE (IFNULL(IS_Effective, 0) <> 0 OR ENDDATE >= NOW())
      ORDER BY COMPANYNAME ASC`
  );
}

function monthArchiveParts(year, month) {
  const safeYear = Math.max(2000, Number(year) || new Date().getFullYear());
  const safeMonth = Math.max(1, Math.min(12, Number(month) || 1));
  const ym = `${safeYear}-${String(safeMonth).padStart(2, '0')}`;
  const lastDay = new Date(safeYear, safeMonth, 0);
  const reportDate = `${safeYear}-${String(safeMonth).padStart(2, '0')}-${String(lastDay.getDate()).padStart(2, '0')}`;
  return { year: safeYear, month: safeMonth, ym, reportDate };
}

function archivePath(year, month, companyId, filename) {
  const parts = monthArchiveParts(year, month);
  return path.join(REPORT_ARCHIVE_ROOT, parts.ym, String(companyId), filename || '');
}

async function generateCompanyArchive(company, year, month) {
  const parts = monthArchiveParts(year, month);
  const dir = archivePath(parts.year, parts.month, company.companyId);
  fs.mkdirSync(dir, { recursive: true });
  const name = company.companyName || await companyName(company.companyId);
  const files = [
    {
      filename: 'pkk2.pdf',
      buffer: await kpmEngine.pkk2({ companyName: name, month: parts.month, year: parts.year, rows: await pkk2Rows(company.companyId, parts.month, parts.year) }),
    },
    {
      filename: 'pkk3.pdf',
      buffer: await kpmEngine.pkk3({ companyName: name, date: parts.reportDate, rows: await pkk3Rows(company.companyId, parts.reportDate) }),
    },
    {
      filename: 'pkk4.pdf',
      buffer: await kpmEngine.pkk4({ companyName: name, date: parts.reportDate, rows: await pkk4Rows(company.companyId, parts.reportDate) }),
    },
  ];
  files.forEach((file) => fs.writeFileSync(path.join(dir, file.filename), file.buffer));
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
    companyId: company.companyId,
    companyName: name,
    year: parts.year,
    month: parts.month,
    reportDate: parts.reportDate,
    files: files.map((file) => ({ filename: file.filename, bytes: file.buffer.length })),
    generatedAt: timestamp(),
  }, null, 2));
  return { companyId: company.companyId, companyName: name, path: dir, files: files.map((file) => file.filename) };
}

let lastArchiveRunKey = '';
async function runMonthlyArchiveScheduler(force = false) {
  const now = new Date();
  const runKey = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
  const due = force || (now.getDate() === 1 && now.getHours() === 8 && now.getMinutes() === 0);
  if (!due || (!force && lastArchiveRunKey === runKey)) return;
  lastArchiveRunKey = runKey;
  const target = new Date(now.getFullYear(), now.getMonth(), 0);
  const year = target.getFullYear();
  const month = target.getMonth() + 1;
  const companies = await activeCompanies();
  for (const company of companies) {
    try {
      await generateCompanyArchive(company, year, month);
    } catch (err) {
      console.error('[Enormity] KPM monthly archive failed:', company.companyId, err.message);
    }
  }
  console.log(`[Enormity] KPM monthly archive completed for ${year}-${String(month).padStart(2, '0')} companies=${companies.length}`);
}

function parseMonthYear(req) {
  const month = parsePositiveInt(req.query.month, new Date().getMonth() + 1, 12);
  const year = parsePositiveInt(req.query.year, new Date().getFullYear(), 2100);
  if (year < 2000) {
    const err = new Error('Invalid year.'); err.status = 400; throw err;
  }
  return { month, year };
}

function sendPdf(res, filename, buffer) {
  res.setHeader('Content-Type', 'application/pdf');
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Length', buffer.length);
  return res.end(buffer);
}

async function pkk2Rows(companyId, month, year) {
  try {
    const rows = await query('CALL sp_company_compliance_report(?, ?, ?)', [companyId, month, year]);
    const data = Array.isArray(rows[0]) ? rows[0] : rows;
    const readCompliance = (row) => Number(row.complianceRate || row.compliance_rate || row.PeratusanPematuhan || row.compliance || 0);
    return data.map((row, index) => ({
      bil: index + 1,
      companyName: row.companyName || row.company_name || row.NamaSyarikat || row.COMPANYNAME || `Company ${companyId}`,
      approvedGuards: row.approvedGuards || row.approved_guards || row.BilanganPengawalDiluluskan || row.approved || '-',
      guardsOnDuty: row.guardsOnDuty || row.guards_on_duty || row.BilanganPengawalBertugas || row.activeGuards || '-',
      siteCount: row.siteCount || row.site_count || row.BilanganTapakKawalan || row.activeSites || '-',
      complianceRate: `${readCompliance(row).toFixed(2)}%`,
      kpmGrade: gradeFromCompliance(readCompliance(row)),
    }));
  } catch (_) {
    const { start, end, daysInMonth } = monthDateRange(month, year);
    const company = companyWhere(companyId);
    const rows = await query(`SELECT COUNT(DISTINCT GUARDID) AS guardsOnDuty, COUNT(DISTINCT SITEID) AS siteCount, COUNT(*) AS scans FROM historydatas WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`, [start, end, ...company.params]);
    const row = rows[0] || {};
    const guardsOnDuty = Number(row.guardsOnDuty || 0);
    const siteCount = Number(row.siteCount || 0);
    const scans = Number(row.scans || 0);
    const expectedActivity = Math.max(guardsOnDuty, siteCount, 1) * daysInMonth;
    const complianceRate = Math.min(100, expectedActivity > 0 ? (scans / expectedActivity) * 100 : 0);
    return [{
      bil: 1,
      companyName: await companyName(companyId),
      approvedGuards: guardsOnDuty,
      guardsOnDuty,
      siteCount,
      complianceRate: `${complianceRate.toFixed(2)}%`,
      kpmGrade: gradeFromCompliance(complianceRate),
    }];
  }
}

async function pkk3Rows(companyId, date) {
  try {
    const company = companyWhere(companyId, 'c');
    return await query(`SELECT ROW_NUMBER() OVER (ORDER BY c.clockin_time) AS bil, g.GUARDNAME AS guardName, g.IDENTITYCARD AS icNo, DATE(c.clockin_time) AS date, TIME(c.clockin_time) AS clockIn, TIME(c.clockout_time) AS clockOut, TIMESTAMPDIFF(HOUR, c.clockin_time, c.clockout_time) AS hoursWorked, 'YA' AS biometric, IFNULL(c.remark, '') AS remarks FROM clocks c LEFT JOIN guards g ON g.GUARDID = c.guardid WHERE DATE(c.clockin_time) = ?${company.clause}`, [date, ...company.params]);
  } catch (_) {
    const [start, end] = dateRange(date);
    const company = companyWhere(companyId);
    const rows = await query(`SELECT GUARDID AS guardId, GUARDNAME AS guardName, MIN(HAPPENTIME) AS clockIn, MAX(HAPPENTIME) AS clockOut, COUNT(*) AS scans FROM historydatas WHERE HAPPENTIME BETWEEN ? AND ?${company.clause} GROUP BY GUARDID, GUARDNAME ORDER BY clockIn`, [start, end, ...company.params]);
    return rows.map((row, index) => ({ bil: index + 1, guardName: row.guardName, icNo: '-', date, clockIn: row.clockIn, clockOut: row.clockOut, hoursWorked: '-', biometric: row.scans > 0 ? 'YA' : 'TIDAK', remarks: `${row.scans} rekod rondaan` }));
  }
}

async function pkk4Rows(companyId, date) {
  const [start, end] = dateRange(date);
  const company = companyWhere(companyId, 'h');
  const rows = await query(`SELECT h.GUARDNAME AS guardName, COALESCE(g.GUARDCODE, h.GUARDID) AS guardCode, h.SITENAME AS siteName, h.HAPPENTIME AS patrolTime, CASE WHEN h.STATUS = 1 THEN 'SELESAI' ELSE 'SEMAKAN' END AS status, h.READERCODE AS deviceCode, COALESCE(h.EVENTINFO, h.REMARK, '') AS remarks FROM historydatas h LEFT JOIN guards g ON g.GUARDID = h.GUARDID WHERE h.HAPPENTIME BETWEEN ? AND ?${company.clause} ORDER BY h.HAPPENTIME ASC LIMIT 1000`, [start, end, ...company.params]);
  return rows.map((row, index) => ({ bil: index + 1, ...row }));
}

async function dailyScorecardPayload(companyId, date) {
  const scorecardRows = firstResultSet(await query('CALL sp_daily_kpm_scorecard(?, ?)', [companyId, date]));
  const scorecard = scorecardRows[0] || {};
  const [start, end] = dateRange(date);
  const company = companyWhere(companyId);
  const [topGuards, sosAlerts] = await Promise.all([
    query(
      `SELECT GUARDID AS guardId, GUARDNAME AS guardName, COUNT(*) AS totalScans
         FROM historydatas
        WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}
        GROUP BY GUARDID, GUARDNAME
        ORDER BY totalScans DESC
        LIMIT 3`,
      [start, end, ...company.params]
    ),
    query(
      `SELECT ID AS alarmId, GUARDNAME AS guardName, SITENAME AS siteName, HAPPENTIME AS happenTime
         FROM alarmdatas
        WHERE ALARMTYPE = 1
          AND DATE(HAPPENTIME) = ?
          AND PUSHED = 0${companyId ? ' AND COMPANYID = ?' : ''}
        ORDER BY HAPPENTIME DESC
        LIMIT 20`,
      companyId ? [date, companyId] : [date]
    ),
  ]);
  return {
    companyName: await companyName(companyId),
    date,
    scorecard,
    topGuards,
    unresolvedSos: sosAlerts,
  };
}

app.get('/api/enormity/reports/pkk2/pdf', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const { month, year } = parseMonthYear(req);
    const buffer = await kpmEngine.pkk2({ companyName: await companyName(companyId), month, year, rows: await pkk2Rows(companyId, month, year) });
    return sendPdf(res, `PKK2_${year}_${String(month).padStart(2, '0')}.pdf`, buffer);
  } catch (err) { return handleRouteError(res, '/api/enormity/reports/pkk2/pdf', err, 'Failed to generate PKK 2 PDF.'); }
});

app.get('/api/enormity/reports/pkk3/pdf', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const date = validateDateParam(req.query.date);
    const buffer = await kpmEngine.pkk3({ companyName: await companyName(companyId), date, rows: await pkk3Rows(companyId, date) });
    return sendPdf(res, `PKK3_${date}.pdf`, buffer);
  } catch (err) { return handleRouteError(res, '/api/enormity/reports/pkk3/pdf', err, 'Failed to generate PKK 3 PDF.'); }
});

app.get('/api/enormity/reports/pkk4/pdf', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const date = validateDateParam(req.query.date);
    const buffer = await kpmEngine.pkk4({ companyName: await companyName(companyId), date, rows: await pkk4Rows(companyId, date) });
    return sendPdf(res, `PKK4_${date}.pdf`, buffer);
  } catch (err) { return handleRouteError(res, '/api/enormity/reports/pkk4/pdf', err, 'Failed to generate PKK 4 PDF.'); }
});

app.get('/api/enormity/reports/bundle/pdf', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const date = validateDateParam(req.query.date);
    const now = new Date(date);
    const month = now.getMonth() + 1;
    const year = now.getFullYear();
    const name = await companyName(companyId);
    const files = [
      { name: `PKK2_${year}_${String(month).padStart(2, '0')}.pdf`, buffer: await kpmEngine.pkk2({ companyName: name, month, year, rows: await pkk2Rows(companyId, month, year) }) },
      { name: `PKK3_${date}.pdf`, buffer: await kpmEngine.pkk3({ companyName: name, date, rows: await pkk3Rows(companyId, date) }) },
      { name: `PKK4_${date}.pdf`, buffer: await kpmEngine.pkk4({ companyName: name, date, rows: await pkk4Rows(companyId, date) }) },
    ];
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="KPM_REPORT_BUNDLE_${date}.zip"`);
    return kpmEngine.bundle(res, files);
  } catch (err) { return handleRouteError(res, '/api/enormity/reports/bundle/pdf', err, 'Failed to generate KPM PDF bundle.'); }
});

app.get('/api/enormity/reports/daily-scorecard', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const date = validateDateParam(req.query.date);
    const buffer = await kpmEngine.dailyScorecard(await dailyScorecardPayload(companyId, date));
    return sendPdf(res, `DAILY_SCORECARD_${date}.pdf`, buffer);
  } catch (err) {
    return handleRouteError(res, '/api/enormity/reports/daily-scorecard', err, 'Failed to generate daily scorecard PDF.');
  }
});

app.get('/api/enormity/reports/archive', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const year = parsePositiveInt(req.query.year, new Date().getFullYear(), 2100);
    if (year < 2000) return fail(res, 400, 'Invalid year.');
    const yearDirs = fs.existsSync(REPORT_ARCHIVE_ROOT) ? fs.readdirSync(REPORT_ARCHIVE_ROOT).filter((name) => name.startsWith(`${year}-`)) : [];
    const reports = [];
    yearDirs.sort().forEach((ym) => {
      const monthDir = path.join(REPORT_ARCHIVE_ROOT, ym);
      fs.readdirSync(monthDir, { withFileTypes: true }).filter((entry) => entry.isDirectory()).forEach((entry) => {
        const cid = Number(entry.name);
        if (companyId && cid !== companyId) return;
        const dir = path.join(monthDir, entry.name);
        const manifestPath = path.join(dir, 'manifest.json');
        let manifest = {};
        try { manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch (_) {}
        reports.push({
          year,
          month: Number(ym.slice(5, 7)),
          companyId: cid,
          companyName: manifest.companyName || null,
          files: ['pkk2.pdf', 'pkk3.pdf', 'pkk4.pdf'].filter((file) => fs.existsSync(path.join(dir, file))),
          generatedAt: manifest.generatedAt || null,
        });
      });
    });
    return ok(res, { companyId, year, reports });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/reports/archive', err, 'Failed to list archived reports.');
  }
});

app.get('/api/enormity/reports/archive/:year/:month/:companyId/pkk4.pdf', async (req, res) => {
  try {
    const year = parsePositiveInt(req.params.year, 0, 2100);
    const month = parsePositiveInt(req.params.month, 0, 12);
    const companyId = parsePositiveInt(req.params.companyId, 0);
    if (!year || year < 2000 || !month || !companyId) return fail(res, 400, 'Invalid archive path.');
    const filePath = archivePath(year, month, companyId, 'pkk4.pdf');
    if (!fs.existsSync(filePath)) return fail(res, 404, 'Archived PKK4 report not found.');
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="PKK4_${year}_${String(month).padStart(2, '0')}_${companyId}.pdf"`);
    return fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    return handleRouteError(res, '/api/enormity/reports/archive/:year/:month/:companyId/pkk4.pdf', err, 'Failed to download archived PKK4 report.');
  }
});

app.post('/api/enormity/reports/kpm', async (req, res) => {
  try {
    const { type, companyId = '', date: requestedDate } = req.body || {};
    const supported = new Set(['pkk2', 'pkk3', 'pkk4']);
    if (!supported.has(type)) {
      return fail(res, 400, "Invalid report type. Expected 'pkk2', 'pkk3', or 'pkk4'.");
    }

    const date = validateDateParam(requestedDate);
    const [start, end] = dateRange(date);
    const company = companyWhere(companyId);

    if (type === 'pkk2') {
      const rows = await query(
        `SELECT GUARDID AS guardId,
                GUARDNAME AS guardName,
                COUNT(*) AS scanCount,
                COUNT(DISTINCT SITEID) AS siteCount,
                MIN(HAPPENTIME) AS firstScan,
                MAX(HAPPENTIME) AS lastScan
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}
          GROUP BY GUARDID, GUARDNAME
          ORDER BY scanCount DESC`,
        [start, end, ...company.params]
      );
      return ok(res, { type, companyId: companyId || null, date, rows });
    }

    if (type === 'pkk3') {
      const rows = await query(
        `SELECT SITEID AS siteId,
                SITENAME AS siteName,
                COUNT(*) AS scanCount,
                COUNT(DISTINCT GUARDID) AS guardCount,
                MIN(HAPPENTIME) AS firstScan,
                MAX(HAPPENTIME) AS lastScan
           FROM historydatas
          WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}
          GROUP BY SITEID, SITENAME
          ORDER BY scanCount DESC`,
        [start, end, ...company.params]
      );
      return ok(res, { type, companyId: companyId || null, date, rows });
    }

    const rows = await query(
      `SELECT r.READERCODE AS readerCode,
              r.COMPANYID AS companyId,
              r.LASTCONTENT AS lastContent,
              r.LASTTIME AS lastTime,
              r.ENDDATE AS licenceExpiry,
              TIMESTAMPDIFF(MINUTE, r.LASTTIME, NOW()) AS minutesSinceLastSeen,
              COUNT(h.ID) AS scanCount
         FROM readers r
    LEFT JOIN historydatas h
           ON h.READERCODE = r.READERCODE
          AND h.HAPPENTIME BETWEEN ? AND ?
        WHERE r.DELETED = 0${companyId ? ' AND r.COMPANYID = ?' : ''}
        GROUP BY r.READERCODE, r.COMPANYID, r.LASTCONTENT, r.LASTTIME, r.ENDDATE
        ORDER BY scanCount DESC, r.LASTTIME DESC`,
      companyId ? [start, end, companyId] : [start, end]
    );

    return ok(res, {
      type,
      companyId: companyId || null,
      date,
      rows: rows.map((row) => ({
        readerCode: row.readerCode,
        companyId: row.companyId,
        lastContent: row.lastContent,
        lastTime: row.lastTime,
        licenceExpiry: row.licenceExpiry,
        status: Number(row.minutesSinceLastSeen) <= 120 ? 'ONLINE' : 'OFFLINE',
        scanCount: Number(row.scanCount),
      })),
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/reports/kpm', err, 'Failed to build KPM report data.');
  }
});

app.post('/api/enormity/devices/:readerCode/notes', async (req, res) => {
  try {
    const readerCode = String(req.params.readerCode || '').trim();
    const note = String(req.body?.note || '').trim();
    const noteType = String(req.body?.noteType || 'GENERAL').trim().toUpperCase();
    const addedBy = String(req.body?.addedBy || req.enormityAuth?.subject || 'nexus-api').trim();
    const companyId = optionalCompanyId(req.body?.companyId);
    if (!readerCode) return fail(res, 400, 'readerCode is required.');
    if (!note) return fail(res, 400, 'note is required.');
    const allowed = new Set(['MAINTENANCE', 'INCIDENT', 'REPLACEMENT', 'GENERAL']);
    if (!allowed.has(noteType)) return fail(res, 400, 'Invalid noteType.');
    await query(
      `INSERT INTO enormity_device_notes (readerCode, companyId, note, noteType, addedBy)
       VALUES (?, ?, ?, ?, ?)`,
      [readerCode, companyId, note, noteType, addedBy]
    );
    return ok(res, { readerCode, companyId, noteType, addedBy });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/devices/:readerCode/notes', err, 'Failed to store device note.');
  }
});

app.get('/api/enormity/devices/:readerCode/notes', async (req, res) => {
  try {
    const readerCode = String(req.params.readerCode || '').trim();
    if (!readerCode) return fail(res, 400, 'readerCode is required.');
    const rows = await query(
      `SELECT id, readerCode, companyId, note, noteType, addedBy, createdAt
         FROM enormity_device_notes
        WHERE readerCode = ?
        ORDER BY createdAt DESC, id DESC`,
      [readerCode]
    );
    return ok(res, { readerCode, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/devices/:readerCode/notes', err, 'Failed to fetch device notes.');
  }
});

app.get('/api/enormity/devices/maintenance-due', async (req, res) => {
  try {
    const companyId = optionalCompanyId(req.query.companyId);
    const days = parsePositiveInt(req.query.days, 90, 365);
    const params = [];
    let sql = `SELECT r.READERCODE AS readerCode,
                      COALESCE(r.NAME, r.LASTCONTENT, r.READERCODE) AS readerName,
                      r.COMPANYID AS companyId,
                      c.COMPANYNAME AS companyName,
                      MAX(n.createdAt) AS lastServiceAt,
                      DATEDIFF(CURDATE(), DATE(MAX(n.createdAt))) AS daysSinceService
                 FROM readers r
            LEFT JOIN companys c ON c.COMPANYID = r.COMPANYID
            LEFT JOIN enormity_device_notes n
                   ON n.readerCode = r.READERCODE
                  AND n.noteType IN ('MAINTENANCE','REPLACEMENT')
                WHERE r.DELETED = 0`;
    if (companyId) {
      sql += ' AND r.COMPANYID = ?';
      params.push(companyId);
    }
    sql += ` GROUP BY r.READERCODE, r.NAME, r.LASTCONTENT, r.COMPANYID, c.COMPANYNAME
              HAVING lastServiceAt IS NULL OR lastServiceAt < DATE_SUB(NOW(), INTERVAL ? DAY)
              ORDER BY lastServiceAt IS NULL DESC, lastServiceAt ASC
              LIMIT 500`;
    params.push(days);
    const rows = await query(sql, params);
    return ok(res, { companyId, days, rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/devices/maintenance-due', err, 'Failed to fetch maintenance due devices.');
  }
});

const wsServer = http.createServer();
const wss = new WebSocket.Server({ server: wsServer, maxPayload: 1024, perMessageDeflate: false });
let lastScanId = 0;
let lastAlarmId = 0;
let lastEscalationId = 0;

function broadcast(event) {
  const payload = JSON.stringify(event);
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN && canReceiveRealtimeEvent(client.nexusCompanyId, event.companyId)) {
      try {
        client.send(payload);
      } catch (err) {
        console.error('[Enormity] WebSocket broadcast failed:', err.message);
      }
    }
  }
}

wss.on('connection', (socket, request) => {
  let ticketRecord = null;
  try {
    const url = new URL(request.url || '/', 'ws://enormity-sidecar.internal');
    ticketRecord = consumeRealtimeTicket(url.searchParams.get('ticket'));
  } catch (_) {
    ticketRecord = null;
  }
  if (!ticketRecord) {
    socket.close(1008, 'A valid one-time realtime ticket is required.');
    return;
  }
  socket.nexusCompanyId = ticketRecord.global ? null : ticketRecord.companyId;
  socket.isAlive = true;
  socket.on('pong', () => {
    socket.isAlive = true;
  });
  socket.on('message', () => socket.close(1008, 'Realtime connections are read-only.'));
  socket.send(JSON.stringify({
    event: 'CONNECTED',
    service: 'enormity-realtime',
    scope: ticketRecord.global ? 'global' : 'company',
    companyId: ticketRecord.companyId,
    timestamp: timestamp(),
  }));
});

function heartbeatWebSocketClients() {
  for (const client of wss.clients) {
    if (client.isAlive === false) {
      client.terminate();
      continue;
    }
    client.isAlive = false;
    try {
      client.ping();
    } catch (err) {
      client.terminate();
    }
  }
}

async function initialiseRealtimeCursors() {
  try {
    const scanRows = await query('SELECT COALESCE(MAX(ID), 0) AS id FROM historydatas');
    const alarmRows = await query('SELECT COALESCE(MAX(ID), 0) AS id FROM alarmdatas');
    const escalationRows = await query('SELECT COALESCE(MAX(escalation_id), 0) AS id FROM enormity_escalations');
    lastScanId = Number(scanRows[0]?.id || 0);
    lastAlarmId = Number(alarmRows[0]?.id || 0);
    lastEscalationId = Number(escalationRows[0]?.id || 0);
  } catch (err) {
    console.error('realtime cursor init failed:', err.message);
  }
}

async function pollPatrolScans() {
  let rows = [];
  try {
    rows = await query(
      `SELECT ID AS id,
              COMPANYID AS companyId,
              GUARDNAME AS guardName,
              SITENAME AS siteName,
              HAPPENTIME AS happenTime,
              LATITUDE AS latitude,
              LONGITUDE AS longitude
         FROM historydatas
        WHERE ID > ?
        ORDER BY ID ASC
        LIMIT 100`,
      [lastScanId]
    );
    for (const row of rows) {
      lastScanId = Math.max(lastScanId, Number(row.id));
      broadcast({
        event: 'NEW_PATROL_SCAN',
        companyId: row.companyId,
        guardName: row.guardName,
        siteName: row.siteName,
        happenTime: row.happenTime,
        latitude: row.latitude === null ? null : Number(row.latitude),
        longitude: row.longitude === null ? null : Number(row.longitude),
      });
    }
  } catch (err) {
    console.error('patrol scan poll failed:', err.message);
  } finally {
    rows = null;
  }
}

async function pollAlarmRows() {
  let rows = [];
  try {
    rows = await query(
      `SELECT ID AS alarmId,
              COMPANYID AS companyId,
              ALARMTYPE AS alarmType,
              ALARMINFO AS alarmInfo,
              GUARDNAME AS guardName,
              SITENAME AS siteName,
              READERCODE AS readerCode,
              HAPPENTIME AS happenTime
         FROM alarmdatas
        WHERE ID > ?
        ORDER BY ID ASC
        LIMIT 100`,
      [lastAlarmId]
    );
    for (const row of rows) {
      lastAlarmId = Math.max(lastAlarmId, Number(row.alarmId));
      broadcast({
        event: 'NEW_ALARM',
        alarmId: row.alarmId,
        companyId: row.companyId,
        alarmType: row.alarmType,
        alarmInfo: row.alarmInfo,
        guardName: row.guardName,
        siteName: row.siteName,
        readerCode: row.readerCode,
        severity: Number(row.alarmType) === 1 ? 'CRITICAL' : 'WARNING',
        createdAt: row.happenTime,
      });
    }
  } catch (err) {
    console.error('raw alarm poll failed:', err.message);
  } finally {
    rows = null;
  }
}

async function sendTelegramAlert(escalation) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  const message = [
    'SOS ALERT',
    `Guard: ${escalation.guardName || 'Unknown'}`,
    `Site: ${escalation.siteName || 'Unknown'}`,
    `Company: ${escalation.companyId || 'Unknown'}`,
    `Time: ${escalation.createdAt || timestamp()}`,
    'Action required: Acknowledge at nexus.enormity.tech',
  ].join('\n');
  await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
    chat_id: TELEGRAM_CHAT_ID,
    text: message,
  }, { timeout: 5000 });
}

async function pollCriticalSosAlarms() {
  let rows = [];
  try {
    rows = await query(
      `SELECT a.ID AS alarmId,
              a.COMPANYID AS companyId,
              a.ALARMTYPE AS alarmType,
              a.GUARDNAME AS guardName,
              a.SITENAME AS siteName,
              a.HAPPENTIME AS happenTime
         FROM alarmdatas a
    LEFT JOIN enormity_escalations e ON e.alarm_id = a.ID
        WHERE a.ALARMTYPE = 1
          AND e.escalation_id IS NULL
          AND a.HAPPENTIME >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        ORDER BY a.ID ASC
        LIMIT 50`
    );
    for (const row of rows) {
      await query(
        `INSERT IGNORE INTO enormity_escalations
          (alarm_id, companyid, alarm_type, guard_name, site_name, severity, status, requiresAck, created_at)
         VALUES (?, ?, ?, ?, ?, 'CRITICAL', 'ACTIVE', 1, NOW())`,
        [row.alarmId, row.companyId, row.alarmType, row.guardName, row.siteName]
      );
      const escalation = {
        escalationId: row.alarmId,
        alarmId: row.alarmId,
        companyId: row.companyId,
        alarmType: row.alarmType,
        guardName: row.guardName,
        siteName: row.siteName,
        severity: 'CRITICAL',
        createdAt: row.happenTime,
      };
      // pollAlarmRows is the single read-only source for raw alarm events.
      sendTelegramAlert(escalation).catch((err) => console.error('telegram sos failed:', err.message));
    }
  } catch (err) {
    console.error('critical sos poll failed:', err.message);
  } finally {
    rows = null;
  }
}

async function pollEscalations() {
  let rows = [];
  try {
    rows = await query(
      `SELECT escalation_id AS escalationId,
              alarm_id AS alarmId,
              companyid AS companyId,
              alarm_type AS alarmType,
              guard_name AS guardName,
              site_name AS siteName,
              severity,
              status,
              created_at AS createdAt
         FROM enormity_escalations
        WHERE escalation_id > ?
        ORDER BY escalation_id ASC
        LIMIT 100`,
      [lastEscalationId]
    );
    for (const row of rows) {
      lastEscalationId = Math.max(lastEscalationId, Number(row.escalationId));
      broadcast({
        event: 'NEW_ALARM',
        companyId: row.companyId,
        alarmType: row.alarmType,
        guardName: row.guardName,
        severity: row.severity,
        siteName: row.siteName,
        createdAt: row.createdAt,
      });
      if (row.severity === 'CRITICAL' && !notifiedEscalations.has(row.escalationId)) {
        notifiedEscalations.add(row.escalationId);
        sendTelegramAlert(row).catch((err) => console.error('telegram alert failed:', err.message));
      }
    }
  } catch (err) {
    console.error('alarm poll failed:', err.message);
  } finally {
    rows = null;
  }
}

app.use((req, res) => {
  fail(res, 404, `Route not found: ${req.method} ${req.originalUrl}`);
});

async function validateStartup() {
  const missing = [];
  if (!JWT_SECRET) missing.push('JWT_SECRET');
  if (VALID_API_KEYS.length === 0) missing.push('ENORMITY_API_KEYS');
  if (!process.env.MYSQL_HOST) missing.push('MYSQL_HOST');
  if (!process.env.MYSQL_USER) missing.push('MYSQL_USER');
  if (!process.env.MYSQL_DATABASE) missing.push('MYSQL_DATABASE');
  if (missing.length) throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  validateNexusSourceModes();
  const databaseHealth = await getDatabaseHealth();
  if (!databaseHealth.connected) throw new Error('Database startup check failed.');
  const redisHealth = await getRedisHealth();
  if (!redisHealth.connected) throw new Error('Redis startup check failed.');
  if (NEXUS_DB_IDENTITY_STRICT) {
    const identityStatus = nexusDbIdentityStatus();
    if (!identityStatus.allConfigured || !identityStatus.distinctUsers) throw new Error('Dedicated Nexus database identities are incomplete or reused.');
    await Promise.all(nexusDbRoles.map(async (role) => {
      const rolePool = nexusPoolForRole(role);
      await rolePool.query({ sql: 'SELECT 1', timeout: QUERY_TIMEOUT_MS });
    }));
  }
  console.log(`[Enormity] Startup checks passed: db=${databaseHealth.latencyMs}ms redis=${redisHealth.latencyMs}ms`);
}

let server;
function trackInterval(handle) {
  intervalHandles.push(handle);
  return handle;
}

function waitForInflight(maxMs) {
  const started = Date.now();
  return new Promise((resolve) => {
    const timer = setInterval(() => {
      if (inFlightRequests <= 0 || Date.now() - started >= maxMs) {
        clearInterval(timer);
        resolve();
      }
    }, 250);
  });
}

validateStartup().then(() => {
  server = app.listen(PORT, BIND_HOST, () => {
    console.log(`Enormity sidecar API listening on http://${BIND_HOST}:${PORT}`);
  });

  wsServer.listen(WS_PORT, BIND_HOST, async () => {
    await initialiseRealtimeCursors();
    trackInterval(setInterval(pollPatrolScans, 10000));
    trackInterval(setInterval(pollAlarmRows, 5000));
    if (BACKGROUND_WRITES_ENABLED) {
      trackInterval(setInterval(pollCriticalSosAlarms, 5000));
      trackInterval(setInterval(pollEscalations, 5000));
      trackInterval(setInterval(cleanupAuditLogs, 60000));
      trackInterval(setInterval(() => runMonthlyArchiveScheduler(false).catch((err) => console.error('[Enormity] archive scheduler failed:', err.message)), 60000));
    }
    trackInterval(setInterval(heartbeatWebSocketClients, 30000));
    trackInterval(setInterval(cleanupRealtimeTickets, 30000));
    console.log(`Enormity realtime WebSocket listening on ws://${BIND_HOST}:${WS_PORT}`);
  });
}).catch((err) => {
  console.error('[Enormity] Startup validation failed:', err.message);
  process.exit(1);
});

process.on('SIGTERM', async () => {
  if (shuttingDown) return;
  shuttingDown = true;
  acceptingRequests = false;
  console.log(`[Enormity] SIGTERM received - graceful shutdown started inFlight=${inFlightRequests}`);
  intervalHandles.forEach((handle) => clearInterval(handle));
  await new Promise((resolve) => {
    if (!server) return resolve();
    server.close(resolve);
  });
  await new Promise((resolve) => {
    try { wsServer.close(resolve); } catch (_) { resolve(); }
  });
  await waitForInflight(30000);
  try { await pool.end(); console.log('[Enormity] MySQL pool closed cleanly'); } catch (err) { console.error('[Enormity] pool close failed:', err.message); }
  try {
    if (redisReady) {
      await redis.quit();
      console.log('[Enormity] Redis connection closed cleanly');
    }
  } catch (err) {
    console.error('[Enormity] redis close failed:', err.message);
  }
  console.log('[Enormity] Server closed cleanly');
  process.exit(0);
});
