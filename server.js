require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const WebSocket = require('ws');
const Redis = require('ioredis');
const axios = require('axios');
const kpmEngine = require('./kpm-engine');

process.on('uncaughtException', (err) => {
  console.error('[Enormity] Uncaught exception:', err && err.message, err && err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[Enormity] Unhandled rejection at:', promise, 'reason:', reason);
});

const app = express();
const startedAt = Date.now();
const PORT = Number(process.env.PORT || 3100);
const WS_PORT = Number(process.env.WS_PORT || 3101);
const JWT_SECRET = String(process.env.JWT_SECRET || '').trim();
const VALID_API_KEYS = String(process.env.ENORMITY_API_KEYS || '').split(',').map((key) => key.trim()).filter(Boolean);
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || process.env.TELEGRAM_TOKEN || '';
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID || process.env.TELEGRAM_CHAT || '';

if (!JWT_SECRET) {
  throw new Error('JWT_SECRET is required for Enormity sidecar startup.');
}

if (VALID_API_KEYS.length === 0) {
  throw new Error('ENORMITY_API_KEYS must contain at least one API key.');
}

const pool = mysql.createPool({
  host: process.env.MYSQL_HOST || '127.0.0.1',
  port: Number(process.env.MYSQL_PORT || 13306),
  user: process.env.MYSQL_USER || 'root',
  password: process.env.MYSQL_PASSWORD || '',
  database: process.env.MYSQL_DATABASE || 'cloudpatrol',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  timezone: 'local',
  dateStrings: false,
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
const notifiedEscalations = new Set();
let shuttingDown = false;

app.disable('x-powered-by');
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false }));

app.use((req, res, next) => {
  const start = process.hrtime.bigint();
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

async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
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
  if (!req.originalUrl.startsWith('/api/enormity/')) return;
  try {
    await ensureAuditTable();
    const params = JSON.stringify({ query: req.query || {}, body: sanitizeAuditBody(req.body || {}) });
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

function sanitizeAuditBody(body) {
  const clean = { ...body };
  if (clean.apiKey) clean.apiKey = '[redacted]';
  if (clean.password) clean.password = '[redacted]';
  return clean;
}

function authenticateJwt(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return fail(res, 401, 'Missing bearer token.');
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.enormityAuth = decoded;
    return next();
  } catch (err) {
    return fail(res, 401, 'Invalid or expired bearer token.', err.message);
  }
}

function requireApiKey(req, res) {
  const rawApiKey = String(req.body?.apiKey || '').trim();
  const providedKeys = rawApiKey.split(',').map((item) => item.trim()).filter(Boolean);
  const matchedKey = providedKeys.find((candidate) => VALID_API_KEYS.includes(candidate));
  if (!matchedKey) {
    return fail(res, 401, 'Invalid API key.');
  }
  const token = jwt.sign({ subject: 'enormity-sidecar-client', scope: 'api:enormity' }, JWT_SECRET, { expiresIn: '24h' });
  return ok(res, { token, tokenType: 'Bearer', expiresInSeconds: 86400 });
}


app.get('/api/enormity/health', async (req, res) => {
  const dbStart = Date.now();
  try {
    const date = todayString();
    const [databaseConnected, redisHealth, patrolStats] = await Promise.all([
      checkDatabase(),
      getRedisHealth(),
      getPatrolStats(date),
    ]);
    const memoryUsage = process.memoryUsage();
    const uptimeSeconds = Math.floor(process.uptime());
    return ok(res, {
      service: 'enormity-sidecar',
      version: '3.0.0',
      environment: process.env.NODE_ENV || 'production',
      uptimeSeconds,
      uptimeHuman: formatUptime(uptimeSeconds),
      memory: {
        rss: memoryMb(memoryUsage.rss),
        heapUsed: memoryMb(memoryUsage.heapUsed),
        heapTotal: memoryMb(memoryUsage.heapTotal),
      },
      database: {
        connected: databaseConnected,
        host: process.env.MYSQL_HOST || '127.0.0.1',
        port: Number(process.env.MYSQL_PORT || 13306),
        database: process.env.MYSQL_DATABASE || 'cloudpatrol',
        latencyMs: Date.now() - dbStart,
      },
      redis: redisHealth,
      patrolStats,
      node: process.version,
      timestamp: timestamp(),
    });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/health', err, 'Database health check failed.');
  }
});

app.get('/api/enormity/health/db', async (req, res) => {
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

    return ok(res, {
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

app.get('/api/enormity/status/overview', async (req, res) => {
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

app.get('/api/enormity/status/containers', (req, res) => {
  try {
    const output = execSync("docker ps --format '{{.Names}}|{{.Status}}|{{.Ports}}'", { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const rows = output.trim().split('\n').filter(Boolean).map((line) => {
      const parts = line.split('|');
      return { name: parts[0] || '', status: parts[1] || '', ports: parts[2] || '' };
    });
    return ok(res, { rows });
  } catch (err) {
    return handleRouteError(res, '/api/enormity/status/containers', err, 'Failed to read docker container status.');
  }
});

app.post('/api/enormity/auth/token', requireApiKey);
app.get('/api/enormity/docs', (req, res) => {
  const specPath = path.join(__dirname, 'openapi.yaml');
  if (!fs.existsSync(specPath)) return fail(res, 404, 'OpenAPI specification has not been generated yet.');
  res.type('text/yaml');
  return res.send(fs.readFileSync(specPath, 'utf8'));
});

app.get('/api/enormity/company/list', async (req, res) => {
  try {
    const rows = await query(
      `SELECT COMPANYID AS id,
              COMPANYNAME AS companyName,
              COMPANYCODE AS companyCode
         FROM companys
        WHERE IFNULL(IS_Effective, 1) <> 0
        ORDER BY COMPANYNAME ASC`
    );
    return ok(res, rows);
  } catch (err) {
    return handleRouteError(res, '/api/enormity/company/list', err, 'Failed to fetch company list.');
  }
});

app.use('/api/enormity', authenticateJwt);

app.get('/api/enormity/audit/logs', async (req, res) => {
  try {
    const days = parsePositiveInt(req.query.days, 7, 90);
    const limit = parsePositiveInt(req.query.limit, 100, 500);
    const eventType = String(req.query.eventType || '').trim();
    const params = [days];
    let sql = `SELECT id, event_type, endpoint, user_name, ip_address, success, response_code, response_time_ms, reason, created_at
                 FROM enormity_audit_log
                WHERE created_at >= DATE_SUB(NOW(), INTERVAL ? DAY)`;
    if (eventType) {
      sql += ' AND event_type = ?';
      params.push(eventType);
    }
    sql += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);
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
    if (!connected) return ok(res, { connected: false, hitRate: 0, totalKeys: 0, memoryUsed: null, topKeys: [] });
    const total = cacheCounters.hits + cacheCounters.misses;
    const [dbSize, info, keys] = await Promise.all([
      redis.dbsize(),
      redis.info('memory'),
      redis.keys('*').then((items) => items.slice(0, 25)),
    ]);
    const memoryLine = String(info).split('\n').find((line) => line.startsWith('used_memory_human:')) || '';
    return ok(res, {
      connected: true,
      hits: cacheCounters.hits,
      misses: cacheCounters.misses,
      hitRate: total ? Number(((cacheCounters.hits / total) * 100).toFixed(2)) : 0,
      totalKeys: dbSize,
      memoryUsed: memoryLine.split(':')[1]?.trim() || null,
      topKeys: keys,
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

app.post('/api/enormity/alerts/:id/acknowledge', async (req, res) => {
  try {
    const id = parsePositiveInt(req.params.id, 0);
    if (!id) return fail(res, 400, 'Invalid escalation id.');
    const acknowledgedBy = req.enormityAuth?.subject || req.body?.acknowledgedBy || 'nexus-api';
    await query(
      `UPDATE enormity_escalations
          SET requiresAck = 0,
              status = 'ACKNOWLEDGED',
              acknowledged_at = NOW(),
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

const wsServer = http.createServer();
const wss = new WebSocket.Server({ server: wsServer });
let lastScanId = 0;
let lastEscalationId = 0;

function broadcast(event) {
  const payload = JSON.stringify(event);
  for (const client of wss.clients) {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(payload);
      } catch (err) {
        console.error('[Enormity] WebSocket broadcast failed:', err.message);
      }
    }
  }
}

wss.on('connection', (socket) => {
  socket.send(JSON.stringify({ event: 'CONNECTED', service: 'enormity-realtime', timestamp: timestamp() }));
});

async function initialiseRealtimeCursors() {
  try {
    const scanRows = await query('SELECT COALESCE(MAX(ID), 0) AS id FROM historydatas');
    const escalationRows = await query('SELECT COALESCE(MAX(escalation_id), 0) AS id FROM enormity_escalations');
    lastScanId = Number(scanRows[0]?.id || 0);
    lastEscalationId = Number(escalationRows[0]?.id || 0);
  } catch (err) {
    console.error('realtime cursor init failed:', err.message);
  }
}

async function pollPatrolScans() {
  try {
    const rows = await query(
      `SELECT ID AS id,
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
        guardName: row.guardName,
        siteName: row.siteName,
        happenTime: row.happenTime,
        latitude: row.latitude === null ? null : Number(row.latitude),
        longitude: row.longitude === null ? null : Number(row.longitude),
      });
    }
  } catch (err) {
    console.error('patrol scan poll failed:', err.message);
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

async function pollEscalations() {
  try {
    const rows = await query(
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
           OR (requiresAck = 1 AND status = 'ACTIVE' AND severity = 'CRITICAL')
        ORDER BY escalation_id ASC
        LIMIT 100`,
      [lastEscalationId]
    );
    for (const row of rows) {
      lastEscalationId = Math.max(lastEscalationId, Number(row.escalationId));
      broadcast({
        event: 'NEW_ALARM',
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
  }
}

app.use((req, res) => {
  fail(res, 404, `Route not found: ${req.method} ${req.originalUrl}`);
});

const server = app.listen(PORT, '127.0.0.1', () => {
  console.log(`Enormity sidecar API listening on http://127.0.0.1:${PORT}`);
});

wsServer.listen(WS_PORT, '127.0.0.1', async () => {
  await initialiseRealtimeCursors();
  setInterval(pollPatrolScans, 10000);
  setInterval(pollEscalations, 5000);
  console.log(`Enormity realtime WebSocket listening on ws://127.0.0.1:${WS_PORT}`);
});

process.on('SIGTERM', async () => {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('[Enormity] SIGTERM received - closing server gracefully');
  wsServer.close(() => console.log('[Enormity] WebSocket server closed cleanly'));
  server.close(async () => {
    try { await pool.end(); } catch (err) { console.error('[Enormity] pool close failed:', err.message); }
    try { if (redisReady) await redis.quit(); } catch (err) { console.error('[Enormity] redis close failed:', err.message); }
    console.log('[Enormity] Server closed cleanly');
    process.exit(0);
  });
  setTimeout(() => process.exit(0), 5000).unref();
});
