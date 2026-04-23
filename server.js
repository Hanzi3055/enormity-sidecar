require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2/promise');
const kpmEngine = require('./kpm-engine');

const app = express();
const startedAt = Date.now();
const PORT = Number(process.env.PORT || 3100);
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-before-production';
const VALID_API_KEYS = String(process.env.ENORMITY_API_KEYS || '').split(',').map((key) => key.trim()).filter(Boolean);

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

app.disable('x-powered-by');
app.use(helmet());
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, max: 100, standardHeaders: true, legacyHeaders: false }));

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

function fail(res, status, message, details) {
  const payload = { success: false, error: { message }, timestamp: timestamp() };
  if (details) payload.error.details = details;
  return res.status(status).json(payload);
}

function parsePositiveInt(value, fallback, max) {
  const parsed = Number.parseInt(String(value || ''), 10);
  const safe = Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
  return max ? Math.min(safe, max) : safe;
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

function companyWhere(companyId, alias) {
  if (!companyId) return { clause: '', params: [] };
  const column = alias ? `${alias}.COMPANYID` : 'COMPANYID';
  return { clause: ` AND ${column} = ?`, params: [companyId] };
}

async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

async function checkDatabase() {
  const rows = await query('SELECT 1 AS ok');
  return rows[0] && rows[0].ok === 1;
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
      `INSERT INTO enormity_audit_log (event_type, ip_address, success, reason, endpoint, request_params, response_code, response_time_ms, created_at)
       VALUES (?, ?, ?, ?, ?, CAST(? AS JSON), ?, ?, NOW())`,
      [req.enormityAuth ? 'sidecar_authenticated_request' : 'sidecar_public_request', clientIp(req), res.statusCode < 400 ? 1 : 0, req.enormityAuth?.subject || null, req.originalUrl.split('?')[0], params, res.statusCode, Math.round(durationMs)]
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
  const apiKey = req.body?.apiKey;
  if (!apiKey || !VALID_API_KEYS.includes(apiKey)) {
    return fail(res, 401, 'Invalid API key.');
  }
  const token = jwt.sign({ subject: 'enormity-sidecar-client', scope: 'api:enormity' }, JWT_SECRET, { expiresIn: '24h' });
  return ok(res, { token, tokenType: 'Bearer', expiresInSeconds: 86400 });
}


app.get('/api/enormity/health', async (req, res) => {
  const dbStart = Date.now();
  try {
    const databaseConnected = await checkDatabase();
    return ok(res, {
      service: 'enormity-sidecar',
      uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
      memory: process.memoryUsage(),
      database: {
        connected: databaseConnected,
        host: process.env.MYSQL_HOST || '127.0.0.1',
        port: Number(process.env.MYSQL_PORT || 13306),
        database: process.env.MYSQL_DATABASE || 'cloudpatrol',
        latencyMs: Date.now() - dbStart,
      },
      node: process.version,
      timestamp: timestamp(),
    });
  } catch (err) {
    return fail(res, 503, 'Database health check failed.', err.message);
  }
});

app.post('/api/enormity/auth/token', requireApiKey);
app.use('/api/enormity', authenticateJwt);

app.get('/api/enormity/patrol/summary', async (req, res) => {
  try {
    const date = validateDateParam(req.query.date);
    const companyId = req.query.companyId || '';
    const [start, end] = dateRange(date);
    const company = companyWhere(companyId);

    const [totals, hourlyRows, topGuards, topSites] = await Promise.all([
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
    ]);

    const hourlyMap = new Map(hourlyRows.map((row) => [Number(row.hour), Number(row.count)]));
    const hourlyBreakdown = Array.from({ length: 24 }, (_, hour) => ({
      hour,
      count: hourlyMap.get(hour) || 0,
    }));

    return ok(res, {
      date,
      companyId: companyId || null,
      totalScans: Number(totals[0].totalScans || 0),
      activeGuards: Number(totals[0].activeGuards || 0),
      activeSites: Number(totals[0].activeSites || 0),
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
    });
  } catch (err) {
    return fail(res, err.status || 500, 'Failed to build patrol summary.', err.message);
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
    return fail(res, 500, 'Failed to fetch live patrol records.', err.message);
  }
});

app.get('/api/enormity/guards/efficiency', async (req, res) => {
  try {
    const date = validateDateParam(req.query.date);
    const companyId = req.query.companyId || '';
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

    return ok(res, rows.map((row) => {
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
    }));
  } catch (err) {
    return fail(res, err.status || 500, 'Failed to compute guard efficiency.', err.message);
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
    return fail(res, 500, 'Failed to fetch device status.', err.message);
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
    return fail(res, 500, 'Failed to build analytics heatmap.', err.message);
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
    return data.map((row, index) => ({
      bil: index + 1,
      companyName: row.companyName || row.company_name || row.NamaSyarikat || row.COMPANYNAME || `Company ${companyId}`,
      approvedGuards: row.approvedGuards || row.approved_guards || row.BilanganPengawalDiluluskan || row.approved || '-',
      guardsOnDuty: row.guardsOnDuty || row.guards_on_duty || row.BilanganPengawalBertugas || row.activeGuards || '-',
      siteCount: row.siteCount || row.site_count || row.BilanganTapakKawalan || row.activeSites || '-',
      complianceRate: `${Number(row.complianceRate || row.compliance_rate || row.PeratusanPematuhan || row.compliance || 0).toFixed(2)}%`,
    }));
  } catch (_) {
    const start = `${year}-${String(month).padStart(2, '0')}-01 00:00:00`;
    const end = `${year}-${String(month).padStart(2, '0')}-31 23:59:59`;
    const company = companyWhere(companyId);
    const rows = await query(`SELECT COUNT(DISTINCT GUARDID) AS guardsOnDuty, COUNT(DISTINCT SITEID) AS siteCount, COUNT(*) AS scans FROM historydatas WHERE HAPPENTIME BETWEEN ? AND ?${company.clause}`, [start, end, ...company.params]);
    const row = rows[0] || {};
    return [{ bil: 1, companyName: await companyName(companyId), approvedGuards: row.guardsOnDuty || 0, guardsOnDuty: row.guardsOnDuty || 0, siteCount: row.siteCount || 0, complianceRate: row.scans > 0 ? '100.00%' : '0.00%' }];
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
  const rows = await query(`SELECT h.GUARDNAME AS guardName, COALESCE(g.GUARDCODE, h.GUARDID) AS guardCode, h.SITENAME AS siteName, h.HAPPENTIME AS patrolTime, CASE WHEN h.STATUS = 1 THEN 'SELESAI' ELSE 'SEMAKAN' END AS status, COALESCE(h.EVENTINFO, h.REMARK, '') AS remarks FROM historydatas h LEFT JOIN guards g ON g.GUARDID = h.GUARDID WHERE h.HAPPENTIME BETWEEN ? AND ?${company.clause} ORDER BY h.HAPPENTIME ASC LIMIT 1000`, [start, end, ...company.params]);
  return rows.map((row, index) => ({ bil: index + 1, ...row }));
}

app.get('/api/enormity/reports/pkk2/pdf', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const { month, year } = parseMonthYear(req);
    const buffer = await kpmEngine.pkk2({ companyName: await companyName(companyId), month, year, rows: await pkk2Rows(companyId, month, year) });
    return sendPdf(res, `PKK2_${year}_${String(month).padStart(2, '0')}.pdf`, buffer);
  } catch (err) { return fail(res, err.status || 500, 'Failed to generate PKK 2 PDF.', err.message); }
});

app.get('/api/enormity/reports/pkk3/pdf', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const date = validateDateParam(req.query.date);
    const buffer = await kpmEngine.pkk3({ companyName: await companyName(companyId), date, rows: await pkk3Rows(companyId, date) });
    return sendPdf(res, `PKK3_${date}.pdf`, buffer);
  } catch (err) { return fail(res, err.status || 500, 'Failed to generate PKK 3 PDF.', err.message); }
});

app.get('/api/enormity/reports/pkk4/pdf', async (req, res) => {
  try {
    const companyId = req.query.companyId || '';
    const date = validateDateParam(req.query.date);
    const buffer = await kpmEngine.pkk4({ companyName: await companyName(companyId), date, rows: await pkk4Rows(companyId, date) });
    return sendPdf(res, `PKK4_${date}.pdf`, buffer);
  } catch (err) { return fail(res, err.status || 500, 'Failed to generate PKK 4 PDF.', err.message); }
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
  } catch (err) { return fail(res, err.status || 500, 'Failed to generate KPM PDF bundle.', err.message); }
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
    return fail(res, err.status || 500, 'Failed to build KPM report data.', err.message);
  }
});

app.use((req, res) => {
  fail(res, 404, `Route not found: ${req.method} ${req.originalUrl}`);
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`Enormity sidecar API listening on http://127.0.0.1:${PORT}`);
});
