'use strict';

// Read-only integration probe for the internal Nexus Core V2 contracts.
// It intentionally reports only booleans, counts, status codes, and field
// names. Entity names, coordinates, credentials, and biometric data are never
// printed. Run this only against an explicitly approved test or read-only
// environment.

const mysql = require('mysql2/promise');

const baseUrl = String(process.env.NEXUS_CORE_QA_BASE_URL || 'http://127.0.0.1:3100').replace(/\/$/, '');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function jsonRequest(path, init = {}) {
  const response = await fetch(`${baseUrl}${path}`, init);
  const body = await response.json().catch(() => ({}));
  return { response, body };
}

async function fixture(pool) {
  const [locationRows] = await pool.execute(
    `SELECT d.COMPANYID AS companyId,
            g.DEPTID AS deptId,
            g.GUARDID AS guardId,
            g.GUARDNAME AS searchValue
       FROM guards g
       JOIN depts d ON d.DEPTID = g.DEPTID
      WHERE CHAR_LENGTH(TRIM(g.GUARDNAME)) BETWEEN 2 AND 80
      ORDER BY g.GUARDID
      LIMIT 1`
  );
  assert(locationRows.length === 1, 'A read-only guard fixture is required.');

  const [companyRows] = await pool.execute(
    `SELECT COMPANYID AS companyId
       FROM companys
      WHERE COMPANYID <> ?
      ORDER BY COMPANYID
      LIMIT 1`,
    [locationRows[0].companyId]
  );

  return {
    companyId: Number(locationRows[0].companyId),
    deptId: Number(locationRows[0].deptId),
    guardId: Number(locationRows[0].guardId),
    searchValue: String(locationRows[0].searchValue),
    otherCompanyId: companyRows.length ? Number(companyRows[0].companyId) : null,
  };
}

async function main() {
  const apiKey = String(process.env.ENORMITY_API_KEYS || '').split(',').map((value) => value.trim()).find(Boolean);
  assert(apiKey, 'ENORMITY_API_KEYS is required.');

  const pool = mysql.createPool({
    host: process.env.MYSQL_HOST || '127.0.0.1',
    port: Number(process.env.MYSQL_PORT || 3306),
    user: process.env.MYSQL_USER,
    password: process.env.MYSQL_PASSWORD,
    database: process.env.MYSQL_DATABASE || 'cloudpatrol',
    connectionLimit: 1,
  });

  try {
    const testFixture = await fixture(pool);
    const tokenResult = await jsonRequest('/api/enormity/auth/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ apiKey, client: 'nexus-core-contract-qa' }),
    });
    assert(tokenResult.response.status === 200 && tokenResult.body?.data?.token, 'Service token exchange failed.');
    const authorization = `Bearer ${tokenResult.body.data.token}`;

    const locationResult = await jsonRequest('/api/enormity/nexus/v2/locations/search', {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({
        companyId: testFixture.companyId,
        query: testFixture.searchValue,
        entityType: 'guard',
      }),
    });
    assert(locationResult.response.status === 200, 'Location contract failed.');
    assert(locationResult.response.headers.get('x-nexus-data-source') === 'cloudpatrol-mysql-direct', 'Location source header is missing.');
    const matches = locationResult.body?.data?.matches;
    assert(Array.isArray(matches) && matches.length > 0 && matches.length <= 5, 'Location results are not bounded.');
    assert(matches.every((row) => String(row.entityType) === 'guard'), 'Location entity filter was not preserved.');
    assert(matches.every((row) => !('template' in row) && !('Feather' in row) && !('password' in row)), 'Sensitive location field detected.');

    let crossCompanyResult = 'not-applicable';
    if (testFixture.otherCompanyId) {
      const hostileResult = await jsonRequest('/api/enormity/nexus/v2/locations/search', {
        method: 'POST',
        headers: { authorization, 'content-type': 'application/json' },
        body: JSON.stringify({
          companyId: testFixture.otherCompanyId,
          query: testFixture.searchValue,
          entityType: 'guard',
        }),
      });
      assert(hostileResult.response.status === 200, 'Cross-company isolation probe failed.');
      const hostileMatches = hostileResult.body?.data?.matches;
      assert(Array.isArray(hostileMatches), 'Cross-company response is malformed.');
      crossCompanyResult = hostileMatches.length === 0 ? 'isolated' : 'name-collision-only';
    }

    const metricsResult = await jsonRequest('/api/enormity/nexus/v2/assistant/metrics', {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({
        companyId: testFixture.companyId,
        tools: ['attendance_summary', 'patrol_completion_summary'],
        dateFrom: '2026-01-01',
        dateTo: '2026-12-31',
      }),
    });
    assert(metricsResult.response.status === 200, 'Assistant metrics contract failed.');
    assert(metricsResult.response.headers.get('x-nexus-data-source') === 'cloudpatrol-mysql-direct', 'Metrics source header is missing.');
    assert(metricsResult.body?.data?.scope?.companyId === testFixture.companyId, 'Metrics scope differs from the requested server scope.');

    const secondMetricsResult = await jsonRequest('/api/enormity/nexus/v2/assistant/metrics', {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({
        companyId: testFixture.companyId,
        tools: ['shift_summary', 'fingerprint_metadata'],
        dateFrom: '2026-01-01',
        dateTo: '2026-12-31',
      }),
    });
    assert(secondMetricsResult.response.status === 200, 'Secondary assistant metrics contract failed.');

    const biometricResult = await jsonRequest('/api/enormity/nexus/v2/biometrics/metadata', {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({ companyId: testFixture.companyId, guardId: testFixture.guardId }),
    });
    assert(biometricResult.response.status === 200, 'Biometric metadata contract failed.');
    assert(biometricResult.response.headers.get('x-nexus-data-source') === 'cloudpatrol-mysql-direct', 'Biometric source header is missing.');
    const biometricText = JSON.stringify(biometricResult.body || {});
    assert(!/(?:FINGERFEA|Feather|template|password|readerCode)/i.test(biometricText), 'Sensitive biometric metadata field detected.');

    const contractTotals = {};
    for (const [contractId, filters] of [
      ['dept-tree-list', {}],
      ['sites-by-dept', { DeptID: testFixture.deptId }],
      ['guards-by-dept', { DeptID: testFixture.deptId }],
      ['attendance-config', { DeptID: testFixture.deptId }],
    ]) {
      const contractResult = await jsonRequest('/api/enormity/nexus/v2/contracts/query', {
        method: 'POST',
        headers: { authorization, 'content-type': 'application/json' },
        body: JSON.stringify({ companyId: testFixture.companyId, contractId, filters, limit: 25 }),
      });
      assert(contractResult.response.status === 200, `Direct contract ${contractId} failed.`);
      assert(contractResult.response.headers.get('x-nexus-data-source') === 'cloudpatrol-mysql-direct', `Direct contract ${contractId} source header is missing.`);
      const rows = contractResult.body?.data?.rows;
      assert(Array.isArray(rows) && rows.length <= 25, `Direct contract ${contractId} rows are not bounded.`);
      assert(rows.every((row) => Number(row.COMPANYID ?? row.companyid) === testFixture.companyId), `Direct contract ${contractId} crossed company scope.`);
      contractTotals[contractId] = Number(contractResult.body?.data?.total || 0);
    }

    const hostileFilterResult = await jsonRequest('/api/enormity/nexus/v2/contracts/query', {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: JSON.stringify({ companyId: testFixture.companyId, contractId: 'guards-by-dept', filters: { companyId: testFixture.otherCompanyId || 999999 } }),
    });
    assert(hostileFilterResult.response.status === 400, 'Direct contract accepted caller-supplied tenant scope.');

    const writeResult = await jsonRequest('/api/enormity/nexus/v2/commands/disabled-contract-probe', {
      method: 'POST',
      headers: { authorization, 'content-type': 'application/json' },
      body: '{}',
    });
    assert(writeResult.response.status === 503 && writeResult.body?.error?.code === 'E_WRITES_DISABLED', 'Read-only release accepted a mutation request.');

    console.log(JSON.stringify({
      status: 'passed',
      location: {
        status: locationResult.response.status,
        bounded: matches.length <= 5,
        sourceHeader: true,
        returnedMatchCount: matches.length,
        fields: Object.keys(matches[0] || {}).sort(),
      },
      metrics: {
        status: metricsResult.response.status,
        sourceHeader: true,
        metricGroups: [
          ...Object.keys(metricsResult.body?.data?.metrics || {}),
          ...Object.keys(secondMetricsResult.body?.data?.metrics || {}),
        ].sort(),
      },
      biometricMetadata: {
        status: biometricResult.response.status,
        sourceHeader: true,
        metadataOnly: biometricResult.body?.data?.redaction === 'metadata-only',
        recordCount: Number(biometricResult.body?.data?.total || 0),
      },
      directContracts: {
        status: 'passed',
        contracts: Object.keys(contractTotals).sort(),
        totals: contractTotals,
        hostileTenantFilterBlocked: true,
      },
      tenantIsolationProbe: crossCompanyResult,
      writesLocked: true,
    }));
  } finally {
    await pool.end();
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ status: 'failed', message: String(error?.message || 'Contract probe failed.').slice(0, 240) }));
  process.exitCode = 1;
});
