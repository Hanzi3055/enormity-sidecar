'use strict';

const assert = require('node:assert/strict');
const {
  canReceiveRealtimeEvent,
  normalizeCompanyId,
  normalizeRealtimeScope,
} = require('../realtime-scope');

assert.equal(normalizeCompanyId('17'), 17);
assert.equal(normalizeCompanyId('0'), null);
assert.equal(normalizeCompanyId('not-a-company'), null);
assert.equal(normalizeCompanyId('17-trailing-data'), null);

assert.deepEqual(normalizeRealtimeScope({ companyId: 17 }), { global: false, companyId: 17 });
assert.deepEqual(normalizeRealtimeScope({ global: true }), { global: true, companyId: null });
assert.throws(() => normalizeRealtimeScope({}), /companyId/);
assert.throws(() => normalizeRealtimeScope({ global: true, companyId: 17 }), /either global or company/);

assert.equal(canReceiveRealtimeEvent(17, 17), true);
assert.equal(canReceiveRealtimeEvent(17, 18), false);
assert.equal(canReceiveRealtimeEvent(17, undefined), false);
assert.equal(canReceiveRealtimeEvent(null, 18), true);
assert.equal(canReceiveRealtimeEvent(null, undefined), true);

process.stdout.write('tenant-scope-tests=passed\n');
