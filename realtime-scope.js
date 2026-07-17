'use strict';

function normalizeCompanyId(value) {
  const normalized = String(value ?? '').trim();
  if (!/^\d{1,15}$/.test(normalized)) return null;
  const parsed = Number(normalized);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : null;
}

function normalizeRealtimeScope(input = {}) {
  const global = input.global === true || String(input.global || '').trim() === '1';
  const companyId = normalizeCompanyId(input.companyId);
  if (global && companyId) throw new Error('Choose either global or company scope, not both.');
  if (!global && !companyId) throw new Error('A positive companyId is required for company scope.');
  return { global, companyId: global ? null : companyId };
}

function canReceiveRealtimeEvent(clientCompanyId, eventCompanyId) {
  if (clientCompanyId === null) return true;
  const eventTenant = normalizeCompanyId(eventCompanyId);
  return eventTenant !== null && eventTenant === normalizeCompanyId(clientCompanyId);
}

module.exports = {
  canReceiveRealtimeEvent,
  normalizeCompanyId,
  normalizeRealtimeScope,
};
