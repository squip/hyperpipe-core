import { promises as fs } from 'node:fs';
import { join } from 'node:path';

const RELAY_GATEWAY_MAP_FILENAME = 'relay-gateway-map.json';
const ENTRY_TTL_MS = 120 * 24 * 60 * 60 * 1000;

let configuredStorageBase = null;
let configuredLogger = console;
let loaded = false;
let dirty = false;
let flushTimer = null;
const entries = new Map();

function isHex64(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim());
}

function normalizeIdentity(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return isHex64(trimmed) ? trimmed.toLowerCase() : trimmed;
}

function normalizeHttpOrigin(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    return parsed.origin;
  } catch (_) {
    return null;
  }
}

function resolveStorageBase() {
  if (configuredStorageBase) return configuredStorageBase;
  return global?.userConfig?.storage || process.env.STORAGE_DIR || join(process.cwd(), 'data');
}

function storePath() {
  return join(resolveStorageBase(), RELAY_GATEWAY_MAP_FILENAME);
}

function identityKeys({ relayKey = null, publicIdentifier = null } = {}) {
  const keys = new Set();
  const normalizedRelayKey = normalizeIdentity(relayKey);
  const normalizedPublicIdentifier = normalizeIdentity(publicIdentifier);
  if (normalizedRelayKey) keys.add(normalizedRelayKey);
  if (normalizedPublicIdentifier) keys.add(normalizedPublicIdentifier);
  return keys;
}

function normalizeEntry(entry, now = Date.now()) {
  if (!entry || typeof entry !== 'object') return null;
  const normalizedRelayKey = normalizeIdentity(entry.relayKey);
  const normalizedPublicIdentifier = normalizeIdentity(entry.publicIdentifier);
  if (!normalizedRelayKey && !normalizedPublicIdentifier) return null;
  const gatewayOrigin = normalizeHttpOrigin(entry.gatewayOrigin);
  const gatewayId =
    typeof entry.gatewayId === 'string' && entry.gatewayId.trim()
      ? entry.gatewayId.trim().toLowerCase()
      : null;
  const directJoinOnly = entry.directJoinOnly === true;
  if (!directJoinOnly && !gatewayOrigin && !gatewayId) return null;

  return {
    relayKey: normalizedRelayKey,
    publicIdentifier: normalizedPublicIdentifier,
    gatewayOrigin,
    gatewayId,
    directJoinOnly,
    source:
      typeof entry.source === 'string' && entry.source.trim()
        ? entry.source.trim()
        : null,
    updatedAt: Number.isFinite(entry.updatedAt) ? Number(entry.updatedAt) : now
  };
}

function mergeEntries(left, right, now = Date.now()) {
  const a = normalizeEntry(left, now);
  const b = normalizeEntry(right, now);
  if (!a && !b) return null;
  if (!a) return b;
  if (!b) return a;

  const newer = (a.updatedAt || 0) >= (b.updatedAt || 0) ? a : b;
  const older = newer === a ? b : a;

  return {
    relayKey: newer.relayKey || older.relayKey || null,
    publicIdentifier: newer.publicIdentifier || older.publicIdentifier || null,
    gatewayOrigin: newer.gatewayOrigin || older.gatewayOrigin || null,
    gatewayId: newer.gatewayId || older.gatewayId || null,
    directJoinOnly: newer.directJoinOnly === true,
    source: newer.source || older.source || null,
    updatedAt: Math.max(Number(a.updatedAt || 0), Number(b.updatedAt || 0), now)
  };
}

function pruneEntry(entry, now = Date.now()) {
  const normalized = normalizeEntry(entry, now);
  if (!normalized) return null;
  if ((now - normalized.updatedAt) > ENTRY_TTL_MS) return null;
  return normalized;
}

async function loadStore() {
  if (loaded) return;
  loaded = true;
  const path = storePath();
  try {
    const payload = await fs.readFile(path, 'utf8');
    const parsed = JSON.parse(payload);
    const relays = parsed?.relays && typeof parsed.relays === 'object' ? parsed.relays : parsed;
    if (!relays || typeof relays !== 'object') return;
    const now = Date.now();
    for (const [key, value] of Object.entries(relays)) {
      const normalizedKey = normalizeIdentity(key);
      if (!normalizedKey) continue;
      const entry = pruneEntry(value, now);
      if (!entry) continue;
      entries.set(normalizedKey, entry);
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      configuredLogger?.warn?.('[Worker] Failed to load relay gateway map', {
        path,
        error: error?.message || error
      });
    }
  }
}

async function flushStore() {
  if (!dirty) return;
  dirty = false;
  const now = Date.now();
  for (const [key, value] of entries.entries()) {
    const pruned = pruneEntry(value, now);
    if (!pruned) {
      entries.delete(key);
      continue;
    }
    entries.set(key, pruned);
  }
  const relays = {};
  for (const [key, value] of entries.entries()) {
    relays[key] = value;
  }
  const payload = JSON.stringify({
    version: 1,
    updatedAt: new Date(now).toISOString(),
    relays
  }, null, 2);
  await fs.mkdir(resolveStorageBase(), { recursive: true });
  await fs.writeFile(storePath(), payload, 'utf8');
}

function scheduleFlush() {
  if (flushTimer) return;
  flushTimer = setTimeout(() => {
    flushTimer = null;
    flushStore().catch((error) => {
      configuredLogger?.warn?.('[Worker] Failed to flush relay gateway map', {
        error: error?.message || error
      });
    });
  }, 1200);
  flushTimer.unref?.();
}

export function configureRelayGatewayMapStore({ storageBase = null, logger = null } = {}) {
  if (typeof storageBase === 'string' && storageBase.trim()) {
    configuredStorageBase = storageBase;
  }
  if (logger) configuredLogger = logger;
}

export async function upsertRelayGatewayRoute({
  relayKey = null,
  publicIdentifier = null,
  gatewayOrigin = null,
  gatewayId = null,
  directJoinOnly = false,
  source = null,
  observedAt = Date.now()
} = {}) {
  await loadStore();
  const keys = identityKeys({ relayKey, publicIdentifier });
  if (!keys.size) return null;

  const update = normalizeEntry({
    relayKey,
    publicIdentifier,
    gatewayOrigin,
    gatewayId,
    directJoinOnly: directJoinOnly === true,
    source,
    updatedAt: observedAt
  }, observedAt);

  if (!update) {
    return await removeRelayGatewayRoute({ relayKey, publicIdentifier });
  }

  let mergedResult = null;
  for (const key of keys) {
    const merged = mergeEntries(entries.get(key) || null, update, observedAt);
    if (merged) {
      entries.set(key, merged);
      mergedResult = merged;
    }
  }

  dirty = true;
  scheduleFlush();
  return mergedResult;
}

export async function getRelayGatewayRoute({ relayKey = null, publicIdentifier = null } = {}) {
  await loadStore();
  const keys = identityKeys({ relayKey, publicIdentifier });
  if (!keys.size) return null;
  const now = Date.now();
  let merged = null;
  for (const key of keys) {
    const current = pruneEntry(entries.get(key), now);
    if (!current) {
      entries.delete(key);
      continue;
    }
    entries.set(key, current);
    merged = mergeEntries(merged, current, now);
  }
  return merged;
}

export async function removeRelayGatewayRoute({ relayKey = null, publicIdentifier = null } = {}) {
  await loadStore();
  const keys = identityKeys({ relayKey, publicIdentifier });
  if (!keys.size) return null;
  let removed = false;
  for (const key of keys) {
    removed = entries.delete(key) || removed;
  }
  if (removed) {
    dirty = true;
    scheduleFlush();
  }
  return removed;
}

export async function pruneRelayGatewayMapStore(now = Date.now()) {
  await loadStore();
  let changed = false;
  for (const [key, value] of entries.entries()) {
    const pruned = pruneEntry(value, now);
    if (!pruned) {
      entries.delete(key);
      changed = true;
      continue;
    }
    if (JSON.stringify(pruned) !== JSON.stringify(value)) {
      entries.set(key, pruned);
      changed = true;
    }
  }
  if (changed) {
    dirty = true;
    scheduleFlush();
  }
}

export async function listRelayGatewayRoutes() {
  await loadStore();
  await pruneRelayGatewayMapStore();
  return Array.from(entries.values()).map((entry) => ({ ...entry }));
}
