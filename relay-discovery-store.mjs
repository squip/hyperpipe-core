import { promises as fs } from 'node:fs';
import { join } from 'node:path';

const RELAY_DISCOVERY_CACHE_FILENAME = 'relay-discovery-cache.json';
const CAPABILITY_TTL_MS = 15 * 60 * 1000;
const PEER_HINT_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const DISCOVERY_TOPIC_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const MAX_PEER_HINTS = 64;

let configuredStorageBase = null;
let configuredLogger = console;

const relayDiscoveryEntries = new Map();
let relayDiscoveryLoaded = false;
let relayDiscoveryDirty = false;
let relayDiscoveryFlushTimer = null;

function isHex64(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim());
}

function normalizeRelayIdentity(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return isHex64(trimmed) ? trimmed.toLowerCase() : trimmed;
}

function normalizePeerKey(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || !isHex64(trimmed)) return null;
  return trimmed;
}

function normalizePeerList(values = []) {
  const out = [];
  const seen = new Set();
  for (const value of Array.isArray(values) ? values : []) {
    const normalized = normalizePeerKey(value);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
    if (out.length >= MAX_PEER_HINTS) break;
  }
  return out;
}

function resolveStorageBase() {
  if (configuredStorageBase) return configuredStorageBase;
  return global?.userConfig?.storage || process.env.STORAGE_DIR || join(process.cwd(), 'data');
}

function getRelayDiscoveryPath() {
  return join(resolveStorageBase(), RELAY_DISCOVERY_CACHE_FILENAME);
}

function getIdentityKeys(relayKey = null, publicIdentifier = null) {
  const keys = new Set();
  const normalizedRelayKey = normalizeRelayIdentity(relayKey);
  const normalizedIdentifier = normalizeRelayIdentity(publicIdentifier);
  if (normalizedRelayKey) keys.add(normalizedRelayKey);
  if (normalizedIdentifier) keys.add(normalizedIdentifier);
  return keys;
}

function emptyEntry(now = Date.now()) {
  return {
    relayKey: null,
    publicIdentifier: null,
    discoveryTopic: null,
    discoveryTopicUpdatedAt: null,
    hostPeerKeys: [],
    leaseReplicaPeerKeys: [],
    writerIssuerPubkey: null,
    hintsUpdatedAt: null,
    capabilityByPeer: {},
    updatedAt: now
  };
}

function normalizeCapabilityRecord(record, now = Date.now()) {
  if (!record || typeof record !== 'object') return null;
  const observedAt = Number.isFinite(record.observedAt) ? Number(record.observedAt) : now;
  return {
    observedAt,
    success: record.success === true,
    supported: record.supported !== false,
    rttMs: Number.isFinite(record.rttMs) ? Number(record.rttMs) : null,
    reason: typeof record.reason === 'string' ? record.reason : null,
    canDirectChallenge: record.canDirectChallenge === true,
    canProvisionOpenWriter: record.canProvisionOpenWriter === true,
    hasMatchingLease: record.hasMatchingLease === true,
    canStoreLeaseReplica: record.canStoreLeaseReplica === true,
    leaseExpiresAt: Number.isFinite(record.leaseExpiresAt) ? Number(record.leaseExpiresAt) : null,
    lastSuccessAt: Number.isFinite(record.lastSuccessAt)
      ? Number(record.lastSuccessAt)
      : (record.success === true ? observedAt : null),
    lastFailureAt: Number.isFinite(record.lastFailureAt)
      ? Number(record.lastFailureAt)
      : (record.success === false ? observedAt : null)
  };
}

function normalizeEntry(entry, now = Date.now()) {
  if (!entry || typeof entry !== 'object') return null;

  const normalizedRelayKey = normalizeRelayIdentity(entry.relayKey);
  const normalizedIdentifier = normalizeRelayIdentity(entry.publicIdentifier);
  const topic = typeof entry.discoveryTopic === 'string' ? entry.discoveryTopic.trim() : '';
  const writerIssuerPubkey = isHex64(entry.writerIssuerPubkey) ? String(entry.writerIssuerPubkey).toLowerCase() : null;
  const hostPeerKeys = normalizePeerList(entry.hostPeerKeys);
  const leaseReplicaPeerKeys = normalizePeerList(entry.leaseReplicaPeerKeys);
  const discoveryTopicUpdatedAt = Number.isFinite(entry.discoveryTopicUpdatedAt)
    ? Number(entry.discoveryTopicUpdatedAt)
    : null;
  const hintsUpdatedAt = Number.isFinite(entry.hintsUpdatedAt) ? Number(entry.hintsUpdatedAt) : null;

  const capabilityByPeer = {};
  const rawCapabilities = entry.capabilityByPeer && typeof entry.capabilityByPeer === 'object'
    ? entry.capabilityByPeer
    : {};
  for (const [peerKey, value] of Object.entries(rawCapabilities)) {
    const normalizedPeer = normalizePeerKey(peerKey);
    if (!normalizedPeer) continue;
    const capability = normalizeCapabilityRecord(value, now);
    if (!capability) continue;
    capabilityByPeer[normalizedPeer] = capability;
  }

  return {
    relayKey: normalizedRelayKey,
    publicIdentifier: normalizedIdentifier,
    discoveryTopic: topic || null,
    discoveryTopicUpdatedAt,
    hostPeerKeys,
    leaseReplicaPeerKeys,
    writerIssuerPubkey,
    hintsUpdatedAt,
    capabilityByPeer,
    updatedAt: Number.isFinite(entry.updatedAt) ? Number(entry.updatedAt) : now
  };
}

function mergePeerLists(...lists) {
  return normalizePeerList(lists.flat());
}

function mergeEntries(primary, secondary, now = Date.now()) {
  const base = emptyEntry(now);
  const left = normalizeEntry(primary, now) || base;
  const right = normalizeEntry(secondary, now) || base;

  return {
    relayKey: left.relayKey || right.relayKey || null,
    publicIdentifier: left.publicIdentifier || right.publicIdentifier || null,
    discoveryTopic:
      (Number(right.discoveryTopicUpdatedAt || 0) >= Number(left.discoveryTopicUpdatedAt || 0)
        ? right.discoveryTopic
        : left.discoveryTopic) || null,
    discoveryTopicUpdatedAt:
      Math.max(Number(left.discoveryTopicUpdatedAt || 0), Number(right.discoveryTopicUpdatedAt || 0)) || null,
    hostPeerKeys: mergePeerLists(left.hostPeerKeys, right.hostPeerKeys),
    leaseReplicaPeerKeys: mergePeerLists(left.leaseReplicaPeerKeys, right.leaseReplicaPeerKeys),
    writerIssuerPubkey: right.writerIssuerPubkey || left.writerIssuerPubkey || null,
    hintsUpdatedAt: Math.max(Number(left.hintsUpdatedAt || 0), Number(right.hintsUpdatedAt || 0)) || null,
    capabilityByPeer: {
      ...left.capabilityByPeer,
      ...right.capabilityByPeer
    },
    updatedAt: Math.max(Number(left.updatedAt || 0), Number(right.updatedAt || 0), now)
  };
}

function pruneEntry(entry, now = Date.now()) {
  const normalized = normalizeEntry(entry, now);
  if (!normalized) return null;

  const next = { ...normalized };
  if (
    next.discoveryTopicUpdatedAt
    && now - next.discoveryTopicUpdatedAt > DISCOVERY_TOPIC_TTL_MS
  ) {
    next.discoveryTopic = null;
    next.discoveryTopicUpdatedAt = null;
  }

  if (
    next.hintsUpdatedAt
    && now - next.hintsUpdatedAt > PEER_HINT_TTL_MS
  ) {
    next.hostPeerKeys = [];
    next.leaseReplicaPeerKeys = [];
    next.writerIssuerPubkey = null;
    next.hintsUpdatedAt = null;
  }

  const filteredCapabilities = {};
  for (const [peerKey, capability] of Object.entries(next.capabilityByPeer || {})) {
    const observedAt = Number(capability?.observedAt || 0);
    if (!observedAt || now - observedAt > CAPABILITY_TTL_MS) continue;
    filteredCapabilities[peerKey] = capability;
  }
  next.capabilityByPeer = filteredCapabilities;

  if (
    !next.discoveryTopic
    && !next.hostPeerKeys.length
    && !next.leaseReplicaPeerKeys.length
    && !next.writerIssuerPubkey
    && Object.keys(next.capabilityByPeer).length === 0
  ) {
    return null;
  }

  return next;
}

async function loadRelayDiscoveryStore() {
  if (relayDiscoveryLoaded) return;
  relayDiscoveryLoaded = true;
  const cachePath = getRelayDiscoveryPath();
  try {
    const payload = await fs.readFile(cachePath, 'utf8');
    const parsed = JSON.parse(payload);
    const relays = parsed?.relays && typeof parsed.relays === 'object' ? parsed.relays : parsed;
    if (!relays || typeof relays !== 'object') return;
    const now = Date.now();
    for (const [key, value] of Object.entries(relays)) {
      const normalizedKey = normalizeRelayIdentity(key);
      if (!normalizedKey) continue;
      const entry = pruneEntry(value, now);
      if (!entry) continue;
      relayDiscoveryEntries.set(normalizedKey, entry);
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      configuredLogger?.warn?.('[Worker] Failed to load relay discovery store', {
        path: cachePath,
        error: error?.message || error
      });
    }
  }
}

function scheduleRelayDiscoveryFlush() {
  if (relayDiscoveryFlushTimer) return;
  relayDiscoveryFlushTimer = setTimeout(() => {
    relayDiscoveryFlushTimer = null;
    flushRelayDiscoveryStore().catch((error) => {
      configuredLogger?.warn?.('[Worker] Failed to flush relay discovery store', {
        error: error?.message || error
      });
    });
  }, 1200);
  relayDiscoveryFlushTimer.unref?.();
}

async function flushRelayDiscoveryStore() {
  if (!relayDiscoveryDirty) return;
  relayDiscoveryDirty = false;
  const now = Date.now();
  for (const [key, value] of relayDiscoveryEntries.entries()) {
    const pruned = pruneEntry(value, now);
    if (!pruned) {
      relayDiscoveryEntries.delete(key);
      continue;
    }
    relayDiscoveryEntries.set(key, pruned);
  }
  const relays = {};
  for (const [key, value] of relayDiscoveryEntries.entries()) {
    relays[key] = value;
  }
  const payload = JSON.stringify({
    version: 1,
    updatedAt: new Date(now).toISOString(),
    relays
  }, null, 2);
  await fs.mkdir(resolveStorageBase(), { recursive: true });
  await fs.writeFile(getRelayDiscoveryPath(), payload, 'utf8');
}

export function configureRelayDiscoveryStore({ storageBase = null, logger = null } = {}) {
  if (typeof storageBase === 'string' && storageBase.trim()) {
    configuredStorageBase = storageBase;
  }
  if (logger) {
    configuredLogger = logger;
  }
}

export async function pruneRelayDiscoveryStore(now = Date.now()) {
  await loadRelayDiscoveryStore();
  let changed = false;
  for (const [key, value] of relayDiscoveryEntries.entries()) {
    const pruned = pruneEntry(value, now);
    if (!pruned) {
      relayDiscoveryEntries.delete(key);
      changed = true;
      continue;
    }
    if (JSON.stringify(pruned) !== JSON.stringify(value)) {
      relayDiscoveryEntries.set(key, pruned);
      changed = true;
    }
  }
  if (changed) {
    relayDiscoveryDirty = true;
    scheduleRelayDiscoveryFlush();
  }
}

export async function upsertRelayDiscoveryHints({
  relayKey = null,
  publicIdentifier = null,
  discoveryTopic = undefined,
  hostPeerKeys = undefined,
  leaseReplicaPeerKeys = undefined,
  writerIssuerPubkey = undefined,
  observedAt = Date.now()
} = {}) {
  await loadRelayDiscoveryStore();
  const keys = getIdentityKeys(relayKey, publicIdentifier);
  if (!keys.size) return null;

  const normalizedRelayKey = normalizeRelayIdentity(relayKey);
  const normalizedIdentifier = normalizeRelayIdentity(publicIdentifier);
  const normalizedWriterIssuer = isHex64(writerIssuerPubkey) ? String(writerIssuerPubkey).toLowerCase() : null;

  const update = emptyEntry(observedAt);
  update.relayKey = normalizedRelayKey;
  update.publicIdentifier = normalizedIdentifier;

  if (typeof discoveryTopic === 'string' && discoveryTopic.trim()) {
    update.discoveryTopic = discoveryTopic.trim();
    update.discoveryTopicUpdatedAt = observedAt;
  }
  if (Array.isArray(hostPeerKeys)) {
    update.hostPeerKeys = normalizePeerList(hostPeerKeys);
    update.hintsUpdatedAt = observedAt;
  }
  if (Array.isArray(leaseReplicaPeerKeys)) {
    update.leaseReplicaPeerKeys = normalizePeerList(leaseReplicaPeerKeys);
    update.hintsUpdatedAt = observedAt;
  }
  if (typeof writerIssuerPubkey !== 'undefined') {
    update.writerIssuerPubkey = normalizedWriterIssuer;
    update.hintsUpdatedAt = observedAt;
  }

  let mergedResult = null;
  for (const key of keys) {
    const current = relayDiscoveryEntries.get(key) || null;
    const merged = mergeEntries(current, update, observedAt);
    relayDiscoveryEntries.set(key, merged);
    mergedResult = merged;
  }

  relayDiscoveryDirty = true;
  scheduleRelayDiscoveryFlush();
  return mergedResult;
}

export async function recordRelayCapabilityProbe({
  relayKey = null,
  publicIdentifier = null,
  peerKey,
  observedAt = Date.now(),
  success = false,
  supported = true,
  rttMs = null,
  reason = null,
  canDirectChallenge = false,
  canProvisionOpenWriter = false,
  hasMatchingLease = false,
  canStoreLeaseReplica = false,
  leaseExpiresAt = null
} = {}) {
  await loadRelayDiscoveryStore();
  const normalizedPeerKey = normalizePeerKey(peerKey);
  if (!normalizedPeerKey) return null;

  const keys = getIdentityKeys(relayKey, publicIdentifier);
  if (!keys.size) return null;

  const capability = normalizeCapabilityRecord({
    observedAt,
    success,
    supported,
    rttMs,
    reason,
    canDirectChallenge,
    canProvisionOpenWriter,
    hasMatchingLease,
    canStoreLeaseReplica,
    leaseExpiresAt,
    lastSuccessAt: success ? observedAt : null,
    lastFailureAt: success ? null : observedAt
  }, observedAt);

  let mergedResult = null;
  for (const key of keys) {
    const current = relayDiscoveryEntries.get(key) || emptyEntry(observedAt);
    const next = {
      ...current,
      relayKey: current.relayKey || normalizeRelayIdentity(relayKey),
      publicIdentifier: current.publicIdentifier || normalizeRelayIdentity(publicIdentifier),
      capabilityByPeer: {
        ...(current.capabilityByPeer || {}),
        [normalizedPeerKey]: capability
      },
      updatedAt: observedAt
    };
    const pruned = pruneEntry(next, observedAt) || next;
    relayDiscoveryEntries.set(key, pruned);
    mergedResult = pruned;
  }

  relayDiscoveryDirty = true;
  scheduleRelayDiscoveryFlush();
  return mergedResult;
}

export async function getRelayDiscoveryHints({ relayKey = null, publicIdentifier = null } = {}) {
  await loadRelayDiscoveryStore();
  const keys = getIdentityKeys(relayKey, publicIdentifier);
  if (!keys.size) {
    return {
      relayKey: normalizeRelayIdentity(relayKey),
      publicIdentifier: normalizeRelayIdentity(publicIdentifier),
      discoveryTopic: null,
      hostPeerKeys: [],
      leaseReplicaPeerKeys: [],
      writerIssuerPubkey: null,
      capabilities: {}
    };
  }

  const now = Date.now();
  let merged = emptyEntry(now);
  for (const key of keys) {
    const current = pruneEntry(relayDiscoveryEntries.get(key), now);
    if (!current) continue;
    merged = mergeEntries(merged, current, now);
    relayDiscoveryEntries.set(key, current);
  }

  return {
    relayKey: merged.relayKey || normalizeRelayIdentity(relayKey),
    publicIdentifier: merged.publicIdentifier || normalizeRelayIdentity(publicIdentifier),
    discoveryTopic: merged.discoveryTopic || null,
    hostPeerKeys: normalizePeerList(merged.hostPeerKeys),
    leaseReplicaPeerKeys: normalizePeerList(merged.leaseReplicaPeerKeys),
    writerIssuerPubkey: merged.writerIssuerPubkey || null,
    capabilities: merged.capabilityByPeer || {},
    updatedAt: merged.updatedAt || null
  };
}
