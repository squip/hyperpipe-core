import { promises as fs } from 'node:fs';
import { join } from 'node:path';

const RELAY_LEASE_REPLICA_CACHE_FILENAME = 'relay-lease-replica-cache.json';
const MAX_LEASES_PER_RELAY = 256;
const MAX_REPLICA_PEERS_PER_RELAY = 32;

let configuredStorageBase = null;
let configuredLogger = console;

const relayLeaseEntries = new Map();
let relayLeaseLoaded = false;
let relayLeaseDirty = false;
let relayLeaseFlushTimer = null;

function isHex64(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim());
}

function normalizeRelayIdentity(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return isHex64(trimmed) ? trimmed.toLowerCase() : trimmed;
}

function normalizeHex(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || !isHex64(trimmed)) return null;
  return trimmed.toLowerCase();
}

function normalizeReplicaPeerKey(value) {
  return normalizeHex(value);
}

function normalizeReplicaPeerList(values = []) {
  const out = [];
  const seen = new Set();
  for (const value of Array.isArray(values) ? values : []) {
    const normalized = normalizeReplicaPeerKey(value);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    out.push(normalized);
    if (out.length >= MAX_REPLICA_PEERS_PER_RELAY) break;
  }
  return out;
}

function normalizeCoreRefs(coreRefs) {
  if (!Array.isArray(coreRefs)) return undefined;
  const out = [];
  const seen = new Set();
  for (const entry of coreRefs) {
    if (!entry || typeof entry !== 'object') continue;
    const key = String(entry.key || '').trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push({
      key,
      role: typeof entry.role === 'string' ? entry.role : null
    });
  }
  return out.length ? out : undefined;
}

function normalizeFastForward(value) {
  if (!value || typeof value !== 'object') return null;
  const candidate = value;
  const result = {
    key: typeof candidate.key === 'string' ? candidate.key : undefined,
    length: Number.isFinite(candidate.length) ? Number(candidate.length) : undefined,
    signedLength: Number.isFinite(candidate.signedLength) ? Number(candidate.signedLength) : undefined,
    timeoutMs: Number.isFinite(candidate.timeoutMs) ? Number(candidate.timeoutMs) : undefined
  };
  if (!result.key && !Number.isFinite(result.length) && !Number.isFinite(result.signedLength) && !Number.isFinite(result.timeoutMs)) {
    return null;
  }
  return result;
}

function normalizeEnvelope(input) {
  if (!input || typeof input !== 'object') return null;
  const version = Number(input.version);
  if (!Number.isFinite(version) || version !== 1) return null;

  const leaseId = typeof input.leaseId === 'string' ? input.leaseId.trim() : '';
  const relayKey = normalizeHex(input.relayKey);
  const publicIdentifier = normalizeRelayIdentity(input.publicIdentifier);
  const inviteePubkey = normalizeHex(input.inviteePubkey);
  const tokenHash = typeof input.tokenHash === 'string' ? input.tokenHash.trim().toLowerCase() : '';
  const writerCore = typeof input.writerCore === 'string' ? input.writerCore.trim() : '';
  const writerCoreHex = typeof input.writerCoreHex === 'string' ? input.writerCoreHex.trim() : null;
  const autobaseLocal = typeof input.autobaseLocal === 'string' ? input.autobaseLocal.trim() : null;
  const writerSecret = typeof input.writerSecret === 'string' ? input.writerSecret.trim() : '';
  const issuedAt = Number(input.issuedAt);
  const expiresAt = Number(input.expiresAt);
  const issuerPubkey = normalizeHex(input.issuerPubkey);
  const issuerSwarmPeerKey = normalizeReplicaPeerKey(input.issuerSwarmPeerKey);
  const signature = typeof input.signature === 'string' ? input.signature.trim() : '';

  if (!leaseId || !relayKey || !publicIdentifier || !inviteePubkey) return null;
  if (!tokenHash || !writerCore || !writerSecret) return null;
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) return null;
  if (!issuerPubkey || !issuerSwarmPeerKey || !signature) return null;

  const envelope = {
    version: 1,
    leaseId,
    relayKey,
    publicIdentifier,
    inviteePubkey,
    tokenHash,
    writerCore,
    writerCoreHex: writerCoreHex || undefined,
    autobaseLocal: autobaseLocal || undefined,
    writerSecret,
    coreRefs: normalizeCoreRefs(input.coreRefs),
    fastForward: normalizeFastForward(input.fastForward),
    issuedAt,
    expiresAt,
    issuerPubkey,
    issuerSwarmPeerKey,
    signature
  };

  return envelope;
}

function leaseFingerprint(envelope) {
  return `${envelope.leaseId}:${envelope.inviteePubkey}:${envelope.tokenHash}`;
}

function resolveStorageBase() {
  if (configuredStorageBase) return configuredStorageBase;
  return global?.userConfig?.storage || process.env.STORAGE_DIR || join(process.cwd(), 'data');
}

function getRelayLeaseReplicaPath() {
  return join(resolveStorageBase(), RELAY_LEASE_REPLICA_CACHE_FILENAME);
}

function emptyRelayLeaseEntry(now = Date.now()) {
  return {
    relayKey: null,
    publicIdentifier: null,
    envelopes: [],
    replicaPeerKeys: [],
    updatedAt: now
  };
}

function mergeReplicaPeers(...lists) {
  return normalizeReplicaPeerList(lists.flat());
}

function pruneRelayLeaseEntry(entry, now = Date.now()) {
  if (!entry || typeof entry !== 'object') return null;
  const relayKey = normalizeHex(entry.relayKey);
  const publicIdentifier = normalizeRelayIdentity(entry.publicIdentifier);

  const envelopes = [];
  const seen = new Set();
  for (const rawEnvelope of Array.isArray(entry.envelopes) ? entry.envelopes : []) {
    const envelope = normalizeEnvelope(rawEnvelope);
    if (!envelope) continue;
    if (envelope.expiresAt <= now) continue;
    const key = leaseFingerprint(envelope);
    if (seen.has(key)) continue;
    seen.add(key);
    envelopes.push({
      ...envelope,
      storedAt: Number.isFinite(rawEnvelope.storedAt) ? Number(rawEnvelope.storedAt) : now,
      sourcePeerKey: normalizeReplicaPeerKey(rawEnvelope.sourcePeerKey) || undefined
    });
  }

  envelopes.sort((left, right) => {
    if (right.expiresAt !== left.expiresAt) return right.expiresAt - left.expiresAt;
    if (right.issuedAt !== left.issuedAt) return right.issuedAt - left.issuedAt;
    return String(left.leaseId).localeCompare(String(right.leaseId));
  });

  const limitedEnvelopes = envelopes.slice(0, MAX_LEASES_PER_RELAY);
  const replicaPeerKeys = mergeReplicaPeers(
    entry.replicaPeerKeys,
    limitedEnvelopes.map((item) => item.sourcePeerKey || null),
    limitedEnvelopes.map((item) => item.issuerSwarmPeerKey || null)
  );

  if (!relayKey && !publicIdentifier) return null;
  if (!limitedEnvelopes.length && !replicaPeerKeys.length) return null;

  return {
    relayKey,
    publicIdentifier,
    envelopes: limitedEnvelopes,
    replicaPeerKeys,
    updatedAt: Number.isFinite(entry.updatedAt) ? Number(entry.updatedAt) : now
  };
}

function getIdentityKeys(relayKey = null, publicIdentifier = null, envelope = null) {
  const keys = new Set();
  const normalizedRelayKey = normalizeRelayIdentity(relayKey || envelope?.relayKey || null);
  const normalizedIdentifier = normalizeRelayIdentity(publicIdentifier || envelope?.publicIdentifier || null);
  if (normalizedRelayKey) keys.add(normalizedRelayKey);
  if (normalizedIdentifier) keys.add(normalizedIdentifier);
  return keys;
}

async function loadRelayLeaseReplicaStore() {
  if (relayLeaseLoaded) return;
  relayLeaseLoaded = true;
  const cachePath = getRelayLeaseReplicaPath();
  try {
    const payload = await fs.readFile(cachePath, 'utf8');
    const parsed = JSON.parse(payload);
    const relays = parsed?.relays && typeof parsed.relays === 'object' ? parsed.relays : parsed;
    if (!relays || typeof relays !== 'object') return;
    const now = Date.now();
    for (const [key, value] of Object.entries(relays)) {
      const normalizedKey = normalizeRelayIdentity(key);
      if (!normalizedKey) continue;
      const entry = pruneRelayLeaseEntry(value, now);
      if (!entry) continue;
      relayLeaseEntries.set(normalizedKey, entry);
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      configuredLogger?.warn?.('[Worker] Failed to load relay lease replica store', {
        path: cachePath,
        error: error?.message || error
      });
    }
  }
}

function scheduleRelayLeaseReplicaFlush() {
  if (relayLeaseFlushTimer) return;
  relayLeaseFlushTimer = setTimeout(() => {
    relayLeaseFlushTimer = null;
    flushRelayLeaseReplicaStore().catch((error) => {
      configuredLogger?.warn?.('[Worker] Failed to flush relay lease replica store', {
        error: error?.message || error
      });
    });
  }, 1200);
  relayLeaseFlushTimer.unref?.();
}

async function flushRelayLeaseReplicaStore() {
  if (!relayLeaseDirty) return;
  relayLeaseDirty = false;
  const now = Date.now();
  for (const [key, value] of relayLeaseEntries.entries()) {
    const pruned = pruneRelayLeaseEntry(value, now);
    if (!pruned) {
      relayLeaseEntries.delete(key);
      continue;
    }
    relayLeaseEntries.set(key, pruned);
  }
  const relays = {};
  for (const [key, value] of relayLeaseEntries.entries()) {
    relays[key] = value;
  }
  const payload = JSON.stringify({
    version: 1,
    updatedAt: new Date(now).toISOString(),
    relays
  }, null, 2);
  await fs.mkdir(resolveStorageBase(), { recursive: true });
  await fs.writeFile(getRelayLeaseReplicaPath(), payload, 'utf8');
}

export function configureRelayLeaseReplicaStore({ storageBase = null, logger = null } = {}) {
  if (typeof storageBase === 'string' && storageBase.trim()) {
    configuredStorageBase = storageBase;
  }
  if (logger) {
    configuredLogger = logger;
  }
}

export async function pruneRelayLeaseReplicaStore(now = Date.now()) {
  await loadRelayLeaseReplicaStore();
  let changed = false;
  for (const [key, value] of relayLeaseEntries.entries()) {
    const pruned = pruneRelayLeaseEntry(value, now);
    if (!pruned) {
      relayLeaseEntries.delete(key);
      changed = true;
      continue;
    }
    if (JSON.stringify(pruned) !== JSON.stringify(value)) {
      relayLeaseEntries.set(key, pruned);
      changed = true;
    }
  }
  if (changed) {
    relayLeaseDirty = true;
    scheduleRelayLeaseReplicaFlush();
  }
}

export async function upsertRelayLeaseEnvelope({
  envelope,
  relayKey = null,
  publicIdentifier = null,
  sourcePeerKey = null,
  observedAt = Date.now()
} = {}) {
  await loadRelayLeaseReplicaStore();
  const normalizedEnvelope = normalizeEnvelope(envelope);
  if (!normalizedEnvelope) return null;

  const keys = getIdentityKeys(relayKey, publicIdentifier, normalizedEnvelope);
  if (!keys.size) return null;

  const normalizedSourcePeerKey = normalizeReplicaPeerKey(sourcePeerKey);
  let mergedResult = null;
  for (const key of keys) {
    const current = relayLeaseEntries.get(key) || emptyRelayLeaseEntry(observedAt);
    const seen = new Set();
    const envelopes = [];

    const ingest = (candidateEnvelope, candidateSourcePeerKey = null) => {
      const normalizedCandidate = normalizeEnvelope(candidateEnvelope);
      if (!normalizedCandidate || normalizedCandidate.expiresAt <= observedAt) return;
      const fingerprint = leaseFingerprint(normalizedCandidate);
      if (seen.has(fingerprint)) return;
      seen.add(fingerprint);
      envelopes.push({
        ...normalizedCandidate,
        storedAt: observedAt,
        sourcePeerKey: normalizeReplicaPeerKey(candidateSourcePeerKey) || undefined
      });
    };

    for (const existing of Array.isArray(current.envelopes) ? current.envelopes : []) {
      ingest(existing, existing?.sourcePeerKey || null);
    }
    ingest(normalizedEnvelope, normalizedSourcePeerKey);

    envelopes.sort((left, right) => {
      if (right.expiresAt !== left.expiresAt) return right.expiresAt - left.expiresAt;
      return right.issuedAt - left.issuedAt;
    });

    const next = {
      relayKey: current.relayKey || normalizedEnvelope.relayKey,
      publicIdentifier: current.publicIdentifier || normalizedEnvelope.publicIdentifier,
      envelopes: envelopes.slice(0, MAX_LEASES_PER_RELAY),
      replicaPeerKeys: mergeReplicaPeers(
        current.replicaPeerKeys,
        normalizedEnvelope.issuerSwarmPeerKey,
        normalizedSourcePeerKey
      ),
      updatedAt: observedAt
    };

    const pruned = pruneRelayLeaseEntry(next, observedAt) || next;
    relayLeaseEntries.set(key, pruned);
    mergedResult = pruned;
  }

  relayLeaseDirty = true;
  scheduleRelayLeaseReplicaFlush();
  return mergedResult;
}

export async function recordRelayLeaseReplicaPeer({
  relayKey = null,
  publicIdentifier = null,
  peerKey,
  observedAt = Date.now()
} = {}) {
  await loadRelayLeaseReplicaStore();
  const normalizedPeerKey = normalizeReplicaPeerKey(peerKey);
  if (!normalizedPeerKey) return null;
  const keys = getIdentityKeys(relayKey, publicIdentifier);
  if (!keys.size) return null;

  let mergedResult = null;
  for (const key of keys) {
    const current = relayLeaseEntries.get(key) || emptyRelayLeaseEntry(observedAt);
    const next = {
      ...current,
      relayKey: current.relayKey || normalizeHex(relayKey),
      publicIdentifier: current.publicIdentifier || normalizeRelayIdentity(publicIdentifier),
      replicaPeerKeys: mergeReplicaPeers(current.replicaPeerKeys, normalizedPeerKey),
      updatedAt: observedAt
    };
    relayLeaseEntries.set(key, next);
    mergedResult = next;
  }

  relayLeaseDirty = true;
  scheduleRelayLeaseReplicaFlush();
  return mergedResult;
}

export async function getRelayLeaseReplicaSnapshot({ relayKey = null, publicIdentifier = null } = {}) {
  await loadRelayLeaseReplicaStore();
  const keys = getIdentityKeys(relayKey, publicIdentifier);
  const now = Date.now();
  const merged = emptyRelayLeaseEntry(now);

  for (const key of keys) {
    const entry = pruneRelayLeaseEntry(relayLeaseEntries.get(key), now);
    if (!entry) continue;
    relayLeaseEntries.set(key, entry);
    if (!merged.relayKey && entry.relayKey) merged.relayKey = entry.relayKey;
    if (!merged.publicIdentifier && entry.publicIdentifier) merged.publicIdentifier = entry.publicIdentifier;
    merged.envelopes = [...merged.envelopes, ...(entry.envelopes || [])];
    merged.replicaPeerKeys = mergeReplicaPeers(merged.replicaPeerKeys, entry.replicaPeerKeys || []);
    merged.updatedAt = Math.max(merged.updatedAt || 0, entry.updatedAt || 0);
  }

  const deduped = [];
  const seen = new Set();
  for (const envelope of merged.envelopes) {
    const normalized = normalizeEnvelope(envelope);
    if (!normalized) continue;
    const fingerprint = leaseFingerprint(normalized);
    if (seen.has(fingerprint)) continue;
    seen.add(fingerprint);
    deduped.push({
      ...normalized,
      storedAt: Number.isFinite(envelope.storedAt) ? Number(envelope.storedAt) : now,
      sourcePeerKey: normalizeReplicaPeerKey(envelope.sourcePeerKey) || undefined
    });
  }
  deduped.sort((left, right) => {
    if (right.expiresAt !== left.expiresAt) return right.expiresAt - left.expiresAt;
    return right.issuedAt - left.issuedAt;
  });

  return {
    relayKey: merged.relayKey || normalizeHex(relayKey) || null,
    publicIdentifier: merged.publicIdentifier || normalizeRelayIdentity(publicIdentifier) || null,
    envelopes: deduped.slice(0, MAX_LEASES_PER_RELAY),
    replicaPeerKeys: mergeReplicaPeers(merged.replicaPeerKeys),
    updatedAt: merged.updatedAt || null
  };
}

export async function findMatchingRelayLeaseEnvelope({
  relayKey = null,
  publicIdentifier = null,
  inviteePubkey,
  tokenHash,
  now = Date.now()
} = {}) {
  const normalizedInvitee = normalizeHex(inviteePubkey);
  const normalizedTokenHash = typeof tokenHash === 'string' ? tokenHash.trim().toLowerCase() : null;
  if (!normalizedInvitee || !normalizedTokenHash) {
    return { envelope: null, leaseExpiresAt: null };
  }

  const snapshot = await getRelayLeaseReplicaSnapshot({ relayKey, publicIdentifier });
  const candidates = (snapshot.envelopes || []).filter((entry) => (
    entry.inviteePubkey === normalizedInvitee
    && entry.tokenHash === normalizedTokenHash
    && Number(entry.expiresAt) > now
  ));

  if (!candidates.length) {
    return { envelope: null, leaseExpiresAt: null };
  }

  candidates.sort((left, right) => {
    if (right.expiresAt !== left.expiresAt) return right.expiresAt - left.expiresAt;
    return right.issuedAt - left.issuedAt;
  });

  return {
    envelope: candidates[0],
    leaseExpiresAt: candidates[0].expiresAt
  };
}
