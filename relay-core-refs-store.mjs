import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import HypercoreId from 'hypercore-id-encoding';
import {
  getRelayProfileByKey,
  getRelayProfileByPublicIdentifier
} from './hyperpipe-relay-profile-manager.mjs';
import { normalizeRelayIdentifier } from './relay-identifier-utils.mjs';

const RELAY_CORE_REFS_CACHE_FILENAME = 'relay-core-refs-cache.json';

let configuredStorageBase = null;
let configuredLogger = console;

const relayMirrorCoreRefs = new Map();
const relayMirrorCoreRefsCache = new Map();
let relayCoreRefsCacheLoaded = false;
let relayCoreRefsCacheDirty = false;
let relayCoreRefsCacheTimer = null;

function isHex64(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim());
}

function normalizeRelayKeyHex(value) {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || !isHex64(trimmed)) return null;
  return trimmed.toLowerCase();
}

async function resolveCanonicalRelayKeys(relayKey, publicIdentifier) {
  const relayKeyHex = normalizeRelayKeyHex(relayKey);
  const publicKeyHex = normalizeRelayKeyHex(publicIdentifier);
  const normalizedAlias = normalizeRelayIdentifier(publicIdentifier || relayKey || '');

  if (relayKeyHex) {
    return {
      canonicalKey: relayKeyHex,
      aliasKey: normalizedAlias && normalizedAlias !== relayKeyHex ? normalizedAlias : null
    };
  }

  if (publicKeyHex) {
    return {
      canonicalKey: publicKeyHex,
      aliasKey: normalizedAlias && normalizedAlias !== publicKeyHex ? normalizedAlias : null
    };
  }

  let profile = null;
  if (relayKey && typeof relayKey === 'string') {
    profile = await getRelayProfileByPublicIdentifier(relayKey);
  }
  if (!profile && publicIdentifier) {
    profile = await getRelayProfileByPublicIdentifier(publicIdentifier);
  }

  const canonicalKey = normalizeRelayKeyHex(profile?.relay_key || profile?.relayKey || null);
  const aliasKey = normalizeRelayIdentifier(
    profile?.public_identifier
      || profile?.publicIdentifier
      || normalizedAlias
      || ''
  );

  return {
    canonicalKey: canonicalKey || null,
    aliasKey: aliasKey && aliasKey !== canonicalKey ? aliasKey : null
  };
}

export function configureRelayCoreRefsStore({ storageBase = null, logger = null } = {}) {
  if (typeof storageBase === 'string' && storageBase.trim()) {
    configuredStorageBase = storageBase;
  }
  if (logger) {
    configuredLogger = logger;
  }
}

function resolveStorageBase() {
  if (configuredStorageBase) return configuredStorageBase;
  return global?.userConfig?.storage || process.env.STORAGE_DIR || join(process.cwd(), 'data');
}

function getRelayCoreRefsCachePath() {
  return join(resolveStorageBase(), RELAY_CORE_REFS_CACHE_FILENAME);
}

export function normalizeCoreRef(value) {
  if (!value) return null;
  if (Buffer.isBuffer(value)) {
    try {
      return HypercoreId.encode(value);
    } catch (_) {
      return null;
    }
  }
  if (value instanceof Uint8Array) {
    return normalizeCoreRef(Buffer.from(value));
  }
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    try {
      const decoded = HypercoreId.decode(trimmed);
      return HypercoreId.encode(decoded);
    } catch (_) {
      if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        try {
          return HypercoreId.encode(Buffer.from(trimmed, 'hex'));
        } catch (_) {
          return null;
        }
      }
      return null;
    }
  }
  if (value && typeof value === 'object') {
    if (value.key) return normalizeCoreRef(value.key);
    if (value.core) return normalizeCoreRef(value.core);
  }
  return null;
}

export function decodeCoreRef(value) {
  if (!value) return null;
  if (Buffer.isBuffer(value)) return Buffer.from(value);
  if (value instanceof Uint8Array) return Buffer.from(value);
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    try {
      return HypercoreId.decode(trimmed);
    } catch (_) {
      if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
        return Buffer.from(trimmed, 'hex');
      }
      return null;
    }
  }
  if (value && typeof value === 'object') {
    if (value.key) return decodeCoreRef(value.key);
    if (value.core) return decodeCoreRef(value.core);
  }
  return null;
}

export function normalizeCoreRefList(refs) {
  if (!Array.isArray(refs)) return [];
  const seen = new Set();
  const result = [];
  for (const ref of refs) {
    const normalized = normalizeCoreRef(ref);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

export function normalizeMirrorCoreRefs(cores) {
  if (!Array.isArray(cores)) return [];
  return normalizeCoreRefList(cores);
}

export function normalizeMirrorWriterCoreRefs(cores) {
  if (!Array.isArray(cores)) return [];
  const writerRefs = [];
  for (const entry of cores) {
    if (!entry || typeof entry !== 'object') continue;
    const roles = [];
    if (typeof entry.role === 'string') roles.push(entry.role);
    if (Array.isArray(entry.roles)) roles.push(...entry.roles);
    const isWriter = roles.some((role) => role && (role === 'autobase-writer' || role.startsWith('autobase-writer-')));
    if (!isWriter) continue;
    const normalized = normalizeCoreRef(entry.key || entry.core || entry);
    if (normalized) writerRefs.push(normalized);
  }
  return normalizeCoreRefList(writerRefs);
}

export function mergeCoreRefLists(...lists) {
  const merged = [];
  const seen = new Set();
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const ref of list) {
      if (!ref || seen.has(ref)) continue;
      seen.add(ref);
      merged.push(ref);
    }
  }
  return merged;
}

export function coreRefsFingerprint(coreRefs = []) {
  return Array.isArray(coreRefs) ? coreRefs.join('|') : '';
}

export function collectRelayCoreRefsFromAutobase(autobase) {
  if (!autobase) return [];
  const seen = new Set();
  const entries = [];
  const addCore = (candidate, role = null) => {
    const key = normalizeCoreRef(candidate);
    if (!key || seen.has(key)) return;
    seen.add(key);
    if (role) {
      entries.push({ key, role });
    } else {
      entries.push({ key });
    }
  };
  const addArray = (arr, prefix) => {
    if (!arr) return;
    const list = Array.isArray(arr) ? arr : (arr[Symbol.iterator] ? Array.from(arr) : []);
    list.forEach((entry, index) => addCore(entry?.core || entry, prefix ? `${prefix}-${index}` : null));
  };

  addCore(autobase, 'autobase');
  addCore(autobase?.system || autobase?.system?.core, 'autobase-system');
  addCore(autobase?.system?.core, 'autobase-system-core');
  addCore(autobase?.core, 'autobase-core');
  addCore(autobase?.local || autobase?.local?.core, 'autobase-local');
  addCore(autobase?.localInput || autobase?.localInput?.core, 'autobase-local');
  addCore(autobase?.localWriter || autobase?.localWriter?.core, 'autobase-local');
  addCore(autobase?.defaultWriter || autobase?.defaultWriter?.core, 'autobase-writer');
  addCore(autobase?.view || autobase?.view?.core, 'autobase-view');
  addArray(autobase?.activeWriters, 'autobase-writer');
  addArray(autobase?.writers, 'autobase-writer');
  addArray(
    Array.isArray(autobase?.inputs)
      ? autobase.inputs
      : (autobase?.inputs ? Array.from(autobase.inputs) : []),
    'autobase-writer'
  );
  if (autobase?.writer && typeof autobase.writer === 'object') {
    addCore(autobase.writer.core || autobase.writer, 'autobase-writer');
  }

  return entries;
}

async function loadRelayCoreRefsCache() {
  if (relayCoreRefsCacheLoaded) return;
  relayCoreRefsCacheLoaded = true;
  const cachePath = getRelayCoreRefsCachePath();
  try {
    const payload = await fs.readFile(cachePath, 'utf8');
    const parsed = JSON.parse(payload);
    const relays = parsed?.relays && typeof parsed.relays === 'object'
      ? parsed.relays
      : parsed;
    if (!relays || typeof relays !== 'object') return;
    for (const [relayKey, entry] of Object.entries(relays)) {
      const coreRefs = Array.isArray(entry) ? entry : entry?.coreRefs;
      const normalized = normalizeCoreRefList(coreRefs);
      if (!normalized.length) continue;
      relayMirrorCoreRefsCache.set(relayKey, normalized);
      const existing = relayMirrorCoreRefs.get(relayKey) || [];
      const merged = mergeCoreRefLists(existing, normalized);
      if (merged.length && coreRefsFingerprint(existing) !== coreRefsFingerprint(merged)) {
        relayMirrorCoreRefs.set(relayKey, merged);
      }
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      configuredLogger?.warn?.('[Worker] Failed to load relay core refs cache', {
        path: cachePath,
        error: error?.message || error
      });
    }
  }
}

function scheduleRelayCoreRefsCachePersist() {
  if (relayCoreRefsCacheTimer) return;
  relayCoreRefsCacheTimer = setTimeout(() => {
    relayCoreRefsCacheTimer = null;
    persistRelayCoreRefsCache().catch((error) => {
      configuredLogger?.warn?.('[Worker] Failed to persist relay core refs cache', {
        error: error?.message || error
      });
    });
  }, 2000);
  relayCoreRefsCacheTimer.unref?.();
}

export async function persistRelayCoreRefsCache(force = false) {
  await loadRelayCoreRefsCache();
  if (!force && !relayCoreRefsCacheDirty) return;
  const relays = {};
  for (const [relayKey, coreRefs] of relayMirrorCoreRefs.entries()) {
    const normalized = normalizeCoreRefList(coreRefs);
    if (!normalized.length) continue;
    relays[relayKey] = { coreRefs: normalized };
  }
  const payload = JSON.stringify({
    version: 1,
    updatedAt: new Date().toISOString(),
    relays
  }, null, 2);
  const cachePath = getRelayCoreRefsCachePath();
  try {
    await fs.mkdir(resolveStorageBase(), { recursive: true });
    await fs.writeFile(cachePath, payload, 'utf8');
    relayMirrorCoreRefsCache.clear();
    for (const [relayKey, entry] of Object.entries(relays)) {
      relayMirrorCoreRefsCache.set(relayKey, entry.coreRefs);
    }
    relayCoreRefsCacheDirty = false;
  } catch (error) {
    configuredLogger?.warn?.('[Worker] Failed to persist relay core refs cache', {
      path: cachePath,
      error: error?.message || error
    });
  }
}

export async function getRelayMirrorCoreRefsCache(relayKey) {
  await loadRelayCoreRefsCache();
  if (!relayKey) return [];
  const { canonicalKey, aliasKey } = await resolveCanonicalRelayKeys(relayKey, null);
  const direct = relayMirrorCoreRefsCache.get(relayKey) || [];
  const canonical = canonicalKey ? (relayMirrorCoreRefsCache.get(canonicalKey) || []) : [];
  const alias = aliasKey ? (relayMirrorCoreRefsCache.get(aliasKey) || []) : [];
  return mergeCoreRefLists(direct, canonical, alias);
}

export async function updateRelayMirrorCoreRefs(relayKey, coreRefs, { persist = true, publicIdentifier = null, updateAlias = true } = {}) {
  if (!relayKey || !Array.isArray(coreRefs) || !coreRefs.length) return;
  const normalized = normalizeCoreRefList(coreRefs);
  if (!normalized.length) return;

  const { canonicalKey, aliasKey } = await resolveCanonicalRelayKeys(relayKey, publicIdentifier);
  const targets = new Set();
  if (canonicalKey) targets.add(canonicalKey);
  if (!canonicalKey) targets.add(relayKey);
  if (updateAlias && aliasKey) targets.add(aliasKey);

  let changed = false;
  for (const key of targets) {
    const existing = relayMirrorCoreRefs.get(key) || [];
    if (coreRefsFingerprint(existing) === coreRefsFingerprint(normalized)) {
      continue;
    }
    relayMirrorCoreRefs.set(key, normalized);
    changed = true;
  }
  if (!changed) return;
  if (persist) {
    relayCoreRefsCacheDirty = true;
    scheduleRelayCoreRefsCachePersist();
  }
}

export async function resolveRelayMirrorCoreRefs(relayKey, publicIdentifier = null, fallbackRefs = []) {
  const normalizedFallback = normalizeCoreRefList(fallbackRefs);
  await loadRelayCoreRefsCache();

  const { canonicalKey, aliasKey } = await resolveCanonicalRelayKeys(relayKey, publicIdentifier);
  const cachedRefs = mergeCoreRefLists(
    relayKey ? (relayMirrorCoreRefsCache.get(relayKey) || []) : [],
    canonicalKey ? (relayMirrorCoreRefsCache.get(canonicalKey) || []) : [],
    aliasKey ? (relayMirrorCoreRefsCache.get(aliasKey) || []) : []
  );

  if (canonicalKey && relayMirrorCoreRefs.has(canonicalKey)) {
    const cached = relayMirrorCoreRefs.get(canonicalKey) || [];
    const merged = mergeCoreRefLists(cachedRefs, cached, normalizedFallback);
    await updateRelayMirrorCoreRefs(canonicalKey, merged, {
      publicIdentifier,
      updateAlias: true
    });
    return merged;
  }
  if (relayKey && relayMirrorCoreRefs.has(relayKey)) {
    const cached = relayMirrorCoreRefs.get(relayKey) || [];
    const merged = mergeCoreRefLists(cachedRefs, cached, normalizedFallback);
    await updateRelayMirrorCoreRefs(relayKey, merged, {
      publicIdentifier,
      updateAlias: true
    });
    return merged;
  }

  let profile = null;
  if (relayKey) {
    profile = await getRelayProfileByKey(relayKey);
  }
  if (!profile && publicIdentifier) {
    profile = await getRelayProfileByPublicIdentifier(publicIdentifier);
  }
  const storedRefs = normalizeCoreRefList(profile?.core_refs || profile?.coreRefs);
  const merged = mergeCoreRefLists(cachedRefs, storedRefs, normalizedFallback);
  await updateRelayMirrorCoreRefs(relayKey || canonicalKey || aliasKey, merged, {
    publicIdentifier,
    updateAlias: true
  });
  return merged;
}

export function previewCoreRefs(coreRefs = [], limit = 3) {
  if (!Array.isArray(coreRefs) || coreRefs.length === 0) return [];
  return coreRefs.slice(0, limit).map((ref) => String(ref).slice(0, 16));
}
