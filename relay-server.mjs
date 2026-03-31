// ./hyperpipe-worker/relay-server.mjs - Enhanced relay server with comprehensive debug logging
import Hyperswarm from 'hyperswarm';
import { RelayProtocol } from './relay-protocol.mjs';
import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';
import nodeCrypto from 'node:crypto';
import crypto from 'hypercore-crypto';
import Hypercore from 'hypercore';
import hypercoreCaps from 'hypercore/lib/caps.js';
import { setTimeout, setInterval, clearInterval, clearTimeout } from 'node:timers';
import b4a from 'b4a';
import { URL } from 'node:url';
import { initializeChallengeManager, getChallengeManager } from './challenge-manager.mjs';
import { getRelayAuthStore } from './relay-auth-store.mjs';
import { nobleSecp256k1 } from './pure-secp256k1.js';
import { NostrUtils } from './nostr-utils.js';
import { SimplePool } from 'nostr-tools/pool';
import { updateRelayAuthToken } from './hyperpipe-relay-profile-manager.mjs';
import { applyPendingAuthUpdates } from './pending-auth.mjs';
import HypercoreId from 'hypercore-id-encoding';
import {
  collectRelayCoreRefsFromAutobase,
  decodeCoreRef,
  mergeCoreRefLists,
  normalizeCoreRef,
  normalizeCoreRefList,
  resolveRelayMirrorCoreRefs,
  updateRelayMirrorCoreRefs
} from './relay-core-refs-store.mjs';
import {
  findMatchingRelayLeaseEnvelope,
  recordRelayLeaseReplicaPeer,
  upsertRelayLeaseEnvelope
} from './relay-lease-replica-store.mjs';
import {
  recordRelayCapabilityProbe,
  upsertRelayDiscoveryHints
} from './relay-discovery-store.mjs';
import {
  getRelayGatewayRoute
} from './relay-gateway-map-store.mjs';
import {
  createRelay as createRelayManager,
  joinRelay as joinRelayManager,
  disconnectRelay as disconnectRelayManager,
  getRelayProfiles,
  autoConnectStoredRelays,
  handleRelayMessage,
  handleRelaySubscription,
  getActiveRelays,
  cleanupRelays,
  updateRelaySubscriptions,
  getRelaySubscriptions,
  getRelayClientSubscriptions,
  updateRelayClientSubscriptions,
  rehydrateRelaySubscriptions,
  getRelayMembers,
  getRelayMetadata,
  activeRelays
} from './hyperpipe-relay-manager-adapter.mjs';

import {
  findRelayByPublicIdentifier,
  getRelayKeyFromPublicIdentifier,
  isRelayActiveByPublicIdentifier,
  normalizeRelayIdentifier
} from './relay-lookup-utils.mjs';

import {
  updateRelayMemberSets,
  getRelayProfileByKey,
  getRelayProfileByPublicIdentifier,
  saveRelayProfile,
  calculateAuthorizedUsers
} from './hyperpipe-relay-profile-manager.mjs';

import { getFile, getPfpFile } from './hyperdrive-manager.mjs';
import { loadGatewaySettings, getCachedGatewaySettings } from '@squip/hyperpipe-bridge/config/GatewaySettings';

const PUBLIC_GATEWAY_REPLICA_IDENTIFIER = 'public-gateway:hyperbee';
const PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED = false;
const { DEFAULT_NAMESPACE } = hypercoreCaps;
const HYPERPIPE_IDENTIFIER_TAG = 'hyperpipe:relay';
const HYPERPIPE_GATEWAY_ID_TAG = 'hyperpipe-gateway-id';
const HYPERPIPE_GATEWAY_ORIGIN_TAG = 'hyperpipe-gateway-origin';
const HYPERPIPE_DIRECT_JOIN_ONLY_TAG = 'hyperpipe-direct-join-only';
const KIND_GROUP_CREATE = 9007;
const KIND_GROUP_METADATA = 39000;
const KIND_GROUP_ADMIN_LIST = 39001;
const KIND_GROUP_MEMBER_LIST = 39002;
const KIND_HYPERPIPE_RELAY = 30166;
const CREATE_RELAY_BOOTSTRAP_MAX_ATTEMPTS = 3;
// Keep discovery bootstrap targets aligned with renderer/TUI BIG relay defaults.
const CREATE_RELAY_DISCOVERY_RELAYS = [
  'wss://relay.damus.io/',
  'wss://relay.primal.net/',
  'wss://nos.lol/',
  'wss://hypertuna.com/relay'
];

function isHex64(value) {
  return typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value.trim());
}

function normalizeRelayKeyHex(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || !isHex64(trimmed)) return null;
  return trimmed.toLowerCase();
}

function normalizePubkeyHex(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed || !/^[0-9a-fA-F]{64}$/.test(trimmed)) return null;
  return trimmed.toLowerCase();
}

function normalizeGatewayId(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim().toLowerCase();
  return trimmed.length ? trimmed : null;
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

function normalizePublicIdentifierForRoute(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  return normalizeRelayIdentifier(trimmed) || trimmed;
}

function normalizeGatewayRouteHint(hint) {
  if (!hint || typeof hint !== 'object') return null;
  const relayKey = normalizeRelayKeyHex(hint.relayKey || null);
  const publicIdentifier = normalizePublicIdentifierForRoute(
    hint.publicIdentifier || hint.identifier || null
  );
  if (!relayKey && !publicIdentifier) return null;
  return {
    relayKey,
    publicIdentifier,
    gatewayOrigin: normalizeHttpOrigin(hint.gatewayOrigin || null),
    gatewayId: normalizeGatewayId(hint.gatewayId || null),
    directJoinOnly: hint.directJoinOnly === true
  };
}

function normalizeGatewayRouteHints(routeHints = []) {
  if (!Array.isArray(routeHints)) return [];
  const normalized = [];
  for (const hint of routeHints) {
    const parsed = normalizeGatewayRouteHint(hint);
    if (parsed) normalized.push(parsed);
  }
  return normalized;
}

function findGatewayRouteHint(routeHints, { relayKey = null, publicIdentifier = null } = {}) {
  if (!Array.isArray(routeHints) || routeHints.length === 0) return null;
  const normalizedRelayKey = normalizeRelayKeyHex(relayKey);
  const normalizedPublicIdentifier = normalizePublicIdentifierForRoute(publicIdentifier);
  for (const hint of routeHints) {
    if (!hint) continue;
    if (normalizedRelayKey && hint.relayKey && hint.relayKey === normalizedRelayKey) {
      return hint;
    }
    if (
      normalizedPublicIdentifier
      && hint.publicIdentifier
      && hint.publicIdentifier === normalizedPublicIdentifier
    ) {
      return hint;
    }
  }
  return null;
}

async function getRelayGatewayRouteSafe({ relayKey = null, publicIdentifier = null } = {}) {
  try {
    return await getRelayGatewayRoute({ relayKey, publicIdentifier });
  } catch (error) {
    console.warn('[RelayServer] Failed to resolve relay gateway route', {
      relayKey: relayKey || null,
      publicIdentifier: publicIdentifier || null,
      error: error?.message || error
    });
    return null;
  }
}

function evaluateGatewayRegistrationRoute(route = null) {
  const gatewayOrigin = normalizeHttpOrigin(route?.gatewayOrigin || null);
  const gatewayId = normalizeGatewayId(route?.gatewayId || null);
  const directJoinOnly = route?.directJoinOnly === true;
  if (directJoinOnly) {
    return {
      eligible: false,
      reason: 'direct-join-only',
      gatewayOrigin,
      gatewayId
    };
  }
  if (gatewayOrigin || gatewayId) {
    return {
      eligible: true,
      reason: 'mapped',
      gatewayOrigin,
      gatewayId
    };
  }
  return {
    eligible: false,
    reason: 'gateway-unassigned',
    gatewayOrigin: null,
    gatewayId: null
  };
}

async function resolveRelayGatewayRegistrationEligibility({
  relayKey = null,
  publicIdentifier = null,
  gatewayOrigin = null,
  gatewayId = null,
  directJoinOnly = null
} = {}) {
  const normalizedRelayKey = normalizeRelayKeyHex(relayKey);
  const normalizedPublicIdentifier = normalizePublicIdentifierForRoute(publicIdentifier);
  const explicitGatewayOrigin = normalizeHttpOrigin(gatewayOrigin);
  const explicitGatewayId = normalizeGatewayId(gatewayId);
  const explicitDirectJoinOnly = directJoinOnly === true;
  const hasExplicitRouteInput = explicitDirectJoinOnly || !!explicitGatewayOrigin || !!explicitGatewayId;

  if (hasExplicitRouteInput) {
    const explicitRoute = {
      relayKey: normalizedRelayKey,
      publicIdentifier: normalizedPublicIdentifier,
      gatewayOrigin: explicitGatewayOrigin,
      gatewayId: explicitGatewayId,
      directJoinOnly: explicitDirectJoinOnly
    };
    const evaluation = evaluateGatewayRegistrationRoute(explicitRoute);
    return {
      ...evaluation,
      route: explicitRoute,
      source: 'explicit'
    };
  }

  const storedRoute = await getRelayGatewayRouteSafe({
    relayKey: normalizedRelayKey || null,
    publicIdentifier: normalizedPublicIdentifier || null
  });
  const evaluation = evaluateGatewayRegistrationRoute(storedRoute);
  return {
    ...evaluation,
    route: storedRoute,
    source: 'stored'
  };
}

function normalizeAuthTokenValue(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function assertTokenOwnerMatchesExpectedPubkey({
  relayKey,
  publicIdentifier,
  authToken,
  expectedPubkey,
  context = 'join'
} = {}) {
  const token = normalizeAuthTokenValue(authToken);
  const normalizedExpectedPubkey =
    normalizePubkeyHex(expectedPubkey) || (typeof expectedPubkey === 'string' ? expectedPubkey.trim().toLowerCase() : null);
  if (!token || !normalizedExpectedPubkey) {
    return { checked: false, matched: false, source: null };
  }

  const relayRefs = [];
  const normalizedRelayKey = normalizeRelayKeyHex(relayKey) || (typeof relayKey === 'string' ? relayKey.trim() : null);
  const normalizedIdentifier =
    typeof publicIdentifier === 'string' && publicIdentifier.trim()
      ? normalizeRelayIdentifier(publicIdentifier.trim()) || publicIdentifier.trim()
      : null;
  if (normalizedRelayKey) relayRefs.push(normalizedRelayKey);
  if (normalizedIdentifier && !relayRefs.includes(normalizedIdentifier)) relayRefs.push(normalizedIdentifier);

  if (!relayRefs.length) {
    return { checked: false, matched: false, source: null };
  }

  const authStore = getRelayAuthStore();
  for (const relayRef of relayRefs) {
    const existing = authStore.verifyAuth(relayRef, token);
    if (!existing?.pubkey) continue;
    const tokenPubkey = normalizePubkeyHex(existing.pubkey) || String(existing.pubkey).trim().toLowerCase();
    if (!tokenPubkey || tokenPubkey === normalizedExpectedPubkey) {
      return { checked: true, matched: true, source: relayRef };
    }
    const mismatchError = new Error(
      `auth-token-owner-mismatch (${context}) expected=${normalizedExpectedPubkey.slice(0, 8)} token=${tokenPubkey.slice(0, 8)}`
    );
    mismatchError.code = 'auth-token-owner-mismatch';
    mismatchError.context = context;
    mismatchError.relayRef = relayRef;
    mismatchError.expectedPubkey = normalizedExpectedPubkey;
    mismatchError.tokenPubkey = tokenPubkey;
    throw mismatchError;
  }

  return { checked: true, matched: false, source: null };
}

export function deriveRelayDiscoveryTopic(identifier) {
  const normalized = normalizeRelayIdentifier(identifier || '');
  if (!normalized) return null;
  return sha256Hex(`hyperpipe:relay-topic:v1:${normalized}`);
}

function parseNostrMessagePayload(message) {
  if (typeof message === 'string') {
    const trimmed = message.trim();
    if (!trimmed.length) {
      throw new Error('Empty NOSTR message payload');
    }
    return JSON.parse(trimmed);
  }

  if (message && message.type === 'Buffer' && Array.isArray(message.data)) {
    const messageStr = b4a.from(message.data).toString('utf8');
    if (!messageStr.trim().length) {
      throw new Error('Empty NOSTR message payload');
    }
    return JSON.parse(messageStr);
  }

  return message;
}

function getRelayWritableGate(relayKey) {
  if (!relayKey || !activeRelays?.get) {
    return { available: false, writable: null };
  }
  const relayManager = activeRelays.get(relayKey);
  if (!relayManager) {
    return { available: false, writable: null };
  }
  const writable = relayManager?.relay?.writable === true;
  return { available: true, writable };
}


// Global state
let config = null;
let swarm = null;
let gatewayRegistrationInterval = null;
let gatewayConnection = null;
let relayServerShuttingDown = false;
let pendingRegistrations = []; // Queue registrations until gateway connects
let connectedPeers = new Map(); // Track all connected peers
const relayClientConnections = new Map(); // relayKey -> Map(clientId -> { connectionKey, updatedAt })

function shouldSuppressMissingRelayLog(identifier) {
  if (identifier === PUBLIC_GATEWAY_REPLICA_IDENTIFIER) return true;
  return relayServerShuttingDown && identifier === PUBLIC_GATEWAY_REPLICA_IDENTIFIER;
}

function getRelayClientMap(relayKey) {
  let map = relayClientConnections.get(relayKey);
  if (!map) {
    map = new Map();
    relayClientConnections.set(relayKey, map);
  }
  return map;
}

function getRelayClientConnectionKey(relayKey, clientId) {
  if (!relayKey || !clientId) return null;
  const map = relayClientConnections.get(relayKey);
  return map?.get(clientId)?.connectionKey || null;
}

function setRelayClientConnectionKey(relayKey, clientId, connectionKey) {
  if (!relayKey || !clientId || !connectionKey) return null;
  const map = getRelayClientMap(relayKey);
  const previous = map.get(clientId)?.connectionKey || null;
  map.set(clientId, { connectionKey, updatedAt: Date.now() });
  return previous;
}

function resetSubscriptionTimestamps(snapshot, connectionKey) {
  if (!snapshot || typeof snapshot !== 'object') return null;
  if (!snapshot.subscriptions || typeof snapshot.subscriptions !== 'object') return null;
  const touchedAt = Date.now();
  const subscriptions = {};
  for (const [subscriptionId, subscription] of Object.entries(snapshot.subscriptions)) {
    subscriptions[subscriptionId] = {
      ...subscription,
      last_returned_event_timestamp: null,
      updated_at: touchedAt
    };
  }
  return {
    ...snapshot,
    connection: connectionKey || snapshot.connection || null,
    subscriptions
  };
}

function isEphemeralSubscriptionId(subscriptionId) {
  return typeof subscriptionId === 'string' && subscriptionId.startsWith('f-fetch-events');
}

const SUBSCRIPTION_REFRESH_MAX_ENTRIES = 128;
const SUBSCRIPTION_REFRESH_MAX_TIMELINE_ENTRIES = 32;
const TIMELINE_SUBSCRIPTION_STALE_TTL_MS = 20 * 60 * 1000;
const TIMELINE_VOLATILE_FILTER_KEYS = new Set(['since', 'until', 'limit']);

function isTimelineSubscriptionId(subscriptionId) {
  return typeof subscriptionId === 'string' && subscriptionId.startsWith('f-timeline');
}

function buildSubscriptionSignature(entry, { stripVolatileTimelineKeys = false } = {}) {
  if (!entry || typeof entry !== 'object') return null;
  const filters = Array.isArray(entry.filters) ? entry.filters : null;
  if (!filters || filters.length === 0) return null;
  try {
    const normalized = filters.map((filter) => {
      if (!filter || typeof filter !== 'object') return filter;
      const normalizedFilter = {};
      const keys = Object.keys(filter).sort();
      for (const key of keys) {
        if (stripVolatileTimelineKeys && TIMELINE_VOLATILE_FILTER_KEYS.has(key)) {
          continue;
        }
        const value = filter[key];
        if (Array.isArray(value)) {
          normalizedFilter[key] = [...value].sort((a, b) =>
            String(a).localeCompare(String(b))
          );
        } else if (value && typeof value === 'object' && !Array.isArray(value)) {
          normalizedFilter[key] = JSON.parse(JSON.stringify(value));
        } else {
          normalizedFilter[key] = value;
        }
      }
      return normalizedFilter;
    });
    return JSON.stringify(normalized);
  } catch (_) {
    return null;
  }
}

function getTimelineSubscriptionBaseId(subscriptionId) {
  if (typeof subscriptionId !== 'string') return null;
  const separatorIdx = subscriptionId.indexOf(':');
  return separatorIdx === -1 ? subscriptionId : subscriptionId.slice(0, separatorIdx);
}

function getSubscriptionEntryUpdatedAtMs(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const updatedAt = entry.updated_at;
  if (Number.isFinite(updatedAt)) return updatedAt;
  const lastReturned = entry.last_returned_event_timestamp;
  if (Number.isFinite(lastReturned)) return lastReturned * 1000;
  return null;
}

function getSubscriptionEntryTimestamp(entry) {
  const ts = getSubscriptionEntryUpdatedAtMs(entry);
  return Number.isFinite(ts) ? ts : -Infinity;
}

function isStaleTimelineSubscription(entry, nowMs, staleTimelineTtlMs) {
  if (!Number.isFinite(staleTimelineTtlMs) || staleTimelineTtlMs <= 0) {
    return false;
  }
  const updatedAt = getSubscriptionEntryUpdatedAtMs(entry);
  if (!Number.isFinite(updatedAt)) return false;
  return nowMs - updatedAt > staleTimelineTtlMs;
}

function compactSubscriptionSnapshot(
  snapshot,
  {
    preferredSubscriptionId = null,
    maxEntries = SUBSCRIPTION_REFRESH_MAX_ENTRIES,
    maxTimelineEntries = SUBSCRIPTION_REFRESH_MAX_TIMELINE_ENTRIES,
    staleTimelineTtlMs = TIMELINE_SUBSCRIPTION_STALE_TTL_MS
  } = {}
) {
  if (!snapshot || typeof snapshot !== 'object') return snapshot;
  if (!snapshot.subscriptions || typeof snapshot.subscriptions !== 'object') return snapshot;
  const nowMs = Date.now();
  const nonTimelineEntries = [];
  const timelineBySignature = new Map();

  for (const [subscriptionId, entry] of Object.entries(snapshot.subscriptions)) {
    if (isEphemeralSubscriptionId(subscriptionId)) {
      continue;
    }

    if (!isTimelineSubscriptionId(subscriptionId)) {
      nonTimelineEntries.push([subscriptionId, entry]);
      continue;
    }

    if (
      subscriptionId !== preferredSubscriptionId &&
      isStaleTimelineSubscription(entry, nowMs, staleTimelineTtlMs)
    ) {
      continue;
    }

    const timelineBaseId = getTimelineSubscriptionBaseId(subscriptionId) || subscriptionId;
    const signature =
      buildSubscriptionSignature(entry, { stripVolatileTimelineKeys: true }) || '__nosig';
    const dedupeKey = `${timelineBaseId}|${signature}`;
    const existing = timelineBySignature.get(dedupeKey);
    if (!existing) {
      timelineBySignature.set(dedupeKey, { subscriptionId, entry });
      continue;
    }

    const existingPreferred = existing.subscriptionId === preferredSubscriptionId;
    const incomingPreferred = subscriptionId === preferredSubscriptionId;
    if (incomingPreferred && !existingPreferred) {
      timelineBySignature.set(dedupeKey, { subscriptionId, entry });
      continue;
    }
    if (!incomingPreferred && existingPreferred) {
      continue;
    }

    if (getSubscriptionEntryTimestamp(entry) > getSubscriptionEntryTimestamp(existing.entry)) {
      timelineBySignature.set(dedupeKey, { subscriptionId, entry });
    }
  }

  const timelineEntries = Array.from(timelineBySignature.values())
    .sort((left, right) => {
      if (left.subscriptionId === preferredSubscriptionId) return -1;
      if (right.subscriptionId === preferredSubscriptionId) return 1;
      return getSubscriptionEntryTimestamp(right.entry) - getSubscriptionEntryTimestamp(left.entry);
    })
    .slice(0, maxTimelineEntries)
    .map(({ subscriptionId, entry }) => [subscriptionId, entry]);

  const compactedEntries = [...nonTimelineEntries, ...timelineEntries];

  if (compactedEntries.length > maxEntries) {
    compactedEntries.sort((left, right) => {
      if (left[0] === preferredSubscriptionId) return -1;
      if (right[0] === preferredSubscriptionId) return 1;
      return getSubscriptionEntryTimestamp(right[1]) - getSubscriptionEntryTimestamp(left[1]);
    });
  }

  const limited = {};
  for (const [subscriptionId, entry] of compactedEntries.slice(0, maxEntries)) {
    limited[subscriptionId] = entry;
  }

  return {
    ...snapshot,
    subscriptions: limited
  };
}

function mergeSubscriptionEntry(primary = {}, secondary = {}) {
  const merged = { ...secondary, ...primary };
  if (!merged.filters) {
    merged.filters = primary.filters || secondary.filters;
  }

  const primaryTimestamp = primary.last_returned_event_timestamp;
  const secondaryTimestamp = secondary.last_returned_event_timestamp;
  if (Number.isFinite(primaryTimestamp) || Number.isFinite(secondaryTimestamp)) {
    const safePrimary = Number.isFinite(primaryTimestamp) ? primaryTimestamp : -Infinity;
    const safeSecondary = Number.isFinite(secondaryTimestamp) ? secondaryTimestamp : -Infinity;
    merged.last_returned_event_timestamp = Math.max(safePrimary, safeSecondary);
  }

  const primaryUpdatedAt = getSubscriptionEntryUpdatedAtMs(primary);
  const secondaryUpdatedAt = getSubscriptionEntryUpdatedAtMs(secondary);
  if (Number.isFinite(primaryUpdatedAt) || Number.isFinite(secondaryUpdatedAt)) {
    const safePrimaryUpdated = Number.isFinite(primaryUpdatedAt) ? primaryUpdatedAt : -Infinity;
    const safeSecondaryUpdated = Number.isFinite(secondaryUpdatedAt) ? secondaryUpdatedAt : -Infinity;
    merged.updated_at = Math.max(safePrimaryUpdated, safeSecondaryUpdated);
  }

  return merged;
}

function mergeSubscriptionSnapshots(primarySnapshot, secondarySnapshot) {
  const primarySubscriptions = primarySnapshot?.subscriptions && typeof primarySnapshot.subscriptions === 'object'
    ? primarySnapshot.subscriptions
    : {};
  const secondarySubscriptions = secondarySnapshot?.subscriptions && typeof secondarySnapshot.subscriptions === 'object'
    ? secondarySnapshot.subscriptions
    : {};
  const mergedSubscriptions = { ...secondarySubscriptions };

  for (const [subscriptionId, entry] of Object.entries(primarySubscriptions)) {
    mergedSubscriptions[subscriptionId] = mergeSubscriptionEntry(entry, mergedSubscriptions[subscriptionId]);
  }

  const merged = {
    ...(secondarySnapshot || {}),
    ...(primarySnapshot || {}),
    subscriptions: mergedSubscriptions
  };

  if (primarySnapshot?.connection || secondarySnapshot?.connection) {
    merged.connection = primarySnapshot?.connection || secondarySnapshot?.connection || null;
  }
  if (primarySnapshot?.clientId || secondarySnapshot?.clientId) {
    merged.clientId = primarySnapshot?.clientId || secondarySnapshot?.clientId || null;
  }

  return merged;
}

export async function requestRelaySubscriptionRefresh(relayKey, { reason = 'writer-sync' } = {}) {
  if (!relayKey) {
    return { status: 'skipped', reason: 'missing-relay-key', total: 0, updated: 0, failed: 0 };
  }
  const map = relayClientConnections.get(relayKey);
  if (!map || map.size === 0) {
    const knownRelayKeys = Array.from(relayClientConnections.keys());
    console.log('[RelayServer] Subscription refresh skipped (no clients)', { relayKey, reason });
    console.log('[RelayServer] Subscription refresh skip diagnostics', {
      relayKey,
      reason,
      knownRelayCount: knownRelayKeys.length,
      knownRelayPreview: knownRelayKeys.slice(0, 10),
      requestedRelayKnown: knownRelayKeys.includes(relayKey)
    });
    return { status: 'skipped', reason: 'no-clients', total: 0, updated: 0, failed: 0 };
  }

  const summary = {
    status: 'ok',
    reason,
    total: map.size,
    updated: 0,
    failed: 0
  };

  for (const [clientId, info] of map.entries()) {
    const connectionKey = info?.connectionKey || null;
    if (!connectionKey) continue;
    let updated = false;

    try {
      const snapshot = await getRelaySubscriptions(relayKey, connectionKey);
      const compactSnapshot = compactSubscriptionSnapshot(snapshot);
      const resetSnapshot = resetSubscriptionTimestamps(compactSnapshot, connectionKey);
      if (resetSnapshot) {
        await updateRelaySubscriptions(relayKey, connectionKey, resetSnapshot);
        updated = true;
      }
    } catch (error) {
      summary.failed += 1;
      console.warn('[RelayServer] Failed to reset connection subscription cursor', {
        relayKey,
        connectionKey,
        reason,
        error: error?.message || error
      });
    }

    if (clientId) {
      try {
        const clientSnapshot = await getRelayClientSubscriptions(relayKey, clientId);
        const compactClientSnapshot = compactSubscriptionSnapshot(clientSnapshot);
        const resetClient = resetSubscriptionTimestamps(compactClientSnapshot, connectionKey);
        if (resetClient) {
          await updateRelayClientSubscriptions(relayKey, clientId, resetClient);
          updated = true;
        }
      } catch (error) {
        summary.failed += 1;
        console.warn('[RelayServer] Failed to reset client subscription cursor', {
          relayKey,
          clientId,
          reason,
          error: error?.message || error
        });
      }
    }

    if (updated) {
      summary.updated += 1;
    }
  }

  console.log('[RelayServer] Subscription refresh complete', {
    relayKey,
    reason,
    total: summary.total,
    updated: summary.updated,
    failed: summary.failed
  });
  return summary;
}
const lateWriterRecoveryTasks = new Map();
function resolveTimeoutEnvMs(name, fallbackMs, { minMs = 1, allowDisable = false } = {}) {
  const raw = process.env[name];
  if (typeof raw !== 'string' || !raw.trim()) return fallbackMs;
  const normalized = raw.trim().toLowerCase();
  if (
    allowDisable
    && (
      normalized === '0'
      || normalized === 'false'
      || normalized === 'off'
      || normalized === 'disabled'
      || normalized === 'none'
    )
  ) {
    return null;
  }
  const parsed = Number(raw);
  if (allowDisable && parsed <= 0) return null;
  if (!Number.isFinite(parsed) || parsed < minMs) return fallbackMs;
  return Math.floor(parsed);
}

function normalizeGatewayMode(value) {
  return value === 'disabled' ? 'disabled' : 'auto';
}

const BLIND_PEER_JOIN_WRITABLE_TIMEOUT_MS = resolveTimeoutEnvMs(
  'BLIND_PEER_JOIN_WRITABLE_TIMEOUT_MS',
  90000,
  { minMs: 1000 }
);
const MIRROR_WARM_GATE_TIMEOUT_MS = resolveTimeoutEnvMs(
  'MIRROR_WARM_GATE_TIMEOUT_MS',
  4000,
  { minMs: 250, allowDisable: true }
);
const MIRROR_WARM_GATE_POLL_MS = resolveTimeoutEnvMs(
  'MIRROR_WARM_GATE_POLL_MS',
  250,
  { minMs: 50 }
);
// NOTE: We previously experimented with a "join sync gate" that delayed calling
// relay.update({ wait: true }) during cold-sync, but it commonly timed out and
// only added latency. The logic has been removed; keep only cheap snapshot logs.
const DIRECT_JOIN_WRITABLE_TIMEOUT_MS = resolveTimeoutEnvMs(
  'DIRECT_JOIN_WRITABLE_TIMEOUT_MS',
  15000,
  { minMs: 1000 }
);
const DIRECT_JOIN_VERIFY_TIMEOUT_MS = resolveTimeoutEnvMs(
  'DIRECT_JOIN_VERIFY_TIMEOUT_MS',
  null,
  { minMs: 1000, allowDisable: true }
);
const LATE_WRITER_RECOVERY_TIMEOUT_MS = resolveTimeoutEnvMs(
  'LATE_WRITER_RECOVERY_TIMEOUT_MS',
  180000,
  { minMs: 1000 }
);
const GATEWAY_REGISTRATION_REQUEST_TIMEOUT_MS = resolveTimeoutEnvMs(
  'GATEWAY_REGISTRATION_REQUEST_TIMEOUT_MS',
  12000,
  { minMs: 500 }
);
const WRITER_LEASE_SYNC_RATE_LIMIT_MAX = 24;
const WRITER_LEASE_SYNC_RATE_LIMIT_WINDOW_MS = 60 * 1000;
const WRITER_LEASE_ENVELOPE_VERSION = 1;
let pendingPeerProtocols = new Map(); // Awaiters for outbound connections
const peerJoinHandles = new Map(); // Persistent joinPeer handles
const writerLeaseSyncRateLimits = new Map();
const joinAuthAttemptLocks = new Map(); // `${publicIdentifier}:${pubkey}` -> { startedAt, attemptId }
let healthMonitorTimer = null;

// Enhanced health state tracking
let healthState = {
  startTime: Date.now(),
  lastCheck: Date.now(),
  status: 'initializing',
  activeRelaysCount: 0,
  metrics: {
    totalRequests: 0,
    successfulRequests: 0,
    failedRequests: 0,
    lastMetricsReset: Date.now()
  },
  services: {
    hyperswarmStatus: 'initializing',
    protocolStatus: 'initializing',
    gatewayStatus: 'disconnected'
  }
};

function getGatewayWebsocketProtocol(cfg = config) {
  const protocol = cfg?.proxy_websocket_protocol === 'ws' ? 'ws' : 'wss';
  return protocol;
}

function buildGatewayWebsocketBase(cfg = config) {
  const protocol = getGatewayWebsocketProtocol(cfg);
  const host = cfg?.proxy_server_address || 'localhost';
  return `${protocol}://${host}`;
}

function buildCanonicalRelayUrl(identifier, authToken = null, cfg = config) {
  const normalizedIdentifier = normalizeRelayIdentifier(identifier || '') || String(identifier || '').trim();
  if (!normalizedIdentifier) return null;
  const identifierPath = normalizedIdentifier.includes(':')
    ? normalizedIdentifier.replace(':', '/')
    : normalizedIdentifier;
  const baseUrl = `${buildGatewayWebsocketBase(cfg)}/${identifierPath}`;
  const token = normalizeAuthTokenValue(authToken);
  return token ? `${baseUrl}?token=${token}` : baseUrl;
}

export function applyRuntimeGatewayEndpoint({
  gatewayUrl = null,
  proxyHost = null,
  proxyWebsocketProtocol = null
} = {}) {
  if (!config || typeof config !== 'object') {
    return { applied: false, reason: 'config-uninitialized' };
  }

  const normalizedGatewayUrl = toHttpOrigin(gatewayUrl);
  const normalizedProxyHost =
    typeof proxyHost === 'string' && proxyHost.trim()
      ? proxyHost.trim()
      : null;
  const normalizedWsProtocol =
    proxyWebsocketProtocol === 'ws' || proxyWebsocketProtocol === 'wss'
      ? proxyWebsocketProtocol
      : null;

  let changed = false;

  if (normalizedGatewayUrl && config.gatewayUrl !== normalizedGatewayUrl) {
    config.gatewayUrl = normalizedGatewayUrl;
    changed = true;
  }
  if (normalizedProxyHost && config.proxy_server_address !== normalizedProxyHost) {
    config.proxy_server_address = normalizedProxyHost;
    changed = true;
  }
  if (normalizedWsProtocol && config.proxy_websocket_protocol !== normalizedWsProtocol) {
    config.proxy_websocket_protocol = normalizedWsProtocol;
    changed = true;
  }

  if (changed) {
    console.log('[RelayServer] Runtime gateway endpoint updated', {
      gatewayUrl: config.gatewayUrl || null,
      proxyServerAddress: config.proxy_server_address || null,
      proxyWebsocketProtocol: config.proxy_websocket_protocol || null
    });
  }

  return {
    applied: true,
    changed,
    gatewayUrl: config.gatewayUrl || null,
    proxyServerAddress: config.proxy_server_address || null,
    proxyWebsocketProtocol: config.proxy_websocket_protocol || null
  };
}

function previewValue(value, limit = 16) {
  if (!value) return null;
  const str = String(value);
  return str.length > limit ? `${str.slice(0, limit)}...` : str;
}

function toHttpOrigin(value) {
  if (!value || typeof value !== 'string') return null;
  try {
    const url = new URL(value);
    if (url.protocol === 'ws:') url.protocol = 'http:';
    if (url.protocol === 'wss:') url.protocol = 'https:';
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return null;
    }
    return url.origin;
  } catch (_err) {
    if (/^wss?:\/\//i.test(value)) {
      return value.replace(/^wss:\/\//i, 'https://').replace(/^ws:\/\//i, 'http://').replace(/\/$/, '');
    }
    if (/^https?:\/\//i.test(value)) {
      try {
        return new URL(value).origin;
      } catch (_) {
        return null;
      }
    }
    return null;
  }
}

function extractIdentifierFromRelayUrl(relayUrl) {
  if (!relayUrl || typeof relayUrl !== 'string') return null;
  try {
    const parsed = new URL(relayUrl);
    const parts = parsed.pathname.split('/').filter(Boolean);
    if (!parts.length) return null;
    if (parts.length >= 2 && parts[0].startsWith('npub')) {
      return `${parts[0]}:${parts[1]}`;
    }
    return parts[0] || null;
  } catch (_err) {
    const parts = relayUrl.split('/').filter(Boolean);
    if (!parts.length) return null;
    if (parts.length >= 2 && parts[0].startsWith('npub')) {
      return `${parts[0]}:${parts[1]}`;
    }
    return parts[0] || null;
  }
}

async function collectGatewayHttpOrigins() {
  const origins = new Set();
  const cachedSettings = getCachedGatewaySettings();
  const cachedOrigin = toHttpOrigin(cachedSettings?.gatewayUrl);
  if (cachedOrigin) origins.add(cachedOrigin);

  const configOrigin = toHttpOrigin(config?.gatewayUrl);
  if (configOrigin) origins.add(configOrigin);

  try {
    const loaded = await loadGatewaySettings();
    const loadedOrigin = toHttpOrigin(loaded?.gatewayUrl);
    if (loadedOrigin) origins.add(loadedOrigin);
  } catch (_err) {
    // ignore load failures; fall back to cached
  }

  return Array.from(origins);
}

async function fetchMirrorMetadataFromGateway(identifier, { reason = 'join-fallback' } = {}) {
  if (!identifier) return { status: 'skipped', reason: 'missing-identifier' };
  const fetchImpl = globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    return { status: 'skipped', reason: 'fetch-unavailable' };
  }

  const origins = await collectGatewayHttpOrigins();
  if (!origins.length) {
    return { status: 'skipped', reason: 'gateway-origin-unavailable' };
  }
  let lastError = null;

  for (const origin of origins) {
    if (!origin) continue;
    const url = `${origin.replace(/\/$/, '')}/api/relays/${encodeURIComponent(identifier)}/mirror`;
    try {
      console.log('[RelayServer] Mirror metadata request', {
        identifier,
        origin,
        reason
      });
      const response = await fetchImpl(url);
      if (!response.ok) {
        lastError = new Error(`status ${response.status}`);
        continue;
      }
      const data = await response.json().catch(() => null);
      if (!data || typeof data !== 'object') {
        lastError = new Error('invalid-payload');
        continue;
      }
      const mirrorRelayKey = data.relayKey || data.relay_key || null;
      const mirrorBlindPeer = data.blindPeer || data.blind_peer || null;
      console.log('[RelayServer] Mirror metadata response', {
        identifier,
        origin,
        relayKey: previewValue(mirrorRelayKey, 16),
        publicIdentifier: data.publicIdentifier || data.public_identifier || null,
        coreRefsCount: Array.isArray(data.cores) ? data.cores.length : 0,
        blindPeerKey: previewValue(mirrorBlindPeer?.publicKey, 16),
        blindPeerHasEncryptionKey: !!mirrorBlindPeer?.encryptionKey
      });
      return { status: 'ok', origin, data };
    } catch (error) {
      lastError = error;
    }
  }

  if (lastError) {
    console.warn('[RelayServer] Mirror metadata lookup failed', {
      identifier,
      reason,
      error: lastError?.message || lastError
    });
  }

  return { status: 'error', reason: 'mirror-unavailable', error: lastError };
}

// Initialize with enhanced config
export async function initializeRelayServer(customConfig = {}) {
  relayServerShuttingDown = false;
  console.log('[RelayServer] ========================================');
  console.log('[RelayServer] Initializing with Hyperswarm support...');
  console.log('[RelayServer] Timestamp:', new Date().toISOString());
  
  const fallbackGatewaySettings = getCachedGatewaySettings();
  let gatewaySettings = fallbackGatewaySettings;
  try {
    gatewaySettings = await loadGatewaySettings();
  } catch (error) {
    console.error('[RelayServer] Failed to load gateway settings, using cached defaults:', error);
  }

  const defaultGatewayUrl = gatewaySettings.gatewayUrl || fallbackGatewaySettings.gatewayUrl;
  const defaultProxyHost = gatewaySettings.proxyHost || fallbackGatewaySettings.proxyHost;
  const defaultProxyProtocol = gatewaySettings.proxyWebsocketProtocol || fallbackGatewaySettings.proxyWebsocketProtocol;

  // Merge with defaults
  config = {
    userKey: customConfig.userKey,  // Preserve user key
    port: 1945,
    nostr_pubkey_hex: customConfig.nostr_pubkey_hex || generateHexKey(),
    nostr_nsec_hex: customConfig.nostr_nsec_hex || generateHexKey(),
    proxy_privateKey: customConfig.proxy_privateKey || generateHexKey(),
    proxy_publicKey: customConfig.proxy_publicKey || generateHexKey(),
    proxy_seed: customConfig.proxy_seed || generateHexKey(),
    proxy_server_address: customConfig.proxy_server_address || defaultProxyHost,
    proxy_websocket_protocol: customConfig.proxy_websocket_protocol || defaultProxyProtocol,
    gatewayUrl: customConfig.gatewayUrl || defaultGatewayUrl,
    registerWithGateway: customConfig.registerWithGateway ?? true,
    registerInterval: customConfig.registerInterval || 60000,
    relays: customConfig.relays || [],
    storage: customConfig.storage || global.userConfig?.storage || process.env.STORAGE_DIR || join(process.cwd(), 'data'),
    // Add gateway public key if known (optional)
    gatewayPublicKey: customConfig.gatewayPublicKey || null,
    pfpDriveKey: customConfig.pfpDriveKey || null,
    ...customConfig
  };
  
  console.log('[RelayServer] Configuration:', {
    proxy_server_address: config.proxy_server_address,
    gatewayUrl: config.gatewayUrl,
    registerWithGateway: config.registerWithGateway,
    registerInterval: config.registerInterval,
    gatewayPublicKey: config.gatewayPublicKey ? config.gatewayPublicKey.substring(0, 8) + '...' : 'not set',
    storage: config.storage,
    userKey: config.userKey ? config.userKey.substring(0, 8) + '...' : 'not set'
  });
  
  // Save config to storage
  await saveConfig(config);
  
  // Start Hyperswarm server
  await startHyperswarmServer();

  if (customConfig && typeof customConfig === 'object') {
    customConfig.swarmPublicKey = config.swarmPublicKey;
    customConfig.proxy_seed = config.proxy_seed;
    customConfig.proxy_privateKey = config.proxy_privateKey;
    customConfig.proxy_publicKey = config.proxy_publicKey;
  }

  // Initialize challenge manager with relay private key
  console.log('[RelayServer] Initializing challenge manager...');
  initializeChallengeManager(config.nostr_nsec_hex);
  
  // Initialize auth store
  const authStore = getRelayAuthStore();
  console.log('[RelayServer] Auth store initialized');
  
  console.log('[RelayServer] Base initialization complete (gateway startup deferred)');
  console.log('[RelayServer] ========================================');
  
  return true;
}

export async function connectStoredRelays() {
  if (!config) {
    throw new Error('Relay server not initialized');
  }

  let connectedRelays = [];

  try {
    console.log('[RelayServer] Starting auto-connection to stored relays...');
    connectedRelays = await autoConnectStoredRelays(config);
    console.log(`[RelayServer] Auto-connected to ${connectedRelays.length} relays`);

    if (config.registerWithGateway) {
      console.log('[RelayServer] Registering auto-connected relays with gateway...');

      if (connectedRelays.length > 0) {
        for (const relayKey of connectedRelays) {
          try {
            const profile = await getRelayProfileByKey(relayKey);
            if (!profile) continue;

            await registerWithGateway(profile);
          } catch (regError) {
            console.error(`[RelayServer] Failed to register relay ${relayKey}:`, regError);
          }
        }
      } else {
        try {
          await registerWithGateway();
        } catch (regError) {
          console.error('[RelayServer] Failed to register gateway metadata with no connected relays:', regError);
        }
      }
    }
  } catch (error) {
    console.error('[RelayServer] Error during auto-connection:', error);
  }

  try {
    await updateHealthState();
  } catch (error) {
    console.warn('[RelayServer] Failed to update health state after auto-connect:', error.message);
  }

  startHealthMonitoring();

  if (config.registerWithGateway) {
    console.log('[RelayServer] Gateway registration is ENABLED');

    // Try to register immediately if we have pending registrations
    processPendingRegistrations();

    if (gatewayRegistrationInterval) {
      clearInterval(gatewayRegistrationInterval);
      gatewayRegistrationInterval = null;
    }

    gatewayRegistrationInterval = setInterval(() => {
      console.log('[RelayServer] Periodic registration check...');
      if (gatewayConnection) {
        console.log('[RelayServer] Gateway connected, performing registration');
        registerWithGateway().catch((error) => {
          console.error('[RelayServer] Periodic gateway registration failed:', error.message);
        });
      } else {
        console.log('[RelayServer] No gateway connection for periodic registration');
        console.log('[RelayServer] Connected peers:', Array.from(connectedPeers.keys()).map(k => k.substring(0, 8) + '...'));
      }
    }, config.registerInterval);

    // Trigger initial registration via Hyperswarm after a brief delay
    setTimeout(async () => {
      if (!config.registerWithGateway) return;
      console.log('[RelayServer] Performing initial Hyperswarm registration with gateway...');
      try {
        await registerWithGateway();
      } catch (error) {
        console.error('[RelayServer] Initial gateway registration failed:', error.message);
      }
    }, 2000);
  } else {
    console.log('[RelayServer] Gateway registration is DISABLED');
  }

  return connectedRelays;
}

function generateHexKey() {
  return crypto.randomBytes(32).toString('hex');
}

function sanitizeConfigForDisk(configData) {
  if (!configData || typeof configData !== 'object') return configData;
  const sanitized = { ...configData };

  // Never persist nostr private keys (memory-only).
  delete sanitized.nostr_nsec;
  delete sanitized.nostr_nsec_hex;
  delete sanitized.nostr_nsec_bech32;

  // Never persist proxy key material (re-derived from nostr_nsec_hex at runtime).
  delete sanitized.proxy_seed;
  delete sanitized.proxy_privateKey;
  delete sanitized.proxy_private_key;
  delete sanitized.proxySecretKey;

  return sanitized;
}

async function saveConfig(configData) {
  const configPath = join(config.storage || '.', 'relay-config.json');
  await fs.writeFile(configPath, JSON.stringify(sanitizeConfigForDisk(configData), null, 2));
  console.log('[RelayServer] Config saved to:', configPath);
}

// Start Hyperswarm server
async function startHyperswarmServer() {
  try {
    console.log('[RelayServer] ----------------------------------------');
    console.log('[RelayServer] Starting Hyperswarm server...');
    
    // Create key pair from seed
    const keyPair = crypto.keyPair(b4a.from(config.proxy_seed, 'hex'));
    config.swarmPublicKey = keyPair.publicKey.toString('hex');
    // Persist the generated public key so it can be read on next start
    await saveConfig(config);
    
    console.log('[RelayServer] Generated keypair from seed (redacted)');
    console.log('[RelayServer] Hyperswarm Peer Public key:', config.swarmPublicKey);
    
    // Initialize Hyperswarm
    swarm = new Hyperswarm({
      keyPair,
      // Limit connections for stability
      maxPeers: 64,
      maxClientConnections: 32,
      maxServerConnections: 32
    });
    
    console.log('[RelayServer] Hyperswarm instance created with options:', {
      maxPeers: 64,
      maxClientConnections: 32,
      maxServerConnections: 32
    });
    
    // Handle incoming connections
    swarm.on('connection', (stream, peerInfo) => {
      const peerKey = peerInfo.publicKey.toString('hex');
      console.log('[RelayServer] ========================================');
      console.log('[RelayServer] NEW PEER CONNECTION RECEIVED');
      console.log('[RelayServer] Peer public key:', peerKey);
      console.log('[RelayServer] Connection time:', new Date().toISOString());
      console.log('[RelayServer] Total connected peers:', connectedPeers.size + 1);
      handlePeerConnection(stream, peerInfo);
    });
    
    // Join the swarm with a well-known topic
    const topicString = 'hyperpipe-relay-network';
    const topic = crypto.hash(b4a.from(topicString));
    console.log('[RelayServer] Joining swarm with topic:', topicString);
    console.log('[RelayServer] Topic hash:', topic.toString('hex'));
    
    const discovery = swarm.join(topic, { server: true, client: false });
    console.log('[RelayServer] Waiting for topic announcement...');
    
    await discovery.flushed();
    
    console.log('[RelayServer] Topic fully announced to DHT');
    console.log('[RelayServer] Hyperswarm server started successfully');
    console.log('[RelayServer] Listening for connections...');
    console.log('[RelayServer] ----------------------------------------');
    
    healthState.services.hyperswarmStatus = 'connected';
    
    // Update worker status
    if (global.sendMessage) {
      console.log('[RelayServer] Notifying worker of Hyperswarm status');
      global.sendMessage({
        type: 'status',
        message: 'Hyperswarm server connected',
        swarmKey: config.swarmPublicKey
      });
    }
    
  } catch (error) {
    console.error('[RelayServer] Failed to start Hyperswarm server:', error);
    console.error('[RelayServer] Error stack:', error.stack);
    healthState.services.hyperswarmStatus = 'error';
    throw error;
  }
}

function ensurePeerJoinHandle(publicKey) {
  if (!swarm) {
    throw new Error('Hyperswarm swarm not initialized');
  }

  const decodePeerKey = (key) => {
    if (!key) return null;
    const trimmed = String(key).trim();
    if (!trimmed) return null;
    // Hex path
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return Buffer.from(trimmed, 'hex');
    }
    // hypercore-id/base32 path
    try {
      const decoded = HypercoreId.decode(trimmed);
      if (decoded && decoded.length === 32) {
        return Buffer.from(decoded);
      }
    } catch (_) {
      // ignore
    }
    return null;
  };

  const keyBuffer = decodePeerKey(publicKey);
  if (!keyBuffer || keyBuffer.length !== 32) {
    throw new Error(`Invalid peer public key: ${publicKey}`);
  }

  const normalized = keyBuffer.toString('hex');
  if (peerJoinHandles.has(normalized)) {
    return peerJoinHandles.get(normalized);
  }

  const handle = swarm.joinPeer(keyBuffer);
  peerJoinHandles.set(normalized, handle);
  return handle;
}

function toBuffer(body) {
  if (!body) return Buffer.alloc(0);
  if (Buffer.isBuffer(body)) return body;
  if (Array.isArray(body)) return Buffer.from(body);
  if (typeof body === 'string') return Buffer.from(body);
  return Buffer.alloc(0);
}

function parseJsonBody(body) {
  const buffer = toBuffer(body);
  if (!buffer.length) return null;
  try {
    return JSON.parse(buffer.toString('utf8'));
  } catch (error) {
    throw new Error(`Failed to parse JSON response: ${error.message}`);
  }
}

function sha256Hex(payload) {
  return nodeCrypto.createHash('sha256').update(payload).digest('hex');
}

function normalizeHex64(value) {
  if (!isHex64(value)) return null;
  return String(value).trim().toLowerCase();
}

function normalizeCoreRefsForEnvelope(coreRefs) {
  if (!Array.isArray(coreRefs)) return undefined;
  const normalized = [];
  const seen = new Set();
  for (const entry of coreRefs) {
    if (!entry || typeof entry !== 'object') continue;
    const key = String(entry.key || '').trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    normalized.push({
      key,
      role: typeof entry.role === 'string' ? entry.role : null
    });
  }
  if (!normalized.length) return undefined;
  normalized.sort((left, right) => {
    if (left.key !== right.key) return left.key.localeCompare(right.key);
    return String(left.role || '').localeCompare(String(right.role || ''));
  });
  return normalized;
}

function normalizeFastForwardForEnvelope(fastForward) {
  if (!fastForward || typeof fastForward !== 'object') return null;
  const normalized = {
    key: typeof fastForward.key === 'string' ? fastForward.key : undefined,
    length: Number.isFinite(fastForward.length) ? Number(fastForward.length) : undefined,
    signedLength: Number.isFinite(fastForward.signedLength) ? Number(fastForward.signedLength) : undefined,
    timeoutMs: Number.isFinite(fastForward.timeoutMs) ? Number(fastForward.timeoutMs) : undefined
  };
  if (
    typeof normalized.key !== 'string'
    && !Number.isFinite(normalized.length)
    && !Number.isFinite(normalized.signedLength)
    && !Number.isFinite(normalized.timeoutMs)
  ) {
    return null;
  }
  return normalized;
}

function normalizeWriterCommitCheckpointForEnvelope(checkpoint) {
  const normalized = normalizeWriterCommitCheckpoint(checkpoint);
  if (!normalized) return null;
  return {
    relayKey: normalized.relayKey || null,
    systemKey: normalized.systemKey || null,
    systemLength: Number.isFinite(normalized.systemLength) ? Number(normalized.systemLength) : null,
    systemSignedLength: Number.isFinite(normalized.systemSignedLength) ? Number(normalized.systemSignedLength) : null,
    viewVersion: Number.isFinite(normalized.viewVersion) ? Number(normalized.viewVersion) : null,
    activeWritersHash: typeof normalized.activeWritersHash === 'string' ? normalized.activeWritersHash : null,
    activeWritersCount: Number.isFinite(normalized.activeWritersCount) ? Number(normalized.activeWritersCount) : null,
    writerCore: typeof normalized.writerCore === 'string' ? normalized.writerCore : null,
    recordedAt: Number.isFinite(normalized.recordedAt) ? Number(normalized.recordedAt) : null
  };
}

function canonicalizeWriterLeaseEnvelopePayload(input) {
  if (!input || typeof input !== 'object') return null;
  const version = Number(input.version);
  if (!Number.isFinite(version) || version !== WRITER_LEASE_ENVELOPE_VERSION) return null;

  const leaseId = typeof input.leaseId === 'string' ? input.leaseId.trim() : '';
  const relayKey = normalizeHex64(input.relayKey);
  const publicIdentifier = typeof input.publicIdentifier === 'string' ? input.publicIdentifier.trim() : '';
  const inviteePubkey = normalizeHex64(input.inviteePubkey);
  const tokenHash = typeof input.tokenHash === 'string' ? input.tokenHash.trim().toLowerCase() : '';
  const writerCore = typeof input.writerCore === 'string' ? input.writerCore.trim() : '';
  const writerCoreHex = typeof input.writerCoreHex === 'string' ? input.writerCoreHex.trim() : undefined;
  const autobaseLocal = typeof input.autobaseLocal === 'string' ? input.autobaseLocal.trim() : undefined;
  const writerSecret = typeof input.writerSecret === 'string' ? input.writerSecret.trim() : '';
  const issuedAt = Number(input.issuedAt);
  const expiresAt = Number(input.expiresAt);
  const issuerPubkey = normalizeHex64(input.issuerPubkey);
  const issuerSwarmPeerKey = normalizeHex64(input.issuerSwarmPeerKey);
  const coreRefs = normalizeCoreRefsForEnvelope(input.coreRefs);
  const fastForward = normalizeFastForwardForEnvelope(input.fastForward);
  const writerCommitCheckpoint = normalizeWriterCommitCheckpointForEnvelope(
    input.writerCommitCheckpoint || input.writer_commit_checkpoint || null
  );

  if (!leaseId || !relayKey || !publicIdentifier || !inviteePubkey) return null;
  if (!tokenHash || !writerCore || !writerSecret) return null;
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) return null;
  if (!issuerPubkey || !issuerSwarmPeerKey) return null;

  return {
    version: WRITER_LEASE_ENVELOPE_VERSION,
    leaseId,
    relayKey,
    publicIdentifier,
    inviteePubkey,
    tokenHash,
    writerCore,
    writerCoreHex: writerCoreHex || undefined,
    autobaseLocal: autobaseLocal || undefined,
    writerSecret,
    coreRefs,
    fastForward,
    writerCommitCheckpoint: writerCommitCheckpoint || undefined,
    issuedAt,
    expiresAt,
    issuerPubkey,
    issuerSwarmPeerKey
  };
}

function serializeWriterLeaseEnvelopePayload(payload) {
  return JSON.stringify({
    version: payload.version,
    leaseId: payload.leaseId,
    relayKey: payload.relayKey,
    publicIdentifier: payload.publicIdentifier,
    inviteePubkey: payload.inviteePubkey,
    tokenHash: payload.tokenHash,
    writerCore: payload.writerCore,
    writerCoreHex: payload.writerCoreHex || null,
    autobaseLocal: payload.autobaseLocal || null,
    writerSecret: payload.writerSecret,
    coreRefs: Array.isArray(payload.coreRefs) ? payload.coreRefs : [],
    fastForward: payload.fastForward || null,
    ...(payload.writerCommitCheckpoint
      ? { writerCommitCheckpoint: payload.writerCommitCheckpoint }
      : {}),
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    issuerPubkey: payload.issuerPubkey,
    issuerSwarmPeerKey: payload.issuerSwarmPeerKey
  });
}

async function signWriterLeaseEnvelopePayload(payload, privateKeyHex) {
  const digestHex = sha256Hex(serializeWriterLeaseEnvelopePayload(payload));
  const signatureBytes = await nobleSecp256k1.schnorr.sign(digestHex, privateKeyHex);
  return NostrUtils.bytesToHex(signatureBytes);
}

export async function verifyWriterLeaseEnvelope(envelope) {
  const payload = canonicalizeWriterLeaseEnvelopePayload(envelope);
  if (!payload) return false;
  const signature = typeof envelope?.signature === 'string' ? envelope.signature.trim() : '';
  if (!signature) return false;
  const digestHex = sha256Hex(serializeWriterLeaseEnvelopePayload(payload));
  try {
    return await nobleSecp256k1.schnorr.verify(signature, digestHex, payload.issuerPubkey);
  } catch (_) {
    return false;
  }
}

export async function createSignedWriterLeaseEnvelope(input = {}) {
  const issuerPrivateKey = typeof input.issuerPrivateKey === 'string' && input.issuerPrivateKey.trim()
    ? input.issuerPrivateKey.trim()
    : config?.nostr_nsec_hex || null;
  if (!issuerPrivateKey) {
    throw new Error('Missing issuer private key for writer lease envelope');
  }
  const issuerPubkey = normalizeHex64(
    input.issuerPubkey || config?.nostr_pubkey_hex || NostrUtils.getPublicKey(issuerPrivateKey)
  );
  const issuerSwarmPeerKey = normalizeHex64(input.issuerSwarmPeerKey || config?.swarmPublicKey || null);
  if (!issuerPubkey || !issuerSwarmPeerKey) {
    throw new Error('Missing issuer identity for writer lease envelope');
  }

  const now = Number.isFinite(input.issuedAt) ? Number(input.issuedAt) : Date.now();
  const expiresAt = Number.isFinite(input.expiresAt) ? Number(input.expiresAt) : (now + (3 * 24 * 60 * 60 * 1000));
  const payload = canonicalizeWriterLeaseEnvelopePayload({
    version: WRITER_LEASE_ENVELOPE_VERSION,
    leaseId: input.leaseId || nodeCrypto.randomUUID(),
    relayKey: input.relayKey,
    publicIdentifier: input.publicIdentifier,
    inviteePubkey: input.inviteePubkey,
    tokenHash: input.tokenHash,
    writerCore: input.writerCore,
    writerCoreHex: input.writerCoreHex || null,
    autobaseLocal: input.autobaseLocal || null,
    writerSecret: input.writerSecret,
    coreRefs: input.coreRefs || [],
    fastForward: input.fastForward || null,
    writerCommitCheckpoint: input.writerCommitCheckpoint || input.writer_commit_checkpoint || null,
    issuedAt: now,
    expiresAt,
    issuerPubkey,
    issuerSwarmPeerKey
  });
  if (!payload) {
    throw new Error('Invalid writer lease envelope payload');
  }
  const signature = await signWriterLeaseEnvelopePayload(payload, issuerPrivateKey);
  return {
    ...payload,
    signature
  };
}

function computeLeaseTokenHash(relayKey, token) {
  const normalizedRelayKey = normalizeHex64(relayKey);
  const normalizedToken = typeof token === 'string' ? token.trim() : '';
  if (!normalizedRelayKey || !normalizedToken) return null;
  return sha256Hex(`${normalizedRelayKey}:${normalizedToken}`);
}

function consumeWriterLeaseSyncRateLimit(peerKey) {
  const normalized = normalizeHex64(peerKey);
  if (!normalized) return true;
  const now = Date.now();
  const existing = writerLeaseSyncRateLimits.get(normalized);
  if (!existing || now - existing.windowStartAt >= WRITER_LEASE_SYNC_RATE_LIMIT_WINDOW_MS) {
    writerLeaseSyncRateLimits.set(normalized, { windowStartAt: now, count: 1 });
    return true;
  }
  if (existing.count >= WRITER_LEASE_SYNC_RATE_LIMIT_MAX) {
    return false;
  }
  existing.count += 1;
  writerLeaseSyncRateLimits.set(normalized, existing);
  return true;
}

async function resolveRelayRuntimeForIdentifier(identifier) {
  const normalizedIdentifier = normalizeRelayIdentifier(identifier);
  const directKey = normalizeHex64(normalizedIdentifier);
  const relayKey = directKey || await getRelayKeyFromPublicIdentifier(normalizedIdentifier);
  const relayManager = relayKey ? activeRelays.get(relayKey) : null;
  const profile =
    (relayKey ? await getRelayProfileByKey(relayKey) : null)
    || await getRelayProfileByPublicIdentifier(normalizedIdentifier);
  const publicIdentifier = profile?.public_identifier || normalizedIdentifier;
  return {
    normalizedIdentifier,
    relayKey: relayKey || profile?.relay_key || null,
    relayManager: relayManager || null,
    profile: profile || null,
    publicIdentifier
  };
}

function parseRequestBodyJson(request) {
  try {
    return parseJsonBody(request?.body) || {};
  } catch (_) {
    return {};
  }
}

async function waitForPeerProtocol(publicKey, timeoutMs = 20000, reason = 'unspecified') {
  const decodePeerKey = (key) => {
    if (!key) return null;
    const trimmed = String(key).trim();
    if (!trimmed) return null;
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return Buffer.from(trimmed, 'hex');
    }
    try {
      const decoded = HypercoreId.decode(trimmed);
      if (decoded && decoded.length === 32) {
        return Buffer.from(decoded);
      }
    } catch (_) {
      // ignore
    }
    return null;
  };

  const keyBuffer = decodePeerKey(publicKey);
  const normalized = keyBuffer ? keyBuffer.toString('hex') : String(publicKey || '').trim().toLowerCase();
  const buildConnectionSnapshot = () => {
    const keys = Array.from(connectedPeers.keys());
    return {
      connectedPeers: keys.length,
      connectedPreview: keys.slice(0, 8).map((entry) => String(entry || '').slice(0, 16)),
      targetConnected: connectedPeers.has(normalized),
      pendingForTarget: (pendingPeerProtocols.get(normalized) || []).length
    };
  };
  console.log('[RelayServer][waitForPeerProtocol] wait-start', {
    reason,
    peerKey: normalized.slice(0, 16),
    timeoutMs,
    ...buildConnectionSnapshot()
  });
  const existing = connectedPeers.get(normalized);
  if (existing?.protocol && existing.protocol.channel && !existing.protocol.channel.closed) {
    console.log('[RelayServer][waitForPeerProtocol] wait-hit-existing', {
      reason,
      peerKey: normalized.slice(0, 16),
      timeoutMs,
      ...buildConnectionSnapshot()
    });
    return existing.protocol;
  }

  const hadJoinHandle = peerJoinHandles.has(normalized);
  ensurePeerJoinHandle(normalized);
  console.log('[RelayServer][waitForPeerProtocol] join-handle-ensured', {
    reason,
    peerKey: normalized.slice(0, 16),
    timeoutMs,
    hadJoinHandle,
    ...buildConnectionSnapshot()
  });

  return new Promise((resolve, reject) => {
    const pending = pendingPeerProtocols.get(normalized) || [];
    const timeout = setTimeout(() => {
      const list = pendingPeerProtocols.get(normalized) || [];
      const filtered = list.filter(entry => entry !== pendingEntry);
      if (filtered.length) {
        pendingPeerProtocols.set(normalized, filtered);
      } else {
        pendingPeerProtocols.delete(normalized);
      }
      console.warn('[RelayServer][waitForPeerProtocol] wait-timeout', {
        reason,
        peerKey: normalized.slice(0, 16),
        timeoutMs,
        ...buildConnectionSnapshot()
      });
      reject(new Error('Timed out waiting for peer connection'));
    }, timeoutMs);

    const pendingEntry = {
      resolve(protocol) {
        clearTimeout(timeout);
        console.log('[RelayServer][waitForPeerProtocol] wait-resolved', {
          reason,
          peerKey: normalized.slice(0, 16),
          timeoutMs,
          ...buildConnectionSnapshot()
        });
        resolve(protocol);
      },
      reject(err) {
        clearTimeout(timeout);
        console.warn('[RelayServer][waitForPeerProtocol] wait-rejected', {
          reason,
          peerKey: normalized.slice(0, 16),
          timeoutMs,
          error: err?.message || String(err),
          ...buildConnectionSnapshot()
        });
        reject(err);
      }
    };

    pending.push(pendingEntry);
    pendingPeerProtocols.set(normalized, pending);
  });
}

function withOperationTimeout(promise, timeoutMs, label = 'operation') {
  const timeout = Math.max(250, Number.isFinite(timeoutMs) ? Number(timeoutMs) : 1500);
  return new Promise((resolve, reject) => {
    const handle = setTimeout(() => {
      reject(new Error(`${label} timeout after ${timeout}ms`));
    }, timeout);
    handle.unref?.();
    Promise.resolve(promise)
      .then((value) => {
        clearTimeout(handle);
        resolve(value);
      })
      .catch((error) => {
        clearTimeout(handle);
        reject(error);
      });
  });
}

export async function discoverPeersOnTopic({
  topicHex,
  timeoutMs = 1200,
  maxPeers = 12
} = {}) {
  const normalizedTopic = typeof topicHex === 'string' ? topicHex.trim().toLowerCase() : '';
  if (!swarm || !/^[0-9a-f]{64}$/.test(normalizedTopic)) {
    return [];
  }
  const waitMs = Math.max(200, Number.isFinite(timeoutMs) ? Number(timeoutMs) : 1200);
  const peerCap = Math.max(1, Number.isFinite(maxPeers) ? Number(maxPeers) : 12);
  const before = new Set(Array.from(connectedPeers.keys()));
  const joinHandle = swarm.join(Buffer.from(normalizedTopic, 'hex'), {
    server: false,
    client: true
  });
  try {
    await Promise.race([
      joinHandle.flushed(),
      new Promise((resolve) => setTimeout(resolve, Math.min(500, waitMs)))
    ]);
  } catch (_) {
    // ignore flushed errors and continue with bounded wait
  }
  try {
    await new Promise((resolve) => setTimeout(resolve, waitMs));
    const connectedKeys = Array.from(connectedPeers.keys())
      .map((value) => normalizeHex64(value))
      .filter(Boolean);
    const newlyConnected = connectedKeys.filter((value) => !before.has(value));
    const ordered = [...newlyConnected, ...connectedKeys.filter((value) => !newlyConnected.includes(value))];
    return Array.from(new Set(ordered)).slice(0, peerCap);
  } finally {
    try {
      joinHandle.destroy();
    } catch (_) {
      // ignore
    }
  }
}

export async function probeJoinCapabilities({
  peerKey,
  publicIdentifier,
  inviteePubkey = null,
  tokenHash = null,
  timeoutMs = 1500,
  nonce = null
} = {}) {
  const normalizedPeerKey = normalizeHex64(peerKey);
  const normalizedIdentifier = normalizeRelayIdentifier(publicIdentifier || '');
  if (!normalizedPeerKey || !normalizedIdentifier) {
    return {
      success: false,
      supported: false,
      statusCode: null,
      error: 'invalid-probe-input'
    };
  }
  const requestNonce = typeof nonce === 'string' && nonce.trim()
    ? nonce.trim()
    : nodeCrypto.randomUUID();
  const startedAt = Date.now();
  console.log('[RelayServer] probeJoinCapabilities start', {
    peerKey: normalizedPeerKey.slice(0, 16),
    publicIdentifier: normalizedIdentifier,
    timeoutMs,
    hasInviteePubkey: !!normalizeHex64(inviteePubkey),
    hasTokenHash: typeof tokenHash === 'string' && tokenHash.length > 0
  });
  try {
    const protocol = await withOperationTimeout(
      waitForPeerProtocol(normalizedPeerKey, timeoutMs, 'probe-join-capabilities'),
      timeoutMs,
      'wait-peer'
    );
    console.log('[RelayServer] probeJoinCapabilities peer-ready', {
      peerKey: normalizedPeerKey.slice(0, 16),
      publicIdentifier: normalizedIdentifier,
      timeoutMs,
      elapsedMs: Date.now() - startedAt
    });
    const responseRaw = await withOperationTimeout(
      protocol.sendRequest({
        method: 'POST',
        path: `/post/join-capabilities/${normalizedIdentifier}`,
        headers: { 'content-type': 'application/json' },
        body: Buffer.from(JSON.stringify({
          nonce: requestNonce,
          inviteePubkey: normalizeHex64(inviteePubkey) || null,
          tokenHash: typeof tokenHash === 'string' ? tokenHash.trim().toLowerCase() : null
        }))
      }),
      timeoutMs,
      'probe-request'
    );
    const statusCode = Number(responseRaw?.statusCode || 0) || null;
    const parsed = parseJsonBody(responseRaw?.body) || {};
    console.log('[RelayServer] probeJoinCapabilities response', {
      peerKey: normalizedPeerKey.slice(0, 16),
      publicIdentifier: normalizedIdentifier,
      statusCode: statusCode || 200,
      elapsedMs: Date.now() - startedAt
    });
    if ((statusCode || 200) >= 400) {
      return {
        success: false,
        supported: statusCode !== 404,
        statusCode,
        rttMs: Date.now() - startedAt,
        error: typeof parsed?.error === 'string' ? parsed.error : `status-${statusCode}`
      };
    }
    const echoedNonce = typeof parsed?.nonce === 'string' ? parsed.nonce.trim() : '';
    if (!echoedNonce || echoedNonce !== requestNonce) {
      return {
        success: false,
        supported: true,
        statusCode: statusCode || 200,
        rttMs: Date.now() - startedAt,
        error: 'nonce-mismatch'
      };
    }
    return {
      success: true,
      supported: true,
      statusCode: statusCode || 200,
      rttMs: Date.now() - startedAt,
      data: parsed
    };
  } catch (error) {
    console.warn('[RelayServer] probeJoinCapabilities failed', {
      peerKey: normalizedPeerKey.slice(0, 16),
      publicIdentifier: normalizedIdentifier,
      timeoutMs,
      elapsedMs: Date.now() - startedAt,
      error: error?.message || String(error)
    });
    return {
      success: false,
      supported: false,
      statusCode: null,
      rttMs: Date.now() - startedAt,
      error: error?.message || String(error)
    };
  }
}

export async function syncWriterLeaseToPeer({
  peerKey,
  publicIdentifier,
  envelope,
  timeoutMs = 4000
} = {}) {
  const normalizedPeerKey = normalizeHex64(peerKey);
  const normalizedIdentifier = normalizeRelayIdentifier(publicIdentifier || '');
  if (!normalizedPeerKey || !normalizedIdentifier || !envelope) {
    return { acknowledged: false, statusCode: null, error: 'invalid-sync-input' };
  }
  try {
    const protocol = await withOperationTimeout(
      waitForPeerProtocol(normalizedPeerKey, timeoutMs, 'sync-writer-lease'),
      timeoutMs,
      'wait-peer'
    );
    const responseRaw = await withOperationTimeout(
      protocol.sendRequest({
        method: 'POST',
        path: `/post/relay/${normalizedIdentifier}/writer-lease-sync`,
        headers: {
          'content-type': 'application/json',
          'x-source-peer-key': config?.swarmPublicKey || ''
        },
        body: Buffer.from(JSON.stringify({ envelope }))
      }),
      timeoutMs,
      'lease-sync'
    );
    const statusCode = Number(responseRaw?.statusCode || 0) || null;
    const parsed = parseJsonBody(responseRaw?.body) || {};
    if ((statusCode || 200) >= 400) {
      return {
        acknowledged: false,
        statusCode,
        error: typeof parsed?.error === 'string' ? parsed.error : `status-${statusCode}`
      };
    }
    return {
      acknowledged: parsed?.acknowledged === true,
      statusCode: statusCode || 200,
      data: parsed
    };
  } catch (error) {
    return {
      acknowledged: false,
      statusCode: null,
      error: error?.message || String(error)
    };
  }
}

export async function claimWriterLeaseFromPeer({
  peerKey,
  publicIdentifier,
  inviteePubkey,
  token = null,
  tokenHash = null,
  relayKey = null,
  timeoutMs = 5000
} = {}) {
  const normalizedPeerKey = normalizeHex64(peerKey);
  const normalizedIdentifier = normalizeRelayIdentifier(publicIdentifier || '');
  const normalizedInvitee = normalizeHex64(inviteePubkey);
  if (!normalizedPeerKey || !normalizedIdentifier || !normalizedInvitee) {
    return { success: false, statusCode: null, error: 'invalid-claim-input' };
  }
  const computedTokenHash =
    (typeof tokenHash === 'string' && tokenHash.trim().toLowerCase())
    || computeLeaseTokenHash(relayKey, token)
    || null;
  if (!computedTokenHash) {
    return { success: false, statusCode: null, error: 'missing-token-hash' };
  }
  try {
    const protocol = await withOperationTimeout(
      waitForPeerProtocol(normalizedPeerKey, timeoutMs, 'claim-writer-lease'),
      timeoutMs,
      'wait-peer'
    );
    const responseRaw = await withOperationTimeout(
      protocol.sendRequest({
        method: 'POST',
        path: `/post/relay/${normalizedIdentifier}/writer-lease-claim`,
        headers: { 'content-type': 'application/json' },
        body: Buffer.from(JSON.stringify({
          inviteePubkey: normalizedInvitee,
          tokenHash: computedTokenHash,
          relayKey: normalizeHex64(relayKey) || null
        }))
      }),
      timeoutMs,
      'lease-claim'
    );
    const statusCode = Number(responseRaw?.statusCode || 0) || null;
    const parsed = parseJsonBody(responseRaw?.body) || {};
    if ((statusCode || 200) >= 400) {
      return {
        success: false,
        statusCode,
        error: typeof parsed?.error === 'string' ? parsed.error : `status-${statusCode}`
      };
    }
    return {
      success: true,
      statusCode: statusCode || 200,
      data: parsed
    };
  } catch (error) {
    return {
      success: false,
      statusCode: null,
      error: error?.message || String(error)
    };
  }
}

// Handle incoming peer connections
function handlePeerConnection(stream, peerInfo) {
  const publicKey = peerInfo.publicKey.toString('hex');
  const normalizedKey = publicKey.toLowerCase();
  console.log('[RelayServer] Setting up protocol for peer:', publicKey);
  
  // Track the peer
  connectedPeers.set(normalizedKey, {
    connectedAt: Date.now(),
    peerInfo,
    protocol: null,
    identified: false,
    stream: stream, // Keep reference to stream
    keepAliveInterval: null, // Add keepalive tracking
    publicKey
  });
  
  const gatewayServiceInstance = global.gatewayService || null;
  const replicaInfo = gatewayServiceInstance?.getPublicGatewayReplicaInfo?.() || null;

  const handshakeInfo = {
    role: 'relay-peer',
    isGateway: false,
    gatewayReplica: false,
    relayPublicKey: config?.swarmPublicKey,
    peerId: config?.swarmPublicKey,
    relayCount: healthState?.activeRelaysCount || 0,
    proxyAddress: config?.proxy_server_address || null,
    delegateReqToPeers: !!replicaInfo?.delegateReqToPeers
  };

  if (replicaInfo) {
    handshakeInfo.hyperbeeKey = replicaInfo.hyperbeeKey || null;
    handshakeInfo.hyperbeeDiscoveryKey = replicaInfo.discoveryKey || null;
    handshakeInfo.hyperbeeLength = Number.isFinite(replicaInfo.length) ? replicaInfo.length : 0;
    handshakeInfo.hyperbeeContiguousLength = Number.isFinite(replicaInfo.contiguousLength)
      ? replicaInfo.contiguousLength
      : 0;
    handshakeInfo.hyperbeeLag = Number.isFinite(replicaInfo.lag) ? replicaInfo.lag : 0;
    handshakeInfo.hyperbeeVersion = Number.isFinite(replicaInfo.version) ? replicaInfo.version : 0;
    handshakeInfo.hyperbeeUpdatedAt = Number.isFinite(replicaInfo.updatedAt) ? replicaInfo.updatedAt : 0;
    if (replicaInfo.telemetry && typeof replicaInfo.telemetry === 'object') {
      handshakeInfo.telemetry = { ...replicaInfo.telemetry };
    }
  }

  // Create relay protocol handler
  const protocol = new RelayProtocol(stream, true, handshakeInfo);
  
  // Store protocol reference
  const peerData = connectedPeers.get(normalizedKey);
  peerData.protocol = protocol;
  
  // Set up keepalive for gateway connections
  protocol.on('open', (handshake) => {
    console.log('[RelayServer] ----------------------------------------');
    console.log('[RelayServer] PROTOCOL OPENED');
    console.log('[RelayServer] Peer:', publicKey.substring(0, 8) + '...');
    console.log('[RelayServer] Handshake received:', JSON.stringify(handshake, null, 2));
    
    healthState.services.protocolStatus = 'connected';
    
    // Check if this is the gateway
    const gatewayIndicators = {
      role: handshake?.role || null,
      isGateway: !!handshake?.isGateway,
      gatewayReplica: !!handshake?.gatewayReplica
    };
    const knownGatewayKey = typeof config.gatewayPublicKey === 'string'
      ? config.gatewayPublicKey.trim().toLowerCase()
      : null;
    const matchesKnownGatewayKey = !!(knownGatewayKey && publicKey.toLowerCase() === knownGatewayKey);
    const handshakeClaimsGateway = !!(
      handshake
      && (
        handshake.role === 'gateway'
        || handshake.isGateway === true
      )
    );
    const isGatewayHandshake = handshake && (
      matchesKnownGatewayKey
      && handshakeClaimsGateway
    );
    console.log('[RelayServer] Gateway detection check:', {
      ...gatewayIndicators,
      isGatewayHandshake,
      hasKnownGatewayKey: !!knownGatewayKey,
      matchesKnownGatewayKey,
      handshakeClaimsGateway
    });

    if (isGatewayHandshake) {
      console.log('[RelayServer] >>> GATEWAY IDENTIFIED FROM HANDSHAKE <<<');
      setGatewayConnection(protocol, publicKey);
      
      // Start keepalive for gateway connection
      startKeepAlive(publicKey);
    }
    else if (matchesKnownGatewayKey) {
      console.log('[RelayServer] >>> GATEWAY IDENTIFIED BY PUBLIC KEY <<<');
      setGatewayConnection(protocol, publicKey);
      
      // Start keepalive for gateway connection
      startKeepAlive(publicKey);
    } else {
      console.log('[RelayServer] Regular peer connection (not gateway)');
    }
    console.log('[RelayServer] ----------------------------------------');

    const pending = pendingPeerProtocols.get(normalizedKey);
    if (pending && pending.length) {
      pendingPeerProtocols.delete(normalizedKey);
      for (const entry of pending) {
        try {
          entry.resolve(protocol);
        } catch (err) {
          console.warn('[RelayServer] Failed to resolve pending peer protocol:', err.message);
        }
      }
    }
  });
  
  protocol.on('close', () => {
    console.log('[RelayServer] ----------------------------------------');
    console.log('[RelayServer] PROTOCOL CLOSED');
    console.log('[RelayServer] Peer:', publicKey.substring(0, 8) + '...');
    
    // Clean up keepalive
    const peer = connectedPeers.get(normalizedKey);
    if (peer && peer.keepAliveInterval) {
      clearInterval(peer.keepAliveInterval);
    }
    
    // Remove from connected peers
    connectedPeers.delete(normalizedKey);

    const pending = pendingPeerProtocols.get(normalizedKey);
    if (pending && pending.length) {
      pendingPeerProtocols.delete(normalizedKey);
      for (const entry of pending) {
        try {
          entry.reject(new Error('Peer connection closed'));
        } catch (_) {}
      }
    }

    if (gatewayConnection === protocol) {
      console.log('[RelayServer] >>> GATEWAY CONNECTION LOST <<<');
      gatewayConnection = null;
      healthState.services.gatewayStatus = 'disconnected';
    }
    
    console.log('[RelayServer] Remaining connected peers:', connectedPeers.size);
    console.log('[RelayServer] ----------------------------------------');
  });
  
  // Set up request handlers
  setupProtocolHandlers(protocol);
  
  // Handle gateway identification via registration endpoint
  protocol.on('request', (request) => {
    console.log('[RelayServer] Generic request received:', request.method, request.path);
    
    // If this is a registration request from the gateway, identify it
    if (request.path === '/identify-gateway') {
      if (gatewayConnection && gatewayConnection !== protocol) {
        console.log('[RelayServer] >>> REPLACING EXISTING GATEWAY CONNECTION <<<');
        try {
          gatewayConnection.destroy?.();
        } catch (_) {}
      }

      console.log('[RelayServer] >>> GATEWAY IDENTIFICATION REQUEST RECEIVED <<<');
      setGatewayConnection(protocol, publicKey);

      protocol.sendResponse({
        id: request.id,
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ 
          status: 'identified',
          relayPublicKey: config.swarmPublicKey,
          timestamp: new Date().toISOString()
        }))
      });
    }
  });
}

// Add keepalive function
function startKeepAlive(publicKey) {
  const normalizedKey = publicKey.toLowerCase();
  const peer = connectedPeers.get(normalizedKey);
  if (!peer || !peer.protocol) return;
  
  console.log(`[RelayServer] Starting keepalive for ${publicKey.substring(0, 8)}...`);
  
  // Send periodic health responses to keep connection alive
  peer.keepAliveInterval = setInterval(async () => {
    try {
      if (peer.protocol && peer.protocol.channel && !peer.protocol.channel.closed) {
        // Just check if the connection is still valid
        console.log(`[RelayServer] Keepalive check for ${publicKey.substring(0, 8)}...`);
      } else {
        console.log(`[RelayServer] Connection lost for ${publicKey.substring(0, 8)}, stopping keepalive`);
        clearInterval(peer.keepAliveInterval);
        connectedPeers.delete(normalizedKey);
      }
    } catch (error) {
      console.error(`[RelayServer] Keepalive error for ${publicKey.substring(0, 8)}:`, error.message);
    }
  }, 15000); // Every 15 seconds
}

// Set gateway connection and process pending registrations
function setGatewayConnection(protocol, publicKey) {
  gatewayConnection = protocol;
  healthState.services.gatewayStatus = 'connected';

  // Mark peer as identified
  const normalizedKey = publicKey.toLowerCase();
  const peer = connectedPeers.get(normalizedKey);
  if (peer) {
    peer.identified = true;
    peer.isGateway = true;
  }
  
  console.log('[RelayServer] ========================================');
  console.log('[RelayServer] GATEWAY CONNECTION ESTABLISHED');
  console.log('[RelayServer] Gateway public key:', publicKey);
  console.log('[RelayServer] Connection time:', new Date().toISOString());
  console.log('[RelayServer] ========================================');

  try {
    global.gatewayService?.attachGatewayProtocol?.(publicKey, protocol);
  } catch (error) {
    console.warn('[RelayServer] Failed to attach gateway protocol to GatewayService:', error.message);
  }

  // Update worker status
  if (global.sendMessage) {
    console.log('[RelayServer] Notifying worker of gateway connection');
    global.sendMessage({
      type: 'gateway-connected',
      gatewayPublicKey: publicKey
    });
  }
  
  // Process any pending registrations
  processPendingRegistrations();

  // Always re-register active relays on reconnect to rebuild gateway state
  registerWithGateway(null, { skipQueue: true })
    .then(() => {
      console.log('[RelayServer] Refreshed gateway registration after reconnect');
    })
    .catch((error) => {
      console.warn('[RelayServer] Failed to refresh gateway registration after reconnect:', error?.message || error);
    });
}

// Process pending registrations
async function processPendingRegistrations() {
  if (!gatewayConnection) {
    console.log('[RelayServer] Cannot process pending registrations - no gateway connection', {
      pendingCount: pendingRegistrations.length
    });
    return;
  }
  
  if (pendingRegistrations.length === 0) {
    console.log('[RelayServer] No pending registrations to process');
    return;
  }
  
  console.log('[RelayServer] ----------------------------------------');
  console.log(`[RelayServer] Processing ${pendingRegistrations.length} pending registrations`);
  
  let processedCount = 0;
  while (pendingRegistrations.length > 0) {
    const registration = pendingRegistrations.shift();
    console.log('[RelayServer] Processing pending registration:', registration ? 'with profile' : 'general update');
    try {
      await registerWithGateway(registration, { skipQueue: true });
      processedCount++;
    } catch (error) {
      console.error('[RelayServer] Pending registration failed:', error.message);
      pendingRegistrations.unshift(registration);
      console.log('[RelayServer] Will retry pending registrations later');
      return;
    }
  }
  
  if (processedCount > 0) {
    console.log('[RelayServer] Sending fresh registration with current state');
    try {
      await registerWithGateway(null, { skipQueue: true });
    } catch (error) {
      console.error('[RelayServer] Failed to send catch-up registration:', error.message);
      pendingRegistrations.unshift(null);
    }
  }

  console.log('[RelayServer] ----------------------------------------');
}

// Setup protocol handlers for all endpoints
function setupProtocolHandlers(protocol) {
  console.log('[RelayServer] Setting up protocol handlers');
  
  // Health endpoint
  protocol.handle('/health', async () => {
    console.log('[RelayServer] Health check requested');
    await updateHealthState();
    
    const activeRelays = await getActiveRelays();
    
    // Always return healthy if we're connected
    const healthResponse = {
        status: 'healthy', // Force healthy status when responding
        uptime: Date.now() - healthState.startTime,
        lastCheck: healthState.lastCheck,
        activeRelays: {
            count: healthState.activeRelaysCount,
            keys: activeRelays.map(r => r.relayKey)
        },
        services: {
            ...healthState.services,
            // Ensure protocol status is connected when we're responding
            protocolStatus: 'connected',
            hyperswarmStatus: 'connected'
        },
        metrics: {
            ...healthState.metrics,
            successRate: healthState.metrics.totalRequests === 0 ? 100 : 
              (healthState.metrics.successfulRequests / healthState.metrics.totalRequests) * 100
        },
        config: {
            port: config.port,
            proxy_server_address: config.proxy_server_address,
            gatewayUrl: config.gatewayUrl,
            publicKey: config.swarmPublicKey
        },
        timestamp: new Date().toISOString()
    };
    
    updateMetrics(true);
    
    console.log('[RelayServer] Sending health response:', {
        status: healthResponse.status,
        activeRelays: healthResponse.activeRelays.count
    });
    
    return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify(healthResponse))
    };
});
  
  // Get relay list
  protocol.handle('/relays', async () => {
    console.log('[RelayServer] Relay list requested');
    try {
        const activeRelays = await getActiveRelays();
        const profiles = await getRelayProfiles();
        
        const gatewayBase = buildGatewayWebsocketBase(config);
        const relayList = activeRelays.map(relay => {
            const profile = profiles.find(p => p.relay_key === relay.relayKey) || {};
            
            // Use public identifier in the connection URL if available
            const connectionUrl = profile.public_identifier ? 
                `${gatewayBase}/${profile.public_identifier.replace(':', '/')}` :
                `${gatewayBase}/${relay.relayKey}`;
            
            return {
                relayKey: relay.relayKey, // Still include for backward compatibility
                publicIdentifier: profile.public_identifier || null, // Include public identifier
                connectionUrl: connectionUrl,
                name: profile.name || 'Unnamed Relay',
                description: profile.description || '',
                createdAt: profile.created_at || profile.joined_at || null,
                peerCount: relay.peerCount || 0
            };
        });
        
        console.log(`[RelayServer] Returning ${relayList.length} relays`);
        updateMetrics(true);
        return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            body: b4a.from(JSON.stringify({
                relays: relayList,
                count: relayList.length
            }))
        };
    } catch (error) {
        console.error('[RelayServer] Error getting relay list:', error);
        updateMetrics(false);
        return {
            statusCode: 500,
            headers: { 'content-type': 'application/json' },
            body: b4a.from(JSON.stringify({ error: error.message }))
        };
    }
});
  
  // Create relay
  protocol.handle('/relay/create', async (request) => {
    console.log('[RelayServer] Create relay requested');
    const body = JSON.parse(request.body.toString());
    const { name, description, isPublic = false, isOpen = false, fileSharing = true } = body;

    console.log('[RelayServer] Creating relay:', { name, description, isPublic, isOpen, fileSharing });
    
    if (!name) {
      updateMetrics(false);
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Relay name is required' }))
      };
    }
    
    try {
      const result = await createRelayManager({
        name,
        description,
        isPublic,
        isOpen,
        fileSharing,
        config
      });
      
      if (result.success) {
        console.log('[RelayServer] Relay created successfully:', result.relayKey);
        await updateHealthState();
        
        // Send update to parent if connected
        if (global.sendMessage) {
          const activeRelays = await getActiveRelays();
          global.sendMessage({
            type: 'relay-update',
            relays: activeRelays
          });
        }
        
        // ALWAYS register with gateway via Hyperswarm if enabled
        if (config.registerWithGateway) {
          console.log('[RelayServer] Registering new relay with gateway via Hyperswarm');
          try {
            await registerWithGateway(result.profile);
            console.log('[RelayServer] Successfully registered new relay with gateway');
          } catch (regError) {
            console.error('[RelayServer] Failed to register new relay with gateway:', regError.message);
            // Don't fail the relay creation, just log the error
          }
        }
        
        updateMetrics(true);
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify(result))
        };
      } else {
        console.error('[RelayServer] Failed to create relay:', result.error);
        updateMetrics(false);
        return {
          statusCode: 500,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: result.error }))
        };
      }
    } catch (error) {
      console.error('[RelayServer] Error creating relay:', error);
      updateMetrics(false);
      return {
        statusCode: 500,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: error.message }))
      };
    }
  });
  
  // Join relay
  protocol.handle('/relay/join', async (request) => {
    console.log('[RelayServer] Join relay requested');
    const body = JSON.parse(request.body.toString());
    const { relayKey, name, description, fileSharing = true } = body;

    console.log('[RelayServer] Joining relay:', { relayKey, name, description, fileSharing });
    
    if (!relayKey) {
      updateMetrics(false);
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Relay key is required' }))
      };
    }
    
    try {
      const result = await joinRelayManager({
        relayKey,
        name,
        description,
        fileSharing,
        config
      });
      
      if (result.success) {
        console.log('[RelayServer] Joined relay successfully');
        await updateHealthState();
        
        // Send update to parent
        if (global.sendMessage) {
          const activeRelays = await getActiveRelays();
          global.sendMessage({
            type: 'relay-update',
            relays: activeRelays
          });
        }
        
        // ALWAYS register with gateway via Hyperswarm if enabled
        if (config.registerWithGateway) {
          console.log('[RelayServer] Registering joined relay with gateway via Hyperswarm');
          try {
            // For join, we register all relays since we don't have specific profile for joined relay
            await registerWithGateway();
            console.log('[RelayServer] Successfully registered joined relay with gateway');
          } catch (regError) {
            console.error('[RelayServer] Failed to register joined relay with gateway:', regError.message);
            // Don't fail the relay join, just log the error
          }
        }
        
        updateMetrics(true);
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify(result))
        };
      } else {
        console.error('[RelayServer] Failed to join relay:', result.error);
        updateMetrics(false);
        return {
          statusCode: 500,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: result.error }))
        };
      }
    } catch (error) {
      console.error('[RelayServer] Error joining relay:', error);
      updateMetrics(false);
      return {
        statusCode: 500,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: error.message }))
      };
    }
  });

  // Handle join requests
  protocol.handle('/post/join/:identifier', async (request) => {
    const rawIdentifier = request.params.identifier;
    const identifier = normalizeRelayIdentifier(rawIdentifier);
    console.log(`[RelayServer] Join request for relay: ${rawIdentifier}`);
    if (rawIdentifier !== identifier) {
      console.log(`[RelayServer] Normalized identifier: ${identifier}`);
    }

    try {
      const body = JSON.parse(request.body.toString());
      const { event } = body;

      if (!event) {
        updateMetrics(false);
        return {
          statusCode: 400,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: 'Missing required fields' }))
        };
      }
      
      // Verify this is a kind 9021 event
      if (event.kind !== 9021) {
        updateMetrics(false);
        return {
          statusCode: 400,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: 'Invalid event kind' }))
        };
      }

      // Load relay profile using the public identifier
      const profile = await getRelayProfileByPublicIdentifier(identifier);
      if (!profile) {
        updateMetrics(false);
        return {
          statusCode: 404,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: 'Relay not found' }))
        };
      }

      try {
        await publishEventToRelay(identifier, event);
        console.log(`[RelayServer] Published kind 9021 join request event`);
      } catch (publishError) {
        console.error(`[RelayServer] Failed to publish join request:`, publishError);
        // Continue anyway - the auth process can still work
      }

      if (profile.isOpen === false) {
        updateMetrics(true);
        return {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ status: 'pending' }))
        };
      }

      // Generate challenge
      const challengeManager = getChallengeManager();
      const { challenge, relayPubkey } = challengeManager.createChallenge(event.pubkey, identifier);
      
      console.log(`[RelayServer] Generated challenge for ${event.pubkey.substring(0, 8)}...`);
      
      // Prepare response with challenge information only
      const response = {
        challenge,
        relayPubkey
      };
      
      updateMetrics(true);
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify(response))
      };
      
    } catch (error) {
      console.error(`[RelayServer] Error processing join request:`, error);
      updateMetrics(false);
      return {
        statusCode: 500,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: error.message }))
      };
    }
  });

  protocol.handle('/post/join-capabilities/:identifier', async (request) => {
    const rawIdentifier = request.params.identifier;
    const runtime = await resolveRelayRuntimeForIdentifier(rawIdentifier);
    const body = parseRequestBodyJson(request);
    const nonce =
      (typeof body.nonce === 'string' && body.nonce.trim())
      || (typeof request?.query?.nonce === 'string' && request.query.nonce.trim())
      || nodeCrypto.randomUUID();
    const inviteePubkey = normalizeHex64(
      body.inviteePubkey || request?.query?.inviteePubkey || null
    );
    const tokenHashRaw = body.tokenHash || request?.query?.tokenHash || null;
    const tokenHash = typeof tokenHashRaw === 'string' ? tokenHashRaw.trim().toLowerCase() : null;
    const observedAt = Date.now();
    const relayActive = !!runtime?.relayManager?.relay;
    const writable = runtime?.relayManager?.relay?.writable === true;
    const isClosed = runtime?.profile?.isOpen === false;
    const canDirectChallenge = relayActive && writable && !isClosed;
    const canProvisionOpenWriter = canDirectChallenge;
    const canStoreLeaseReplica = relayActive && writable;
    console.log('[RelayServer] join-capabilities request', {
      identifier: normalizeRelayIdentifier(rawIdentifier || ''),
      relayKey: runtime?.relayKey || null,
      publicIdentifier: runtime?.publicIdentifier || null,
      relayActive,
      writable,
      isClosed,
      hasInviteePubkey: !!inviteePubkey,
      hasTokenHash: typeof tokenHash === 'string' && tokenHash.length > 0,
      sourcePeerKey: typeof request?.headers?.['x-source-peer-key'] === 'string'
        ? String(request.headers['x-source-peer-key']).slice(0, 16)
        : null
    });

    let hasMatchingLease = false;
    let leaseExpiresAt = null;
    if (isClosed && inviteePubkey && tokenHash) {
      const match = await findMatchingRelayLeaseEnvelope({
        relayKey: runtime?.relayKey,
        publicIdentifier: runtime?.publicIdentifier,
        inviteePubkey,
        tokenHash
      });
      hasMatchingLease = !!match?.envelope;
      leaseExpiresAt = Number.isFinite(match?.leaseExpiresAt) ? Number(match.leaseExpiresAt) : null;
    }

    if (!relayActive && !runtime?.profile) {
      console.warn('[RelayServer] join-capabilities relay-not-found', {
        identifier: normalizeRelayIdentifier(rawIdentifier || ''),
        relayKey: runtime?.relayKey || null,
        publicIdentifier: runtime?.publicIdentifier || null
      });
      updateMetrics(false);
      return {
        statusCode: 404,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({
          error: 'Relay not found',
          nonce,
          observedAt
        }))
      };
    }

    const response = {
      nonce,
      relayKey: runtime?.relayKey || null,
      publicIdentifier: runtime?.publicIdentifier || normalizeRelayIdentifier(rawIdentifier),
      writable,
      canDirectChallenge,
      canProvisionOpenWriter,
      hasMatchingLease,
      canStoreLeaseReplica,
      leaseExpiresAt,
      observedAt
    };
    console.log('[RelayServer] join-capabilities response', {
      identifier: response.publicIdentifier || normalizeRelayIdentifier(rawIdentifier || ''),
      relayKey: response.relayKey,
      writable: response.writable,
      canDirectChallenge: response.canDirectChallenge,
      canProvisionOpenWriter: response.canProvisionOpenWriter,
      hasMatchingLease: response.hasMatchingLease,
      canStoreLeaseReplica: response.canStoreLeaseReplica,
      leaseExpiresAt: response.leaseExpiresAt
    });

    await recordRelayCapabilityProbe({
      relayKey: response.relayKey,
      publicIdentifier: response.publicIdentifier,
      peerKey: config?.swarmPublicKey || null,
      observedAt,
      success: true,
      supported: true,
      canDirectChallenge,
      canProvisionOpenWriter,
      hasMatchingLease,
      canStoreLeaseReplica,
      leaseExpiresAt
    }).catch(() => {});

    await upsertRelayDiscoveryHints({
      relayKey: response.relayKey,
      publicIdentifier: response.publicIdentifier,
      hostPeerKeys: config?.swarmPublicKey ? [config.swarmPublicKey] : [],
      writerIssuerPubkey: runtime?.profile?.admin_pubkey || config?.nostr_pubkey_hex || null,
      observedAt
    }).catch(() => {});

    updateMetrics(true);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: b4a.from(JSON.stringify(response))
    };
  });

  protocol.handle('/post/relay/:identifier/writer-lease-sync', async (request) => {
    const rawIdentifier = request.params.identifier;
    const runtime = await resolveRelayRuntimeForIdentifier(rawIdentifier);
    const body = parseRequestBodyJson(request);
    const headers = request?.headers || {};
    const sourcePeerKey = normalizeHex64(
      headers['x-source-peer-key']
      || headers['x-source-peer']
      || body?.sourcePeerKey
      || null
    );

    if (!runtime?.relayManager?.relay) {
      updateMetrics(false);
      return {
        statusCode: 404,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Relay not active' }))
      };
    }
    if (runtime.relayManager.relay.writable !== true) {
      updateMetrics(false);
      return {
        statusCode: 409,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Relay not writable for lease sync' }))
      };
    }
    if (sourcePeerKey && !consumeWriterLeaseSyncRateLimit(sourcePeerKey)) {
      updateMetrics(false);
      return {
        statusCode: 429,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Rate limit exceeded' }))
      };
    }

    const envelopeInput =
      (body?.envelope && typeof body.envelope === 'object' ? body.envelope : null)
      || (body?.writerLeaseEnvelope && typeof body.writerLeaseEnvelope === 'object' ? body.writerLeaseEnvelope : null);
    const signature = typeof envelopeInput?.signature === 'string' ? envelopeInput.signature.trim() : '';
    const payload = canonicalizeWriterLeaseEnvelopePayload(envelopeInput);
    if (!payload || !signature) {
      updateMetrics(false);
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Invalid lease envelope' }))
      };
    }

    const relayKeyMismatch = runtime?.relayKey && payload.relayKey !== runtime.relayKey;
    const identifierMismatch = runtime?.publicIdentifier && payload.publicIdentifier !== runtime.publicIdentifier;
    if (relayKeyMismatch || identifierMismatch) {
      updateMetrics(false);
      return {
        statusCode: 409,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Lease envelope relay mismatch' }))
      };
    }

    const envelope = { ...payload, signature };
    const validSignature = await verifyWriterLeaseEnvelope(envelope);
    if (!validSignature) {
      updateMetrics(false);
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Invalid lease signature' }))
      };
    }

    const observedAt = Date.now();
    await upsertRelayLeaseEnvelope({
      envelope,
      relayKey: runtime?.relayKey || payload.relayKey,
      publicIdentifier: runtime?.publicIdentifier || payload.publicIdentifier,
      sourcePeerKey: sourcePeerKey || payload.issuerSwarmPeerKey || null,
      observedAt
    });
    await recordRelayLeaseReplicaPeer({
      relayKey: runtime?.relayKey || payload.relayKey,
      publicIdentifier: runtime?.publicIdentifier || payload.publicIdentifier,
      peerKey: sourcePeerKey || payload.issuerSwarmPeerKey || null,
      observedAt
    }).catch(() => {});
    await upsertRelayDiscoveryHints({
      relayKey: runtime?.relayKey || payload.relayKey,
      publicIdentifier: runtime?.publicIdentifier || payload.publicIdentifier,
      leaseReplicaPeerKeys: [
        sourcePeerKey || null,
        payload.issuerSwarmPeerKey || null,
        config?.swarmPublicKey || null
      ],
      observedAt
    }).catch(() => {});

    updateMetrics(true);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: b4a.from(JSON.stringify({
        acknowledged: true,
        leaseId: payload.leaseId,
        expiresAt: payload.expiresAt,
        observedAt
      }))
    };
  });

  protocol.handle('/post/relay/:identifier/writer-lease-claim', async (request) => {
    const rawIdentifier = request.params.identifier;
    const runtime = await resolveRelayRuntimeForIdentifier(rawIdentifier);
    const body = parseRequestBodyJson(request);
    const inviteePubkey = normalizeHex64(body?.inviteePubkey || null);
    const relayKeyHint = normalizeHex64(body?.relayKey || runtime?.relayKey || null);
    const tokenHash =
      (typeof body?.tokenHash === 'string' && body.tokenHash.trim().toLowerCase())
      || computeLeaseTokenHash(relayKeyHint || runtime?.relayKey || null, body?.token || null)
      || null;

    if (!inviteePubkey || !tokenHash) {
      updateMetrics(false);
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Missing inviteePubkey or tokenHash' }))
      };
    }

    const match = await findMatchingRelayLeaseEnvelope({
      relayKey: relayKeyHint || runtime?.relayKey || null,
      publicIdentifier: runtime?.publicIdentifier || normalizeRelayIdentifier(rawIdentifier),
      inviteePubkey,
      tokenHash
    });
    if (!match?.envelope) {
      updateMetrics(false);
      return {
        statusCode: 404,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'No matching lease' }))
      };
    }

    const validSignature = await verifyWriterLeaseEnvelope(match.envelope);
    if (!validSignature) {
      updateMetrics(false);
      return {
        statusCode: 409,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Stored lease signature invalid' }))
      };
    }

    const observedAt = Date.now();
    await recordRelayLeaseReplicaPeer({
      relayKey: runtime?.relayKey || match.envelope.relayKey,
      publicIdentifier: runtime?.publicIdentifier || match.envelope.publicIdentifier,
      peerKey: config?.swarmPublicKey || null,
      observedAt
    }).catch(() => {});
    await upsertRelayDiscoveryHints({
      relayKey: runtime?.relayKey || match.envelope.relayKey,
      publicIdentifier: runtime?.publicIdentifier || match.envelope.publicIdentifier,
      leaseReplicaPeerKeys: [config?.swarmPublicKey || null],
      observedAt
    }).catch(() => {});

    updateMetrics(true);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: b4a.from(JSON.stringify({
        ok: true,
        envelope: match.envelope,
        leaseExpiresAt: match.leaseExpiresAt || match.envelope.expiresAt || null,
        observedAt
      }))
    };
  });

  // Handle verify ownership
  protocol.handle('/verify-ownership', async (request) => {
    console.log(`[RelayServer] ========================================`);
    console.log(`[RelayServer] VERIFY OWNERSHIP REQUEST`);
    
    try {
      const body = JSON.parse(request.body.toString());
      const { pubkey, ciphertext, iv } = body;
      
      if (!pubkey || !ciphertext || !iv) {
        console.error(`[RelayServer] Missing required fields`);
        updateMetrics(false);
        return {
          statusCode: 400,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: 'Missing required fields' }))
        };
      }
      
      console.log(`[RelayServer] Verifying for pubkey: ${pubkey.substring(0, 8)}...`);
      console.log(`[RelayServer] Ciphertext length: ${ciphertext.length}`);
      console.log(`[RelayServer] IV length: ${iv.length}`);
      
      // Verify the challenge
      const challengeManager = getChallengeManager();
      const result = await challengeManager.verifyChallenge(pubkey, ciphertext, iv);
      
      if (!result.success) {
        console.error(`[RelayServer] Verification failed: ${result.error}`);
        updateMetrics(false);
        return {
          statusCode: 400,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: result.error }))
        };
      }
      
      console.log(`[RelayServer] Verification SUCCESSFUL`);
      console.log(`[RelayServer] Token: ${result.token.substring(0, 16)}...`);
      console.log(`[RelayServer] Identifier: ${result.identifier}`);

      // Finalize authentication locally (replaces /finalize-auth)

      const canonicalIdentifier = normalizeRelayIdentifier(result.identifier);
      let internalRelayKey = canonicalIdentifier;
      const resolvedKey = await getRelayKeyFromPublicIdentifier(canonicalIdentifier);
      if (resolvedKey) {
        internalRelayKey = resolvedKey;
      }

      assertTokenOwnerMatchesExpectedPubkey({
        relayKey: internalRelayKey,
        publicIdentifier: canonicalIdentifier,
        authToken: result.token,
        expectedPubkey: pubkey,
        context: 'verify-ownership'
      });

      const authStore = getRelayAuthStore();
      authStore.addAuth(internalRelayKey, pubkey, result.token);
      if (internalRelayKey !== canonicalIdentifier) {
        authStore.addAuth(canonicalIdentifier, pubkey, result.token);
      }

      let profile = await getRelayProfileByKey(internalRelayKey);
      if (!profile) {
        profile = await getRelayProfileByPublicIdentifier(canonicalIdentifier);
      }
      const relayUrl = buildCanonicalRelayUrl(canonicalIdentifier, result.token, config);
      const shouldProvisionWriter = Boolean(profile && profile.isOpen !== false);
      const writerProvisionTask = shouldProvisionWriter
        ? provisionWriterForInvitee({
          relayKey: internalRelayKey,
          publicIdentifier: canonicalIdentifier,
          // Keep verify-ownership response latency low; do not block on relay.update({ wait: true }).
          skipUpdateWait: true,
          reason: 'open-join-verify'
        }).then((writerInfo) => {
          console.log('[RelayServer] Provisioned writer for open join (async verify tail)', {
            relayKey: internalRelayKey,
            publicIdentifier: canonicalIdentifier,
            writerCore: writerInfo?.writerCore ? String(writerInfo.writerCore).slice(0, 16) : null,
            writerCoreHex: writerInfo?.writerCoreHex ? String(writerInfo.writerCoreHex).slice(0, 16) : null,
            autobaseLocal: writerInfo?.autobaseLocal ? String(writerInfo.autobaseLocal).slice(0, 16) : null
          });
          return writerInfo;
        }).catch((writerError) => {
          console.warn('[RelayServer] Failed to provision writer for open join (async verify tail)', writerError?.message || writerError);
          return null;
        })
        : null;

      // Keep verify-ownership latency bounded: commit membership/profile updates and
      // open-writer provisioning in the background after returning auth success.
      void (async () => {
        if (profile) {
          await updateRelayAuthToken(internalRelayKey, pubkey, result.token);
          const currentAdds = profile.member_adds || [];
          const currentRemoves = profile.member_removes || [];
          const memberAdd = { pubkey, ts: Date.now() };
          const existingIndex = currentAdds.findIndex((member) => member.pubkey === pubkey);
          if (existingIndex >= 0) currentAdds[existingIndex] = memberAdd;
          else currentAdds.push(memberAdd);
          await updateRelayMemberSets(internalRelayKey, currentAdds, currentRemoves);
          await publishMemberAddEvent(canonicalIdentifier, pubkey, result.token).catch((publishError) => {
            console.warn('[RelayServer] Async member add publish failed during verify', {
              identifier: canonicalIdentifier,
              pubkey: pubkey.substring(0, 8),
              error: publishError?.message || publishError
            });
          });
        }
      })().catch((tailError) => {
        console.warn('[RelayServer] Verify tail task failed', {
          identifier: canonicalIdentifier,
          pubkey: pubkey.substring(0, 8),
          error: tailError?.message || tailError
        });
      });

      const verifyResponseWriterWindowMs = 1200;
      let writerInfo = null;
      if (writerProvisionTask) {
        writerInfo = await Promise.race([
          writerProvisionTask,
          new Promise((resolve) => {
            const timer = setTimeout(() => resolve(null), verifyResponseWriterWindowMs);
            timer.unref?.();
          })
        ]);
      }
      const writerProvisionPending = shouldProvisionWriter && !writerInfo;

      console.log(`[RelayServer] Auth finalized successfully`);
      updateMetrics(true);
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({
          success: true,
          relayKey: internalRelayKey,
          publicIdentifier: canonicalIdentifier,
          authToken: result.token,
          relayUrl,
          writerCore: writerInfo?.writerCore || null,
          writerCoreHex: writerInfo?.writerCoreHex || null,
          autobaseLocal: writerInfo?.autobaseLocal || null,
          writerSecret: writerInfo?.writerSecret || null,
          writerProvisionPending
        }))
      };
      
    } catch (error) {
      console.error(`[RelayServer] ========================================`);
      console.error(`[RelayServer] VERIFY OWNERSHIP ERROR`);
      console.error(`[RelayServer] Error:`, error.message);
      console.error(`[RelayServer] Stack:`, error.stack);
      console.error(`[RelayServer] ========================================`);
      
      if (error?.code === 'auth-token-owner-mismatch') {
        updateMetrics(false);
        return {
          statusCode: 409,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: error.message, code: error.code }))
        };
      }

      updateMetrics(false);
      return {
        statusCode: 500,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: error.message }))
      };
    }
  });

  // Removed finalize-auth and authorize handlers (handled during verification)

  // Disconnect from relay
  protocol.handle('/relay/:identifier/disconnect', async (request) => {
    const rawIdentifier = request.params.identifier;
    const identifier = normalizeRelayIdentifier(rawIdentifier);
    console.log('[RelayServer] Disconnect relay requested for identifier:', rawIdentifier);
    if (rawIdentifier !== identifier) {
      console.log(`[RelayServer] Normalized identifier: ${identifier}`);
    }
    
    try {
        // Resolve public identifier to relay key if needed
        let relayKey = await getRelayKeyFromPublicIdentifier(identifier) || identifier;
        if (relayKey !== identifier) {
            console.log(`[RelayServer] Resolved public identifier ${identifier} to relay key ${relayKey.substring(0, 8)}...`);
        } else if (!/^[a-f0-9]{64}$/i.test(relayKey)) {
            if (!shouldSuppressMissingRelayLog(identifier)) {
              console.warn(`[RelayServer] No relay found for public identifier: ${identifier}`);
            }
            updateMetrics(false);
            return {
                statusCode: 404,
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify({ error: 'Relay not found' }))
            };
        }
        
        const result = await disconnectRelayManager(relayKey);
        
        if (result.success) {
            console.log('[RelayServer] Disconnected from relay successfully');
            await updateHealthState();
            
            // Send update to parent
            if (global.sendMessage) {
                const activeRelays = await getActiveRelays();
                global.sendMessage({
                    type: 'relay-update',
                    relays: activeRelays
                });
            }
            
            // Update gateway if connected
            if (config.registerWithGateway && gatewayConnection) {
                console.log('[RelayServer] Updating gateway after relay disconnect');
                try {
                    await registerWithGateway();
                } catch (regError) {
                    console.error('[RelayServer] Failed to notify gateway of relay disconnect:', regError.message);
                }
            }
            
            updateMetrics(true);
            return {
                statusCode: 200,
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify(result))
            };
        } else {
            console.error('[RelayServer] Failed to disconnect relay:', result.error);
            updateMetrics(false);
            return {
                statusCode: 404,
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify({ error: result.error }))
            };
        }
    } catch (error) {
        console.error('[RelayServer] Error disconnecting relay:', error);
        updateMetrics(false);
        return {
            statusCode: 500,
            headers: { 'content-type': 'application/json' },
            body: b4a.from(JSON.stringify({ error: error.message }))
        };
    }
});
  
  // Handle relay messages (from gateway)
  protocol.handle('/post/relay/:identifier', async (request) => {
    const rawIdentifier = request.params.identifier;
    const identifier = normalizeRelayIdentifier(rawIdentifier);
    const { message, connectionKey } = JSON.parse(request.body.toString());

    console.log(`[RelayServer] Relay message for identifier: ${rawIdentifier}, connectionKey: ${connectionKey}`);
    if (rawIdentifier !== identifier) {
      console.log(`[RelayServer] Normalized identifier: ${identifier}`);
    }
    
    try {
      // Extract auth token from request headers
      let authToken = request.headers['x-auth-token'];
      if (!authToken && request.query?.token) {
        authToken = request.query.token;
      }
      let clientId = null;

      console.log(`[RelayServer] Auth token present: ${!!authToken}`);
      
      // Check if identifier is a public identifier or relay key
      let relayKey = await getRelayKeyFromPublicIdentifier(identifier) || identifier;
      const relayKeyPreview = typeof relayKey === 'string' && relayKey.length > 8
        ? `${relayKey.substring(0, 8)}...`
        : relayKey;

      let virtualRelay = false;
      if (relayKey !== identifier) {
        console.log(`[RelayServer] Resolved public identifier ${identifier} to relay key ${relayKeyPreview}`);
      }

      if (!/^[a-f0-9]{64}$/i.test(relayKey)) {
        const isActive = await isRelayActiveByPublicIdentifier(identifier);
        if (!isActive) {
          if (!shouldSuppressMissingRelayLog(identifier)) {
            console.error(`[RelayServer] No relay found for public identifier: ${identifier}`);
          }
          updateMetrics(false);
          return {
            statusCode: 404,
            headers: { 'content-type': 'application/json' },
            body: b4a.from(JSON.stringify({ error: 'Relay not found' }))
          };
        }
        virtualRelay = true;
        console.log(`[RelayServer] Handling virtual relay ${identifier} (resolved key: ${relayKey})`);
      }
      
      // Parse the message (supports both string payloads and Buffer objects)
      let nostrMessage;
      try {
        nostrMessage = parseNostrMessagePayload(message);
      } catch (parseError) {
        throw new Error(`Failed to parse NOSTR message: ${parseError.message}`);
      }
  
      if (!Array.isArray(nostrMessage)) {
        throw new Error('Invalid NOSTR message format - expected array');
      }
  
      console.log(`[RelayServer] Processing ${nostrMessage[0]} message`);
  
      // Get auth store and check if relay is protected
      const authStore = getRelayAuthStore();
      const authorizedPubkeys = authStore.getAuthorizedPubkeys(relayKey);
      
      // Get relay profile to check auth configuration
      let profile = await getRelayProfileByKey(relayKey);
      if (!profile && identifier !== relayKey) {
        profile = await getRelayProfileByPublicIdentifier(identifier);
      }
      
      const requiresAuth = authorizedPubkeys.length > 0 || 
                          profile?.auth_config?.requiresAuth || 
                          false;
      
      console.log(`[RelayServer] Relay ${identifier} requires auth: ${requiresAuth}${virtualRelay ? ' (virtual relay)' : ''}`);
      console.log(`[RelayServer] Authorized pubkeys count: ${authorizedPubkeys.length}`);

      // Handle authentication for protected relays
      if (requiresAuth) {
        // For REQ (subscription) messages, check if read access requires auth
        if (nostrMessage[0] === 'REQ') {
          // Some relays might allow public read access
          // You can customize this based on your requirements
          if (profile?.auth_config?.publicRead !== true) {
            if (!authToken) {
              console.warn(`[RelayServer] Missing auth token for REQ on protected relay`);
              updateMetrics(false);
              return {
                statusCode: 403,
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify([
                  ['NOTICE', 'Authentication required for read access']
                ]))
              };
            }

            // Verify auth for REQ
            const auth = authStore.verifyAuth(relayKey, authToken);
            if (!auth) {
              console.warn(`[RelayServer] Invalid auth for REQ`);
              updateMetrics(false);
              return {
                statusCode: 403,
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify([
                  ['NOTICE', 'Invalid authentication']
                ]))
              };
            }
            
            console.log(`[RelayServer] REQ authenticated for ${auth.pubkey.substring(0, 8)}...`);
            clientId = authToken || auth.pubkey;
          }
        }
        
        // For EVENT messages, always require auth
        if (nostrMessage[0] === 'EVENT') {
          const event = nostrMessage.length === 2 ? nostrMessage[1] : nostrMessage[2];
          
          if (!authToken) {
            console.warn(`[RelayServer] Missing auth token for EVENT`);
            updateMetrics(false);

            // Return proper NOSTR OK response with auth error
            const okResponse = ['OK', event?.id || '', false, 'error: authentication required'];
            return {
              statusCode: 200, // Still 200 because it's a valid NOSTR response
              headers: { 'content-type': 'application/json' },
              body: b4a.from(JSON.stringify(okResponse))
            };
          }
          
          // Verify the auth
          const auth = authStore.verifyAuth(relayKey, authToken);
          if (!auth) {
            console.warn(`[RelayServer] Invalid auth token`);
            updateMetrics(false);
            
            const okResponse = ['OK', event?.id || '', false, 'error: invalid authentication'];
            return {
              statusCode: 200,
              headers: { 'content-type': 'application/json' },
              body: b4a.from(JSON.stringify(okResponse))
            };
          }
          
          clientId = authToken || auth.pubkey;

          // Check if the event pubkey matches the authenticated user
          if (event && event.pubkey !== auth.pubkey) {
            console.warn(`[RelayServer] Event pubkey ${event.pubkey} doesn't match auth pubkey ${auth.pubkey}`);
            updateMetrics(false);
            
            const okResponse = ['OK', event.id, false, 'error: pubkey mismatch - event must be signed by authenticated user'];
            return {
              statusCode: 200,
              headers: { 'content-type': 'application/json' },
              body: b4a.from(JSON.stringify(okResponse))
            };
          }
          
          // Get current member list to verify membership
          const members = await getRelayMembers(relayKey);
          if (!members.includes(auth.pubkey)) {
            console.warn(`[RelayServer] Authenticated pubkey ${auth.pubkey} is not a member`);
            updateMetrics(false);
            
            const okResponse = ['OK', event.id, false, 'error: not a member of this relay'];
            return {
              statusCode: 200,
              headers: { 'content-type': 'application/json' },
              body: b4a.from(JSON.stringify(okResponse))
            };
          }
          
          console.log(`[RelayServer] EVENT authenticated and authorized for ${auth.pubkey.substring(0, 8)}...`);
          
          // Update last used timestamp
          auth.lastUsed = Date.now();
        }
      } else {
        // For non-protected relays, still check member list for EVENT messages
        if (nostrMessage[0] === 'EVENT') {
          const event = nostrMessage.length === 2 ? nostrMessage[1] : nostrMessage[2];
          const members = await getRelayMembers(relayKey);
          
          // If relay has members defined, check membership
          if (members.length > 0 && event && !members.includes(event.pubkey)) {
            console.warn(`[RelayServer] Non-member ${event.pubkey} attempting to publish to relay with member list`);
            updateMetrics(false);
            
            const okResponse = ['OK', event.id, false, 'error: not a member of this relay'];
            return {
              statusCode: 200,
              headers: { 'content-type': 'application/json' },
              body: b4a.from(JSON.stringify(okResponse))
            };
          }
        }
      }
      
      if (!clientId && authToken) {
        clientId = authToken;
      }

      if (nostrMessage[0] === 'REQ' && !virtualRelay) {
        const gate = getRelayWritableGate(relayKey);
        if (gate.available && !gate.writable) {
          console.log('[RelayServer] Deferring REQ (relay not writable)', {
            relayKey: relayKeyPreview,
            connectionKey,
            writable: gate.writable
          });
          updateMetrics(true);
          return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            body: b4a.from(JSON.stringify([['NOTICE', 'Relay initializing; read deferred']]))
          };
        }
      }

      if (clientId) {
        const previousKey = setRelayClientConnectionKey(relayKey, clientId, connectionKey);
        if (previousKey && previousKey !== connectionKey) {
          console.log('[RelayServer] Client connectionKey updated', {
            relayKey,
            clientId,
            fromKey: previousKey,
            toKey: connectionKey,
            context: `post-${nostrMessage[0]}`
          });
        }
      }

      // Process the message through relay manager
      const responses = [];
      const sendResponse = (response) => {
        console.log(`[RelayServer] Queueing response for relay ${relayKey}:`, 
          Array.isArray(response) ? `${response[0]} message` : 'unknown response');
        responses.push(response);
      };
      
      await handleRelayMessage(relayKey, nostrMessage, sendResponse, connectionKey, clientId);
      
      console.log(`[RelayServer] Handled message, ${responses.length} responses queued`);
      
      // Format responses for return
      const responseBody = responses.length > 0 
        ? responses.map(r => JSON.stringify(r)).join('\n')
        : '';
      
      updateMetrics(true);
      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(responseBody)
      };
      
    } catch (error) {
      console.error(`[RelayServer] Error processing message:`, error);
      console.error(`[RelayServer] Stack trace:`, error.stack);
      updateMetrics(false);
      
      // Return NOTICE with error
      return {
        statusCode: 200, // Still 200 for valid NOSTR error response
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify([
          ['NOTICE', `Error: ${error.message}`]
        ]))
      };
    }
  });
  
  // Handle relay subscriptions (from gateway)
  protocol.handle('/get/relay/:identifier/:connectionKey', async (request) => {
    const rawIdentifier = request.params.identifier;
    const identifier = normalizeRelayIdentifier(rawIdentifier);
    // Extract auth token from request headers
    let authToken = request.headers['x-auth-token'];
    if (!authToken && request.query?.token) {
      authToken = request.query.token;
    }
    let auth = null;
    let clientId = null;
    const connectionKey = request.params.connectionKey;

    console.log(`[RelayServer] Checking subscriptions for identifier: ${rawIdentifier}, connectionKey: ${connectionKey}`);
    if (rawIdentifier !== identifier) {
      console.log(`[RelayServer] Normalized identifier: ${identifier}`);
    }
    
    try {
        // Resolve public identifier to relay key if needed
        let relayKey = await getRelayKeyFromPublicIdentifier(identifier) || identifier;
        const relayKeyPreview = typeof relayKey === 'string' && relayKey.length > 8
          ? `${relayKey.substring(0, 8)}...`
          : relayKey;

        let virtualRelay = false;
        if (relayKey !== identifier) {
            console.log(`[RelayServer] Resolved public identifier ${identifier} to relay key ${relayKeyPreview}`);
        }

        if (!/^[a-f0-9]{64}$/i.test(relayKey)) {
            const isActive = await isRelayActiveByPublicIdentifier(identifier);
            if (!isActive) {
                if (!shouldSuppressMissingRelayLog(identifier)) {
                  console.error(`[RelayServer] No relay found for public identifier: ${identifier}`);
                }
                updateMetrics(false);
                return {
                    statusCode: 404,
                    headers: { 'content-type': 'application/json' },
                    body: b4a.from(JSON.stringify(['NOTICE', 'Relay not found']))
                };
            }
            virtualRelay = true;
            console.log(`[RelayServer] Handling virtual relay ${identifier} (resolved key: ${relayKey})`);
        }

        // Get auth store and check if relay is protected
        const authStore = getRelayAuthStore();
        const authorizedPubkeys = authStore.getAuthorizedPubkeys(relayKey);

        // Get relay profile to check auth configuration
        let profile = await getRelayProfileByKey(relayKey);
        if (!profile && identifier !== relayKey) {
        profile = await getRelayProfileByPublicIdentifier(identifier);
      }

      const requiresAuth = authorizedPubkeys.length > 0 ||
                          profile?.auth_config?.requiresAuth ||
                          false;

      console.log(`[RelayServer] Relay ${identifier} requires auth for read: ${requiresAuth}${virtualRelay ? ' (virtual relay)' : ''}`);
      console.log(`[RelayServer] Authorized pubkeys count: ${authorizedPubkeys.length}`);

      // Handle authentication for protected relays
      if (requiresAuth) {
        // This endpoint is implicitly for REQ messages (fetching events for a subscription)
        // Check if public read access is explicitly allowed
          if (profile?.auth_config?.publicRead !== true) {
            if (!authToken) {
              console.warn(`[RelayServer] Missing auth token for read access on protected relay`);
              updateMetrics(false);
              return {
                statusCode: 200, // Return 200 for valid NOSTR NOTICE response
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify([
                  ['NOTICE', 'Authentication required for read access']
                ]))
              };
            }

            // Verify auth
            auth = authStore.verifyAuth(relayKey, authToken);
            if (!auth) {
              console.warn(`[RelayServer] Invalid auth for read access`);
              updateMetrics(false);
              return {
                statusCode: 200, // Return 200 for valid NOSTR NOTICE response
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify([
                  ['NOTICE', 'Invalid authentication']
                ]))
              };
            }

            console.log(`[RelayServer] Read access authenticated for ${auth.pubkey.substring(0, 8)}...`);
            clientId = authToken || auth.pubkey;
            // Update last used timestamp
            auth.lastUsed = Date.now();
          } else {
            console.log(`[RelayServer] Relay ${identifier} allows public read access despite requiring auth.`);
          }
        }
        
        if (!clientId && authToken) {
          clientId = authToken;
        }

        const stableClientId = auth?.pubkey || null;

        if (!virtualRelay) {
          const gate = getRelayWritableGate(relayKey);
          if (gate.available && !gate.writable) {
            console.log('[RelayServer] Deferring subscription replay (relay not writable)', {
              relayKey: relayKeyPreview,
              connectionKey,
              writable: gate.writable
            });
            updateMetrics(true);
            return {
              statusCode: 200,
              headers: { 'content-type': 'application/json' },
              body: b4a.from(JSON.stringify([['NOTICE', 'Relay initializing; read deferred']]))
            };
          }
        }

        if (clientId) {
          const previousKey = getRelayClientConnectionKey(relayKey, clientId);
          let rehydrateResult = null;
          let rehydrateOk = false;

          if (previousKey && previousKey !== connectionKey) {
            try {
              rehydrateResult = await rehydrateRelaySubscriptions(relayKey, previousKey, connectionKey, { clientId });
            } catch (rehydrateError) {
              rehydrateResult = {
                ok: false,
                reason: rehydrateError?.message || rehydrateError
              };
            }

            console.log('[RelayServer] Subscription rehydrate attempt', {
              clientId,
              relayKey,
              fromKey: previousKey,
              toKey: connectionKey,
              subscriptionCount: rehydrateResult?.subscriptionCount ?? 0,
              last_returned_event_timestamp: rehydrateResult?.lastReturned ?? null,
              ok: rehydrateResult?.ok ?? false,
              source: 'connection-key'
            });
          }

          rehydrateOk = rehydrateResult?.ok === true;

          if (!rehydrateOk) {
            try {
              const clientSnapshotRaw = await getRelayClientSubscriptions(relayKey, clientId);
              const clientSnapshot = compactSubscriptionSnapshot(clientSnapshotRaw);
              const currentSnapshot = compactSubscriptionSnapshot(
                await getRelaySubscriptions(relayKey, connectionKey)
              );
              const mergedSnapshot = compactSubscriptionSnapshot(
                mergeSubscriptionSnapshots(currentSnapshot, clientSnapshot)
              );
              const subscriptionCount = mergedSnapshot?.subscriptions
                ? Object.keys(mergedSnapshot.subscriptions).length
                : 0;
              if (subscriptionCount > 0) {
                const snapshotTimestamps = Object.values(mergedSnapshot.subscriptions || {})
                  .map((subscription) => subscription?.last_returned_event_timestamp)
                  .filter((value) => typeof value === 'number');
                const lastReturned = snapshotTimestamps.length ? Math.max(...snapshotTimestamps) : null;
                const updated = {
                  ...mergedSnapshot,
                  clientId,
                  connection: connectionKey
                };
                await updateRelaySubscriptions(relayKey, connectionKey, updated);
                await updateRelayClientSubscriptions(relayKey, clientId, updated);
                console.log('[RelayServer] Subscription rehydrate from client snapshot', {
                  clientId,
                  relayKey,
                  fromKey: clientSnapshot?.connection || null,
                  toKey: connectionKey,
                  subscriptionCount,
                  last_returned_event_timestamp: lastReturned,
                  ok: true,
                  source: 'client-snapshot'
                });
                rehydrateOk = true;
              }
            } catch (snapshotError) {
              console.log('[RelayServer] Subscription rehydrate from client snapshot failed', {
                clientId,
                relayKey,
                error: snapshotError?.message || snapshotError
              });
            }
          }

          if (!rehydrateOk && stableClientId && stableClientId !== clientId) {
            const stablePreviousKey = getRelayClientConnectionKey(relayKey, stableClientId);
            let stableRehydrateResult = null;

            if (stablePreviousKey && stablePreviousKey !== connectionKey) {
              try {
                stableRehydrateResult = await rehydrateRelaySubscriptions(relayKey, stablePreviousKey, connectionKey, { clientId });
              } catch (rehydrateError) {
                stableRehydrateResult = {
                  ok: false,
                  reason: rehydrateError?.message || rehydrateError
                };
              }

              console.log('[RelayServer] Subscription rehydrate attempt', {
                clientId,
                relayKey,
                fromKey: stablePreviousKey,
                toKey: connectionKey,
                subscriptionCount: stableRehydrateResult?.subscriptionCount ?? 0,
                last_returned_event_timestamp: stableRehydrateResult?.lastReturned ?? null,
                ok: stableRehydrateResult?.ok ?? false,
                source: 'pubkey-connection-key'
              });
            }

            rehydrateOk = stableRehydrateResult?.ok === true;

            if (!rehydrateOk) {
              try {
                const stableSnapshotRaw = await getRelayClientSubscriptions(relayKey, stableClientId);
                const stableSnapshot = compactSubscriptionSnapshot(stableSnapshotRaw);
                const currentSnapshot = compactSubscriptionSnapshot(
                  await getRelaySubscriptions(relayKey, connectionKey)
                );
                const mergedSnapshot = compactSubscriptionSnapshot(
                  mergeSubscriptionSnapshots(currentSnapshot, stableSnapshot)
                );
                const subscriptionCount = mergedSnapshot?.subscriptions
                  ? Object.keys(mergedSnapshot.subscriptions).length
                  : 0;
                if (subscriptionCount > 0) {
                  const snapshotTimestamps = Object.values(mergedSnapshot.subscriptions || {})
                    .map((subscription) => subscription?.last_returned_event_timestamp)
                    .filter((value) => typeof value === 'number');
                  const lastReturned = snapshotTimestamps.length ? Math.max(...snapshotTimestamps) : null;
                  const updated = {
                    ...mergedSnapshot,
                    clientId,
                    connection: connectionKey
                  };
                  const stableUpdated = {
                    ...mergedSnapshot,
                    clientId: stableClientId,
                    connection: connectionKey
                  };
                  await updateRelaySubscriptions(relayKey, connectionKey, updated);
                  await updateRelayClientSubscriptions(relayKey, clientId, updated);
                  await updateRelayClientSubscriptions(relayKey, stableClientId, stableUpdated);
                  console.log('[RelayServer] Subscription rehydrate from client snapshot', {
                    clientId,
                    relayKey,
                    fromKey: stableSnapshot?.connection || null,
                    toKey: connectionKey,
                    subscriptionCount,
                    last_returned_event_timestamp: lastReturned,
                    ok: true,
                    source: 'pubkey-snapshot'
                  });
                  rehydrateOk = true;
                }
              } catch (snapshotError) {
                console.log('[RelayServer] Subscription rehydrate from client snapshot failed', {
                  clientId,
                  relayKey,
                  error: snapshotError?.message || snapshotError
                });
              }
            }
          }

          const previousStored = setRelayClientConnectionKey(relayKey, clientId, connectionKey);
          if (previousStored && previousStored !== connectionKey) {
            console.log('[RelayServer] Client connectionKey updated', {
              relayKey,
              clientId,
              fromKey: previousStored,
              toKey: connectionKey,
              context: 'get-relay'
            });
          }
          if (stableClientId && stableClientId !== clientId) {
            const previousStableStored = setRelayClientConnectionKey(relayKey, stableClientId, connectionKey);
            if (previousStableStored && previousStableStored !== connectionKey) {
              console.log('[RelayServer] Client connectionKey updated', {
                relayKey,
                clientId: stableClientId,
                fromKey: previousStableStored,
                toKey: connectionKey,
                context: 'get-relay-pubkey'
              });
            }
          }
        }

        const [events, activeSubscriptionsUpdated] = await handleRelaySubscription(relayKey, connectionKey);
        
        if (!Array.isArray(events)) {
            console.log(`[RelayServer] Invalid response format from handleSubscription`);
            updateMetrics(false);
            return {
                statusCode: 500,
                headers: { 'content-type': 'application/json' },
                body: b4a.from(JSON.stringify(['NOTICE', 'Internal server error: Invalid response format']))
            };
        }
  
        if (Array.isArray(events)) {
            const eventFrames = events.filter((frame) => Array.isArray(frame) && frame[0] === 'EVENT');
            const eoseFrames = events.filter((frame) => Array.isArray(frame) && frame[0] === 'EOSE');
            console.log(`[RelayServer] Subscription replay for connectionKey: ${connectionKey}${virtualRelay ? ' [virtual relay]' : ''} events=${eventFrames.length} eose=${eoseFrames.length}`);
            const relayManager = !virtualRelay && relayKey ? activeRelays.get(relayKey) : null;
            const relayProgressSnapshot = relayManager?.relay
              ? collectRelayProgressSnapshot(relayManager.relay)
              : null;
            const relaySyncReady = isRelayProgressSyncReady(relayProgressSnapshot);
            const replaySummaries = summarizeSubscriptionReplayFrames(events, relaySyncReady);
            const replayedAt = Date.now();
            const publicIdentifier =
              profile?.public_identifier
              || (identifier && identifier.includes(':') ? identifier : null)
              || null;
            if (global.sendMessage) {
              global.sendMessage({
                type: 'relay-subscription-replay',
                data: {
                  relayKey: relayKey || null,
                  publicIdentifier,
                  connectionKey,
                  relaySyncReady,
                  replayedAt,
                  summaries: replaySummaries
                }
              });
            }
        } else {
            console.log(`[RelayServer] Subscription replay produced unexpected payload for connectionKey: ${connectionKey}${virtualRelay ? ' [virtual relay]' : ''}`);
        }
        
        // Update subscriptions if needed
        if (activeSubscriptionsUpdated) {
            try {
                console.log(`[RelayServer] Updating subscriptions for connectionKey: ${connectionKey}`);
                const compactActiveSubscriptions = compactSubscriptionSnapshot(activeSubscriptionsUpdated);
                await updateRelaySubscriptions(relayKey, connectionKey, compactActiveSubscriptions);
                if (clientId) {
                    await updateRelayClientSubscriptions(relayKey, clientId, {
                      ...compactActiveSubscriptions,
                      clientId
                    });
                    if (stableClientId && stableClientId !== clientId) {
                      await updateRelayClientSubscriptions(relayKey, stableClientId, {
                        ...compactActiveSubscriptions,
                        clientId: stableClientId
                      });
                    }
                }
                console.log(`[RelayServer] Successfully updated subscriptions for connectionKey: ${connectionKey}`);
            } catch (updateError) {
                console.log(`[RelayServer] Warning: Failed to update subscriptions for connectionKey: ${connectionKey}:`, updateError.message);
            }
        }
        
        updateMetrics(true);
        return {
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            body: b4a.from(JSON.stringify(events))
        };
        
    } catch (error) {
        console.error(`[RelayServer] Error processing subscription:`, error);
        updateMetrics(false);
        return {
            statusCode: 500,
            headers: { 'content-type': 'application/json' },
            body: b4a.from(JSON.stringify(['NOTICE', `Error: ${error.message}`]))
        };
    }
});

  
  // Registration endpoint (for gateway to call)
  protocol.handle('/register', async (request) => {
    const registrationData = JSON.parse(request.body.toString());
    console.log('[RelayServer] Registration endpoint called by gateway');
    console.log('[RelayServer] Registration data:', registrationData);
    
    // Handle any registration response from gateway
    updateMetrics(true);
    return {
      statusCode: 200,
      headers: { 'content-type': 'application/json' },
      body: b4a.from(JSON.stringify({ 
        status: 'acknowledged',
        timestamp: new Date().toISOString()
      }))
    };
  });

  const buildDriveCorsHeaders = (contentType = null, extraHeaders = {}) => {
    const headers = {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,HEAD,OPTIONS',
      'access-control-allow-headers': 'Content-Type, Range',
      'access-control-expose-headers': 'Content-Length, Content-Range, Accept-Ranges',
      'cross-origin-resource-policy': 'cross-origin',
      ...extraHeaders
    };
    if (contentType) headers['content-type'] = contentType;
    return headers;
  };

  const buildDriveSuccessHeaders = ({ contentType, contentLength, fileHash }) => {
    const etag = `"${fileHash}"`
    return buildDriveCorsHeaders(contentType, {
      'content-length': String(contentLength),
      'accept-ranges': 'bytes',
      etag,
      'cache-control': 'private, max-age=31536000, immutable'
    })
  }

  const buildDriveErrorHeaders = () =>
    buildDriveCorsHeaders('application/json', {
      'cache-control': 'no-store'
    })

  const isHtmlDriveRequest = (fileName = '') =>
    typeof fileName === 'string' && /\.html?$/i.test(fileName)

  const readDriveHeaderValue = (headers, name) => {
    if (!headers || typeof headers !== 'object') return null
    const target = String(name || '').toLowerCase()
    const entry = Object.entries(headers).find(([key]) => String(key).toLowerCase() === target)
    if (!entry) return null
    const value = entry[1]
    if (Array.isArray(value)) return value.map((item) => String(item)).join(', ')
    if (typeof value === 'number') return String(value)
    return typeof value === 'string' ? value : null
  }

  const summarizeDriveHeaders = (headers) => ({
    contentType: readDriveHeaderValue(headers, 'content-type'),
    contentSecurityPolicy: readDriveHeaderValue(headers, 'content-security-policy'),
    crossOriginResourcePolicy: readDriveHeaderValue(headers, 'cross-origin-resource-policy'),
    cacheControl: readDriveHeaderValue(headers, 'cache-control')
  })

  const etagMatches = (ifNoneMatchHeader, etag) => {
    if (!ifNoneMatchHeader || !etag) return false
    const normalized = String(ifNoneMatchHeader).trim()
    if (!normalized) return false
    if (normalized === '*') return true
    const candidates = normalized.split(',').map((part) => part.trim()).filter(Boolean)
    return candidates.some((candidate) => {
      const weakNormalized = candidate.startsWith('W/') ? candidate.slice(2) : candidate
      return weakNormalized === etag
    })
  }

  // Serve files stored in Hyperdrive
  protocol.handle('/drive/:identifier/:file', async (request) => {
    if (request?.method === 'OPTIONS') {
      updateMetrics(true);
      return {
        statusCode: 204,
        headers: buildDriveCorsHeaders(null, {
          'content-length': '0',
          'cache-control': 'no-store'
        }),
        body: b4a.from('')
      };
    }

    const rawIdentifier = request.params.identifier;
    const identifier = normalizeRelayIdentifier(rawIdentifier);
    const fileId = request.params.file;

    console.log(`[RelayServer] Drive file requested: ${rawIdentifier}/${fileId}`);
    if (rawIdentifier !== identifier) {
      console.log(`[RelayServer] Normalized identifier: ${identifier}`);
    }

    try {
      const hash = fileId.split('.')[0];
      // Prefer new layout using publicIdentifier path; fall back to legacy relayKey path
      let fileBuffer = await getFile(identifier, hash);
	      if (!fileBuffer) {
	        const relayKey = await getRelayKeyFromPublicIdentifier(identifier);
	        if (relayKey) {
	          fileBuffer = await getFile(relayKey, hash);
	        }
        if (!fileBuffer && typeof global.recoverRelayDriveFile === 'function') {
          const recoverResult = await global.recoverRelayDriveFile({
            relayKey: relayKey || null,
            identifier,
            fileHash: hash,
            reason: 'drive-http-request'
          }).catch((error) => ({
            status: 'error',
            reason: 'recover-threw',
            error: error?.message || String(error)
          }));
          if (recoverResult?.status === 'ok') {
            fileBuffer = await getFile(identifier, hash);
            if (!fileBuffer && relayKey) {
              fileBuffer = await getFile(relayKey, hash);
            }
          } else {
            console.warn('[RelayServer] Drive recovery failed', {
              identifier,
              hash,
              relayKey: relayKey || null,
              recoverResult
            });
          }
        }
      }
      if (!fileBuffer) {
        updateMetrics(false);
        return {
          statusCode: 404,
          headers: buildDriveErrorHeaders(),
          body: b4a.from(JSON.stringify({ error: 'File not found' }))
        };
      }

      // Determine content type from file extension
      let contentType = 'application/octet-stream';
      if (fileId.includes('.')) {
        const ext = fileId.split('.').pop().toLowerCase();
        const mimeTypes = {
          'jpg': 'image/jpeg',
          'jpeg': 'image/jpeg',
          'png': 'image/png',
          'gif': 'image/gif',
          'webp': 'image/webp',
          'svg': 'image/svg+xml',
          'html': 'text/html; charset=utf-8',
          'htm': 'text/html; charset=utf-8',
          'css': 'text/css; charset=utf-8',
          'js': 'text/javascript; charset=utf-8',
          'mjs': 'text/javascript; charset=utf-8',
          'json': 'application/json; charset=utf-8',
          'csv': 'text/csv; charset=utf-8',
          'md': 'text/markdown; charset=utf-8',
          'pdf': 'application/pdf',
          'txt': 'text/plain; charset=utf-8',
          'wav': 'audio/wav',
          'ogg': 'audio/ogg',
          'flac': 'audio/flac'
        };
        contentType = mimeTypes[ext] || contentType;
      }

      const successHeaders = buildDriveSuccessHeaders({
        contentType,
        contentLength: fileBuffer.length,
        fileHash: hash
      })
      if (isHtmlDriveRequest(fileId)) {
        console.log('[RelayServer] Drive HTML response headers', {
          identifier,
          fileId,
          statusCode: 200,
          headers: summarizeDriveHeaders(successHeaders)
        })
      }
      const ifNoneMatch = request?.headers?.['if-none-match'] || request?.headers?.['If-None-Match']
      if (etagMatches(ifNoneMatch, successHeaders.etag)) {
        updateMetrics(true);
        return {
          statusCode: 304,
          headers: buildDriveCorsHeaders(null, {
            etag: successHeaders.etag,
            'cache-control': successHeaders['cache-control'],
            'accept-ranges': successHeaders['accept-ranges'],
            'content-length': '0'
          }),
          body: b4a.from('')
        };
      }

      updateMetrics(true);
      return {
        statusCode: 200,
        headers: successHeaders,
        body: b4a.from(fileBuffer)
      };
    } catch (error) {
      console.error('[RelayServer] Error fetching drive file:', error);
      updateMetrics(false);
      return {
        statusCode: 500,
        headers: buildDriveErrorHeaders(),
        body: b4a.from(JSON.stringify({ error: error.message }))
      };
    }
  });

  async function handlePfpRequest(request, ownerParam = null) {
    const rawOwner = ownerParam || request.params.owner || null;
    const fileId = request.params.file;

    if (!fileId) {
      updateMetrics(false);
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Missing file identifier' }))
      };
    }

    try {
      const hash = fileId.split('.')[0];
      const ownerKey = rawOwner ? rawOwner.trim() : '';
      const fileBuffer = await getPfpFile(ownerKey, hash);

      if (!fileBuffer) {
        updateMetrics(false);
        return {
          statusCode: 404,
          headers: { 'content-type': 'application/json' },
          body: b4a.from(JSON.stringify({ error: 'Avatar not found' }))
        };
      }

      const ext = fileId.includes('.') ? fileId.split('.').pop().toLowerCase() : '';
      const mimeTypes = {
        jpg: 'image/jpeg',
        jpeg: 'image/jpeg',
        png: 'image/png',
        gif: 'image/gif',
        webp: 'image/webp'
      };
      const contentType = mimeTypes[ext] || 'application/octet-stream';

      updateMetrics(true);
      return {
        statusCode: 200,
        headers: {
          'content-type': contentType,
          'cache-control': 'public, max-age=60'
        },
        body: b4a.from(fileBuffer)
      };
    } catch (error) {
      console.error('[RelayServer] PFP handler error:', error);
      updateMetrics(false);
      return {
        statusCode: 500,
        headers: { 'content-type': 'application/json' },
        body: b4a.from(JSON.stringify({ error: 'Internal Server Error', message: error.message }))
      };
    }
  }

  protocol.handle('/pfp/:file', (request) => handlePfpRequest(request, null));
  protocol.handle('/pfp/:owner/:file', (request) => handlePfpRequest(request));
  
  console.log('[RelayServer] Protocol handlers setup complete');
}

// Helper function to publish member add event (kind 9000)
// role can be 'admin' when the creator is automatically authorized during relay creation
async function publishMemberAddEvent(identifier, pubkey, token, subnetHashes = [], role = 'member') {
  try {
    console.log(`[RelayServer] Publishing kind 9000 event for ${pubkey.substring(0, 8)}...`);
    const canonicalIdentifier = normalizeRelayIdentifier(identifier);

    // Create the event
    let event = {
      kind: 9000,
      content: `Adding user ${pubkey} with auth token`,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['h', canonicalIdentifier],
        ['p', pubkey, role, token, ...subnetHashes] // Spread all subnet hashes
      ],
      pubkey: config.nostr_pubkey_hex
    };
    
    // Use NostrUtils to sign the event, which also generates the ID
    event = await NostrUtils.signEvent(event, config.nostr_nsec_hex);
    
    // Publish to the relay
    await publishEventToRelay(canonicalIdentifier, event);
    
    console.log(`[RelayServer] Published kind 9000 event: ${event.id.substring(0, 8)}...`);
    
  } catch (error) {
    console.error(`[RelayServer] Error publishing member add event:`, error);
  }
}

function buildCreateRelayBootstrapDraftEvents({
  publicIdentifier,
  adminPubkey,
  name,
  description,
  isPublic,
  isOpen,
  fileSharing,
  relayWsUrl,
  picture,
  discoveryTopic = null,
  hostPeerKeys = [],
  writerIssuerPubkey = null,
  leaseReplicaPeerKeys = [],
  gatewayOrigin = null,
  gatewayId = null,
  directJoinOnly = false
}) {
  const canonicalIdentifier = normalizeRelayIdentifier(publicIdentifier);
  const now = Math.floor(Date.now() / 1000);
  const groupName = String(name || canonicalIdentifier || 'Untitled Group');
  const about = description ? String(description) : '';
  const fileSharingEnabled = fileSharing !== false;
  const pictureTag = typeof picture === 'string' && picture.trim() ? picture.trim() : null;
  const normalizedGatewayOrigin = normalizeHttpOrigin(gatewayOrigin);
  const normalizedGatewayId = normalizeGatewayId(gatewayId);
  const directJoinOnlyEnabled = directJoinOnly === true;

  const groupTags = [
    ['h', canonicalIdentifier],
    ['name', groupName],
    ['about', about],
    ['hyperpipe', canonicalIdentifier],
    ['i', HYPERPIPE_IDENTIFIER_TAG],
    [isPublic ? 'public' : 'private'],
    [isOpen ? 'open' : 'closed'],
    [fileSharingEnabled ? 'file-sharing-on' : 'file-sharing-off']
  ];
  if (pictureTag) groupTags.push(['picture', pictureTag, 'hyperpipe:drive:pfp']);

  const metadataTags = [
    ['d', canonicalIdentifier],
    ['h', canonicalIdentifier],
    ['name', groupName],
    ['about', about],
    ['hyperpipe', canonicalIdentifier],
    ['i', HYPERPIPE_IDENTIFIER_TAG],
    [isPublic ? 'public' : 'private'],
    [isOpen ? 'open' : 'closed'],
    [fileSharingEnabled ? 'file-sharing-on' : 'file-sharing-off']
  ];
  if (pictureTag) metadataTags.push(['picture', pictureTag, 'hyperpipe:drive:pfp']);
  if (normalizedGatewayId) metadataTags.push([HYPERPIPE_GATEWAY_ID_TAG, normalizedGatewayId]);
  if (normalizedGatewayOrigin) metadataTags.push([HYPERPIPE_GATEWAY_ORIGIN_TAG, normalizedGatewayOrigin]);
  if (directJoinOnlyEnabled) metadataTags.push([HYPERPIPE_DIRECT_JOIN_ONLY_TAG, '1']);

  if (isPublic && isOpen) {
    const topic = typeof discoveryTopic === 'string' && discoveryTopic.trim()
      ? discoveryTopic.trim()
      : deriveRelayDiscoveryTopic(canonicalIdentifier);
    if (topic) {
      metadataTags.push(['hyperpipe-topic', topic]);
    }

    const normalizedHostPeers = Array.from(
      new Set(
        (Array.isArray(hostPeerKeys) ? hostPeerKeys : [])
          .map((value) => normalizeHex64(value))
          .filter(Boolean)
      )
    );
    normalizedHostPeers.forEach((peerKey) => {
      metadataTags.push(['hyperpipe-host-peer', peerKey]);
    });

    const normalizedWriterIssuer = normalizeHex64(writerIssuerPubkey || adminPubkey || null);
    if (normalizedWriterIssuer) {
      metadataTags.push(['hyperpipe-writer-issuer', normalizedWriterIssuer]);
    }

    const normalizedLeaseReplicaPeers = Array.from(
      new Set(
        (Array.isArray(leaseReplicaPeerKeys) ? leaseReplicaPeerKeys : [])
          .map((value) => normalizeHex64(value))
          .filter(Boolean)
      )
    ).slice(0, 8);
    normalizedLeaseReplicaPeers.forEach((peerKey) => {
      metadataTags.push(['hyperpipe-lease-replica-peer', peerKey]);
    });
  }

  const adminTags = [
    ['h', canonicalIdentifier],
    ['d', canonicalIdentifier],
    ['hyperpipe', canonicalIdentifier],
    ['i', HYPERPIPE_IDENTIFIER_TAG],
    ['p', adminPubkey, 'admin']
  ];

  return [
    {
      kind: KIND_GROUP_CREATE,
      created_at: now,
      tags: groupTags,
      content: `Created group: ${groupName}`
    },
    {
      kind: KIND_GROUP_METADATA,
      created_at: now,
      tags: metadataTags,
      content: `Group metadata for: ${groupName}`
    },
    {
      kind: KIND_HYPERPIPE_RELAY,
      created_at: now,
      tags: [
        ['d', relayWsUrl],
        ['hyperpipe', canonicalIdentifier],
        ['h', canonicalIdentifier],
        ['i', HYPERPIPE_IDENTIFIER_TAG]
      ],
      content: `Hyperpipe relay for group: ${groupName}`
    },
    {
      kind: KIND_GROUP_ADMIN_LIST,
      created_at: now,
      tags: adminTags,
      content: `Admin list for group: ${groupName}`
    },
    {
      kind: KIND_GROUP_MEMBER_LIST,
      created_at: now,
      tags: adminTags,
      content: `Member list for group: ${groupName}`
    }
  ];
}

function isPublishAckSuccessful(message) {
  if (typeof message !== 'string') return true;
  const normalized = message.trim().toLowerCase();
  if (!normalized) return true;
  if (normalized.startsWith('ok')) return true;

  const failureIndicators = [
    'connection failure',
    'failed',
    'error',
    'timeout',
    'closed',
    'rejected',
    'not defined'
  ];
  return !failureIndicators.some((indicator) => normalized.includes(indicator));
}

async function publishEventToDiscoveryRelays(event, relayUrls = CREATE_RELAY_DISCOVERY_RELAYS) {
  const targets = Array.from(new Set(
    (Array.isArray(relayUrls) ? relayUrls : [])
      .map((relayUrl) => String(relayUrl || '').trim())
      .filter(Boolean)
  ));
  if (!targets.length) {
    return {
      ok: false,
      published: [],
      failed: []
    };
  }

  const pool = new SimplePool({
    enablePing: true,
    enableReconnect: true
  });

  try {
    const writes = pool.publish(targets, event, { maxWait: 12_000 });
    const settled = await Promise.allSettled(writes);
    const published = [];
    const failed = [];

    for (let index = 0; index < settled.length; index += 1) {
      const result = settled[index];
      const relayUrl = targets[index] || null;
      if (result?.status === 'fulfilled' && isPublishAckSuccessful(result?.value)) {
        published.push(relayUrl);
      } else {
        failed.push({
          relay: relayUrl,
          error:
            result?.status === 'fulfilled'
              ? String(result?.value || 'publish failed')
              : (result?.reason?.message || String(result?.reason || 'publish failed'))
        });
      }
    }

    return {
      ok: published.length > 0,
      published,
      failed
    };
  } finally {
    try {
      pool.destroy();
    } catch (_) {
      // noop
    }
  }
}

async function publishCreateRelayBootstrapEvents({
  relayKey,
  publicIdentifier,
  adminPubkey,
  name,
  description,
  isPublic,
  isOpen,
  fileSharing,
  picture,
  gatewayOrigin = null,
  gatewayId = null,
  directJoinOnly = false
}) {
  const canonicalIdentifier = normalizeRelayIdentifier(publicIdentifier || relayKey || '');
  if (!canonicalIdentifier) {
    return {
      ok: false,
      attempt: 0,
      published: [],
      error: 'missing relay identifier'
    };
  }
  if (!adminPubkey || !config.nostr_nsec_hex) {
    return {
      ok: false,
      attempt: 0,
      published: [],
      error: 'missing signer context for bootstrap publish'
    };
  }

  const relayWsUrl = `${buildGatewayWebsocketBase(config)}/${canonicalIdentifier.replace(':', '/')}`;
  const discoveryTopic = deriveRelayDiscoveryTopic(canonicalIdentifier);
  const hostPeerKeys = config?.swarmPublicKey ? [config.swarmPublicKey] : [];
  const writerIssuerPubkey = config?.nostr_pubkey_hex || adminPubkey || null;
  const drafts = buildCreateRelayBootstrapDraftEvents({
    publicIdentifier: canonicalIdentifier,
    adminPubkey,
    name,
    description,
    isPublic,
    isOpen,
    fileSharing,
    relayWsUrl,
    picture,
    gatewayOrigin,
    gatewayId,
    directJoinOnly,
    discoveryTopic,
    hostPeerKeys,
    writerIssuerPubkey,
    leaseReplicaPeerKeys: hostPeerKeys
  });

  let lastError = null;
  for (let attempt = 0; attempt < CREATE_RELAY_BOOTSTRAP_MAX_ATTEMPTS; attempt += 1) {
    try {
      const published = [];
      for (const draft of drafts) {
        const signed = await NostrUtils.signEvent(
          { ...draft, pubkey: adminPubkey },
          config.nostr_nsec_hex
        );
        await publishEventToRelay(canonicalIdentifier, signed);
        const discoveryPublish = await publishEventToDiscoveryRelays(signed);
        if (!discoveryPublish.ok) {
          const failureReason = discoveryPublish.failed
            .map((entry) => `${entry.relay || 'unknown'}:${entry.error}`)
            .join(', ') || 'no discovery relay accepted event';
          console.warn('[RelayServer] Discovery relay publish failed (continuing with local bootstrap)', {
            relayIdentifier: canonicalIdentifier,
            kind: signed.kind,
            error: failureReason
          });
        }
        published.push({ kind: signed.kind, id: signed.id });
      }
      return {
        ok: true,
        attempt: attempt + 1,
        relayIdentifier: canonicalIdentifier,
        relayWsUrl,
        published,
        error: null
      };
    } catch (error) {
      lastError = error;
      if (attempt < CREATE_RELAY_BOOTSTRAP_MAX_ATTEMPTS - 1) {
        await new Promise((resolve) => setTimeout(resolve, 350 * (attempt + 1)));
      }
    }
  }

  return {
    ok: false,
    attempt: CREATE_RELAY_BOOTSTRAP_MAX_ATTEMPTS,
    relayIdentifier: canonicalIdentifier,
    relayWsUrl,
    published: [],
    error: lastError?.message || String(lastError || 'bootstrap publish failed')
  };
}

async function isRelayAuthProtected(identifier) {
  try {
    const canonicalIdentifier = normalizeRelayIdentifier(identifier);
    // Check auth store first
    const authStore = getRelayAuthStore();
    let relayKey = await getRelayKeyFromPublicIdentifier(canonicalIdentifier) || canonicalIdentifier;
    
    const authorizedPubkeys = authStore.getAuthorizedPubkeys(relayKey);
    if (authorizedPubkeys.length > 0) {
      return true;
    }
    
    // Check profile configuration
    let profile = await getRelayProfileByKey(relayKey);
    if (!profile) {
      profile = await getRelayProfileByPublicIdentifier(canonicalIdentifier);
    }
    
    return profile?.auth_config?.requiresAuth || false;
  } catch (error) {
    console.error(`[RelayServer] Error checking auth status:`, error);
    return false;
  }
}

// Helper function to publish event to relay
async function publishEventToRelay(identifier, event) {
  try {
    const canonicalIdentifier = normalizeRelayIdentifier(identifier);
    if (event?.kind === KIND_GROUP_ADMIN_LIST || event?.kind === KIND_GROUP_MEMBER_LIST) {
      const taggedPubkeys = Array.from(new Set(
        (Array.isArray(event?.tags) ? event.tags : [])
          .filter((tag) => tag[0] === 'p' && typeof tag[1] === 'string' && tag[1].trim())
          .map((tag) => tag[1].trim().toLowerCase())
      )).sort();
      const adminTaggedPubkeys = Array.from(new Set(
        (Array.isArray(event?.tags) ? event.tags : [])
          .filter((tag) => (
            tag[0] === 'p' &&
            typeof tag[1] === 'string' &&
            tag[1].trim() &&
            tag.slice(2).some((value) => String(value || '').trim() === 'admin')
          ))
          .map((tag) => tag[1].trim().toLowerCase())
      )).sort();
      console.log('[RelayServer] Publishing group snapshot event', {
        relayIdentifier: canonicalIdentifier,
        kind: event.kind,
        eventId: event.id || null,
        createdAt: event.created_at || null,
        taggedPubkeysCount: taggedPubkeys.length,
        adminTaggedPubkeysCount: adminTaggedPubkeys.length,
        selfOnly: taggedPubkeys.length === 1,
        eventPubkey: normalizePubkeyHex(event.pubkey || null)
      });
    }
    console.log(`[RelayServer] Publishing event to relay ${canonicalIdentifier}:`, event);
    
    // Resolve public identifier to relay key if needed
    let relayKey = await getRelayKeyFromPublicIdentifier(canonicalIdentifier) || canonicalIdentifier;
    if (!/^[a-f0-9]{64}$/i.test(relayKey)) {
      throw new Error(`No relay found for identifier: ${canonicalIdentifier}`);
    }
    
    // Get the relay manager from activeRelays (imported from adapter)
    const { activeRelays } = await import('./hyperpipe-relay-manager-adapter.mjs');
    const relayManager = activeRelays.get(relayKey);
    
    if (!relayManager) {
      throw new Error(`Relay manager not found for key: ${relayKey}`);
    }
    
    // Publish the event
    const result = await relayManager.publishEvent(event);
    console.log(`[RelayServer] Event published successfully:`, result);
    
    return result;
  } catch (error) {
    console.error(`[RelayServer] Error publishing event to relay:`, error);
    throw error;
  }
}

function normalizeWriterKey(writerKey) {
  if (!writerKey) return null;
  if (b4a.isBuffer(writerKey)) return writerKey;
  if (typeof writerKey !== 'string') return null;
  try {
    return HypercoreId.decode(writerKey);
  } catch (_) {
    if (/^[0-9a-fA-F]{64}$/.test(writerKey)) {
      return Buffer.from(writerKey, 'hex');
    }
  }
  return null;
}

function resolveExpectedWriterKey({ writerCoreHex = null, autobaseLocal = null, writerCore = null } = {}) {
  if (writerCoreHex) {
    return { expectedWriterKey: writerCoreHex, source: 'writerCoreHex' };
  }
  if (autobaseLocal) {
    return { expectedWriterKey: autobaseLocal, source: 'autobaseLocal' };
  }
  if (writerCore) {
    return { expectedWriterKey: writerCore, source: 'writerCore' };
  }
  return { expectedWriterKey: null, source: null };
}

function resolveWriterKeyHex(candidate) {
  const normalized = normalizeWriterKey(candidate);
  return normalized ? b4a.toString(normalized, 'hex') : null;
}

function deriveCoreKeyFromSignerKey(signerKey, manifestVersion = 0) {
  if (!signerKey) {
    return { key: null, error: null };
  }
  try {
    const key = Hypercore.key(signerKey, {
      compat: false,
      version: manifestVersion,
      namespace: DEFAULT_NAMESPACE
    });
    return { key, error: null };
  } catch (error) {
    return { key: null, error };
  }
}

function normalizeCoreRefString(candidate) {
  const normalized = normalizeWriterKey(candidate);
  if (!normalized) return null;
  try {
    return HypercoreId.encode(normalized);
  } catch (_) {
    return null;
  }
}

function previewWriterKey(writerKey) {
  if (!writerKey) return null;
  try {
    return b4a.toString(writerKey, 'hex').slice(0, 16);
  } catch (_) {
    return null;
  }
}

function sampleActiveWriterKeys(relay, limit = 4) {
  const writers = relay?.activeWriters;
  if (!writers || typeof writers[Symbol.iterator] !== 'function') {
    return [];
  }
  const sample = [];
  for (const writer of writers) {
    const key = writer?.core?.key || writer?.key || writer;
    if (key && b4a.isBuffer(key)) {
      sample.push(b4a.toString(key, 'hex').slice(0, 16));
    }
    if (sample.length >= limit) break;
  }
  return sample;
}

function normalizeWriterLeaseId(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function collectActiveWriterCoreRefs(relay) {
  const writers = relay?.activeWriters;
  if (!writers || typeof writers[Symbol.iterator] !== 'function') {
    return [];
  }
  const refs = [];
  const seen = new Set();
  for (const writer of writers) {
    const keyCandidate = writer?.core?.key || writer?.key || writer;
    const normalized = normalizeCoreRef(keyCandidate);
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    refs.push(normalized);
  }
  refs.sort();
  return refs;
}

function normalizeWriterCommitCheckpoint(input = null) {
  if (!input || typeof input !== 'object') return null;
  const systemKey = normalizeCoreRef(input.systemKey || input.system_key || null);
  const writerCore = normalizeCoreRef(input.writerCore || input.writer_core || null);
  const activeWritersHash = typeof input.activeWritersHash === 'string'
    ? input.activeWritersHash
    : (typeof input.active_writers_hash === 'string' ? input.active_writers_hash : null);
  const activeWritersCountRaw =
    Number.isFinite(input.activeWritersCount)
      ? Number(input.activeWritersCount)
      : Number.isFinite(input.active_writers_count)
        ? Number(input.active_writers_count)
        : null;
  const systemSignedLengthRaw =
    Number.isFinite(input.systemSignedLength)
      ? Number(input.systemSignedLength)
      : Number.isFinite(input.system_signed_length)
        ? Number(input.system_signed_length)
        : null;
  const systemLengthRaw =
    Number.isFinite(input.systemLength)
      ? Number(input.systemLength)
      : Number.isFinite(input.system_length)
        ? Number(input.system_length)
        : null;
  const viewVersionRaw =
    Number.isFinite(input.viewVersion)
      ? Number(input.viewVersion)
      : Number.isFinite(input.view_version)
        ? Number(input.view_version)
        : null;
  const recordedAtRaw =
    Number.isFinite(input.recordedAt)
      ? Number(input.recordedAt)
      : Number.isFinite(input.recorded_at)
        ? Number(input.recorded_at)
        : null;
  const checkpoint = {
    relayKey: normalizeRelayKeyHex(input.relayKey || input.relay_key || null) || null,
    systemKey: systemKey || null,
    systemLength: Number.isFinite(systemLengthRaw) ? Math.trunc(systemLengthRaw) : null,
    systemSignedLength: Number.isFinite(systemSignedLengthRaw) ? Math.trunc(systemSignedLengthRaw) : null,
    viewVersion: Number.isFinite(viewVersionRaw) ? Math.trunc(viewVersionRaw) : null,
    activeWritersHash: activeWritersHash || null,
    activeWritersCount: Number.isFinite(activeWritersCountRaw) ? Math.max(0, Math.trunc(activeWritersCountRaw)) : null,
    writerCore: writerCore || null,
    recordedAt: Number.isFinite(recordedAtRaw) ? Math.trunc(recordedAtRaw) : null
  };
  if (
    !checkpoint.systemKey
    && checkpoint.systemLength === null
    && checkpoint.systemSignedLength === null
    && checkpoint.viewVersion === null
    && !checkpoint.activeWritersHash
    && checkpoint.activeWritersCount === null
    && !checkpoint.writerCore
  ) {
    return null;
  }
  return checkpoint;
}

function summarizeWriterCommitCheckpoint(checkpoint = null) {
  const normalized = normalizeWriterCommitCheckpoint(checkpoint);
  if (!normalized) {
    return {
      hasCheckpoint: false
    };
  }
  return {
    hasCheckpoint: true,
    relayKey: normalized.relayKey ? normalized.relayKey.slice(0, 16) : null,
    systemKey: normalized.systemKey ? normalized.systemKey.slice(0, 16) : null,
    systemLength: normalized.systemLength,
    systemSignedLength: normalized.systemSignedLength,
    viewVersion: normalized.viewVersion,
    activeWritersCount: normalized.activeWritersCount,
    activeWritersHash: normalized.activeWritersHash ? normalized.activeWritersHash.slice(0, 16) : null,
    writerCore: normalized.writerCore ? normalized.writerCore.slice(0, 16) : null,
    recordedAt: normalized.recordedAt
  };
}

function buildWriterCommitCheckpoint(relay, {
  relayKey = null,
  writerCore = null
} = {}) {
  if (!relay) return null;
  const systemCore = relay?.system?.core || null;
  const systemKey = normalizeCoreRef(systemCore?.key || null);
  const activeWriterRefs = collectActiveWriterCoreRefs(relay);
  const activeWritersHash = activeWriterRefs.length
    ? sha256Hex(JSON.stringify(activeWriterRefs))
    : null;
  const checkpoint = {
    relayKey: normalizeRelayKeyHex(relayKey) || null,
    systemKey: systemKey || null,
    systemLength: Number.isFinite(systemCore?.length) ? Math.trunc(systemCore.length) : null,
    systemSignedLength: Number.isFinite(systemCore?.signedLength) ? Math.trunc(systemCore.signedLength) : null,
    viewVersion: Number.isFinite(relay?.view?.version) ? Math.trunc(relay.view.version) : null,
    activeWritersHash,
    activeWritersCount: activeWriterRefs.length,
    writerCore: normalizeCoreRef(writerCore),
    recordedAt: Date.now()
  };
  return normalizeWriterCommitCheckpoint(checkpoint);
}

function collectRelayUpdateStats(relay) {
  if (!relay) {
    return { hasRelay: false };
  }

  const view = relay.view || null;
  const viewCore = view?.core || null;
  const local = relay.local || null;

  return {
    hasRelay: true,
    writable: relay.writable ?? null,
    activeWriters: relay.activeWriters?.size ?? null,
    writerSample: sampleActiveWriterKeys(relay),
    viewVersion: typeof view?.version === 'number' ? view.version : null,
    viewLength: typeof view?.length === 'number' ? view.length : null,
    viewCoreLength: typeof viewCore?.length === 'number' ? viewCore.length : null,
    viewCoreByteLength: typeof viewCore?.byteLength === 'number' ? viewCore.byteLength : null,
    viewKey: viewCore?.key ? b4a.toString(viewCore.key, 'hex').slice(0, 16) : null,
    localLength: typeof local?.length === 'number' ? local.length : null,
    localByteLength: typeof local?.byteLength === 'number' ? local.byteLength : null,
    localKey: local?.key ? b4a.toString(local.key, 'hex').slice(0, 16) : null
  };
}

function collectRelayProgressSnapshot(relay) {
  if (!relay) {
    return { hasRelay: false };
  }

  const resolveCore = (candidate) => {
    if (!candidate) return null;
    if (candidate?.core) return candidate.core;
    return candidate;
  };

  const decodeCoreRef = (ref) => {
    if (!ref) return null;
    if (Buffer.isBuffer(ref)) return Buffer.from(ref);
    if (ref instanceof Uint8Array) return Buffer.from(ref);
    const trimmed = String(ref).trim();
    if (!trimmed) return null;
    if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return Buffer.from(trimmed, 'hex');
    }
    try {
      const decoded = HypercoreId.decode(trimmed);
      if (decoded && decoded.length === 32) {
        return Buffer.from(decoded);
      }
    } catch (_) {
      // ignore
    }
    return null;
  };

  const toList = (candidate) => {
    if (!candidate) return [];
    if (Array.isArray(candidate)) return candidate;
    if (candidate[Symbol.iterator]) return Array.from(candidate);
    return [];
  };

  const getPeerCount = (core) => {
    if (!core) return null;
    if (typeof core.peerCount === 'number') return core.peerCount;
    if (Array.isArray(core.peers)) return core.peers.length;
    if (typeof core.peers?.size === 'number') return core.peers.size;
    return null;
  };

  const getRemoteLength = (core) => {
    if (!core) return null;
    if (typeof core.remoteLength === 'number') return core.remoteLength;
    if (!core.peers) return null;
    const peers = Array.isArray(core.peers)
      ? core.peers
      : core.peers[Symbol.iterator]
        ? Array.from(core.peers)
        : [];
    let max = null;
    for (const peer of peers) {
      const value = typeof peer?.remoteLength === 'number' ? peer.remoteLength : null;
      if (value === null) continue;
      max = max === null ? value : Math.max(max, value);
    }
    return max;
  };

  const summarizeCore = (core) => {
    if (!core) return null;
    return {
      key: core.key ? b4a.toString(core.key, 'hex').slice(0, 16) : null,
      length: typeof core.length === 'number' ? core.length : null,
      contiguousLength: typeof core.contiguousLength === 'number' ? core.contiguousLength : null,
      remoteLength: getRemoteLength(core),
      byteLength: typeof core.byteLength === 'number' ? core.byteLength : null,
      fork: typeof core.fork === 'number' ? core.fork : null,
      peers: getPeerCount(core)
    };
  };

  const summarizeCoreList = (cores, previewCount = 6) => {
    const stats = {
      count: cores.length,
      minLength: null,
      maxLength: null,
      minContiguousLength: null,
      maxContiguousLength: null,
      minRemoteLength: null,
      maxRemoteLength: null,
      minByteLength: null,
      maxByteLength: null,
      minFork: null,
      maxFork: null,
      keysPreview: [],
      slowest: null
    };
    if (!cores.length) return stats;
    const chooseSlowest = (current, candidate) => {
      if (!candidate) return current;
      if (!current) return candidate;
      const cContig = candidate.contiguousLength;
      const pContig = current.contiguousLength;
      if (typeof cContig === 'number' && typeof pContig === 'number') {
        if (cContig !== pContig) return cContig < pContig ? candidate : current;
      } else if (typeof cContig === 'number' && typeof pContig !== 'number') {
        return candidate;
      } else if (typeof cContig !== 'number' && typeof pContig === 'number') {
        return current;
      }
      const cLen = candidate.length;
      const pLen = current.length;
      if (typeof cLen === 'number' && typeof pLen === 'number') {
        if (cLen !== pLen) return cLen < pLen ? candidate : current;
      } else if (typeof cLen === 'number' && typeof pLen !== 'number') {
        return candidate;
      } else if (typeof cLen !== 'number' && typeof pLen === 'number') {
        return current;
      }
      const cRemote = candidate.remoteLength;
      const pRemote = current.remoteLength;
      if (typeof cRemote === 'number' && typeof pRemote === 'number') {
        if (cRemote !== pRemote) return cRemote < pRemote ? candidate : current;
      }
      return current;
    };
    for (const core of cores) {
      const summary = summarizeCore(core);
      if (!summary) continue;
      if (summary.key && stats.keysPreview.length < previewCount) {
        stats.keysPreview.push(summary.key);
      }
      const applyRange = (value, minKey, maxKey) => {
        if (typeof value !== 'number') return;
        stats[minKey] = stats[minKey] === null ? value : Math.min(stats[minKey], value);
        stats[maxKey] = stats[maxKey] === null ? value : Math.max(stats[maxKey], value);
      };
      applyRange(summary.length, 'minLength', 'maxLength');
      applyRange(summary.contiguousLength, 'minContiguousLength', 'maxContiguousLength');
      applyRange(summary.remoteLength, 'minRemoteLength', 'maxRemoteLength');
      applyRange(summary.byteLength, 'minByteLength', 'maxByteLength');
      applyRange(summary.fork, 'minFork', 'maxFork');
      stats.slowest = chooseSlowest(stats.slowest, summary);
    }
    return stats;
  };

  const viewCore = resolveCore(relay?.view?.core || null);
  const localCore = resolveCore(relay?.local || relay?.localInput || relay?.localWriter || relay?.defaultWriter || null);
  const autobaseCore = resolveCore(relay?.core || null);
  const writerRefs = [];
  const writerRefSet = new Set();
  const coreRefEntries = collectRelayCoreRefsFromAutobase(relay);
  for (const entry of coreRefEntries) {
    const role = entry?.role || '';
    if (!role || !role.startsWith('autobase-writer')) continue;
    const ref = entry?.key || null;
    if (!ref) continue;
    const key = typeof ref === 'string' ? ref : Buffer.isBuffer(ref) || ref instanceof Uint8Array ? b4a.toString(ref, 'hex') : null;
    const dedupe = key || ref;
    if (dedupe && writerRefSet.has(dedupe)) continue;
    if (dedupe) writerRefSet.add(dedupe);
    writerRefs.push(ref);
  }

  const relayCorestore = relay?.corestore || relay?.store || relay?.session?.corestore || relay?.session?.store || null;
  const writerCores = [];
  if (relayCorestore && typeof relayCorestore.get === 'function') {
    for (const ref of writerRefs) {
      const keyBuffer = decodeCoreRef(ref);
      if (!keyBuffer) continue;
      try {
        const core = relayCorestore.get({ key: keyBuffer });
        if (core) writerCores.push(core);
      } catch (_) {
        // ignore
      }
    }
  }

  const viewSummary = summarizeCore(viewCore);
  const localSummary = summarizeCore(localCore);
  const autobaseSummary = summarizeCore(autobaseCore);
  const writersSummary = summarizeCoreList(writerCores);
  const writerRefsPreview = writerRefs.slice(0, 8).map((ref) => {
    if (typeof ref === 'string') return ref.slice(0, 16);
    if (Buffer.isBuffer(ref) || ref instanceof Uint8Array) return b4a.toString(ref, 'hex').slice(0, 16);
    return null;
  }).filter(Boolean);
  writersSummary.refsCount = writerRefs.length;
  writersSummary.refsPreview = writerRefsPreview;
  writersSummary.resolved = writerCores.length;
  writersSummary.keysPreviewText = writersSummary.keysPreview.length
    ? JSON.stringify(writersSummary.keysPreview)
    : '[]';
  writersSummary.refsPreviewText = writerRefsPreview.length
    ? JSON.stringify(writerRefsPreview)
    : '[]';
  writersSummary.slowestText = writersSummary.slowest
    ? JSON.stringify(writersSummary.slowest)
    : 'null';

  return {
    hasRelay: true,
    writable: relay?.writable ?? null,
    activeWriters: relay?.activeWriters?.size ?? null,
    view: viewSummary,
    local: localSummary,
    autobase: autobaseSummary,
    writers: writersSummary
  };
}

function maxNumber(values = []) {
  const numeric = values.filter((value) => typeof value === 'number' && Number.isFinite(value));
  if (!numeric.length) return null;
  return Math.max(...numeric);
}

function minNumber(values = []) {
  const numeric = values.filter((value) => typeof value === 'number' && Number.isFinite(value));
  if (!numeric.length) return null;
  return Math.min(...numeric);
}

function isRelayProgressSyncReady(snapshot) {
  if (!snapshot || snapshot.hasRelay !== true) return false;
  if (snapshot.writable !== true) return false;

  const view = snapshot.view || {};
  const writers = snapshot.writers || {};

  const writerScopeKnown =
    (typeof writers.refsCount === 'number' && writers.refsCount > 0) ||
    (typeof writers.count === 'number' && writers.count > 0) ||
    (typeof snapshot.activeWriters === 'number' && snapshot.activeWriters > 0);
  if (!writerScopeKnown) return false;

  const targetLength = maxNumber([
    view.remoteLength,
    view.length,
    writers.maxRemoteLength,
    writers.maxLength,
    writers.maxContiguousLength
  ]);
  if (targetLength == null) return false;

  const currentProgress = minNumber([
    minNumber([view.contiguousLength, view.length]),
    minNumber([writers.minContiguousLength, writers.minLength])
  ]);
  if (currentProgress == null) return false;

  return currentProgress >= targetLength;
}

function summarizeSubscriptionReplayFrames(frames, relaySyncReady) {
  if (!Array.isArray(frames)) return [];
  const bySubscription = new Map();
  for (const frame of frames) {
    if (!Array.isArray(frame) || frame.length < 2) continue;
    const frameType = frame[0];
    const subscriptionId = typeof frame[1] === 'string' ? frame[1] : null;
    if (!subscriptionId) continue;
    if (!bySubscription.has(subscriptionId)) {
      bySubscription.set(subscriptionId, {
        subscriptionId,
        eventCount: 0,
        eoseSeen: false
      });
    }
    const summary = bySubscription.get(subscriptionId);
    if (frameType === 'EVENT') {
      summary.eventCount += 1;
    } else if (frameType === 'EOSE') {
      summary.eoseSeen = true;
    }
  }

  return Array.from(bySubscription.values()).map((summary) => ({
    ...summary,
    isTimelineGroup: summary.subscriptionId.startsWith('f-timeline-group-'),
    relaySyncReady
  }));
}

function prehydrateRelayCoreRefs({ relay, coreRefs, writerRefsHint = [], relayKey, reason, context } = {}) {
  const relayCorestore = relay?.corestore
    || relay?.store
    || relay?.session?.corestore
    || relay?.session?.store
    || null;
  if (!relayCorestore || typeof relayCorestore.get !== 'function') {
    console.warn('[RelayServer] Prehydrate core refs skipped (corestore unavailable)', {
      relayKey,
      reason,
      context
    });
    return { ok: false, reason: 'missing-corestore' };
  }

  const autobaseEntries = collectRelayCoreRefsFromAutobase(relay);
  const autobaseRefs = normalizeCoreRefList(autobaseEntries);
  const inputRefs = normalizeCoreRefList(coreRefs || []);
  const writerHintRefs = normalizeCoreRefList(writerRefsHint || []);
  const mergedRefs = mergeCoreRefLists(autobaseRefs, inputRefs, writerHintRefs);
  const writerEntries = autobaseEntries.filter((entry) => entry?.role && entry.role.startsWith('autobase-writer'));
  const writerRefs = mergeCoreRefLists(normalizeCoreRefList(writerEntries), writerHintRefs);

  let opened = 0;
  let errors = 0;
  const preview = [];
  for (const ref of mergedRefs) {
    const keyBuffer = decodeCoreRef(ref);
    if (!keyBuffer) continue;
    try {
      const core = relayCorestore.get({ key: keyBuffer });
      opened += 1;
      if (core?.key && preview.length < 8) {
        preview.push(b4a.toString(core.key, 'hex').slice(0, 16));
      }
      if (typeof core?.ready === 'function') {
        core.ready().catch(() => {});
      }
    } catch (_) {
      errors += 1;
    }
  }

  const summary = {
    ok: true,
    relayKey,
    reason,
    context,
    mergedCount: mergedRefs.length,
    autobaseCount: autobaseRefs.length,
    inputCount: inputRefs.length,
    writerCount: writerRefs.length,
    writerHintCount: writerHintRefs.length,
    opened,
    errors,
    openedPreview: preview
  };

  console.log('[RelayServer] Prehydrated core refs', summary);
  return summary;
}

function collectRelayGateSnapshot(relay) {
  if (!relay) return { hasRelay: false };
  const viewCore = relay?.view?.core || null;
  const peerCount = typeof viewCore?.peerCount === 'number'
    ? viewCore.peerCount
    : Array.isArray(viewCore?.peers)
      ? viewCore.peers.length
      : typeof viewCore?.peers?.size === 'number'
        ? viewCore.peers.size
        : null;
  const activeWriters = relay?.activeWriters;
  const activeWritersCount = typeof activeWriters?.size === 'number'
    ? activeWriters.size
    : Array.isArray(activeWriters)
      ? activeWriters.length
      : null;
  return {
    hasRelay: true,
    writable: relay?.writable ?? null,
    viewLength: typeof viewCore?.length === 'number' ? viewCore.length : null,
    viewKey: viewCore?.key ? b4a.toString(viewCore.key, 'hex').slice(0, 16) : null,
    peerCount,
    activeWriters: activeWritersCount
  };
}

function resolveRelaySyncGateReason(initial, current) {
  if (!current) return null;
  if (typeof current.peerCount === 'number' && current.peerCount > 0) return 'peer';
  if (
    typeof current.viewLength === 'number'
    && typeof initial?.viewLength === 'number'
    && current.viewLength > initial.viewLength
  ) return 'view-advanced';
  if (typeof current.activeWriters === 'number' && current.activeWriters >= 2) return 'writers';
  if (initial?.viewLength == null && typeof current.viewLength === 'number') return 'view-available';
  return null;
}

const relayViewCoreSnapshots = new WeakMap();
const relayWriterRefSnapshots = new WeakMap();

function collectViewCoreIdentity(relay) {
  const viewCore = relay?.view?.core || null;
  const keyBuffer = viewCore?.key || null;
  const keyHex = keyBuffer ? b4a.toString(keyBuffer, 'hex') : null;
  const peerCount = typeof viewCore?.peerCount === 'number'
    ? viewCore.peerCount
    : Array.isArray(viewCore?.peers)
      ? viewCore.peers.length
      : typeof viewCore?.peers?.size === 'number'
        ? viewCore.peers.size
        : null;
  return {
    keyHex,
    keyShort: keyHex ? keyHex.slice(0, 16) : null,
    coreRef: keyBuffer ? normalizeCoreRef(keyBuffer) : null,
    length: typeof viewCore?.length === 'number' ? viewCore.length : null,
    contiguousLength: typeof viewCore?.contiguousLength === 'number' ? viewCore.contiguousLength : null,
    byteLength: typeof viewCore?.byteLength === 'number' ? viewCore.byteLength : null,
    fork: typeof viewCore?.fork === 'number' ? viewCore.fork : null,
    peerCount
  };
}

function collectCoreRefRoles(relay) {
  const entries = collectRelayCoreRefsFromAutobase(relay);
  const roleMap = new Map();
  const viewCandidates = [];

  for (const entry of entries) {
    const key = entry?.key || null;
    if (!key) continue;
    const role = entry?.role || null;
    let roles = roleMap.get(key);
    if (!roles) {
      roles = new Set();
      roleMap.set(key, roles);
    }
    if (role) {
      roles.add(role);
      if (role === 'autobase-view' || role.startsWith('autobase-view-')) {
        viewCandidates.push({ key: key.slice(0, 16), role });
      }
    }
  }

  return {
    roleMap,
    viewCandidates,
    coreRefsCount: entries.length
  };
}

function collectWriterRefRoles(relay) {
  const entries = collectRelayCoreRefsFromAutobase(relay);
  const roleMap = new Map();
  for (const entry of entries) {
    const role = entry?.role || '';
    if (!role || !role.startsWith('autobase-writer')) continue;
    const key = normalizeCoreRef(entry?.key);
    if (!key) continue;
    const roles = roleMap.get(key);
    if (roles) {
      roles.add(role);
    } else {
      roleMap.set(key, new Set([role]));
    }
  }
  const writerRefs = Array.from(roleMap.keys());
  return { writerRefs, roleMap };
}

function logRelayViewCoreIdentity(relay, { relayKey, reason, context, force = false } = {}) {
  if (!relay) return;
  const current = collectViewCoreIdentity(relay);
  const previous = relayViewCoreSnapshots.get(relay) || null;
  const changed = !previous || previous.keyHex !== current.keyHex;
  if (!changed && !force) return;

  const { roleMap, viewCandidates, coreRefsCount } = collectCoreRefRoles(relay);
  const roles = current.coreRef ? Array.from(roleMap.get(current.coreRef) || []) : [];
  const previousRoles = previous?.coreRef ? Array.from(roleMap.get(previous.coreRef) || []) : [];

  console.log('[RelayServer] View core identity', {
    relayKey,
    reason,
    context,
    changed,
    previous: previous
      ? {
        keyShort: previous.keyShort,
        coreRef: previous.coreRef ? previous.coreRef.slice(0, 16) : null,
        roles: previousRoles,
        length: previous.length,
        byteLength: previous.byteLength,
        contiguousLength: previous.contiguousLength,
        peerCount: previous.peerCount,
        fork: previous.fork
      }
      : null,
    current: {
      keyShort: current.keyShort,
      coreRef: current.coreRef ? current.coreRef.slice(0, 16) : null,
      roles,
      length: current.length,
      byteLength: current.byteLength,
      contiguousLength: current.contiguousLength,
      peerCount: current.peerCount,
      fork: current.fork
    },
    coreRefsCount,
    viewCandidates: viewCandidates.length <= 10 ? viewCandidates : viewCandidates.slice(0, 10)
  });

  relayViewCoreSnapshots.set(relay, { ...current, roles });
}

function startRelayUpdateProgressLogger({ relay, relayKey, reason, intervalMs = 5000, coreRefs = null, expectedWriterKey = null }) {
  if (!relay) return () => {};
  const start = Date.now();
  const normalizedInputRefs = normalizeCoreRefList(coreRefs || []);
  const expectedWriterRef = expectedWriterKey ? normalizeCoreRef(expectedWriterKey) || normalizeCoreRefString(expectedWriterKey) : null;
  const baseline = { view: null };
  const previous = { view: null };

  const summarizeView = (view) => ({
    key: view?.key || null,
    length: typeof view?.length === 'number' ? view.length : null,
    contiguousLength: typeof view?.contiguousLength === 'number' ? view.contiguousLength : null,
    remoteLength: typeof view?.remoteLength === 'number' ? view.remoteLength : null,
    byteLength: typeof view?.byteLength === 'number' ? view.byteLength : null,
    fork: typeof view?.fork === 'number' ? view.fork : null,
    peers: typeof view?.peers === 'number' ? view.peers : null
  });

  const logViewDelta = (stats, context) => {
    const view = stats?.view || null;
    if (!view) return;
    const current = summarizeView(view);
    if (!baseline.view) baseline.view = current;
    if (!previous.view) previous.view = current;

    const changed =
      current.length !== previous.view.length ||
      current.contiguousLength !== previous.view.contiguousLength ||
      current.remoteLength !== previous.view.remoteLength ||
      current.byteLength !== previous.view.byteLength ||
      current.fork !== previous.view.fork ||
      current.peers !== previous.view.peers;

    if (!changed) return;

    const delta = {
      length: (typeof current.length === 'number' && typeof baseline.view.length === 'number')
        ? current.length - baseline.view.length
        : null,
      contiguousLength: (typeof current.contiguousLength === 'number' && typeof baseline.view.contiguousLength === 'number')
        ? current.contiguousLength - baseline.view.contiguousLength
        : null,
      remoteLength: (typeof current.remoteLength === 'number' && typeof baseline.view.remoteLength === 'number')
        ? current.remoteLength - baseline.view.remoteLength
        : null,
      byteLength: (typeof current.byteLength === 'number' && typeof baseline.view.byteLength === 'number')
        ? current.byteLength - baseline.view.byteLength
        : null
    };

    console.log('[RelayServer] View length delta', {
      relayKey,
      reason,
      context,
      elapsedMs: Date.now() - start,
      baseline: baseline.view,
      previous: previous.view,
      current,
      delta
    });

    previous.view = current;
  };

  const logSnapshot = (context) => {
    logRelayViewCoreIdentity(relay, { relayKey, reason, context });
    const { writerRefs, roleMap } = collectWriterRefRoles(relay);
    const previous = relayWriterRefSnapshots.get(relay) || { count: 0, refs: [] };
    const countChanged = writerRefs.length !== previous.count;
    const becameVisible = previous.count === 0 && writerRefs.length > 0;
    if (countChanged) {
      relayWriterRefSnapshots.set(relay, { count: writerRefs.length, refs: writerRefs });
    }
    if (becameVisible || (countChanged && writerRefs.length > previous.count)) {
      const inInput = normalizedInputRefs.length
        ? writerRefs.filter((ref) => normalizedInputRefs.includes(ref))
        : [];
      const expectedMatch = expectedWriterRef ? writerRefs.includes(expectedWriterRef) : false;
      const source = inInput.length
        ? 'coreRefs'
        : expectedMatch
          ? 'expected-writer'
          : 'autobase';
      const writerPreview = writerRefs.slice(0, 5).map((ref) => ref.slice(0, 16));
      const rolesPreview = writerRefs.slice(0, 5).map((ref) => ({
        key: ref.slice(0, 16),
        roles: Array.from(roleMap.get(ref) || [])
      }));
      console.log('[RelayServer] Writer refs became visible', {
        relayKey,
        reason,
        context,
        count: writerRefs.length,
        added: writerRefs.length - previous.count,
        source,
        inputRefsCount: normalizedInputRefs.length,
        inInputCount: inInput.length,
        expectedWriterMatch: expectedMatch,
        writerPreview,
        rolesPreview
      });
    }
    const stats = collectRelayProgressSnapshot(relay);
    logViewDelta(stats, context);
    console.log('[RelayServer] Relay update wait progress', {
      relayKey,
      reason,
      context,
      elapsedMs: Date.now() - start,
      stats
    });
  };

  logSnapshot('start');
  const interval = setInterval(() => logSnapshot('tick'), intervalMs);
  interval.unref?.();
  return () => {
    clearInterval(interval);
    logSnapshot('end');
  };
}

function emitJoinCheckpointTrace(phase, data = {}) {
  const payload = {
    phase,
    ts: Date.now(),
    ...(data && typeof data === 'object' ? data : {})
  };
  console.log('[RelayServer][JoinCheckpoint]', payload);
  try {
    if (global.sendMessage) {
      global.sendMessage({
        type: 'JOIN_CHECKPOINT_TRACE',
        data: payload
      });
    }
  } catch (_) {}
}

function emitWriterActivationPrewaitTrace({
  relayKey = null,
  publicIdentifier = null,
  mode = null,
  reason = null,
  expectedWriterKey = null,
  joinTraceId = null,
  joinAttemptId = null,
  joinRequestId = null,
  writerLeaseId = null,
  writerCommitCheckpoint = null,
  fastForward = null
} = {}) {
  const relay = relayKey ? activeRelays.get(relayKey)?.relay || null : null;
  const normalizedLeaseId = normalizeWriterLeaseId(writerLeaseId);
  const checkpointSummary = summarizeWriterCommitCheckpoint(writerCommitCheckpoint);
  const fastForwardKey = normalizeCoreRef(fastForward?.key || fastForward?.checkpointKey || null);
  const fastForwardSignedLength = Number.isFinite(fastForward?.signedLength)
    ? Math.trunc(fastForward.signedLength)
    : (Number.isFinite(fastForward?.length) ? Math.trunc(fastForward.length) : null);
  const gate = collectRelayGateSnapshot(relay);
  const progress = collectRelayProgressSnapshot(relay);
  emitJoinCheckpointTrace('writer-activation-prewait', {
    joinTraceId: typeof joinTraceId === 'string' ? joinTraceId : null,
    joinAttemptId: typeof joinAttemptId === 'string' ? joinAttemptId : null,
    joinRequestId: typeof joinRequestId === 'string' ? joinRequestId : null,
    relayKey,
    publicIdentifier,
    mode,
    reason,
    expectedWriter: previewWriterKey(normalizeWriterKey(expectedWriterKey)),
    writerLeaseId: normalizedLeaseId,
    writerCommitCheckpoint: checkpointSummary,
    fastForwardKey: fastForwardKey ? fastForwardKey.slice(0, 16) : null,
    fastForwardSignedLength,
    gate,
    progress: {
      writable: progress?.writable ?? null,
      activeWriters: progress?.activeWriters ?? null,
      view: progress?.view || null,
      local: progress?.local || null,
      writers: progress?.writers || null
    }
  });
}

function classifyWriterActivationBlock(snapshot = {}) {
  if (!snapshot || typeof snapshot !== 'object') return 'unknown';
  if (snapshot.writable === true) return 'none';
  if (snapshot.expectedWriter && snapshot.expectedWriterActive === false) {
    if (snapshot.localKey && snapshot.localKey === snapshot.expectedWriter) {
      return 'local-writer-not-active';
    }
    return 'expected-writer-not-active';
  }
  if (typeof snapshot.activeWriters === 'number' && snapshot.activeWriters <= 0) {
    return 'no-active-writers';
  }
  if (snapshot.localKey && Array.isArray(snapshot.writerSample) && !snapshot.writerSample.includes(snapshot.localKey)) {
    return 'local-writer-missing-from-active-set';
  }
  return 'unknown';
}

function summarizeWriterActivationDiagnostics(relay, snapshot = {}) {
  const gateSnapshot = collectRelayGateSnapshot(relay);
  const progress = collectRelayProgressSnapshot(relay);
  return {
    blockReason: classifyWriterActivationBlock(snapshot),
    gate: gateSnapshot,
    progress: {
      writable: progress?.writable ?? null,
      activeWriters: progress?.activeWriters ?? null,
      view: progress?.view || null,
      local: progress?.local || null,
      autobase: progress?.autobase || null,
      writers: progress?.writers || null
    }
  };
}

async function waitForRelayWriterActivation(options = {}) {
  const {
    relayKey,
    expectedWriterKey = null,
    timeoutMs = 10000,
    reason = 'unknown',
    pollMs = 500,
    writerLeaseId = null,
    writerCommitCheckpoint = null
  } = options;
  if (!relayKey) return { ok: false, reason, relayKey: null };

  const { activeRelays } = await import('./hyperpipe-relay-manager-adapter.mjs');
  const relayManager = activeRelays.get(relayKey);
  if (!relayManager?.relay) {
    console.warn('[RelayServer] waitForRelayWriterActivation: relay manager missing', { relayKey, reason });
    emitJoinCheckpointTrace('writer-activation-missing-relay', {
      relayKey,
      reason
    });
    return { ok: false, reason, relayKey };
  }

  const relay = relayManager.relay;
  const expectedKey = normalizeWriterKey(expectedWriterKey);
  const expectedHex = previewWriterKey(expectedKey);
  const normalizedWriterLeaseId = normalizeWriterLeaseId(writerLeaseId);
  const writerCommitCheckpointSummary = summarizeWriterCommitCheckpoint(writerCommitCheckpoint);
  const start = Date.now();
  let timeoutId = null;
  let pollId = null;
  let lastSnapshot = null;
  emitJoinCheckpointTrace('writer-activation-start', {
    relayKey,
    reason,
    expectedWriter: expectedHex,
    timeoutMs,
    pollMs,
    writerLeaseId: normalizedWriterLeaseId,
    writerCommitCheckpoint: writerCommitCheckpointSummary
  });

  if (typeof relay.ready === 'function') {
    try {
      await relay.ready();
    } catch (error) {
      console.warn('[RelayServer] waitForRelayWriterActivation: relay.ready() failed', {
        relayKey,
        reason,
        error: error?.message || error
      });
    }
  }

  const snapshot = (context) => {
    const localKey = relay?.local?.key ? b4a.toString(relay.local.key, 'hex') : null;
    const expectedActive = expectedKey && relay?.activeWriters?.has
      ? relay.activeWriters.has(expectedKey)
      : null;
    return {
      relayKey,
      reason,
      context,
      writable: relay?.writable ?? null,
      activeWriters: relay?.activeWriters?.size ?? null,
      writerSample: sampleActiveWriterKeys(relay),
      localKey: localKey ? localKey.slice(0, 16) : null,
      expectedWriter: expectedHex,
      expectedWriterActive: expectedActive,
      elapsedMs: Date.now() - start
    };
  };

  const shouldLog = (snap) => {
    if (!lastSnapshot) return true;
    return (
      snap.writable !== lastSnapshot.writable ||
      snap.activeWriters !== lastSnapshot.activeWriters ||
      snap.localKey !== lastSnapshot.localKey ||
      snap.expectedWriterActive !== lastSnapshot.expectedWriterActive
    );
  };

  const logState = (snap) => {
    if (shouldLog(snap)) {
      lastSnapshot = snap;
      console.log('[RelayServer] waitForRelayWriterActivation state', snap);
    }
  };

  const isReady = (snap) => Boolean(snap.writable) || (expectedKey ? Boolean(snap.expectedWriterActive) : false);

  return await new Promise((resolve) => {
    const cleanup = (result) => {
      if (timeoutId) clearTimeout(timeoutId);
      if (pollId) clearInterval(pollId);
      if (typeof relay.off === 'function') {
        relay.off('update', onUpdate);
        relay.off('writable', onWritable);
      } else if (typeof relay.removeListener === 'function') {
        relay.removeListener('update', onUpdate);
        relay.removeListener('writable', onWritable);
      }
      resolve(result);
    };

    const onUpdate = () => {
      if (checkReady('update')) return;
    };

    const onWritable = () => {
      if (checkReady('writable')) return;
    };

    const checkReady = (context) => {
      const snap = snapshot(context);
      logState(snap);
      if (isReady(snap)) {
        const diagnostics = summarizeWriterActivationDiagnostics(relay, snap);
        emitJoinCheckpointTrace('writer-activation-ready', {
          ...snap,
          ...diagnostics,
          writerLeaseId: normalizedWriterLeaseId,
          writerCommitCheckpoint: writerCommitCheckpointSummary
        });
        console.log(`[RelayServer] waitForRelayWriterActivation resolved on ${context}`, snap);
        cleanup({ ok: true, ...snap });
        return true;
      }
      return false;
    };

    if (typeof relay.on === 'function') {
      relay.on('update', onUpdate);
      relay.on('writable', onWritable);
    }

    if (checkReady('initial')) {
      return;
    }

    timeoutId = setTimeout(() => {
      const snap = snapshot('timeout');
      const diagnostics = summarizeWriterActivationDiagnostics(relay, snap);
      if (isReady(snap)) {
        console.warn('[RelayServer] waitForRelayWriterActivation timeout but ready', snap);
        emitJoinCheckpointTrace('writer-activation-timeout-ready', {
          ...snap,
          ...diagnostics,
          writerLeaseId: normalizedWriterLeaseId,
          writerCommitCheckpoint: writerCommitCheckpointSummary
        });
        cleanup({ ok: true, timeout: true, ...snap });
        return;
      }
      console.warn('[RelayServer] waitForRelayWriterActivation timeout', snap);
      emitJoinCheckpointTrace('writer-activation-timeout', {
        ...snap,
        ...diagnostics,
        writerLeaseId: normalizedWriterLeaseId,
        writerCommitCheckpoint: writerCommitCheckpointSummary
      });
      cleanup({ ok: false, timeout: true, ...snap });
    }, timeoutMs);

    if (pollMs > 0) {
      pollId = setInterval(() => {
        checkReady('poll');
      }, pollMs);
      pollId.unref?.();
    }
  });
}

function resolveMirrorCheckpointMatch(relay, checkpointRef = null) {
  const normalizedCheckpoint = normalizeCoreRef(checkpointRef) || normalizeCoreRefString(checkpointRef) || null;
  if (!normalizedCheckpoint || !relay) return { checkpointRef: normalizedCheckpoint, hasCheckpoint: null };
  const relayRefs = normalizeCoreRefList(collectRelayCoreRefsFromAutobase(relay));
  return {
    checkpointRef: normalizedCheckpoint,
    hasCheckpoint: relayRefs.includes(normalizedCheckpoint)
  };
}

async function waitForRelayMirrorWarmGate(options = {}) {
  const {
    relayKey,
    checkpointRef = null,
    timeoutMs = MIRROR_WARM_GATE_TIMEOUT_MS,
    pollMs = MIRROR_WARM_GATE_POLL_MS,
    reason = 'unknown'
  } = options;
  if (!relayKey) return { ok: false, warmed: false, reason, relayKey: null, error: 'missing-relay-key' };
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    return { ok: true, warmed: false, skipped: true, reason, relayKey };
  }

  const { activeRelays } = await import('./hyperpipe-relay-manager-adapter.mjs');
  const relayManager = activeRelays.get(relayKey);
  if (!relayManager?.relay) {
    return { ok: false, warmed: false, reason, relayKey, error: 'relay-not-active' };
  }

  const relay = relayManager.relay;
  const start = Date.now();
  let timeoutId = null;
  let pollId = null;
  let lastSnapshot = null;

  const snapshot = (context) => {
    const gateSnapshot = collectRelayGateSnapshot(relay);
    const checkpoint = resolveMirrorCheckpointMatch(relay, checkpointRef);
    const viewReady = typeof gateSnapshot.viewLength === 'number' && gateSnapshot.viewLength > 0;
    const writableReady = gateSnapshot.writable === true;
    const checkpointReady = checkpoint.hasCheckpoint === true;
    const warmReason = writableReady
      ? 'writable'
      : viewReady
        ? 'view-length'
        : checkpointReady
          ? 'checkpoint'
          : null;
    return {
      relayKey,
      reason,
      context,
      checkpointRef: checkpoint.checkpointRef ? checkpoint.checkpointRef.slice(0, 16) : null,
      hasCheckpoint: checkpoint.hasCheckpoint,
      writable: gateSnapshot.writable,
      viewLength: gateSnapshot.viewLength,
      peerCount: gateSnapshot.peerCount,
      activeWriters: gateSnapshot.activeWriters,
      warmReason,
      warmed: Boolean(warmReason),
      elapsedMs: Date.now() - start
    };
  };

  const shouldLog = (snap) => {
    if (!lastSnapshot) return true;
    return (
      snap.warmed !== lastSnapshot.warmed
      || snap.warmReason !== lastSnapshot.warmReason
      || snap.writable !== lastSnapshot.writable
      || snap.viewLength !== lastSnapshot.viewLength
      || snap.hasCheckpoint !== lastSnapshot.hasCheckpoint
      || snap.peerCount !== lastSnapshot.peerCount
      || snap.activeWriters !== lastSnapshot.activeWriters
    );
  };

  return await new Promise((resolve) => {
    const cleanup = (result) => {
      if (timeoutId) clearTimeout(timeoutId);
      if (pollId) clearInterval(pollId);
      if (typeof relay.off === 'function') {
        relay.off('update', onUpdate);
        relay.off('writable', onWritable);
      } else if (typeof relay.removeListener === 'function') {
        relay.removeListener('update', onUpdate);
        relay.removeListener('writable', onWritable);
      }
      resolve(result);
    };

    const check = (context) => {
      const snap = snapshot(context);
      if (shouldLog(snap)) {
        lastSnapshot = snap;
        console.log('[RelayServer] Mirror warm gate state', snap);
      }
      if (snap.warmed) {
        cleanup({ ok: true, ...snap });
        return true;
      }
      return false;
    };

    const onUpdate = () => { check('update'); };
    const onWritable = () => { check('writable'); };

    if (typeof relay.on === 'function') {
      relay.on('update', onUpdate);
      relay.on('writable', onWritable);
    }

    if (check('initial')) return;

    timeoutId = setTimeout(() => {
      const snap = snapshot('timeout');
      if (shouldLog(snap)) {
        lastSnapshot = snap;
        console.warn('[RelayServer] Mirror warm gate timeout', snap);
      }
      cleanup({ ok: false, timeout: true, ...snap });
    }, timeoutMs);

    if (pollMs > 0) {
      pollId = setInterval(() => {
        check('poll');
      }, pollMs);
      pollId.unref?.();
    }
  });
}

function scheduleLateWriterRecovery(options = {}) {
  const {
    relayKey,
    expectedWriterKey = null,
    publicIdentifier = null,
    authToken = null,
    relayUrl = null,
    mode = 'unknown',
    timeoutMs = LATE_WRITER_RECOVERY_TIMEOUT_MS,
    requireWritable = true,
    reason = 'unknown'
  } = options;
  if (!relayKey) return null;
  if (lateWriterRecoveryTasks.has(relayKey)) {
    console.log('[RelayServer] Late writer recovery already scheduled', { relayKey, reason, mode });
    return lateWriterRecoveryTasks.get(relayKey);
  }
  console.log('[RelayServer] Scheduling late writer recovery', {
    relayKey,
    reason,
    mode,
    requireWritable,
    timeoutMs,
    expectedWriter: previewWriterKey(normalizeWriterKey(expectedWriterKey))
  });

  const waitKey = requireWritable ? null : expectedWriterKey;
  const task = waitForRelayWriterActivation({
    relayKey,
    expectedWriterKey: waitKey,
    timeoutMs,
    reason: `${reason}-late`
  }).then((result) => {
    lateWriterRecoveryTasks.delete(relayKey);
    if (result?.ok) {
      console.log('[RelayServer] Late writer recovery succeeded', {
        relayKey,
        writable: result?.writable ?? null,
        expectedWriterActive: result?.expectedWriterActive ?? null,
        elapsedMs: result?.elapsedMs ?? null
      });
      if (global.sendMessage) {
        console.log('[RelayServer] Emitting relay-writable (late recovery)', {
          relayKey,
          publicIdentifier,
          mode,
          writable: true,
          expectedWriterActive: result?.expectedWriterActive ?? null
        });
        const relayWritablePayload = {
          relayKey,
          publicIdentifier,
          relayUrl,
          authToken,
          mode,
          writable: true,
          expectedWriterActive: result?.expectedWriterActive ?? null
        };
        global.sendMessage({
          type: 'relay-writable',
          data: relayWritablePayload
        });
        if (typeof global.onRelayWritable === 'function') {
          try {
            global.onRelayWritable(relayWritablePayload);
          } catch (error) {
            console.warn('[RelayServer] Failed to invoke relay-writable hook:', error?.message || error);
          }
        }
      }
    } else {
      console.warn('[RelayServer] Late writer recovery timed out', {
        relayKey,
        writable: result?.writable ?? null,
        expectedWriterActive: result?.expectedWriterActive ?? null,
        elapsedMs: result?.elapsedMs ?? null
      });
    }
    return result;
  }).catch((error) => {
    lateWriterRecoveryTasks.delete(relayKey);
    console.warn('[RelayServer] Late writer recovery failed', {
      relayKey,
      error: error?.message || error
    });
  });

  lateWriterRecoveryTasks.set(relayKey, task);
  return task;
}

// Update health state
async function updateHealthState() {
  const now = Date.now();
  healthState.lastCheck = now;
  const activeRelays = await getActiveRelays(); // Added await
  healthState.activeRelaysCount = activeRelays.length;
  
  if (healthState.activeRelaysCount > 0 && healthState.services.hyperswarmStatus === 'connected') {
    healthState.status = 'healthy';
  } else if (healthState.services.hyperswarmStatus === 'connected') {
    healthState.status = 'ready';
  } else {
    healthState.status = 'degraded';
  }
  
  console.log('[RelayServer] Health state updated:', {
    status: healthState.status,
    activeRelays: healthState.activeRelaysCount,
    services: healthState.services
  });
}

// Start health monitoring
function startHealthMonitoring() {
  if (healthMonitorTimer) {
    return;
  }

  console.log('[RelayServer] Starting health monitoring (30s interval)');

  healthMonitorTimer = setInterval(async () => {
    await updateHealthState();

    const now = Date.now();
    if (now - healthState.lastCheck > 30000) {
      healthState.status = 'warning';
    }

    console.log('[RelayServer] Periodic health check:', {
      status: healthState.status,
      activeRelays: healthState.activeRelaysCount,
      services: healthState.services,
      connectedPeers: connectedPeers.size,
      gatewayConnected: !!gatewayConnection
    });

    if (global.sendMessage) {
      global.sendMessage({
        type: 'health-update',
        healthState
      });
    }
  }, 30000);
}

// Update metrics
function updateMetrics(success = true) {
  healthState.metrics.totalRequests++;
  if (success) {
    healthState.metrics.successfulRequests++;
  } else {
    healthState.metrics.failedRequests++;
  }
  
  // Reset metrics every hour
  if (Date.now() - healthState.metrics.lastMetricsReset > 60 * 60 * 1000) {
    console.log('[RelayServer] Resetting hourly metrics');
    healthState.metrics.totalRequests = 0;
    healthState.metrics.successfulRequests = 0;
    healthState.metrics.failedRequests = 0;
    healthState.metrics.lastMetricsReset = Date.now();
  }
}

// Register with gateway using Hyperswarm
async function registerWithGateway(relayProfileInfo = null, options = {}) {
  const {
    skipQueue = false,
    requestTimeoutMs = GATEWAY_REGISTRATION_REQUEST_TIMEOUT_MS,
    reason = 'unspecified',
    routeHint = null,
    routeHints = []
  } = options || {};
  const normalizedRouteHints = normalizeGatewayRouteHints([
    ...((Array.isArray(routeHints) ? routeHints : [])),
    ...(routeHint ? [routeHint] : [])
  ]);

  console.log('[RelayServer] ========================================');
  console.log('[RelayServer] GATEWAY REGISTRATION ATTEMPT (Hyperswarm)');
  console.log('[RelayServer] Timestamp:', new Date().toISOString());

  if (!config.registerWithGateway) {
    console.log('[RelayServer] Gateway registration is DISABLED in config');
    console.log('[RelayServer] ========================================');
    return { skipped: true };
  }

  const publicKey = config.swarmPublicKey;
  if (!publicKey) {
    console.warn('[RelayServer] Cannot register with gateway - swarm public key unavailable');
    return { skipped: true };
  }

  try {
    const activeRelays = await getActiveRelays();
    const profiles = await getRelayProfiles();

    const profilesByRelayKey = new Map();
    const profilesByIdentifier = new Map();
    for (const profile of profiles) {
      profilesByRelayKey.set(profile.relay_key, profile);
      if (profile.public_identifier) {
        profilesByIdentifier.set(profile.public_identifier, profile);
      }
    }

    const toTimestamp = (value) => {
      if (!value) return null;
      if (typeof value === 'number' && Number.isFinite(value)) return value;
      const parsed = Date.parse(value);
      return Number.isFinite(parsed) ? parsed : null;
    };

    const resolveProfileAvatar = (profile) => {
      if (!profile) return null;
      const candidates = [
        profile.avatarUrl,
        profile.avatar_url,
        profile.avatar,
        profile.pictureTagUrl,
        profile.picture_tag_url,
        profile.pictureUrl,
        profile.picture_url,
        profile.picture
      ];
      const value = candidates.find((entry) => typeof entry === 'string' && entry.trim().length > 0);
      return value || null;
    };

    const metadataCache = new Map();
    const relayList = [];
    let skippedByRouting = 0;

    for (const relay of activeRelays) {
      const profile =
        profilesByRelayKey.get(relay.relayKey) ||
        (relay.publicIdentifier ? profilesByIdentifier.get(relay.publicIdentifier) : null) ||
        null;

      const routeRelayKey = normalizeRelayKeyHex(relay.relayKey || profile?.relay_key || null);
      const routePublicIdentifier = normalizePublicIdentifierForRoute(
        profile?.public_identifier || relay.publicIdentifier || null
      );
      const relayRouteHint = findGatewayRouteHint(normalizedRouteHints, {
        relayKey: routeRelayKey,
        publicIdentifier: routePublicIdentifier
      });
      const relayRoute = relayRouteHint || await getRelayGatewayRouteSafe({
        relayKey: routeRelayKey || null,
        publicIdentifier: routePublicIdentifier || null
      });
      const relayRouteEvaluation = evaluateGatewayRegistrationRoute(relayRoute);
      if (!relayRouteEvaluation.eligible) {
        skippedByRouting += 1;
        continue;
      }

      const publicIdentifier = String(
        profile?.public_identifier || relay.publicIdentifier || relay.relayKey
      );

      let metadata = metadataCache.get(relay.relayKey);
      if (metadata === undefined) {
        metadata = await getRelayMetadata(relay.relayKey, publicIdentifier);
        metadataCache.set(relay.relayKey, metadata || null);
      }
      const resolvedMetadata = metadata || null;

      const resolvedName =
        resolvedMetadata?.name ||
        profile?.name ||
        relay.name ||
        `Relay ${relay.relayKey.substring(0, 8)}`;

      const resolvedDescription =
        resolvedMetadata?.description ||
        profile?.description ||
        relay.description ||
        '';

      const resolvedAvatar = resolvedMetadata?.avatarUrl || resolveProfileAvatar(profile);

      let resolvedIsPublic;
      if (typeof resolvedMetadata?.isPublic === 'boolean') {
        resolvedIsPublic = resolvedMetadata.isPublic;
      } else if (typeof profile?.isPublic === 'boolean') {
        resolvedIsPublic = profile.isPublic;
      } else if (typeof profile?.is_public === 'boolean') {
        resolvedIsPublic = profile.is_public;
      } else {
        resolvedIsPublic = true;
      }

      const identifierPath = publicIdentifier.includes(':')
        ? publicIdentifier.replace(':', '/')
        : publicIdentifier;

      relayList.push({
        identifier: publicIdentifier,
        name: resolvedName,
        description: resolvedDescription,
        avatarUrl: resolvedAvatar || null,
        isPublic: resolvedIsPublic,
        metadataUpdatedAt: resolvedMetadata?.updatedAt || toTimestamp(profile?.updated_at),
        metadataEventId: resolvedMetadata?.eventId || null,
        gatewayPath: identifierPath
      });
    }

    const gatewayServiceInstance = global.gatewayService || null;
    const publicGatewayState = gatewayServiceInstance?.getPublicGatewayState?.();
    const replicaInfo = gatewayServiceInstance?.getPublicGatewayReplicaInfo?.();
    const replicaStateEntry = publicGatewayState?.relays?.[PUBLIC_GATEWAY_REPLICA_IDENTIFIER] || null;

    if (PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED && (replicaInfo || replicaStateEntry)) {
      const metadata = (replicaStateEntry && replicaStateEntry.metadata) || {};
      const normalizePath = (value) => {
        if (!value || typeof value !== 'string') return null;
        const trimmed = value.trim();
        if (!trimmed) return null;
        return trimmed.replace(/^\//, '').replace(/\/+$/, '');
      };
      const canonicalGatewayPath = normalizePath(metadata.gatewayPath) || 'relay';
      const aliasCandidates = Array.isArray(metadata.pathAliases)
        ? metadata.pathAliases.map((alias) => normalizePath(alias)).filter(Boolean)
        : [];
      aliasCandidates.push('relay');
      aliasCandidates.push('public-gateway/hyperbee');
      const pathAliases = Array.from(
        new Set(
          aliasCandidates
            .filter((alias) => alias && alias !== canonicalGatewayPath)
        )
      );

      let replicaEntry = relayList.find((entry) => entry?.identifier === PUBLIC_GATEWAY_REPLICA_IDENTIFIER);
      if (!replicaEntry) {
        replicaEntry = {
          identifier: PUBLIC_GATEWAY_REPLICA_IDENTIFIER,
          name: metadata.name || 'Public Gateway Relay Replica',
          description: metadata.description || 'Replicated public gateway relay dataset',
          avatarUrl: metadata.avatarUrl || null,
          isPublic: true,
          metadataUpdatedAt: metadata.metadataUpdatedAt || Date.now(),
          metadataEventId: metadata.metadataEventId || null,
          gatewayPath: canonicalGatewayPath,
          pathAliases
        };
        relayList.push(replicaEntry);
      } else {
        replicaEntry.name = metadata.name || replicaEntry.name;
        replicaEntry.description = metadata.description || replicaEntry.description;
        replicaEntry.avatarUrl = metadata.avatarUrl || replicaEntry.avatarUrl || null;
        replicaEntry.metadataUpdatedAt = metadata.metadataUpdatedAt || replicaEntry.metadataUpdatedAt || Date.now();
        replicaEntry.metadataEventId = metadata.metadataEventId || replicaEntry.metadataEventId || null;
      }

      replicaEntry.gatewayPath = canonicalGatewayPath;
      replicaEntry.pathAliases = pathAliases;

      replicaEntry.isGatewayReplica = true;

      const gatewayRelay = replicaStateEntry?.metadata?.gatewayRelay || {};
      replicaEntry.gatewayRelay = {
        hyperbeeKey: replicaInfo?.hyperbeeKey || gatewayRelay.hyperbeeKey || null,
        discoveryKey: replicaInfo?.discoveryKey || gatewayRelay.discoveryKey || null,
        replicationTopic: gatewayRelay.replicationTopic || null
      };

      const fallbackMetrics = replicaEntry.replicaMetrics || {};
      replicaEntry.replicaMetrics = {
        length: Number.isFinite(replicaInfo?.length) ? replicaInfo.length : (Number.isFinite(fallbackMetrics.length) ? fallbackMetrics.length : 0),
        contiguousLength: Number.isFinite(replicaInfo?.contiguousLength) ? replicaInfo.contiguousLength : (Number.isFinite(fallbackMetrics.contiguousLength) ? fallbackMetrics.contiguousLength : 0),
        lag: Number.isFinite(replicaInfo?.lag) ? replicaInfo.lag : (Number.isFinite(fallbackMetrics.lag) ? fallbackMetrics.lag : 0),
        version: Number.isFinite(replicaInfo?.version) ? replicaInfo.version : (Number.isFinite(fallbackMetrics.version) ? fallbackMetrics.version : 0),
        updatedAt: Number.isFinite(replicaInfo?.updatedAt) ? replicaInfo.updatedAt : (Number.isFinite(fallbackMetrics.updatedAt) ? fallbackMetrics.updatedAt : 0)
      };

      if (replicaInfo?.telemetry) {
        replicaEntry.replicaTelemetry = replicaInfo.telemetry;
      }

      if (typeof replicaInfo?.delegateReqToPeers === 'boolean') {
        replicaEntry.delegateReqToPeers = replicaInfo.delegateReqToPeers;
      }
    }

    const advertisedAddress = config.proxy_server_address && config.proxy_server_address.includes(':')
      ? config.proxy_server_address
      : `${config.proxy_server_address}:${config.port}`;

    const registrationData = {
      publicKey,
      relays: relayList,
      address: advertisedAddress,
      mode: 'hyperswarm',
      timestamp: new Date().toISOString(),
      nostrPubkeyHex: config.nostr_pubkey_hex || null,
      pfpDriveKey: config.pfpDriveKey || null
    };

    if (PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED && replicaInfo) {
      registrationData.gatewayReplica = {
        hyperbeeKey: replicaInfo.hyperbeeKey || null,
        discoveryKey: replicaInfo.discoveryKey || null,
        length: replicaInfo.length || 0,
        contiguousLength: replicaInfo.contiguousLength || 0,
        lag: replicaInfo.lag || 0,
        version: replicaInfo.version || 0,
        updatedAt: replicaInfo.updatedAt || 0,
        telemetry: replicaInfo.telemetry || null
      };
      if (typeof replicaInfo.delegateReqToPeers === 'boolean') {
        registrationData.gatewayReplica.delegateReqToPeers = replicaInfo.delegateReqToPeers;
      }
    }

    if (relayProfileInfo) {
      const newRelayRouteHint = findGatewayRouteHint(normalizedRouteHints, {
        relayKey: relayProfileInfo.relay_key || null,
        publicIdentifier: relayProfileInfo.public_identifier || null
      });
      const newRelayRoute = newRelayRouteHint || await getRelayGatewayRouteSafe({
        relayKey: relayProfileInfo.relay_key || null,
        publicIdentifier: relayProfileInfo.public_identifier || null
      });
      const newRelayRouteEvaluation = evaluateGatewayRegistrationRoute(newRelayRoute);

      if (!newRelayRouteEvaluation.eligible) {
        console.log('[RelayServer] Skipping newRelay registration payload due to routing', {
          relayKey: relayProfileInfo.relay_key || null,
          publicIdentifier: relayProfileInfo.public_identifier || null,
          reason: newRelayRouteEvaluation.reason
        });
      } else {
        const newRelayIdentifier = String(
          relayProfileInfo.public_identifier || relayProfileInfo.relay_key
        );

        let newRelayMetadata = metadataCache.get(relayProfileInfo.relay_key);
        if (newRelayMetadata === undefined) {
          newRelayMetadata = await getRelayMetadata(
            relayProfileInfo.relay_key,
            newRelayIdentifier
          );
          metadataCache.set(relayProfileInfo.relay_key, newRelayMetadata || null);
        }
        const resolvedNewMetadata = newRelayMetadata || null;

        const profileAvatar = resolveProfileAvatar(relayProfileInfo);

        let newRelayIsPublic;
        if (typeof resolvedNewMetadata?.isPublic === 'boolean') {
          newRelayIsPublic = resolvedNewMetadata.isPublic;
        } else if (typeof relayProfileInfo.isPublic === 'boolean') {
          newRelayIsPublic = relayProfileInfo.isPublic;
        } else if (typeof relayProfileInfo.is_public === 'boolean') {
          newRelayIsPublic = relayProfileInfo.is_public;
        } else {
          newRelayIsPublic = true;
        }

        const identifierPath = newRelayIdentifier.includes(':')
          ? newRelayIdentifier.replace(':', '/')
          : newRelayIdentifier;

        registrationData.newRelay = {
          identifier: newRelayIdentifier,
          name: resolvedNewMetadata?.name || relayProfileInfo.name,
          description: resolvedNewMetadata?.description || relayProfileInfo.description || '',
          avatarUrl: resolvedNewMetadata?.avatarUrl || profileAvatar || null,
          isPublic: newRelayIsPublic,
          metadataUpdatedAt: resolvedNewMetadata?.updatedAt || toTimestamp(relayProfileInfo.updated_at),
          metadataEventId: resolvedNewMetadata?.eventId || null,
          gatewayPath: identifierPath
        };
      }
    }

    if (relayList.length === 0 && !registrationData.newRelay) {
      console.log('[RelayServer] Skipping gateway registration payload (no routing-eligible relays)', {
        reason: 'gateway-unassigned-or-direct-join-only',
        activeRelayCount: activeRelays.length,
        skippedByRouting
      });
      console.log('[RelayServer] ========================================');
      return {
        skipped: true,
        reason: 'gateway-unassigned-or-direct-join-only',
        skippedByRouting
      };
    }

    if (!gatewayConnection) {
      console.log('[RelayServer] Gateway connection unavailable - queuing registration for later processing', {
        skipQueue,
        pendingCount: pendingRegistrations.length,
        hasGatewayConnection: !!gatewayConnection
      });
      if (!skipQueue) {
        pendingRegistrations.push(relayProfileInfo || null);
        console.log('[RelayServer] Pending registrations queued', {
          pendingCount: pendingRegistrations.length,
          enqueuedWithProfile: !!relayProfileInfo
        });
      }
      console.log('[RelayServer] ========================================');
      return { queued: true };
    }

    console.log('[RelayServer] Sending Hyperswarm registration payload to gateway');
    console.log('[RelayServer] Registration data:', {
      publicKey: publicKey.substring(0, 8) + '...',
      relayCount: registrationData.relays.length,
      address: registrationData.address,
      hasNewRelay: !!registrationData.newRelay,
      mode: registrationData.mode,
      reason,
      requestTimeoutMs
    });
    console.log('[RelayServer][Checkpoint] create-register-start', {
      reason,
      relayKey: relayProfileInfo?.relay_key || null,
      publicIdentifier: relayProfileInfo?.public_identifier || null,
      requestTimeoutMs
    });

    const response = await gatewayConnection.sendRequest({
      method: 'POST',
      path: '/gateway/register',
      headers: { 'content-type': 'application/json' },
      body: b4a.from(JSON.stringify(registrationData)),
      timeoutMs: requestTimeoutMs
    });

    if (response.statusCode !== 200) {
      throw new Error(`Gateway responded with status ${response.statusCode}`);
    }

    let ack = null;
    const responseBody = response.body?.length ? response.body.toString() : '';
    if (responseBody) {
      try {
        ack = JSON.parse(responseBody);
      } catch (parseError) {
        console.warn('[RelayServer] Failed to parse gateway registration acknowledgement:', parseError.message);
      }
    }

    console.log('[RelayServer] Gateway registration acknowledged:', ack || { statusCode: response.statusCode });
    console.log('[RelayServer][Checkpoint] create-register-ack', {
      reason,
      relayKey: relayProfileInfo?.relay_key || null,
      publicIdentifier: relayProfileInfo?.public_identifier || null,
      statusCode: response.statusCode
    });

    if (ack && ack.subnetHash) {
      config.subnetHash = ack.subnetHash;
      await saveConfig(config);
      console.log(`[RelayServer] Stored subnet hash: ${config.subnetHash.substring(0, 8)}...`);
    }

    if (global.sendMessage) {
      const readinessFn = (typeof global.waitForGatewayReady === 'function') ? global.waitForGatewayReady : null;
      if (readinessFn) {
        try {
          await readinessFn();
        } catch (waitError) {
          console.warn('[RelayServer] Proceeding despite gateway readiness wait failure:', waitError?.message || waitError);
        }
        if (global.waitForGatewayReady === readinessFn) {
          delete global.waitForGatewayReady;
        }
      }
      global.sendMessage({
        type: 'gateway-registered',
        data: ack || { statusCode: response.statusCode }
      });

      if (relayProfileInfo) {
        try {
          let userAuthToken = null;
          if (relayProfileInfo.auth_config?.requiresAuth && config.nostr_pubkey_hex) {
            const authorizedUsers = calculateAuthorizedUsers(
              relayProfileInfo.auth_config.auth_adds || [],
              relayProfileInfo.auth_config.auth_removes || []
            );
            const userAuth = authorizedUsers.find(u => u.pubkey === config.nostr_pubkey_hex);
            userAuthToken = userAuth?.token || null;
          }

          const identifierPath = relayProfileInfo.public_identifier
            ? relayProfileInfo.public_identifier.replace(':', '/')
            : relayProfileInfo.relay_key;
          const baseUrl = `${buildGatewayWebsocketBase(config)}/${identifierPath}`;
          const connectionUrl = userAuthToken ? `${baseUrl}?token=${userAuthToken}` : baseUrl;

          global.sendMessage({
            type: 'relay-registration-complete',
            relayKey: relayProfileInfo.relay_key || null,
            publicIdentifier: relayProfileInfo.public_identifier || null,
            gatewayUrl: connectionUrl,
            authToken: userAuthToken,
            requiresAuth: relayProfileInfo.auth_config?.requiresAuth || false
          });
        } catch (notifyError) {
          console.warn('[RelayServer] Failed to emit relay-registration-complete message:', notifyError?.message || notifyError);
        }
      }
    }

    console.log('[RelayServer] Registration SUCCESSFUL');
    console.log('[RelayServer] ========================================');
    return { acknowledged: true, ack };
  } catch (error) {
    const errorMessage = error?.message || String(error);
    const timeoutLike = /timeout/i.test(errorMessage);
    if (timeoutLike && !error?.code) {
      error.code = 'gateway-registration-timeout';
    }
    if (error?.code === 'gateway-registration-timeout') {
      console.warn('[RelayServer][Checkpoint] create-register-timeout', {
        reason,
        relayKey: relayProfileInfo?.relay_key || null,
        publicIdentifier: relayProfileInfo?.public_identifier || null,
        requestTimeoutMs,
        error: errorMessage
      });
    }
    console.error('[RelayServer] Gateway registration via Hyperswarm FAILED:', errorMessage);
    if (!skipQueue) {
      pendingRegistrations.push(relayProfileInfo || null);
      console.log('[RelayServer] Registration re-queued due to failure', {
        pendingCount: pendingRegistrations.length,
        enqueuedWithProfile: !!relayProfileInfo
      });
    }
    try {
      if (global.sendMessage && relayProfileInfo) {
        global.sendMessage({
          type: 'relay-registration-failed',
          relayKey: relayProfileInfo.relay_key || null,
          publicIdentifier: relayProfileInfo.public_identifier || null,
          error: errorMessage
        });
      }
    } catch (notifyError) {
      console.warn('[RelayServer] Failed to notify renderer about registration failure:', notifyError?.message || notifyError);
    }
    console.log('[RelayServer] ========================================');
    throw error;
  }
}

// Export relay management functions for worker access
export async function createRelay(options) {
  // The subnetHash is no longer passed in, it's retrieved from the config
  const {
    name,
    description,
    isPublic = false,
    isOpen = false,
    fileSharing = true,
    picture,
    gatewayOrigin = null,
    gatewayId = null,
    directJoinOnly = false
  } = options;
  const normalizedGatewayOrigin = normalizeHttpOrigin(gatewayOrigin);
  const normalizedGatewayId = normalizeGatewayId(gatewayId);
  const relayDirectJoinOnly = directJoinOnly === true;
  console.log('[RelayServer] Creating relay via adapter:', {
    name,
    description,
    isPublic,
    isOpen,
    fileSharing,
    hasPicture: typeof picture === 'string' && !!picture.trim(),
    gatewayOrigin: normalizedGatewayOrigin,
    gatewayId: normalizedGatewayId,
    directJoinOnly: relayDirectJoinOnly
  });

  const result = await createRelayManager({
    name,
    description,
    isPublic,
    isOpen,
    fileSharing,
    config
  });
  
  if (result.success) {
    result.gatewayOrigin = normalizedGatewayOrigin;
    result.gatewayId = normalizedGatewayId;
    result.directJoinOnly = relayDirectJoinOnly;
    // This is now the single source of truth for token generation on creation.
    await updateHealthState();
    
    // Auto-authorize the creator
    // Use nostr_pubkey_hex to check if an admin exists to be authorized.
    if (config.nostr_pubkey_hex) {
      try {
        const adminPubkey = config.nostr_pubkey_hex;
        const challengeManager = getChallengeManager();
        const authToken = challengeManager.generateAuthToken(adminPubkey);
        const authStore = getRelayAuthStore();
        
        // The subnet hash might not be available immediately, but we can still create the token.
        const subnetHashes = config.subnetHash ? [config.subnetHash] : [];

        // Add auth to the in-memory store for both internal and public identifiers
        authStore.addAuth(result.relayKey, adminPubkey, authToken);
        const canonicalPublicIdentifier = normalizeRelayIdentifier(result.publicIdentifier);
        if (canonicalPublicIdentifier && canonicalPublicIdentifier !== result.relayKey) {
          authStore.addAuth(canonicalPublicIdentifier, adminPubkey, authToken);
        }
        
        // Persist the token to the relay's profile on disk.
        // This now adds the first auth entry.
        const updatedProfile = await updateRelayAuthToken(result.relayKey, adminPubkey, authToken);

        // CRITICAL: Update the profile in the result object to ensure consistency.
        if (updatedProfile) {
          result.profile = updatedProfile;
        }
        
        // Update the result object with the definitive token and URL.
        result.authToken = authToken;
        result.relayUrl = `${buildGatewayWebsocketBase(config)}/${result.publicIdentifier.replace(':', '/')}?token=${authToken}`;

        await publishMemberAddEvent(result.publicIdentifier, adminPubkey, authToken, subnetHashes, 'admin');
        console.log(`[RelayServer] Auto-authorized creator ${adminPubkey.substring(0, 8)}...`);
      } catch (authError) {
        console.error('[RelayServer] Failed to auto-authorize creator:', authError);
        result.registrationError = (result.registrationError || '') + ` | Auth Error: ${authError.message}`;
      }
    }

    const registrationEligibility = await resolveRelayGatewayRegistrationEligibility({
      relayKey: result.relayKey || null,
      publicIdentifier: result.publicIdentifier || null,
      gatewayOrigin: normalizedGatewayOrigin,
      gatewayId: normalizedGatewayId,
      directJoinOnly: relayDirectJoinOnly
    });

    // Register with gateway via Hyperswarm only when relay route has a gateway target
    let registrationStatus = 'disabled';
    if (config.registerWithGateway && registrationEligibility.eligible) {
      console.log('[RelayServer][Checkpoint] create-register-attempt', {
        relayKey: result.relayKey,
        publicIdentifier: result.publicIdentifier || null,
        requestTimeoutMs: GATEWAY_REGISTRATION_REQUEST_TIMEOUT_MS,
        routeSource: registrationEligibility.source || 'unknown'
      });
      try {
        const registrationResult = await registerWithGateway(result.profile, {
          reason: 'create-relay',
          requestTimeoutMs: GATEWAY_REGISTRATION_REQUEST_TIMEOUT_MS,
          routeHint: {
            relayKey: result.relayKey || null,
            publicIdentifier: result.publicIdentifier || null,
            gatewayOrigin: registrationEligibility.gatewayOrigin || null,
            gatewayId: registrationEligibility.gatewayId || null,
            directJoinOnly: false
          }
        });
        registrationStatus = registrationResult?.skipped
          ? 'skipped'
          : registrationResult?.queued
            ? 'queued'
            : 'success';
      } catch (regError) {
        registrationStatus = regError?.code === 'gateway-registration-timeout' ? 'timeout' : 'failed';
        result.registrationError = regError?.message || String(regError);
      }
      console.log('[RelayServer][Checkpoint] create-register-result', {
        relayKey: result.relayKey,
        publicIdentifier: result.publicIdentifier || null,
        gatewayRegistration: registrationStatus,
        registrationError: result.registrationError || null
      });
    } else if (config.registerWithGateway) {
      registrationStatus = 'skipped';
      console.log('[RelayServer][Checkpoint] create-register-skipped', {
        relayKey: result.relayKey || null,
        publicIdentifier: result.publicIdentifier || null,
        reason: registrationEligibility.reason || 'gateway-unassigned'
      });
    }
    result.gatewayRegistration = registrationStatus;

    try {
      const relayWaitResult = await waitForRelayWriterActivation({
        relayKey: result.relayKey,
        timeoutMs: DIRECT_JOIN_WRITABLE_TIMEOUT_MS,
        reason: 'create-relay'
      });
      result.writable = relayWaitResult?.writable ?? null;
      result.expectedWriterActive = relayWaitResult?.expectedWriterActive ?? null;
      console.log('[RelayServer] Create relay writer wait result', {
        relayKey: result.relayKey,
        publicIdentifier: result.publicIdentifier || null,
        ok: relayWaitResult?.ok ?? null,
        writable: relayWaitResult?.writable ?? null,
        expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
        elapsedMs: relayWaitResult?.elapsedMs ?? null
      });

      if (relayWaitResult?.writable === true && global.sendMessage) {
        const relayWritablePayload = {
          relayKey: result.relayKey,
          publicIdentifier: result.publicIdentifier || null,
          relayUrl: result.relayUrl || null,
          authToken: result.authToken || null,
          mode: 'create-relay',
          writable: relayWaitResult?.writable ?? null,
          expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null
        };
        global.sendMessage({
          type: 'relay-writable',
          data: relayWritablePayload
        });
        if (typeof global.onRelayWritable === 'function') {
          try {
            global.onRelayWritable(relayWritablePayload);
          } catch (error) {
            console.warn('[RelayServer] Failed to invoke relay-writable hook:', error?.message || error);
          }
        }
      }

      if (!relayWaitResult?.ok || !relayWaitResult?.writable) {
        scheduleLateWriterRecovery({
          relayKey: result.relayKey,
          publicIdentifier: result.publicIdentifier || null,
          authToken: result.authToken || null,
          relayUrl: result.relayUrl || null,
          mode: 'create-relay',
          requireWritable: true,
          reason: 'create-relay'
        });
      }
    } catch (waitError) {
      console.warn('[RelayServer] Create relay writer wait failed', {
        relayKey: result.relayKey,
        error: waitError?.message || waitError
      });
    }

    const bootstrapPublish = {
      status: 'skipped',
      attempt: 0,
      publishedKinds: [],
      eventIds: [],
      relayIdentifier: result.publicIdentifier || result.relayKey || null,
      relayWsUrl: result.publicIdentifier
        ? `${buildGatewayWebsocketBase(config)}/${String(result.publicIdentifier).replace(':', '/')}`
        : null,
      error: null
    };

    if (config.nostr_pubkey_hex && config.nostr_nsec_hex && result.publicIdentifier) {
      console.log('[RelayServer] Create relay bootstrap publish start', {
        relayKey: result.relayKey,
        publicIdentifier: result.publicIdentifier,
        isPublic,
        isOpen
      });
      const bootstrapResult = await publishCreateRelayBootstrapEvents({
        relayKey: result.relayKey,
        publicIdentifier: result.publicIdentifier,
        adminPubkey: config.nostr_pubkey_hex,
        name,
        description,
        isPublic,
        isOpen,
        fileSharing,
        picture,
        gatewayOrigin: normalizedGatewayOrigin,
        gatewayId: normalizedGatewayId,
        directJoinOnly: relayDirectJoinOnly
      });
      bootstrapPublish.status = bootstrapResult.ok ? 'success' : 'failed';
      bootstrapPublish.attempt = bootstrapResult.attempt || 0;
      bootstrapPublish.publishedKinds = (bootstrapResult.published || []).map((entry) => entry.kind);
      bootstrapPublish.eventIds = (bootstrapResult.published || []).map((entry) => entry.id);
      bootstrapPublish.relayIdentifier = bootstrapResult.relayIdentifier || bootstrapPublish.relayIdentifier;
      bootstrapPublish.relayWsUrl = bootstrapResult.relayWsUrl || bootstrapPublish.relayWsUrl;
      bootstrapPublish.error = bootstrapResult.error || null;

      console.log('[RelayServer] Create relay bootstrap publish complete', {
        relayKey: result.relayKey,
        publicIdentifier: result.publicIdentifier,
        status: bootstrapPublish.status,
        attempt: bootstrapPublish.attempt,
        publishedKinds: bootstrapPublish.publishedKinds,
        error: bootstrapPublish.error
      });
    } else {
      bootstrapPublish.error = 'missing signer or public identifier for bootstrap publish';
      console.warn('[RelayServer] Create relay bootstrap publish skipped', {
        relayKey: result.relayKey,
        publicIdentifier: result.publicIdentifier || null,
        hasPubkey: !!config.nostr_pubkey_hex,
        hasNsec: !!config.nostr_nsec_hex
      });
    }

    result.bootstrapPublish = bootstrapPublish;
    result.discoveryTopic = deriveRelayDiscoveryTopic(result.publicIdentifier || result.relayKey || null);
    result.hostPeerKeys = config?.swarmPublicKey ? [String(config.swarmPublicKey).toLowerCase()] : [];
    result.leaseReplicaPeerKeys = [...result.hostPeerKeys];
    result.writerIssuerPubkey = normalizeHex64(config?.nostr_pubkey_hex || null);

    await upsertRelayDiscoveryHints({
      relayKey: result.relayKey || null,
      publicIdentifier: result.publicIdentifier || null,
      discoveryTopic: result.discoveryTopic || undefined,
      hostPeerKeys: result.hostPeerKeys,
      leaseReplicaPeerKeys: result.leaseReplicaPeerKeys,
      writerIssuerPubkey: result.writerIssuerPubkey || undefined,
      observedAt: Date.now()
    }).catch(() => {});

    console.log('[RelayServer][Checkpoint] create-return', {
      relayKey: result.relayKey,
      publicIdentifier: result.publicIdentifier || null,
      gatewayRegistration: result.gatewayRegistration || null,
      registrationError: result.registrationError || null,
      writable: result.writable ?? null
    });
  }
  
  return result;
}

export async function joinRelay(options) {
  const { fileSharing = true } = options;
  console.log('[RelayServer] Joining relay via adapter:', { ...options, fileSharing });
  const result = await joinRelayManager({
    ...options,
    fileSharing,
    config
  });
  
  if (result.success) {
    await updateHealthState();
    
    // ALWAYS register with gateway via Hyperswarm if enabled
    let registrationStatus = 'disabled';
    if (config.registerWithGateway) {
      try {
        const registrationResult = await registerWithGateway(result.profile, {
          reason: 'join-relay',
          requestTimeoutMs: GATEWAY_REGISTRATION_REQUEST_TIMEOUT_MS
        });
        registrationStatus = registrationResult?.queued ? 'queued' : 'success';
      } catch (regError) {
        registrationStatus = regError?.code === 'gateway-registration-timeout' ? 'timeout' : 'failed';
        result.registrationError = regError?.message || String(regError);
      }
    }
    result.gatewayRegistration = registrationStatus;
  }
  
  return result;
}

/**
 * Helper function to create a kind 9021 join request event.
 * This replicates the logic from the desktop's NostrEvents class.
 * @param {string} publicIdentifier - The public identifier of the relay to join.
 * @param {string} privateKey - The user's hex-encoded private key for signing.
 * @returns {Promise<Object>} - A signed Nostr event.
 */
async function createGroupJoinRequest(publicIdentifier, privateKey) {
  const pubkey = NostrUtils.getPublicKey(privateKey);
  const event = {
    kind: 9021, // KIND_GROUP_JOIN_REQUEST
    content: 'Request to join the group',
    tags: [['h', publicIdentifier]],
    created_at: Math.floor(Date.now() / 1000),
    pubkey
  };
  return NostrUtils.signEvent(event, privateKey);
}

function buildJoinAuthAttemptLockKey(publicIdentifier, userPubkey) {
  const identifier =
    typeof publicIdentifier === 'string' && publicIdentifier.trim().length
      ? normalizeRelayIdentifier(publicIdentifier.trim()) || publicIdentifier.trim()
      : null;
  const pubkey =
    typeof userPubkey === 'string' && userPubkey.trim().length
      ? userPubkey.trim().toLowerCase()
      : null;
  if (!identifier || !pubkey) return null;
  return `${identifier}:${pubkey}`;
}

function acquireJoinAuthAttemptLock(publicIdentifier, userPubkey) {
  const lockKey = buildJoinAuthAttemptLockKey(publicIdentifier, userPubkey);
  if (!lockKey) return { lockKey: null, attemptId: null, acquired: false, inFlight: false };
  const existing = joinAuthAttemptLocks.get(lockKey);
  if (existing?.attemptId) {
    return { lockKey, attemptId: existing.attemptId, acquired: false, inFlight: true };
  }
  const attemptId = `${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
  joinAuthAttemptLocks.set(lockKey, { startedAt: Date.now(), attemptId });
  return { lockKey, attemptId, acquired: true, inFlight: false };
}

function releaseJoinAuthAttemptLock(lockKey, attemptId) {
  if (!lockKey || !attemptId) return;
  const current = joinAuthAttemptLocks.get(lockKey);
  if (current?.attemptId === attemptId) {
    joinAuthAttemptLocks.delete(lockKey);
  }
}

async function preseedJoinMetadata({
  relayKey,
  publicIdentifier,
  userPubkey,
  authToken,
  storageDir,
  reason
}) {
  if (!relayKey || !userPubkey || !authToken) return null;

  const resolvedStorageDir =
    storageDir || join(config.storage || './data', 'relays', relayKey);

  let profile = await getRelayProfileByKey(relayKey);
  if (!profile && publicIdentifier) {
    profile = await getRelayProfileByPublicIdentifier(publicIdentifier);
  }

  if (!profile) {
    profile = {
      name: `Joined Relay ${relayKey.substring(0, 8)}`,
      description: `Relay joined on ${new Date().toISOString()}`,
      relay_key: relayKey,
      public_identifier: publicIdentifier || null,
      relay_storage: resolvedStorageDir,
      joined_at: new Date().toISOString(),
      auto_connect: true,
      is_active: true,
      admin_pubkey: config.nostr_pubkey_hex || null,
      members: config.nostr_pubkey_hex ? [config.nostr_pubkey_hex] : [],
      member_adds: config.nostr_pubkey_hex
        ? [{ pubkey: config.nostr_pubkey_hex, ts: Date.now() }]
        : [],
      member_removes: []
    };
    await saveRelayProfile(profile);
  } else {
    let changed = false;
    if (publicIdentifier && !profile.public_identifier) {
      profile.public_identifier = publicIdentifier;
      changed = true;
    }
    if (resolvedStorageDir && !profile.relay_storage) {
      profile.relay_storage = resolvedStorageDir;
      changed = true;
    }
    if (changed) {
      await saveRelayProfile(profile);
    }
  }

  const updatedProfile = await updateRelayAuthToken(relayKey, userPubkey, authToken);
  if (updatedProfile) {
    profile = updatedProfile;
  }

  console.log('[RelayServer] Preseeded join metadata', {
    relayKey,
    publicIdentifier,
    reason: reason || 'unspecified',
    authToken: authToken ? authToken.slice(0, 8) + '...' : null
  });

  return profile;
}

export async function startJoinAuthentication(options) {
  const {
    publicIdentifier,
    fileSharing = true,
    hostPeers: hostPeerList = [],
    blindPeer = null,
    token: inviteToken = null,
    relayKey: inviteRelayKey = null,
    relayUrl: inviteRelayUrl = null,
    gatewayMode = 'auto',
    joinDirectDiscoveryV2 = false,
    joinPathMode = null,
    selectedDirectPeerKey = null,
    openJoin = false,
    isOpen = null,
    writerCore = null,
    writerSecret = null,
    writerCoreHex = null,
    autobaseLocal = null,
    writerLeaseId = null,
    writerCommitCheckpoint = null,
    coreRefs = [],
    writerCoreRefs = [],
    fastForward = null,
    joinAttemptId = null,
    joinTraceId = null,
    joinRequestId = null,
    joinWritableTimeoutMs = null
  } = options;
  const expectedWriter = resolveExpectedWriterKey({ writerCoreHex, autobaseLocal, writerCore });
  const expectedWriterKey = expectedWriter.expectedWriterKey;
  const expectedWriterSource = expectedWriter.source;
  const expectedWriterKeyHex = resolveWriterKeyHex(expectedWriterKey);
  const normalizedWriterLeaseId = normalizeWriterLeaseId(
    writerLeaseId || options?.writerLeaseEnvelope?.leaseId || null
  );
  const normalizedWriterCommitCheckpoint = normalizeWriterCommitCheckpoint(
    writerCommitCheckpoint
      || options?.writerLeaseEnvelope?.writerCommitCheckpoint
      || options?.writerLeaseEnvelope?.writer_commit_checkpoint
      || null
  );
  const requiresClosedJoinCheckpoint = Boolean(
    !openJoin
    && !!inviteToken
    && (writerSecret || expectedWriterKey || writerCore || writerCoreHex || autobaseLocal)
  );
  if (requiresClosedJoinCheckpoint && !normalizedWriterCommitCheckpoint) {
    emitJoinCheckpointTrace('writer-checkpoint-missing', {
      publicIdentifier,
      relayKey: normalizeRelayKeyHex(inviteRelayKey) || inviteRelayKey || null,
      joinTraceId: typeof joinTraceId === 'string' ? joinTraceId : null,
      joinAttemptId: typeof joinAttemptId === 'string' ? joinAttemptId : null,
      joinRequestId: typeof joinRequestId === 'string' ? joinRequestId : null,
      mode: 'invite-fallback',
      reason: 'closed-join-requires-checkpoint',
      hasWriterSecret: !!writerSecret,
      expectedWriter: previewWriterKey(expectedWriterKey),
      writerLeaseId: normalizedWriterLeaseId ? normalizedWriterLeaseId.slice(0, 24) : null
    });
    throw new Error('writer-checkpoint-missing: closed join requires writer commit checkpoint');
  }
  const normalizedGatewayMode = normalizeGatewayMode(gatewayMode);
  const gatewayDisabled = normalizedGatewayMode === 'disabled';
  const scopedJoinAttemptId =
    typeof joinAttemptId === 'string' && joinAttemptId.trim().length
      ? joinAttemptId.trim()
      : null;
  const scopedJoinTraceId =
    typeof joinTraceId === 'string' && joinTraceId.trim().length
      ? joinTraceId.trim()
      : scopedJoinAttemptId;
  const scopedJoinRequestId =
    typeof joinRequestId === 'string' && joinRequestId.trim().length
      ? joinRequestId.trim()
      : null;
  const resolvedJoinWritableTimeoutMs =
    Number.isFinite(joinWritableTimeoutMs) && Number(joinWritableTimeoutMs) > 0
      ? Math.max(1000, Math.floor(Number(joinWritableTimeoutMs)))
      : BLIND_PEER_JOIN_WRITABLE_TIMEOUT_MS;
  const normalizedJoinPathMode =
    typeof joinPathMode === 'string'
      ? joinPathMode.trim().toLowerCase()
      : null;
  const directDiscoveryV2Enabled = joinDirectDiscoveryV2 === true;
  const closedLeaseDirectPath =
    normalizedJoinPathMode === 'closed-lease-direct'
    && !openJoin
    && !!inviteToken;
  const openGatewayBootstrapPath =
    normalizedJoinPathMode === 'open-gateway-bootstrap'
    && !!openJoin
    && !inviteToken;
  const requestedDirectPeerKey = typeof selectedDirectPeerKey === 'string'
    ? selectedDirectPeerKey.trim().toLowerCase()
    : null;
  const hasClosedInviteWriterMaterial = Boolean(
    !openJoin
    && !!inviteToken
    && (writerSecret || expectedWriterKey || writerCore || writerCoreHex || autobaseLocal)
  );
  const closedInviteOfflineFallbackPath =
    hasClosedInviteWriterMaterial
    && !closedLeaseDirectPath
    && !requestedDirectPeerKey
    && normalizedJoinPathMode !== 'direct-join';
  const hasVerifiedDirectPathLock = Boolean(
    requestedDirectPeerKey
    || normalizedJoinPathMode === 'direct-join'
    || normalizedJoinPathMode === 'direct-challenge'
    || normalizedJoinPathMode === 'lease-claim'
  );
  const blockUnverifiedDirectLoop = Boolean(
    directDiscoveryV2Enabled
    && !hasVerifiedDirectPathLock
    && !closedLeaseDirectPath
    && !openGatewayBootstrapPath
    && !closedInviteOfflineFallbackPath
  );
  let resolvedCoreRefs = Array.isArray(coreRefs) ? [...coreRefs] : [];
  let resolvedWriterCoreRefs = Array.isArray(writerCoreRefs) ? writerCoreRefs.filter(Boolean) : [];
  const expectedCoreRef = normalizeCoreRefString(expectedWriterKey);
  if (expectedCoreRef && !resolvedCoreRefs.includes(expectedCoreRef)) {
    resolvedCoreRefs.push(expectedCoreRef);
  }
  if (expectedCoreRef && !resolvedWriterCoreRefs.includes(expectedCoreRef)) {
    resolvedWriterCoreRefs.push(expectedCoreRef);
  }
  let coreRefsForJoin = resolvedCoreRefs;
  let writerCoreRefsForJoin = Array.from(new Set(resolvedWriterCoreRefs));
  const relayKeyHint = normalizeRelayKeyHex(inviteRelayKey) || inviteRelayKey || null;
  const publicIdentifierHint = publicIdentifier || null;
  let resolvedCoreRefsSource = 'invite';
  if (typeof global.resolveRelayMirrorCoreRefs === 'function' && (relayKeyHint || publicIdentifierHint)) {
    try {
      const merged = await global.resolveRelayMirrorCoreRefs(
        relayKeyHint,
        publicIdentifierHint,
        coreRefsForJoin
      );
      if (Array.isArray(merged) && merged.length) {
        coreRefsForJoin = merged;
        resolvedCoreRefsSource = 'cache';
      }
    } catch (error) {
      console.warn('[RelayServer] Failed to resolve relay core refs from cache', {
        relayKey: relayKeyHint,
        publicIdentifier: publicIdentifierHint,
        error: error?.message || error
      });
    }
  }

  const checkpointRefForJoin = fastForward?.key ? normalizeCoreRef(fastForward.key) : null;
  let checkpointInJoinRefs = checkpointRefForJoin
    ? normalizeCoreRefList(coreRefsForJoin).includes(checkpointRefForJoin)
    : null;
  if (
    !checkpointInJoinRefs
    && !gatewayDisabled
    && typeof global.fetchAndApplyRelayMirrorMetadata === 'function'
    && (relayKeyHint || publicIdentifierHint)
  ) {
    try {
      const mirrorResult = await global.fetchAndApplyRelayMirrorMetadata({
        relayKey: relayKeyHint || publicIdentifierHint,
        publicIdentifier: publicIdentifierHint,
        reason: 'join-refresh'
      });
      const merged = typeof global.resolveRelayMirrorCoreRefs === 'function'
        ? await global.resolveRelayMirrorCoreRefs(
          relayKeyHint,
          publicIdentifierHint,
          coreRefsForJoin
        )
        : null;
      if (Array.isArray(merged) && merged.length) {
        coreRefsForJoin = merged;
        resolvedCoreRefsSource = 'mirror';
        checkpointInJoinRefs = checkpointRefForJoin
          ? normalizeCoreRefList(coreRefsForJoin).includes(checkpointRefForJoin)
          : checkpointInJoinRefs;
      }
      console.log('[RelayServer] Join mirror refresh result', {
        relayKey: relayKeyHint,
        publicIdentifier: publicIdentifierHint,
        status: mirrorResult?.status ?? null,
        checkpointInJoinRefs,
        coreRefsCount: Array.isArray(coreRefsForJoin) ? coreRefsForJoin.length : 0
      });
    } catch (error) {
      console.warn('[RelayServer] Mirror refresh failed during join', {
        relayKey: relayKeyHint,
        publicIdentifier: publicIdentifierHint,
        error: error?.message || error
      });
    }
  } else if (
    !checkpointInJoinRefs
    && gatewayDisabled
    && (relayKeyHint || publicIdentifierHint)
  ) {
    console.log('[RelayServer] Skipping mirror refresh during join (gateway disabled)', {
      relayKey: relayKeyHint,
      publicIdentifier: publicIdentifierHint
    });
  }

  writerCoreRefsForJoin = Array.from(new Set(writerCoreRefsForJoin));
  console.log('[RelayServer] startJoinAuthentication payload', {
    publicIdentifier,
    joinAttemptId: scopedJoinAttemptId,
    joinTraceId: scopedJoinTraceId,
    joinRequestId: scopedJoinRequestId,
    joinWritableTimeoutMs: resolvedJoinWritableTimeoutMs,
    hasWriterSecret: !!writerSecret,
    hasWriterCore: !!writerCore,
    hasWriterCoreHex: !!writerCoreHex,
    hasAutobaseLocal: !!autobaseLocal,
    hasWriterLeaseId: !!normalizedWriterLeaseId,
    writerLeaseId: normalizedWriterLeaseId ? normalizedWriterLeaseId.slice(0, 24) : null,
    writerCommitCheckpoint: summarizeWriterCommitCheckpoint(normalizedWriterCommitCheckpoint),
    hasFastForward: !!fastForward,
    expectedWriterSource,
    expectedWriterKeyHex,
    coreRefsCount: resolvedCoreRefs.length,
    writerCoreRefsCount: writerCoreRefsForJoin.length,
    hostPeersCount: Array.isArray(hostPeerList) ? hostPeerList.length : 0,
    blindPeer: !!blindPeer,
    inviteRelayKey,
    openJoin,
    gatewayMode: normalizedGatewayMode,
    joinPathMode: normalizedJoinPathMode,
    selectedDirectPeerKey: requestedDirectPeerKey,
    joinDirectDiscoveryV2: directDiscoveryV2Enabled,
    resolvedCoreRefsSource,
    resolvedCoreRefsCount: coreRefsForJoin.length,
    checkpointInJoinRefs
  });
  emitJoinCheckpointTrace('join-auth-start', {
    publicIdentifier,
    joinAttemptId: scopedJoinAttemptId,
    joinTraceId: scopedJoinTraceId,
    joinRequestId: scopedJoinRequestId,
    gatewayMode: normalizedGatewayMode,
    openJoin,
    hasInviteToken: !!inviteToken,
    expectedWriterSource,
    expectedWriterKeyHex,
    writerLeaseId: normalizedWriterLeaseId,
    writerCommitCheckpoint: summarizeWriterCommitCheckpoint(normalizedWriterCommitCheckpoint)
  });
  console.log('[RelayServer][WriterMaterial] Join auth writer material', {
    publicIdentifier,
    writerLeaseId: normalizedWriterLeaseId,
    writerCommitCheckpoint: summarizeWriterCommitCheckpoint(normalizedWriterCommitCheckpoint),
    writerCore,
    writerSecret,
    writerCoreHex,
    autobaseLocal,
    expectedWriterKey,
    expectedWriterSource,
    expectedWriterKeyHex,
    coreRefs: resolvedCoreRefs,
    writerCoreRefs: writerCoreRefsForJoin
  });
  const userNsec = config.nostr_nsec_hex;
  const userPubkey = NostrUtils.getPublicKey(userNsec);
  if (config.nostr_pubkey_hex && userPubkey !== config.nostr_pubkey_hex) {
    console.warn('[RelayServer] Derived pubkey does not match configured pubkey');
  }

  console.log(`[RelayServer] Starting join authentication for: ${publicIdentifier}`);
  console.log(`[RelayServer] Using user pubkey: ${userPubkey.substring(0, 8)}...`);
  console.log(`[RelayServer] File sharing enabled: ${fileSharing}`);

  if (!publicIdentifier || !userPubkey || !userNsec) {
    const errorMsg = 'Missing publicIdentifier or user credentials for join flow.';
    console.error(`[RelayServer] ${errorMsg}`);
    if (global.sendMessage) {
      global.sendMessage({
        type: 'join-auth-error',
        data: {
          publicIdentifier,
          error: errorMsg,
          joinAttemptId: scopedJoinAttemptId,
          joinTraceId: scopedJoinTraceId,
          joinRequestId: scopedJoinRequestId
        }
      });
    }
    return {
      ok: false,
      code: 'missing-join-input',
      error: errorMsg,
      publicIdentifier: publicIdentifier || null
    };
  }

  const joinAttemptLock = acquireJoinAuthAttemptLock(publicIdentifier, userPubkey);
  if (!joinAttemptLock.acquired && joinAttemptLock.inFlight) {
    const errorMsg = 'Join authentication already in progress for this relay/user';
    console.warn('[RelayServer] Join auth request rejected: in-flight attempt exists', {
      publicIdentifier,
      pubkey: userPubkey.substring(0, 8),
      lockKey: joinAttemptLock.lockKey
    });
    return {
      ok: false,
      code: 'join-auth-in-flight',
      error: errorMsg,
      publicIdentifier: publicIdentifier || null
    };
  }

  try {
    // Send initial progress message to the desktop UI
    if (global.sendMessage) {
      global.sendMessage({
        type: 'join-auth-progress',
        data: {
          publicIdentifier,
          status: 'request',
          joinAttemptId: scopedJoinAttemptId,
          joinTraceId: scopedJoinTraceId,
          joinRequestId: scopedJoinRequestId
        }
      });
    }
    
    // 1. Construct the kind 9021 event
    console.log('[RelayServer] Creating kind 9021 join request event...');
    const joinEvent = await createGroupJoinRequest(publicIdentifier, userNsec);
    console.log(`[RelayServer] Created join event ID: ${joinEvent.id.substring(0, 8)}...`);
    
    const hostPeers = Array.isArray(hostPeerList)
      ? hostPeerList.map((key) => String(key || '').trim().toLowerCase()).filter(Boolean)
      : [];

    const blindPeerKey = blindPeer?.publicKey ? String(blindPeer.publicKey).trim().toLowerCase() : null;

    if (!hostPeers.length && !inviteToken && !openJoin) {
      throw new Error('No hosting peers discovered for this relay');
    }

    let challengePayload = null;
    let relayPubkey = null;
    let selectedPeerKey = requestedDirectPeerKey || null;
    let joinProtocol = null;
    let lastJoinError = null;

    if (closedLeaseDirectPath) {
      console.log('[RelayServer] Closed lease-direct path selected; skipping direct challenge handshake', {
        publicIdentifier,
        selectedDirectPeer: selectedPeerKey ? selectedPeerKey.substring(0, 8) : null,
        hostPeersCount: hostPeers.length
      });
    } else if (openGatewayBootstrapPath) {
      console.log('[RelayServer] Open gateway-bootstrap path selected; skipping direct host dial', {
        publicIdentifier,
        hostPeersCount: hostPeers.length,
        hasWriterSecret: !!writerSecret,
        hasWriterCore: !!writerCore,
        hasWriterCoreHex: !!writerCoreHex,
        hasAutobaseLocal: !!autobaseLocal
      });
    } else if (closedInviteOfflineFallbackPath) {
      console.log('[RelayServer] Closed invite offline-fallback guard active; skipping direct host dial', {
        publicIdentifier,
        hostPeersSuppressed: hostPeers.length,
        hasWriterSecret: !!writerSecret,
        hasWriterCore: !!writerCore,
        hasWriterCoreHex: !!writerCoreHex,
        hasAutobaseLocal: !!autobaseLocal
      });
    } else if (blockUnverifiedDirectLoop) {
      console.log('[RelayServer] Direct host dial suppressed (Direct Discovery v2 requires verified candidate lock)', {
        publicIdentifier,
        joinPathMode: normalizedJoinPathMode,
        hostPeersSuppressed: hostPeers.length,
        gatewayMode: normalizedGatewayMode
      });
      lastJoinError = new Error('no-verified-direct-candidate');
    } else {
      for (const hostPeerKey of hostPeers) {
        if (blindPeerKey && hostPeerKey === blindPeerKey) {
          console.log('[RelayServer] Skipping direct join attempt for blind-peer host', hostPeerKey.substring(0, 8));
          continue;
        }
        try {
          console.log(`[RelayServer] Attempting direct join via peer ${hostPeerKey.substring(0, 8)}...`);
          const protocol = await waitForPeerProtocol(hostPeerKey, 20000, 'direct-join-handshake');
          const joinResponse = await protocol.sendRequest({
            method: 'POST',
            path: `/post/join/${publicIdentifier}`,
            headers: { 'content-type': 'application/json' },
            body: Buffer.from(JSON.stringify({ event: joinEvent }))
          });

          if ((joinResponse.statusCode || 200) >= 400) {
            const responseBody = toBuffer(joinResponse.body).toString('utf8');
            throw new Error(`Peer returned status ${joinResponse.statusCode}: ${responseBody}`);
          }

          const parsed = parseJsonBody(joinResponse.body) || {};
          if (parsed.status === 'pending') {
            console.log('[RelayServer] Join request pending (closed relay)', {
              publicIdentifier,
              hostPeer: hostPeerKey.substring(0, 8)
            });
            lastJoinError = new Error('closed-join-pending');
            continue;
          }
          if (!parsed.challenge || !parsed.relayPubkey) {
            throw new Error('Invalid join response from peer');
          }

          challengePayload = parsed;
          relayPubkey = parsed.relayPubkey;
          selectedPeerKey = hostPeerKey;
          joinProtocol = protocol;
          break;
        } catch (error) {
          console.error(`[RelayServer] Direct join attempt failed for ${hostPeerKey.substring(0, 8)}:`, error.message);
          lastJoinError = error;
        }
      }
    }

    if (!challengePayload || !relayPubkey || !joinProtocol) {
      // Offline/blind-peer fallback: if we have an invite token and relay info, finalize locally without a host handshake.
      if (inviteToken && (inviteRelayKey || publicIdentifier)) {
        const inviteFallbackMode = closedLeaseDirectPath
          ? 'closed-lease-direct'
          : closedInviteOfflineFallbackPath
            ? 'closed-invite-offline-fallback'
          : 'blind-peer-offline';
        const inviteFallbackReason = closedLeaseDirectPath
          ? 'closed-lease-direct'
          : closedInviteOfflineFallbackPath
            ? 'closed-invite-offline-fallback'
          : 'blind-peer-fallback';
        const inviteFallbackHostPeer = selectedPeerKey || blindPeerKey || null;
        let resolvedRelayKey = inviteRelayKey || null;
        let relayKeySource = resolvedRelayKey ? 'invite' : null;
        if (!resolvedRelayKey && publicIdentifier) {
          resolvedRelayKey = await getRelayKeyFromPublicIdentifier(publicIdentifier);
          if (resolvedRelayKey) relayKeySource = 'local-profile';
        }
        if (!resolvedRelayKey && inviteRelayUrl) {
          try {
            const parsed = new URL(inviteRelayUrl);
            const parts = parsed.pathname.split('/').filter(Boolean);
            const maybeKey = parts[0] || null;
            if (maybeKey && /^[0-9a-fA-F]{64}$/.test(maybeKey)) {
              resolvedRelayKey = maybeKey;
              relayKeySource = 'relay-url';
            }
          } catch (_) {
            // ignore
          }
        }
        if (!resolvedRelayKey && !gatewayDisabled) {
          const mirrorIdentifier = publicIdentifier || extractIdentifierFromRelayUrl(inviteRelayUrl);
          if (mirrorIdentifier) {
            const mirrorResult = await fetchMirrorMetadataFromGateway(mirrorIdentifier, {
              reason: inviteFallbackReason
            });
            if (mirrorResult?.status === 'ok' && mirrorResult.data) {
              const mirrorRelayKey = mirrorResult.data.relayKey || mirrorResult.data.relay_key || null;
              if (mirrorRelayKey && /^[0-9a-fA-F]{64}$/.test(String(mirrorRelayKey))) {
                resolvedRelayKey = String(mirrorRelayKey);
                relayKeySource = 'gateway-mirror';
              }
            }
          }
        }
        if (resolvedRelayKey && /^[0-9a-fA-F]{64}$/.test(String(resolvedRelayKey))) {
          resolvedRelayKey = String(resolvedRelayKey).toLowerCase();
        }
        if (!resolvedRelayKey) {
          if (gatewayDisabled) {
            throw new Error('Missing relay key for invite fallback while gatewayMode=disabled');
          }
          throw new Error('Missing relay key for invite fallback; cannot join relay');
        }
        const fallbackRelayKey = resolvedRelayKey;
        console.log('[RelayServer] Falling back to invite token path (no direct host)', {
          relayKey: fallbackRelayKey,
          publicIdentifier,
          relayKeySource,
          mode: inviteFallbackMode
        });

        if (!writerSecret) {
          console.warn('[RelayServer] No writerSecret provided in invite; fallback join may be read-only');
        }

        assertTokenOwnerMatchesExpectedPubkey({
          relayKey: fallbackRelayKey,
          publicIdentifier,
          authToken: inviteToken,
          expectedPubkey: userPubkey,
          context: inviteFallbackReason
        });

        await preseedJoinMetadata({
          relayKey: fallbackRelayKey,
          publicIdentifier,
          userPubkey,
          authToken: inviteToken,
          storageDir: join(config.storage || './data', 'relays', fallbackRelayKey),
          reason: inviteFallbackReason
        });

        await joinRelayManager({
          relayKey: fallbackRelayKey,
          config,
          fileSharing,
          isOpen,
          publicIdentifier,
          authToken: inviteToken,
          writerSecret,
          writerCore,
          writerCoreHex,
          autobaseLocal,
          blindPeer,
          coreRefs: coreRefsForJoin,
          fastForward,
          expectedWriterKey,
          suppressInitMessage: true,
          useSharedCorestore: true
        });
        await applyPendingAuthUpdates(updateRelayAuthToken, fallbackRelayKey, publicIdentifier);

        let joinedProfile = await getRelayProfileByKey(fallbackRelayKey);
        if (joinedProfile && !joinedProfile.public_identifier) {
          joinedProfile.public_identifier = publicIdentifier;
          await saveRelayProfile(joinedProfile);
        }

        await updateRelayAuthToken(fallbackRelayKey, userPubkey, inviteToken);

        let relayManager = null;
        try {
          const { activeRelays } = await import('./hyperpipe-relay-manager-adapter.mjs');
          relayManager = activeRelays.get(fallbackRelayKey);
          if (relayManager?.relay?.update) {
            const updateStart = Date.now();
            const preUpdateStats = collectRelayUpdateStats(relayManager.relay);
            if (typeof global.syncActiveRelayCoreRefs === 'function' && coreRefsForJoin?.length) {
              try {
              const syncSummary = await global.syncActiveRelayCoreRefs({
                  relayKey: fallbackRelayKey,
                  publicIdentifier,
                  coreRefs: coreRefsForJoin,
                  writerCoreRefs: writerCoreRefsForJoin,
                  reason: 'pre-wait'
                });
              const checkpointRef = fastForward?.key ? normalizeCoreRef(fastForward.key) : null;
              const checkpointInMirror = checkpointRef
                ? normalizeCoreRefList(coreRefsForJoin).includes(checkpointRef)
                : null;
              console.log('[RelayServer] Pre-wait writer sync', {
                  relayKey: fallbackRelayKey,
                  status: syncSummary?.status ?? null,
                  writerAdded: syncSummary?.writerSummary?.added ?? null,
                  writerStatus: syncSummary?.writerSummary?.status ?? null,
                  checkpointInMirror
              });
              } catch (error) {
                console.warn('[RelayServer] Pre-wait writer sync failed', {
                  relayKey: fallbackRelayKey,
                  error: error?.message || error
                });
              }
            }
            // NOTE: We previously attempted a short "sync gate" delay here to avoid waiting too early
            // during cold-sync, but logs showed it commonly times out and only adds latency. Keep a
            // cheap snapshot for debugging and proceed directly to relay.update({ wait: true }).
            try {
              const snapshot = collectRelayGateSnapshot(relayManager.relay);
              const gate = resolveRelaySyncGateReason(snapshot, snapshot);
              const writerSummary = collectRelayProgressSnapshot(relayManager.relay)?.writers || null;
              console.log('[RelayServer] Relay sync gate snapshot', {
                relayKey: fallbackRelayKey,
                reason: inviteFallbackReason,
                gate,
                snapshot,
                writerSummary
              });
              prehydrateRelayCoreRefs({
                relay: relayManager.relay,
                coreRefs: coreRefsForJoin,
                writerRefsHint: writerCoreRefsForJoin,
                relayKey: fallbackRelayKey,
                reason: inviteFallbackReason,
                context: 'pre-update'
              });
            } catch (error) {
              console.warn('[RelayServer] Failed to collect relay sync gate snapshot', {
                relayKey: fallbackRelayKey,
                reason: inviteFallbackReason,
                error: error?.message || error
              });
            }
            const stopProgressLog = startRelayUpdateProgressLogger({
              relay: relayManager.relay,
              relayKey: fallbackRelayKey,
              reason: inviteFallbackReason,
              coreRefs: coreRefsForJoin,
              expectedWriterKey
            });
            console.log('[RelayServer] Starting relay update after join (background)', {
              relayKey: fallbackRelayKey,
              reason: inviteFallbackReason,
              stats: preUpdateStats
            });
            const updateTask = relayManager.relay.update().catch((error) => {
              console.warn('[RelayServer] Relay update failed (background)', {
                relayKey: fallbackRelayKey,
                error: error?.message || error,
                elapsedMs: Date.now() - updateStart,
                stats: collectRelayUpdateStats(relayManager.relay)
              });
            }).finally(() => {
              stopProgressLog();
            });
            updateTask.then(() => {
              console.log('[RelayServer] Relay update complete after join (background)', {
                relayKey: fallbackRelayKey,
                elapsedMs: Date.now() - updateStart,
                writable: relayManager.relay?.writable ?? null,
                activeWriters: relayManager.relay?.activeWriters?.size ?? null,
                stats: collectRelayUpdateStats(relayManager.relay)
              });
            });
          }
        } catch (err) {
          console.warn('[RelayServer] Relay sync wait failed after join', {
            relayKey: fallbackRelayKey,
            error: err?.message || err
          });
        }

        let relayWaitResult = null;
        const hasBypassWriterMaterial = Boolean(writerSecret && (expectedWriterKey || writerCore || writerCoreHex));
        const relayAlreadyWritable = relayManager?.relay?.writable === true;
        const canBypassWait = hasBypassWriterMaterial && relayAlreadyWritable;
        emitWriterActivationPrewaitTrace({
          relayKey: fallbackRelayKey,
          publicIdentifier,
          mode: inviteFallbackMode,
          reason: inviteFallbackReason,
          expectedWriterKey,
          joinTraceId: scopedJoinTraceId,
          joinAttemptId: scopedJoinAttemptId,
          joinRequestId: scopedJoinRequestId,
          writerLeaseId: normalizedWriterLeaseId,
          writerCommitCheckpoint: normalizedWriterCommitCheckpoint,
          fastForward
        });
        if (canBypassWait) {
          let expectedWriterActive = null;
          try {
            const activeWriters = relayManager?.relay?.activeWriters;
            if (expectedWriterKey && activeWriters?.has) {
              expectedWriterActive = activeWriters.has(expectedWriterKey);
            }
          } catch (_) {
            expectedWriterActive = null;
          }
          relayWaitResult = {
            ok: true,
            writable: relayManager?.relay?.writable ?? false,
            expectedWriterActive,
            elapsedMs: 0,
            bypassed: true
          };
          console.log('[RelayServer] Bypassing relay-writable wait (writer secret present)', {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            expectedWriterActive,
            writable: relayWaitResult.writable
          });
        } else {
          if (hasBypassWriterMaterial && !relayAlreadyWritable) {
            console.log('[RelayServer] Relay-writable bypass suppressed (relay not yet writable)', {
              relayKey: fallbackRelayKey,
              publicIdentifier,
              writable: relayManager?.relay?.writable ?? null
            });
          }
          relayWaitResult = await waitForRelayWriterActivation({
            relayKey: fallbackRelayKey,
            expectedWriterKey,
            timeoutMs: resolvedJoinWritableTimeoutMs,
            reason: inviteFallbackReason,
            writerLeaseId: normalizedWriterLeaseId,
            writerCommitCheckpoint: normalizedWriterCommitCheckpoint
          });
        }
        console.log('[RelayServer] Invite fallback writer wait result', {
          relayKey: fallbackRelayKey,
          ok: relayWaitResult?.ok ?? null,
          writable: relayWaitResult?.writable ?? null,
          expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
          elapsedMs: relayWaitResult?.elapsedMs ?? null,
          bypassed: relayWaitResult?.bypassed ?? false
        });
        emitJoinCheckpointTrace('writer-activation-result', {
          joinTraceId: scopedJoinTraceId,
          joinAttemptId: scopedJoinAttemptId,
          relayKey: fallbackRelayKey,
          publicIdentifier,
          mode: inviteFallbackMode,
          writerLeaseId: normalizedWriterLeaseId,
          writerCommitCheckpoint: summarizeWriterCommitCheckpoint(normalizedWriterCommitCheckpoint),
          ok: relayWaitResult?.ok ?? null,
          writable: relayWaitResult?.writable ?? null,
          expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
          elapsedMs: relayWaitResult?.elapsedMs ?? null
        });
        const identifierPath = publicIdentifier
          ? publicIdentifier.replace(':', '/')
          : fallbackRelayKey;
        const gatewayBase = buildGatewayWebsocketBase(config);
        const baseUrl = `${gatewayBase}/${identifierPath}`;
        const connectionUrl = inviteToken ? `${baseUrl}?token=${inviteToken}` : baseUrl;
        const resolvedRelayUrl = inviteRelayUrl || connectionUrl;

        if (relayWaitResult?.writable === true && global.sendMessage) {
          console.log('[RelayServer] Emitting relay-writable (invite fallback)', {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            writable: relayWaitResult?.writable ?? null,
            expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null
          });
          const relayWritablePayload = {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            relayUrl: resolvedRelayUrl,
            authToken: inviteToken,
            mode: inviteFallbackMode,
            writable: relayWaitResult?.writable ?? null,
            expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null
          };

          global.sendMessage({
            type: 'relay-writable',
            data: relayWritablePayload
          });

          if (typeof global.onRelayWritable === 'function') {
            try {
              global.onRelayWritable(relayWritablePayload);
            } catch (error) {
              console.warn('[RelayServer] Failed to invoke relay-writable hook:', error?.message || error);
            }
          }
        }
        const relayWritable = relayWaitResult?.writable === true;
        if (!relayWaitResult?.ok || !relayWaitResult?.writable) {
          scheduleLateWriterRecovery({
            relayKey: fallbackRelayKey,
            expectedWriterKey,
            publicIdentifier,
            authToken: inviteToken,
            relayUrl: inviteRelayUrl,
            mode: inviteFallbackMode,
            requireWritable: true,
            reason: inviteFallbackReason
          });
        }

        // If the invite provided a writer core, add it to Autobase.
        const inviteWriterKey = expectedWriterKey || writerCore || null;
        if (inviteWriterKey) {
          try {
            const { activeRelays } = await import('./hyperpipe-relay-manager-adapter.mjs');
            relayManager = relayManager || activeRelays.get(fallbackRelayKey);
            if (relayManager) {
              if (!relayWritable || !relayManager.relay?.writable) {
                console.warn('[RelayServer] Skipping invite writer add (relay not writable)', {
                  relayKey: fallbackRelayKey,
                  relayWritable: relayManager.relay?.writable ?? null,
                  expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null
                });
              } else {
              let writerHex = null;
              try {
                const decoded = HypercoreId.decode(String(inviteWriterKey));
                writerHex = b4a.toString(decoded, 'hex');
              } catch (_) {
                if (/^[0-9a-fA-F]{64}$/.test(String(inviteWriterKey))) writerHex = String(inviteWriterKey);
              }
              if (writerHex && typeof relayManager.addWriter === 'function') {
                await relayManager.addWriter(writerHex).catch((err) => {
                  console.warn('[RelayServer] Failed to add invite writer core during fallback', err?.message || err);
                });
              }
              }
            }
          } catch (err) {
            console.warn('[RelayServer] Failed to add invite writer core during fallback', err?.message || err);
          }
        }

        try {
          const { activeRelays } = await import('./hyperpipe-relay-manager-adapter.mjs');
          relayManager = relayManager || activeRelays.get(fallbackRelayKey);
          const writerKey = relayManager?.relay?.local?.key || relayManager?.relay?.localWriter?.core?.key || null;
          if (relayManager && writerKey) {
            if (!relayWritable || !relayManager.relay?.writable) {
              console.warn('[RelayServer] Skipping local writer add (relay not writable)', {
                relayKey: fallbackRelayKey,
                relayWritable: relayManager.relay?.writable ?? null,
                expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null
              });
            } else {
              const writerHex = b4a.toString(writerKey, 'hex');
              console.log('[RelayServer] Adding local writer to relay during invite fallback', { relayKey: fallbackRelayKey, writer: writerHex.substring(0, 8) });
              await relayManager.addWriter(writerHex).catch((err) => {
                console.warn('[RelayServer] Failed to add writer during invite fallback', err?.message || err);
              });
            }
          }
        } catch (err) {
          console.warn('[RelayServer] Writer bootstrap during invite fallback failed', err?.message || err);
        }
        if (!relayWritable) {
          console.warn('[RelayServer] Relay still not writable after invite fallback; writes will remain disabled', {
            relayKey: fallbackRelayKey
          });
        }

        let mirrorWarmResult = null;
        try {
          mirrorWarmResult = await waitForRelayMirrorWarmGate({
            relayKey: fallbackRelayKey,
            checkpointRef: fastForward?.key || null,
            reason: inviteFallbackReason
          });
          if (mirrorWarmResult?.ok && mirrorWarmResult?.warmed) {
            console.log('[RelayServer] Invite fallback mirror warm gate satisfied', {
              relayKey: fallbackRelayKey,
              publicIdentifier,
              warmReason: mirrorWarmResult?.warmReason || null,
              elapsedMs: mirrorWarmResult?.elapsedMs ?? null
            });
          } else if (mirrorWarmResult?.skipped) {
            console.log('[RelayServer] Invite fallback mirror warm gate skipped', {
              relayKey: fallbackRelayKey,
              publicIdentifier
            });
          } else {
            console.warn('[RelayServer] Invite fallback mirror warm gate incomplete', {
              relayKey: fallbackRelayKey,
              publicIdentifier,
              warmReason: mirrorWarmResult?.warmReason || null,
              writable: mirrorWarmResult?.writable ?? null,
              viewLength: mirrorWarmResult?.viewLength ?? null,
              hasCheckpoint: mirrorWarmResult?.hasCheckpoint ?? null,
              elapsedMs: mirrorWarmResult?.elapsedMs ?? null
            });
          }
        } catch (error) {
          console.warn('[RelayServer] Invite fallback mirror warm gate failed', {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            error: error?.message || error
          });
        }

        if (global.sendMessage) {
          console.log('[RelayServer] Emitting relay-initialized (invite fallback)', {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            writable: relayWaitResult?.writable ?? null,
            expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
            mirrorWarmReason: mirrorWarmResult?.warmReason || null
          });
          global.sendMessage({
            type: 'relay-initialized',
            relayKey: fallbackRelayKey,
            publicIdentifier,
            gatewayUrl: resolvedRelayUrl,
            connectionUrl: resolvedRelayUrl,
            alreadyActive: true,
            requiresAuth: true,
            userAuthToken: inviteToken,
            writable: relayWaitResult?.writable ?? null,
            expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
            mirrorWarmReason: mirrorWarmResult?.warmReason || null,
            timestamp: new Date().toISOString()
          });
        }

        if (global.sendMessage) {
          global.sendMessage({
            type: 'join-auth-success',
            data: {
              publicIdentifier,
              relayKey: fallbackRelayKey,
              authToken: inviteToken,
              relayUrl: inviteRelayUrl || null,
              hostPeer: inviteFallbackHostPeer,
              mode: inviteFallbackMode,
              provisional: false,
              joinAttemptId: scopedJoinAttemptId,
              joinTraceId: scopedJoinTraceId,
              joinRequestId: scopedJoinRequestId
            }
          });
        }
        return {
          ok: true,
          mode: inviteFallbackMode,
          relayKey: fallbackRelayKey,
          publicIdentifier,
          hostPeer: inviteFallbackHostPeer
        };
      }

      if (openJoin) {
        let resolvedRelayKey = inviteRelayKey || null;
        if (!resolvedRelayKey && publicIdentifier) {
          resolvedRelayKey = await getRelayKeyFromPublicIdentifier(publicIdentifier);
        }
        if (!resolvedRelayKey && inviteRelayUrl) {
          try {
            const parsed = new URL(inviteRelayUrl);
            const parts = parsed.pathname.split('/').filter(Boolean);
            const maybeKey = parts[0] || null;
            if (maybeKey && /^[0-9a-fA-F]{64}$/.test(maybeKey)) {
              resolvedRelayKey = maybeKey;
            }
          } catch (_) {
            // ignore
          }
        }
        if (!resolvedRelayKey) {
          throw new Error('Missing relay key for open join fallback; cannot join relay');
        }

        const fallbackRelayKey = resolvedRelayKey;
        const challengeManager = getChallengeManager();
        const provisionalToken = challengeManager.generateAuthToken(userPubkey);
        console.log('[RelayServer] Falling back to open join offline path', {
          relayKey: fallbackRelayKey,
          publicIdentifier
        });

        assertTokenOwnerMatchesExpectedPubkey({
          relayKey: fallbackRelayKey,
          publicIdentifier,
          authToken: provisionalToken,
          expectedPubkey: userPubkey,
          context: 'open-offline-fallback'
        });

        await preseedJoinMetadata({
          relayKey: fallbackRelayKey,
          publicIdentifier,
          userPubkey,
          authToken: provisionalToken,
          storageDir: join(config.storage || './data', 'relays', fallbackRelayKey),
          reason: 'open-offline'
        });

        await joinRelayManager({
          relayKey: fallbackRelayKey,
          config,
          fileSharing,
          isOpen,
          publicIdentifier,
          authToken: provisionalToken,
          writerSecret,
          writerCore,
          writerCoreHex,
          autobaseLocal,
          blindPeer,
          coreRefs: coreRefsForJoin,
          fastForward,
          expectedWriterKey,
          suppressInitMessage: true,
          useSharedCorestore: true
        });
        await applyPendingAuthUpdates(updateRelayAuthToken, fallbackRelayKey, publicIdentifier);

        let joinedProfile = await getRelayProfileByKey(fallbackRelayKey);
        if (joinedProfile && !joinedProfile.public_identifier) {
          joinedProfile.public_identifier = publicIdentifier;
          await saveRelayProfile(joinedProfile);
        }

        await updateRelayAuthToken(fallbackRelayKey, userPubkey, provisionalToken);

        emitWriterActivationPrewaitTrace({
          relayKey: fallbackRelayKey,
          publicIdentifier,
          mode: 'open-offline',
          reason: 'open-offline',
          expectedWriterKey,
          joinTraceId: scopedJoinTraceId,
          joinAttemptId: scopedJoinAttemptId,
          joinRequestId: scopedJoinRequestId,
          writerLeaseId: normalizedWriterLeaseId,
          writerCommitCheckpoint: normalizedWriterCommitCheckpoint,
          fastForward
        });
        const relayWaitResult = await waitForRelayWriterActivation({
          relayKey: fallbackRelayKey,
          expectedWriterKey,
          timeoutMs: resolvedJoinWritableTimeoutMs,
          reason: 'open-offline',
          writerLeaseId: normalizedWriterLeaseId,
          writerCommitCheckpoint: normalizedWriterCommitCheckpoint
        });
        console.log('[RelayServer] Open join offline writer wait result', {
          relayKey: fallbackRelayKey,
          ok: relayWaitResult?.ok ?? null,
          writable: relayWaitResult?.writable ?? null,
          expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
          elapsedMs: relayWaitResult?.elapsedMs ?? null
        });
        emitJoinCheckpointTrace('writer-activation-result', {
          joinTraceId: scopedJoinTraceId,
          joinAttemptId: scopedJoinAttemptId,
          relayKey: fallbackRelayKey,
          publicIdentifier,
          mode: 'open-offline',
          writerLeaseId: normalizedWriterLeaseId,
          writerCommitCheckpoint: summarizeWriterCommitCheckpoint(normalizedWriterCommitCheckpoint),
          ok: relayWaitResult?.ok ?? null,
          writable: relayWaitResult?.writable ?? null,
          expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
          elapsedMs: relayWaitResult?.elapsedMs ?? null
        });
        const identifierPath = publicIdentifier
          ? publicIdentifier.replace(':', '/')
          : fallbackRelayKey;
        const gatewayBase = buildGatewayWebsocketBase(config);
        const baseUrl = `${gatewayBase}/${identifierPath}`;
        const connectionUrl = provisionalToken ? `${baseUrl}?token=${provisionalToken}` : baseUrl;
        const resolvedRelayUrl = inviteRelayUrl || connectionUrl;

        if (relayWaitResult?.writable === true && global.sendMessage) {
          console.log('[RelayServer] Emitting relay-writable (open join offline)', {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            writable: relayWaitResult?.writable ?? null,
            expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null
          });
          const relayWritablePayload = {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            relayUrl: resolvedRelayUrl,
            authToken: provisionalToken,
            mode: 'open-offline',
            writable: relayWaitResult?.writable ?? null,
            expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null
          };

          global.sendMessage({
            type: 'relay-writable',
            data: relayWritablePayload
          });

          if (typeof global.onRelayWritable === 'function') {
            try {
              global.onRelayWritable(relayWritablePayload);
            } catch (error) {
              console.warn('[RelayServer] Failed to invoke relay-writable hook:', error?.message || error);
            }
          }
        }

        if (!relayWaitResult?.ok || !relayWaitResult?.writable) {
          scheduleLateWriterRecovery({
            relayKey: fallbackRelayKey,
            expectedWriterKey,
            publicIdentifier,
            authToken: provisionalToken,
            relayUrl: resolvedRelayUrl,
            mode: 'open-offline',
            requireWritable: true,
            reason: 'open-offline'
          });
        }

        let mirrorWarmResult = null;
        try {
          mirrorWarmResult = await waitForRelayMirrorWarmGate({
            relayKey: fallbackRelayKey,
            checkpointRef: fastForward?.key || null,
            reason: 'open-offline'
          });
          if (mirrorWarmResult?.ok && mirrorWarmResult?.warmed) {
            console.log('[RelayServer] Open join offline mirror warm gate satisfied', {
              relayKey: fallbackRelayKey,
              publicIdentifier,
              warmReason: mirrorWarmResult?.warmReason || null,
              elapsedMs: mirrorWarmResult?.elapsedMs ?? null
            });
          } else if (mirrorWarmResult?.skipped) {
            console.log('[RelayServer] Open join offline mirror warm gate skipped', {
              relayKey: fallbackRelayKey,
              publicIdentifier
            });
          } else {
            console.warn('[RelayServer] Open join offline mirror warm gate incomplete', {
              relayKey: fallbackRelayKey,
              publicIdentifier,
              warmReason: mirrorWarmResult?.warmReason || null,
              writable: mirrorWarmResult?.writable ?? null,
              viewLength: mirrorWarmResult?.viewLength ?? null,
              hasCheckpoint: mirrorWarmResult?.hasCheckpoint ?? null,
              elapsedMs: mirrorWarmResult?.elapsedMs ?? null
            });
          }
        } catch (error) {
          console.warn('[RelayServer] Open join offline mirror warm gate failed', {
            relayKey: fallbackRelayKey,
            publicIdentifier,
            error: error?.message || error
          });
        }

        if (global.sendMessage) {
          global.sendMessage({
            type: 'relay-initialized',
            relayKey: fallbackRelayKey,
            publicIdentifier,
            gatewayUrl: resolvedRelayUrl,
            connectionUrl: resolvedRelayUrl,
            alreadyActive: true,
            requiresAuth: true,
            userAuthToken: provisionalToken,
            writable: relayWaitResult?.writable ?? null,
            expectedWriterActive: relayWaitResult?.expectedWriterActive ?? null,
            mirrorWarmReason: mirrorWarmResult?.warmReason || null,
            timestamp: new Date().toISOString()
          });
        }

      if (global.sendMessage) {
        global.sendMessage({
          type: 'join-auth-success',
          data: {
            publicIdentifier,
            relayKey: fallbackRelayKey,
            authToken: provisionalToken,
            relayUrl: resolvedRelayUrl || null,
            hostPeer: blindPeerKey || null,
            mode: 'open-offline',
            provisional: true,
            joinAttemptId: scopedJoinAttemptId,
            joinTraceId: scopedJoinTraceId,
            joinRequestId: scopedJoinRequestId
          }
        });
      }
        return {
          ok: true,
          mode: 'open-offline',
          relayKey: fallbackRelayKey,
          publicIdentifier,
          hostPeer: blindPeerKey || null
        };
      }

      throw lastJoinError || new Error('Failed to contact relay host');
    }

    console.log('[RelayServer] Received challenge from peer:', challengePayload);

    const { challenge } = challengePayload;

    console.log(`[RelayServer] Challenge: ${challenge.substring(0, 16)}...`);

    if (!challenge || !relayPubkey) {
      throw new Error('Invalid challenge response from relay host. Missing required fields.');
    }

    // Send 'verify' progress update to the desktop UI
    if (global.sendMessage) {
      global.sendMessage({
        type: 'join-auth-progress',
        data: {
          publicIdentifier,
          status: 'verify',
          joinAttemptId: scopedJoinAttemptId,
          joinTraceId: scopedJoinTraceId,
          joinRequestId: scopedJoinRequestId
        }
      });
    }

    // Compute the shared secret using ECDH
    console.log('[RelayServer] Computing shared secret for ECDH...');
    let sharedSecret = await nobleSecp256k1.getSharedSecret(
      userNsec,
      '02' + relayPubkey, // Add compression prefix for noble-secp256k1
      true
    );
    // noble-secp256k1 may return a 33 byte buffer with a leading 0x00.
    // Trim it so both sides derive the same 32 byte AES key.
    if (sharedSecret.length === 33) sharedSecret = sharedSecret.slice(1);
    const keyBuffer = b4a.from(sharedSecret);
    console.log(`[RelayServer] Shared key computed: ${keyBuffer.toString('hex').substring(0, 8)}...`);

    // Encrypt the challenge using AES-256-CBC
    const iv = crypto.randomBytes(16);
    const encrypted = nobleSecp256k1.aes.encrypt(challenge, keyBuffer, iv);
    const ciphertext = b4a.from(encrypted).toString('base64');
    const ivBase64 = b4a.from(iv).toString('base64');
    console.log('[RelayServer] Challenge encrypted.');
    console.log(`[RelayServer] Ciphertext length: ${ciphertext.length}`);
    console.log(`[RelayServer] IV base64: ${ivBase64}`);

    const verifyTimeoutMs = Number.isFinite(DIRECT_JOIN_VERIFY_TIMEOUT_MS)
      ? Math.max(1000, Number(DIRECT_JOIN_VERIFY_TIMEOUT_MS))
      : null;
    console.log('[RelayServer] Sending verification request directly to peer', {
      peer: selectedPeerKey.substring(0, 8),
      timeoutMs: verifyTimeoutMs,
      timeoutDisabled: !Number.isFinite(verifyTimeoutMs)
    });

    const verifyStartedAt = Date.now();
    const verifyRequest = joinProtocol.sendRequest({
      method: 'POST',
      path: `/verify-ownership`,
      headers: { 'content-type': 'application/json' },
      body: Buffer.from(JSON.stringify({
        pubkey: userPubkey,
        ciphertext,
        iv: ivBase64
      }))
    });
    const verifyResponseRaw = Number.isFinite(verifyTimeoutMs)
      ? await withOperationTimeout(
        verifyRequest,
        verifyTimeoutMs,
        'verify-ownership request'
      )
      : await verifyRequest;
    console.log('[RelayServer] Verification response received', {
      peer: selectedPeerKey.substring(0, 8),
      elapsedMs: Date.now() - verifyStartedAt,
      statusCode: verifyResponseRaw?.statusCode || 200
    });

    if ((verifyResponseRaw.statusCode || 200) >= 400) {
      const responseBody = toBuffer(verifyResponseRaw.body).toString('utf8');
      throw new Error(`Peer verification failed with status ${verifyResponseRaw.statusCode}: ${responseBody}`);
    }

    const verifyResponse = parseJsonBody(verifyResponseRaw.body) || {};

    console.log('[RelayServer] Received verification response from peer:', verifyResponse);
    if (verifyResponse && verifyResponse.success === false) {
      console.log(`[RelayServer] Verification failed: ${verifyResponse.error}`);
    }

    // Treat verify response as the final result
    if (global.sendMessage) {
      global.sendMessage({
        type: 'join-auth-progress',
        data: {
          publicIdentifier,
          status: 'complete',
          joinAttemptId: scopedJoinAttemptId,
          joinTraceId: scopedJoinTraceId,
          joinRequestId: scopedJoinRequestId
        }
      });
    }

    const {
      authToken,
      relayUrl,
      relayKey,
      publicIdentifier: returnedIdentifier,
      writerCore: responseWriterCore,
      writerCoreHex: responseWriterCoreHex,
      autobaseLocal: responseAutobaseLocal,
      writerSecret: responseWriterSecret
    } = verifyResponse;
    const finalIdentifier = returnedIdentifier || publicIdentifier;
    const finalWriterCore = responseWriterCore || writerCore;
    const finalWriterSecret = responseWriterSecret || writerSecret;
    const finalWriterCoreHex =
      responseWriterCoreHex ||
      responseAutobaseLocal ||
      writerCoreHex ||
      autobaseLocal ||
      null;
    const directExpectedWriter = resolveExpectedWriterKey({
      writerCoreHex: finalWriterCoreHex,
      autobaseLocal: null,
      writerCore: finalWriterCore
    });
    const finalExpectedWriterKey = directExpectedWriter.expectedWriterKey;
    const finalExpectedWriterSource = directExpectedWriter.source;
    const finalExpectedWriterKeyHex = resolveWriterKeyHex(finalExpectedWriterKey);
    const canonicalRelayUrl = buildCanonicalRelayUrl(finalIdentifier, authToken, config);
    if (relayUrl && canonicalRelayUrl && relayUrl !== canonicalRelayUrl) {
      console.log('[RelayServer] Normalizing relay URL from verify response', {
        publicIdentifier: finalIdentifier,
        relayKey,
        remoteRelayUrl: String(relayUrl).slice(0, 120),
        canonicalRelayUrl: String(canonicalRelayUrl).slice(0, 120)
      });
    }
    let directCoreRefs = coreRefsForJoin;
    const finalCoreRef = normalizeCoreRefString(finalExpectedWriterKey);
    if (finalCoreRef && !directCoreRefs.includes(finalCoreRef)) {
      directCoreRefs = [...coreRefsForJoin, finalCoreRef];
    }

    console.log('[RelayServer][WriterMaterial] Direct join writer material', {
      publicIdentifier: finalIdentifier,
      relayKey,
      writerCore: finalWriterCore,
      writerCoreHex: finalWriterCoreHex,
      autobaseLocal: finalWriterCoreHex,
      writerSecret: finalWriterSecret,
      expectedWriterKey: finalExpectedWriterKey,
      expectedWriterSource: finalExpectedWriterSource,
      expectedWriterKeyHex: finalExpectedWriterKeyHex,
      coreRefs: directCoreRefs
    });
    if (!authToken || !relayKey || !canonicalRelayUrl) {
      throw new Error('Final response from relay host missing authToken, relayKey, or resolvable relayUrl');
    }

    assertTokenOwnerMatchesExpectedPubkey({
      relayKey,
      publicIdentifier: finalIdentifier,
      authToken,
      expectedPubkey: userPubkey,
      context: 'direct-join-verify-response'
    });

    await preseedJoinMetadata({
      relayKey,
      publicIdentifier: finalIdentifier,
      userPubkey,
      authToken,
      storageDir: join(config.storage || './data', 'relays', relayKey),
      reason: 'direct-join'
    });

    // Join the relay locally so we have a profile and key mapping
    await joinRelayManager({
      relayKey,
      config,
      fileSharing,
      isOpen,
      publicIdentifier: finalIdentifier,
      authToken,
      writerSecret: finalWriterSecret,
      writerCore: finalWriterCore,
      writerCoreHex: finalWriterCoreHex,
      autobaseLocal: finalWriterCoreHex,
      blindPeer,
      coreRefs: directCoreRefs,
      fastForward,
      expectedWriterKey: finalExpectedWriterKey,
      // Prevent early renderer websocket subscription attempts before join finalize completes.
      suppressInitMessage: true
    });
    await applyPendingAuthUpdates(updateRelayAuthToken, relayKey, finalIdentifier);

    // Ensure the joined relay profile has the public identifier recorded
    let joinedProfile = await getRelayProfileByKey(relayKey);
    if (joinedProfile && !joinedProfile.public_identifier) {
      joinedProfile.public_identifier = finalIdentifier;
      await saveRelayProfile(joinedProfile);
    }

    // Persist the auth token and subnet hash to the local relay profile
    console.log(`[RelayServer] Persisting auth token for ${userPubkey.substring(0, 8)}...`);
    await updateRelayAuthToken(relayKey, userPubkey, authToken);

    // Wait for the relay to become writable or the expected writer to activate before announcing membership.
    // In gateway-disabled open-join mode, completion is blocked until writable to avoid false "success".
    emitWriterActivationPrewaitTrace({
      relayKey,
      publicIdentifier: finalIdentifier,
      mode: 'direct-join',
      reason: 'direct-join',
      expectedWriterKey: finalExpectedWriterKey,
      joinTraceId: scopedJoinTraceId,
      joinAttemptId: scopedJoinAttemptId,
      joinRequestId: scopedJoinRequestId,
      writerLeaseId: normalizedWriterLeaseId,
      writerCommitCheckpoint: normalizedWriterCommitCheckpoint,
      fastForward
    });
    let directWaitResult = await waitForRelayWriterActivation({
      relayKey,
      expectedWriterKey: finalExpectedWriterKey,
      timeoutMs: DIRECT_JOIN_WRITABLE_TIMEOUT_MS,
      reason: 'direct-join',
      writerLeaseId: normalizedWriterLeaseId,
      writerCommitCheckpoint: normalizedWriterCommitCheckpoint
    });
    console.log('[RelayServer] Direct join writer wait result', {
      relayKey,
      ok: directWaitResult?.ok ?? null,
      writable: directWaitResult?.writable ?? null,
      expectedWriterActive: directWaitResult?.expectedWriterActive ?? null,
      elapsedMs: directWaitResult?.elapsedMs ?? null
    });
    emitJoinCheckpointTrace('writer-activation-result', {
      joinTraceId: scopedJoinTraceId,
      joinAttemptId: scopedJoinAttemptId,
      relayKey,
      publicIdentifier: finalIdentifier,
      mode: 'direct-join',
      writerLeaseId: normalizedWriterLeaseId,
      writerCommitCheckpoint: summarizeWriterCommitCheckpoint(normalizedWriterCommitCheckpoint),
      ok: directWaitResult?.ok ?? null,
      writable: directWaitResult?.writable ?? null,
      expectedWriterActive: directWaitResult?.expectedWriterActive ?? null,
      elapsedMs: directWaitResult?.elapsedMs ?? null
    });
    const enforceWritableBeforeCompletion = Boolean(openJoin && gatewayDisabled);
    if (enforceWritableBeforeCompletion && (!directWaitResult?.ok || !directWaitResult?.writable)) {
      console.warn('[RelayServer] Direct join writable gate not satisfied; waiting before completion', {
        relayKey,
        publicIdentifier: finalIdentifier,
        gatewayMode: normalizedGatewayMode,
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null
      });
      emitWriterActivationPrewaitTrace({
        relayKey,
        publicIdentifier: finalIdentifier,
        mode: 'direct-join-finalize',
        reason: 'direct-join-finalize',
        expectedWriterKey: finalExpectedWriterKey,
        joinTraceId: scopedJoinTraceId,
        joinAttemptId: scopedJoinAttemptId,
        joinRequestId: scopedJoinRequestId,
        writerLeaseId: normalizedWriterLeaseId,
        writerCommitCheckpoint: normalizedWriterCommitCheckpoint,
        fastForward
      });
      directWaitResult = await waitForRelayWriterActivation({
        relayKey,
        expectedWriterKey: finalExpectedWriterKey,
        timeoutMs: LATE_WRITER_RECOVERY_TIMEOUT_MS,
        reason: 'direct-join-finalize',
        writerLeaseId: normalizedWriterLeaseId,
        writerCommitCheckpoint: normalizedWriterCommitCheckpoint
      });
      console.log('[RelayServer] Direct join finalize writable wait result', {
        relayKey,
        ok: directWaitResult?.ok ?? null,
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null,
        elapsedMs: directWaitResult?.elapsedMs ?? null
      });
      emitJoinCheckpointTrace('writer-activation-result', {
        joinTraceId: scopedJoinTraceId,
        joinAttemptId: scopedJoinAttemptId,
        relayKey,
        publicIdentifier: finalIdentifier,
        mode: 'direct-join-finalize',
        writerLeaseId: normalizedWriterLeaseId,
        writerCommitCheckpoint: summarizeWriterCommitCheckpoint(normalizedWriterCommitCheckpoint),
        ok: directWaitResult?.ok ?? null,
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null,
        elapsedMs: directWaitResult?.elapsedMs ?? null
      });
    }
    if (directWaitResult?.writable === true && global.sendMessage) {
      console.log('[RelayServer] Emitting relay-writable (direct join)', {
        relayKey,
        publicIdentifier: finalIdentifier,
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null
      });
      const relayWritablePayload = {
        relayKey,
        publicIdentifier: finalIdentifier,
        relayUrl: canonicalRelayUrl,
        authToken,
        mode: 'direct-join',
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null
      };

      global.sendMessage({
        type: 'relay-writable',
        data: relayWritablePayload
      });

      if (typeof global.onRelayWritable === 'function') {
        try {
          global.onRelayWritable(relayWritablePayload);
        } catch (error) {
          console.warn('[RelayServer] Failed to invoke relay-writable hook:', error?.message || error);
        }
      }
    }
    if (!directWaitResult?.ok || !directWaitResult?.writable) {
      if (enforceWritableBeforeCompletion) {
        throw new Error('Direct join writer activation timeout before completion');
      }
      console.warn('[RelayServer] Relay did not become writable before membership publish', {
        relayKey,
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null
      });
      if (finalExpectedWriterKey) {
        scheduleLateWriterRecovery({
          relayKey,
          expectedWriterKey: finalExpectedWriterKey,
          publicIdentifier: finalIdentifier,
          authToken,
          relayUrl: canonicalRelayUrl,
          mode: 'direct-join',
          requireWritable: true,
          reason: 'direct-join'
        });
      }
    }

    // Publish kind 9000 event to announce the new member
    console.log('[RelayServer] Publishing kind 9000 member add event...');
    await publishMemberAddEvent(finalIdentifier, userPubkey, authToken);

    let directMirrorWarmResult = null;
    try {
      directMirrorWarmResult = await waitForRelayMirrorWarmGate({
        relayKey,
        checkpointRef: fastForward?.key || null,
        reason: 'direct-join'
      });
      if (directMirrorWarmResult?.ok && directMirrorWarmResult?.warmed) {
        console.log('[RelayServer] Direct join mirror warm gate satisfied', {
          relayKey,
          publicIdentifier: finalIdentifier,
          warmReason: directMirrorWarmResult?.warmReason || null,
          elapsedMs: directMirrorWarmResult?.elapsedMs ?? null
        });
      } else if (directMirrorWarmResult?.skipped) {
        console.log('[RelayServer] Direct join mirror warm gate skipped', {
          relayKey,
          publicIdentifier: finalIdentifier
        });
      } else {
        console.warn('[RelayServer] Direct join mirror warm gate incomplete', {
          relayKey,
          publicIdentifier: finalIdentifier,
          warmReason: directMirrorWarmResult?.warmReason || null,
          writable: directMirrorWarmResult?.writable ?? null,
          viewLength: directMirrorWarmResult?.viewLength ?? null,
          hasCheckpoint: directMirrorWarmResult?.hasCheckpoint ?? null,
          elapsedMs: directMirrorWarmResult?.elapsedMs ?? null
        });
      }
    } catch (error) {
      console.warn('[RelayServer] Direct join mirror warm gate failed', {
        relayKey,
        publicIdentifier: finalIdentifier,
        error: error?.message || error
      });
    }

    if (global.sendMessage) {
      console.log('[RelayServer] Emitting relay-initialized (direct join)', {
        relayKey,
        publicIdentifier: finalIdentifier,
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null,
        mirrorWarmReason: directMirrorWarmResult?.warmReason || null
      });
      global.sendMessage({
        type: 'relay-initialized',
        relayKey,
        publicIdentifier: finalIdentifier,
        gatewayUrl: canonicalRelayUrl,
        connectionUrl: canonicalRelayUrl,
        alreadyActive: true,
        requiresAuth: true,
        userAuthToken: authToken,
        writable: directWaitResult?.writable ?? null,
        expectedWriterActive: directWaitResult?.expectedWriterActive ?? null,
        mirrorWarmReason: directMirrorWarmResult?.warmReason || null,
        timestamp: new Date().toISOString()
      });
    }

    // Notify the desktop UI of success
    if (global.sendMessage) {
      global.sendMessage({
        type: 'join-auth-success',
        data: {
          publicIdentifier: finalIdentifier,
          relayKey,
          authToken,
          relayUrl: canonicalRelayUrl,
          hostPeer: selectedPeerKey,
          mode: 'direct-join',
          provisional: false,
          joinAttemptId: scopedJoinAttemptId,
          joinTraceId: scopedJoinTraceId,
          joinRequestId: scopedJoinRequestId
        }
      });
    }

    console.log(`[RelayServer] Join flow for ${finalIdentifier} completed successfully.`);
    return {
      ok: true,
      mode: 'direct-join',
      relayKey,
      publicIdentifier: finalIdentifier,
      hostPeer: selectedPeerKey || null
    };

  } catch (error) {
    const errorMessage = error?.message || String(error);
    const errorCode = error?.code === 'auth-token-owner-mismatch'
      ? 'auth-token-owner-mismatch'
      : /writer-checkpoint-missing/i.test(errorMessage)
        ? 'writer-checkpoint-missing'
      : /timeout/i.test(errorMessage)
        ? 'request-timeout'
        : /closed-join-pending/i.test(errorMessage)
          ? 'closed-join-pending'
          : 'join-auth-failed';
    console.error(`[RelayServer] Error during join authentication for ${publicIdentifier}:`, error);
    if (global.sendMessage) {
      global.sendMessage({
        type: 'join-auth-error',
        data: {
          publicIdentifier,
          error: errorMessage,
          joinAttemptId: scopedJoinAttemptId,
          joinTraceId: scopedJoinTraceId,
          joinRequestId: scopedJoinRequestId
        }
      });
    }
    return {
      ok: false,
      code: errorCode,
      error: errorMessage,
      publicIdentifier: publicIdentifier || null
    };
  } finally {
    releaseJoinAuthAttemptLock(joinAttemptLock.lockKey, joinAttemptLock.attemptId);
  }
}

export async function provisionWriterForInvitee(options = {}) {
  const provisionStartedAt = Date.now();
  const { relayKey, publicIdentifier, skipUpdateWait = false, reason = 'invite-writer' } = options;
  const inviteTraceId = typeof options?.inviteTraceId === 'string' ? options.inviteTraceId.trim() : null;
  const inviteePubkey = typeof options?.inviteePubkey === 'string'
    ? options.inviteePubkey.trim().toLowerCase()
    : null;
  const timing = {
    resolveRelayMs: null,
    addWriterMs: null,
    updateMs: null,
    persistRefsMs: null,
    totalMs: null
  };
  const resolvedRelayKey = relayKey || (publicIdentifier ? await getRelayKeyFromPublicIdentifier(publicIdentifier) : null);
  timing.resolveRelayMs = Date.now() - provisionStartedAt;
  if (!resolvedRelayKey) {
    throw new Error('relayKey or publicIdentifier is required to provision writer');
  }
  const { activeRelays } = await import('./hyperpipe-relay-manager-adapter.mjs');
  const relayManager = activeRelays.get(resolvedRelayKey);
  if (!relayManager || !relayManager.relay) {
    throw new Error('Relay manager not found for provisioning writer');
  }

  const keyPair = crypto.keyPair();
  const writerSigner = HypercoreId.encode(keyPair.publicKey);
  const writerSecret = b4a.toString(keyPair.secretKey, 'hex');
  const writerHex = b4a.toString(keyPair.publicKey, 'hex');
  const writerLeaseId = `wl-${nodeCrypto.randomUUID()}`;
  let writerCore = writerSigner;
  let writerCoreHex = null;
  let writerCoreId = null;
  let writerCommitCheckpoint = null;
  let coreKeyMatchesSigner = null;
  let corestoreId = null;
  let corestorePath = null;

  const relayCorestore = relayManager.store || relayManager.corestore || relayManager.relay?.corestore || relayManager.relay?.store || null;
  corestoreId = relayCorestore?.__ht_id || null;
  corestorePath = relayCorestore?.__ht_storage_path || null;
  const manifestVersion = Number.isInteger(relayCorestore?.manifestVersion)
    ? relayCorestore.manifestVersion
    : 0;
  const { key: derivedKey, error: deriveError } = deriveCoreKeyFromSignerKey(
    keyPair.publicKey,
    manifestVersion
  );
  if (derivedKey) {
    writerCoreHex = b4a.toString(derivedKey, 'hex');
    try {
      writerCoreId = HypercoreId.encode(derivedKey);
    } catch (_) {
      writerCoreId = null;
    }
    if (writerCoreId) {
      writerCore = writerCoreId;
    }
  } else {
    console.warn('[RelayServer] Failed to derive invite writer core key from signer', {
      relayKey: resolvedRelayKey,
      manifestVersion,
      error: deriveError?.message || deriveError
    });
  }

  coreKeyMatchesSigner = writerCoreHex ? writerCoreHex === writerHex : null;
  const writerAddHex = writerCoreHex || writerHex;

  console.log('[RelayServer] Writing invite writer to relay', {
    relayKey: resolvedRelayKey,
    trace: inviteTraceId || null,
    invitee: inviteePubkey ? inviteePubkey.slice(0, 16) : null,
    writer: writerAddHex.slice(0, 16),
    writerSigner: writerHex.slice(0, 16),
    writerCoreHex: writerCoreHex ? writerCoreHex.slice(0, 16) : null,
    writable: relayManager.relay?.writable ?? null,
    skipUpdateWait
  });
  const addWriterStartedAt = Date.now();
  await relayManager.addWriter(writerAddHex);
  timing.addWriterMs = Date.now() - addWriterStartedAt;
  console.log('[RelayServer] Invite writer add committed', {
    relayKey: resolvedRelayKey,
    trace: inviteTraceId || null,
    writer: writerAddHex.slice(0, 16),
    activeWriters: relayManager.relay?.activeWriters?.size ?? null,
    viewVersion: relayManager.relay?.view?.version ?? null,
    elapsedMs: timing.addWriterMs
  });

  try {
    if (typeof relayManager.relay?.update === 'function') {
      const updateStartedAt = Date.now();
      const stopProgressLog = startRelayUpdateProgressLogger({
        relay: relayManager.relay,
        relayKey: resolvedRelayKey,
        reason
      });
      if (skipUpdateWait) {
        relayManager.relay.update().catch((error) => {
          console.warn('[RelayServer] Relay update failed after invite writer (background)', {
            relayKey: resolvedRelayKey,
            error: error?.message || error
          });
        }).finally(() => {
          stopProgressLog();
        });
      } else {
        try {
          await relayManager.relay.update({ wait: true });
        } catch (_) {
          await relayManager.relay.update();
        } finally {
          stopProgressLog();
        }
      }
      timing.updateMs = Date.now() - updateStartedAt;
      console.log('[RelayServer] Invite writer relay update complete', {
        relayKey: resolvedRelayKey,
        trace: inviteTraceId || null,
        elapsedMs: timing.updateMs,
        skipUpdateWait
      });
    }
  } catch (error) {
    console.warn('[RelayServer] Relay update failed after invite writer add', {
      relayKey: resolvedRelayKey,
      trace: inviteTraceId || null,
      error: error?.message || error
    });
  }

  writerCommitCheckpoint = buildWriterCommitCheckpoint(relayManager.relay, {
    relayKey: resolvedRelayKey,
    writerCore: writerCoreHex || writerCore
  });
  console.log('[RelayServer] Invite writer commit checkpoint', {
    relayKey: resolvedRelayKey,
    trace: inviteTraceId || null,
    writerLeaseId,
    checkpoint: summarizeWriterCommitCheckpoint(writerCommitCheckpoint)
  });

  try {
    const persistRefsStartedAt = Date.now();
    const relayIdentifier = publicIdentifier || relayManager?.publicIdentifier || null;
    const autobaseEntries = collectRelayCoreRefsFromAutobase(relayManager.relay);
    const autobaseRefs = normalizeCoreRefList(autobaseEntries);
    const autobaseWriterRefs = normalizeCoreRefList(
      autobaseEntries.filter((entry) => entry?.role && entry.role.startsWith('autobase-writer'))
    );
    const inviteRefs = normalizeCoreRefList([writerCore, writerCoreHex, writerAddHex]);
    const storedRefs = await resolveRelayMirrorCoreRefs(resolvedRelayKey, relayIdentifier, autobaseEntries);
    const mergedCoreRefs = mergeCoreRefLists(storedRefs, autobaseRefs, inviteRefs);
    const mergedWriterRefs = mergeCoreRefLists(autobaseWriterRefs, inviteRefs);
    await updateRelayMirrorCoreRefs(resolvedRelayKey, mergedCoreRefs, {
      publicIdentifier: relayIdentifier
    });
    if (typeof global.syncActiveRelayCoreRefs === 'function') {
      await global.syncActiveRelayCoreRefs({
        relayKey: resolvedRelayKey,
        publicIdentifier: relayIdentifier,
        coreRefs: mergedCoreRefs,
        writerCoreRefs: mergedWriterRefs,
        reason
      });
    }
    timing.persistRefsMs = Date.now() - persistRefsStartedAt;
    console.log('[RelayServer] Persisted invite writer core refs', {
      relayKey: resolvedRelayKey,
      trace: inviteTraceId || null,
      coreRefs: mergedCoreRefs.length,
      elapsedMs: timing.persistRefsMs
    });
  } catch (error) {
    console.warn('[RelayServer] Failed to persist invite writer core refs', {
      relayKey: resolvedRelayKey,
      trace: inviteTraceId || null,
      error: error?.message || error
    });
  }

  console.log('[RelayServer][WriterMaterial] Invite writer material', {
    relayKey: resolvedRelayKey,
    writerLeaseId,
    writerCommitCheckpoint: summarizeWriterCommitCheckpoint(writerCommitCheckpoint),
    writerCore,
    writerCoreHex,
    writerCoreId,
    writerSigner,
    autobaseLocal: writerCoreHex,
    writerSecret,
    writerSignerHex: writerHex,
    writerAddHex,
    coreKeyMatchesSigner,
    corestoreId,
    corestorePath,
    manifestVersion
  });

  console.log('[RelayServer] Provisioned writer for invitee', {
    relayKey: resolvedRelayKey,
    trace: inviteTraceId || null,
    invitee: inviteePubkey ? inviteePubkey.slice(0, 16) : null,
    writerCore,
    writerSecretPreview: writerSecret ? `${writerSecret.slice(0, 8)}...` : null
  });
  timing.totalMs = Date.now() - provisionStartedAt;
  console.log('[RelayServer] Invite writer provisioning timing', {
    relayKey: resolvedRelayKey,
    trace: inviteTraceId || null,
    timing
  });

  return {
    relayKey: resolvedRelayKey,
    writerLeaseId,
    writerCommitCheckpoint,
    writerCore,
    writerCoreHex,
    autobaseLocal: writerCoreHex,
    writerSecret
  };
}

export async function disconnectRelay(relayKey) {
  console.log('[RelayServer] Disconnecting relay via adapter:', relayKey);
  const result = await disconnectRelayManager(relayKey);
  
  if (result.success) {
    await updateHealthState(); // Added await
    
    // Update gateway if connected
    if (config.registerWithGateway && gatewayConnection) {
      try {
        await registerWithGateway();
      } catch (regError) {
        console.error('[RelayServer] Failed to notify gateway after relay disconnect (adapter):', regError.message);
      }
    }
  }
  
  return result;
}

export async function shutdownRelayServer() {
  relayServerShuttingDown = true;
  console.log('[RelayServer] ========================================');
  console.log('[RelayServer] SHUTTING DOWN');
  console.log('[RelayServer] Timestamp:', new Date().toISOString());
  
  // Clear registration interval
  if (gatewayRegistrationInterval) {
    clearInterval(gatewayRegistrationInterval);
    gatewayRegistrationInterval = null;
  }

  if (healthMonitorTimer) {
    clearInterval(healthMonitorTimer);
    healthMonitorTimer = null;
  }
  
  // Clean up all active relays
  await cleanupRelays();
  
  // Destroy swarm
  if (swarm) {
    console.log('[RelayServer] Destroying Hyperswarm instance');
    await swarm.destroy();
    swarm = null;
  }
  
  console.log('[RelayServer] Shutdown complete');
  console.log('[RelayServer] ========================================');
}

// Export for testing
export { config, healthState, getActiveRelays, parseNostrMessagePayload };
