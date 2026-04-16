import express from 'express';
import WebSocket from 'ws';
import url from 'node:url';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { schnorr } from '@noble/curves/secp256k1.js';

import LocalGatewayServer from './LocalGatewayServer.mjs';
import {
  EnhancedHyperswarmPool,
  checkPeerHealthWithHyperswarm,
  forwardRequestToPeer,
  forwardMessageToPeerHyperswarm,
  getEventsFromPeerHyperswarm,
  forwardJoinRequestToPeer,
  forwardCallbackToPeer,
  requestFileFromPeer,
  requestPfpFromPeer
} from './HyperswarmClient.mjs';
import PublicGatewayRegistrar from './PublicGatewayRegistrar.mjs';
import PublicGatewayAuthClient from './PublicGatewayAuthClient.mjs';
import PublicGatewayControlClient from './PublicGatewayControlClient.mjs';
import PublicGatewayDiscoveryClient from './PublicGatewayDiscoveryClient.mjs';
import PublicGatewayRelayClient from './PublicGatewayRelayClient.mjs';
import PublicGatewayHyperbeeAdapter from '@squip/hyperpipe-bridge/public-gateway/PublicGatewayHyperbeeAdapter';
import { activeRelays as relayManagerMap } from '../hyperpipe-relay-manager-adapter.mjs';
import { getRelayAuthStore } from '../relay-auth-store.mjs';
import { updatePublicGatewaySettings } from '@squip/hyperpipe-bridge/config/PublicGatewaySettings';
import { verifyOperatorAttestation } from '@squip/hyperpipe-bridge/public-gateway/OperatorAttestation';
import HypercoreId from 'hypercore-id-encoding';
import { resolveRelayMirrorCoreRefs } from '../relay-core-refs-store.mjs';
import { getFile } from '../hyperdrive-manager.mjs';

const MAX_LOG_ENTRIES = 500;
const DEFAULT_PORT = 8443;
const PUBLIC_GATEWAY_RELAY_KEY = 'public-gateway:hyperbee';
const PUBLIC_GATEWAY_RELAY_PATH = 'relay';
const PUBLIC_GATEWAY_RELAY_PATH_ALIASES = ['public-gateway/hyperbee'];
const PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED = false;

function guessContentType(fileName = '') {
  const lower = typeof fileName === 'string' ? fileName.toLowerCase() : '';
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.gif')) return 'image/gif';
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.svg')) return 'image/svg+xml';
  if (lower.endsWith('.mp4')) return 'video/mp4';
  if (lower.endsWith('.webm')) return 'video/webm';
  if (lower.endsWith('.mp3')) return 'audio/mpeg';
  if (lower.endsWith('.m4a')) return 'audio/mp4';
  if (lower.endsWith('.wav')) return 'audio/wav';
  if (lower.endsWith('.ogg')) return 'audio/ogg';
  if (lower.endsWith('.flac')) return 'audio/flac';
  if (lower.endsWith('.pdf')) return 'application/pdf';
  if (lower.endsWith('.json')) return 'application/json; charset=utf-8';
  if (lower.endsWith('.js')) return 'text/javascript; charset=utf-8';
  if (lower.endsWith('.mjs')) return 'text/javascript; charset=utf-8';
  if (lower.endsWith('.css')) return 'text/css; charset=utf-8';
  if (lower.endsWith('.csv')) return 'text/csv; charset=utf-8';
  if (lower.endsWith('.md')) return 'text/markdown; charset=utf-8';
  if (lower.endsWith('.html') || lower.endsWith('.htm')) return 'text/html; charset=utf-8';
  if (lower.endsWith('.txt')) return 'text/plain; charset=utf-8';
  return 'application/octet-stream';
}

function applyDriveCorsHeaders(res, extraHeaders = {}) {
  const headers = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,HEAD,OPTIONS',
    'access-control-allow-headers': 'Content-Type, Range',
    'access-control-expose-headers': 'Content-Length, Content-Range, Accept-Ranges',
    'cross-origin-resource-policy': 'cross-origin',
    ...extraHeaders
  };

  Object.entries(headers).forEach(([key, value]) => {
    if (value === undefined || value === null) return;
    res.setHeader(key, value);
  });
}

function isHtmlDriveRequest(fileName = '') {
  return typeof fileName === 'string' && /\.html?$/i.test(fileName);
}

function readHeaderValue(headers, name) {
  if (!headers || typeof headers !== 'object') return null;
  const target = String(name || '').toLowerCase();
  const entry = Object.entries(headers).find(([key]) => String(key).toLowerCase() === target);
  if (!entry) return null;
  const value = entry[1];
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).join(', ');
  }
  if (typeof value === 'number') {
    return String(value);
  }
  return typeof value === 'string' ? value : null;
}

function summarizeDriveHeaders(headers) {
  return {
    contentType: readHeaderValue(headers, 'content-type'),
    contentSecurityPolicy: readHeaderValue(headers, 'content-security-policy'),
    crossOriginResourcePolicy: readHeaderValue(headers, 'cross-origin-resource-policy'),
    cacheControl: readHeaderValue(headers, 'cache-control'),
    server: readHeaderValue(headers, 'server')
  };
}

function cloneJson(value) {
  return value && typeof value === 'object'
    ? JSON.parse(JSON.stringify(value))
    : value;
}

class MessageQueue {
  constructor() {
    this.queue = [];
    this.processing = false;
  }

  async enqueue(message, handler) {
    this.queue.push({ message, handler });
    if (!this.processing) {
      this.processing = true;
      while (this.queue.length) {
        const { message: msg, handler: cb } = this.queue.shift();
        try {
          await cb(msg);
        } catch (error) {
          // eslint-disable-next-line no-console
          console.error('[GatewayService] Message handler error:', error);
        }
      }
      this.processing = false;
    }
  }
}

class PeerHealthManager {
  constructor(cleanupThreshold = 5 * 60 * 1000) {
    this.healthChecks = new Map();
    this.checkLocks = new Map();
    this.failureCount = new Map();
    this.cleanupThreshold = cleanupThreshold;
    this.circuitBreakerThreshold = 3;
    this.circuitBreakerTimeout = 5 * 60 * 1000;
    this.metrics = {
      totalChecks: 0,
      failedChecks: 0,
      recoveredPeers: 0,
      lastMetricsReset: Date.now()
    };
  }

  async checkPeerHealth(peer, connectionPool) {
    if (this.checkLocks.get(peer.publicKey)) {
      return this.isPeerHealthy(peer.publicKey);
    }

    this.checkLocks.set(peer.publicKey, true);
    const now = Date.now();
    this.metrics.totalChecks++;

    try {
      if (peer.mode === 'hyperswarm') {
        const connection = connectionPool.connections.get(peer.publicKey);
        if (connection && connection.connected) {
          try {
            const isHealthy = await checkPeerHealthWithHyperswarm(peer, connectionPool);
            if (isHealthy) {
              peer.lastSeen = now;
              this.healthChecks.set(peer.publicKey, {
                lastCheck: now,
                status: 'healthy',
                responseTime: Date.now() - now
              });

              if (this.failureCount.get(peer.publicKey)) {
                this.metrics.recoveredPeers++;
                this.failureCount.delete(peer.publicKey);
              }
              return true;
            }
          } catch (_) {
            // fall through to full check
          }
        }
      }

      const healthy = await checkPeerHealthWithHyperswarm(peer, connectionPool);
      if (healthy) {
        peer.lastSeen = now;
        this.healthChecks.set(peer.publicKey, {
          lastCheck: now,
          status: 'healthy',
          responseTime: Date.now() - now
        });
        this.failureCount.delete(peer.publicKey);
        return true;
      }

      await this.recordFailure(peer.publicKey);
      return false;
    } catch (error) {
      this.healthChecks.set(peer.publicKey, {
        lastCheck: now,
        status: 'unhealthy',
        error: error.message
      });
      await this.recordFailure(peer.publicKey);
      return false;
    } finally {
      this.checkLocks.delete(peer.publicKey);
    }
  }

  async recordFailure(publicKey) {
    const failures = (this.failureCount.get(publicKey) || 0) + 1;
    this.failureCount.set(publicKey, failures);

    if (failures >= this.circuitBreakerThreshold) {
      this.healthChecks.set(publicKey, {
        ...(this.healthChecks.get(publicKey) || {}),
        status: 'circuit-broken',
        circuitBroken: true,
        circuitBrokenAt: Date.now()
      });
    }
  }

  isPeerHealthy(publicKey) {
    const check = this.healthChecks.get(publicKey);
    if (!check) return false;

    const now = Date.now();
    if (check.circuitBroken) {
      if (now - (check.circuitBrokenAt || 0) > this.circuitBreakerTimeout) {
        check.circuitBroken = false;
        check.circuitBrokenAt = null;
        this.healthChecks.set(publicKey, check);
        return true;
      }
      return false;
    }

    return check.status === 'healthy' && (now - check.lastCheck) < this.cleanupThreshold;
  }
}

function generateConnectionKey() {
  return crypto.randomBytes(16).toString('hex');
}

export class GatewayService extends EventEmitter {
  constructor(options = {}) {
    super();
    this.options = options;
    this.server = null;
    this.wss = null;
    this.app = null;
    this.gatewayServer = null;
    this.connectionPool = new EnhancedHyperswarmPool({
      onProtocol: this._onProtocolCreated.bind(this),
      onHandshake: this._onProtocolHandshake.bind(this),
      onTelemetry: this._onPeerTelemetry.bind(this),
      handshakeBuilder: this.#buildHandshakePayload.bind(this)
    });
    this.peerHealthManager = new PeerHealthManager();
    this.activePeers = [];
    this.activeRelays = new Map();
    this.wsConnections = new Map();
    this.messageQueues = new Map();
    this.logs = [];
    this.isRunning = false;
    this.startedAt = null;
    this.config = null;
    this.healthState = {
      startTime: null,
      lastCheck: null,
      status: 'offline',
      activeRelaysCount: 0,
      metrics: {
        totalRequests: 0,
        successfulRequests: 0,
        failedRequests: 0,
        lastMetricsReset: Date.now()
      },
      services: {
        hyperswarmStatus: 'disconnected',
        protocolStatus: 'disconnected',
        gatewayStatus: 'offline'
      }
    };
    this.healthInterval = null;
    this.eventCheckTimers = new Map();
    this.activePeerPolls = new Map();
    this.pfpOwnerIndex = new Map(); // owner -> Set<peerPublicKey>
    this.pfpDriveKeys = new Map(); // peerPublicKey -> driveKey
    this.peerHandshakes = new Map();
    this.loggerBridge = null;
    this.publicGatewaySettings = this.#normalizePublicGatewayConfig(options.publicGateway);
    this.publicGatewayRegistrar = null;
    this.publicGatewayAuthClients = new Map();
    this.publicGatewayControlClients = new Map();
    this.publicGatewayLegacyRegistrars = new Map();
    this.gatewayAccessCatalog = new Map();
    this.gatewayAccessProbeInflight = new Map();
    this.openJoinPoolProvider = typeof options.openJoinPoolProvider === 'function'
      ? options.openJoinPoolProvider
      : null;
    this.publicGatewayRelayState = new Map();
    this.relayCoreCache = new Map();
    this.blindPeerSummary = null;
    this.blindPeerFallbackState = {
      inflight: null,
      lastAttempt: 0
    };
    this.publicGatewayRelayTokens = new Map();
    this.publicGatewayRelayTokenTimers = new Map();
    this.openJoinPoolSyncInterval = null;
    this.openJoinPoolSyncLocks = new Set();
    this.gatewayTelemetryTimers = new Map();
    this.gatewayProtocols = new Map();
    this.publicGatewayRelayClient = new PublicGatewayRelayClient({ logger: this.#createExternalLogger?.() || console });
    this.hyperbeeAdapter = new PublicGatewayHyperbeeAdapter({
      relayClient: this.publicGatewayRelayClient,
      logger: this.loggerBridge || console
    });
    this.publicGatewayVirtualRelayManager = null;
    this.hyperbeeQueryStats = {
      totalServed: 0,
      totalEvents: 0,
      totalFallbacks: 0,
      totalErrors: 0,
      lastServedAt: null,
      lastFallbackAt: null,
      lastErrorAt: null,
      lastErrorMessage: null
    };
    this.publicGatewayReplicaMetrics = null;
    this.ownPeerPublicKey = typeof options.getOwnPeerPublicKey === 'function'
      ? options.getOwnPeerPublicKey()
      : (options.ownPeerPublicKey || null);
    this.publicGatewayWsBase = null;
    this.publicGatewayStatusUpdatedAt = null;
    this.discoveredGateways = [];
    this.discoveryDisabledReason = null;
    this.discoveryWarning = null;
    this.discoveryClient = null;
    this.discoveryClientReady = null;
    this._discoveryRefreshScheduled = false;
    this.getCurrentPubkey = typeof options.getCurrentPubkey === 'function'
      ? options.getCurrentPubkey
      : () => options.currentPubkey || null;
    this.getGatewayAuthContext = typeof options.getGatewayAuthContext === 'function'
      ? options.getGatewayAuthContext
      : () => ({
        pubkey: this.getCurrentPubkey?.() || null,
        nsecHex: options.currentNsecHex || null
      });

    this.#configurePublicGateway();
  }

  #normalizePublicGatewayConfig(rawConfig = {}) {
    const envEnabled = process.env.PUBLIC_GATEWAY_ENABLED === 'true';
    const envBaseUrl = (process.env.PUBLIC_GATEWAY_URL || '').trim();
    const envSecret = (process.env.PUBLIC_GATEWAY_SECRET || '').trim();
    const envTtl = Number(process.env.PUBLIC_GATEWAY_DEFAULT_TOKEN_TTL);
    const envDelegateRaw = process.env.PUBLIC_GATEWAY_DELEGATE_REQS;
    const envDelegate = envDelegateRaw === 'true' ? true : envDelegateRaw === 'false' ? false : null;

    const ttlCandidate = rawConfig?.defaultTokenTtl ?? (Number.isFinite(envTtl) ? envTtl : undefined);
    const ttlNumber = Number(ttlCandidate);
    const defaultTokenTtl = Number.isFinite(ttlNumber) && ttlNumber > 0 ? Math.round(ttlNumber) : 3600;

    const refreshCandidate = rawConfig?.tokenRefreshWindowSeconds ?? Number(process.env.PUBLIC_GATEWAY_TOKEN_REFRESH_WINDOW);
    const refreshNumber = Number(refreshCandidate);
    const tokenRefreshWindowSeconds = Number.isFinite(refreshNumber) && refreshNumber > 0
      ? Math.round(refreshNumber)
      : 300;
    const openJoinPoolSyncIntervalCandidate = Number(
      rawConfig?.openJoinPoolSyncIntervalMs
        ?? process.env.PUBLIC_GATEWAY_OPEN_JOIN_POOL_SYNC_INTERVAL_MS
        ?? 300000
    );
    const openJoinPoolSyncIntervalMs = Number.isFinite(openJoinPoolSyncIntervalCandidate)
      ? Math.max(0, Math.trunc(openJoinPoolSyncIntervalCandidate))
      : 300000;

    const selectionRaw = typeof rawConfig?.selectionMode === 'string'
      ? rawConfig.selectionMode.trim().toLowerCase()
      : '';
    const selectionMode = ['default', 'discovered', 'manual'].includes(selectionRaw)
      ? selectionRaw
      : '';
    const authMethod = typeof rawConfig?.authMethod === 'string' && rawConfig.authMethod.trim()
      ? rawConfig.authMethod.trim()
      : (rawConfig?.sharedSecret ? 'shared-secret-v1' : 'relay-scoped-bearer-v1');

    const config = {
      enabled: rawConfig?.enabled ?? envEnabled,
      authMethod,
      selectionMode,
      selectedGatewayId: typeof rawConfig?.selectedGatewayId === 'string'
        ? rawConfig.selectedGatewayId.trim() || null
        : null,
      baseUrl: typeof rawConfig?.baseUrl === 'string' ? rawConfig.baseUrl.trim() : '',
      sharedSecret: typeof rawConfig?.sharedSecret === 'string' ? rawConfig.sharedSecret.trim() : '',
      preferredBaseUrl: typeof rawConfig?.preferredBaseUrl === 'string'
        ? rawConfig.preferredBaseUrl.trim()
        : '',
      defaultTokenTtl,
      tokenRefreshWindowSeconds,
      openJoinPoolSyncIntervalMs,
      resolvedGatewayId: rawConfig?.resolvedGatewayId || null,
      resolvedAuthMethod: typeof rawConfig?.resolvedAuthMethod === 'string' && rawConfig.resolvedAuthMethod.trim()
        ? rawConfig.resolvedAuthMethod.trim()
        : null,
      resolvedSecretVersion: rawConfig?.resolvedSecretVersion || null,
      resolvedSharedSecretHash: rawConfig?.resolvedSharedSecretHash || null,
      resolvedDisplayName: rawConfig?.resolvedDisplayName || null,
      resolvedRegion: rawConfig?.resolvedRegion || null,
      resolvedWsUrl: rawConfig?.resolvedWsUrl || null,
      resolvedAt: Number(rawConfig?.resolvedAt) || null,
      resolvedFallback: !!rawConfig?.resolvedFallback,
      resolvedFromDiscovery: !!rawConfig?.resolvedFromDiscovery,
      disabledReason: rawConfig?.disabledReason || null,
      dispatcherMaxConcurrent: this.#parsePositiveNumber(rawConfig?.dispatcherMaxConcurrent, 3),
      dispatcherInFlightWeight: this.#parsePositiveNumber(rawConfig?.dispatcherInFlightWeight, 25),
      dispatcherLatencyWeight: this.#parsePositiveNumber(rawConfig?.dispatcherLatencyWeight, 1),
      dispatcherFailureWeight: this.#parsePositiveNumber(rawConfig?.dispatcherFailureWeight, 500),
      dispatcherReassignLagBlocks: this.#parsePositiveNumber(rawConfig?.dispatcherReassignLagBlocks, 500),
      dispatcherCircuitBreakerThreshold: this.#parsePositiveNumber(rawConfig?.dispatcherCircuitBreakerThreshold, 5),
      dispatcherCircuitBreakerTimeoutMs: this.#parsePositiveNumber(rawConfig?.dispatcherCircuitBreakerTimeoutMs, 60000)
    };

    if (envDelegate !== null) {
      config.delegateReqToPeers = envDelegate;
    } else if (typeof rawConfig?.delegateReqToPeers === 'boolean') {
      config.delegateReqToPeers = rawConfig.delegateReqToPeers;
    } else {
      config.delegateReqToPeers = false;
    }

    if (!config.selectionMode) {
      config.selectionMode = envSecret ? 'manual' : 'default';
    }

    if (!config.preferredBaseUrl) {
      config.preferredBaseUrl = config.baseUrl || envBaseUrl || '';
    }

    if (config.selectionMode === 'default') {
      config.baseUrl = '';
      config.selectedGatewayId = null;
    } else if (config.selectionMode === 'manual' && !config.baseUrl) {
      config.baseUrl = envBaseUrl || config.preferredBaseUrl || '';
    }

    if (envBaseUrl && envSecret) {
      config.enabled = true;
      config.selectionMode = 'manual';
      config.baseUrl = envBaseUrl;
      config.preferredBaseUrl = envBaseUrl;
      config.sharedSecret = envSecret;
    } else if (envSecret && config.selectionMode === 'manual' && !config.sharedSecret) {
      config.sharedSecret = envSecret;
    }

    if (!config.baseUrl && config.selectionMode !== 'default') {
      config.baseUrl = config.preferredBaseUrl || envBaseUrl || '';
    }

    const blindPeerConfig = this.#normalizeBlindPeerConfig(rawConfig, this.publicGatewaySettings);
    Object.assign(config, blindPeerConfig);

    config.enabled = !!config.enabled;
    return config;
  }

  #parsePositiveNumber(value, fallback) {
    const num = Number(value);
    if (Number.isFinite(num) && num > 0) return Math.round(num);
    return fallback;
  }

  #normalizeBlindPeerConfig(rawConfig = {}, fallback = {}) {
    const hasOwn = (obj, key) => Object.prototype.hasOwnProperty.call(obj || {}, key);
    const selectBoolean = (key, defaultValue = false) => {
      if (hasOwn(rawConfig, key)) return !!rawConfig[key];
      if (hasOwn(fallback, key)) return !!fallback[key];
      return defaultValue;
    };
    const selectKeys = (key) => {
      const source = hasOwn(rawConfig, key) ? rawConfig[key] : fallback?.[key];
      return this.#sanitizeKeyList(source);
    };
    const selectString = (key) => {
      if (hasOwn(rawConfig, key)) return this.#sanitizeOptionalString(rawConfig[key]);
      if (hasOwn(fallback, key)) return this.#sanitizeOptionalString(fallback[key]);
      return null;
    };
    const selectNumber = (key) => {
      const candidate = hasOwn(rawConfig, key)
        ? Number(rawConfig[key])
        : Number(fallback?.[key]);
      return Number.isFinite(candidate) && candidate > 0 ? Math.trunc(candidate) : null;
    };

    return {
      blindPeerEnabled: selectBoolean('blindPeerEnabled'),
      blindPeerKeys: selectKeys('blindPeerKeys'),
      blindPeerManualKeys: selectKeys('blindPeerManualKeys'),
      blindPeerEncryptionKey: selectString('blindPeerEncryptionKey'),
      blindPeerReplicationTopic: selectString('blindPeerReplicationTopic'),
      blindPeerMaxBytes: selectNumber('blindPeerMaxBytes'),
      gatewayBlindPeerCatalog: this.#normalizeGatewayBlindPeerCatalog(
        hasOwn(rawConfig, 'gatewayBlindPeerCatalog')
          ? rawConfig.gatewayBlindPeerCatalog
          : fallback?.gatewayBlindPeerCatalog
      )
    };
  }

  #sanitizeKeyList(value) {
    if (value == null) return [];
    const list = Array.isArray(value) ? value : [value];
    const seen = new Set();
    for (const entry of list) {
      if (typeof entry !== 'string') continue;
      const trimmed = entry.trim();
      if (!trimmed) continue;
      seen.add(trimmed);
    }
    return Array.from(seen);
  }

  #sanitizeOptionalString(value) {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    return trimmed.length ? trimmed : null;
  }

  #normalizeGatewayBlindPeerCatalog(value) {
    if (!value || typeof value !== 'object') return {};
    const entries = Object.entries(value);
    const catalog = {};
    for (const [rawKey, rawEntry] of entries) {
      if (!rawEntry || typeof rawEntry !== 'object') continue;
      const gatewayOrigin = this.#normalizeGatewayOrigin(
        rawEntry.gatewayOrigin || rawEntry.publicUrl || rawKey || null
      );
      const gatewayId = this.#normalizeGatewayId(rawEntry.gatewayId || null);
      const catalogKey = gatewayOrigin || gatewayId;
      if (!catalogKey) continue;
      const blindPeer =
        rawEntry.blindPeer && typeof rawEntry.blindPeer === 'object'
          ? {
              enabled: rawEntry.blindPeer.enabled !== false,
              publicKey: this.#sanitizeOptionalString(rawEntry.blindPeer.publicKey),
              encryptionKey: this.#sanitizeOptionalString(rawEntry.blindPeer.encryptionKey),
              maxBytes: Number.isFinite(Number(rawEntry.blindPeer.maxBytes))
                ? Number(rawEntry.blindPeer.maxBytes)
                : null
            }
          : null;
      catalog[catalogKey] = {
        gatewayOrigin,
        gatewayId,
        updatedAt: Number.isFinite(Number(rawEntry.updatedAt)) ? Number(rawEntry.updatedAt) : null,
        blindPeer
      };
    }
    return catalog;
  }

  #normalizeGatewayOrigin(value) {
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

  #normalizeGatewayId(value) {
    if (typeof value !== 'string') return null;
    const trimmed = value.trim().toLowerCase();
    return trimmed || null;
  }

  #gatewayAccessCatalogKey({ gatewayId = null, gatewayOrigin = null } = {}) {
    return this.#normalizeGatewayId(gatewayId)
      || this.#normalizeGatewayOrigin(gatewayOrigin)
      || null;
  }

  #inferGatewayAuthMethod(entry = null) {
    const advertised = typeof entry?.authMethod === 'string' ? entry.authMethod.trim() : '';
    if (advertised) return advertised;
    if (entry?.openAccess === true) return 'shared-secret-v1';
    return 'relay-scoped-bearer-v1';
  }

  #findDiscoveredGatewayByOrigin(origin) {
    const normalizedOrigin = this.#normalizeGatewayOrigin(origin);
    if (!normalizedOrigin) return null;
    return (this.discoveredGateways || []).find((candidate) => {
      const candidateOrigin = this.#normalizeGatewayOrigin(candidate?.publicUrl || candidate?.gatewayOrigin || null);
      return candidateOrigin === normalizedOrigin;
    }) || null;
  }

  #findDiscoveredGateway({ gatewayId = null, gatewayOrigin = null } = {}) {
    const normalizedId = this.#normalizeGatewayId(gatewayId);
    if (normalizedId && this.discoveryClient?.getGatewayById) {
      return this.discoveryClient.getGatewayById(normalizedId) || null;
    }
    if (normalizedId) {
      return (this.discoveredGateways || []).find((candidate) =>
        this.#normalizeGatewayId(candidate?.gatewayId) === normalizedId
      ) || null;
    }
    return this.#findDiscoveredGatewayByOrigin(gatewayOrigin);
  }

  #summarizeGatewayPolicy(entry = null) {
    if (!entry || typeof entry !== 'object') return null;
    return {
      hostPolicy: typeof entry.hostPolicy === 'string' ? entry.hostPolicy : null,
      authMethod: this.#inferGatewayAuthMethod(entry),
      openAccess: entry.openAccess === true,
      operatorPubkey: typeof entry.operatorPubkey === 'string' ? entry.operatorPubkey : null,
      wotRootPubkey: typeof entry.wotRootPubkey === 'string' ? entry.wotRootPubkey : null,
      wotMaxDepth: Number.isFinite(Number(entry.wotMaxDepth)) ? Number(entry.wotMaxDepth) : null,
      wotMinFollowersDepth2: Number.isFinite(Number(entry.wotMinFollowersDepth2))
        ? Number(entry.wotMinFollowersDepth2)
        : null,
      capabilities: Array.isArray(entry.capabilities)
        ? entry.capabilities.filter((value) => typeof value === 'string' && value.trim())
        : []
    };
  }

  #verifyGatewayOperatorIdentity(operatorIdentity = null, route = null) {
    if (!operatorIdentity || typeof operatorIdentity !== 'object') return null;
    const pubkey = typeof operatorIdentity.pubkey === 'string'
      ? operatorIdentity.pubkey.trim().toLowerCase()
      : '';
    const attestation = operatorIdentity.attestation && typeof operatorIdentity.attestation === 'object'
      ? operatorIdentity.attestation
      : null;
    if (!pubkey || !attestation) return null;
    const verification = verifyOperatorAttestation(attestation, {
      expectedOperatorPubkey: pubkey,
      expectedGatewayId: route?.gatewayId || null,
      expectedPublicUrl: route?.gatewayOrigin || null,
      now: Date.now(),
      schnorrImpl: schnorr
    });
    if (!verification.ok) {
      return null;
    }
    return {
      pubkey: verification.payload.operatorPubkey,
      attestation: cloneJson(verification.attestation)
    };
  }

  async #resolveGatewayRoute({
    relayKey = null,
    metadata = null,
    gatewayOrigin = null,
    gatewayId = null,
    allowSettingsFallback = true
  } = {}) {
    const settings = this.publicGatewaySettings || null;
    const settingsOrigin = allowSettingsFallback
      ? this.#normalizeGatewayOrigin(settings?.baseUrl || null)
      : null;
    const settingsSelectionMode = typeof settings?.selectionMode === 'string'
      ? settings.selectionMode
      : null;
    const normalizedSettingsGatewayId = allowSettingsFallback
      ? this.#normalizeGatewayId(settings?.resolvedGatewayId || null)
      : null;
    const normalizedOrigin = this.#normalizeGatewayOrigin(
      gatewayOrigin
      || metadata?.gatewayOrigin
      || null
    );
    let normalizedGatewayId = this.#normalizeGatewayId(gatewayId || metadata?.gatewayId || null);

    let entry = this.#findDiscoveredGateway({
      gatewayId: normalizedGatewayId,
      gatewayOrigin: normalizedOrigin
    });

    if (!entry && allowSettingsFallback) {
      const settingsOrigin = this.#normalizeGatewayOrigin(this.publicGatewaySettings?.baseUrl || null);
      if (settingsOrigin && (!normalizedOrigin || settingsOrigin === normalizedOrigin)) {
        entry = this.#findDiscoveredGatewayByOrigin(settingsOrigin);
      }
    }

    if (!normalizedGatewayId && entry?.gatewayId) {
      normalizedGatewayId = this.#normalizeGatewayId(entry.gatewayId);
    }

    const manualSettingsMatch = settingsSelectionMode === 'manual'
      && settingsOrigin
      && (!normalizedOrigin || normalizedOrigin === settingsOrigin);

    if (manualSettingsMatch && !normalizedGatewayId && normalizedSettingsGatewayId) {
      normalizedGatewayId = normalizedSettingsGatewayId;
    }

    const routeOrigin = this.#normalizeGatewayOrigin(
      manualSettingsMatch
        ? settingsOrigin
        : (
          normalizedOrigin
          || entry?.publicUrl
          || settingsOrigin
        )
    );
    if (!routeOrigin) {
      return null;
    }

    let authMethod;
    let sharedSecret = null;
    if (manualSettingsMatch) {
      authMethod = typeof settings?.resolvedAuthMethod === 'string' && settings.resolvedAuthMethod.trim()
        ? settings.resolvedAuthMethod.trim()
        : (
          typeof settings?.authMethod === 'string' && settings.authMethod.trim()
            ? settings.authMethod.trim()
            : (typeof settings?.sharedSecret === 'string' && settings.sharedSecret.trim()
                ? 'shared-secret-v1'
                : 'relay-scoped-bearer-v1')
        );
      sharedSecret = authMethod !== 'relay-scoped-bearer-v1'
        && typeof settings?.sharedSecret === 'string'
        && settings.sharedSecret.trim()
        ? settings.sharedSecret.trim()
        : null;
    } else {
      authMethod = this.#inferGatewayAuthMethod(entry);
      sharedSecret = typeof entry?.sharedSecret === 'string' && entry.sharedSecret.trim()
        ? entry.sharedSecret.trim()
        : null;
      if (!sharedSecret
        && authMethod !== 'relay-scoped-bearer-v1'
        && normalizedGatewayId
        && this.discoveryClient?.ensureSecret) {
        try {
          await this.discoveryClient.ensureSecret(normalizedGatewayId);
          entry = this.#findDiscoveredGateway({ gatewayId: normalizedGatewayId, gatewayOrigin: routeOrigin });
          sharedSecret = typeof entry?.sharedSecret === 'string' && entry.sharedSecret.trim()
            ? entry.sharedSecret.trim()
            : null;
        } catch (error) {
          this.log('debug', `[PublicGateway] Secret fetch skipped for ${normalizedGatewayId}: ${error.message}`);
        }
      }
    }

    return {
      relayKey: relayKey || null,
      gatewayId: normalizedGatewayId || null,
      gatewayOrigin: routeOrigin,
      publicUrl: routeOrigin,
      wsUrl: typeof entry?.wsUrl === 'string' ? entry.wsUrl : this.#computePublicGatewayWsBase(routeOrigin),
      authMethod,
      sharedSecret,
      openAccess: entry?.openAccess === true,
      memberDelegationMode: typeof entry?.memberDelegationMode === 'string'
        ? entry.memberDelegationMode
        : null,
      policy: this.#summarizeGatewayPolicy(entry),
      discoveryEntry: entry || null
    };
  }

  #getGatewayAuthClient(baseUrl) {
    const normalizedBaseUrl = this.#normalizeGatewayOrigin(baseUrl);
    if (!normalizedBaseUrl) return null;
    let client = this.publicGatewayAuthClients.get(normalizedBaseUrl) || null;
    if (!client) {
      client = new PublicGatewayAuthClient({
        baseUrl: normalizedBaseUrl,
        logger: this.loggerBridge || console,
        getAuthContext: () => this.getGatewayAuthContext?.() || null
      });
      this.publicGatewayAuthClients.set(normalizedBaseUrl, client);
    } else if (typeof client.setBaseUrl === 'function') {
      client.setBaseUrl(normalizedBaseUrl);
    }
    return client;
  }

  #getGatewayControlClient(baseUrl) {
    const normalizedBaseUrl = this.#normalizeGatewayOrigin(baseUrl);
    if (!normalizedBaseUrl) return null;
    let client = this.publicGatewayControlClients.get(normalizedBaseUrl) || null;
    if (!client) {
      client = new PublicGatewayControlClient({
        baseUrl: normalizedBaseUrl,
        authClient: this.#getGatewayAuthClient(normalizedBaseUrl),
        logger: this.loggerBridge || console
      });
      this.publicGatewayControlClients.set(normalizedBaseUrl, client);
    } else {
      client.setBaseUrl(normalizedBaseUrl);
      client.authClient = this.#getGatewayAuthClient(normalizedBaseUrl);
    }
    return client;
  }

  #getLegacyGatewayRegistrar(baseUrl, sharedSecret) {
    const normalizedBaseUrl = this.#normalizeGatewayOrigin(baseUrl);
    const normalizedSecret = typeof sharedSecret === 'string' ? sharedSecret.trim() : '';
    if (!normalizedBaseUrl || !normalizedSecret) return null;
    const cacheKey = `${normalizedBaseUrl}::${normalizedSecret}`;
    let registrar = this.publicGatewayLegacyRegistrars.get(cacheKey) || null;
    if (!registrar) {
      registrar = new PublicGatewayRegistrar({
        baseUrl: normalizedBaseUrl,
        sharedSecret: normalizedSecret,
        logger: this.loggerBridge || console
      });
      this.publicGatewayLegacyRegistrars.set(cacheKey, registrar);
    }
    return registrar;
  }

  async #getGatewayBridgeClient(route = null) {
    if (!route?.gatewayOrigin) return null;
    if (route.authMethod === 'relay-scoped-bearer-v1') {
      const controlClient = this.#getGatewayControlClient(route.gatewayOrigin);
      if (!controlClient?.isEnabled?.()) return null;
      return {
        mode: route.authMethod,
        gatewayOrigin: route.gatewayOrigin,
        gatewayId: route.gatewayId || null,
        authMethod: route.authMethod,
        isEnabled: () => controlClient.isEnabled?.() !== false,
        registerRelay: (...args) => controlClient.registerRelay(...args),
        unregisterRelay: (...args) => controlClient.unregisterRelay(...args),
        updateOpenJoinPool: (...args) => controlClient.updateOpenJoinPool(...args),
        issueGatewayToken: (...args) => controlClient.issueGatewayToken(...args),
        refreshGatewayToken: (...args) => controlClient.refreshGatewayToken(...args),
        revokeGatewayToken: (...args) => controlClient.revokeGatewayToken(...args),
        controlClient
      };
    }

    const registrar = this.#getLegacyGatewayRegistrar(route.gatewayOrigin, route.sharedSecret);
    if (!registrar?.isEnabled?.()) return null;
      return {
        mode: 'legacy-shared-secret',
        gatewayOrigin: route.gatewayOrigin,
        gatewayId: route.gatewayId || null,
        authMethod: route.authMethod,
        isEnabled: () => registrar.isEnabled?.() === true,
        registerRelay: (...args) => registrar.registerRelay(...args),
        unregisterRelay: (...args) => registrar.unregisterRelay(...args),
        updateOpenJoinPool: (...args) => registrar.updateOpenJoinPool(...args),
        issueGatewayToken: (...args) => registrar.issueGatewayToken(...args),
        refreshGatewayToken: (...args) => registrar.refreshGatewayToken(...args),
        revokeGatewayToken: (...args) => registrar.revokeGatewayToken(...args),
        registrar
      };
  }

  async #probeGatewayHostingAccess(route = null, { force = false } = {}) {
    const catalogKey = this.#gatewayAccessCatalogKey(route);
    if (!catalogKey || !route?.gatewayOrigin) return null;

    const existing = this.gatewayAccessCatalog.get(catalogKey) || null;
    if (!force && existing?.hostingState === 'approved') {
      return existing;
    }
    if (!force && existing?.lastCheckedAt && (Date.now() - existing.lastCheckedAt) < 60_000) {
      return existing;
    }
    if (this.gatewayAccessProbeInflight.has(catalogKey)) {
      return this.gatewayAccessProbeInflight.get(catalogKey);
    }

    const task = (async () => {
      const base = {
        gatewayId: route.gatewayId || null,
        gatewayOrigin: route.gatewayOrigin,
        policy: route.policy || null,
        memberDelegationMode: route.memberDelegationMode || null,
        authMethod: route.authMethod || null,
        lastCheckedAt: Date.now(),
        reason: null,
        hostingState: 'unknown',
        operatorIdentity: null
      };

      try {
        if (route.openAccess === true || route.policy?.hostPolicy === 'open') {
          let operatorIdentity = null;
          if (route.authMethod === 'relay-scoped-bearer-v1') {
            try {
              const authClient = this.#getGatewayAuthClient(route.gatewayOrigin);
              const authResponse = await authClient.issueBearerTokenResponse({
                scope: 'gateway:relay-register',
                relayKey: null,
                forceRefresh: force
              });
              operatorIdentity = this.#verifyGatewayOperatorIdentity(authResponse?.operatorIdentity, route);
            } catch (_) {}
          }
          const approved = { ...base, hostingState: 'approved', reason: 'open-access', operatorIdentity };
          this.gatewayAccessCatalog.set(catalogKey, approved);
          return approved;
        }
        if (route.authMethod !== 'relay-scoped-bearer-v1') {
          const unknown = { ...base, hostingState: route.sharedSecret ? 'approved' : 'unknown', reason: route.sharedSecret ? 'shared-secret-available' : 'shared-secret-required' };
          this.gatewayAccessCatalog.set(catalogKey, unknown);
          return unknown;
        }
        const authClient = this.#getGatewayAuthClient(route.gatewayOrigin);
        const authResponse = await authClient.issueBearerTokenResponse({
          scope: 'gateway:relay-register',
          relayKey: null,
          forceRefresh: force
        });
        const approved = {
          ...base,
          hostingState: 'approved',
          reason: 'gateway-host-approved',
          operatorIdentity: this.#verifyGatewayOperatorIdentity(authResponse?.operatorIdentity, route)
        };
        this.gatewayAccessCatalog.set(catalogKey, approved);
        return approved;
      } catch (error) {
        const reason = error?.message || 'gateway-host-unauthorized';
        const denied = {
          ...base,
          hostingState: reason === 'gateway-host-unauthorized' ? 'denied' : 'error',
          reason
        };
        this.gatewayAccessCatalog.set(catalogKey, denied);
        return denied;
      } finally {
        this.gatewayAccessProbeInflight.delete(catalogKey);
      }
    })();

    this.gatewayAccessProbeInflight.set(catalogKey, task);
    return task;
  }

  async #refreshGatewayAccessCatalog({ force = false } = {}) {
    const routes = [];
    const seen = new Set();
    for (const entry of this.discoveredGateways || []) {
      const route = await this.#resolveGatewayRoute({
        gatewayId: entry?.gatewayId || null,
        gatewayOrigin: entry?.publicUrl || entry?.gatewayOrigin || null,
        allowSettingsFallback: false
      });
      if (!route) continue;
      const cacheKey = this.#gatewayAccessCatalogKey(route);
      if (!cacheKey || seen.has(cacheKey)) continue;
      seen.add(cacheKey);
      routes.push(route);
    }

    await Promise.all(routes.map((route) => this.#probeGatewayHostingAccess(route, { force })));
  }

  #configurePublicGateway() {
    const config = this.publicGatewaySettings || { enabled: false };
    const hasBaseUrl = !!(config.baseUrl && String(config.baseUrl).trim());
    const hasSharedSecret = !!(config.sharedSecret && String(config.sharedSecret).trim());
    const authMethod = typeof config.resolvedAuthMethod === 'string' && config.resolvedAuthMethod.trim()
      ? config.resolvedAuthMethod.trim()
      : (typeof config.authMethod === 'string' && config.authMethod.trim() ? config.authMethod.trim() : 'relay-scoped-bearer-v1');

    console.info('[PublicGateway] Registrar config', {
      enabled: !!config.enabled,
      hasBaseUrl,
      hasSharedSecret,
      authMethod,
      baseUrl: hasBaseUrl ? config.baseUrl : null
    });

    if (!this.loggerBridge) {
      this.loggerBridge = this.#createExternalLogger();
    }

    if (this.publicGatewayRelayClient) {
      this.publicGatewayRelayClient.logger = this.loggerBridge;
    }

    if (this.hyperbeeAdapter) {
      this.hyperbeeAdapter.logger = this.loggerBridge;
    }

    if (config.enabled && config.baseUrl) {
      if (authMethod === 'relay-scoped-bearer-v1') {
        this.publicGatewayRegistrar = this.#getGatewayControlClient(config.baseUrl);
      } else if (config.sharedSecret) {
        this.publicGatewayRegistrar = this.#getLegacyGatewayRegistrar(config.baseUrl, config.sharedSecret);
      } else {
        this.publicGatewayRegistrar = null;
      }
      this.publicGatewayWsBase = this.#computePublicGatewayWsBase(config.baseUrl);
    } else {
      this.publicGatewayRegistrar = null;
      this.publicGatewayWsBase = null;
      this.#clearAllRelayTokens();
    }
    this.discoveryDisabledReason = config.disabledReason || null;
    if (config.disabledReason) {
      this.discoveryWarning = null;
    }

    this.#ensurePublicGatewayRelayEntry();
  }

  async #ensureDiscoveryClient() {
    if (!this.discoveryClient) {
      if (!this.loggerBridge) {
        this.loggerBridge = this.#createExternalLogger();
      }
      this.discoveryClient = new PublicGatewayDiscoveryClient({ logger: this.loggerBridge });
      this.discoveryClient.on('updated', (catalog) => {
        this.discoveredGateways = catalog;
        this.#refreshGatewayAccessCatalog().catch((error) => {
          this.log('debug', `[PublicGateway] Gateway access catalog refresh skipped: ${error.message}`);
        });
        if (this.publicGatewaySettings?.enabled) {
          this.#scheduleDiscoveryConfigRefresh();
        }
        this.#emitPublicGatewayStatus();
      });
    }

    if (!this.discoveryClientReady) {
      this.discoveryClientReady = this.discoveryClient.start().catch((error) => {
        this.discoveryClientReady = null;
        this.discoveryDisabledReason = error?.message || 'Failed to start gateway discovery';
        throw error;
      });
    }

    try {
      await this.discoveryClientReady;
      this.discoveryDisabledReason = null;
      this.discoveredGateways = this.discoveryClient.getGateways({ includeExpired: true });
      await this.#refreshGatewayAccessCatalog();
    } catch (error) {
      throw error;
    }
  }

  #scheduleDiscoveryConfigRefresh() {
    if (this._discoveryRefreshScheduled) {
      return;
    }
    this._discoveryRefreshScheduled = true;

    queueMicrotask(() => {
      this._discoveryRefreshScheduled = false;
      if (!this.publicGatewaySettings?.enabled) {
        return;
      }
      this.updatePublicGatewayConfig({ ...this.publicGatewaySettings }).catch((error) => {
        this.log('debug', `[PublicGateway] Discovery refresh skipped: ${error.message}`);
      });
    });
  }

  #clearRelayToken(relayKey) {
    if (!relayKey) return;
    const timer = this.publicGatewayRelayTokenTimers.get(relayKey);
    if (timer) {
      clearTimeout(timer);
      this.publicGatewayRelayTokenTimers.delete(relayKey);
    }
    this.publicGatewayRelayTokens.delete(relayKey);
    if (this.publicGatewayRelayState.has(relayKey)) {
      const current = this.publicGatewayRelayState.get(relayKey);
      if (current) {
        const next = { ...current };
        delete next.token;
        delete next.expiresAt;
        delete next.ttlSeconds;
        delete next.connectionUrl;
        delete next.tokenIssuedAt;
        this.publicGatewayRelayState.set(relayKey, next);
      }
    }
  }

  #clearAllRelayTokens() {
    for (const timer of this.publicGatewayRelayTokenTimers.values()) {
      clearTimeout(timer);
    }
    this.publicGatewayRelayTokenTimers.clear();
    this.publicGatewayRelayTokens.clear();
    for (const [relayKey, state] of this.publicGatewayRelayState.entries()) {
      if (!state) continue;
      const next = { ...state };
      delete next.token;
      delete next.expiresAt;
      delete next.ttlSeconds;
      delete next.connectionUrl;
      delete next.tokenIssuedAt;
      this.publicGatewayRelayState.set(relayKey, next);
    }
  }

  #scheduleRelayTokenRetry(relayKey) {
    if (!relayKey) return;
    const existing = this.publicGatewayRelayTokenTimers.get(relayKey);
    if (existing) {
      clearTimeout(existing);
      this.publicGatewayRelayTokenTimers.delete(relayKey);
    }
    const handle = setTimeout(() => {
      this.publicGatewayRelayTokenTimers.delete(relayKey);
      this.#refreshRelayToken(relayKey, { force: true }).catch((error) => {
        this.log('warn', `[PublicGateway] Token retry failed for ${relayKey}: ${error.message}`);
        this.#scheduleRelayTokenRetry(relayKey);
      });
    }, 30_000);
    handle.unref?.();
    this.publicGatewayRelayTokenTimers.set(relayKey, handle);
  }

  #scheduleRelayTokenRefresh(relayKey, targetTime, fallbackExpiresAt = null) {
    if (!relayKey) return;
    if (!Number.isFinite(targetTime)) return;
    const existing = this.publicGatewayRelayTokenTimers.get(relayKey);
    if (existing) {
      clearTimeout(existing);
      this.publicGatewayRelayTokenTimers.delete(relayKey);
    }
    const now = Date.now();
    let delay = targetTime - now;
    if (!Number.isFinite(delay)) {
      delay = 30_000;
    }
    if (delay <= 0) {
      const fallback = Number.isFinite(fallbackExpiresAt) ? fallbackExpiresAt : targetTime;
      delay = fallback > now ? Math.max(5_000, fallback - now - 5_000) : 5_000;
    }
    const handle = setTimeout(() => {
      this.publicGatewayRelayTokenTimers.delete(relayKey);
      this.#refreshRelayToken(relayKey, { force: true }).catch((error) => {
        this.log('warn', `[PublicGateway] Automatic token refresh failed for ${relayKey}: ${error.message}`);
        this.#scheduleRelayTokenRetry(relayKey);
      });
    }, Math.max(5_000, delay));
    handle.unref?.();
    this.publicGatewayRelayTokenTimers.set(relayKey, handle);
  }

  #resolveRelayAuth(relayKey, requestingPubkey) {
    if (!relayKey || !requestingPubkey) return null;
    const authStore = getRelayAuthStore();
    const candidateIdentifiers = new Set([relayKey]);

    const relayData = this.activeRelays.get(relayKey);
    if (relayData) {
      const metadataIdentifier = relayData.metadata?.identifier;
      if (metadataIdentifier) {
        candidateIdentifiers.add(metadataIdentifier);
      }

      const metadataGatewayPath = relayData.metadata?.gatewayPath;
      if (metadataGatewayPath && typeof metadataGatewayPath === 'string') {
        const normalizedPath = this._normalizeRelayIdentifier(metadataGatewayPath);
        if (normalizedPath) {
          candidateIdentifiers.add(normalizedPath);
        }
      }
    }

    for (const identifier of candidateIdentifiers) {
      if (!identifier) continue;
      const record = authStore.getAuthByPubkey(identifier, requestingPubkey);
      if (record) {
        return { identifier, ...record };
      }
    }

    return null;
  }

  #resolveConnectionAuthToken(connData, identifier) {
    if (!connData) return null;
    const relayKey = identifier || connData.relayKey;
    if (!relayKey) return connData.authToken || null;

    const requestingPubkey = this.getCurrentPubkey?.() || null;
    const authResolution = requestingPubkey ? this.#resolveRelayAuth(relayKey, requestingPubkey) : null;
    const resolvedToken = authResolution?.token || null;

    if (resolvedToken && resolvedToken !== connData.authToken) {
      const prevToken = connData.authToken;
      connData.authToken = resolvedToken;
      this.log('debug', '[PublicGateway] Updated connection auth token from store', {
        connectionKey: connData.connectionKey,
        relayKey,
        authIdentifier: authResolution?.identifier || null,
        prevTokenPreview: prevToken ? `${prevToken.slice(0, 8)}...` : null,
        nextTokenPreview: `${resolvedToken.slice(0, 8)}...`
      });
    }

    return resolvedToken || connData.authToken || null;
  }

  #recordRelayToken(relayKey, info, { schedule = true } = {}) {
    if (!relayKey || !info) return;
    const storedInfo = { ...info };
    this.publicGatewayRelayTokens.set(relayKey, storedInfo);
    if (schedule) {
      const targetTime = storedInfo.refreshAfter || storedInfo.expiresAt;
      if (Number.isFinite(targetTime)) {
        this.#scheduleRelayTokenRefresh(relayKey, targetTime, storedInfo.expiresAt);
      }
    }
    const current = this.publicGatewayRelayState.get(relayKey);
    if (current) {
      const issuedAt = Number.isFinite(info.issuedAt) ? info.issuedAt : null;
      const next = {
        ...current,
        token: info.token,
        expiresAt: info.expiresAt,
        ttlSeconds: info.ttlSeconds,
        connectionUrl: info.connectionUrl,
        tokenIssuedAt: issuedAt
      };
      this.publicGatewayRelayState.set(relayKey, next);
      this.#emitPublicGatewayStatus();
    }
  }

  async #refreshRelayToken(relayKey, { force = false } = {}) {
    if (!relayKey) return;
    const state = this.publicGatewayRelayState.get(relayKey);
    const metadata = this.activeRelays.get(relayKey)?.metadata || state?.metadata || null;
    const route = await this.#resolveGatewayRoute({ relayKey, metadata });
    const bridgeClient = await this.#getGatewayBridgeClient(route);
    const isBridgeEnabled = this.publicGatewaySettings?.enabled && bridgeClient?.isEnabled?.();
    if (!isBridgeEnabled || !state || state.status !== 'registered') {
      this.#clearRelayToken(relayKey);
      this.#emitPublicGatewayStatus();
      return;
    }

    const requestingPubkey = this.getCurrentPubkey?.() || null;
    if (!requestingPubkey) {
      this.log('debug', `[PublicGateway] Skipping token refresh for ${relayKey}: no active pubkey`);
      this.#clearRelayToken(relayKey);
      this.#emitPublicGatewayStatus();
      return;
    }

    const authResolution = this.#resolveRelayAuth(relayKey, requestingPubkey);
    if (!authResolution?.token) {
      this.log('debug', `[PublicGateway] Skipping token refresh for ${relayKey}: no relay auth available`);
      this.#clearRelayToken(relayKey);
      this.#scheduleRelayTokenRetry(relayKey);
      return;
    }

    const authToken = authResolution.token;
    const existing = this.publicGatewayRelayTokens.get(relayKey);
    const now = Date.now();
    const tokenMismatch = !existing?.relayAuthToken || existing.relayAuthToken !== authToken;
    const ttlSeconds = this.publicGatewaySettings?.defaultTokenTtl || 3600;

    if (existing) {
      existing.relayAuthToken = authToken;
      this.publicGatewayRelayTokens.set(relayKey, { ...existing });
    }

    const refreshAfter = existing?.refreshAfter || existing?.expiresAt || null;

    if (!force && refreshAfter && (refreshAfter - now) > 30_000 && !tokenMismatch) {
      this.#scheduleRelayTokenRefresh(relayKey, refreshAfter, existing?.expiresAt);
      const next = {
        ...state,
        token: existing.token,
        expiresAt: existing.expiresAt,
        ttlSeconds: existing.ttlSeconds,
        connectionUrl: existing.connectionUrl,
        tokenIssuedAt: existing.issuedAt || null
      };
      this.publicGatewayRelayState.set(relayKey, next);
      this.#emitPublicGatewayStatus();
      return;
    }

    if (tokenMismatch) {
      this.log('debug', `[PublicGateway] Relay auth updated for ${relayKey}; issuing new public gateway token`);
    }

    try {
      if (existing?.token && !tokenMismatch) {
        const refreshed = await bridgeClient.refreshGatewayToken(relayKey, {
          token: existing.token,
          ttlSeconds,
          relayAuthToken: authToken,
          pubkey: requestingPubkey,
          scope: 'relay-access'
        });
        const expiresAt = Number(refreshed?.expiresAt) || (now + ttlSeconds * 1000);
        const refreshAfterResult = Number(refreshed?.refreshAfter) || null;
        const sequence = refreshed?.sequence || existing?.sequence || null;

        let gatewayPath = metadata.gatewayPath || null;
        if (!gatewayPath) {
          gatewayPath = this._normalizeGatewayPath(relayKey, metadata.gatewayPath, metadata.connectionUrl);
        }
        if (!gatewayPath) {
          gatewayPath = relayKey.includes(':') ? relayKey.replace(':', '/') : relayKey;
        }
        const wsBase = route?.wsUrl || this.#computePublicGatewayWsBase(route?.gatewayOrigin || this.publicGatewaySettings?.baseUrl);
        const connectionUrl = wsBase
          ? `${wsBase}/${gatewayPath}?token=${encodeURIComponent(refreshed.token)}`
          : null;

        this.#recordRelayToken(relayKey, {
          token: refreshed.token,
          expiresAt,
          ttlSeconds,
          connectionUrl,
          baseUrl: route?.gatewayOrigin || this.publicGatewaySettings.baseUrl,
          issuedForPubkey: requestingPubkey,
          issuedAt: now,
          relayAuthToken: authToken,
          refreshAfter: refreshAfterResult,
          sequence
        }, { schedule: true });
        return;
      }

      await this.issuePublicGatewayToken(relayKey, { ttlSeconds });
    } catch (error) {
      this.log('warn', `[PublicGateway] Failed to refresh relay token for ${relayKey}: ${error.message}`);
      this.#scheduleRelayTokenRetry(relayKey);
    }
  }

  async #resolvePublicGatewayConfig(rawConfig = {}) {
    const config = this.#normalizePublicGatewayConfig(rawConfig);
    this.discoveryWarning = null;
    const previousResolved = {
      baseUrl: config.baseUrl,
      sharedSecret: config.sharedSecret,
      authMethod: config.authMethod,
      resolvedGatewayId: config.resolvedGatewayId,
      resolvedAuthMethod: config.resolvedAuthMethod,
      resolvedSecretVersion: config.resolvedSecretVersion,
      resolvedSharedSecretHash: config.resolvedSharedSecretHash,
      resolvedDisplayName: config.resolvedDisplayName,
      resolvedRegion: config.resolvedRegion,
      resolvedWsUrl: config.resolvedWsUrl,
      resolvedAt: config.resolvedAt,
      resolvedFallback: config.resolvedFallback,
      resolvedFromDiscovery: config.resolvedFromDiscovery,
      resolvedGatewayRelay: config.resolvedGatewayRelay,
      resolvedDefaultTokenTtl: config.resolvedDefaultTokenTtl,
      resolvedTokenRefreshWindowSeconds: config.resolvedTokenRefreshWindowSeconds,
      resolvedDispatcher: config.resolvedDispatcher
    };
    config.resolvedFromDiscovery = false;
    config.resolvedFallback = false;
    config.disabledReason = null;
    config.resolvedGatewayId = null;
    config.resolvedSecretVersion = null;
    config.resolvedSharedSecretHash = null;
    config.resolvedDisplayName = null;
    config.resolvedRegion = null;
    config.resolvedWsUrl = null;
    config.resolvedAt = null;
    config.resolvedGatewayRelay = null;
    config.resolvedDefaultTokenTtl = null;
    config.resolvedTokenRefreshWindowSeconds = null;
    config.resolvedDispatcher = null;

    const restorePreviousResolved = () => {
      if (config.selectionMode !== 'default') {
        return;
      }
      if (previousResolved.baseUrl != null && previousResolved.baseUrl !== '') {
        config.baseUrl = previousResolved.baseUrl;
      }
      if (previousResolved.sharedSecret != null) {
        config.sharedSecret = previousResolved.sharedSecret;
      }
      config.authMethod = previousResolved.authMethod || config.authMethod || 'relay-scoped-bearer-v1';
      config.resolvedGatewayId = previousResolved.resolvedGatewayId || null;
      config.resolvedAuthMethod = previousResolved.resolvedAuthMethod || null;
      config.resolvedSecretVersion = previousResolved.resolvedSecretVersion || null;
      config.resolvedSharedSecretHash = previousResolved.resolvedSharedSecretHash || null;
      config.resolvedDisplayName = previousResolved.resolvedDisplayName || null;
      config.resolvedRegion = previousResolved.resolvedRegion || null;
      config.resolvedWsUrl = previousResolved.resolvedWsUrl || null;
      config.resolvedAt = previousResolved.resolvedAt || null;
      config.resolvedFallback = !!previousResolved.resolvedFallback;
      config.resolvedFromDiscovery = !!previousResolved.resolvedFromDiscovery;
      config.resolvedGatewayRelay = previousResolved.resolvedGatewayRelay || null;
      config.resolvedDefaultTokenTtl = previousResolved.resolvedDefaultTokenTtl || null;
      config.resolvedTokenRefreshWindowSeconds = previousResolved.resolvedTokenRefreshWindowSeconds || null;
      config.resolvedDispatcher = previousResolved.resolvedDispatcher || null;
    };

    if (!config.enabled) {
      config.baseUrl = '';
      config.sharedSecret = '';
      return config;
    }

    if (config.selectionMode === 'manual') {
      if (!config.baseUrl) {
        config.enabled = false;
        config.disabledReason = 'Manual configuration requires a gateway URL';
        config.baseUrl = '';
        config.sharedSecret = '';
      } else {
        config.authMethod = config.sharedSecret ? 'shared-secret-v1' : 'relay-scoped-bearer-v1';
        config.resolvedAuthMethod = config.authMethod;
      }
      return config;
    }

    try {
      await this.#ensureDiscoveryClient();
    } catch (error) {
      config.disabledReason = error?.message || 'Gateway discovery unavailable';
      restorePreviousResolved();
      return config;
    }

    const refreshCatalog = () => {
      if (this.discoveryClient) {
        this.discoveredGateways = this.discoveryClient.getGateways({ includeExpired: true });
      }
    };

    refreshCatalog();

    const ensureEntrySecret = async (entry) => {
      if (!entry) return null;
      try {
        await this.discoveryClient.ensureSecret(entry.gatewayId);
        refreshCatalog();
        return this.discoveryClient.getGatewayById(entry.gatewayId);
      } catch (error) {
        this.log('warn', `[PublicGateway] Failed to retrieve shared secret for gateway ${entry.gatewayId}: ${error.message}`);
        return null;
      }
    };

    const resolveEntryForSelection = async (entry) => {
      if (!entry || entry.isExpired) return null;
      const authMethod = this.#inferGatewayAuthMethod(entry);
      if (authMethod === 'relay-scoped-bearer-v1') {
        return entry;
      }
      return ensureEntrySecret(entry);
    };

    let resolvedEntry = null;

    if (config.selectionMode === 'discovered') {
      if (!config.selectedGatewayId) {
        config.disabledReason = 'No public gateway selected';
        config.sharedSecret = '';
        return config;
      }

      const entry = this.discoveryClient.getGatewayById(config.selectedGatewayId);
      if (!entry) {
        config.disabledReason = 'Selected public gateway is offline';
        config.sharedSecret = '';
        return config;
      }

      resolvedEntry = await resolveEntryForSelection(entry);
      if (!resolvedEntry) {
        config.disabledReason = entry.isExpired
          ? 'Selected public gateway advertisement expired'
          : 'Unable to resolve selected gateway';
        config.sharedSecret = '';
        return config;
      }
    } else {
      const preferredUrl = config.preferredBaseUrl || config.baseUrl || '';
      if (preferredUrl) {
        let entry = this.discoveryClient.findGatewayByUrl(preferredUrl);
        if (entry && entry.isExpired) {
          entry = null;
        }

        resolvedEntry = await resolveEntryForSelection(entry);
      }

      if (!resolvedEntry) {
        const candidates = (this.discoveryClient.getGateways() || [])
          .filter((candidate) => !candidate.isExpired);
        if (candidates.length) {
          resolvedEntry = await resolveEntryForSelection(candidates[0]);
          if (resolvedEntry) {
            config.resolvedFallback = true;
          }
        }
      }

      if (!resolvedEntry) {
        this.discoveryWarning = 'No public gateways available; using cached discovery state';
        this.log('debug', '[PublicGateway] Discovery catalog empty; reusing cached gateway route');
        restorePreviousResolved();
        return config;
      }
    }

    config.baseUrl = resolvedEntry.publicUrl || config.baseUrl || config.preferredBaseUrl;
    config.authMethod = this.#inferGatewayAuthMethod(resolvedEntry);
    config.sharedSecret = resolvedEntry.sharedSecret || '';
    config.resolvedGatewayId = resolvedEntry.gatewayId;
    config.resolvedAuthMethod = config.authMethod;
    config.resolvedSecretVersion = resolvedEntry.sharedSecretVersion || null;
    config.resolvedSharedSecretHash = resolvedEntry.secretHash || null;
    config.resolvedDisplayName = resolvedEntry.displayName || null;
    config.resolvedRegion = resolvedEntry.region || null;
    config.resolvedWsUrl = resolvedEntry.wsUrl || null;
    config.resolvedAt = Date.now();
    config.resolvedFromDiscovery = config.selectionMode !== 'manual';
    config.resolvedGatewayRelay = resolvedEntry.relayHyperbeeKey || resolvedEntry.relayDiscoveryKey || resolvedEntry.relayReplicationTopic
      ? {
        hyperbeeKey: resolvedEntry.relayHyperbeeKey || null,
        discoveryKey: resolvedEntry.relayDiscoveryKey || null,
        replicationTopic: resolvedEntry.relayReplicationTopic || null
      }
      : null;
    config.resolvedDefaultTokenTtl = resolvedEntry.defaultTokenTtl || null;
    config.resolvedTokenRefreshWindowSeconds = resolvedEntry.tokenRefreshWindowSeconds || null;
    config.resolvedDispatcher = resolvedEntry.dispatcherPolicy || null;
    config.disabledReason = null;

    return config;
  }

  #createExternalLogger() {
    return {
      info: (message, meta) => this.#logExternal('info', message, meta),
      warn: (message, meta) => this.#logExternal('warn', message, meta),
      error: (message, meta) => this.#logExternal('error', message, meta),
      debug: (message, meta) => this.#logExternal('debug', message, meta)
    };
  }

  #logExternal(level, message, meta) {
    const parts = ['[PublicGateway]'];
    if (message) parts.push(message);
    if (meta && Object.keys(meta).length) {
      try {
        parts.push(JSON.stringify(meta));
      } catch (_) {
        parts.push(String(meta));
      }
    }
    this.log(level, parts.join(' '));
  }

  #computePublicGatewayWsBase(baseUrl) {
    if (!baseUrl) return null;
    try {
      const parsed = new URL(baseUrl);
      if (parsed.protocol === 'http:') parsed.protocol = 'ws:';
      else if (parsed.protocol === 'https:') parsed.protocol = 'wss:';
      else if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') {
        this.log('warn', `[PublicGateway] Unsupported protocol for base URL: ${parsed.protocol}`);
        return null;
      }
      return parsed.toString().replace(/\/$/, '');
    } catch (error) {
      this.log('warn', `[PublicGateway] Invalid base URL: ${error.message}`);
      return null;
    }
  }

  #emitPublicGatewayStatus() {
    this.publicGatewayStatusUpdatedAt = Date.now();
    const state = this.getPublicGatewayState();
    this.emit('public-gateway-status', state);
  }

  _normalizeOwnerKey(owner) {
    if (!owner) return null;
    try {
      return owner.trim().toLowerCase();
    } catch (_) {
      return null;
    }
  }

  _addOwnerMapping(owner, peerKey) {
    const normalized = this._normalizeOwnerKey(owner);
    if (!normalized) return;
    let peers = this.pfpOwnerIndex.get(normalized);
    if (!peers) {
      peers = new Set();
      this.pfpOwnerIndex.set(normalized, peers);
    }
    peers.add(peerKey);
  }

  _removeOwnerMapping(owner, peerKey) {
    const normalized = this._normalizeOwnerKey(owner);
    if (!normalized) return;
    const peers = this.pfpOwnerIndex.get(normalized);
    if (!peers) return;
    peers.delete(peerKey);
    if (peers.size === 0) {
      this.pfpOwnerIndex.delete(normalized);
    }
  }

  _getPeersForOwner(owner) {
    const normalized = this._normalizeOwnerKey(owner);
    if (!normalized) return [];
    const peers = this.pfpOwnerIndex.get(normalized);
    return peers ? Array.from(peers) : [];
  }

  _getPeersWithPfpDrives() {
    return Array.from(this.pfpDriveKeys.keys());
  }

  _drainStream(stream) {
    if (!stream) return Promise.resolve();
    return new Promise((resolve) => {
      let resolved = false;
      const done = () => {
        if (resolved) return;
        resolved = true;
        resolve();
      };
      stream.on('end', done);
      stream.on('close', done);
      stream.on('error', done);
      try {
        stream.resume?.();
      } catch (_) {
        done();
      }
    });
  }

  async #syncPublicGatewayRelay(relayKey, { forceTokenRefresh = false } = {}) {
    if (!this.publicGatewaySettings?.enabled) {
      this.publicGatewayRelayState.delete(relayKey);
      this.#clearRelayToken(relayKey);
      await this.#unregisterPublicGatewayVirtualRelay(relayKey);
      this.#emitPublicGatewayStatus();
      return;
    }

    if (this.#isPublicGatewayRelayKey(relayKey)) {
      this.#ensurePublicGatewayRelayEntry();
    }

    const relayData = this.activeRelays.get(relayKey);
    if (!relayData) {
      this.publicGatewayRelayState.delete(relayKey);
      this.#clearRelayToken(relayKey);
      await this.#unregisterPublicGatewayVirtualRelay(relayKey);
      this.#emitPublicGatewayStatus();
      return;
    }

    const peers = Array.from(relayData.peers || []);
    const metadata = relayData.metadata || {};
    const metadataCopy = metadata ? { ...metadata } : {};

    if (this.#isPublicGatewayRelayKey(relayKey)) {
      metadataCopy.identifier = metadataCopy.identifier || relayKey;
      metadataCopy.name = metadataCopy.name || this.publicGatewaySettings?.resolvedDisplayName || 'Public Gateway Relay';
      metadataCopy.description = metadataCopy.description || 'Replicated public gateway relay dataset';
      this.#applyPublicGatewayPathMetadata(metadataCopy);
      metadataCopy.isPublic = true;
      if (metadataCopy.requiresAuth === undefined) {
        metadataCopy.requiresAuth = false;
      }
      if (!metadataCopy.gatewayRelay && this.publicGatewaySettings?.resolvedGatewayRelay) {
        const gatewayRelay = this.publicGatewaySettings.resolvedGatewayRelay;
        metadataCopy.gatewayRelay = {
          hyperbeeKey: gatewayRelay.hyperbeeKey || null,
          discoveryKey: gatewayRelay.discoveryKey || null,
          replicationTopic: gatewayRelay.replicationTopic || null,
          defaultTokenTtl: gatewayRelay.defaultTokenTtl ?? null,
          tokenRefreshWindowSeconds: gatewayRelay.tokenRefreshWindowSeconds ?? null,
          dispatcher: gatewayRelay.dispatcher || null
        };
      }
      relayData.metadata = {
        ...metadata,
        ...metadataCopy
      };
    }

    if (!this.#isPublicGatewayRelayKey(relayKey) && metadataCopy?.directJoinOnly === true) {
      this.publicGatewayRelayState.delete(relayKey);
      this.#clearRelayToken(relayKey);
      this.log('debug', `[PublicGateway] Skipping registration for direct-join-only relay ${relayKey}`);
      this.#emitPublicGatewayStatus();
      return;
    }

    if (!this.#isPublicGatewayRelayKey(relayKey)
      && metadataCopy?.isHosted === false
      && metadataCopy?.isJoined !== true) {
      this.publicGatewayRelayState.delete(relayKey);
      this.#clearRelayToken(relayKey);
      this.log('debug', `[PublicGateway] Skipping registration for non-hosted relay ${relayKey}`, {
        isHosted: metadataCopy?.isHosted ?? null,
        isJoined: metadataCopy?.isJoined ?? null
      });
      this.#emitPublicGatewayStatus();
      return;
    }

    const route = await this.#resolveGatewayRoute({ relayKey, metadata: metadataCopy });
    const normalizedPublicIdentifier =
      typeof metadataCopy?.publicIdentifier === 'string' && metadataCopy.publicIdentifier.trim()
        ? metadataCopy.publicIdentifier.trim()
        : (
          typeof metadataCopy?.identifier === 'string'
          && metadataCopy.identifier.trim()
          && !/^[a-fA-F0-9]{64}$/.test(metadataCopy.identifier.trim())
            ? metadataCopy.identifier.trim()
            : null
        );
    if (route?.gatewayId && !metadataCopy?.gatewayId) {
      metadataCopy.gatewayId = route.gatewayId;
    }
    if (route?.gatewayOrigin && !metadataCopy?.gatewayOrigin) {
      metadataCopy.gatewayOrigin = route.gatewayOrigin;
    }
    if (normalizedPublicIdentifier && !metadataCopy?.publicIdentifier) {
      metadataCopy.publicIdentifier = normalizedPublicIdentifier;
    }
    const relayStateIdentity = {
      gatewayId: route?.gatewayId || metadataCopy?.gatewayId || null,
      gatewayOrigin: route?.gatewayOrigin || metadataCopy?.gatewayOrigin || null,
      publicIdentifier: normalizedPublicIdentifier || metadataCopy?.publicIdentifier || null,
      name: metadataCopy?.name || null
    };
    const bridgeClient = await this.#getGatewayBridgeClient(route);
    if (!bridgeClient?.isEnabled?.()) {
      this.publicGatewayRelayState.set(relayKey, {
        relayKey,
        status: 'error',
        peerCount: peers.length,
        lastSyncedAt: Date.now(),
        message: 'Gateway route unavailable or unauthorized',
        metadata: metadataCopy,
        peers,
        ...relayStateIdentity
      });
      this.#clearRelayToken(relayKey);
      this.#emitPublicGatewayStatus();
      return;
    }

    const now = Date.now();

    const relayCores = await this.#collectRelayCoreMetadata(relayKey, metadataCopy?.identifier || null);
    if (relayCores?.length) {
      this.log('debug', `[PublicGateway] Collected relay core metadata for registration relay=${relayKey}`, {
        cores: relayCores.length
      });
    } else {
      this.log('debug', `[PublicGateway] No relay core metadata found for relay=${relayKey}`);
    }

    if (!peers.length) {
      if (metadataCopy?.isOpen === true) {
        const payload = {
          peers,
          metadata: metadataCopy
        };
        if (relayCores?.length) {
          payload.relayCores = relayCores;
          payload.relayCoresMode = 'merge';
        }
        try {
          const registrationResult = await bridgeClient.registerRelay(relayKey, payload);
          if (!registrationResult?.success) {
            throw new Error(registrationResult?.error || 'Registration rejected by gateway');
          }
          await this.#syncOpenJoinPool(relayKey, metadataCopy);
          this.publicGatewayRelayState.set(relayKey, {
            relayKey,
            status: 'offline',
            peerCount: 0,
            lastSyncedAt: now,
            message: 'No peers connected',
            metadata: metadataCopy,
            peers: [],
            blindPeer: this.blindPeerSummary || null,
            relayCores: relayCores || [],
            localConnectionUrl: this.#isPublicGatewayRelayKey(relayKey)
              ? `${(this.config?.urls?.hostname || this.gatewayServer?.getServerUrls()?.hostname || 'ws://127.0.0.1:8443').replace(/\/$/, '')}/${this.#getPublicGatewayRelayPath()}`
              : null,
            requiresAuth: this.#isPublicGatewayRelayKey(relayKey) ? false : metadataCopy?.requiresAuth ?? true,
            ...relayStateIdentity
          });
        } catch (error) {
          this.publicGatewayRelayState.set(relayKey, {
            relayKey,
            status: 'error',
            peerCount: 0,
            lastSyncedAt: now,
            message: error.message,
            metadata: metadataCopy,
            peers: [],
            blindPeer: this.blindPeerSummary || null,
            relayCores: relayCores || [],
            localConnectionUrl: this.#isPublicGatewayRelayKey(relayKey)
              ? `${(this.config?.urls?.hostname || this.gatewayServer?.getServerUrls()?.hostname || 'ws://127.0.0.1:8443').replace(/\/$/, '')}/${this.#getPublicGatewayRelayPath()}`
              : null,
            requiresAuth: this.#isPublicGatewayRelayKey(relayKey) ? false : metadataCopy?.requiresAuth ?? true,
            ...relayStateIdentity
          });
          this.log('warn', `[PublicGateway] Failed to register offline relay ${relayKey}: ${error.message}`);
        }
        this.#clearRelayToken(relayKey);
        this.#emitPublicGatewayStatus();
        return;
      }
      try {
        await bridgeClient.unregisterRelay(relayKey);
        this.publicGatewayRelayState.set(relayKey, {
          relayKey,
          status: 'offline',
          peerCount: 0,
          lastSyncedAt: now,
          message: 'No peers connected',
          metadata: metadataCopy,
          peers: [],
          blindPeer: this.blindPeerSummary || null,
          relayCores: relayCores || [],
          localConnectionUrl: this.#isPublicGatewayRelayKey(relayKey)
            ? `${(this.config?.urls?.hostname || this.gatewayServer?.getServerUrls()?.hostname || 'ws://127.0.0.1:8443').replace(/\/$/, '')}/${this.#getPublicGatewayRelayPath()}`
            : null,
          requiresAuth: this.#isPublicGatewayRelayKey(relayKey) ? false : metadataCopy?.requiresAuth ?? true,
          ...relayStateIdentity
        });
      } catch (error) {
        this.publicGatewayRelayState.set(relayKey, {
          relayKey,
          status: 'error',
          peerCount: 0,
          lastSyncedAt: now,
          message: error.message,
          metadata: metadataCopy,
          peers: [],
          blindPeer: this.blindPeerSummary || null,
          relayCores: relayCores || [],
          localConnectionUrl: this.#isPublicGatewayRelayKey(relayKey)
            ? `${(this.config?.urls?.hostname || this.gatewayServer?.getServerUrls()?.hostname || 'ws://127.0.0.1:8443').replace(/\/$/, '')}/${this.#getPublicGatewayRelayPath()}`
            : null,
          requiresAuth: this.#isPublicGatewayRelayKey(relayKey) ? false : metadataCopy?.requiresAuth ?? true,
          ...relayStateIdentity
        });
        this.log('warn', `[PublicGateway] Failed to unregister relay ${relayKey}: ${error.message}`);
      }
      this.#clearRelayToken(relayKey);
      this.#emitPublicGatewayStatus();
      return;
    }

    const payload = {
      peers,
      metadata: metadataCopy
    };
    if (relayCores?.length) {
      payload.relayCores = relayCores;
      payload.relayCoresMode = 'merge';
    }

    try {
      const registrationResult = await bridgeClient.registerRelay(relayKey, payload);
      if (!registrationResult?.success) {
        throw new Error(registrationResult?.error || 'Registration rejected by gateway');
      }
      if (registrationResult.blindPeer) {
        this.blindPeerSummary = registrationResult.blindPeer;
      }
      if (registrationResult.hyperbee?.hyperbeeKey) {
        try {
          await this.publicGatewayRelayClient.configure({
            hyperbeeKey: registrationResult.hyperbee.hyperbeeKey,
            discoveryKey: registrationResult.hyperbee.discoveryKey
          });
          this.hyperbeeAdapter?.setRelayClient(this.publicGatewayRelayClient);
          for (const protocol of this.gatewayProtocols.values()) {
            this.publicGatewayRelayClient.attachProtocol(protocol);
          }
          metadataCopy.gatewayRelay = {
            hyperbeeKey: registrationResult.hyperbee.hyperbeeKey,
            discoveryKey: registrationResult.hyperbee.discoveryKey,
            replicationTopic: registrationResult.hyperbee.replicationTopic || null,
            defaultTokenTtl: registrationResult.hyperbee.defaultTokenTtl ?? null,
            tokenRefreshWindowSeconds: registrationResult.hyperbee.tokenRefreshWindowSeconds ?? null,
            dispatcher: registrationResult.hyperbee.dispatcher || null
          };
          relayData.metadata = {
            ...metadata,
            gatewayRelay: metadataCopy.gatewayRelay
          };
          if (this.#isPublicGatewayRelayKey(relayKey)) {
            this.#ensurePublicGatewayRelayEntry({ hyperbee: registrationResult.hyperbee });
          }
        } catch (error) {
          this.log('warn', `[PublicGateway] Failed to configure Hyperbee relay client: ${error.message}`);
        }
      }

      const registrationBlindPeer = registrationResult?.blindPeer;
      if (registrationBlindPeer && typeof registrationBlindPeer === 'object') {
        await this.#applyBlindPeerInfo(registrationBlindPeer, { persist: true }).catch((error) => {
          this.log('warn', `[PublicGateway] Failed to persist blind peer announcement: ${error.message}`);
        });
      } else {
        this.log('debug', '[PublicGateway] Registration response missing blind peer summary; preserving existing configuration');
      }
      if ((!this.blindPeerSummary?.enabled || !this.blindPeerSummary?.publicKey)
        && (!Array.isArray(this.publicGatewaySettings?.blindPeerKeys) || !this.publicGatewaySettings.blindPeerKeys.length)) {
        const fallbackReason = registrationBlindPeer && typeof registrationBlindPeer === 'object'
          ? 'registration-disabled'
          : 'registration-missing';
        this.#maybeFetchBlindPeerInfo({ reason: fallbackReason }).catch((error) => {
          this.log('debug', `[PublicGateway] Blind peer fallback lookup failed after registration: ${error?.message || error}`);
        });
      }

      await this.#syncOpenJoinPool(relayKey, metadataCopy);

      if (this.#isPublicGatewayRelayKey(relayKey)) {
        await this.#registerPublicGatewayVirtualRelay(metadataCopy);
      }
      const tokenInfo = this.publicGatewayRelayTokens.get(relayKey) || null;
      const localBase = this.config?.urls?.hostname || this.gatewayServer?.getServerUrls()?.hostname || 'ws://127.0.0.1:8443';
      const localConnectionUrl = this.#isPublicGatewayRelayKey(relayKey)
        ? `${localBase.replace(/\/$/, '')}/${this.#getPublicGatewayRelayPath()}`
        : null;
      this.publicGatewayRelayState.set(relayKey, {
        relayKey,
        status: 'registered',
        peerCount: peers.length,
        lastSyncedAt: now,
        message: null,
        metadata: metadataCopy,
        peers,
        blindPeer: registrationResult.blindPeer || this.blindPeerSummary || null,
        token: tokenInfo?.token || null,
        relayCores: relayCores || [],
        expiresAt: tokenInfo?.expiresAt || null,
        ttlSeconds: tokenInfo?.ttlSeconds || null,
        connectionUrl: tokenInfo?.connectionUrl || null,
        tokenIssuedAt: tokenInfo?.issuedAt || null,
        defaultTokenTtl: registrationResult.hyperbee?.defaultTokenTtl ?? null,
        tokenRefreshWindowSeconds: registrationResult.hyperbee?.tokenRefreshWindowSeconds ?? null,
        dispatcher: registrationResult.hyperbee?.dispatcher || null,
        localConnectionUrl: localConnectionUrl || tokenInfo?.localConnectionUrl || null,
        requiresAuth: this.#isPublicGatewayRelayKey(relayKey) ? false : metadataCopy?.requiresAuth ?? true,
        ...relayStateIdentity
      });
      if (this.#isPublicGatewayRelayKey(relayKey)) {
        this.log('info', '[PublicGateway] Public gateway relay bridge ready', {
          relayKey,
          localUrl: localConnectionUrl,
          remoteUrl: tokenInfo?.connectionUrl || null
        });
      }
      if (!(this.#isPublicGatewayRelayKey(relayKey) && metadataCopy.requiresAuth === false)) {
        await this.#refreshRelayToken(relayKey, {
          force: forceTokenRefresh || !tokenInfo
        });
      } else {
        this.#emitPublicGatewayStatus();
      }
    } catch (error) {
      this.publicGatewayRelayState.set(relayKey, {
        relayKey,
        status: 'error',
        peerCount: peers.length,
        lastSyncedAt: now,
        message: error.message,
        metadata: metadataCopy,
        peers,
        blindPeer: this.blindPeerSummary || null,
        relayCores: relayCores || [],
        ...relayStateIdentity
      });
      this.log('warn', `[PublicGateway] Failed to sync relay ${relayKey}: ${error.message}`);
      this.#scheduleRelayTokenRetry(relayKey);
    }

    this.#emitPublicGatewayStatus();
  }

  async _fetchPfpFromPeers(owner, file) {
    const ownerPeers = owner ? this._getPeersForOwner(owner) : [];
    const generalPeers = this._getPeersWithPfpDrives().filter((peerKey) => !ownerPeers.includes(peerKey));
    const candidates = [...ownerPeers, ...generalPeers];

    if (!candidates.length) {
      this.log('warn', `[PublicGateway] No candidate peers for PFP fetch owner=${owner || 'n/a'} file=${file}`);
      return null;
    }

    this.log('debug', `[PublicGateway] Attempting PFP fetch owner=${owner || 'n/a'} file=${file} candidates=${candidates.length}`);

    for (const peerKey of candidates) {
      const peer = this.activePeers.find(p => p.publicKey === peerKey);
      if (!peer) {
        this.log('debug', `[PublicGateway] Candidate peer missing from active list ${peerKey.slice(0, 8)} owner=${owner || 'n/a'}`);
        continue;
      }
      let healthy = this.peerHealthManager.isPeerHealthy(peerKey);
      if (!healthy) {
        try {
          healthy = await this.peerHealthManager.checkPeerHealth(peer, this.connectionPool);
        } catch (err) {
          this.log('warn', `PFP health check failed for peer ${peerKey.slice(0, 8)}: ${err.message}`);
          healthy = false;
        }
      }
      if (!healthy) continue;

      try {
        const stream = await requestPfpFromPeer(peer, owner || null, file, this.connectionPool);
        peer.lastSeen = Date.now();
        if ((stream.statusCode || 200) === 200) {
          this.log('info', `[PublicGateway] PFP proxy success owner=${owner || 'n/a'} file=${file} peer=${peerKey.slice(0, 8)}`);
          return stream;
        }

        if ((stream.statusCode || 500) === 404) {
          this.log('debug', `[PublicGateway] Peer responded 404 for PFP owner=${owner || 'n/a'} file=${file} peer=${peerKey.slice(0, 8)}`);
          await this._drainStream(stream);
          continue;
        }

        return stream;
      } catch (error) {
        this.log('warn', `[PublicGateway] Failed to proxy PFP owner=${owner || 'n/a'} file=${file} peer=${peerKey.slice(0, 8)} error=${error.message}`);
      }
    }

    this.log('warn', `[PublicGateway] Exhausted peers without PFP owner=${owner || 'n/a'} file=${file}`);
    return null;
  }

  async _fetchPfpFromRelay(identifier, owner, file) {
    const normalized = this._normalizeRelayIdentifier(identifier);
    if (!normalized) return null;

    const relayEntry = this.activeRelays.get(normalized);
    if (!relayEntry || !relayEntry.peers?.size) {
      return null;
    }

    const peerKeys = Array.from(relayEntry.peers);
    let encounteredNotFound = false;
    let attempted = false;

    for (const peerKey of peerKeys) {
      const peer = this.activePeers.find(p => p.publicKey === peerKey);
      if (!peer) continue;

      let healthy = this.peerHealthManager.isPeerHealthy(peerKey);
      if (!healthy) {
        try {
          healthy = await this.peerHealthManager.checkPeerHealth(peer, this.connectionPool);
        } catch (error) {
          this.log('warn', `PFP health probe failed for relay host ${peerKey.slice(0, 8)}: ${error.message}`);
          healthy = false;
        }
      }

      if (!healthy) {
        continue;
      }

      try {
        attempted = true;
        const stream = await requestPfpFromPeer(peer, owner || null, file, this.connectionPool);
        peer.lastSeen = Date.now();

        if ((stream.statusCode || 200) === 200) {
          return stream;
        }

        if ((stream.statusCode || 500) === 404) {
          encounteredNotFound = true;
        }

        await this._drainStream(stream);
      } catch (error) {
        this.log('warn', `Failed to proxy relay PFP ${file} for ${normalized} via ${peerKey.slice(0, 8)}: ${error.message}`);
      }
    }

    if (encounteredNotFound) {
      return false;
    }

    return null;
  }

  _onProtocolCreated({ publicKey, protocol, context = {} }) {
    if (!protocol) return;
    const isServer = !!context.isServer;
    if (!isServer) return;

    this.log('debug', '[PublicGateway] Hyperswarm protocol created for peer', {
      peer: publicKey,
      isServer
    });

    protocol.handle('/gateway/register', async (request) => {
      return this._handleGatewayRegisterRequest(publicKey, request);
    });
  }

  #buildHandshakePayload({ isServer }) {
    const peerId = this.ownPeerPublicKey
      || this.connectionPool?.getPublicKey?.()
      || this.getCurrentPubkey?.()
      || null;
    const relayCount = this.activeRelays?.size || 0;
    const replicaInfo = this.getPublicGatewayReplicaInfo();
    const gatewayOrigin = this.#normalizeGatewayOrigin(
      this.publicGatewaySettings?.baseUrl
      || this.publicGatewaySettings?.preferredBaseUrl
      || null
    );
    const gatewayId = this.#normalizeGatewayId(this.publicGatewaySettings?.resolvedGatewayId || this.publicGatewaySettings?.selectedGatewayId || null);

    const payload = {
      role: PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED ? 'gateway-replica' : 'relay-peer',
      isGateway: false,
      gatewayReplica: PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED,
      peerId,
      relayCount,
      delegateReqToPeers: !!this.publicGatewaySettings?.delegateReqToPeers,
      isServer: !!isServer
    };

    if (gatewayOrigin) {
      payload.gatewayOrigin = gatewayOrigin;
      payload.publicUrl = gatewayOrigin;
    }
    if (gatewayId) {
      payload.gatewayId = gatewayId;
    }

    if (replicaInfo) {
      payload.hyperbeeKey = replicaInfo.hyperbeeKey || null;
      payload.hyperbeeDiscoveryKey = replicaInfo.discoveryKey || null;
      payload.hyperbeeLength = replicaInfo.length || 0;
      payload.hyperbeeContiguousLength = replicaInfo.contiguousLength || 0;
      payload.hyperbeeLag = replicaInfo.lag || 0;
      payload.hyperbeeVersion = replicaInfo.version || 0;
      payload.hyperbeeUpdatedAt = replicaInfo.updatedAt || 0;
      if (replicaInfo.telemetry) {
        payload.telemetry = replicaInfo.telemetry;
      }
    }

    return payload;
  }

  _onProtocolHandshake({ publicKey, protocol, handshake, context = {}, stage = 'open' }) {
    if (!handshake) return;
    this.peerHandshakes.set(publicKey, handshake);

    const handshakeKeys = handshake ? Object.keys(handshake) : [];
    const summary = `peer=${publicKey} stage=${stage} role=${handshake?.role ?? 'unknown'} isGateway=${handshake?.isGateway ?? 'unknown'}`;
    this.log('debug', `[PublicGateway] Hyperswarm handshake received (${summary})`);

    if (handshake) {
      let serialized = null;
      try {
        serialized = JSON.stringify(handshake);
      } catch (_) {
        serialized = '[unserializable]';
      }
      this.log('debug', `[PublicGateway] Hyperswarm handshake payload peer=${publicKey} keys=${handshakeKeys.join(',')} payload=${serialized}`);
    }

    if (Object.prototype.hasOwnProperty.call(handshake, 'blindPeerEnabled')) {
      this.#applyBlindPeerInfo({
        enabled: handshake.blindPeerEnabled,
        publicKey: handshake.blindPeerPublicKey || null,
        encryptionKey: handshake.blindPeerEncryptionKey || null,
        maxBytes: handshake.blindPeerMaxBytes ?? null
      }, { persist: false }).then(() => {
        if ((!this.blindPeerSummary?.enabled || !this.blindPeerSummary?.publicKey)
          && (!Array.isArray(this.publicGatewaySettings?.blindPeerKeys) || !this.publicGatewaySettings.blindPeerKeys.length)) {
          this.#maybeFetchBlindPeerInfo({ reason: 'handshake-disabled' }).catch((error) => {
            this.log('debug', `[PublicGateway] Blind peer fallback lookup failed after handshake: ${error?.message || error}`);
          });
        }
      }).catch((error) => {
        this.log('debug', `[PublicGateway] Failed to apply blind peer info from handshake: ${error.message}`);
      });
    } else {
      this.#maybeFetchBlindPeerInfo({ reason: 'handshake-missing' }).catch((error) => {
        this.log('debug', `[PublicGateway] Blind peer fallback lookup failed: ${error?.message || error}`);
      });
    }

    if (handshake.role === 'relay' || handshake.isGateway === false) {
      this.healthState.services.hyperswarmStatus = 'connected';
      this.healthState.services.protocolStatus = 'connected';
      this.emit('status', this.getStatus());
    }

    const isGatewayLike = handshake?.isGateway === true
      || handshake?.role === 'gateway'
      || handshake?.role === 'gateway-replica'
      || this.#isResolvedGatewayPeer(publicKey, handshake);

    if (isGatewayLike) {
      if (protocol) {
        this.gatewayProtocols.set(publicKey, protocol);
        const cleanup = () => {
          this.gatewayProtocols.delete(publicKey);
        };
        protocol.once('close', cleanup);
        protocol.once('destroy', cleanup);
        protocol.mux?.stream?.once('close', cleanup);
      }
      this.log('debug', '[PublicGateway] Attaching protocol to public gateway relay client (handshake)', {
        peer: publicKey,
        handshakeRole: handshake.role,
        isGateway: handshake.isGateway,
        protocolOpen: protocol?.isOpen
      });
      this.attachGatewayProtocol(publicKey, protocol);
    } else {
      this.log('debug', `[PublicGateway] Hyperswarm handshake did not identify peer as gateway (peer=${publicKey} role=${handshake?.role ?? 'unknown'} isGateway=${handshake?.isGateway ?? 'unknown'})`);
    }
  }

  #isResolvedGatewayPeer(peerPublicKey, handshake = {}) {
    const resolvedGatewayId = this.publicGatewaySettings?.resolvedGatewayId;
    if (!resolvedGatewayId) return false;

    const normalize = (value) => (typeof value === 'string' ? value.toLowerCase() : null);

    const target = normalize(resolvedGatewayId);
    if (!target) return false;

    const candidates = new Set();
    candidates.add(normalize(peerPublicKey));
    candidates.add(normalize(handshake?.relayPublicKey));
    candidates.add(normalize(handshake?.gatewayPublicKey));

    return Array.from(candidates).some((candidate) => candidate === target);
  }

  attachGatewayProtocol(peerPublicKey, protocol) {
    if (!protocol) {
      this.log('debug', '[PublicGateway] attachGatewayProtocol invoked without protocol', {
        peer: peerPublicKey
      });
      return;
    }

    this.log('debug', '[PublicGateway] Attaching gateway protocol stream', {
      peer: peerPublicKey,
      protocolOpen: protocol?.isOpen ?? null
    });

    try {
      this.publicGatewayRelayClient?.attachProtocol(protocol);
      this.#startGatewayTelemetry(peerPublicKey, protocol);
    } catch (error) {
      this.log('warn', `[PublicGateway] Failed to attach gateway protocol stream: ${error.message}`);
    }
  }

  _onPeerTelemetry({ publicKey, payload }) {
    if (!publicKey || !payload) return;
    this.dispatcher?.reportPeerMetrics(publicKey, {
      peerId: publicKey,
      latencyMs: Number(payload.latencyMs) || 0,
      inFlightJobs: Number(payload.inFlightJobs) || 0,
      failureRate: Number(payload.failureRate) || 0,
      hyperbeeVersion: payload.hyperbeeVersion,
      hyperbeeLag: payload.hyperbeeLag,
      queueDepth: payload.queueDepth,
      reportedAt: Number(payload.reportedAt) || Date.now()
    });
  }

  log(level, message) {
    const entry = {
      id: `${Date.now()}-${Math.random().toString(16).slice(2, 8)}`,
      level,
      message,
      timestamp: new Date().toISOString()
    };
    this.logs.push(entry);
    if (this.logs.length > MAX_LOG_ENTRIES) {
      this.logs.shift();
    }
    this.emit('log', entry);
  }

  async start(config = {}) {
    if (this.isRunning) {
      return;
    }

    const parsedPort = Number(config.port);
    const port = Number.isFinite(parsedPort) && parsedPort >= 0
      ? parsedPort
      : DEFAULT_PORT;
    const hostname = config.hostname || 'localhost';
    const listenHost = config.listenHost || '127.0.0.1';
    this.log('info', `Starting gateway on port ${port}`);

    global.joinSessions = global.joinSessions || new Map();

    this.app = express();
    this.app.use(express.json({ limit: '2mb' }));

    this.gatewayServer = new LocalGatewayServer({
      hostname,
      port,
      listenHost
    });

    try {
      await this.gatewayServer.init();

      this.setupRoutes();

      const { server, wss } = await this.gatewayServer.startServer(
        (ws, req) => this.handleGatewayWebSocketConnection(ws, req),
        this.app,
        () => this.log('info', `Gateway listening on port ${this.gatewayServer?.config?.port || port}`)
      );

      this.server = server;
      this.wss = wss;
      await this.connectionPool.initialize();
      this.config = {
        hostname,
        port: this.gatewayServer?.config?.port || port,
        listenHost,
        urls: this.gatewayServer.getServerUrls()
      };

      this.isRunning = true;
      this.startedAt = Date.now();
      this.healthState.startTime = this.startedAt;
      this.healthState.services.gatewayStatus = 'online';
      this.healthState.services.hyperswarmStatus = 'connected';

      this.healthInterval = setInterval(() => {
        this.healthState.lastCheck = Date.now();
        this.emit('status', this.getStatus());
      }, 30000);
      this.#refreshOpenJoinPoolSyncInterval();

      this.emit('status', this.getStatus());
    } catch (error) {
      this.log('error', `Gateway failed to start: ${error?.message || error}`);
      if (this.healthInterval) {
        clearInterval(this.healthInterval);
        this.healthInterval = null;
      }
      try {
        await this.connectionPool.destroy();
      } catch (_) {}
      if (this.wss) {
        try {
          await new Promise(resolve => this.wss.close(resolve));
        } catch (_) {}
        this.wss = null;
      }
      if (this.server) {
        try {
          await new Promise(resolve => this.server.close(resolve));
        } catch (_) {}
        this.server = null;
      }
      this.app = null;
      this.gatewayServer = null;
      this.config = null;
      this.isRunning = false;
      this.startedAt = null;
      this.healthState.status = 'offline';
      this.healthState.services.gatewayStatus = 'offline';
      this.healthState.services.hyperswarmStatus = 'disconnected';
      throw error;
    }
  }

  async stop() {
    if (!this.isRunning) return;

    this.log('info', 'Stopping gateway');

    if (this.healthInterval) {
      clearInterval(this.healthInterval);
      this.healthInterval = null;
    }
    if (this.openJoinPoolSyncInterval) {
      clearInterval(this.openJoinPoolSyncInterval);
      this.openJoinPoolSyncInterval = null;
    }

    for (const timer of this.eventCheckTimers.values()) {
      clearTimeout(timer);
    }
    this.eventCheckTimers.clear();

    for (const { ws } of this.wsConnections.values()) {
      try { ws.close(); } catch (_) {}
    }
    this.wsConnections.clear();

    for (const cleanup of this.gatewayTelemetryTimers.values()) {
      try {
        cleanup();
      } catch (_) {}
    }
    this.gatewayTelemetryTimers.clear();

    await this.publicGatewayRelayClient?.close?.();
    await this.#unregisterPublicGatewayVirtualRelay();

    await this.connectionPool.destroy();

    if (this.wss) {
      await new Promise(resolve => this.wss.close(resolve));
      this.wss = null;
    }

    if (this.server) {
      await new Promise(resolve => this.server.close(resolve));
      this.server = null;
    }

    this.app = null;
    this.isRunning = false;
    this.startedAt = null;
    this.healthState.status = 'offline';
    this.healthState.services.gatewayStatus = 'offline';

    this.emit('status', this.getStatus());
  }

  getPublicGatewayState() {
    const gatewayAccessCatalog = Array.from(this.gatewayAccessCatalog.values())
      .map((entry) => ({ ...(entry || {}) }))
      .sort((left, right) => {
        const byState = String(left.hostingState || '').localeCompare(String(right.hostingState || ''));
        if (byState !== 0) return byState;
        return String(left.gatewayOrigin || left.gatewayId || '').localeCompare(String(right.gatewayOrigin || right.gatewayId || ''));
      });
    const gatewayByOrigin = new Map();
    const gatewayById = new Map();

    for (const gateway of this.discoveredGateways || []) {
      const normalizedOrigin = this.#normalizeGatewayOrigin(gateway?.publicUrl || gateway?.gatewayOrigin || null);
      const normalizedId = this.#normalizeGatewayId(gateway?.gatewayId || null);
      if (normalizedOrigin && !gatewayByOrigin.has(normalizedOrigin)) {
        gatewayByOrigin.set(normalizedOrigin, gateway);
      }
      if (normalizedId && !gatewayById.has(normalizedId)) {
        gatewayById.set(normalizedId, gateway);
      }
    }

    for (const entry of gatewayAccessCatalog) {
      const normalizedOrigin = this.#normalizeGatewayOrigin(entry?.gatewayOrigin || null);
      const normalizedId = this.#normalizeGatewayId(entry?.gatewayId || null);
      if (normalizedOrigin && !gatewayByOrigin.has(normalizedOrigin)) {
        gatewayByOrigin.set(normalizedOrigin, entry);
      }
      if (normalizedId && !gatewayById.has(normalizedId)) {
        gatewayById.set(normalizedId, entry);
      }
    }

    const relays = {};
    for (const [key, value] of this.publicGatewayRelayState.entries()) {
      const metadata = value?.metadata && typeof value.metadata === 'object' ? value.metadata : {};
      const rawGatewayOrigin = this.#normalizeGatewayOrigin(value?.gatewayOrigin || metadata?.gatewayOrigin || null);
      const rawGatewayId = this.#normalizeGatewayId(value?.gatewayId || metadata?.gatewayId || null);
      const matchedGateway = rawGatewayOrigin
        ? (gatewayByOrigin.get(rawGatewayOrigin) || null)
        : (rawGatewayId ? (gatewayById.get(rawGatewayId) || null) : null);
      const canonicalGatewayOrigin = this.#normalizeGatewayOrigin(
        matchedGateway?.publicUrl || matchedGateway?.gatewayOrigin || rawGatewayOrigin || null
      );
      const canonicalGatewayId = this.#normalizeGatewayId(
        matchedGateway?.gatewayId || rawGatewayId || null
      );
      relays[key] = {
        ...value,
        message: typeof value?.message === 'string' ? value.message : null,
        gatewayId: canonicalGatewayId,
        gatewayOrigin: canonicalGatewayOrigin,
        publicIdentifier: value?.publicIdentifier || metadata?.publicIdentifier || metadata?.identifier || null,
        name: value?.name || metadata?.name || null,
        error:
          value?.error
          || (value?.status === 'error' && typeof value?.message === 'string' ? value.message : null)
      };
    }

    const config = this.publicGatewaySettings || {};
    const enabled = !!config.enabled;
    const summary = this.blindPeerSummary;
    const defaultKeys = Array.isArray(config.blindPeerKeys) ? config.blindPeerKeys.filter(Boolean) : [];
    const manualKeys = Array.isArray(config.blindPeerManualKeys) ? config.blindPeerManualKeys.filter(Boolean) : [];
    const summaryKeys = summary?.publicKey ? [summary.publicKey] : [];
    const blindPeerKeys = summaryKeys.length ? summaryKeys : defaultKeys;
    const combinedBlindPeerKeys = Array.from(new Set([...manualKeys, ...blindPeerKeys]));
    const approvedCatalogKeys = new Set(
      gatewayAccessCatalog
        .filter((entry) => entry?.hostingState === 'approved')
        .map((entry) => this.#gatewayAccessCatalogKey(entry))
        .filter(Boolean)
    );
    const approvedCatalogByKey = new Map(
      gatewayAccessCatalog
        .filter((entry) => entry?.hostingState === 'approved')
        .map((entry) => [
          this.#gatewayAccessCatalogKey(entry),
          entry
        ])
        .filter(([key]) => !!key)
    );
    const authorizedGateways = (this.discoveredGateways || [])
      .filter((gateway) => approvedCatalogKeys.has(this.#gatewayAccessCatalogKey({
        gatewayId: gateway?.gatewayId || null,
        gatewayOrigin: gateway?.publicUrl || gateway?.gatewayOrigin || null
      })))
      .map((gateway) => {
        const catalogEntry = approvedCatalogByKey.get(this.#gatewayAccessCatalogKey({
          gatewayId: gateway?.gatewayId || null,
          gatewayOrigin: gateway?.publicUrl || gateway?.gatewayOrigin || null
        })) || null;
        return {
          ...gateway,
          operatorIdentity: cloneJson(catalogEntry?.operatorIdentity || null)
        };
      });

    return {
      enabled,
      authMethod: config.resolvedAuthMethod || config.authMethod || null,
      selectionMode: config.selectionMode || 'default',
      selectedGatewayId: config.selectedGatewayId || null,
      preferredBaseUrl: config.preferredBaseUrl || null,
      baseUrl: enabled ? config.baseUrl || null : null,
      resolvedGatewayId: config.resolvedGatewayId || null,
      resolvedDisplayName: config.resolvedDisplayName || null,
      resolvedRegion: config.resolvedRegion || null,
      resolvedSecretVersion: config.resolvedSecretVersion || null,
      resolvedFallback: !!config.resolvedFallback,
      resolvedFromDiscovery: !!config.resolvedFromDiscovery,
      resolvedAt: config.resolvedAt || null,
      resolvedGatewayRelay: config.resolvedGatewayRelay || null,
      resolvedDefaultTokenTtl: config.resolvedDefaultTokenTtl || null,
      resolvedTokenRefreshWindowSeconds: config.resolvedTokenRefreshWindowSeconds || null,
      resolvedDispatcher: config.resolvedDispatcher || null,
      delegateReqToPeers: !!config.delegateReqToPeers,
      defaultTokenTtl: config.defaultTokenTtl || 3600,
      blindPeer: {
        enabled: summary?.enabled ?? !!config.blindPeerEnabled,
        keys: blindPeerKeys,
        manualKeys,
        combinedKeys: combinedBlindPeerKeys,
        encryptionKey: summary?.encryptionKey || config.blindPeerEncryptionKey || null,
        maxBytes: config.blindPeerMaxBytes ?? null,
        storageUsageBytes: summary?.storageUsageBytes ?? null,
        trustedPeers: Array.isArray(summary?.trustedPeers) ? summary.trustedPeers : [],
        summary: summary || null
      },
      blindPeerCatalog: cloneJson(config.gatewayBlindPeerCatalog || {}),
      wsBase: enabled ? (config.resolvedWsUrl || this.publicGatewayWsBase) : null,
      lastUpdatedAt: this.publicGatewayStatusUpdatedAt,
      relays,
      discoveredGateways: this.discoveredGateways || [],
      authorizedGateways,
      gatewayAccessCatalog,
      discoveryUnavailableReason: this.discoveryDisabledReason,
      discoveryWarning: this.discoveryWarning,
      disabledReason: enabled ? null : (config.disabledReason || this.discoveryDisabledReason || null)
    };
  }

  getPublicGatewayReplicaInfo() {
    if (!PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED) {
      return null;
    }
    const snapshot = this.publicGatewayRelayClient?.getReplicaSnapshot?.() || null;
    const telemetry = this.publicGatewayReplicaMetrics ? { ...this.publicGatewayReplicaMetrics } : null;
    if (!snapshot) {
      return {
        hyperbeeKey: null,
        discoveryKey: null,
        length: 0,
        contiguousLength: 0,
        lag: 0,
        version: 0,
        updatedAt: 0,
        telemetry,
        delegateReqToPeers: !!this.publicGatewaySettings?.delegateReqToPeers
      };
    }

    return {
      hyperbeeKey: snapshot.hyperbeeKey || null,
      discoveryKey: snapshot.discoveryKey || null,
      length: Number.isFinite(snapshot.length) ? snapshot.length : 0,
      contiguousLength: Number.isFinite(snapshot.contiguousLength) ? snapshot.contiguousLength : 0,
      lag: Number.isFinite(snapshot.lag) ? snapshot.lag : 0,
      version: Number.isFinite(snapshot.version) ? snapshot.version : 0,
      updatedAt: Number.isFinite(snapshot.updatedAt) ? snapshot.updatedAt : 0,
      telemetry,
      delegateReqToPeers: !!this.publicGatewaySettings?.delegateReqToPeers
    };
  }

  async #syncOpenJoinPool(relayKey, metadata) {
    const previewValue = (value, limit = 16) => {
      if (value === null || value === undefined) return null;
      const text = typeof value === 'string' ? value : String(value);
      if (!text) return null;
      return text.length > limit ? text.slice(0, limit) : text;
    };
    const previewEntries = (entries = [], limit = 3) => {
      if (!Array.isArray(entries) || entries.length === 0) return [];
      return entries.slice(0, limit).map((entry) => ({
        writerCore: previewValue(entry?.writerCore, 16),
        writerCoreHex: previewValue(entry?.writerCoreHex || entry?.autobaseLocal, 16),
        writerLeaseId: previewValue(entry?.writerLeaseId, 24),
        writerCommitCheckpoint: entry?.writerCommitCheckpoint && typeof entry.writerCommitCheckpoint === 'object'
          ? {
              systemKey: previewValue(entry.writerCommitCheckpoint.systemKey, 16),
              systemSignedLength: Number.isFinite(entry.writerCommitCheckpoint.systemSignedLength)
                ? Number(entry.writerCommitCheckpoint.systemSignedLength)
                : null,
              viewVersion: Number.isFinite(entry.writerCommitCheckpoint.viewVersion)
                ? Number(entry.writerCommitCheckpoint.viewVersion)
                : null,
              activeWritersHash: previewValue(entry.writerCommitCheckpoint.activeWritersHash, 16)
            }
          : null,
        issuedAt: entry?.issuedAt ?? null,
        expiresAt: entry?.expiresAt ?? null
      }));
    };
    if (!relayKey) return;
    if (this.openJoinPoolSyncLocks.has(relayKey)) {
      this.log('debug', `[PublicGateway] Open join pool sync skipped: in-flight relay=${relayKey}`);
      return;
    }
    this.openJoinPoolSyncLocks.add(relayKey);

    try {
      if (!this.openJoinPoolProvider) {
        console.info('[PublicGateway] Open join pool sync skipped: missing provider', { relayKey });
        return;
      }
      const route = await this.#resolveGatewayRoute({ relayKey, metadata });
      const bridgeClient = await this.#getGatewayBridgeClient(route);
      if (!bridgeClient?.isEnabled?.()) {
        console.info('[PublicGateway] Open join pool sync skipped: gateway bridge unavailable', {
          relayKey,
          enabled: !!this.publicGatewaySettings?.enabled
        });
        return;
      }
      if (this.#isPublicGatewayRelayKey(relayKey)) {
        console.info('[PublicGateway] Open join pool sync skipped: public gateway relay', { relayKey });
        return;
      }

      this.log('info', `[PublicGateway] Open join pool sync start relay=${relayKey}`, {
        identifier: metadata?.identifier ?? null,
        isOpen: metadata?.isOpen ?? null,
        isHosted: metadata?.isHosted ?? null,
        isJoined: metadata?.isJoined ?? null,
        isPublic: metadata?.isPublic ?? null,
        metadataUpdatedAt: metadata?.metadataUpdatedAt ?? null
      });

      if (metadata?.isHosted === false || metadata?.isJoined === true) {
        console.info('[PublicGateway] Open join pool sync skipped: joined relay', {
          relayKey,
          isHosted: metadata?.isHosted ?? null,
          isJoined: metadata?.isJoined ?? null
        });
        return;
      }
      if (!metadata || metadata.isOpen !== true) {
        console.info('[PublicGateway] Open join pool sync skipped: relay not open', {
          relayKey,
          isOpen: metadata?.isOpen ?? null,
          identifier: metadata?.identifier ?? null,
          isHosted: metadata?.isHosted ?? null,
          isJoined: metadata?.isJoined ?? null,
          metadataUpdatedAt: metadata?.metadataUpdatedAt ?? null
        });
        return;
      }

      const metadataIdentifier = typeof metadata?.identifier === 'string' ? metadata.identifier : null;
      const relayUrl = typeof metadata?.connectionUrl === 'string'
        ? metadata.connectionUrl
        : (typeof metadata?.relayUrl === 'string' ? metadata.relayUrl : null);
      const gatewayPath = this._normalizeGatewayPath(metadataIdentifier || relayKey, metadata?.gatewayPath, relayUrl);
      const relayCores = await this.#collectRelayCoreMetadata(relayKey, metadataIdentifier || null) || [];
      const targetResult = await this.openJoinPoolProvider({
        relayKey,
        publicIdentifier: metadataIdentifier,
        metadata,
        mode: 'target-only'
      });
      const canonicalRelayKeyRaw = typeof targetResult?.relayKey === 'string'
        ? targetResult.relayKey.trim()
        : null;
      const canonicalRelayKey = canonicalRelayKeyRaw && /^[a-fA-F0-9]{64}$/.test(canonicalRelayKeyRaw)
        ? canonicalRelayKeyRaw.toLowerCase()
        : null;
      const poolRelayKey = canonicalRelayKey || relayKey;
      const poolPublicIdentifier = typeof targetResult?.publicIdentifier === 'string'
        ? targetResult.publicIdentifier
        : metadataIdentifier;
      const targetSize = Number.isFinite(targetResult?.targetSize)
        ? Math.trunc(targetResult.targetSize)
        : null;
      const poolMetadata = {
        identifier: poolPublicIdentifier || metadataIdentifier || null,
        isOpen: metadata?.isOpen ?? null,
        isPublic: metadata?.isPublic ?? null,
        isHosted: metadata?.isHosted ?? null,
        isJoined: metadata?.isJoined ?? null,
        metadataUpdatedAt: metadata?.metadataUpdatedAt ?? null,
        gatewayPath: gatewayPath || null,
        relayUrl: relayUrl || null
      };
      const fastForward = targetResult?.fastForward || metadata?.fastForward || null;
      if (fastForward) {
        poolMetadata.fastForward = fastForward;
      }
      const aliasSet = new Set();
      if (poolPublicIdentifier) aliasSet.add(poolPublicIdentifier);
      if (gatewayPath) aliasSet.add(gatewayPath);
      const aliases = Array.from(aliasSet);
      const poolRelayCores = relayCores.length ? relayCores : null;
      this.log('info', `[PublicGateway] Open join pool target resolved relay=${poolRelayKey}`, {
        requestRelay: relayKey,
        canonicalRelayKey: canonicalRelayKey ? previewValue(canonicalRelayKey, 16) : null,
        publicIdentifier: poolPublicIdentifier,
        targetSize,
        metadataIdentifier: metadata?.identifier ?? null
      });
      if (!targetSize || targetSize <= 0) {
        this.log('debug', `[PublicGateway] Open join pool target unavailable relay=${poolRelayKey}`);
        return;
      }

      if (canonicalRelayKey && canonicalRelayKey !== relayKey) {
        this.log('info', `[PublicGateway] Open join pool canonical relay ${relayKey} -> ${canonicalRelayKey}`);
      }
      if (canonicalRelayKey
        && canonicalRelayKey !== relayKey
        && this.activeRelays?.has?.(canonicalRelayKey)) {
        this.log('debug', `[PublicGateway] Open join pool sync skipped: alias relay=${relayKey}`, {
          canonicalRelayKey
        });
        return;
      }

      const logReport = (phase, report, extra = null) => {
        if (!report || typeof report !== 'object') return;
        this.log('info', `[PublicGateway] Open join pool report ${phase} relay=${poolRelayKey}`, {
          total: report?.total ?? null,
          targetSize,
          needed: report?.needed ?? null,
          stored: report?.stored ?? null,
          received: report?.received ?? null,
          entriesSent: extra?.entriesSent ?? null
        });
      };

      let report = await bridgeClient.updateOpenJoinPool(poolRelayKey, [], {
        updatedAt: Date.now(),
        targetSize,
        publicIdentifier: poolPublicIdentifier || null,
        relayUrl,
        relayCores: poolRelayCores,
        metadata: poolMetadata,
        aliases
      });
      logReport('preflight', report, { entriesSent: 0 });
      let needed = Number.isFinite(report?.needed) ? Math.trunc(report.needed) : 0;
      if (needed <= 0) {
        this.log('debug', `[PublicGateway] Open join pool already satisfied relay=${poolRelayKey}`, {
          total: report?.total ?? null,
          targetSize
        });
        return;
      }

      let attempts = 0;
      while (needed > 0 && attempts < 2) {
        const provision = await this.openJoinPoolProvider({
          relayKey: poolRelayKey,
          publicIdentifier: poolPublicIdentifier,
          metadata,
          needed,
          targetSize
        });
        const entries = Array.isArray(provision?.entries)
          ? provision.entries
          : (Array.isArray(provision) ? provision : []);
        this.log('info', `[PublicGateway] Open join pool provision batch relay=${poolRelayKey}`, {
          needed,
          provided: entries.length,
          entryPreview: previewEntries(entries),
          targetSize
        });
        if (!entries.length) {
          this.log('warn', `[PublicGateway] Open join pool provider returned empty entries relay=${poolRelayKey}`, {
            needed,
            targetSize
          });
          return;
        }
        const updatedAt = provision.updatedAt || Date.now();
        report = await bridgeClient.updateOpenJoinPool(poolRelayKey, entries, {
          updatedAt,
          targetSize,
          publicIdentifier: poolPublicIdentifier || null,
          relayUrl,
          relayCores: poolRelayCores,
          metadata: poolMetadata,
          aliases
        });
        logReport('provision', report, { entriesSent: entries.length });
        needed = Number.isFinite(report?.needed) ? Math.trunc(report.needed) : 0;
        attempts += 1;
      }

      if (needed > 0) {
        this.log('warn', `[PublicGateway] Open join pool still below target relay=${poolRelayKey}`, {
          needed,
          total: report?.total ?? null,
          targetSize
        });
        return;
      }

      this.log('info', `[PublicGateway] Open join pool updated relay=${poolRelayKey}`, {
        total: report?.total ?? null,
        targetSize
      });
    } catch (error) {
      this.log('warn', `[PublicGateway] Open join pool update failed relay=${relayKey}: ${error?.message || error}`);
    } finally {
      this.openJoinPoolSyncLocks.delete(relayKey);
    }
  }

  async #runOpenJoinPoolKeepWarm() {
    if (!this.isRunning) return;
    if (!(this.publicGatewaySettings?.enabled && this.publicGatewayRegistrar?.isEnabled?.())) return;
    const relayEntries = Array.from(this.activeRelays.entries());
    for (const [relayKey, relayData] of relayEntries) {
      if (this.#isPublicGatewayRelayKey(relayKey)) continue;
      // eslint-disable-next-line no-await-in-loop
      await this.#syncOpenJoinPool(relayKey, relayData?.metadata || {});
    }
  }

  #refreshOpenJoinPoolSyncInterval() {
    if (this.openJoinPoolSyncInterval) {
      clearInterval(this.openJoinPoolSyncInterval);
      this.openJoinPoolSyncInterval = null;
    }
    if (!this.isRunning) return;
    const enabled = this.publicGatewaySettings?.enabled && this.publicGatewayRegistrar?.isEnabled?.();
    const intervalMs = Number(this.publicGatewaySettings?.openJoinPoolSyncIntervalMs);
    if (!enabled || !Number.isFinite(intervalMs) || intervalMs <= 0) {
      this.log('debug', '[PublicGateway] Open join keep-warm disabled');
      return;
    }
    this.log('info', `[PublicGateway] Open join keep-warm enabled intervalMs=${intervalMs}`);
    this.openJoinPoolSyncInterval = setInterval(() => {
      this.#runOpenJoinPoolKeepWarm().catch((error) => {
        this.log('warn', `[PublicGateway] Open join keep-warm tick failed: ${error?.message || error}`);
      });
    }, intervalMs);
  }

  async syncPublicGatewayRelay(relayKey, { forceTokenRefresh = true } = {}) {
    await this.#syncPublicGatewayRelay(relayKey, { forceTokenRefresh });
  }

  async resyncPublicGateway() {
    try {
      await this.#ensureDiscoveryClient();
      await this.#refreshGatewayAccessCatalog({ force: true });
    } catch (error) {
      this.log('debug', `[PublicGateway] Gateway access refresh skipped during resync: ${error.message}`);
    }

    const enabled = this.publicGatewaySettings?.enabled && this.publicGatewayRegistrar?.isEnabled?.();
    if (!enabled) {
      this.publicGatewayRelayState.clear();
      this.#clearAllRelayTokens();
      this.#emitPublicGatewayStatus();
      return;
    }

    const gatewayRelayKey = this.#getPublicGatewayRelayKey();
    if (gatewayRelayKey && this.publicGatewaySettings?.resolvedGatewayRelay?.hyperbeeKey) {
      this.#ensurePublicGatewayRelayEntry();
      try {
        // eslint-disable-next-line no-await-in-loop
        await this.#syncPublicGatewayRelay(gatewayRelayKey, { forceTokenRefresh: true });
      } catch (error) {
        this.log('warn', `[PublicGateway] Failed to sync gateway relay replica: ${error.message}`);
      }
    }

    for (const key of this.activeRelays.keys()) {
      if (this.#isPublicGatewayRelayKey(key)) continue;
      // Sequential resync to avoid saturating registrar
      // eslint-disable-next-line no-await-in-loop
      await this.#syncPublicGatewayRelay(key, { forceTokenRefresh: true });
    }
  }

  async updatePublicGatewayConfig(rawConfig = {}) {
    const previousSettings = this.publicGatewaySettings;
    const mergedConfig = {
      ...(previousSettings || {}),
      ...(rawConfig || {})
    };
    this.publicGatewaySettings = await this.#resolvePublicGatewayConfig(mergedConfig);
    this.#configurePublicGateway();

    const isEnabled = this.publicGatewaySettings?.enabled && this.publicGatewayRegistrar?.isEnabled?.();

    if (isEnabled) {
      try {
        await this.resyncPublicGateway();
      } catch (error) {
        this.log('warn', `[PublicGateway] Resync failed: ${error.message}`);
      }
    } else {
      this.publicGatewayRelayState.clear();
      this.#clearAllRelayTokens();
    }
    this.#refreshOpenJoinPoolSyncInterval();

    const previousHash = previousSettings?.resolvedSharedSecretHash || null;
    const nextHash = this.publicGatewaySettings?.resolvedSharedSecretHash || null;
    const statusChanged = Boolean(previousSettings?.enabled) !== Boolean(this.publicGatewaySettings?.enabled);
    const secretChanged = previousHash !== nextHash && nextHash !== null;

    if (statusChanged || secretChanged) {
      try {
        await updatePublicGatewaySettings(this.publicGatewaySettings);
      } catch (error) {
        this.log('warn', `[PublicGateway] Failed to persist settings: ${error.message}`);
      }
    }

    this.#emitPublicGatewayStatus();
  }

  async issuePublicGatewayToken(relayKey, options = {}) {
    if (!relayKey) {
      throw new Error('relayKey is required');
    }

    const relayData = this.activeRelays.get(relayKey);
    if (!relayData) {
      throw new Error('Relay not registered with gateway');
    }
    const metadata = relayData.metadata || null;
    const route = await this.#resolveGatewayRoute({ relayKey, metadata });
    const bridgeClient = await this.#getGatewayBridgeClient(route);
    if (!bridgeClient?.isEnabled?.() || !this.publicGatewaySettings?.enabled) {
      throw new Error('Public gateway bridge is disabled');
    }

    const requestingPubkey = this.getCurrentPubkey?.() || null;
    if (!requestingPubkey) {
      throw new Error('Unable to determine requesting pubkey for token issuance');
    }

    const authRecord = this.#resolveRelayAuth(relayKey, requestingPubkey);
    if (!authRecord) {
      throw new Error('No relay authentication token found for requesting user');
    }

    const relayAuthToken = authRecord.token;

    const ttl = Number(options?.ttlSeconds);
    const ttlSeconds = Number.isFinite(ttl) && ttl > 0
      ? Math.round(ttl)
      : this.publicGatewaySettings?.defaultTokenTtl || 3600;

    const issuedAt = Date.now();

    const tokenResponse = await bridgeClient.issueGatewayToken(relayKey, {
      ttlSeconds,
      relayAuthToken,
      pubkey: requestingPubkey,
      scope: options.scope || 'relay-access'
    });

    const token = tokenResponse?.token;
    if (!token) {
      throw new Error('Gateway did not return token');
    }

    const expiresAt = Number(tokenResponse.expiresAt) || (issuedAt + ttlSeconds * 1000);
    const refreshAfter = Number(tokenResponse.refreshAfter) || null;
    const sequence = tokenResponse.sequence || null;
    let gatewayPath = metadata.gatewayPath || null;
    if (!gatewayPath) {
      gatewayPath = this._normalizeGatewayPath(relayKey, metadata.gatewayPath, metadata.connectionUrl);
    }
    if (!gatewayPath) {
      gatewayPath = relayKey.includes(':') ? relayKey.replace(':', '/') : relayKey;
    }

    const wsBase = route?.wsUrl || this.#computePublicGatewayWsBase(route?.gatewayOrigin || this.publicGatewaySettings?.baseUrl);
    if (!wsBase) {
      throw new Error('Invalid public gateway base URL');
    }

    const connectionUrl = `${wsBase}/${gatewayPath}?token=${encodeURIComponent(token)}`;

    const logDetails = {
      relayKey,
      expiresAt,
      ttlSeconds,
      gatewayPath,
      pubkey: `${requestingPubkey.slice(0, 16)}...`
    };
    this.log('info', `[PublicGateway] Issued public token ${JSON.stringify(logDetails)}`);

    this.#recordRelayToken(relayKey, {
      token,
      expiresAt,
      ttlSeconds,
      connectionUrl,
      baseUrl: route?.gatewayOrigin || this.publicGatewaySettings.baseUrl,
      issuedForPubkey: requestingPubkey,
      issuedAt,
      relayAuthToken,
      refreshAfter,
      sequence
    }, { schedule: true });

    return {
      relayKey,
      token,
      connectionUrl,
      expiresAt,
      ttlSeconds,
      gatewayPath,
      baseUrl: route?.gatewayOrigin || this.publicGatewaySettings.baseUrl,
      issuedForPubkey: requestingPubkey,
      refreshAfter,
      sequence
    };
  }

  async authorizeRelayMemberAccess(relayKey, payload = {}, options = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : '';
    if (!relayIdentifier) {
      throw new Error('relayKey is required');
    }

    const relayData = this.activeRelays.get(relayIdentifier);
    const metadata = options?.metadata || relayData?.metadata || null;
    const route = await this.#resolveGatewayRoute({
      relayKey: relayIdentifier,
      metadata,
      gatewayOrigin: options?.gatewayOrigin || null,
      gatewayId: options?.gatewayId || null,
      allowSettingsFallback: false
    });
    const bridgeClient = await this.#getGatewayBridgeClient(route);
    if (!bridgeClient?.isEnabled?.() || !this.publicGatewaySettings?.enabled) {
      throw new Error('Public gateway bridge is disabled');
    }
    if (route?.authMethod !== 'relay-scoped-bearer-v1' || !bridgeClient.controlClient?.authorizeRelayMember) {
      throw new Error('relay-member-authorize-unsupported');
    }

    const result = await bridgeClient.controlClient.authorizeRelayMember(relayIdentifier, payload);
    if (!result?.success) {
      const message = typeof result?.error === 'string'
        ? result.error
        : (typeof result?.reason === 'string' ? result.reason : `gateway-member-authorize status ${result?.statusCode || 'unknown'}`);
      throw new Error(message);
    }

    return {
      ...result,
      gatewayOrigin: route?.gatewayOrigin || null,
      gatewayId: route?.gatewayId || null
    };
  }

  #startGatewayTelemetry(publicKey, protocol) {
    if (!protocol || this.gatewayTelemetryTimers.has(publicKey)) return;

    const sendTelemetry = async () => {
      try {
        const payload = await this.#collectTelemetrySnapshot();
        payload.peerId = payload.peerId || publicKey;
        protocol.sendTelemetry(payload);
      } catch (error) {
        this.log('debug', `[PublicGateway] Failed to send telemetry for ${publicKey}: ${error.message}`);
      }
    };

    sendTelemetry();
    const interval = setInterval(sendTelemetry, 15000);
    interval.unref?.();

    const cleanup = () => {
      clearInterval(interval);
      this.gatewayTelemetryTimers.delete(publicKey);
    };

    this.gatewayTelemetryTimers.set(publicKey, cleanup);
    protocol.once('close', cleanup);
    protocol.once('destroy', cleanup);
    protocol.mux?.stream?.once('close', cleanup);
  }

  async #collectTelemetrySnapshot() {
    const queueDepth = Array.from(this.messageQueues.values()).reduce((total, queue) => {
      if (!queue || !Array.isArray(queue.queue)) return total;
      return total + queue.queue.length;
    }, 0);

    const metrics = this.peerHealthManager?.metrics || {};
    const failureRate = metrics.totalChecks
      ? Math.min(1, metrics.failedChecks / metrics.totalChecks)
      : 0;

    let hyperbeeVersion = 0;
    let hyperbeeLag = 0;
    let hyperbeeContiguousLength = 0;
    let hyperbeeLength = 0;
    let hyperbeeLastUpdatedAt = 0;
    let hyperbeeKey = null;
    let hyperbeeDiscoveryKey = null;
    if (this.publicGatewayRelayClient) {
      try {
        const telemetry = await this.publicGatewayRelayClient.getTelemetry();
        hyperbeeVersion = telemetry?.hyperbeeVersion || 0;
        hyperbeeLag = telemetry?.hyperbeeLag || 0;
        hyperbeeContiguousLength = telemetry?.hyperbeeContiguousLength || 0;
        hyperbeeLength = telemetry?.hyperbeeLength || 0;
        hyperbeeLastUpdatedAt = telemetry?.hyperbeeLastUpdatedAt || 0;
        hyperbeeKey = telemetry?.hyperbeeKey || null;
        hyperbeeDiscoveryKey = telemetry?.hyperbeeDiscoveryKey || null;
        this.publicGatewayReplicaMetrics = {
          hyperbeeVersion,
          hyperbeeLag,
          hyperbeeContiguousLength,
          hyperbeeLength,
          hyperbeeLastUpdatedAt,
          hyperbeeKey,
          hyperbeeDiscoveryKey,
          recordedAt: Date.now()
        };
      } catch (error) {
        this.log('debug', `[PublicGateway] Hyperbee telemetry error: ${error.message}`);
      }
    }

    const peerId = this.ownPeerPublicKey || this.getCurrentPubkey?.() || null;

    return {
      peerId,
      latencyMs: 0,
      inFlightJobs: queueDepth,
      failureRate,
      hyperbeeVersion,
      hyperbeeLag,
      hyperbeeContiguousLength,
      hyperbeeLength,
      hyperbeeLastUpdatedAt,
      hyperbeeKey,
      hyperbeeDiscoveryKey,
      queueDepth,
      reportedAt: Date.now(),
      hyperbeeServed: this.hyperbeeQueryStats?.totalServed || 0,
      hyperbeeServedEvents: this.hyperbeeQueryStats?.totalEvents || 0,
      hyperbeeFallbacks: this.hyperbeeQueryStats?.totalFallbacks || 0,
      hyperbeeErrors: this.hyperbeeQueryStats?.totalErrors || 0,
      hyperbeeLastServedAt: this.hyperbeeQueryStats?.lastServedAt || null,
      hyperbeeLastFallbackAt: this.hyperbeeQueryStats?.lastFallbackAt || null,
      hyperbeeLastFallbackReason: this.hyperbeeQueryStats?.lastFallbackReason || null
    };
  }

  async #collectRelayCoreMetadata(relayKey, publicIdentifier = null) {
    if (!relayKey) return [];
    const relayManager = relayManagerMap?.get ? relayManagerMap.get(relayKey) : null;
    const autobase = relayManager?.relay || null;
    const cached = this.relayCoreCache.get(relayKey) || [];
    const seen = new Set();
    const cores = [];

    const normalizeKey = (candidate) => {
      if (!candidate) return null;
      const coreLike = candidate.core || candidate;
      const key = coreLike?.key || coreLike?.discoveryKey || null;
      if (!key) return null;
      if (typeof key === 'string') {
        try {
          return HypercoreId.decode(key);
        } catch (_) {
          if (/^[0-9a-fA-F]{64}$/.test(key)) {
            return Buffer.from(key, 'hex');
          }
          return null;
        }
      }
      if (Buffer.isBuffer(key)) return key;
      if (key instanceof Uint8Array) return Buffer.from(key);
      return null;
    };

    const addCore = (candidate, role = null) => {
      const keyBuf = normalizeKey(candidate);
      if (!keyBuf || keyBuf.length !== 32) return;
      let encoded = null;
      try {
        encoded = HypercoreId.encode(keyBuf);
      } catch (_) {
        encoded = Buffer.from(keyBuf).toString('hex');
      }
      if (!encoded || seen.has(encoded)) return;
      seen.add(encoded);
      cores.push(role ? { key: encoded, role } : { key: encoded });
    };

    const addArray = (arr, prefix) => {
      if (!Array.isArray(arr)) return;
      arr.forEach((entry, index) => addCore(entry?.core || entry, prefix ? `${prefix}-${index}` : null));
    };

    if (autobase) {
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
      addArray(Array.isArray(autobase?.inputs) ? autobase.inputs : (autobase?.inputs ? Array.from(autobase.inputs) : []), 'autobase-writer');
      if (autobase?.writer && typeof autobase.writer === 'object') {
        addCore(autobase.writer.core || autobase.writer, 'autobase-writer');
      }
    }

    const mergedEntries = [];
    const indexByKey = new Map();
    const addEntry = (entry) => {
      if (!entry || !entry.key) return;
      const existingIndex = indexByKey.get(entry.key);
      if (existingIndex === undefined) {
        indexByKey.set(entry.key, mergedEntries.length);
        mergedEntries.push({ key: entry.key, role: entry.role ?? null });
        return;
      }
      if (!mergedEntries[existingIndex].role && entry.role) {
        mergedEntries[existingIndex] = { ...mergedEntries[existingIndex], role: entry.role };
      }
    };

    if (cached.length) cached.forEach(addEntry);
    if (cores.length) cores.forEach(addEntry);

    const persistedRefs = await resolveRelayMirrorCoreRefs(relayKey, publicIdentifier, mergedEntries);
    if (Array.isArray(persistedRefs) && persistedRefs.length) {
      for (const ref of persistedRefs) {
        addEntry({ key: ref });
      }
    }

    if (mergedEntries.length) {
      this.relayCoreCache.set(relayKey, mergedEntries);
      return mergedEntries;
    }

    return cached;
  }

  getStatus() {
    const ownPeerPublicKey = this.ownPeerPublicKey || this.connectionPool?.getPublicKey?.() || null;
    const peerRelayMap = {};
    for (const [identifier, relay] of this.activeRelays.entries()) {
      peerRelayMap[identifier] = {
        peers: Array.from(relay.peers || []),
        peerCount: relay.peers ? relay.peers.size : 0,
        status: relay.status || 'unknown',
        lastActive: relay.lastActive || null,
        createdAt: relay.createdAt || null,
        metadata: relay.metadata || null
      };
    }

    const peerDetails = {};
    for (const peer of this.activePeers) {
      const relays = peer.relays ? Array.from(peer.relays) : [];
      peerDetails[peer.publicKey] = {
        nostrPubkeyHex: peer.nostrPubkeyHex || null,
        relays,
        relayCount: relays.length,
        lastSeen: peer.lastSeen || null,
        status: peer.status || 'unknown',
        mode: peer.mode || null,
        address: peer.address || null
      };
    }

    return {
      running: this.isRunning,
      port: this.config?.port || DEFAULT_PORT,
      hostname: this.config?.hostname || 'localhost',
      startedAt: this.startedAt,
      urls: this.config?.urls || this.gatewayServer?.getServerUrls() || null,
      ownPeerPublicKey,
      health: this.healthState,
      peers: this.activePeers.length,
      relays: this.activeRelays.size,
      peerRelayMap,
      peerDetails,
      publicGateway: this.getPublicGatewayState()
    };
  }

  getOwnPeerPublicKey() {
    return this.ownPeerPublicKey || null;
  }

  setOwnPeerPublicKey(peerKey) {
    if (typeof peerKey === 'string' && peerKey.trim()) {
      this.ownPeerPublicKey = peerKey.trim();
    }
  }

  getDiagnostics() {
    const peerList = this.activePeers.map(peer => ({
      publicKey: peer.publicKey,
      status: this.peerHealthManager.isPeerHealthy(peer.publicKey) ? 'healthy' : 'unknown',
      relayCount: peer.relays?.size || 0,
      lastSeen: peer.lastSeen,
      mode: peer.mode
    }));

    const relays = Array.from(this.activeRelays.entries()).map(([identifier, relay]) => ({
      identifier,
      peers: Array.from(relay.peers)
    }));

    return {
      peers: {
        totalActive: peerList.length,
        list: peerList
      },
      relays: {
        totalActive: relays.length,
        list: relays
      }
    };
  }

  getLogs() {
    return [...this.logs];
  }

  setupRoutes() {
    if (!this.app) return;

    this.app.get('/', (_req, res) => {
      res.json({
        status: this.isRunning ? 'ok' : 'offline',
        peers: this.activePeers.length,
        relays: this.activeRelays.size,
        timestamp: new Date().toISOString()
      });
    });

    this.app.get('/health', (_req, res) => {
      res.json({
        status: this.isRunning ? 'healthy' : 'offline',
        mode: 'hyperswarm',
        timestamp: new Date().toISOString()
      });
    });

    this.app.get('/debug/connections', (_req, res) => {
      res.json(this.getDiagnostics());
    });

    this.app.post('/register', async (req, res) => {
      try {
        const result = await this.registerPeerMetadata(req.body || {}, { source: 'http' });
        res.json(result);
      } catch (error) {
        const statusCode = error.message === 'Public key is required' ? 400 : 500;
        this.log('error', `Registration failed: ${error.message}`);
        res.status(statusCode).json({ error: error.message });
      }
    });

    this.app.post('/callback/finalize-auth/:identifier', async (req, res) => {
      const identifier = req.params.identifier;
      try {
        const { pubkey } = req.body || {};
        if (!pubkey) {
          return res.status(400).json({ error: 'Missing pubkey' });
        }

        const sessionKey = `${pubkey}-${identifier}`;
        const session = global.joinSessions?.get(sessionKey);
        if (!session || !session.token) {
          return res.status(400).json({ error: 'Session not found or verification not completed' });
        }

        const peer = this.activePeers.find(p => p.publicKey === session.peerPublicKey);
        if (!peer) {
          return res.status(503).json({ error: 'Peer no longer available' });
        }

        const result = await forwardCallbackToPeer(
          peer,
          '/finalize-auth',
          {
            pubkey,
            token: session.token,
            identifier
          },
          this.connectionPool
        );

        global.joinSessions.delete(sessionKey);
        res.json(result);
      } catch (error) {
        this.log('error', `Finalize auth error: ${error.message}`);
        res.status(500).json({ error: 'Finalization failed', message: error.message });
      }
    });

    this.app.get('/drive/:identifier/:file', async (req, res) => {
      const { identifier, file } = req.params;
      const shouldLogHtml = isHtmlDriveRequest(file);
      try {
        if (shouldLogHtml) {
          this.log('info', `[DriveHTML][Gateway] request ${JSON.stringify({
            identifier,
            file,
            host: req.get('host') || null,
            origin: req.get('origin') || null,
            referer: req.get('referer') || null,
            userAgent: req.get('user-agent') || null
          })}`);
        }

        const fileHash = typeof file === 'string' ? file.split('.')[0] : null;
        const validHash = typeof fileHash === 'string' && /^[a-f0-9]{64}$/i.test(fileHash);
        if (validHash) {
          let localBuffer = null;
          try {
            localBuffer = await getFile(identifier, fileHash.toLowerCase());
          } catch (_) {}

          if (!localBuffer && typeof global.recoverRelayDriveFile === 'function') {
            try {
              const recovery = await global.recoverRelayDriveFile({
                relayKey: null,
                identifier,
                fileHash: fileHash.toLowerCase(),
                reason: 'gateway-http-request'
              });
              if (recovery?.status === 'ok') {
                localBuffer = await getFile(identifier, fileHash.toLowerCase());
              }
            } catch (_) {}
          }

          if (localBuffer) {
            applyDriveCorsHeaders(res, {
              'content-type': guessContentType(file),
              'cache-control': 'public, max-age=31536000, immutable'
            });
            if (shouldLogHtml) {
              this.log('info', `[DriveHTML][Gateway] local-response ${JSON.stringify({
                identifier,
                file,
                statusCode: 200,
                ...summarizeDriveHeaders(res.getHeaders())
              })}`);
            }
            res.status(200).send(Buffer.isBuffer(localBuffer) ? localBuffer : Buffer.from(localBuffer));
            return;
          }
        }

        const peer = await this.findHealthyPeerForRelay(identifier);
        if (!peer) {
          return res.status(503).json({ error: 'No healthy peers available for this relay' });
        }

        const stream = await requestFileFromPeer(peer, identifier, file, this.connectionPool);
        applyDriveCorsHeaders(res);
        Object.entries(stream.headers).forEach(([key, value]) => res.setHeader(key, value));
        if (shouldLogHtml) {
          this.log('info', `[DriveHTML][Gateway] peer-response ${JSON.stringify({
            identifier,
            file,
            statusCode: stream.statusCode,
            upstream: summarizeDriveHeaders(stream.headers || {}),
            response: summarizeDriveHeaders(res.getHeaders())
          })}`);
        }
        res.status(stream.statusCode);
        stream.pipe(res);
        peer.lastSeen = Date.now();
      } catch (error) {
        if (shouldLogHtml) {
          this.log('error', `[DriveHTML][Gateway] error ${JSON.stringify({
            identifier,
            file,
            message: error?.message || String(error)
          })}`);
        }
        this.log('error', `Drive file error: ${error.message}`);
        res.status(500).json({ error: 'Internal Server Error', message: error.message });
      }
    });

    this.app.post('/post/join/:identifier', async (req, res) => {
      const identifier = req.params.identifier;

      try {
        const relayEntry = this.activeRelays.get(identifier);
        if (!relayEntry || !relayEntry.peers?.size) {
          return res.status(404).json({ error: 'Relay not registered with gateway' });
        }

        const peer = await this.findHealthyPeerForRelay(identifier, true);
        if (!peer) {
          return res.status(503).json({ error: 'No healthy peers available for this relay' });
        }

        const payloadBody = req.body ? Buffer.from(JSON.stringify(req.body)) : undefined;
        const headers = { ...req.headers };
        delete headers['content-length'];
        delete headers['transfer-encoding'];
        delete headers['content-encoding'];
        headers['content-type'] = 'application/json';

        const forwardResponse = await forwardRequestToPeer(peer, {
          method: req.method,
          path: req.originalUrl || req.url,
          headers,
          body: payloadBody
        }, this.connectionPool);

        Object.entries(forwardResponse.headers || {}).forEach(([key, value]) => {
          if (value !== undefined) {
            res.setHeader(key, value);
          }
        });

        const statusCode = forwardResponse.statusCode || 200;
        const responseBody = forwardResponse.body || Buffer.alloc(0);
        res.status(statusCode);
        res.send(responseBody);
      } catch (error) {
        this.log('error', `Join request forwarding failed for ${identifier}: ${error.message}`);

        const match = /status\s(\d{3})/i.exec(error.message || '');
        const status = match ? Number(match[1]) : 502;
        res.status(status).json({ error: error.message });
      }
    });

    const servePfp = async (req, res) => {
      const owner = req.params.owner;
      const file = req.params.file;
      if (!file) {
        res.status(400).json({ error: 'Missing file parameter' });
        return;
      }

      const relayHintRaw = req.query?.relay || req.query?.identifier || req.query?.relayId;
      const relayIdentifier = this._normalizeRelayIdentifier(relayHintRaw);

      if (relayIdentifier) {
        try {
          const targetedStream = await this._fetchPfpFromRelay(relayIdentifier, owner || null, file);
          if (targetedStream === false) {
            res.status(404).json({ error: 'Avatar not found' });
            return;
          }

          if (!targetedStream) {
            const relayEntry = this.activeRelays.get(relayIdentifier);
            if (!relayEntry || !relayEntry.peers?.size) {
              res.status(404).json({ error: 'Relay not registered with gateway' });
            } else {
              res.status(503).json({ error: 'No healthy peers available for this relay' });
            }
            return;
          }

          Object.entries(targetedStream.headers || {}).forEach(([key, value]) => {
            if (value !== undefined) {
              res.setHeader(key, value);
            }
          });
          res.status(targetedStream.statusCode || 200);
          targetedStream.pipe(res);
          return;
        } catch (error) {
          this.log('warn', `Relay-specific PFP fetch failed for ${relayIdentifier}: ${error.message}`);
          res.status(502).json({ error: 'Failed to proxy avatar from relay host', message: error.message });
          return;
        }
      }

      try {
        const stream = await this._fetchPfpFromPeers(owner || null, file);
        if (!stream) {
          res.status(404).json({ error: 'Avatar not found' });
          return;
        }

        Object.entries(stream.headers || {}).forEach(([key, value]) => {
          if (value !== undefined) {
            res.setHeader(key, value);
          }
        });
        res.status(stream.statusCode || 200);
        stream.pipe(res);
      } catch (error) {
        this.log('error', `PFP proxy error: ${error.message}`);
        res.status(500).json({ error: 'Internal Server Error', message: error.message });
      }
    };

    this.app.get('/pfp/:file', servePfp);
    this.app.get('/pfp/:owner/:file', servePfp);

    this.app.use(async (req, res, next) => {
      if (req.path === '/health' || req.path === '/register' || req.path.startsWith('/callback')) {
        return next();
      }

      if (this.activePeers.length === 0) {
        return res.status(503).json({
          status: 'error',
          message: 'No peers available',
          timestamp: new Date().toISOString()
        });
      }

      const hyperswarmPeers = this.activePeers.filter(p => p.mode === 'hyperswarm');
      if (!hyperswarmPeers.length) {
        return res.status(503).json({ error: 'No Hyperswarm peers available' });
      }

      const targetPeer = hyperswarmPeers[Math.floor(Math.random() * hyperswarmPeers.length)];
      try {
        const response = await forwardRequestToPeer(targetPeer, {
          method: req.method,
          path: req.url,
          headers: req.headers,
          body: req.body ? Buffer.from(JSON.stringify(req.body)) : undefined
        }, this.connectionPool);

        Object.entries(response.headers || {}).forEach(([key, value]) => {
          if (value !== undefined) {
            res.setHeader(key, value);
          }
        });
        res.status(response.statusCode || 200);
        res.send(response.body || Buffer.alloc(0));
      } catch (error) {
        this.log('error', `Forward request error: ${error.message}`);
        res.status(502).json({ error: error.message });
      }
    });
  }

  async registerPeerMetadata(data = {}, options = {}) {
    const { skipConnect = false, source = 'unknown' } = options;
    const { publicKey, relays, mode = 'hyperswarm', address } = data;
    const topLevelBlindPeeringKey = typeof data.blindPeeringPublicKey === 'string'
      ? data.blindPeeringPublicKey.trim()
      : (typeof data.blind_peering_public_key === 'string' ? data.blind_peering_public_key.trim() : null);

    if (!publicKey) {
      throw new Error('Public key is required');
    }

    let peer = this.activePeers.find(p => p.publicKey === publicKey);
    if (!peer) {
      peer = {
        publicKey,
        lastSeen: Date.now(),
        relays: new Set(),
        status: 'registered',
        registeredAt: Date.now(),
        mode
      };
      this.activePeers.push(peer);
    } else {
      peer.lastSeen = Date.now();
      peer.status = 'registered';
      peer.mode = mode;
    }

    const previousOwner = peer.nostrPubkeyHex || null;
    const previousDriveKey = peer.pfpDriveKey || null;

    const nostrPubkeyHex = data.nostrPubkeyHex || data.nostr_pubkey_hex || null;
    const pfpDriveKey = data.pfpDriveKey || data.pfp_drive_key || null;

    if (previousOwner && previousOwner !== nostrPubkeyHex) {
      this._removeOwnerMapping(previousOwner, publicKey);
    }

    peer.nostrPubkeyHex = nostrPubkeyHex || previousOwner || null;
    peer.pfpDriveKey = pfpDriveKey || previousDriveKey || null;
    if (topLevelBlindPeeringKey) {
      peer.blindPeeringPublicKey = topLevelBlindPeeringKey;
    }

    this.log('debug', `[PublicGateway] registerPeerMetadata update ${publicKey.slice(0, 8)} owner=${peer.nostrPubkeyHex ? peer.nostrPubkeyHex.slice(0, 8) : 'none'} pfpDrive=${peer.pfpDriveKey ? peer.pfpDriveKey.slice(0, 8) : 'none'}`);

    if (peer.nostrPubkeyHex) {
      this._addOwnerMapping(peer.nostrPubkeyHex, publicKey);
    }

    if (peer.pfpDriveKey) {
      this.pfpDriveKeys.set(publicKey, peer.pfpDriveKey);
    } else {
      this.pfpDriveKeys.delete(publicKey);
    }

    const updatedRelays = [];

    if (Array.isArray(relays)) {
      relays.forEach(entry => {
        const identifier = typeof entry === 'string' ? entry : entry?.identifier;
        if (!identifier) return;

        const normalizedIdentifier = this._normalizeRelayIdentifier(identifier) || identifier;
        const relayObj = (entry && typeof entry === 'object') ? { ...entry } : { identifier };
        relayObj.identifier = normalizedIdentifier;

        peer.relays.add(normalizedIdentifier);
        if (!this.activeRelays.has(normalizedIdentifier)) {
          this.activeRelays.set(normalizedIdentifier, {
            peers: new Set(),
            status: 'active',
            createdAt: Date.now(),
            lastActive: Date.now(),
            metadata: null
          });
        }

        const relayData = this.activeRelays.get(normalizedIdentifier);
        relayData.peers.add(publicKey);
        relayData.lastActive = Date.now();

        const prevMetadata = relayData.metadata || {};
        const nextMetadata = { ...prevMetadata };

        if (relayObj.name && relayObj.name !== prevMetadata.name) {
          nextMetadata.name = relayObj.name;
        }
        if (relayObj.description !== undefined && relayObj.description !== prevMetadata.description) {
          nextMetadata.description = relayObj.description;
        }
        const relayBlindPeeringKey = typeof relayObj.blindPeeringPublicKey === 'string'
          ? relayObj.blindPeeringPublicKey.trim()
          : (typeof relayObj.blind_peering_public_key === 'string' ? relayObj.blind_peering_public_key.trim() : null);
        if (relayBlindPeeringKey) {
          nextMetadata.blindPeeringPublicKey = relayBlindPeeringKey;
        } else if (topLevelBlindPeeringKey) {
          nextMetadata.blindPeeringPublicKey = topLevelBlindPeeringKey;
        }
        if (relayObj.avatarUrl !== undefined) {
          if (relayObj.avatarUrl) {
            nextMetadata.avatarUrl = this._ensureRelayAvatarUrl(relayObj.avatarUrl, identifier);
          } else {
            nextMetadata.avatarUrl = null;
          }
        }
        if (relayObj.metadataEventId) {
          nextMetadata.metadataEventId = relayObj.metadataEventId;
        }
        if (!nextMetadata.identifier) {
          nextMetadata.identifier = normalizedIdentifier;
        }
        if (typeof relayObj.publicIdentifier === 'string' && relayObj.publicIdentifier.trim()) {
          nextMetadata.publicIdentifier = relayObj.publicIdentifier.trim();
        }
        const relayGatewayId = this.#normalizeGatewayId(relayObj.gatewayId || null);
        if (relayGatewayId) {
          nextMetadata.gatewayId = relayGatewayId;
        }
        const relayGatewayOrigin = this.#normalizeGatewayOrigin(relayObj.gatewayOrigin || null);
        if (relayGatewayOrigin) {
          nextMetadata.gatewayOrigin = relayGatewayOrigin;
        }

        const gatewayPath = this._normalizeGatewayPath(normalizedIdentifier, relayObj.gatewayPath, relayObj.connectionUrl);
        if (gatewayPath) {
          nextMetadata.gatewayPath = gatewayPath;
        }

        if (Array.isArray(relayObj.pathAliases)) {
          const aliasSet = new Set(Array.isArray(nextMetadata.pathAliases) ? nextMetadata.pathAliases : []);
          for (const rawAlias of relayObj.pathAliases) {
            if (typeof rawAlias !== 'string') continue;
            const normalizedAlias = rawAlias.trim().replace(/^\//, '').replace(/\/+$/, '');
            if (!normalizedAlias) continue;
            if (gatewayPath && normalizedAlias === gatewayPath) continue;
            aliasSet.add(normalizedAlias);
          }
          if (aliasSet.size > 0) {
            nextMetadata.pathAliases = Array.from(aliasSet);
          }
        }

        if (typeof relayObj.isPublic === 'boolean') {
          nextMetadata.isPublic = relayObj.isPublic;
        } else if (nextMetadata.isPublic === undefined) {
          nextMetadata.isPublic = true;
        }

        if (typeof relayObj.isOpen === 'boolean') {
          nextMetadata.isOpen = relayObj.isOpen;
        }

        if (typeof relayObj.isHosted === 'boolean') {
          nextMetadata.isHosted = relayObj.isHosted;
        }

        if (typeof relayObj.isJoined === 'boolean') {
          nextMetadata.isJoined = relayObj.isJoined;
        }

        if (typeof relayObj.directJoinOnly === 'boolean') {
          nextMetadata.directJoinOnly = relayObj.directJoinOnly;
        } else if (typeof relayObj.gatewayDirectJoinOnly === 'boolean') {
          nextMetadata.directJoinOnly = relayObj.gatewayDirectJoinOnly;
        }

        if (typeof relayObj.isGatewayReplica === 'boolean') {
          nextMetadata.isGatewayReplica = relayObj.isGatewayReplica;
        }

        if (relayObj.gatewayRelay && typeof relayObj.gatewayRelay === 'object') {
          nextMetadata.gatewayRelay = {
            ...(nextMetadata.gatewayRelay || {}),
            ...relayObj.gatewayRelay
          };
        }

        if (relayObj.replicaMetrics && typeof relayObj.replicaMetrics === 'object') {
          nextMetadata.replicaMetrics = {
            ...(nextMetadata.replicaMetrics || {}),
            ...relayObj.replicaMetrics
          };
        }

        if (relayObj.replicaTelemetry && typeof relayObj.replicaTelemetry === 'object') {
          nextMetadata.replicaTelemetry = relayObj.replicaTelemetry;
        }

        if (typeof relayObj.delegateReqToPeers === 'boolean') {
          nextMetadata.delegateReqToPeers = relayObj.delegateReqToPeers;
        }

        const incomingTimestamp = this._coerceTimestamp(relayObj.metadataUpdatedAt);
        const existingTimestamp = this._coerceTimestamp(prevMetadata.metadataUpdatedAt);
        if (incomingTimestamp !== null) {
          if (existingTimestamp === null || incomingTimestamp >= existingTimestamp) {
            nextMetadata.metadataUpdatedAt = incomingTimestamp;
          }
        }

        relayData.metadata = nextMetadata;
        if (nextMetadata.replicaMetrics) {
          relayData.replicaMetrics = { ...nextMetadata.replicaMetrics };
        }
        if (nextMetadata.replicaTelemetry) {
          relayData.replicaTelemetry = { ...nextMetadata.replicaTelemetry };
        }
        if (typeof nextMetadata.isGatewayReplica === 'boolean') {
          relayData.isGatewayReplica = nextMetadata.isGatewayReplica;
        }
        updatedRelays.push(normalizedIdentifier);
      });
    }

    if (data.gatewayReplica && typeof data.gatewayReplica === 'object') {
      peer.gatewayReplica = {
        ...(peer.gatewayReplica || {}),
        ...data.gatewayReplica
      };
    }

    peer.address = address || null;
    peer.lastSeen = Date.now();

    updatedRelays.forEach(identifier => {
      const syncTraceId = `relay-sync-${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 8)}`
      const relayMetadata = this.activeRelays.get(identifier)?.metadata || null
      this.#resolveGatewayRoute({ relayKey: identifier, metadata: relayMetadata }).then((route) => {
        this.log('info', `[PublicGateway] Relay sync scheduled ${syncTraceId} relay=${identifier}`, {
          source,
          skipConnect,
          gatewayOrigin: route?.gatewayOrigin || relayMetadata?.gatewayOrigin || null,
          gatewayId: route?.gatewayId || relayMetadata?.gatewayId || null,
          isHosted: relayMetadata?.isHosted ?? null,
          isJoined: relayMetadata?.isJoined ?? null,
          isOpen: relayMetadata?.isOpen ?? null,
          isPublic: relayMetadata?.isPublic ?? null,
          peerCount: this.activeRelays.get(identifier)?.peers?.size || 0
        });
      }).catch((error) => {
        this.log('warn', `[PublicGateway] Relay route trace failed ${syncTraceId} relay=${identifier}: ${error.message}`);
      });
      this.#syncPublicGatewayRelay(identifier, { forceTokenRefresh: true }).catch(error => {
        this.log('warn', `[PublicGateway] Sync error for ${identifier}: ${error.message}`);
      });
    });

    this.healthState.activeRelaysCount = this.activeRelays.size;
    this.healthState.services.hyperswarmStatus = 'connected';

    this.emit('status', this.getStatus());

    const connectAndCheck = async () => {
      try {
        await this.connectionPool.getConnection(publicKey, {
          reason: 'peer-register-connect',
          peerKey: publicKey,
          source
        });
        peer.status = 'connected';
        await this.peerHealthManager.checkPeerHealth(peer, this.connectionPool);
        this.emit('status', this.getStatus());
      } catch (error) {
        this.log('warn', `Failed to connect to peer ${publicKey.slice(0, 8)} (${source}): ${error.message}`);
      }
    };

    setTimeout(connectAndCheck, skipConnect ? 0 : 1000);

    return {
      message: 'Registered successfully (Hyperswarm mode)',
      status: 'active',
      mode,
      timestamp: new Date().toISOString(),
      relayCount: peer.relays.size,
      relays: Array.from(peer.relays)
    };
  }

  async _handleGatewayRegisterRequest(publicKey, request) {
    try {
      let payload = {};
      if (request.body && request.body.length) {
        payload = JSON.parse(request.body.toString());
      }

      if (!payload.publicKey) {
        payload.publicKey = publicKey;
      }

      this.log('debug', '[PublicGateway] register request payload', {
        peer: publicKey.slice(0, 8),
        owner: (payload.nostrPubkeyHex || payload.nostr_pubkey_hex || '').slice(0, 8) || null,
        hasPfpDrive: !!(payload.pfpDriveKey || payload.pfp_drive_key)
      });

      const result = await this.registerPeerMetadata(payload, {
        source: 'hyperswarm',
        skipConnect: true
      });

      const responseBody = {
        status: 'ok',
        acknowledgedAt: new Date().toISOString(),
        publicKey,
        relayCount: result.relayCount,
        relays: result.relays,
        subnetHash: this.config?.subnetHash || null
      };

      this.log('info', `Hyperswarm registration acknowledged for peer ${publicKey.slice(0, 8)}...`);

      return {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: Buffer.from(JSON.stringify(responseBody))
      };
    } catch (error) {
      this.log('error', `Hyperswarm registration failed for peer ${publicKey.slice(0, 8)}: ${error.message}`);
      return {
        statusCode: 400,
        headers: { 'content-type': 'application/json' },
        body: Buffer.from(JSON.stringify({ error: error.message }))
      };
    }
  }

  _coerceTimestamp(value) {
    if (value === null || value === undefined) return null;
    if (typeof value === 'number') {
      return Number.isFinite(value) ? value : null;
    }
    const parsed = Date.parse(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  _normalizeGatewayPath(identifier, gatewayPath = null, legacyUrl = null) {
    if (typeof gatewayPath === 'string' && gatewayPath.trim()) {
      return gatewayPath.replace(/^\//, '');
    }

    if (typeof legacyUrl === 'string' && legacyUrl.trim()) {
      try {
        const parsed = new URL(legacyUrl);
        const path = parsed.pathname.replace(/^\//, '');
        if (path) return path;
      } catch (_) {
        // ignore malformed URL
      }
    }

    if (typeof identifier === 'string' && identifier.includes(':')) {
      return identifier.replace(':', '/');
    }

    return typeof identifier === 'string' ? identifier : null;
  }

  _normalizeRelayIdentifier(value) {
    if (!value || typeof value !== 'string') return null;
    let normalized = value.trim();
    if (!normalized) return null;

    try {
      normalized = decodeURIComponent(normalized);
    } catch (_) {
      // ignore URI decoding errors
    }

    if (normalized.includes('/')) {
      const parts = normalized.split('/').filter(Boolean);
      if (parts.length >= 2) {
        normalized = `${parts[0]}:${parts[1]}`;
      }
    }

    return normalized;
  }

  #getPublicGatewayRelayKey() {
    if (!PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED) return null;
    if (!this.publicGatewaySettings?.enabled) return null;
    return PUBLIC_GATEWAY_RELAY_KEY;
  }

  #getPublicGatewayRelayPath() {
    return this._normalizeGatewayPath(null, PUBLIC_GATEWAY_RELAY_PATH, null);
  }

  #getPublicGatewayRelayPathAliases() {
    return PUBLIC_GATEWAY_RELAY_PATH_ALIASES
      .map((alias) => this._normalizeGatewayPath(null, alias, null))
      .filter(Boolean);
  }

  #applyPublicGatewayPathMetadata(target = {}) {
    if (!target || typeof target !== 'object') return target;
    const normalizePath = (value) => this._normalizeGatewayPath(null, value, null);
    const canonicalPath = normalizePath(this.#getPublicGatewayRelayPath());
    if (canonicalPath) {
      target.gatewayPath = canonicalPath;
    }
    const aliasSet = new Set();
    const existingAliases = Array.isArray(target.pathAliases) ? target.pathAliases : [];
    for (const alias of existingAliases) {
      const normalizedAlias = normalizePath(alias);
      if (normalizedAlias && normalizedAlias !== canonicalPath) {
        aliasSet.add(normalizedAlias);
      }
    }
    for (const alias of this.#getPublicGatewayRelayPathAliases()) {
      const normalizedAlias = normalizePath(alias);
      if (normalizedAlias && normalizedAlias !== canonicalPath) {
        aliasSet.add(normalizedAlias);
      }
    }
    target.pathAliases = Array.from(aliasSet);
    return target;
  }

  #isPublicGatewayRelayKey(relayKey) {
    if (!relayKey) return false;
    return relayKey === PUBLIC_GATEWAY_RELAY_KEY;
  }

  #ensurePublicGatewayRelayEntry({ hyperbee } = {}) {
    if (!PUBLIC_GATEWAY_VIRTUAL_RELAY_ENABLED) {
      return;
    }
    const relayKey = this.#getPublicGatewayRelayKey();
    const resolvedRelay = this.publicGatewaySettings?.resolvedGatewayRelay;
    if (!relayKey || !resolvedRelay?.hyperbeeKey) {
      return;
    }

    let relayData = this.activeRelays.get(relayKey);
    if (!relayData) {
      relayData = {
        peers: new Set(),
        status: 'active',
        createdAt: Date.now(),
        lastActive: Date.now(),
        metadata: {}
      };
      this.activeRelays.set(relayKey, relayData);
    }

    relayData.lastActive = Date.now();
    if (!relayData.peers) {
      relayData.peers = new Set();
    }
    if (this.ownPeerPublicKey) {
      relayData.peers.add(this.ownPeerPublicKey);
    }
    const poolPublicKey = this.connectionPool?.getPublicKey?.();
    if (!this.ownPeerPublicKey && poolPublicKey) {
      relayData.peers.add(poolPublicKey);
    }

    const metadata = { ...(relayData.metadata || {}) };
    metadata.identifier = metadata.identifier || relayKey;
    if (!metadata.name) {
      metadata.name = this.publicGatewaySettings?.resolvedDisplayName || 'Public Gateway Relay';
    }
    if (!metadata.description) {
      metadata.description = 'Replicated public gateway relay dataset';
    }
    this.#applyPublicGatewayPathMetadata(metadata);
    metadata.isPublic = true;
    metadata.isGatewayReplica = true;

    const relayInfo = hyperbee || resolvedRelay || metadata.gatewayRelay || null;
    if (relayInfo) {
      metadata.gatewayRelay = {
        hyperbeeKey: relayInfo.hyperbeeKey || null,
        discoveryKey: relayInfo.discoveryKey || null,
        replicationTopic: relayInfo.replicationTopic || null,
        defaultTokenTtl: relayInfo.defaultTokenTtl ?? null,
        tokenRefreshWindowSeconds: relayInfo.tokenRefreshWindowSeconds ?? null,
        dispatcher: relayInfo.dispatcher || null
      };
    }

    relayData.metadata = metadata;

    const peerList = Array.from(relayData.peers || []);
    const localBase = this.config?.urls?.hostname || this.gatewayServer?.getServerUrls()?.hostname || 'ws://127.0.0.1:8443';
    const localConnectionUrl = `${localBase.replace(/\/$/, '')}/${this.#getPublicGatewayRelayPath()}`;

    const existingState = this.publicGatewayRelayState.get(relayKey);
    const nextState = existingState
      ? {
          ...existingState,
          metadata,
          peerCount: peerList.length,
          peers: peerList,
          defaultTokenTtl: this.publicGatewaySettings?.defaultTokenTtl ?? existingState.defaultTokenTtl ?? null,
          tokenRefreshWindowSeconds: this.publicGatewaySettings?.resolvedTokenRefreshWindowSeconds ?? existingState.tokenRefreshWindowSeconds ?? null,
          dispatcher: this.publicGatewaySettings?.resolvedDispatcher || existingState.dispatcher || null,
          localConnectionUrl,
          requiresAuth: false
        }
      : {
          relayKey,
          status: 'pending',
          peerCount: peerList.length,
          lastSyncedAt: null,
          message: null,
          metadata,
          peers: peerList,
          token: null,
          connectionUrl: null,
          expiresAt: null,
          ttlSeconds: null,
          tokenIssuedAt: null,
          defaultTokenTtl: this.publicGatewaySettings?.defaultTokenTtl ?? null,
          tokenRefreshWindowSeconds: this.publicGatewaySettings?.resolvedTokenRefreshWindowSeconds ?? null,
          dispatcher: this.publicGatewaySettings?.resolvedDispatcher || null,
          localConnectionUrl,
          requiresAuth: false
        };

    this.publicGatewayRelayState.set(relayKey, nextState);
    this.#emitPublicGatewayStatus();
  }

  async #registerPublicGatewayVirtualRelay(metadata = {}) {
    void metadata;
    this.publicGatewayVirtualRelayManager = null;
    this.log('debug', '[PublicGateway] Virtual relay registration disabled');
  }

  async #unregisterPublicGatewayVirtualRelay(relayKey = PUBLIC_GATEWAY_RELAY_KEY) {
    void relayKey;
    this.publicGatewayVirtualRelayManager = null;
  }

  _ensureRelayAvatarUrl(url, identifier) {
    if (!url || typeof url !== 'string' || !identifier) {
      return url;
    }

    const trimmed = url.trim();
    if (!trimmed) return url;

    const isRelative = trimmed.startsWith('/');
    let parsed;

    try {
      parsed = new URL(trimmed, 'http://placeholder.local');
    } catch (_) {
      return url;
    }

    if (!parsed.pathname.startsWith('/pfp/')) {
      return url;
    }

    parsed.searchParams.set('relay', identifier);

    if (isRelative) {
      const search = parsed.search ? parsed.search : '';
      return `${parsed.pathname}${search}`;
    }

    return parsed.toString();
  }

  handleGatewayWebSocketConnection(ws, req) {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname || '';

    const strippedPath = pathname.replace(/^\/+/, '');
    const normalizedIdentifier = this._normalizeRelayIdentifier(strippedPath);

    const rawParts = strippedPath.split('/').filter(Boolean);
    let fallbackIdentifier = null;
    if (rawParts.length >= 2) {
      fallbackIdentifier = `${rawParts[0]}:${rawParts.slice(1).join('/')}`;
    } else if (rawParts.length === 1) {
      fallbackIdentifier = rawParts[0];
    }

    const candidateIdentifiers = new Set();
    if (normalizedIdentifier) candidateIdentifiers.add(normalizedIdentifier);
    if (fallbackIdentifier) candidateIdentifiers.add(fallbackIdentifier);
    if (strippedPath) candidateIdentifiers.add(strippedPath);

    const matchedIdentifier = Array.from(candidateIdentifiers).find(id => this.activeRelays.has(id));

    const authToken = parsedUrl.query?.token || null;

    if (matchedIdentifier) {
      this.handleWebSocket(ws, matchedIdentifier, authToken);
      return;
    }

    const candidateList = Array.from(candidateIdentifiers);
    this.log('warn', `[PublicGateway] Rejecting websocket connection for unknown relay path "${strippedPath}" candidates=${candidateList.length ? candidateList.join(',') : 'none'} activeRelays=${this.activeRelays.size}`);
    ws.close(1008, 'Invalid relay key');
  }

  handleWebSocket(ws, identifier, authToken = null) {
    const connectionKey = generateConnectionKey();
    this.wsConnections.set(connectionKey, {
      ws,
      relayKey: identifier,
      authToken,
      connectionKey,
      shouldPollPeers: false,
      delegatedSubscriptions: new Set(),
      localServedSubscriptions: new Set(),
      pendingDelegations: new Map()
    });

    const messageQueue = new MessageQueue();
    this.messageQueues.set(connectionKey, messageQueue);

    ws.on('message', async (message) => {
      await messageQueue.enqueue(message, async (msg) => {
        const connData = this.wsConnections.get(connectionKey);
        if (!connData) {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(['NOTICE', 'Internal server error: connection data missing']));
          }
          return;
        }

        let frameType = null;
        let frameSubscriptionId = null;
        if (typeof msg === 'string' || msg instanceof Buffer) {
          try {
            const parsed = JSON.parse(typeof msg === 'string' ? msg : msg.toString());
            if (Array.isArray(parsed)) {
              frameType = parsed[0];
              frameSubscriptionId = parsed[1];
            }
          } catch (_) {}
        }

        const wasPolling = connData.shouldPollPeers;
        let shouldTriggerImmediatePoll = false;

        const localResult = await this.#maybeHandleReqLocally(connData, msg);
        if (localResult?.handled) {
          connData.shouldPollPeers = false;
          if (localResult.subscriptionId) {
            connData.localServedSubscriptions.add(localResult.subscriptionId);
            connData.delegatedSubscriptions.delete(localResult.subscriptionId);
            connData.pendingDelegations?.delete?.(localResult.subscriptionId);
          }
          this.log('debug', `[PublicGateway] Served subscription locally`, {
            connectionKey,
            relayKey: connData.relayKey,
            subscriptionId: localResult.subscriptionId,
            events: localResult.eventsServed ?? 0
          });
          return;
        }

        const subscriptionId = localResult?.subscriptionId || frameSubscriptionId || null;
        const wantsDelegation = localResult?.shouldPollPeers === true && typeof subscriptionId === 'string';

        if (frameType === 'CLOSE' && frameSubscriptionId) {
          const wasDelegated = connData.delegatedSubscriptions.has(frameSubscriptionId);
          const hadPendingDelegation = connData.pendingDelegations?.has?.(frameSubscriptionId) === true;
          const wasLocalServed = connData.localServedSubscriptions.has(frameSubscriptionId);
          const shouldForwardClose = wasDelegated || hadPendingDelegation || !wasLocalServed;
          let closeForwarded = false;
          let closeForwardError = null;

          if (shouldForwardClose) {
            const closePeer = await this.findHealthyPeerForRelay(identifier, true);
            if (closePeer) {
              try {
                await this.#forwardMessageToPeer({
                  connData,
                  healthyPeer: closePeer,
                  identifier,
                  rawMessage: msg,
                  subscriptionId: frameSubscriptionId,
                  isRetry: false
                });
                closeForwarded = true;
              } catch (error) {
                closeForwardError = error?.message || String(error);
              }
            } else {
              closeForwardError = 'no healthy peers';
            }
          }

          connData.delegatedSubscriptions.delete(frameSubscriptionId);
          connData.localServedSubscriptions.delete(frameSubscriptionId);
          connData.pendingDelegations?.delete?.(frameSubscriptionId);
          connData.shouldPollPeers = (connData.delegatedSubscriptions.size > 0) ||
            (connData.pendingDelegations?.size > 0);
          if (closeForwardError && shouldForwardClose) {
            this.log('warn', '[PublicGateway] Failed to forward CLOSE to peer', {
              connectionKey,
              relayKey: connData.relayKey,
              subscriptionId: frameSubscriptionId,
              error: closeForwardError
            });
          }
          this.log('debug', '[PublicGateway] Client closed subscription', {
            connectionKey,
            relayKey: connData.relayKey,
            subscriptionId: frameSubscriptionId,
            delegatedSubscriptions: connData.delegatedSubscriptions.size,
            closeForwardAttempted: shouldForwardClose,
            closeForwarded
          });
          return;
        }

        if (wantsDelegation) {
          const outboundMessage = typeof msg === 'string' ? msg : msg?.toString?.() ?? '';
          connData.pendingDelegations?.set(subscriptionId, {
            message: outboundMessage,
            attempts: 0,
            lastAttemptAt: Date.now()
          });
          connData.shouldPollPeers = true;
        }

        const healthyPeer = await this.findHealthyPeerForRelay(identifier, wantsDelegation);
        if (!healthyPeer) {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(['NOTICE', 'No healthy peers available for this relay']));
          }
          connData.shouldPollPeers = (connData.delegatedSubscriptions.size > 0) ||
            (connData.pendingDelegations?.size > 0);
          return;
        }

        this.log('debug', '[PublicGateway] Forwarding message to peer', {
          connectionKey,
          relayKey: identifier,
          peer: healthyPeer.publicKey?.slice(0, 12) || 'unknown',
          delegated: wantsDelegation || connData.delegatedSubscriptions.size > 0,
          subscriptionId
        });

        let forwardSucceeded = false;
        try {
          const responses = await this.#forwardMessageToPeer({
            connData,
            healthyPeer,
            identifier,
            rawMessage: msg,
            subscriptionId,
            isRetry: false
          });

          for (const response of responses) {
            if (!response) continue;
            if (response[0] === 'OK' && response[2] === false) {
              const errorMsg = response[3] || '';
              if (errorMsg.includes('Authentication') && ws.readyState === WebSocket.OPEN) {
                ws.close(4403, 'Authentication failed');
                return;
              }
            }
            if (ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify(response));
            }
          }

          forwardSucceeded = true;
        } catch (error) {
          const pendingEntry = subscriptionId ? connData.pendingDelegations?.get?.(subscriptionId) : null;
          if (pendingEntry) {
            pendingEntry.attempts = (pendingEntry.attempts || 0) + 1;
            pendingEntry.lastAttemptAt = Date.now();
            connData.pendingDelegations.set(subscriptionId, pendingEntry);
          }
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(['NOTICE', `Error: ${error.message}`]));
          }
          connData.shouldPollPeers = (connData.delegatedSubscriptions.size > 0) ||
            (connData.pendingDelegations?.size > 0);
          if (wantsDelegation) {
            setTimeout(() => {
              this.#pollDelegatedSubscriptions(connectionKey, {
                reason: 'retry',
                allowRetry: true
              }).catch((err) => {
                this.log('warn', `[PublicGateway] Delegation retry failed: ${err.message}`);
              });
            }, 250);
          }
          return;
        }

        connData.shouldPollPeers = (connData.delegatedSubscriptions.size > 0) ||
          (connData.pendingDelegations?.size > 0) ||
          (wantsDelegation && forwardSucceeded);

        if (!wasPolling && connData.shouldPollPeers) {
          shouldTriggerImmediatePoll = true;
        }

        if (shouldTriggerImmediatePoll && forwardSucceeded) {
          await this.#pollDelegatedSubscriptions(connectionKey, { reason: 'immediate', allowRetry: true });
        }
      });
    });

    ws.on('close', () => {
      this.cleanupConnection(connectionKey);
    });

    ws.on('error', () => {
      this.cleanupConnection(connectionKey);
    });

    this.startEventChecking(connectionKey);
  }

  async #maybeHandleReqLocally(connData, rawMessage) {
    const response = {
      handled: false,
      subscriptionId: null,
      shouldPollPeers: false,
      eventsServed: 0,
      delegated: false
    };

    const { ws, relayKey } = connData || {};
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      return response;
    }

    let frame;
    let textPayload;
    try {
      textPayload = typeof rawMessage === 'string' ? rawMessage : rawMessage.toString();
      frame = JSON.parse(textPayload);
    } catch (error) {
      return response;
    }

    if (!Array.isArray(frame) || frame[0] !== 'REQ') {
      return response;
    }

    const subscriptionId = frame[1];
    if (!subscriptionId) {
      return response;
    }
    response.subscriptionId = subscriptionId;

    if (!this.#isPublicGatewayRelayKey(relayKey)) {
      this.log('debug', '[PublicGateway] Skip local serve for non-gateway relay', {
        relayKey,
        subscriptionId
      });
      response.shouldPollPeers = true;
      return response;
    }

    const filters = frame.slice(2);

    if (this.publicGatewaySettings?.delegateReqToPeers === false) {
      this.log(
        'debug',
        `[PublicGateway] Delegation disabled via settings for incoming REQ relay=${relayKey} subscription=${subscriptionId} filterCount=${filters.length}`
      );
    }

    this.log(
      'debug',
      `[PublicGateway] Handling incoming REQ relay=${relayKey} subscription=${subscriptionId} connection=${connData.connectionKey} filters=${JSON.stringify(filters)}`
    );

    if (connData.delegatedSubscriptions?.has(subscriptionId)) {
      this.log('debug', '[PublicGateway] Subscription already delegated to peer; bypassing local serve', {
        relayKey,
        subscriptionId
      });
      response.shouldPollPeers = true;
      return response;
    }

    const hasReplica = this.hyperbeeAdapter?.hasReplica?.() === true;
    const hyperbeeKey = this.publicGatewayRelayClient?.getHyperbeeKey?.() || null;
    const canServeLocally = hasReplica ? this.#canServeRelayLocally(relayKey) : false;
    if (!hasReplica || !canServeLocally) {
      this.log(
        'debug',
        `[PublicGateway] Replica unavailable or disabled for local serving relay=${relayKey} subscription=${subscriptionId} hasReplica=${hasReplica} canServeLocally=${canServeLocally} hyperbeeKey=${hyperbeeKey || 'null'}`
      );
      response.shouldPollPeers = true;
      return response;
    }

    if (this.#shouldDelegateReq(filters, relayKey, subscriptionId)) {
      this.#recordHyperbeeFallback('delegated', relayKey, { subscriptionId });
      this.log('info', '[PublicGateway] Delegating subscription to worker', {
        relayKey,
        subscriptionId,
        filterCount: filters.length
      });
      response.shouldPollPeers = true;
      response.delegated = true;
      return response;
    }

    const replicaStats = await this.hyperbeeAdapter.getReplicaStats();
    const lagThreshold = Number(this.publicGatewaySettings?.dispatcherReassignLagBlocks) || 0;
    const replicaLag = replicaStats?.lag || 0;
    const replicaVersion = this.hyperbeeAdapter?.relayClient?.getHyperbee?.()?.version || null;
    this.log(
      'debug',
      `[PublicGateway] Replica stats relay=${relayKey} subscription=${subscriptionId} version=${replicaVersion} lag=${replicaLag}`
    );
    if (lagThreshold > 0 && replicaStats.lag > lagThreshold) {
      this.#recordHyperbeeFallback('lag', relayKey, { lag: replicaStats.lag, lagThreshold });
      this.log('info', '[PublicGateway] Delegating subscription due to replica lag', {
        relayKey,
        subscriptionId,
        lag: replicaStats.lag,
        lagThreshold
      });
      response.shouldPollPeers = true;
      return response;
    }

    let queryResult;
    try {
      queryResult = await this.hyperbeeAdapter.query(filters);
    } catch (error) {
      this.#recordHyperbeeError(error, relayKey);
      response.shouldPollPeers = true;
      return response;
    }

    const returnedEvents = Array.isArray(queryResult?.events) ? queryResult.events.length : 0;
    const served = !!queryResult?.stats?.served;
    const truncated = !!queryResult?.stats?.truncated;
    this.log(
      'debug',
      `[PublicGateway] Local query stats relay=${relayKey} subscription=${subscriptionId} served=${served} events=${returnedEvents} truncated=${truncated}`
    );

    if (!queryResult?.stats?.served) {
      this.#recordHyperbeeFallback('not-served', relayKey);
      this.log('debug', '[PublicGateway] Hyperbee replica unable to serve query, delegating', {
        relayKey,
        subscriptionId
      });
      response.shouldPollPeers = true;
      return response;
    }

    const events = Array.isArray(queryResult.events) ? queryResult.events : [];
    if (events.length === 0) {
      this.log(
        'debug',
        `[PublicGateway] Local query returned no events relay=${relayKey} subscription=${subscriptionId} filterCount=${filters.length}`
      );
    }
    if (events.length === 0 && this.#shouldFallbackOnEmpty(filters)) {
      this.#recordHyperbeeFallback('empty', relayKey);
      this.log('debug', '[PublicGateway] Delegating subscription because replica returned empty result set', {
        relayKey,
        subscriptionId
      });
      response.shouldPollPeers = true;
      return response;
    }

    try {
      for (const event of events) {
        ws.send(JSON.stringify(['EVENT', subscriptionId, event]));
      }
      ws.send(JSON.stringify(['EOSE', subscriptionId]));
    } catch (error) {
      this.#recordHyperbeeError(error, relayKey);
      response.shouldPollPeers = true;
      return response;
    }

    this.#recordHyperbeeServed(relayKey, {
      events: events.length,
      truncated: !!queryResult?.stats?.truncated,
      lag: replicaStats.lag
    });
    this.log(
      'info',
      `[PublicGateway] Served subscription locally relay=${relayKey} subscription=${subscriptionId} events=${events.length}`
    );

    response.handled = true;
    response.eventsServed = events.length;
    return response;
  }

  #canServeRelayLocally(relayKey) {
    if (!relayKey) return false;
    if (!this.#isPublicGatewayRelayKey(relayKey)) return false;
    if (!this.hyperbeeAdapter?.hasReplica()) return false;
    const relayState = this.publicGatewayRelayState.get(relayKey);
    const fallbackRelay = this.publicGatewaySettings?.resolvedGatewayRelay || null;
    const gatewayRelay = relayState?.metadata?.gatewayRelay || fallbackRelay;
    if (!gatewayRelay?.hyperbeeKey) return false;
    const currentKey = this.publicGatewayRelayClient?.getHyperbeeKey?.();
    if (currentKey && currentKey !== gatewayRelay.hyperbeeKey) {
      return false;
    }
    return true;
  }

  #shouldFallbackOnEmpty(filters) {
    if (!Array.isArray(filters) || filters.length === 0) return false;
    return filters.some((filter) => Array.isArray(filter?.ids) && filter.ids.length);
  }

  #shouldDelegateReq(filters, relayKey, subscriptionId) {
    if (!Array.isArray(filters) || filters.length === 0) return false;

    const filterCount = filters.length;

    if (this.publicGatewaySettings?.delegateReqToPeers === true) {
      this.log(
        'debug',
        `[PublicGateway] Delegating based on configuration relay=${relayKey} subscription=${subscriptionId}`
      );
      return true;
    }

    if (process.env.PUBLIC_GATEWAY_DELEGATE_REQS === 'true') {
      this.log(
        'debug',
        `[PublicGateway] Delegation forced by PUBLIC_GATEWAY_DELEGATE_REQS env flag relay=${relayKey} subscription=${subscriptionId} filterCount=${filterCount}`
      );
      return true;
    }

    if (this.publicGatewaySettings?.delegateReqToPeers !== true) {
      const heuristicsTriggered = filterCount >= 6 || filters.some((filter) => {
        const limit = Number(filter?.limit);
        return Number.isFinite(limit) && limit >= 1000;
      });
      if (heuristicsTriggered) {
        this.log(
          'debug',
          `[PublicGateway] Delegation heuristics suppressed (delegate disabled) relay=${relayKey} subscription=${subscriptionId} filterCount=${filterCount}`
        );
      }
      return false;
    }

    if (filterCount >= 6) {
      this.log(
        'debug',
        `[PublicGateway] Delegating based on filter count heuristic relay=${relayKey} subscription=${subscriptionId} filterCount=${filterCount}`
      );
      return true;
    }

    return filters.some((filter) => {
      const limit = Number(filter?.limit);
      const delegate = Number.isFinite(limit) && limit >= 1000;
      if (delegate) {
        this.log(
          'debug',
          `[PublicGateway] Delegating based on filter limit heuristic relay=${relayKey} subscription=${subscriptionId} filterLimit=${limit}`
        );
      }
      return delegate;
    });
  }

  #recordHyperbeeServed(relayKey, { events = 0, truncated = false, lag = 0 } = {}) {
    if (!this.hyperbeeQueryStats) return;
    this.hyperbeeQueryStats.totalServed += 1;
    this.hyperbeeQueryStats.totalEvents += events;
    this.hyperbeeQueryStats.lastServedAt = Date.now();
    this.hyperbeeQueryStats.lastServedLag = lag;
    this.hyperbeeQueryStats.lastServedRelay = relayKey || null;
    this.hyperbeeQueryStats.lastServedTruncated = !!truncated;
  }

  #recordHyperbeeFallback(reason, relayKey, extra = {}) {
    if (!this.hyperbeeQueryStats) return;
    this.hyperbeeQueryStats.totalFallbacks += 1;
    this.hyperbeeQueryStats.lastFallbackAt = Date.now();
    this.hyperbeeQueryStats.lastFallbackReason = reason || 'unknown';
    this.hyperbeeQueryStats.lastFallbackRelay = relayKey || null;
    this.hyperbeeQueryStats.lastFallbackMeta = extra || {};
  }

  #recordHyperbeeError(error, relayKey) {
    if (!this.hyperbeeQueryStats) return;
    this.hyperbeeQueryStats.totalErrors += 1;
    this.hyperbeeQueryStats.lastErrorAt = Date.now();
    this.hyperbeeQueryStats.lastErrorMessage = error?.message || String(error);
    this.hyperbeeQueryStats.lastErrorRelay = relayKey || null;
    this.log('debug', `[PublicGateway] Hyperbee query error: ${this.hyperbeeQueryStats.lastErrorMessage}`);
  }

  cleanupConnection(connectionKey) {
    const data = this.wsConnections.get(connectionKey);
    if (!data) return;

    this.wsConnections.delete(connectionKey);
    this.messageQueues.delete(connectionKey);
    const timer = this.eventCheckTimers.get(connectionKey);
    if (timer) {
      clearTimeout(timer);
      this.eventCheckTimers.delete(connectionKey);
    }

    data.pendingDelegations?.clear?.();
    this.activePeerPolls.delete(connectionKey);
  }

  async #forwardMessageToPeer({ connData, healthyPeer, identifier, rawMessage, subscriptionId = null, isRetry = false }) {
    if (!connData || !healthyPeer) {
      throw new Error('Missing connection context for peer forwarding');
    }

    const outboundMessage = typeof rawMessage === 'string' ? rawMessage : rawMessage?.toString?.() ?? '';
    const authToken = this.#resolveConnectionAuthToken(connData, identifier);
    const responses = await forwardMessageToPeerHyperswarm(
      healthyPeer.publicKey,
      identifier,
      outboundMessage,
      connData.connectionKey,
      this.connectionPool,
      authToken
    );

    let frameType = null;
    try {
      const parsedFrame = JSON.parse(outboundMessage);
      if (Array.isArray(parsedFrame) && typeof parsedFrame[0] === 'string') {
        frameType = parsedFrame[0];
      }
    } catch (_) {}

    if (subscriptionId) {
      if (frameType === 'CLOSE') {
        connData.delegatedSubscriptions.delete(subscriptionId);
        connData.localServedSubscriptions.delete(subscriptionId);
        connData.pendingDelegations?.delete?.(subscriptionId);
        this.log('debug', '[PublicGateway] Forwarded CLOSE to peer', {
          connectionKey: connData.connectionKey,
          relayKey: identifier,
          subscriptionId,
          retry: isRetry
        });
      } else {
        connData.delegatedSubscriptions.add(subscriptionId);
        connData.localServedSubscriptions.delete(subscriptionId);
        connData.pendingDelegations?.delete?.(subscriptionId);
        this.log('debug', '[PublicGateway] Delegated subscription forwarded to peer', {
          connectionKey: connData.connectionKey,
          relayKey: identifier,
          subscriptionId,
          retry: isRetry
        });
      }
    }

    return responses;
  }

  async #pollDelegatedSubscriptions(connectionKey, { reason = 'scheduled', allowRetry = false } = {}) {
    const existing = this.activePeerPolls.get(connectionKey);
    if (existing) {
      if (reason === 'immediate') {
        try {
          await existing;
        } catch (_) {}
      }
      return existing;
    }

    const pollPromise = (async () => {
      const connectionData = this.wsConnections.get(connectionKey);
      if (!connectionData) return;

      const { ws, relayKey: identifier, pendingDelegations } = connectionData;
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        this.cleanupConnection(connectionKey);
        return;
      }

      const hasPending = (pendingDelegations?.size || 0) > 0;
      const hasDelegated = (connectionData.delegatedSubscriptions?.size || 0) > 0;

      if (!hasPending && !hasDelegated) {
        connectionData.shouldPollPeers = false;
        return;
      }

      let healthyPeer = await this.findHealthyPeerForRelay(
        identifier,
        allowRetry || reason === 'immediate' || hasPending
      );
      if (!healthyPeer) {
        ws.send(JSON.stringify(['NOTICE', 'Gateway temporarily unavailable - no healthy peers']));
        return;
      }

      if (hasPending) {
        const entries = Array.from(pendingDelegations.entries());
        for (const [pendingSubscriptionId, payload] of entries) {
          try {
            await this.#forwardMessageToPeer({
              connData: connectionData,
              healthyPeer,
              identifier,
              rawMessage: payload?.message ?? '[]',
              subscriptionId: pendingSubscriptionId,
              isRetry: true
            });
            pendingDelegations.delete(pendingSubscriptionId);
            this.log('debug', '[PublicGateway] Delegated subscription resent to peer', {
              connectionKey,
              relayKey: identifier,
              subscriptionId: pendingSubscriptionId,
              attempts: payload?.attempts ?? 0,
              reason
            });
          } catch (error) {
            const attempts = (payload?.attempts ?? 0) + 1;
            pendingDelegations.set(pendingSubscriptionId, {
              ...(payload || {}),
              attempts,
              lastAttemptAt: Date.now()
            });
            this.log('debug', `[PublicGateway] Failed to resend delegated subscription (attempt ${attempts})`, {
              connectionKey,
              relayKey: identifier,
              subscriptionId: pendingSubscriptionId,
              error: error?.message || error
            });
          }
        }
      }

      if (pendingDelegations?.size) {
        connectionData.shouldPollPeers = true;
        this.log('debug', '[PublicGateway] Pending delegations remain unsent, deferring event polling', {
          connectionKey,
          relayKey: identifier,
          pending: pendingDelegations.size,
          reason
        });
        return;
      }

      if (!connectionData.delegatedSubscriptions?.size) {
        connectionData.shouldPollPeers = false;
        return;
      }

      this.log('debug', '[PublicGateway] Polling delegated subscriptions from peer', {
        connectionKey,
        relayKey: identifier,
        delegatedSubscriptions: connectionData.delegatedSubscriptions?.size || 0,
        reason
      });

      try {
        // reuse existing healthyPeer if available, otherwise resolve again for clarity
        const peer = healthyPeer || await this.findHealthyPeerForRelay(identifier, allowRetry || reason === 'immediate');
        if (!peer) {
          ws.send(JSON.stringify(['NOTICE', 'Gateway temporarily unavailable - no healthy peers']));
          return;
        }

        const events = await getEventsFromPeerHyperswarm(
          peer.publicKey,
          identifier,
          connectionKey,
          this.connectionPool,
          this.#resolveConnectionAuthToken(connectionData, identifier)
        );

        for (const event of events) {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(event));
          }
        }
      } catch (error) {
        this.log('warn', `[PublicGateway] Event check failed (${reason}): ${error.message}`);
      }
    })();

    this.activePeerPolls.set(connectionKey, pollPromise);
    try {
      await pollPromise;
    } finally {
      if (this.activePeerPolls.get(connectionKey) === pollPromise) {
        this.activePeerPolls.delete(connectionKey);
      }
    }

    return pollPromise;
  }

  async startEventChecking(connectionKey) {
    const loop = async () => {
      const connectionData = this.wsConnections.get(connectionKey);
      if (!connectionData) {
        this.eventCheckTimers.delete(connectionKey);
        return;
      }

      const { ws, relayKey: identifier } = connectionData;
      if (!ws || ws.readyState !== WebSocket.OPEN) {
        this.cleanupConnection(connectionKey);
        return;
      }

      const hasPending = (connectionData.pendingDelegations?.size || 0) > 0;
      if (connectionData.shouldPollPeers || hasPending) {
        await this.#pollDelegatedSubscriptions(connectionKey, {
          reason: hasPending ? 'pending-resend' : 'scheduled',
          allowRetry: true
        });
      } else {
        this.log('debug', '[PublicGateway] Skipping peer poll for connection (local handling active)', {
          connectionKey,
          relayKey: identifier
        });
      }

      const timer = setTimeout(() => {
        loop().catch((error) => {
          this.log('warn', `[PublicGateway] Event polling loop error: ${error.message}`);
        });
      }, hasPending ? 2000 : 10000);
      this.eventCheckTimers.set(connectionKey, timer);
    };

    const timer = setTimeout(() => {
      loop().catch((error) => {
        this.log('warn', `[PublicGateway] Initial event polling loop error: ${error.message}`);
      });
    }, 500);
    this.eventCheckTimers.set(connectionKey, timer);
  }

  async findHealthyPeerForRelay(identifier, allowRetry = false) {
    const relay = this.activeRelays.get(identifier);
    if (!relay) return null;

    const peerKeys = Array.from(relay.peers);
    if (!peerKeys.length) return null;

    for (const publicKey of peerKeys) {
      const peer = this.activePeers.find(p => p.publicKey === publicKey);
      if (!peer) continue;
      const healthy = this.peerHealthManager.isPeerHealthy(publicKey);
      if (healthy) {
        return peer;
      }
    }

    if (allowRetry) {
      for (const publicKey of peerKeys) {
        const peer = this.activePeers.find(p => p.publicKey === publicKey);
        if (!peer) continue;
        const healthy = await this.peerHealthManager.checkPeerHealth(peer, this.connectionPool);
        if (healthy) {
          return peer;
        }
      }
    }

    return null;
  }

  async #applyBlindPeerInfo(info = {}, { persist = false } = {}) {
    if (!info || typeof info !== 'object') {
      return false;
    }
    const summary = { ...info };
    this.blindPeerSummary = summary;

    const enabled = !!info.enabled;
    const publicKey = typeof info.publicKey === 'string' ? info.publicKey.trim() : null;
    const encryptionKey = typeof info.encryptionKey === 'string' ? info.encryptionKey.trim() : null;
    const maxBytes = Number.isFinite(info.maxBytes) && info.maxBytes > 0 ? Math.trunc(info.maxBytes) : null;

    const current = this.publicGatewaySettings || {};
    const currentKeys = Array.isArray(current.blindPeerKeys) ? current.blindPeerKeys : [];
    const nextKeys = enabled && publicKey ? [publicKey] : [];

    const changed =
      current.blindPeerEnabled !== enabled
      || current.blindPeerEncryptionKey !== encryptionKey
      || current.blindPeerMaxBytes !== maxBytes
      || currentKeys.length !== nextKeys.length
      || currentKeys.some((value, index) => value !== nextKeys[index]);

    if (!changed) return false;

    this.publicGatewaySettings = {
      ...current,
      blindPeerEnabled: enabled,
      blindPeerKeys: nextKeys,
      blindPeerEncryptionKey: encryptionKey,
      blindPeerMaxBytes: maxBytes
    };

    if (persist) {
      await updatePublicGatewaySettings(this.publicGatewaySettings);
    }

    return true;
  }

  async #maybeFetchBlindPeerInfo({ reason = 'fallback', force = false } = {}) {
    const settings = this.publicGatewaySettings || {};
    const manualKeys = Array.isArray(settings.blindPeerManualKeys) ? settings.blindPeerManualKeys.filter(Boolean) : [];
    const handshakeKeys = Array.isArray(settings.blindPeerKeys) ? settings.blindPeerKeys.filter(Boolean) : [];
    if (!force && (handshakeKeys.length || manualKeys.length)) return false;
    if (!force && this.blindPeerSummary?.enabled && this.blindPeerSummary?.publicKey) return false;

    const baseUrl = settings.baseUrl || settings.preferredBaseUrl || null;
    if (!baseUrl) return false;

    if (!this.blindPeerFallbackState) {
      this.blindPeerFallbackState = {
        inflight: null,
        lastAttempt: 0
      };
    }

    if (this.blindPeerFallbackState.inflight) {
      return this.blindPeerFallbackState.inflight;
    }

    const now = Date.now();
    if (!force && this.blindPeerFallbackState.lastAttempt && (now - this.blindPeerFallbackState.lastAttempt) < 60000) {
      return false;
    }

    const attempt = (async () => {
      this.blindPeerFallbackState.lastAttempt = Date.now();
      try {
        const target = new URL('/api/blind-peer', baseUrl);
        const response = await fetch(target, {
          headers: {
            accept: 'application/json'
          }
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status} ${response.statusText}`);
        }
        const payload = await response.json();
        const summary = payload?.summary || null;
        const status = payload?.status || null;
        const info = {
          enabled: summary?.enabled ?? status?.enabled ?? false,
          publicKey: summary?.publicKey || null,
          encryptionKey: summary?.encryptionKey || null,
          maxBytes: summary?.config?.maxBytes ?? status?.config?.maxBytes ?? null
        };
        const changed = await this.#applyBlindPeerInfo(info, { persist: true });
        if (changed) {
          this.log('info', `[PublicGateway] Blind peer metadata refreshed via REST fallback (${reason})`);
        }
        return changed;
      } catch (error) {
        this.log('debug', `[PublicGateway] Blind peer fallback fetch failed (${reason}): ${error?.message || error}`);
        return false;
      }
    })();

    this.blindPeerFallbackState.inflight = attempt;
    try {
      return await attempt;
    } finally {
      if (this.blindPeerFallbackState.inflight === attempt) {
        this.blindPeerFallbackState.inflight = null;
      }
    }
  }

  getPeersWithPfpDrive() {
    return this.activePeers
      .filter(peer => !!peer.pfpDriveKey)
      .map(peer => ({
        publicKey: peer.publicKey,
        pfpDriveKey: peer.pfpDriveKey,
        nostrPubkeyHex: peer.nostrPubkeyHex || null
      }));
  }
}

export default GatewayService;
