import { EventEmitter } from 'node:events';
import Hyperswarm from 'hyperswarm';
import { SimplePool } from 'nostr-tools/pool';

import {
  DISCOVERY_TOPIC,
  decodeAnnouncement,
  isAnnouncementExpired,
  verifyAnnouncementSignature,
  computeSecretHash
} from '@hyperpipe/bridge/public-gateway/GatewayDiscovery';
import {
  GATEWAY_ANNOUNCEMENT_KIND,
  GATEWAY_ANNOUNCEMENT_TAG,
  DEFAULT_GATEWAY_DISCOVERY_RELAYS,
  normalizeNostrRelayList,
  parseGatewayAnnouncementEvent
} from '@hyperpipe/bridge/public-gateway/GatewayDiscoveryNostr';

function normalizeUrl(value) {
  if (!value) return '';
  try {
    const url = new URL(value);
    url.hash = '';
    return url.toString().replace(/\/$/, '');
  } catch (_) {
    return value.trim();
  }
}

class PublicGatewayDiscoveryClient extends EventEmitter {
  constructor({
    logger,
    fetchImpl = globalThis.fetch?.bind(globalThis),
    clock = () => Date.now(),
    nostrEnabled = true,
    nostrRelayUrls = DEFAULT_GATEWAY_DISCOVERY_RELAYS
  } = {}) {
    super();
    if (typeof fetchImpl !== 'function') {
      throw new Error('PublicGatewayDiscoveryClient requires a fetch implementation');
    }
    this.logger = logger || console;
    this.fetch = fetchImpl;
    this.clock = clock;
    this.swarm = null;
    this.discovery = null;
    this.nostrPool = null;
    this.nostrSubscription = null;
    this.cleanupTimer = null;
    this.gateways = new Map();
    this.nostrEnabled = nostrEnabled !== false;
    this.nostrRelayUrls = normalizeNostrRelayList(nostrRelayUrls);
  }

  #positiveNumber(value) {
    const num = Number(value);
    if (!Number.isFinite(num) || num <= 0) return null;
    return num;
  }

  #sanitizeDispatcherPolicy(existing = null, announcement = {}) {
    const policy = { ...(existing || {}) };
    const assignIfPositive = (key, value) => {
      const num = this.#positiveNumber(value);
      if (num !== null) policy[key] = num;
      else delete policy[key];
    };

    assignIfPositive('maxConcurrentJobsPerPeer', announcement.dispatcherMaxConcurrent);
    assignIfPositive('inFlightWeight', announcement.dispatcherInFlightWeight);
    assignIfPositive('latencyWeight', announcement.dispatcherLatencyWeight);
    assignIfPositive('failureWeight', announcement.dispatcherFailureWeight);
    assignIfPositive('reassignOnLagBlocks', announcement.dispatcherReassignLagBlocks);
    assignIfPositive('circuitBreakerThreshold', announcement.dispatcherCircuitBreakerThreshold);
    assignIfPositive('circuitBreakerDurationMs', announcement.dispatcherCircuitBreakerTimeoutMs);

    return Object.keys(policy).length ? policy : null;
  }

  async start() {
    if (!this.swarm) {
      this.swarm = new Hyperswarm();
      this.swarm.on('connection', (socket) => {
        this.#handleConnection(socket).catch((error) => {
          this.logger?.warn?.('[PublicGatewayDiscovery] Connection handling failed', {
            error: error?.message || error
          });
        });
      });
      this.swarm.on('error', (error) => {
        this.logger?.warn?.('[PublicGatewayDiscovery] Hyperswarm error', {
          error: error?.message || error
        });
      });
      this.discovery = this.swarm.join(DISCOVERY_TOPIC, { server: false, client: true });
      await this.discovery.flushed();
    }

    await this.#startNostrSubscription();

    this.cleanupTimer = setInterval(() => {
      this.#cleanupExpired();
    }, 30_000).unref();
    this.logger?.info?.('[PublicGatewayDiscovery] Discovery client started', {
      hyperswarm: true,
      nostrEnabled: this.nostrEnabled,
      nostrRelays: this.nostrRelayUrls
    });
  }

  async stop() {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    if (this.discovery) {
      try {
        await this.discovery.destroy?.();
      } catch (error) {
        this.logger?.debug?.('[PublicGatewayDiscovery] Failed to destroy discovery handle', {
          error: error?.message || error
        });
      }
      this.discovery = null;
    }

    if (this.nostrSubscription?.close) {
      try {
        this.nostrSubscription.close();
      } catch (error) {
        this.logger?.debug?.('[PublicGatewayDiscovery] Failed to close nostr subscription', {
          error: error?.message || error
        });
      }
      this.nostrSubscription = null;
    }

    if (this.nostrPool?.destroy) {
      try {
        this.nostrPool.destroy();
      } catch (error) {
        this.logger?.debug?.('[PublicGatewayDiscovery] Failed to destroy nostr pool', {
          error: error?.message || error
        });
      }
      this.nostrPool = null;
    }

    if (this.swarm) {
      try {
        await this.swarm.destroy();
      } catch (error) {
        this.logger?.debug?.('[PublicGatewayDiscovery] Failed to destroy hyperswarm instance', {
          error: error?.message || error
        });
      }
      this.swarm = null;
    }
    this.gateways.clear();
  }

  getGateways({ includeExpired = false } = {}) {
    const now = this.clock();
    const entries = [];
    for (const gateway of this.gateways.values()) {
      if (!includeExpired && this.#isExpired(gateway, now)) continue;
      entries.push(this.#formatGateway(gateway));
    }
    entries.sort((a, b) => (b.lastSeenAt || 0) - (a.lastSeenAt || 0));
    return entries;
  }

  getGatewayById(gatewayId) {
    if (!gatewayId) return null;
    const entry = this.gateways.get(String(gatewayId).trim().toLowerCase());
    if (!entry) return null;
    if (this.#isExpired(entry, this.clock())) return null;
    return this.#formatGateway(entry);
  }

  findGatewayByUrl(url) {
    const normalized = normalizeUrl(url);
    if (!normalized) return null;
    const now = this.clock();
    for (const entry of this.gateways.values()) {
      if (entry.normalizedPublicUrl === normalized && !this.#isExpired(entry, now)) {
        return this.#formatGateway(entry);
      }
    }
    return null;
  }

  async ensureSecret(gatewayId) {
    const entry = this.gateways.get(gatewayId);
    if (!entry) throw new Error('Gateway not found');
    if (this.#isExpired(entry, this.clock())) throw new Error('Gateway announcement expired');
    await this.#ensureSecretFetched(entry);
    if (!entry.sharedSecret) throw new Error(entry.secretFetchError || 'Shared secret unavailable');
    return this.#formatGateway(entry);
  }

  async #handleConnection(socket) {
    const chunks = [];
    socket.on('data', (chunk) => {
      chunks.push(chunk);
    });
    await new Promise((resolve) => {
      socket.once('end', resolve);
      socket.once('close', resolve);
      socket.once('error', resolve);
    });
    if (!chunks.length) return;
    const buffer = Buffer.concat(chunks);
    this.#processAnnouncement(buffer).catch((error) => {
      this.logger?.warn?.('[PublicGatewayDiscovery] Failed to process announcement', {
        error: error?.message || error
      });
    });
  }

  async #processAnnouncement(buffer) {
    let announcement;
    try {
      announcement = decodeAnnouncement(buffer);
    } catch (error) {
      this.logger?.debug?.('[PublicGatewayDiscovery] Announcement decode failed', {
        error: error?.message || error
      });
      return;
    }

    if (!announcement?.gatewayId) {
      this.logger?.debug?.('[PublicGatewayDiscovery] Announcement missing gatewayId');
      return;
    }

    if (!verifyAnnouncementSignature(announcement)) {
      this.logger?.warn?.('[PublicGatewayDiscovery] Invalid announcement signature', {
        gatewayId: announcement.gatewayId,
        signatureKey: announcement.signatureKey
      });
      return;
    }

    const now = this.clock();
    if (isAnnouncementExpired(announcement, now)) {
      this.logger?.debug?.('[PublicGatewayDiscovery] Announcement already expired', {
        gatewayId: announcement.gatewayId
      });
      return;
    }

    const ttlMs = Math.max(5_000, (announcement.ttl || 60) * 1000);
    const sourceData = {
      source: 'hyperswarm',
      gatewayId: String(announcement.gatewayId).toLowerCase(),
      publicUrl: announcement.publicUrl || '',
      wsUrl: announcement.wsUrl || '',
      secretUrl: announcement.secretUrl || '',
      displayName: announcement.displayName || '',
      region: announcement.region || '',
      sharedSecretVersion: announcement.sharedSecretVersion || '',
      signatureKey: announcement.signatureKey || '',
      ttl: announcement.ttl || 60,
      secretHash: announcement.secretHash || '',
      lastSeenAt: now,
      timestamp: Number(announcement.timestamp) || now,
      expiresAt: Number(announcement.timestamp) + ttlMs,
      openAccess: announcement.openAccess === true,
      authMethod: announcement.authMethod || '',
      hostPolicy: announcement.hostPolicy || '',
      memberDelegationMode: announcement.memberDelegationMode || '',
      operatorPubkey: announcement.operatorPubkey || '',
      wotRootPubkey: announcement.wotRootPubkey || '',
      wotMaxDepth: this.#positiveNumber(announcement.wotMaxDepth) || null,
      wotMinFollowersDepth2: Number.isFinite(Number(announcement.wotMinFollowersDepth2))
        ? Math.max(0, Math.trunc(Number(announcement.wotMinFollowersDepth2)))
        : 0,
      capabilities: Array.isArray(announcement.capabilities) ? announcement.capabilities : [],
      relayHyperbeeKey: announcement.relayKey || '',
      relayDiscoveryKey: announcement.relayDiscoveryKey || '',
      relayReplicationTopic: announcement.relayReplicationTopic || '',
      defaultTokenTtl: this.#positiveNumber(announcement.relayTokenTtl) || null,
      tokenRefreshWindowSeconds: this.#positiveNumber(announcement.relayTokenRefreshWindow) || null,
      dispatcherPolicy: this.#sanitizeDispatcherPolicy(null, announcement)
    };

    const entry = this.#upsertGatewaySource(sourceData, 'hyperswarm');
    this.#maybeFetchSecret(entry, sourceData);
  }

  async #startNostrSubscription() {
    if (!this.nostrEnabled || !this.nostrRelayUrls.length) {
      return;
    }
    if (!this.nostrPool) {
      this.nostrPool = new SimplePool({ enablePing: true, enableReconnect: true });
    }
    if (this.nostrSubscription?.close) {
      return;
    }
    const since = Math.floor(this.clock() / 1000) - 3600;
    this.nostrSubscription = this.nostrPool.subscribeMany(
      this.nostrRelayUrls,
      {
        kinds: [GATEWAY_ANNOUNCEMENT_KIND],
        '#t': [GATEWAY_ANNOUNCEMENT_TAG],
        since,
        limit: 500
      },
      {
        onevent: (event) => {
          this.#processNostrAnnouncementEvent(event).catch((error) => {
            this.logger?.warn?.('[PublicGatewayDiscovery] Failed to process nostr announcement', {
              error: error?.message || error
            });
          });
        },
        onclose: (reason) => {
          this.logger?.debug?.('[PublicGatewayDiscovery] Nostr subscription closed', {
            reason: reason || null
          });
        }
      }
    );
  }

  async #processNostrAnnouncementEvent(event) {
    const now = this.clock();
    const parsed = parseGatewayAnnouncementEvent(event, { now });
    if (!parsed) return;

    const sourceData = {
      source: 'nostr',
      gatewayId: String(parsed.gatewayId).toLowerCase(),
      publicUrl: parsed.publicUrl || '',
      wsUrl: parsed.wsUrl || '',
      secretUrl: parsed.secretUrl || '',
      displayName: parsed.displayName || '',
      region: parsed.region || '',
      sharedSecretVersion: parsed.sharedSecretVersion || '',
      signatureKey: parsed.eventPubkey || '',
      ttl: parsed.ttl || 60,
      secretHash: parsed.secretHash || '',
      lastSeenAt: parsed.lastSeenAt || now,
      timestamp: parsed.timestamp || now,
      expiresAt: parsed.expiresAt || (now + Math.max(5_000, (parsed.ttl || 60) * 1000)),
      openAccess: parsed.openAccess !== false,
      authMethod: parsed.authMethod || '',
      hostPolicy: parsed.hostPolicy || '',
      memberDelegationMode: parsed.memberDelegationMode || '',
      operatorPubkey: parsed.operatorPubkey || '',
      wotRootPubkey: parsed.wotRootPubkey || '',
      wotMaxDepth: this.#positiveNumber(parsed.wotMaxDepth) || null,
      wotMinFollowersDepth2: Number.isFinite(Number(parsed.wotMinFollowersDepth2))
        ? Math.max(0, Math.trunc(Number(parsed.wotMinFollowersDepth2)))
        : 0,
      capabilities: Array.isArray(parsed.capabilities) ? parsed.capabilities : [],
      relayHyperbeeKey: parsed.relayHyperbeeKey || '',
      relayDiscoveryKey: parsed.relayDiscoveryKey || '',
      relayReplicationTopic: parsed.relayReplicationTopic || '',
      defaultTokenTtl: this.#positiveNumber(parsed.defaultTokenTtl) || null,
      tokenRefreshWindowSeconds: this.#positiveNumber(parsed.tokenRefreshWindowSeconds) || null,
      dispatcherPolicy: this.#sanitizeDispatcherPolicy(null, parsed)
    };

    const entry = this.#upsertGatewaySource(sourceData, 'nostr');
    this.#maybeFetchSecret(entry, sourceData);
  }

  #upsertGatewaySource(sourceData, source) {
    const gatewayId = String(sourceData.gatewayId || '').trim().toLowerCase();
    if (!gatewayId) return null;

    const existing = this.gateways.get(gatewayId) || {
      gatewayId,
      sharedSecret: null,
      secretFetchedAt: 0,
      secretFetchError: null,
      secretHashVerified: false,
      fetchPromise: null,
      sources: {
        hyperswarm: null,
        nostr: null
      },
      activeSource: null
    };

    existing.sources = existing.sources || { hyperswarm: null, nostr: null };
    existing.sources[source] = { ...sourceData };
    this.#refreshGatewayEntry(existing);
    this.gateways.set(gatewayId, existing);
    this.emit('updated', this.getGateways());
    return existing;
  }

  #refreshGatewayEntry(entry) {
    const now = this.clock();
    const selected = this.#selectActiveSource(entry, now, { includeExpired: true });
    const active = selected?.data || null;
    const previousSecretHash = entry.secretHash || null;

    entry.activeSource = selected?.source || null;
    if (!active) {
      entry.normalizedPublicUrl = '';
      return;
    }

    entry.publicUrl = active.publicUrl || '';
    entry.normalizedPublicUrl = normalizeUrl(active.publicUrl || '');
    entry.wsUrl = active.wsUrl || '';
    entry.secretUrl = active.secretUrl || '';
    entry.displayName = active.displayName || '';
    entry.region = active.region || '';
    entry.sharedSecretVersion = active.sharedSecretVersion || '';
    entry.signatureKey = active.signatureKey || '';
    entry.ttl = active.ttl || 60;
    entry.secretHash = active.secretHash || '';
    entry.lastSeenAt = active.lastSeenAt || now;
    entry.expiresAt = active.expiresAt || null;
    entry.openAccess = active.openAccess !== false;
    entry.authMethod = active.authMethod || '';
    entry.hostPolicy = active.hostPolicy || '';
    entry.memberDelegationMode = active.memberDelegationMode || '';
    entry.operatorPubkey = active.operatorPubkey || '';
    entry.wotRootPubkey = active.wotRootPubkey || '';
    entry.wotMaxDepth = active.wotMaxDepth || null;
    entry.wotMinFollowersDepth2 = active.wotMinFollowersDepth2 ?? 0;
    entry.capabilities = Array.isArray(active.capabilities) ? [...active.capabilities] : [];
    entry.relayHyperbeeKey = active.relayHyperbeeKey || '';
    entry.relayDiscoveryKey = active.relayDiscoveryKey || '';
    entry.relayReplicationTopic = active.relayReplicationTopic || '';
    entry.defaultTokenTtl = active.defaultTokenTtl || null;
    entry.tokenRefreshWindowSeconds = active.tokenRefreshWindowSeconds || null;
    entry.dispatcherPolicy = active.dispatcherPolicy || null;

    if (previousSecretHash !== null && previousSecretHash !== entry.secretHash) {
      entry.sharedSecret = null;
      entry.secretFetchedAt = 0;
      entry.secretFetchError = null;
      entry.secretHashVerified = false;
    }
  }

  #selectActiveSource(entry, now = this.clock(), { includeExpired = false } = {}) {
    const sources = entry.sources || {};
    const nostr = sources.nostr || null;
    const hyperswarm = sources.hyperswarm || null;

    const nostrFresh = nostr && !this.#isSourceExpired(nostr, now);
    if (nostrFresh) {
      return { source: 'nostr', data: nostr };
    }

    const hyperswarmFresh = hyperswarm && !this.#isSourceExpired(hyperswarm, now);
    if (hyperswarmFresh) {
      return { source: 'hyperswarm', data: hyperswarm };
    }

    if (!includeExpired) return null;
    const candidates = [];
    if (nostr) candidates.push({ source: 'nostr', data: nostr });
    if (hyperswarm) candidates.push({ source: 'hyperswarm', data: hyperswarm });
    if (!candidates.length) return null;
    candidates.sort((left, right) => {
      const leftSeen = Number(left.data?.lastSeenAt || 0);
      const rightSeen = Number(right.data?.lastSeenAt || 0);
      if (leftSeen !== rightSeen) return rightSeen - leftSeen;
      if (left.source === right.source) return 0;
      return left.source === 'nostr' ? -1 : 1;
    });
    return candidates[0];
  }

  #maybeFetchSecret(entry, sourceData) {
    if (!entry || !sourceData) return;
    const hasSecret = !!entry.sharedSecret;
    const sourceHasSecret = !!sourceData.secretUrl && !!sourceData.secretHash;
    if (!sourceHasSecret) return;
    if (hasSecret && entry.secretHashVerified && entry.secretHash === sourceData.secretHash) {
      return;
    }
    this.#ensureSecretFetched(entry).catch((error) => {
      this.logger?.warn?.('[PublicGatewayDiscovery] Secret fetch failed', {
        gatewayId: entry.gatewayId,
        url: entry.secretUrl,
        error: error?.message || error
      });
    });
  }

  async #ensureSecretFetched(entry) {
    if (!entry.secretUrl) return;
    if (entry.fetchPromise) {
      await entry.fetchPromise;
      return;
    }

    if (entry.sharedSecret && entry.secretHashVerified) {
      const maxAge = Math.max(30_000, entry.ttl * 1000);
      if (entry.secretFetchedAt && (this.clock() - entry.secretFetchedAt) < maxAge) {
        return;
      }
    }

    entry.fetchPromise = (async () => {
      try {
        const response = await this.fetch(entry.secretUrl, {
          method: 'GET',
          headers: { accept: 'application/json' }
        });
        if (!response.ok) {
          throw new Error(`Secret fetch failed with status ${response.status}`);
        }
        const payload = await response.json();
        const sharedSecret = typeof payload?.sharedSecret === 'string' ? payload.sharedSecret.trim() : '';
        if (!sharedSecret) {
          throw new Error('Secret payload missing sharedSecret');
        }
        const hash = computeSecretHash(sharedSecret);
        if (entry.secretHash && hash !== entry.secretHash) {
          throw new Error('Secret hash mismatch');
        }
        entry.sharedSecret = sharedSecret;
        entry.secretHashVerified = hash === entry.secretHash;
        entry.secretFetchedAt = this.clock();
        entry.secretFetchError = null;
        if (typeof payload?.version === 'string' && payload.version) {
          entry.sharedSecretVersion = payload.version;
        }
        if (typeof payload?.wsUrl === 'string' && payload.wsUrl) {
          entry.wsUrl = payload.wsUrl;
        }
      } catch (error) {
        entry.sharedSecret = null;
        entry.secretFetchedAt = this.clock();
        entry.secretFetchError = error?.message || String(error);
        entry.secretHashVerified = false;
        throw error;
      } finally {
        entry.fetchPromise = null;
        this.emit('updated', this.getGateways());
      }
    })();

    await entry.fetchPromise;
  }

  #cleanupExpired() {
    const now = this.clock();
    let removed = false;
    for (const [gatewayId, entry] of this.gateways.entries()) {
      const sources = entry.sources || {};
      const pruneSource = (name) => {
        const current = sources[name];
        if (!current || !current.expiresAt) return;
        const graceMs = Math.max(30_000, (current.ttl || 60) * 1000);
        if (now - current.expiresAt > graceMs) {
          sources[name] = null;
          removed = true;
        }
      };

      pruneSource('nostr');
      pruneSource('hyperswarm');

      if (!sources.nostr && !sources.hyperswarm) {
        this.gateways.delete(gatewayId);
        removed = true;
        continue;
      }

      const previousSource = entry.activeSource;
      this.#refreshGatewayEntry(entry);
      if (previousSource !== entry.activeSource) {
        removed = true;
      }
    }
    if (removed) {
      this.emit('updated', this.getGateways());
    }
  }

  #isSourceExpired(sourceData, now = this.clock()) {
    return !!sourceData?.expiresAt && sourceData.expiresAt <= now;
  }

  #isExpired(entry, now = this.clock()) {
    const selected = this.#selectActiveSource(entry, now);
    if (!selected?.data) return true;
    return this.#isSourceExpired(selected.data, now);
  }

  #formatGateway(entry) {
    const now = this.clock();
    const expired = this.#isExpired(entry, now);
    return {
      gatewayId: entry.gatewayId,
      publicUrl: entry.publicUrl,
      wsUrl: entry.wsUrl,
      secretUrl: entry.secretUrl,
      displayName: entry.displayName || null,
      region: entry.region || null,
      sharedSecretVersion: entry.sharedSecretVersion || null,
      secretHash: entry.secretHash || null,
      sharedSecret: entry.sharedSecret || null,
      secretHashVerified: !!entry.secretHashVerified,
      secretFetchedAt: entry.secretFetchedAt || null,
      secretFetchError: entry.secretFetchError || null,
      lastSeenAt: entry.lastSeenAt || null,
      expiresAt: entry.expiresAt || null,
      ttl: entry.ttl || 60,
      signatureKey: entry.signatureKey || null,
      openAccess: entry.openAccess === true,
      authMethod: entry.authMethod || null,
      hostPolicy: entry.hostPolicy || null,
      memberDelegationMode: entry.memberDelegationMode || null,
      operatorPubkey: entry.operatorPubkey || null,
      wotRootPubkey: entry.wotRootPubkey || null,
      wotMaxDepth: entry.wotMaxDepth || null,
      wotMinFollowersDepth2: entry.wotMinFollowersDepth2 ?? 0,
      capabilities: Array.isArray(entry.capabilities) ? [...entry.capabilities] : [],
      relayHyperbeeKey: entry.relayHyperbeeKey || null,
      relayDiscoveryKey: entry.relayDiscoveryKey || null,
      relayReplicationTopic: entry.relayReplicationTopic || null,
      defaultTokenTtl: entry.defaultTokenTtl || null,
      tokenRefreshWindowSeconds: entry.tokenRefreshWindowSeconds || null,
      dispatcherPolicy: entry.dispatcherPolicy ? { ...entry.dispatcherPolicy } : null,
      source: entry.activeSource || null,
      isExpired: expired
    };
  }
}

export default PublicGatewayDiscoveryClient;
