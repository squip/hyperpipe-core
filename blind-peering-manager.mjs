import { Buffer } from 'node:buffer';
import { EventEmitter } from 'node:events';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import Hyperswarm from 'hyperswarm';
import BlindPeering from 'blind-peering';
import HypercoreId from 'hypercore-id-encoding';

function sanitizeKey(value) {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    HypercoreId.decode(trimmed);
    return trimmed;
  } catch (_) {
    return null;
  }
}

function normalizeCoreKey(value) {
  if (!value) return null;
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
  if (Buffer.isBuffer(value)) {
    try {
      return HypercoreId.encode(value);
    } catch (_) {
      return null;
    }
  }
  if (value instanceof Uint8Array) {
    return normalizeCoreKey(Buffer.from(value));
  }
  if (value && typeof value === 'object') {
    if (value.key) return normalizeCoreKey(value.key);
    if (value.core) return normalizeCoreKey(value.core);
  }
  return null;
}

function decodeCoreKey(value) {
  if (!value) return null;
  const candidate = typeof value === 'string' ? value.trim() : value;
  if (!candidate) return null;
  if (typeof candidate === 'string') {
    try {
      return HypercoreId.decode(candidate);
    } catch (_) {
      if (/^[0-9a-fA-F]{64}$/.test(candidate)) {
        return Buffer.from(candidate, 'hex');
      }
      return null;
    }
  }
  if (Buffer.isBuffer(candidate)) {
    return Buffer.from(candidate);
  }
  if (candidate instanceof Uint8Array) {
    return Buffer.from(candidate);
  }
  return null;
}

let corestoreCounter = 0;

function ensureCorestoreId(store) {
  if (!store) return null;
  if (!store.__ht_id) {
    corestoreCounter += 1;
    store.__ht_id = `corestore-${corestoreCounter}`;
  }
  return store.__ht_id;
}

function describeCorestore(store) {
  if (!store) return { corestoreId: null, storagePath: null };
  return {
    corestoreId: ensureCorestoreId(store),
    storagePath: store.__ht_storage_path || null
  };
}

function previewValue(value, length = 16) {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  if (!text) return null;
  return text.length > length ? text.slice(0, length) : text;
}

export default class BlindPeeringManager extends EventEmitter {
  constructor({ logger, settingsProvider, onLocalIdentityAvailable } = {}) {
    super();
    this.logger = logger || console;
    this.settingsProvider = typeof settingsProvider === 'function' ? settingsProvider : () => null;
    this.onLocalIdentityAvailable = typeof onLocalIdentityAvailable === 'function'
      ? onLocalIdentityAvailable
      : null;

    this.runtime = {
      corestore: null,
      wakeup: null,
      swarmKeyPair: null
    };

    this.enabled = false;
    this.started = false;
    this.lastAnnouncedBlindPeerPublicKey = null;
    this.handshakeMirrors = new Set();
    this.manualMirrors = new Set();
    this.trustedMirrors = new Set();
    this.mirrorTargets = new Map();
    this.blindPeering = null;
    this.swarm = null;
    this.ownsSwarm = false;

    this.metadataPath = null;
    this.metadata = {
      targets: {}
    };
    this.metadataLoaded = false;
    this.metadataDirty = false;
    this.metadataSaveTimer = null;
    this.ownerPeerKey = null;
    this.mirrorCoreCache = new Map();
    this.joinTracking = new Map();
    this.coreTransferMonitors = new Map();

    this.backoffConfig = {
      initialDelayMs: 1000,
      maxDelayMs: 60000,
      maxAttempts: 6
    };
    this.refreshBackoff = {
      attempt: 0,
      timer: null,
      inflight: null,
      nextDelayMs: null,
      nextReason: null,
      nextScheduledAt: null
    };
    this.rehydrationState = {
      inflight: null,
      lastResult: null,
      lastCompletedAt: null
    };
    this.localIdentityMonitorTimer = null;
    this.blindPeerDiagnosticsInstalled = false;
    this.instrumentedBlindPeerClients = new WeakSet();
    this.instrumentedBlindPeerStreams = new WeakSet();
  }

  configure(settings) {
    const nextSettings = settings || this.settingsProvider();
    if (!nextSettings) {
      this.enabled = false;
      this.trustedMirrors.clear();
      return;
    }

    this.enabled = !!nextSettings.blindPeerEnabled;
    const handshakeKeys = Array.isArray(nextSettings.blindPeerKeys)
      ? nextSettings.blindPeerKeys
      : [];
    const manualKeys = Array.isArray(nextSettings.blindPeerManualKeys)
      ? nextSettings.blindPeerManualKeys
      : [];
    const sanitizedHandshake = handshakeKeys.map(sanitizeKey).filter(Boolean);
    const sanitizedManual = manualKeys.map(sanitizeKey).filter(Boolean);
    this.handshakeMirrors = new Set(sanitizedHandshake);
    this.manualMirrors = new Set(sanitizedManual);
    this.trustedMirrors = new Set([...this.handshakeMirrors, ...this.manualMirrors]);

    this.logger?.debug?.('[BlindPeering] Configuration updated', {
      enabled: this.enabled,
      handshakeKeys: this.handshakeMirrors.size,
      manualKeys: this.manualMirrors.size,
      keys: this.trustedMirrors.size
    });

    if (this.blindPeering?.setKeys) {
      this.blindPeering.setKeys(Array.from(this.trustedMirrors));
    }
  }

  async start(runtime = {}) {
    this.configure();
    if (!this.enabled) {
      this.logger?.debug?.('[BlindPeering] Start skipped (disabled)');
      return false;
    }

    this.runtime = {
      corestore: runtime.corestore || this.runtime.corestore,
      wakeup: runtime.wakeup || this.runtime.wakeup,
      swarmKeyPair: runtime.swarmKeyPair || this.runtime.swarmKeyPair || null
    };
    this.ownerPeerKey = null;

    if (!this.runtime.corestore) {
      throw new Error('[BlindPeering] Corestore instance is required to start blind peering manager');
    }

    if (!this.swarm) {
      if (runtime.swarm && typeof runtime.swarm === 'object') {
        this.swarm = runtime.swarm;
        this.ownsSwarm = false;
      } else {
        const swarmOptions = {};
        if (this.runtime.swarmKeyPair?.publicKey && this.runtime.swarmKeyPair?.secretKey) {
          swarmOptions.keyPair = this.runtime.swarmKeyPair;
        }
        this.swarm = new Hyperswarm(swarmOptions);
        this.ownsSwarm = true;
      }
    }

    this.blindPeering = new BlindPeering(this.swarm, this.runtime.corestore, {
      mirrors: Array.from(this.trustedMirrors),
      pick: 2
    });
    this.#installBlindPeerDiagnostics();

    await this.#loadMetadata();

    this.started = true;
    this.lastAnnouncedBlindPeerPublicKey = null;
    this.#startLocalIdentityMonitor();
    const blindPeerKeyBuffer = this.swarm?.dht?.defaultKeyPair?.publicKey || null;
    const blindPeerKey = this.getLocalBlindPeerPublicKey();
    const blindPeerKeyHex = blindPeerKeyBuffer ? Buffer.from(blindPeerKeyBuffer).toString('hex') : null;
    const swarmPublicKeyHex = this.runtime?.swarmKeyPair?.publicKey
      ? Buffer.from(this.runtime.swarmKeyPair.publicKey).toString('hex')
      : null;
    this.logger?.info?.('[BlindPeering] Manager started', {
      mirrors: this.trustedMirrors.size,
      blindPeerKey,
      blindPeerKeyHex,
      swarmPublicKeyHex
    });
    this.logTransportSnapshot('manager-started', {
      blindPeerKey: previewValue(blindPeerKey, 16),
      swarmPublicKeyHex: previewValue(swarmPublicKeyHex, 16)
    });
    this.emit('started', this.getStatus());
    return true;
  }

  async stop() {
    if (!this.started) return;
    this.started = false;
    this.lastAnnouncedBlindPeerPublicKey = null;
    if (this.localIdentityMonitorTimer) {
      clearInterval(this.localIdentityMonitorTimer);
      this.localIdentityMonitorTimer = null;
    }
    try {
      await this.blindPeering?.close?.();
    } catch (error) {
      this.logger?.warn?.('[BlindPeering] Failed to close blind-peering instance', { error: error?.message || error });
    }
    this.blindPeering = null;

    if (this.ownsSwarm && this.swarm) {
      try {
        await this.swarm.destroy();
      } catch (error) {
        this.logger?.warn?.('[BlindPeering] Failed to destroy hyperswarm', { error: error?.message || error });
      }
    }
    this.swarm = null;
    this.ownsSwarm = false;
    if (this.metadataSaveTimer) {
      clearTimeout(this.metadataSaveTimer);
      this.metadataSaveTimer = null;
    }
    for (const key of Array.from(this.coreTransferMonitors.keys())) {
      this.#stopCoreTransferMonitor(key, { reason: 'manager-stop' });
    }
    this.joinTracking.clear();
    await this.#persistMetadata(true);
    this.logger?.info?.('[BlindPeering] Manager stopped');
    this.emit('stopped', this.getStatus());
  }

  markTrustedMirrors(peerKeys = []) {
    let updated = false;
    const added = [];
    for (const key of peerKeys) {
      const sanitized = sanitizeKey(key);
      if (!sanitized) continue;
      if (!this.handshakeMirrors.has(sanitized)) {
        this.handshakeMirrors.add(sanitized);
      }
      if (!this.trustedMirrors.has(sanitized)) {
        this.trustedMirrors.add(sanitized);
        added.push(sanitized);
        updated = true;
      }
    }
    if (updated) {
      this.logger?.debug?.('[BlindPeering] Trusted mirrors updated', {
        count: this.trustedMirrors.size,
        added: added.map((key) => previewValue(key, 16))
      });
      if (this.blindPeering?.setKeys) {
        this.blindPeering.setKeys(Array.from(this.trustedMirrors));
      }
      this.logTransportSnapshot('trusted-mirrors-updated', {
        added: added.length,
        addedPreview: added.slice(0, 3).map((key) => previewValue(key, 16))
      });
      this.emit('trusted-peers-changed', Array.from(this.trustedMirrors));
    }
  }

  markJoinStart({ relayKey = null, publicIdentifier = null, reason = 'join-flow' } = {}) {
    const identifier = sanitizeKey(relayKey || publicIdentifier);
    if (!identifier) return false;
    const now = Date.now();
    const existing = this.joinTracking.get(identifier) || null;
    const attempts = existing ? (existing.attempts || 0) + 1 : 1;
    this.joinTracking.set(identifier, {
      relayKey: identifier,
      publicIdentifier: publicIdentifier || null,
      reason,
      attempts,
      startedAt: existing?.startedAt || now,
      updatedAt: now
    });
    this.logger?.info?.('[BlindPeering] Join tracking start', {
      relayKey: identifier,
      publicIdentifier: publicIdentifier || null,
      reason,
      attempts
    });
    return true;
  }

  markJoinEnd({ relayKey = null, publicIdentifier = null, reason = 'join-flow', status = 'ok' } = {}) {
    const identifier = sanitizeKey(relayKey || publicIdentifier);
    if (!identifier) return false;
    const existing = this.joinTracking.get(identifier) || null;
    this.joinTracking.delete(identifier);
    const elapsedMs = existing?.startedAt ? Math.max(0, Date.now() - existing.startedAt) : null;
    this.logger?.info?.('[BlindPeering] Join tracking end', {
      relayKey: identifier,
      publicIdentifier: existing?.publicIdentifier || publicIdentifier || null,
      reason,
      status,
      elapsedMs
    });
    return true;
  }

  ensureRelayMirror(relayContext = {}) {
    if (!this.started) return;
    if (!this.blindPeering) return;

    const autobase = relayContext.autobase || null;
    const relayCorestore = relayContext.corestore || null;
    let autobaseTarget = null;
    if (autobase) {
      autobaseTarget = this.#resolveAutobaseTarget(relayContext);
      if (!autobaseTarget) {
        this.logger?.warn?.('[BlindPeering] Skipping autobase mirroring (no wakeup target)', {
          identifier: relayContext.relayKey || relayContext.publicIdentifier || null
        });
      } else {
        try {
          this.blindPeering.addAutobaseBackground(autobase, autobaseTarget, {
            pick: 2,
            all: true
          });
        } catch (error) {
          this.logger?.warn?.('[BlindPeering] Failed to mirror autobase', {
            identifier: relayContext.relayKey || relayContext.publicIdentifier || null,
            error: error?.message || error
          });
        }
      }
    }
    const identifier = sanitizeKey(relayContext.relayKey || relayContext.publicIdentifier);
    if (!identifier) return;
    const existingEntry = this.mirrorTargets.get(`relay:${identifier}`);
    const mergedContext = { ...relayContext };
    if (Array.isArray(existingEntry?.coreRefs) && existingEntry.coreRefs.length) {
      const mergedRefs = Array.from(new Set([
        ...existingEntry.coreRefs,
        ...(Array.isArray(relayContext.coreRefs) ? relayContext.coreRefs : [])
      ].map(normalizeCoreKey).filter(Boolean)));
      if (mergedRefs.length) {
        mergedContext.coreRefs = mergedRefs;
      }
    }
    const entry = {
      type: 'relay',
      identifier,
      context: { ...mergedContext },
      updatedAt: Date.now()
    };
    if (!entry.context.relayKey) {
      entry.context.relayKey = identifier;
    }
    if (!entry.context.identifier) {
      entry.context.identifier = identifier;
    }
    if (relayCorestore) {
      const storeInfo = describeCorestore(relayCorestore);
      entry.context.corestore = relayCorestore;
      entry.context.corestoreId = storeInfo.corestoreId;
      entry.context.corestorePath = storeInfo.storagePath;
      this.logger?.info?.('[BlindPeering] Relay mirror corestore override', {
        identifier,
        corestoreId: storeInfo.corestoreId,
        storagePath: storeInfo.storagePath
      });
    }
    if (autobaseTarget) {
      try {
        entry.context.autobaseTarget = HypercoreId.encode(autobaseTarget);
      } catch (_) {
        entry.context.autobaseTarget = autobaseTarget.toString('hex');
      }
    }
    const coreRefs = this.#collectRelayCoreRefs(mergedContext);
    if (coreRefs.length) {
      entry.coreRefs = coreRefs;
      entry.context.coreRefs = coreRefs;
    }
    this.#primeCoreRefsBackground(coreRefs, entry, relayCorestore);
    entry.ownerPeerKey = this.#getOwnerPeerKey();
    entry.announce = true;
    entry.priority = Number.isFinite(relayContext.priority)
      ? Math.trunc(relayContext.priority)
      : 2;
    entry.context.ownerPeerKey = entry.ownerPeerKey;
    entry.context.announce = entry.announce;
    entry.context.priority = entry.priority;
    this.mirrorTargets.set(`relay:${identifier}`, entry);
    this.#recordMirrorMetadata(entry);
    const join = this.joinTracking.get(identifier) || null;
    const now = Date.now();
    this.logger?.debug?.('[BlindPeering] Relay mirror scheduled', {
      identifier,
      writers: coreRefs.length,
      reason: entry.context?.reason || null,
      joinActive: !!join,
      joinAgeMs: join?.startedAt ? Math.max(0, now - join.startedAt) : null,
      coreRefsPreview: coreRefs.slice(0, 3)
    });
    this.emit('mirror-requested', entry);
  }

  async primeRelayCoreRefs({ relayKey = null, publicIdentifier = null, coreRefs = [], timeoutMs = 45000, reason = 'manual', corestore = null } = {}) {
    if (!this.started) {
      return { status: 'skipped', reason: 'not-started' };
    }
    if (!this.blindPeering) {
      return { status: 'skipped', reason: 'not-configured' };
    }
    const targetStore = corestore || this.runtime?.corestore;
    if (!targetStore) {
      return { status: 'skipped', reason: 'no-corestore' };
    }
    const uniqueRefs = Array.from(new Set(
      (Array.isArray(coreRefs) ? coreRefs : [])
        .map(normalizeCoreKey)
        .filter(Boolean)
    ));
    if (!uniqueRefs.length) {
      return { status: 'skipped', reason: 'no-cores' };
    }

    const labelBase = relayKey || publicIdentifier || 'unknown-relay';
    const summary = {
      status: 'ok',
      reason,
      relayKey: relayKey || null,
      total: uniqueRefs.length,
      synced: 0,
      failed: 0,
      connected: 0,
      acknowledged: 0
    };

    const storeInfo = describeCorestore(targetStore);
    summary.corestoreId = storeInfo.corestoreId;
    summary.storagePath = storeInfo.storagePath;
    this.logger?.info?.('[BlindPeering] Relay core prefetch using corestore', {
      relayKey: summary.relayKey,
      reason,
      corestoreId: storeInfo.corestoreId,
      storagePath: storeInfo.storagePath
    });
    this.logger?.debug?.('[BlindPeering] Relay core prefetch transport preflight', {
      relayKey: summary.relayKey,
      reason,
      ...this.getTransportSnapshot({ limit: 3 })
    });

    for (const ref of uniqueRefs) {
      const label = `${labelBase}:${ref.slice(0, 16)}`;
      const core = this.#getMirrorCore(ref, label, targetStore);
      if (!core) {
        summary.failed += 1;
        continue;
      }
      try {
        const result = await this.blindPeering.addCore(core, core.key, {
          announce: false,
          priority: 2,
          pick: 2
        });
        const acknowledgements = Array.isArray(result)
          ? result.filter(Boolean).length
          : (result ? 1 : 0);
        if (acknowledgements <= 0) {
          summary.failed += 1;
          this.logger?.warn?.('[BlindPeering] Relay core mirror add yielded no remote acknowledgement', {
            ref,
            label,
            reason,
            resultType: Array.isArray(result) ? 'array' : typeof result,
            resultLength: Array.isArray(result) ? result.length : null,
            ...this.getTransportSnapshot({ limit: 3 })
          });
          continue;
        }
        summary.connected += 1;
        summary.acknowledged += acknowledgements;
      } catch (error) {
        summary.failed += 1;
        this.logger?.warn?.('[BlindPeering] Relay core mirror add failed', {
          ref,
          label,
          reason,
          error: error?.message || error,
          ...this.getTransportSnapshot({ limit: 3 })
        });
        continue;
      }

      try {
        await this.#waitForCoreSync(core, timeoutMs, label);
        summary.synced += 1;
      } catch (error) {
        summary.failed += 1;
        this.logger?.warn?.('[BlindPeering] Relay core prefetch failed', {
          ref,
          label,
          reason,
          err: error?.message || error
        });
      }
    }

    if (summary.connected === 0 && uniqueRefs.length > 0) {
      this.logger?.warn?.('[BlindPeering] Relay core prefetch completed without confirmed mirror acknowledgements', {
        relayKey: summary.relayKey,
        reason,
        totalRefs: uniqueRefs.length,
        ...this.getTransportSnapshot({ limit: 5 })
      });
    }
    this.logger?.info?.('[BlindPeering] Relay core prefetch complete', summary);
    return summary;
  }

  ensureHyperdriveMirror(driveContext = {}) {
    if (!this.started) return;
    if (!this.blindPeering) return;
    const identifier = sanitizeKey(driveContext.identifier || driveContext.driveKey);
    if (!identifier) return;
    const entry = {
      type: driveContext.type || 'drive',
      identifier,
      context: { ...driveContext },
      updatedAt: Date.now()
    };
    if (!entry.context.identifier) {
      entry.context.identifier = identifier;
    }
    if (!entry.context.driveKey) {
      entry.context.driveKey = identifier;
    }
    const coreRefs = this.#collectDriveCoreRefs(driveContext);
    if (coreRefs.length) {
      entry.coreRefs = coreRefs;
      entry.context.coreRefs = coreRefs;
    }
    entry.ownerPeerKey = this.#getOwnerPeerKey();
    const defaultPriority = driveContext.type === 'pfp-drive' ? 0 : 1;
    entry.priority = Number.isFinite(driveContext.priority)
      ? Math.trunc(driveContext.priority)
      : defaultPriority;
    entry.announce = driveContext.announce ?? true;
    entry.context.ownerPeerKey = entry.ownerPeerKey;
    entry.context.priority = entry.priority;
    entry.context.announce = entry.announce;
    this.mirrorTargets.set(`drive:${identifier}`, entry);
    this.#recordMirrorMetadata(entry);
    this.logger?.debug?.('[BlindPeering] Hyperdrive mirror scheduled', {
      identifier,
      pfp: !!driveContext.isPfp
    });
    this.emit('mirror-requested', entry);

    const drive = driveContext.drive || null;
    if (!drive) return;

    try {
      if (drive.core) {
        this.blindPeering.addCoreBackground(drive.core, drive.core.key, {
          announce: true,
          priority: 1
        });
      }
      if (drive.blobs?.core) {
        this.blindPeering.addCoreBackground(drive.blobs.core, drive.blobs.core.key, {
          announce: false,
          priority: 0
        });
      }
    } catch (error) {
      this.logger?.warn?.('[BlindPeering] Failed to schedule hyperdrive cores', {
        identifier,
        error: error?.message || error
      });
    }
  }

  async removeRelayMirror(relayContext = {}, { reason = 'manual' } = {}) {
    const identifier = sanitizeKey(relayContext.relayKey || relayContext.identifier || relayContext.publicIdentifier);
    if (!identifier) return false;
    const entryKey = `relay:${identifier}`;
    const entry = this.mirrorTargets.get(entryKey);
    const context = entry?.context || relayContext || {};
    const autobase = relayContext.autobase || context.autobase || null;
    const collected = new Set();
    const addKey = (candidate) => {
      const normalized = normalizeCoreKey(candidate);
      if (normalized) collected.add(normalized);
    };
    for (const key of this.#collectRelayCoreRefs({ ...context, autobase })) {
      addKey(key);
    }
    if (Array.isArray(relayContext.coreRefs)) {
      for (const key of relayContext.coreRefs) addKey(key);
    }
    if (Array.isArray(entry?.coreRefs)) {
      for (const key of entry.coreRefs) addKey(key);
    }

    if (entry) {
      this.mirrorTargets.delete(entryKey);
    }

    this.#removeMetadataEntry(entryKey);

    let deleted = 0;
    if (this.blindPeering && collected.size) {
      const operations = [];
      for (const key of collected) {
        operations.push(
          this.#deleteCoreByKey(key).then(() => {
            deleted += 1;
          }).catch((error) => {
            this.logger?.warn?.('[BlindPeering] Failed to delete mirrored relay core', {
              key,
              reason,
              err: error?.message || error
            });
          })
        );
      }
      if (operations.length) {
        await Promise.allSettled(operations);
      }
    }

    this.logger?.debug?.('[BlindPeering] Relay mirror removed', {
      identifier,
      reason,
      mirroredCores: collected.size,
      deletedCores: deleted
    });
    this.emit('mirror-removed', {
      type: 'relay',
      identifier,
      reason,
      deleted
    });
    return true;
  }

  async removeHyperdriveMirror(driveContext = {}, { reason = 'manual' } = {}) {
    const identifier = sanitizeKey(driveContext.identifier || driveContext.driveKey);
    if (!identifier) return false;
    const entryKey = `drive:${identifier}`;
    const entry = this.mirrorTargets.get(entryKey);
    const context = entry?.context || driveContext || {};
    const collected = new Set();
    const addKey = (candidate) => {
      const normalized = normalizeCoreKey(candidate);
      if (normalized) collected.add(normalized);
    };
    for (const key of this.#collectDriveCoreRefs(context)) {
      addKey(key);
    }
    if (Array.isArray(driveContext.coreRefs)) {
      for (const key of driveContext.coreRefs) addKey(key);
    }
    if (Array.isArray(entry?.coreRefs)) {
      for (const key of entry.coreRefs) addKey(key);
    }

    if (entry) {
      this.mirrorTargets.delete(entryKey);
    }

    this.#removeMetadataEntry(entryKey);

    let deleted = 0;
    if (this.blindPeering && collected.size) {
      const operations = [];
      for (const key of collected) {
        operations.push(
          this.#deleteCoreByKey(key).then(() => {
            deleted += 1;
          }).catch((error) => {
            this.logger?.warn?.('[BlindPeering] Failed to delete mirrored drive core', {
              key,
              reason,
              err: error?.message || error
            });
          })
        );
      }
      if (operations.length) {
        await Promise.allSettled(operations);
      }
    }

    const eventType = entry?.type || driveContext.type || 'drive';
    this.logger?.debug?.('[BlindPeering] Drive mirror removed', {
      identifier,
      reason,
      type: eventType,
      mirroredCores: collected.size,
      deletedCores: deleted
    });
    this.emit('mirror-removed', {
      type: eventType,
      identifier,
      reason,
      deleted
    });
    return true;
  }

  async clearAllMirrors({ reason = 'cleanup' } = {}) {
    const entries = Array.from(this.mirrorTargets.values());
    for (const entry of entries) {
      if (entry.type === 'relay') {
        await this.removeRelayMirror(
          { ...entry.context, relayKey: entry.identifier },
          { reason }
        );
      } else {
        await this.removeHyperdriveMirror(
          { ...entry.context, identifier: entry.identifier },
          { reason }
        );
      }
    }
  }

  async rehydrateMirrors({ reason = 'manual', timeoutMs = 45000 } = {}) {
    if (!this.started) {
      return { status: 'skipped', reason: 'not-started' };
    }

    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      timeoutMs = 45000;
    }

    if (this.rehydrationState.inflight) {
      return this.rehydrationState.inflight;
    }

    const promise = (async () => {
      const targets = this.#collectAllMirrorCoreObjects();
      const summary = {
        status: 'ok',
        reason,
        total: targets.size,
        synced: 0,
        failed: 0,
        skipped: 0
      };

      for (const [key, info] of targets) {
        const label = info.label || key;
        if (label && (label === 'autobase-view' || label.startsWith('autobase-view-'))) {
          summary.skipped += 1;
          continue;
        }
        try {
          await this.#waitForCoreSync(info.core, timeoutMs, label);
          summary.synced += 1;
        } catch (error) {
          summary.failed += 1;
          this.logger?.warn?.('[BlindPeering] Mirror rehydration failed', {
            key,
            label,
            reason,
            err: error?.message || error
          });
        }
      }

      this.logger?.info?.('[BlindPeering] Rehydration cycle completed', summary);
      this.rehydrationState.lastResult = summary;
      this.rehydrationState.lastCompletedAt = Date.now();
      return summary;
    })();

    this.rehydrationState.inflight = promise;
    try {
      return await promise;
    } finally {
      if (this.rehydrationState.inflight === promise) {
        this.rehydrationState.inflight = null;
      }
    }
  }

  #resolveAutobaseTarget(relayContext = {}) {
    const tryDecode = (candidate) => {
      if (!candidate) return null;
      if (Buffer.isBuffer(candidate)) {
        return candidate.length === 32 ? Buffer.from(candidate) : null;
      }
      if (typeof candidate === 'string') {
        return decodeCoreKey(candidate);
      }
      if (candidate && typeof candidate === 'object') {
        if (candidate.key) return tryDecode(candidate.key);
        if (candidate.discoveryKey) return tryDecode(candidate.discoveryKey);
      }
      return null;
    };

    const pickFirst = (...candidates) => {
      for (const candidate of candidates) {
        const decoded = tryDecode(candidate);
        if (decoded && decoded.length === 32) return decoded;
      }
      return null;
    };

    const autobase = relayContext.autobase || null;
    const candidateTarget = pickFirst(
      relayContext.target,
      autobase?.wakeupCapability?.key,
      autobase?.local?.key,
      autobase?.local?.discoveryKey,
      autobase?.discoveryKey,
      autobase?.localWriter?.core?.key,
      autobase?.key,
      relayContext.relayKey,
      relayContext.publicIdentifier
    );

    return candidateTarget;
  }

  #collectRelayCoreRefs(relayContext = {}) {
    if (!relayContext) return [];
    const refs = new Set();
    if (Array.isArray(relayContext.coreRefs)) {
      for (const key of relayContext.coreRefs) {
        const normalized = normalizeCoreKey(key);
        if (normalized) refs.add(normalized);
      }
    }
    const autobase = relayContext.autobase || null;
    if (autobase) {
      const objects = this.#collectAutobaseCoreObjects(autobase);
      for (const key of objects.keys()) {
        refs.add(key);
      }
    }
    return Array.from(refs);
  }

  #collectDriveCoreRefs(driveContext = {}) {
    if (!driveContext) return [];
    const refs = new Set();
    if (Array.isArray(driveContext.coreRefs)) {
      for (const key of driveContext.coreRefs) {
        const normalized = normalizeCoreKey(key);
        if (normalized) refs.add(normalized);
      }
    }
    const drive = driveContext.drive || null;
    if (drive) {
      const objects = this.#collectDriveCoreObjects(drive, driveContext.type || 'drive');
      for (const key of objects.keys()) {
        refs.add(key);
      }
    }
    return Array.from(refs);
  }

  #collectAutobaseCoreObjects(autobase) {
    const map = new Map();
    if (!autobase) return map;

    const addWriterArray = (writers, labelPrefix) => {
      if (!Array.isArray(writers)) return;
      writers.forEach((writer, index) => {
        this.#addCoreObject(map, writer?.core || writer, `${labelPrefix}-${index}`);
      });
    };

    this.#addCoreObject(map, autobase.core, 'autobase-core');
    this.#addCoreObject(map, autobase.local?.core || autobase.local, 'autobase-local');
    addWriterArray(autobase.activeWriters, 'autobase-writer');
    addWriterArray(autobase.writers, 'autobase-writer');

    if (typeof autobase.views === 'function') {
      let index = 0;
      try {
        for (const view of autobase.views()) {
          this.#addCoreObject(map, view?.core || view, `autobase-view-${index++}`);
        }
      } catch (_) {
        // ignore iterator errors
      }
    } else if (autobase.view) {
      this.#addCoreObject(map, autobase.view?.core || autobase.view, 'autobase-view');
    }

    if (Array.isArray(autobase.viewCores)) {
      autobase.viewCores.forEach((core, index) => {
        this.#addCoreObject(map, core?.core || core, `autobase-view-${index}`);
      });
    }

    return map;
  }

  #collectDriveCoreObjects(drive, type = 'drive') {
    const map = new Map();
    if (!drive) return map;
    this.#addCoreObject(map, drive.core, `${type}-metadata`);
    this.#addCoreObject(map, drive.content?.core || drive.content, `${type}-content`);
    this.#addCoreObject(map, drive.blobs?.core || drive.blobs, `${type}-blobs`);
    this.#addCoreObject(map, drive.metadata?.core || drive.metadata, `${type}-meta`);
    return map;
  }

  #collectAllMirrorCoreObjects() {
    const map = new Map();
    for (const entry of this.mirrorTargets.values()) {
      if (entry.type === 'relay') {
        const autobase = entry.context?.autobase || null;
        if (autobase) {
          const objects = this.#collectAutobaseCoreObjects(autobase);
          for (const [key, info] of objects) {
            if (!map.has(key)) {
              map.set(key, info);
            }
          }
        }
        if (Array.isArray(entry.coreRefs) && entry.coreRefs.length) {
          const identifier = entry.identifier || entry.context?.relayKey || entry.context?.publicIdentifier || 'relay';
          const entryStore = entry.context?.corestore || null;
          entry.coreRefs.forEach((ref, index) => {
            const label = `relay-core:${identifier}:${index}`;
            const core = this.#getMirrorCore(ref, label, entryStore);
            if (core) {
              this.#addCoreObject(map, core, label);
            }
          });
        }
      } else if (entry.type === 'drive' || entry.type === 'pfp-drive') {
        const drive = entry.context?.drive || null;
        if (!drive) continue;
        const objects = this.#collectDriveCoreObjects(drive, entry.type);
        for (const [key, info] of objects) {
          if (!map.has(key)) {
            map.set(key, info);
          }
        }
      }
    }
    return map;
  }

  #getMirrorCore(key, label, corestoreOverride = null) {
    const store = corestoreOverride || this.runtime?.corestore;
    if (!store) return null;
    const normalized = normalizeCoreKey(key);
    if (!normalized) return null;
    const storeId = ensureCorestoreId(store);
    const cacheKey = `${storeId}:${normalized}`;
    let entry = this.mirrorCoreCache.get(cacheKey);
    if (!entry) {
      const decoded = decodeCoreKey(normalized);
      if (!decoded) return null;
      const core = store.get({ key: decoded, valueEncoding: 'binary', sparse: true });
      entry = {
        core,
        labels: new Set(),
        corestoreId: storeId,
        storagePath: store.__ht_storage_path || null
      };
      this.mirrorCoreCache.set(cacheKey, entry);
      core.on('close', () => {
        this.mirrorCoreCache.delete(cacheKey);
      });
    }
    if (label) entry.labels.add(label);
    return entry.core;
  }

  #primeCoreRefsBackground(coreRefs = [], entry = {}, corestoreOverride = null) {
    const targetStore = corestoreOverride || this.runtime?.corestore;
    if (!this.started || !this.blindPeering || !targetStore) return;
    if (!Array.isArray(coreRefs) || !coreRefs.length) return;
    const identifier = entry.identifier || entry.context?.relayKey || entry.context?.publicIdentifier || 'relay';
    const priority = Number.isFinite(entry.priority) ? entry.priority : 2;
    const storeInfo = describeCorestore(targetStore);
    const reason = entry?.context?.reason || null;
    coreRefs
      .map(normalizeCoreKey)
      .filter(Boolean)
      .forEach((ref, index) => {
        const label = `relay-core:${identifier}:${index}`;
        const core = this.#getMirrorCore(ref, label, targetStore);
        if (!core) return;
        try {
          this.blindPeering.addCoreBackground(core, core.key, {
            announce: false,
            priority,
            pick: 2
          });
          this.#trackCoreTransfer(core, {
            label,
            ref,
            identifier,
            reason,
            priority,
            source: 'prime-core-refs',
            corestoreId: storeInfo.corestoreId,
            storagePath: storeInfo.storagePath
          });
        } catch (error) {
          this.logger?.warn?.('[BlindPeering] Failed to prime relay core mirror', {
            ref,
            label,
            error: error?.message || error
          });
        }
      });
  }

  #addCoreObject(target, candidate, label) {
    if (!candidate) return;
    const core = candidate.core && typeof candidate.core.update === 'function'
      ? candidate.core
      : candidate;
    if (!core || typeof core.update !== 'function' || !core.key) return;
    const key = normalizeCoreKey(core.key);
    if (!key || target.has(key)) return;
    target.set(key, { core, label });
  }

  async #deleteCoreByKey(key) {
    if (!this.blindPeering?.deleteCore) return false;
    const decoded = decodeCoreKey(key);
    if (!decoded) {
      throw new Error(`Invalid core key provided: ${key}`);
    }
    await this.blindPeering.deleteCore(decoded);
    return true;
  }

  #removeMetadataEntry(entryKey) {
    if (!entryKey) return;
    if (Object.prototype.hasOwnProperty.call(this.metadata.targets, entryKey)) {
      delete this.metadata.targets[entryKey];
      this.metadataDirty = true;
      this.#scheduleMetadataPersist();
    }
  }

  async #waitForCoreSync(core, timeoutMs, label) {
    if (!core || typeof core.update !== 'function') return false;
    const syncStart = Date.now();
    const startState = this.#describeCoreState(core);
    this.logger?.info?.('[BlindPeering] Core sync start', {
      label,
      timeoutMs,
      state: startState
    });
    try {
      if (typeof core.ready === 'function') {
        await this.#withTimeout(core.ready(), timeoutMs, label ? `${label}:ready` : null);
      }
    } catch (error) {
      this.logger?.debug?.('[BlindPeering] Core ready wait failed', {
        label,
        err: error?.message || error
      });
    }
    let status = 'ok';
    let errorMessage = null;
    try {
      await this.#withTimeout(core.update({ wait: true }), timeoutMs, label ? `${label}:update` : null);
    } catch (error) {
      status = 'error';
      errorMessage = error?.message || String(error);
      if (errorMessage && String(errorMessage).includes('Operation timed out')) {
        this.logger?.warn?.('[BlindPeering] Core sync timeout', {
          label,
          timeoutMs,
          ...this.#describeCoreState(core),
          err: errorMessage
        });
      }
      throw error;
    } finally {
      const endState = this.#describeCoreState(core);
      const elapsedMs = Date.now() - syncStart;
      const deltaBytes = Number.isFinite(startState.byteLength) && Number.isFinite(endState.byteLength)
        ? Math.max(0, endState.byteLength - startState.byteLength)
        : null;
      const deltaDownloaded = Number.isFinite(startState.downloaded) && Number.isFinite(endState.downloaded)
        ? Math.max(0, endState.downloaded - startState.downloaded)
        : null;
      const bytesPerSec = deltaBytes !== null && elapsedMs > 0
        ? Math.round((deltaBytes / (elapsedMs / 1000)) * 100) / 100
        : null;
      const downloadedPerSec = deltaDownloaded !== null && elapsedMs > 0
        ? Math.round((deltaDownloaded / (elapsedMs / 1000)) * 100) / 100
        : null;
      this.logger?.info?.('[BlindPeering] Core sync end', {
        label,
        status,
        elapsedMs,
        bytesDelta: deltaBytes,
        bytesPerSec,
        downloadedDelta: deltaDownloaded,
        downloadedPerSec,
        error: errorMessage,
        start: startState,
        end: endState
      });
    }
    return true;
  }

  #describeCoreState(core) {
    if (!core) return { key: null };
    const state = {};
    const key = core.key || null;
    const discoveryKey = core.discoveryKey || null;
    const normalizedKey = normalizeCoreKey(key);
    const normalizedDiscovery = normalizeCoreKey(discoveryKey);
    if (normalizedKey) state.key = normalizedKey;
    if (normalizedDiscovery) state.discoveryKey = normalizedDiscovery;
    if (key) {
      try {
        const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(key);
        state.keyHex = keyBuf.toString('hex');
      } catch (_) {
        state.keyHex = null;
      }
    }
    if (discoveryKey) {
      try {
        const keyBuf = Buffer.isBuffer(discoveryKey) ? discoveryKey : Buffer.from(discoveryKey);
        state.discoveryKeyHex = keyBuf.toString('hex');
      } catch (_) {
        state.discoveryKeyHex = null;
      }
    }
    const maybeNumber = (value) => (Number.isFinite(value) ? value : null);
    state.length = maybeNumber(core.length);
    state.contiguousLength = maybeNumber(core.contiguousLength);
    state.remoteLength = maybeNumber(core.remoteLength);
    state.byteLength = maybeNumber(core.byteLength);
    state.downloaded = maybeNumber(core.downloaded);
    state.uploaded = maybeNumber(core.uploaded);
    state.fork = maybeNumber(core.fork);
    if (typeof core.opened === 'boolean') state.opened = core.opened;
    if (typeof core.closed === 'boolean') state.closed = core.closed;
    if (typeof core.writable === 'boolean') state.writable = core.writable;
    if (typeof core.readable === 'boolean') state.readable = core.readable;
    if (typeof core.peerCount === 'number') {
      state.peers = core.peerCount;
    } else if (Array.isArray(core.peers)) {
      state.peers = core.peers.length;
    } else if (core.peers && typeof core.peers.size === 'number') {
      state.peers = core.peers.size;
    } else {
      state.peers = null;
    }
    return state;
  }

  #trackCoreTransfer(core, meta = {}) {
    if (!core || typeof core.update !== 'function') return;
    const normalizedKey = normalizeCoreKey(core.key);
    if (!normalizedKey) return;
    const storeId = meta.corestoreId || ensureCorestoreId(meta.corestore || this.runtime?.corestore) || 'unknown-store';
    const monitorKey = `${storeId}:${normalizedKey}`;
    const existing = this.coreTransferMonitors.get(monitorKey);
    if (existing) {
      if (meta.label) existing.labels.add(meta.label);
      if (meta.source) existing.sources.add(meta.source);
      return;
    }

    const startedAt = Date.now();
    const startState = this.#describeCoreState(core);
    const labels = new Set();
    if (meta.label) labels.add(meta.label);
    const sources = new Set();
    if (meta.source) sources.add(meta.source);

    const monitor = {
      core,
      startedAt,
      startState,
      lastState: startState,
      lastSampleAt: startedAt,
      lastProgressLogAt: null,
      firstPeerAt: null,
      firstProgressAt: null,
      lastProgressAt: null,
      labels,
      sources,
      meta,
      interval: null,
      timeout: null
    };

    this.coreTransferMonitors.set(monitorKey, monitor);

    this.logger?.debug?.('[BlindPeering] Core transfer monitor start', {
      monitorKey,
      key: normalizedKey,
      label: meta.label || null,
      source: meta.source || null,
      identifier: meta.identifier || null,
      reason: meta.reason || null,
      corestoreId: meta.corestoreId || storeId,
      storagePath: meta.storagePath || null,
      state: startState
    });

    const intervalMs = 1000;
    monitor.interval = setInterval(() => {
      const now = Date.now();
      const current = this.#describeCoreState(core);
      const prev = monitor.lastState || {};
      const elapsedMs = Math.max(0, now - startedAt);

      if (current.peers !== prev.peers && current.peers != null) {
        if (monitor.firstPeerAt == null && typeof current.peers === 'number' && current.peers > 0) {
          monitor.firstPeerAt = now;
        }
        this.logger?.debug?.('[BlindPeering] Core transfer peers changed', {
          monitorKey,
          key: normalizedKey,
          label: meta.label || null,
          source: meta.source || null,
          identifier: meta.identifier || null,
          reason: meta.reason || null,
          elapsedMs,
          peers: current.peers,
          prevPeers: prev.peers ?? null
        });
      }

      const byteDelta = Number.isFinite(prev.byteLength) && Number.isFinite(current.byteLength)
        ? current.byteLength - prev.byteLength
        : null;
      const downloadedDelta = Number.isFinite(prev.downloaded) && Number.isFinite(current.downloaded)
        ? current.downloaded - prev.downloaded
        : null;
      const lengthDelta = Number.isFinite(prev.length) && Number.isFinite(current.length)
        ? current.length - prev.length
        : null;

      const hasProgress = (byteDelta != null && byteDelta > 0)
        || (downloadedDelta != null && downloadedDelta > 0)
        || (lengthDelta != null && lengthDelta > 0);

      if (hasProgress) {
        if (monitor.firstProgressAt == null) monitor.firstProgressAt = now;
        monitor.lastProgressAt = now;

        const dtSec = Math.max(0.001, (now - (monitor.lastSampleAt || now)) / 1000);
        const bytesPerSec = byteDelta != null && byteDelta > 0
          ? Math.round((byteDelta / dtSec) * 100) / 100
          : null;
        const downloadedPerSec = downloadedDelta != null && downloadedDelta > 0
          ? Math.round((downloadedDelta / dtSec) * 100) / 100
          : null;

        const shouldLog = monitor.lastProgressLogAt == null || (now - monitor.lastProgressLogAt) >= 2000;
        if (shouldLog) {
          monitor.lastProgressLogAt = now;
          this.logger?.info?.('[BlindPeering] Core transfer progress', {
            monitorKey,
            key: normalizedKey,
            label: meta.label || null,
            source: meta.source || null,
            identifier: meta.identifier || null,
            reason: meta.reason || null,
            elapsedMs,
            byteDelta: byteDelta != null && byteDelta > 0 ? byteDelta : null,
            bytesPerSec,
            downloadedDelta: downloadedDelta != null && downloadedDelta > 0 ? downloadedDelta : null,
            downloadedPerSec,
            lengthDelta: lengthDelta != null && lengthDelta > 0 ? lengthDelta : null,
            peers: current.peers ?? null,
            state: {
              length: current.length ?? null,
              contiguousLength: current.contiguousLength ?? null,
              remoteLength: current.remoteLength ?? null,
              byteLength: current.byteLength ?? null
            }
          });
        }
      }

      monitor.lastState = current;
      monitor.lastSampleAt = now;
    }, intervalMs);
    monitor.interval.unref?.();

    const ttlMs = 10 * 60 * 1000;
    monitor.timeout = setTimeout(() => {
      this.#stopCoreTransferMonitor(monitorKey, { reason: 'ttl' });
    }, ttlMs);
    monitor.timeout.unref?.();

    const closeHandler = () => this.#stopCoreTransferMonitor(monitorKey, { reason: 'close' });
    try {
      core.once?.('close', closeHandler);
    } catch (_) {
      try {
        core.on?.('close', closeHandler);
      } catch (_) {
        // ignore
      }
    }
  }

  #stopCoreTransferMonitor(monitorKey, { reason = null } = {}) {
    const monitor = this.coreTransferMonitors.get(monitorKey);
    if (!monitor) return;
    this.coreTransferMonitors.delete(monitorKey);
    if (monitor.interval) clearInterval(monitor.interval);
    if (monitor.timeout) clearTimeout(monitor.timeout);

    const now = Date.now();
    const elapsedMs = Math.max(0, now - monitor.startedAt);
    const endState = this.#describeCoreState(monitor.core);

    this.logger?.debug?.('[BlindPeering] Core transfer monitor end', {
      monitorKey,
      reason,
      elapsedMs,
      firstPeerMs: monitor.firstPeerAt ? Math.max(0, monitor.firstPeerAt - monitor.startedAt) : null,
      firstProgressMs: monitor.firstProgressAt ? Math.max(0, monitor.firstProgressAt - monitor.startedAt) : null,
      lastProgressAgoMs: monitor.lastProgressAt ? Math.max(0, now - monitor.lastProgressAt) : null,
      labels: Array.from(monitor.labels).slice(0, 3),
      sources: Array.from(monitor.sources).slice(0, 3),
      meta: {
        identifier: monitor.meta?.identifier || null,
        ref: monitor.meta?.ref || null,
        reason: monitor.meta?.reason || null,
        source: monitor.meta?.source || null,
        corestoreId: monitor.meta?.corestoreId || null
      },
      start: monitor.startState,
      end: endState
    });
  }

  async #withTimeout(promise, timeoutMs, label) {
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
      return promise;
    }
    let timer = null;
    try {
      return await Promise.race([
        promise,
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            const message = label
              ? `Operation timed out after ${timeoutMs}ms (${label})`
              : `Operation timed out after ${timeoutMs}ms`;
            reject(new Error(message));
          }, timeoutMs);
        })
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  async refreshFromBlindPeers(reason = 'startup') {
    if (this.refreshBackoff.timer) {
      clearTimeout(this.refreshBackoff.timer);
      this.refreshBackoff.timer = null;
      this.refreshBackoff.nextDelayMs = null;
      this.refreshBackoff.nextReason = null;
      this.refreshBackoff.nextScheduledAt = null;
    }
    if (!this.started) {
      this.logger?.debug?.('[BlindPeering] refresh skipped (not started)', { reason });
      return;
    }
    if (this.refreshBackoff.inflight) {
      this.logger?.debug?.('[BlindPeering] Refresh skipped (in-flight)', { reason });
      return this.refreshBackoff.inflight;
    }
    const attempt = Math.max(0, this.refreshBackoff.attempt);
    const promise = (async () => {
      const refreshStartedAt = Date.now();
      const targetKeys = Array.from(this.mirrorTargets.keys());
      const joinKeys = Array.from(this.joinTracking.keys());
      const touchesJoinRelays = joinKeys.filter((key) => this.mirrorTargets.has(`relay:${key}`));
      this.logger?.info?.('[BlindPeering] Refresh start', {
        reason,
        attempt,
        targets: this.mirrorTargets.size,
        targetPreview: targetKeys.slice(0, 8),
        joinRelays: joinKeys.length,
        joinRelaysPreview: joinKeys.slice(0, 3),
        touchesJoinRelays: touchesJoinRelays.length,
        touchesJoinRelaysPreview: touchesJoinRelays.slice(0, 3)
      });
      try {
        await this.blindPeering?.resume?.();
        const elapsedMs = Math.max(0, Date.now() - refreshStartedAt);
        this.refreshBackoff.attempt = 0;
        this.refreshBackoff.nextDelayMs = null;
        this.refreshBackoff.nextReason = null;
        this.refreshBackoff.nextScheduledAt = null;
        this.logger?.info?.('[BlindPeering] Refresh complete', {
          reason,
          attempt,
          elapsedMs,
          targets: this.mirrorTargets.size,
          touchesJoinRelays: touchesJoinRelays.length
        });
        this.emit('refresh-requested', {
          reason,
          targets: Array.from(this.mirrorTargets.values()),
          elapsedMs,
          touchesJoinRelays
        });
      } catch (error) {
        const elapsedMs = Math.max(0, Date.now() - refreshStartedAt);
        this.logger?.warn?.('[BlindPeering] Refresh failed', {
          reason,
          attempt: attempt + 1,
          elapsedMs,
          error: error?.message || error
        });
        const attemptNext = attempt + 1;
        // Keep the legacy log line for quick grepability.
        this.logger?.warn?.('[BlindPeering] Failed to resume blind-peering activity', {
          error: error?.message || error,
          reason,
          attempt: attemptNext
        });
        this.refreshBackoff.attempt = attemptNext;
        this.#scheduleRefreshRetry(reason, attemptNext);
      } finally {
        this.refreshBackoff.inflight = null;
      }
    })();
    this.refreshBackoff.inflight = promise;
    return promise;
  }

  getStatus() {
    return {
      enabled: this.enabled,
      running: this.started,
      handshakeMirrors: this.handshakeMirrors.size,
      manualMirrors: this.manualMirrors.size,
      trustedMirrors: this.trustedMirrors.size,
      targets: this.mirrorTargets.size,
      refreshBackoff: {
        attempt: this.refreshBackoff.attempt,
        nextDelayMs: this.refreshBackoff.nextDelayMs,
        nextReason: this.refreshBackoff.nextReason,
        nextScheduledAt: this.refreshBackoff.nextScheduledAt
      },
      rehydration: {
        inflight: !!this.rehydrationState.inflight,
        lastCompletedAt: this.rehydrationState.lastCompletedAt || null,
        lastResult: this.rehydrationState.lastResult || null
      }
    };
  }

  getTransportSnapshot({ limit = 5 } = {}) {
    const normalizedLimit = Number.isFinite(limit) && limit > 0 ? Math.trunc(limit) : 5;
    const trustedMirrors = Array.from(this.trustedMirrors);
    const handshakeMirrors = Array.from(this.handshakeMirrors);
    const manualMirrors = Array.from(this.manualMirrors);
    const targetEntries = Array.from(this.mirrorTargets.values());
    const relayTargets = targetEntries.filter((entry) => entry?.type === 'relay').length;
    const driveTargets = targetEntries.filter((entry) => entry?.type !== 'relay').length;

    let swarmConnections = null;
    try {
      if (this.swarm?.connections && typeof this.swarm.connections.size === 'number') {
        swarmConnections = this.swarm.connections.size;
      } else if (Array.isArray(this.swarm?.connections)) {
        swarmConnections = this.swarm.connections.length;
      }
    } catch (_) {
      swarmConnections = null;
    }

    const monitorEntries = Array.from(this.coreTransferMonitors.values());
    const monitorsWithPeers = monitorEntries.filter((entry) => {
      const peers = entry?.lastState?.peers;
      return Number.isFinite(peers) && peers > 0;
    }).length;

    const localBlindPeerPublicKey = this.getLocalBlindPeerPublicKey();
    const blindPeerClients = this.#collectBlindPeerClientSummary({ limit: normalizedLimit });

    return {
      enabled: this.enabled,
      started: this.started,
      localBlindPeerPublicKey: localBlindPeerPublicKey || null,
      trustedMirrorCount: trustedMirrors.length,
      trustedMirrorsPreview: trustedMirrors.slice(0, normalizedLimit).map((key) => previewValue(key, 16)),
      handshakeMirrorCount: handshakeMirrors.length,
      handshakeMirrorsPreview: handshakeMirrors.slice(0, normalizedLimit).map((key) => previewValue(key, 16)),
      manualMirrorCount: manualMirrors.length,
      manualMirrorsPreview: manualMirrors.slice(0, normalizedLimit).map((key) => previewValue(key, 16)),
      mirrorTargetCount: this.mirrorTargets.size,
      relayTargetCount: relayTargets,
      driveTargetCount: driveTargets,
      coreTransferMonitorCount: monitorEntries.length,
      coreTransferMonitorsWithPeers: monitorsWithPeers,
      swarmConnections,
      blindPeerClientCount: blindPeerClients.total,
      blindPeerClientConnected: blindPeerClients.connected,
      blindPeerClientStreams: blindPeerClients.withStream,
      blindPeerClientPreview: blindPeerClients.entries
    };
  }

  getLocalBlindPeerPublicKey() {
    const candidates = [
      {
        source: 'swarm-default-keypair',
        value: this.swarm?.dht?.defaultKeyPair?.publicKey || null
      },
      {
        source: 'blind-peering-swarm-default-keypair',
        value: this.blindPeering?.swarm?.dht?.defaultKeyPair?.publicKey || null
      }
    ];

    const refs = this.blindPeering?.blindPeersByKey;
    if (refs && typeof refs.values === 'function') {
      for (const ref of refs.values()) {
        const peer = ref?.peer || null;
        candidates.push({
          source: 'blind-peer-stream',
          value: peer?.stream?.publicKey || peer?.rpc?.stream?.publicKey || null
        });
        candidates.push({
          source: 'blind-peer-key',
          value: peer?.key || null
        });
      }
    }

    for (const candidate of candidates) {
      const blindPeerKey = normalizeCoreKey(candidate?.value || null);
      if (!blindPeerKey) continue;
      return this.#announceLocalBlindPeerPublicKey(blindPeerKey, candidate?.source || 'unknown');
    }

    return null;
  }

  #announceLocalBlindPeerPublicKey(blindPeerKey, source = 'unknown') {
    if (!blindPeerKey) return null;
    if (blindPeerKey === this.lastAnnouncedBlindPeerPublicKey) {
      return blindPeerKey;
    }
    this.lastAnnouncedBlindPeerPublicKey = blindPeerKey;
    if (this.localIdentityMonitorTimer) {
      clearInterval(this.localIdentityMonitorTimer);
      this.localIdentityMonitorTimer = null;
    }
    this.logger?.info?.('[BlindPeering] Local blind peer identity available', {
      blindPeerKey: previewValue(blindPeerKey, 16),
      source
    });
    if (this.onLocalIdentityAvailable) {
      try {
        this.onLocalIdentityAvailable(blindPeerKey);
      } catch (error) {
        this.logger?.warn?.('[BlindPeering] Failed to notify local identity listener', {
          error: error?.message || error
        });
      }
    }
    this.emit('local-key-available', blindPeerKey);
    return blindPeerKey;
  }

  logTransportSnapshot(reason = 'manual', details = {}, level = 'info') {
    const payload = {
      reason,
      ts: Date.now(),
      ...this.getTransportSnapshot(),
      ...(details && typeof details === 'object' ? details : {})
    };
    if (level === 'debug') {
      this.logger?.debug?.('[BlindPeering] Transport snapshot', payload);
    } else if (level === 'warn') {
      this.logger?.warn?.('[BlindPeering] Transport snapshot', payload);
    } else {
      this.logger?.info?.('[BlindPeering] Transport snapshot', payload);
    }
    return payload;
  }

  #collectBlindPeerClientSummary({ limit = 5 } = {}) {
    const entries = [];
    const refs = this.blindPeering?.blindPeersByKey;
    if (!refs || typeof refs.entries !== 'function') {
      return { total: 0, connected: 0, withStream: 0, entries };
    }

    let connected = 0;
    let withStream = 0;
    for (const [id, ref] of refs.entries()) {
      const peer = ref?.peer || null;
      const stream = peer?.stream || null;
      const streamOpen = !!(stream && !stream.destroyed && !stream.destroying);
      const remoteFromPeer = normalizeCoreKey(peer?.remotePublicKey || null);
      let remoteFromId = null;
      if (!remoteFromPeer && typeof id === 'string' && /^[0-9a-f]+$/i.test(id) && id.length % 2 === 0) {
        try {
          remoteFromId = normalizeCoreKey(Buffer.from(id, 'hex'));
        } catch (_) {
          remoteFromId = null;
        }
      }

      if (peer?.connected === true) connected += 1;
      if (streamOpen) withStream += 1;

      entries.push({
        remoteMirror: previewValue(remoteFromPeer || remoteFromId || id, 16),
        connected: peer?.connected === true,
        rpcClosed: typeof peer?.rpc?.closed === 'boolean' ? peer.rpc.closed : null,
        streamOpen,
        streamRemote: previewValue(normalizeCoreKey(stream?.remotePublicKey || null), 16),
        refs: Number.isFinite(ref?.refs) ? ref.refs : null,
        cores: ref?.cores && typeof ref.cores.size === 'number' ? ref.cores.size : null,
        gc: Number.isFinite(ref?.gc) ? ref.gc : null,
        uploaded: Number.isFinite(ref?.uploaded) ? ref.uploaded : null
      });
    }

    const normalizedLimit = Number.isFinite(limit) && limit > 0 ? Math.trunc(limit) : 5;
    return {
      total: entries.length,
      connected,
      withStream,
      entries: entries.slice(0, normalizedLimit)
    };
  }

  #installBlindPeerDiagnostics() {
    if (!this.blindPeering) return;
    if (this.blindPeerDiagnosticsInstalled) return;
    if (typeof this.blindPeering._getBlindPeer !== 'function') return;

    const originalGetBlindPeer = this.blindPeering._getBlindPeer.bind(this.blindPeering);
    this.blindPeering._getBlindPeer = (mirrorKey) => {
      const ref = originalGetBlindPeer(mirrorKey);
      this.#attachBlindPeerClientDiagnostics(ref, mirrorKey);
      return ref;
    };

    const existing = this.blindPeering?.blindPeersByKey;
    if (existing && typeof existing.values === 'function') {
      for (const ref of existing.values()) {
        this.#attachBlindPeerClientDiagnostics(ref, null);
      }
    }

    this.blindPeerDiagnosticsInstalled = true;
  }

  #attachBlindPeerClientDiagnostics(ref, mirrorKey = null) {
    const peer = ref?.peer || null;
    if (!peer || this.instrumentedBlindPeerClients.has(peer)) return;
    this.instrumentedBlindPeerClients.add(peer);

    const remoteMirror = previewValue(
      normalizeCoreKey(peer.remotePublicKey || mirrorKey || null),
      16
    );

    this.logger?.debug?.('[BlindPeering] Mirror client diagnostics attached', {
      mirror: remoteMirror || null
    });

    if (typeof peer.connect === 'function' && !peer.__ht_connect_instrumented) {
      const originalConnect = peer.connect.bind(peer);
      peer.connect = async (...args) => {
        const startedAt = Date.now();
        this.logger?.debug?.('[BlindPeering] Mirror client connect attempt', {
          mirror: remoteMirror || null,
          connected: peer.connected === true
        });
        try {
          const result = await originalConnect(...args);
          this.logger?.debug?.('[BlindPeering] Mirror client connect resolved', {
            mirror: remoteMirror || null,
            connected: peer.connected === true,
            elapsedMs: Math.max(0, Date.now() - startedAt)
          });
          return result;
        } catch (error) {
          this.logger?.warn?.('[BlindPeering] Mirror client connect rejected', {
            mirror: remoteMirror || null,
            elapsedMs: Math.max(0, Date.now() - startedAt),
            err: error?.message || error
          });
          throw error;
        }
      };
      peer.__ht_connect_instrumented = true;
    }

    if (typeof peer.on === 'function') {
      peer.on('stream', (stream) => {
        this.#attachBlindPeerStreamDiagnostics(stream, {
          mirror: remoteMirror || null,
          peer
        });
      });
    }

    this.#attachBlindPeerStreamDiagnostics(peer.stream || null, {
      mirror: remoteMirror || null,
      peer
    });
  }

  #attachBlindPeerStreamDiagnostics(stream, { mirror = null, peer = null } = {}) {
    if (!stream || this.instrumentedBlindPeerStreams.has(stream)) return;
    this.instrumentedBlindPeerStreams.add(stream);

    const remote = previewValue(normalizeCoreKey(stream.remotePublicKey || null), 16);
    const local = previewValue(normalizeCoreKey(stream.publicKey || null), 16);
    this.#announceLocalBlindPeerPublicKey(normalizeCoreKey(stream.publicKey || null), 'mirror-stream');

    this.logger?.debug?.('[BlindPeering] Mirror stream attached', {
      mirror,
      remote: remote || null,
      local: local || null,
      connected: peer?.connected === true
    });

    if (stream?.opened && typeof stream.opened.then === 'function') {
      stream.opened.then(() => {
        this.#announceLocalBlindPeerPublicKey(normalizeCoreKey(stream.publicKey || null), 'mirror-stream-opened');
        this.logger?.debug?.('[BlindPeering] Mirror stream opened', {
          mirror,
          remote: previewValue(normalizeCoreKey(stream.remotePublicKey || null), 16),
          local: previewValue(normalizeCoreKey(stream.publicKey || null), 16),
          connected: peer?.connected === true
        });
      }).catch((error) => {
        this.logger?.warn?.('[BlindPeering] Mirror stream open failed', {
          mirror,
          remote: previewValue(normalizeCoreKey(stream.remotePublicKey || null), 16),
          local: previewValue(normalizeCoreKey(stream.publicKey || null), 16),
          err: error?.message || error,
          connected: peer?.connected === true
        });
      });
    }

    if (typeof stream.on === 'function') {
      stream.on('error', (error) => {
        this.logger?.warn?.('[BlindPeering] Mirror stream error', {
          mirror,
          remote: previewValue(normalizeCoreKey(stream.remotePublicKey || null), 16),
          local: previewValue(normalizeCoreKey(stream.publicKey || null), 16),
          err: error?.message || error,
          connected: peer?.connected === true
        });
      });
      stream.on('close', () => {
        this.logger?.debug?.('[BlindPeering] Mirror stream closed', {
          mirror,
          remote: previewValue(normalizeCoreKey(stream.remotePublicKey || null), 16),
          local: previewValue(normalizeCoreKey(stream.publicKey || null), 16),
          connected: peer?.connected === true
        });
      });
    }
  }

  setMetadataPath(path) {
    if (typeof path === 'string' && path.trim()) {
      this.metadataPath = path.trim();
    }
  }

  configureBackoff(options = {}) {
    if (Number.isFinite(options.initialDelayMs) && options.initialDelayMs > 0) {
      this.backoffConfig.initialDelayMs = Math.trunc(options.initialDelayMs);
    }
    if (Number.isFinite(options.maxDelayMs) && options.maxDelayMs > 0) {
      this.backoffConfig.maxDelayMs = Math.trunc(options.maxDelayMs);
    }
    if (Number.isFinite(options.maxAttempts) && options.maxAttempts >= 0) {
      this.backoffConfig.maxAttempts = Math.trunc(options.maxAttempts);
    }
  }

  getMirrorMetadata() {
    return {
      ...this.metadata,
      targets: { ...this.metadata.targets }
    };
  }

  async #loadMetadata() {
    if (this.metadataLoaded) return;
    if (!this.metadataPath) {
      this.metadataLoaded = true;
      return;
    }
    try {
      const raw = await readFile(this.metadataPath, 'utf8');
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        if (parsed.targets && typeof parsed.targets === 'object') {
          this.metadata.targets = parsed.targets;
          for (const key of Object.keys(parsed.targets)) {
            const entry = parsed.targets[key];
            if (!entry || typeof entry !== 'object') continue;
            const targetKey = `${entry.type || 'unknown'}:${entry.identifier || key}`;
            if (!this.mirrorTargets.has(targetKey)) {
              this.mirrorTargets.set(targetKey, {
                type: entry.type || 'unknown',
                identifier: entry.identifier || key,
                context: { ...entry.context },
                updatedAt: entry.updatedAt || Date.now()
              });
            }
          }
        }
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        this.logger?.warn?.('[BlindPeering] Failed to load persisted metadata', {
          path: this.metadataPath,
          err: error?.message || error
        });
      }
    } finally {
      this.metadataLoaded = true;
    }
  }

  async #persistMetadata(force = false) {
    if (!this.metadataPath) return;
    if (!force && !this.metadataDirty) return;
    try {
      await mkdir(dirname(this.metadataPath), { recursive: true });
      const payload = JSON.stringify({
        targets: this.metadata.targets
      }, null, 2);
      await writeFile(this.metadataPath, payload, 'utf8');
      this.metadataDirty = false;
    } catch (error) {
      this.logger?.warn?.('[BlindPeering] Failed to persist mirror metadata', {
        path: this.metadataPath,
        err: error?.message || error
      });
    }
  }

  #scheduleMetadataPersist() {
    if (this.metadataSaveTimer) return;
    this.metadataSaveTimer = setTimeout(() => {
      this.metadataSaveTimer = null;
      this.#persistMetadata().catch((error) => {
        this.logger?.warn?.('[BlindPeering] Metadata persist task failed', {
          err: error?.message || error
        });
      });
    }, 2000);
    this.metadataSaveTimer.unref?.();
  }

  #recordMirrorMetadata(entry) {
    if (!entry || !entry.type || !entry.identifier) return;
    const key = `${entry.type}:${entry.identifier}`;
    const payload = this.#sanitizeMetadataEntry(entry);
    if (!payload) return;
    this.metadata.targets[key] = payload;
    this.metadataDirty = true;
    this.#scheduleMetadataPersist();
  }

  #sanitizeMetadataEntry(entry) {
    const base = {
      type: entry.type,
      identifier: entry.identifier,
      updatedAt: entry.updatedAt || Date.now(),
      ownerPeerKey: entry.ownerPeerKey || this.#getOwnerPeerKey() || null,
      announce: entry.announce ?? null,
      priority: Number.isFinite(entry.priority) ? Math.trunc(entry.priority) : null
    };
    if (entry.type === 'relay') {
      const context = entry.context || {};
      const relayCoreRefs = Array.isArray(context.coreRefs)
        ? Array.from(new Set(context.coreRefs.map(normalizeCoreKey).filter(Boolean)))
        : [];
      return {
        ...base,
        relayKey: context.relayKey || entry.identifier,
        publicIdentifier: context.publicIdentifier || null,
        lastWriterCount: relayCoreRefs.length || null,
        coreRefs: relayCoreRefs,
        context: {
          relayKey: context.relayKey || entry.identifier,
          publicIdentifier: context.publicIdentifier || null,
          coreRefs: relayCoreRefs,
          announce: context.announce ?? base.announce,
          priority: Number.isFinite(context.priority) ? Math.trunc(context.priority) : base.priority,
          ownerPeerKey: base.ownerPeerKey
        }
      };
    }
    if (entry.type === 'drive') {
      const context = entry.context || {};
      const driveCoreRefs = Array.isArray(context.coreRefs)
        ? Array.from(new Set(context.coreRefs.map(normalizeCoreKey).filter(Boolean)))
        : [];
      return {
        ...base,
        driveKey: context.driveKey || entry.identifier,
        isPfp: !!context.isPfp,
        coreRefs: driveCoreRefs,
        context: {
          driveKey: context.driveKey || entry.identifier,
          isPfp: !!context.isPfp,
          coreRefs: driveCoreRefs,
          announce: context.announce ?? base.announce ?? true,
          priority: Number.isFinite(context.priority) ? Math.trunc(context.priority) : base.priority,
          ownerPeerKey: base.ownerPeerKey
        }
      };
    }
    return {
      ...base,
      context: {}
    };
  }

  #scheduleRefreshRetry(reason, attempt) {
    if (attempt > this.backoffConfig.maxAttempts) {
      this.logger?.warn?.('[BlindPeering] Refresh backoff aborted after max attempts', {
        reason,
        attempt
      });
      return;
    }
    if (this.refreshBackoff.timer) return;
    const delay = this.#calculateBackoffDelay(attempt);
    this.refreshBackoff.nextDelayMs = delay;
    this.refreshBackoff.nextReason = reason;
    this.refreshBackoff.nextScheduledAt = Date.now() + delay;
    this.logger?.debug?.('[BlindPeering] Scheduling refresh retry', {
      reason,
      attempt,
      delay
    });
    this.refreshBackoff.timer = setTimeout(() => {
      this.refreshBackoff.timer = null;
      this.refreshBackoff.nextDelayMs = null;
      this.refreshBackoff.nextReason = null;
      this.refreshBackoff.nextScheduledAt = null;
      this.refreshFromBlindPeers(reason).catch((error) => {
        this.logger?.warn?.('[BlindPeering] Scheduled refresh failed', {
          err: error?.message || error,
          reason
        });
      });
    }, delay);
    this.refreshBackoff.timer.unref?.();
  }

  #calculateBackoffDelay(attempt) {
    if (attempt <= 0) return this.backoffConfig.initialDelayMs;
    const factor = 2 ** Math.max(0, attempt - 1);
    const delay = this.backoffConfig.initialDelayMs * factor;
    return Math.min(delay, this.backoffConfig.maxDelayMs);
  }

  #getOwnerPeerKey() {
    if (this.ownerPeerKey) return this.ownerPeerKey;
    const keyBuffer = this.runtime?.swarmKeyPair?.publicKey;
    if (!keyBuffer) return null;
    try {
      this.ownerPeerKey = HypercoreId.encode(keyBuffer);
    } catch (_) {
      try {
        this.ownerPeerKey = Buffer.from(keyBuffer).toString('hex');
      } catch (_) {
        this.ownerPeerKey = null;
      }
    }
    return this.ownerPeerKey;
  }

  #startLocalIdentityMonitor() {
    if (this.localIdentityMonitorTimer || !this.started) return;
    const poll = () => {
      try {
        const key = this.getLocalBlindPeerPublicKey();
        if (key && this.localIdentityMonitorTimer) {
          clearInterval(this.localIdentityMonitorTimer);
          this.localIdentityMonitorTimer = null;
        }
      } catch (error) {
        this.logger?.warn?.('[BlindPeering] Failed to poll local blind peer identity', {
          error: error?.message || error
        });
      }
    };
    poll();
    if (this.lastAnnouncedBlindPeerPublicKey) return;
    this.localIdentityMonitorTimer = setInterval(poll, 250);
    if (typeof this.localIdentityMonitorTimer?.unref === 'function') {
      this.localIdentityMonitorTimer.unref();
    }
  }
}
