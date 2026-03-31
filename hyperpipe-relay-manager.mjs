// ./relay-worker/hyperpipe-relay-manager.mjs
// Worker-compatible version of the relay manager

import Corestore from 'corestore';
import Hyperswarm from 'hyperswarm';
import NostrRelay from './hyperpipe-relay-event-processor.mjs';
import Hypercore from 'hypercore';
import hypercoreCaps from 'hypercore/lib/caps.js';
import b4a from 'b4a';
import c from 'compact-encoding';
import Protomux from 'protomux';
import Autobee from './hyperpipe-relay-helper.mjs';
import { nobleSecp256k1 } from './crypto-libraries.js';
import { NostrUtils } from './nostr-utils.js';
import { setTimeout as delay } from 'node:timers/promises';
import { join } from 'node:path';
import { promises as fs } from 'node:fs';

const { DEFAULT_NAMESPACE } = hypercoreCaps;

// File locking utility to handle concurrent access
const fileLocks = new Map();

async function acquireFileLock(filePath, maxRetries = 5, retryDelay = 500) {
  let retries = 0;
  
  while (retries < maxRetries) {
    if (!fileLocks.has(filePath)) {
      // Acquire the lock
      fileLocks.set(filePath, true);
      return true;
    }
    
    // Wait before retrying
    console.log(`File ${filePath} is locked, retrying in ${retryDelay}ms (attempt ${retries + 1}/${maxRetries})`);
    await delay(retryDelay);
    retries++;
  }
  
  // Failed to acquire lock after max retries
  throw new Error(`Failed to acquire lock for ${filePath} after ${maxRetries} attempts`);
}

function releaseFileLock(filePath) {
  fileLocks.delete(filePath);
}

let relayCorestoreCounter = 0;

function ensureCorestoreId(store) {
  if (!store) return null;
  if (!store.__ht_id) {
    relayCorestoreCounter += 1;
    store.__ht_id = `relay-corestore-${relayCorestoreCounter}`;
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

async function verifyEventSignature(event) {
  try {
      console.log('Verifying Event Signature ===');
      const serialized = serializeEvent(event);
      console.log('Serialized Event:', serialized);
      
      // Use sha256 which returns Uint8Array
      const hashBytes = await nobleSecp256k1.utils.sha256(b4a.from(serialized, 'utf8'));
      const hashHex = NostrUtils.bytesToHex(hashBytes);
      console.log('Event Hash:', hashHex);
      
      console.log('Verification Details:');
      console.log('Public Key:', event.pubkey);
      console.log('Signature:', event.sig);
      
      // schnorr.verify expects the signature, hash, and pubkey
      // Our pure implementation handles string/Uint8Array conversion internally
      const isValid = await nobleSecp256k1.schnorr.verify(
        event.sig,  // hex string
        hashHex,    // hex string
        event.pubkey // hex string (x-only pubkey, 32 bytes)
      );
      
      console.log('Verification Result:', isValid);
      return isValid;
  } catch (err) {
      console.error('Error verifying event signature:', err);
      return false;
  }
}

const WAKEUP_CAPABILITY_FILENAME = 'wakeup-capability.json';

function serializeEvent(event) {
  return JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
}

async function getEventHash(event) {
  const serialized = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  const hashBytes = await nobleSecp256k1.utils.sha256(b4a.from(serialized, 'utf8'));
  return NostrUtils.bytesToHex(hashBytes);
}

function validateEvent(event) {
  if (typeof event.kind !== 'number') return false;
  if (typeof event.content !== 'string') return false;
  if (typeof event.created_at !== 'number') return false;
  if (typeof event.pubkey !== 'string') return false;
  if (!event.pubkey.match(/^[a-f0-9]{64}$/)) return false;

  if (!Array.isArray(event.tags)) return false;
  for (let tag of event.tags) {
    if (!Array.isArray(tag)) return false;
    for (let item of tag) {
      if (typeof item === 'object') return false;
    }
  }

  return true;
}

export class RelayManager {
    constructor(storageDir, bootstrap, options = {}) {
      this.storageDir = storageDir;
      this.bootstrap = bootstrap;
      this.keyPair = options?.keyPair || null;
      this.expectedWriterKey = options?.expectedWriterKey || null;
      this.fastForward = options?.fastForward || null;
      this.corestore = options?.corestore || null;
      this.store = null;  // Initialize in the initialize method
      this.relay = null;
      this.swarm = null;
      this.peers = new Map(); // Track connected peers
      this._relayStateSnapshot = null;
    }
  
    async initialize() {
      console.log('Initializing relay with bootstrap:', this.bootstrap);

      try {
        // Acquire lock for the storage directory
        await acquireFileLock(this.storageDir);
        console.log(`Acquired lock for storage directory: ${this.storageDir}`);
        
        // Initialize Corestore after acquiring the lock
        if (this.corestore) {
          this.store = this.corestore;
          const storeInfo = describeCorestore(this.store);
          console.log('[RelayManager] Using shared corestore', {
            relayKey: this.bootstrap,
            storageDir: this.storageDir,
            corestoreId: storeInfo.corestoreId,
            corestorePath: storeInfo.storagePath
          });
        } else {
          this.store = new Corestore(this.storageDir);
          this.store.__ht_storage_path = this.storageDir;
          const storeInfo = describeCorestore(this.store);
          console.log('[RelayManager] Created relay corestore', {
            relayKey: this.bootstrap,
            storageDir: this.storageDir,
            corestoreId: storeInfo.corestoreId
          });
        }

        if (!this.expectedWriterKey && this.keyPair?.publicKey) {
          this.expectedWriterKey = this.keyPair.publicKey;
        }

        await this.ensureAutobaseLocalKey().catch((error) => {
          console.warn('[RelayManager] Failed to inspect autobase/local metadata', error?.message || error);
        });
        await this.ensureLocalWriterManifest().catch((error) => {
          console.warn('[RelayManager] Failed to ensure local writer manifest', error?.message || error);
        });
        
        if (this.keyPair || this.expectedWriterKey) {
          const keyPairHex = this.keyPair?.publicKey ? b4a.toString(this.keyPair.publicKey, 'hex') : null;
          const expectedHex = this.expectedWriterKey ? b4a.toString(this.expectedWriterKey, 'hex') : null;
          console.log('[RelayManager] Preparing autobase writer material', {
            relayKey: this.bootstrap,
            keyPairPublic: keyPairHex ? keyPairHex.slice(0, 16) : null,
            expectedWriter: expectedHex ? expectedHex.slice(0, 16) : null,
            matchesExpected: keyPairHex && expectedHex ? keyPairHex === expectedHex : null
          });
        }

        this.relay = new NostrRelay(this.store, this.bootstrap, {
          ...(this.fastForward ? { fastForward: this.fastForward } : {}),
          apply: async (batch, view, base) => {
            const kvOps = []
            const eventOps = []

            for (const node of batch) {
              const op = node.value
              if (op.type === 'addWriter') {
                const localKeyHex = base?.local?.key ? b4a.toString(base.local.key, 'hex') : null;
                const activeCount = base?.activeWriters?.size ?? null;
                console.log('[RelayManager] Applying addWriter op', {
                  relayKey: this.bootstrap,
                  writer: String(op.key).slice(0, 16),
                  writable: base?.writable ?? null,
                  localKey: localKeyHex ? localKeyHex.slice(0, 16) : null,
                  activeWriters: activeCount
                });
                await base.addWriter(b4a.from(op.key, 'hex'));
                const updatedCount = base?.activeWriters?.size ?? null;
                const nowActive = base?.activeWriters?.has
                  ? base.activeWriters.has(b4a.from(op.key, 'hex'))
                  : null;
                console.log('[RelayManager] Applied addWriter op', {
                  relayKey: this.bootstrap,
                  writer: String(op.key).slice(0, 16),
                  activeWriters: updatedCount,
                  writerActive: nowActive
                });
                continue
              }
              if (op.type === 'put' || op.type === 'del') kvOps.push(node)
              else eventOps.push(node)
            }

            if (kvOps.length) {
              await Autobee.apply(kvOps, view, base)
            }
            if (eventOps.length) {
              await NostrRelay.apply(eventOps, view, base)
            }
          },
          valueEncoding: c.any,
          verifyEvent: this.verifyEvent.bind(this),
          keyPair: this.keyPair || undefined
        });

        if (typeof this.relay.ready === 'function') {
          try {
            await this.relay.ready();
          } catch (error) {
            console.warn('[RelayManager] Relay ready() failed before local key inspection', error?.message || error);
          }
        }
        if (this.relay?.local && typeof this.relay.local.ready === 'function') {
          try {
            await this.relay.local.ready();
          } catch (error) {
            console.warn('[RelayManager] Local core ready() failed before local key inspection', error?.message || error);
          }
        }

        const localKeyHex = this.relay?.local?.key ? b4a.toString(this.relay.local.key, 'hex') : null;
        const expectedHex = this.expectedWriterKey ? b4a.toString(this.expectedWriterKey, 'hex') : null;
        console.log('[RelayManager] Autobase local key set', {
          relayKey: this.bootstrap,
          localKey: localKeyHex ? localKeyHex.slice(0, 16) : null,
          expectedWriter: expectedHex ? expectedHex.slice(0, 16) : null,
          matchesExpected: localKeyHex && expectedHex ? localKeyHex === expectedHex : null
        });

        this.logRelayState('initialized');

        if (typeof this.relay.on === 'function') {
          this.relay.on('writable', () => this.logRelayState('writable'));
          this.relay.on('unwritable', () => this.logRelayState('unwritable'));
          this.relay.on('update', () => this.logRelayState('update'));
        }

        this.relay.on('error', console.error);

        await this.relay.update();
        console.log('[RelayManager] Relay update complete', {
          relayKey: this.bootstrap,
          writable: this.relay?.writable ?? null,
          activeWriters: this.relay?.activeWriters?.size ?? null
        });
        this.logRelayState('update-complete');
        await this.ensureWakeupCapability().catch((error) => {
          console.warn('[RelayManager] Failed to prepare wakeup capability', error?.message || error);
        });

        this.relay.view.core.on('append', async () => {
          if (this.relay.view.version === 1) return;
          console.log('\rRelay event appended. Current version:', this.relay.view.version);
        });

        if (!this.bootstrap) {
          console.log('Relay public key:', b4a.toString(this.relay.key, 'hex'));
        }

        this.swarm = new Hyperswarm();
        this.setupSwarmListeners();

        console.log('Joining swarm with discovery key:', b4a.toString(this.relay.discoveryKey, 'hex'));
        const discovery = this.swarm.join(this.relay.discoveryKey);
        await discovery.flushed();

        console.log('Initializing relay');
        if (this.relay.writable) {
          try {
            const initEventId = await this.initRelay();
            console.log('Relay initialized with event ID:', initEventId);
          } catch (error) {
            console.error('Failed to initialize relay:', error);
          }
        } else {
          console.log('Relay isn\'t writable yet');
          console.log('Have another writer add the following key:');
          console.log(b4a.toString(this.relay.local.key, 'hex'));
        }
        
        // Release the lock after initialization
        releaseFileLock(this.storageDir);
        console.log(`Released lock for storage directory: ${this.storageDir}`);
        
        return this;
      } catch (error) {
        // Make sure to release the lock in case of errors
        releaseFileLock(this.storageDir);
        console.error(`Error during relay initialization: ${error.message}`);
        console.error(error.stack);
        throw error;
      }
    }

    getRelayStateSnapshot() {
      if (!this.relay) return null;
      const localKey = this.relay?.local?.key ? b4a.toString(this.relay.local.key, 'hex') : null;
      const expectedHex = this.expectedWriterKey ? b4a.toString(this.expectedWriterKey, 'hex') : null;
      const expectedActive = this.expectedWriterKey && this.relay?.activeWriters?.has
        ? this.relay.activeWriters.has(this.expectedWriterKey)
        : null;
      return {
        writable: this.relay?.writable ?? null,
        activeWriters: this.relay?.activeWriters?.size ?? null,
        localKey: localKey ? localKey.slice(0, 16) : null,
        expectedWriter: expectedHex ? expectedHex.slice(0, 16) : null,
        expectedActive
      };
    }

    logRelayState(reason, extra = {}) {
      const snapshot = this.getRelayStateSnapshot();
      if (!snapshot) return;
      if (
        this._relayStateSnapshot &&
        snapshot.writable === this._relayStateSnapshot.writable &&
        snapshot.activeWriters === this._relayStateSnapshot.activeWriters &&
        snapshot.localKey === this._relayStateSnapshot.localKey &&
        snapshot.expectedWriter === this._relayStateSnapshot.expectedWriter &&
        snapshot.expectedActive === this._relayStateSnapshot.expectedActive
      ) {
        return;
      }
      this._relayStateSnapshot = snapshot;
      console.log('[RelayManager] Relay state', {
        relayKey: this.bootstrap,
        reason,
        ...snapshot,
        ...extra
      });
    }

    async ensureAutobaseLocalKey() {
      if (!this.bootstrap) return;
      if (!this.expectedWriterKey || !this.keyPair?.publicKey) {
        console.log('[RelayManager] Autobase local key inspection skipped (missing expected writer or keyPair)', {
          relayKey: this.bootstrap,
          hasExpectedWriter: !!this.expectedWriterKey,
          hasKeyPair: !!this.keyPair?.publicKey
        });
        return;
      }

      const expectedHex = b4a.toString(this.expectedWriterKey, 'hex');
      const keyPairHex = b4a.toString(this.keyPair.publicKey, 'hex');
      const manifestVersion = Number.isInteger(this.store?.manifestVersion)
        ? this.store.manifestVersion
        : 0;
      let derivedCoreKey = null;
      let derivedCoreHex = null;
      let derivedMatchesExpected = null;
      try {
        derivedCoreKey = Hypercore.key(this.keyPair.publicKey, {
          compat: false,
          version: manifestVersion,
          namespace: DEFAULT_NAMESPACE
        });
        derivedCoreHex = b4a.toString(derivedCoreKey, 'hex');
        derivedMatchesExpected = b4a.equals(derivedCoreKey, this.expectedWriterKey);
      } catch (error) {
        console.warn('[RelayManager] Failed to derive core key from signer for autobase/local check', {
          relayKey: this.bootstrap,
          error: error?.message || error,
          manifestVersion
        });
      }
      const bootstrapCore = this.store.get({ key: this.bootstrap, compat: false, active: false });
      await bootstrapCore.ready();
      const storedLocal = await bootstrapCore.getUserData('autobase/local');
      const storedHex = storedLocal ? b4a.toString(storedLocal, 'hex') : null;
      const matchesExpected = storedLocal ? b4a.equals(storedLocal, this.expectedWriterKey) : null;
      console.log('[RelayManager] Autobase local key metadata', {
        relayKey: this.bootstrap,
        storedLocal: storedHex ? storedHex.slice(0, 16) : null,
        expectedWriter: expectedHex.slice(0, 16),
        keyPairPublic: keyPairHex.slice(0, 16),
        derivedCore: derivedCoreHex ? derivedCoreHex.slice(0, 16) : null,
        derivedMatchesExpected,
        manifestVersion,
        matchesExpected,
        matchesKeyPair: derivedMatchesExpected
      });

      if (!derivedCoreKey) {
        console.warn('[RelayManager] Skipping autobase/local override (unable to derive core key from signer)', {
          relayKey: this.bootstrap,
          expectedWriter: expectedHex.slice(0, 16),
          keyPairPublic: keyPairHex.slice(0, 16),
          manifestVersion
        });
        return;
      }

      if (derivedMatchesExpected === false) {
        console.warn('[RelayManager] Skipping autobase/local override (keyPair does not match expected writer core)', {
          relayKey: this.bootstrap,
          expectedWriter: expectedHex.slice(0, 16),
          keyPairPublic: keyPairHex.slice(0, 16),
          derivedCore: derivedCoreHex ? derivedCoreHex.slice(0, 16) : null,
          manifestVersion
        });
        return;
      }

      if (!storedLocal || !matchesExpected) {
        const reason = storedLocal ? 'mismatch' : 'missing';
        console.warn('[RelayManager] Updating autobase/local to align with invite writer', {
          relayKey: this.bootstrap,
          reason,
          previousLocal: storedHex ? storedHex.slice(0, 16) : null,
          expectedWriter: expectedHex.slice(0, 16)
        });
        await bootstrapCore.setUserData('autobase/local', this.expectedWriterKey);
        const updatedLocal = await bootstrapCore.getUserData('autobase/local');
        const updatedHex = updatedLocal ? b4a.toString(updatedLocal, 'hex') : null;
        console.log('[RelayManager] Autobase local key updated', {
          relayKey: this.bootstrap,
          updatedLocal: updatedHex ? updatedHex.slice(0, 16) : null,
          matchesExpected: updatedLocal ? b4a.equals(updatedLocal, this.expectedWriterKey) : null
        });
      } else {
        console.log('[RelayManager] Autobase local key matches expected writer; no update needed', {
          relayKey: this.bootstrap,
          localKey: storedHex ? storedHex.slice(0, 16) : null
        });
      }
    }

    async ensureLocalWriterManifest() {
      if (!this.store) return;
      if (!this.expectedWriterKey || !this.keyPair?.publicKey) {
        console.log('[RelayManager] Local writer manifest check skipped (missing expected writer or keyPair)', {
          relayKey: this.bootstrap,
          hasExpectedWriter: !!this.expectedWriterKey,
          hasKeyPair: !!this.keyPair?.publicKey
        });
        return;
      }

      const expectedHex = b4a.toString(this.expectedWriterKey, 'hex');
      const keyPairHex = b4a.toString(this.keyPair.publicKey, 'hex');
      const manifestVersion = Number.isInteger(this.store?.manifestVersion)
        ? this.store.manifestVersion
        : 0;
      let derivedCoreKey = null;
      let derivedCoreHex = null;
      try {
        derivedCoreKey = Hypercore.key(this.keyPair.publicKey, {
          compat: false,
          version: manifestVersion,
          namespace: DEFAULT_NAMESPACE
        });
        derivedCoreHex = b4a.toString(derivedCoreKey, 'hex');
      } catch (error) {
        console.warn('[RelayManager] Failed to derive core key for manifest pre-open', {
          relayKey: this.bootstrap,
          error: error?.message || error,
          manifestVersion
        });
        return;
      }

      const derivedMatchesExpected = b4a.equals(derivedCoreKey, this.expectedWriterKey);
      if (!derivedMatchesExpected) {
        console.warn('[RelayManager] Skipping manifest pre-open (derived core key mismatch)', {
          relayKey: this.bootstrap,
          expectedWriter: expectedHex.slice(0, 16),
          derivedCore: derivedCoreHex.slice(0, 16),
          keyPairPublic: keyPairHex.slice(0, 16),
          manifestVersion
        });
        return;
      }

      const manifest = {
        version: manifestVersion,
        hash: 'blake2b',
        allowPatch: false,
        quorum: 1,
        signers: [{
          signature: 'ed25519',
          namespace: DEFAULT_NAMESPACE,
          publicKey: this.keyPair.publicKey
        }],
        prologue: null
      };

      let core = null;
      try {
        core = this.store.get({
          key: this.expectedWriterKey,
          keyPair: this.keyPair,
          manifest,
          compat: false,
          active: false
        });
      } catch (error) {
        console.warn('[RelayManager] Failed to open local writer core for manifest check', {
          relayKey: this.bootstrap,
          error: error?.message || error
        });
        return;
      }

      try {
        await core.ready();
      } catch (error) {
        console.warn('[RelayManager] Local writer core ready() failed during manifest check', {
          relayKey: this.bootstrap,
          error: error?.message || error
        });
        return;
      }

      const hasManifest = !!core.manifest;
      const coreKeyHex = core.key ? b4a.toString(core.key, 'hex') : null;
      const coreKeyMatchesExpected = core.key
        ? b4a.equals(core.key, this.expectedWriterKey)
        : null;
      const coreKeyPairHex = core.keyPair?.publicKey ? b4a.toString(core.keyPair.publicKey, 'hex') : null;
      const coreKeyPairMatches = core.keyPair?.publicKey
        ? b4a.equals(core.keyPair.publicKey, this.keyPair.publicKey)
        : null;

      console.log('[RelayManager] Local writer core manifest inspection', {
        relayKey: this.bootstrap,
        expectedWriter: expectedHex.slice(0, 16),
        derivedCore: derivedCoreHex.slice(0, 16),
        coreKey: coreKeyHex ? coreKeyHex.slice(0, 16) : null,
        coreKeyMatchesExpected,
        hasManifest,
        coreKeyPair: coreKeyPairHex ? coreKeyPairHex.slice(0, 16) : null,
        coreKeyPairMatches,
        manifestVersion
      });

      if (!hasManifest) {
        try {
          await core.setManifest(manifest);
          console.log('[RelayManager] Local writer core manifest set', {
            relayKey: this.bootstrap,
            expectedWriter: expectedHex.slice(0, 16),
            manifestVersion
          });
        } catch (error) {
          console.warn('[RelayManager] Failed to set local writer manifest', {
            relayKey: this.bootstrap,
            error: error?.message || error,
            manifestVersion
          });
        }
      }

      if (!core.keyPair?.secretKey || coreKeyPairMatches === false) {
        try {
          core.setKeyPair(this.keyPair);
          console.log('[RelayManager] Local writer core keyPair updated', {
            relayKey: this.bootstrap,
            expectedWriter: expectedHex.slice(0, 16),
            manifestVersion
          });
        } catch (error) {
          console.warn('[RelayManager] Failed to update local writer core keyPair', {
            relayKey: this.bootstrap,
            error: error?.message || error
          });
        }
      }
    }

    async ensureWakeupCapability() {
      if (!this.relay) return null;
      try {
        if (typeof this.relay.ready === 'function') {
          await this.relay.ready();
        }
      } catch (error) {
        console.warn('[RelayManager] Relay ready() failed while preparing wakeup capability', error?.message || error);
      }

      const localCore = this.relay.local || null;
      if (localCore && typeof localCore.ready === 'function') {
        try {
          await localCore.ready();
        } catch (error) {
          console.warn('[RelayManager] Failed to ready local core for wakeup capability', error?.message || error);
        }
      }

      let capability = await this.loadWakeupCapability();
      if (capability?.key) {
        this.relay.wakeupCapability = {
          key: capability.key,
          discoveryKey: capability.discoveryKey || null
        };
        return this.relay.wakeupCapability;
      }

      const primaryKey = localCore?.key || localCore?.core?.key || this.relay?.local?.key || this.relay?.key || null;
      if (!primaryKey) {
        console.warn('[RelayManager] Unable to determine wakeup capability key for relay');
        return null;
      }

      const discoveryKey = localCore?.discoveryKey || this.relay.discoveryKey || null;
      const normalizedKey = Buffer.isBuffer(primaryKey) ? primaryKey : Buffer.from(primaryKey);
      capability = {
        key: normalizedKey,
        discoveryKey: discoveryKey ? (Buffer.isBuffer(discoveryKey) ? discoveryKey : Buffer.from(discoveryKey)) : null
      };

      try {
        if (this.relay._wakeup?.queue) {
          this.relay._wakeup.queue(capability.key, localCore?.length || 0);
          await this.relay._wakeup.flush();
        }
      } catch (error) {
        console.warn('[RelayManager] Failed to flush wakeup state', error?.message || error);
      }

      this.relay.wakeupCapability = { ...capability };

      await this.persistWakeupCapability(capability).catch((error) => {
        console.warn('[RelayManager] Failed to persist wakeup capability', error?.message || error);
      });

      return this.relay.wakeupCapability;
    }

    async loadWakeupCapability() {
      const filePath = join(this.storageDir, WAKEUP_CAPABILITY_FILENAME);
      try {
        const raw = await fs.readFile(filePath, 'utf8');
        const parsed = JSON.parse(raw);
        if (!parsed || !parsed.key) return null;
        const keyBuffer = Buffer.from(parsed.key, 'hex');
        const discoveryBuffer = parsed.discoveryKey ? Buffer.from(parsed.discoveryKey, 'hex') : null;
        return {
          key: keyBuffer,
          discoveryKey: discoveryBuffer
        };
      } catch (error) {
        if (error.code !== 'ENOENT') {
          console.warn('[RelayManager] Failed to load wakeup capability', error?.message || error);
        }
        return null;
      }
    }

    async persistWakeupCapability(capability) {
      if (!capability?.key) return;
      const filePath = join(this.storageDir, WAKEUP_CAPABILITY_FILENAME);
      const payload = {
        key: b4a.isBuffer(capability.key) ? capability.key.toString('hex') : Buffer.from(capability.key).toString('hex'),
        discoveryKey: capability.discoveryKey
          ? (b4a.isBuffer(capability.discoveryKey) ? capability.discoveryKey.toString('hex') : Buffer.from(capability.discoveryKey).toString('hex'))
          : null,
        updatedAt: Date.now()
      };
      await fs.writeFile(filePath, JSON.stringify(payload, null, 2), 'utf8');
    }

    setupSwarmListeners() {
      this.swarm.on('connection', async (connection, peerInfo) => {
        const peerKey = b4a.toString(peerInfo.publicKey, 'hex');
        console.log('\rPeer joined', peerKey.substring(0, 16));
        
        // Track peer
        this.peers.set(peerKey, {
          connection,
          connectedAt: new Date(),
          info: peerInfo
        });
        
        const mux = new Protomux(connection);
        console.log('Initialized Protomux on the connection');
        
        const addWriterProtocol = mux.createChannel({
          protocol: 'add-writer',
          onopen: () => {
            console.log('add-writer protocol opened!');
          },
          onclose: () => {
            console.log('add-writer protocol closed!');
            // Remove peer on disconnect
            this.peers.delete(peerKey);
          }
        });
        
        if (!addWriterProtocol) {
          console.error('Failed to create add-writer protocol channel');
          return;
        }
        
        const addWriterMessage = addWriterProtocol.addMessage({
          encoding: c.string,
          onmessage: async (message) => {
            const writerKey = message.toString();
            console.log('Received new writer key:', writerKey);
            try {
              await this.addWriter(writerKey);
              await this.relay.update();
              console.log('Writer key added successfully');
              addWriterProtocol.close();
            } catch (error) {
              console.error('Error adding writer key:', error);
            }
          }
        });
        
        addWriterProtocol.open();
        console.log('Opened add-writer protocol');
        
        const writerKey = b4a.toString(this.relay.local.key, 'hex');
        addWriterMessage.send(writerKey);
        console.log('Sent writer key:', writerKey);
        
        this.relay.replicate(connection);
      });
    }

    async addWriter(key) {
      const localKeyHex = this.relay?.local?.key ? b4a.toString(this.relay.local.key, 'hex') : null;
      console.log('[RelayManager] addWriter append requested', {
        relayKey: this.bootstrap,
        writer: String(key).slice(0, 16),
        writable: this.relay?.writable ?? null,
        localKey: localKeyHex ? localKeyHex.slice(0, 16) : null
      });
      const result = await this.relay.append({
        type: 'addWriter',
        key
      });
      console.log('[RelayManager] addWriter append committed', {
        relayKey: this.bootstrap,
        writer: String(key).slice(0, 16),
        viewVersion: this.relay?.view?.version ?? null
      });
      await this.relay.update().catch(() => {});
      await this.ensureWakeupCapability().catch((error) => {
        console.warn('[RelayManager] Failed to refresh wakeup capability after addWriter', error?.message || error);
      });
      return result;
    }

    async removeWriter(key) {
      console.log('Removing writer:', key);
      return await this.relay.append({
        type: 'removeWriter',
        key
      });
    }

    async handleMessage(message, sendResponse, connectionKey, clientId = null) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      return this.relay.handleMessage(message, sendResponse, connectionKey, clientId);
    }

    async handleSubscription(connectionKey) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      return this.relay.handleSubscription(connectionKey);
    }        

    async getSubscriptions(connectionKey) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      return this.relay.getSubscriptions(connectionKey);
    }

    async getClientSubscriptions(clientId) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      return this.relay.getClientSubscriptions(clientId);
    }

    async updateClientSubscriptions(clientId, subscriptionObject) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      return this.relay.updateClientSubscriptions(clientId, subscriptionObject);
    }

    async updateSubscriptions(connectionKey, activeSubscriptionsUpdated) {
      try {
        if (!this.relay) {
          throw new Error('Relay not initialized');
        }
        
        console.log(`[${new Date().toISOString()}] RelayManager: Updating subscriptions for connection ${connectionKey}`);
        // console.log('Updated subscription data:', JSON.stringify(activeSubscriptionsUpdated, null, 2));
        
        const result = await this.relay.updateSubscriptions(connectionKey, activeSubscriptionsUpdated);
        console.log(`[${new Date().toISOString()}] RelayManager: Successfully updated subscriptions`);
        
        return result;
      } catch (error) {
        console.error(`[${new Date().toISOString()}] RelayManager: Error updating subscriptions:`, error);
        throw error;
      }
    }

    async initRelay() {
      // Generate a new private key
      const privateKey = NostrUtils.generatePrivateKey(); // Returns hex string
      const publicKey = NostrUtils.getPublicKey(privateKey); // Returns hex string (x-only, 32 bytes)
      
      const event = {
        kind: 0,
        content: 'Relay initialized',
        created_at: Math.floor(Date.now() / 1000),
        tags: [],
        pubkey: publicKey, // Already the x-only coordinate without prefix
      };
      
      const serializedEvent = serializeEvent(event);
      const eventHashBytes = await nobleSecp256k1.utils.sha256(b4a.from(serializedEvent, 'utf8'));
      event.id = NostrUtils.bytesToHex(eventHashBytes);
      
      // Sign the event - schnorr.sign returns Uint8Array
      const signatureBytes = await nobleSecp256k1.schnorr.sign(event.id, privateKey);
      event.sig = NostrUtils.bytesToHex(signatureBytes);
      
      console.log('Initialized event (before publishing):', JSON.stringify(event, null, 2));
      console.log('Serialized event:', serializedEvent);
      console.log('Event hash:', event.id);
      
      return this.relay.publishEvent(event);
    }

    async listAllEvents() {
      try {
        await acquireFileLock(`${this.storageDir}-read`);
        
        let count = 0;
        const events = [];
        for await (const node of this.relay.createReadStream()) {
          try {
            const event = JSON.parse(node.value);
            events.push({
              id: node.key.toString('hex'),
              event
            });
            count++;
          } catch (error) {
            console.error('Error parsing event:', error);
          }
        }
        console.log(`Total events: ${count}`);
        
        releaseFileLock(`${this.storageDir}-read`);
        return events;
      } catch (error) {
        releaseFileLock(`${this.storageDir}-read`);
        console.error(`Error listing events: ${error.message}`);
        return [];
      }
    }

    async verifyEvent(event) {
      const isValid = validateEvent(event) && await verifyEventSignature(event);
      return isValid;
    }

    async publishEvent(event) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      
      if (!validateEvent(event)) {
        throw new Error('Invalid event format');
      }
      
      try {
        await acquireFileLock(`${this.storageDir}-write`);
        const result = await this.relay.publishEvent(event);
        releaseFileLock(`${this.storageDir}-write`);
        return result;
      } catch (error) {
        releaseFileLock(`${this.storageDir}-write`);
        throw error;
      }
    }

    async getEvent(eventId) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      
      try {
        await acquireFileLock(`${this.storageDir}-read`);
        const result = await this.relay.getEvent(eventId);
        releaseFileLock(`${this.storageDir}-read`);
        return result;
      } catch (error) {
        releaseFileLock(`${this.storageDir}-read`);
        throw error;
      }
    }

    async queryEvents(filters) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      
      try {
        await acquireFileLock(`${this.storageDir}-read`);
        const result = await this.relay.queryEvents(filters);
        releaseFileLock(`${this.storageDir}-read`);
        return result;
      } catch (error) {
        releaseFileLock(`${this.storageDir}-read`);
        throw error;
      }
    }

    async deleteEvent(eventId) {
      if (!this.relay) {
        throw new Error('Relay not initialized');
      }
      
      try {
        await acquireFileLock(`${this.storageDir}-write`);
        const result = await this.relay.deleteEvent(eventId);
        releaseFileLock(`${this.storageDir}-write`);
        return result;
      } catch (error) {
        releaseFileLock(`${this.storageDir}-write`);
        throw error;
      }
    }

    getPublicKey() {
      return b4a.toString(this.relay.key, 'hex');
    }

    async flushSubscriptionQueue(subscriptionId) {
      try {
        await acquireFileLock(`${this.storageDir}-flush`);
        const result = await this.relay.flushSubscriptionQueue(subscriptionId);
        releaseFileLock(`${this.storageDir}-flush`);
        return result;
      } catch (error) {
        releaseFileLock(`${this.storageDir}-flush`);
        throw error;
      }
    }

    async close() {
      try {
        // Acquire lock for cleanup
        await acquireFileLock(`${this.storageDir}-close`);
        console.log(`Closing relay for ${this.storageDir}`);
        
        if (this.relay) {
          await this.relay.close();
        }
        if (this.swarm) {
          await this.swarm.destroy();
        }
        
        // Release lock when done
        releaseFileLock(`${this.storageDir}-close`);
        console.log(`Released lock for ${this.storageDir}`);
      } catch (error) {
        releaseFileLock(`${this.storageDir}-close`);
        console.error(`Error closing relay: ${error.message}`);
        throw error;
      }
    }
}

// Generate a random public key (potentially used for testing)
export function generateRandomPubkey() {
  const privateKey = NostrUtils.generatePrivateKey(); // Returns hex string
  const publicKey = NostrUtils.getPublicKey(privateKey); // Returns hex string (x-only)
  return publicKey; // Already the correct format, no need to slice
}
