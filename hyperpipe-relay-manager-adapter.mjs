// ./relay-worker/hyperpipe-relay-manager-adapter.mjs
// Adapter to integrate legacy RelayManager functionality into Pear worker

import { promises as fs } from 'node:fs';
import { join } from 'node:path';
import nodeCrypto from 'node:crypto';
import hypercoreCrypto from 'hypercore-crypto';
import Hypercore from 'hypercore';
import hypercoreCaps from 'hypercore/lib/caps.js';
import Corestore from 'corestore';
import HypercoreId from 'hypercore-id-encoding';
import { NostrUtils } from './nostr-utils.js';
import b4a from 'b4a';
import { getRelayCorestore } from './hyperdrive-manager.mjs';

// Import the legacy modules (adapted to run in a pure Node/Electron environment)
import { RelayManager } from './hyperpipe-relay-manager.mjs';
import { 
    initRelayProfilesStorage, 
    getAllRelayProfiles, 
    getRelayProfileByKey,
    calculateAuthorizedUsers, // NEW IMPORT
    saveRelayProfile, 
    removeRelayProfile,
importLegacyRelayProfiles,
updateRelayMemberSets,
calculateMembers
} from './hyperpipe-relay-profile-manager.mjs';

import { ChallengeManager } from './challenge-manager.mjs';
import { normalizeRelayIdentifier } from './relay-identifier-utils.mjs';

const { DEFAULT_NAMESPACE } = hypercoreCaps;
const FAST_FORWARD_JOIN_TIMEOUT_MS = 30000;

// Store active relay managers
const activeRelays = new Map();
const virtualRelayKeys = new Set();
const AUTO_CONNECT_REHYDRATION_TIMEOUT_MS = 60000;

// Store relay members keyed by relay key or public identifier
const relayMembers = new Map();
const relayMemberAdds = new Map();
const relayMemberRemoves = new Map();

// Mapping between public identifiers and internal relay keys
const publicToKey = new Map();
const keyToPublic = new Map();

function parseRelayMetadataEvent(event) {
    if (!event) return null;

    const tags = Array.isArray(event.tags) ? event.tags : [];
    const findTagValue = (key) => {
        const tag = tags.find((t) => t[0] === key && t.length > 1);
        return tag ? tag[1] : null;
    };

    const metadata = {
        name: findTagValue('name'),
        description: findTagValue('about'),
        avatarUrl: null,
        isPublic: null,
        createdAt: event.created_at || null,
        updatedAt: event.created_at ? event.created_at * 1000 : null,
        identifier: findTagValue('d') || null,
        eventId: event.id || null
    };

    const pictureTag = tags.find((t) => t[0] === 'picture' && t.length > 1 && typeof t[1] === 'string');
    if (pictureTag) {
        metadata.avatarUrl = pictureTag[1];
    }

    if (tags.some((t) => t[0] === 'public')) {
        metadata.isPublic = true;
    } else if (tags.some((t) => t[0] === 'private')) {
        metadata.isPublic = false;
    }

    return metadata;
}

function decodeWriterKey(value) {
    if (!value) return null;
    if (Buffer.isBuffer(value)) return value;
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
        }
    }
    return null;
}

function normalizeFastForwardCheckpoint(checkpoint) {
    if (!checkpoint || typeof checkpoint !== 'object') return null;
    const key = decodeWriterKey(
        checkpoint.key ||
        checkpoint.coreKey ||
        checkpoint.relayKey ||
        checkpoint.bootstrapKey ||
        null
    );
    if (!key) return null;
    const timeout =
        Number.isFinite(checkpoint.timeoutMs)
            ? checkpoint.timeoutMs
            : Number.isFinite(checkpoint.timeout)
                ? checkpoint.timeout
                : null;
    const length = Number.isFinite(checkpoint.length) ? checkpoint.length : null;
    const signedLength = Number.isFinite(checkpoint.signedLength) ? checkpoint.signedLength : null;
    return {
        key,
        timeout: timeout ?? undefined,
        length,
        signedLength,
        source: checkpoint.source || null
    };
}

async function applyFastForwardCheckpoint({ relayManager, relayKey, checkpoint, reason = 'join' } = {}) {
    const relay = relayManager?.relay || null;
    if (!relay) {
        return { status: 'skipped', reason: 'missing-relay' };
    }
    if (!checkpoint?.key) {
        return { status: 'skipped', reason: 'missing-checkpoint' };
    }

    const supportsFastForward = typeof relay.initialFastForward === 'function';
    const systemKey = relay?.system?.core?.key || null;
    const checkpointKeyHex = b4a.toString(checkpoint.key, 'hex');
    const systemKeyHex = systemKey ? b4a.toString(systemKey, 'hex') : null;
    const keyMatchesSystem = systemKey ? b4a.equals(systemKey, checkpoint.key) : null;
    const fastForwarding = typeof relay.fastForwarding === 'number' ? relay.fastForwarding : null;
    const fastForwardTo = relay.fastForwardTo ? b4a.toString(relay.fastForwardTo.key, 'hex') : null;

    console.log('[RelayAdapter] Fast-forward checkpoint request', {
        relayKey,
        reason,
        checkpointKey: checkpointKeyHex ? checkpointKeyHex.slice(0, 16) : null,
        systemKey: systemKeyHex ? systemKeyHex.slice(0, 16) : null,
        keyMatchesSystem,
        hasMethod: supportsFastForward,
        fastForwarding,
        fastForwardTo: fastForwardTo ? fastForwardTo.slice(0, 16) : null,
        length: checkpoint.length ?? null,
        signedLength: checkpoint.signedLength ?? null
    });

    if (!supportsFastForward) {
        return { status: 'skipped', reason: 'unsupported' };
    }

    if (systemKey && keyMatchesSystem === false) {
        const pendingFastForward = relay.fastForwardTo?.key ? b4a.toString(relay.fastForwardTo.key, 'hex').slice(0, 16) : null;
        console.warn('[RelayAdapter] Fast-forward checkpoint mismatch (deferring)', {
            relayKey,
            reason,
            checkpointKey: checkpointKeyHex ? checkpointKeyHex.slice(0, 16) : null,
            systemKey: systemKeyHex ? systemKeyHex.slice(0, 16) : null,
            length: checkpoint.length ?? null,
            signedLength: checkpoint.signedLength ?? null,
            fastForwardTo: pendingFastForward
        });
        return {
            status: 'skipped',
            reason: 'key-mismatch',
            keyMatchesSystem: false
        };
    }

    const timeoutMs = Number.isFinite(checkpoint.timeout) ? checkpoint.timeout : FAST_FORWARD_JOIN_TIMEOUT_MS;
    const start = Date.now();
    try {
        await relay.initialFastForward(checkpoint.key, timeoutMs);
        return {
            status: 'ok',
            elapsedMs: Date.now() - start,
            keyMatchesSystem
        };
    } catch (error) {
        return {
            status: 'error',
            elapsedMs: Date.now() - start,
            keyMatchesSystem,
            error: error?.message || error
        };
    }
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

function normalizeCoreRef(value) {
    if (!value) return null;
    if (value && typeof value === 'object') {
        if (value.key) return normalizeCoreRef(value.key);
        if (value.core) return normalizeCoreRef(value.core);
    }
    const decoded = decodeWriterKey(value);
    if (!decoded) return null;
    try {
        return HypercoreId.encode(decoded);
    } catch (_) {
        return null;
    }
}

function normalizeCoreRefs(coreRefs) {
    if (!Array.isArray(coreRefs)) return [];
    const normalized = [];
    const seen = new Set();
    for (const ref of coreRefs) {
        const normalizedRef = normalizeCoreRef(ref);
        if (!normalizedRef || seen.has(normalizedRef)) continue;
        seen.add(normalizedRef);
        normalized.push(normalizedRef);
    }
    return normalized;
}

function mergeCoreRefLists(...lists) {
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

let localCorestoreCounter = 0;

function ensureLocalCorestoreId(store) {
    if (!store) return null;
    if (!store.__ht_id) {
        localCorestoreCounter += 1;
        store.__ht_id = `local-corestore-${localCorestoreCounter}`;
    }
    return store.__ht_id;
}

function createLocalCorestore(storageDir, relayKey = null) {
    if (!storageDir) return null;
    const store = new Corestore(storageDir);
    ensureLocalCorestoreId(store);
    store.__ht_storage_path = storageDir;
    if (relayKey) {
        store.__ht_relay_key = relayKey;
    }
    return store;
}

function sanitizeBlindPeerMeta(blindPeer) {
    if (!blindPeer || typeof blindPeer !== 'object') return null;
    const entry = {};
    if (blindPeer.publicKey) entry.publicKey = String(blindPeer.publicKey);
    if (blindPeer.encryptionKey) entry.encryptionKey = String(blindPeer.encryptionKey);
    if (blindPeer.replicationTopic) entry.replicationTopic = String(blindPeer.replicationTopic);
    if (Number.isFinite(blindPeer.maxBytes)) entry.maxBytes = blindPeer.maxBytes;
    return Object.keys(entry).length ? entry : null;
}

function collectActiveWriterSample(relayManager, limit = 4) {
    const writers = relayManager?.relay?.activeWriters;
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

function validateWriterSecret(
    writerSecret,
    { writerCore = null, expectedWriterKey = null, manifestVersion = 0 } = {}
) {
    if (!writerSecret) {
        return { valid: false, expectedWriterKey: expectedWriterKey || null };
    }

    let expectedKey = null;
    if (writerCore) {
        expectedKey = decodeWriterKey(writerCore);
    }
    if (!expectedKey && expectedWriterKey) {
        expectedKey = decodeWriterKey(expectedWriterKey);
    }
    if (!expectedKey) {
        return { valid: false, expectedWriterKey: null };
    }

    const secretHex = String(writerSecret).trim();
    if (!/^[0-9a-fA-F]+$/.test(secretHex)) {
        return { valid: false, expectedWriterKey: expectedKey };
    }

    let secretKey = null;
    try {
        secretKey = Buffer.from(secretHex, 'hex');
    } catch (_) {
        return { valid: false, expectedWriterKey: expectedKey };
    }

    if (!secretKey || secretKey.length < 32) {
        return { valid: false, expectedWriterKey: expectedKey };
    }

    const seedCandidates = [];
    if (secretKey.length >= 32) seedCandidates.push(secretKey.subarray(0, 32));

    const matchesExpectedKey = (publicKey) => {
        if (!publicKey || !expectedKey) return false;
        if (b4a.equals(publicKey, expectedKey)) return true;
        const { key: derivedKey } = deriveCoreKeyFromSignerKey(publicKey, manifestVersion);
        return derivedKey ? b4a.equals(derivedKey, expectedKey) : false;
    };

    for (const seed of seedCandidates) {
        try {
            const candidate = hypercoreCrypto.keyPair(seed);
            if (candidate?.publicKey && matchesExpectedKey(candidate.publicKey)) {
                return { valid: true, expectedWriterKey: expectedKey };
            }
        } catch (_) {
            // try next seed
        }
    }

    if (secretKey.length === 64) {
        const candidatePublic = secretKey.subarray(32, 64);
        if (matchesExpectedKey(candidatePublic)) {
            const candidate = { publicKey: candidatePublic, secretKey };
            if (hypercoreCrypto.validateKeyPair(candidate)) {
                return { valid: true, expectedWriterKey: expectedKey };
            }
        }
    }

    return { valid: false, expectedWriterKey: expectedKey };
}

function snapshotWriterMaterial(source = {}) {
    return {
        writer_secret: source.writer_secret ?? source.writerSecret ?? null,
        writer_core: source.writer_core ?? source.writerCore ?? null,
        writer_core_hex: source.writer_core_hex ?? source.writerCoreHex ?? null,
        autobase_local: source.autobase_local ?? source.autobaseLocal ?? null
    };
}

function logWriterMaterialChange({ stage, relayKey, before, after, extra = {} } = {}) {
    console.log('[RelayAdapter][WriterMaterial] change', {
        stage,
        relayKey,
        before: before || null,
        after: after || null,
        ...extra
    });
}

function resolveCoreKeyMaterial(core) {
    if (!core) {
        return {
            coreKey: null,
            signerKey: null,
            coreKeyHex: null,
            signerKeyHex: null,
            writerKey: null,
            writerCore: null,
            writerCoreSource: null,
            coreMatchesSigner: null
        };
    }

    const coreKey = decodeWriterKey(core.key || null);
    const signerKey = decodeWriterKey(core.keyPair?.publicKey || null);
    const coreKeyHex = coreKey ? b4a.toString(coreKey, 'hex') : null;
    const signerKeyHex = signerKey ? b4a.toString(signerKey, 'hex') : null;
    const writerKey = signerKey || coreKey || null;
    let writerCore = null;
    if (writerKey) {
        try {
            writerCore = HypercoreId.encode(writerKey);
        } catch (_) {
            writerCore = null;
        }
    }
    const writerCoreSource = signerKey ? 'signer' : coreKey ? 'core' : null;
    const coreMatchesSigner = coreKey && signerKey ? b4a.equals(coreKey, signerKey) : null;

    return {
        coreKey,
        signerKey,
        coreKeyHex,
        signerKeyHex,
        writerKey,
        writerCore,
        writerCoreSource,
        coreMatchesSigner
    };
}

function buildWriterCandidateFromCore(core, label) {
    if (!core) return null;
    const keyInfo = resolveCoreKeyMaterial(core);
    const autobaseLocal = keyInfo.coreKeyHex;
    const secretKey = core.keyPair?.secretKey || core.secretKey || null;
    const writerSecret = secretKey
        ? (typeof secretKey === 'string' ? secretKey : b4a.toString(secretKey, 'hex'))
        : null;

    if (keyInfo.coreKeyHex && keyInfo.signerKeyHex && keyInfo.coreMatchesSigner === false) {
        console.warn('[RelayAdapter][WriterMaterial] Core key differs from signer key', {
            label,
            coreKeyHex: keyInfo.coreKeyHex,
            signerKeyHex: keyInfo.signerKeyHex
        });
    } else if (!keyInfo.coreKeyHex && keyInfo.signerKeyHex) {
        console.warn('[RelayAdapter][WriterMaterial] Missing core key for writer candidate', {
            label,
            signerKeyHex: keyInfo.signerKeyHex
        });
    }

    return {
        label,
        writerSecret,
        writerCore: keyInfo.writerCore,
        autobaseLocal,
        coreKeyHex: keyInfo.coreKeyHex,
        signerKeyHex: keyInfo.signerKeyHex,
        writerCoreSource: keyInfo.writerCoreSource,
        coreMatchesSigner: keyInfo.coreMatchesSigner
    };
}

function collectWriterMaterialCandidates(relayManager) {
    const candidates = [];
    const addCandidate = (core, label) => {
        const candidate = buildWriterCandidateFromCore(core, label);
        if (candidate) candidates.push(candidate);
    };
    addCandidate(relayManager?.relay?.localWriter?.core || null, 'localWriter');
    addCandidate(relayManager?.relay?.local || null, 'local');
    const relayCore = relayManager?.relay?.core || null;
    if (relayCore && relayCore !== relayManager?.relay?.local) {
        addCandidate(relayCore, 'relayCore');
    }
    return candidates;
}

function selectValidWriterMaterial(candidates, { relayKey = null, stage = null } = {}) {
    const inspected = [];
    let selected = null;
    let fallback = null;

    for (const candidate of candidates) {
        if (!candidate) continue;
        if (!fallback && candidate.autobaseLocal) fallback = candidate;
        const validation = validateWriterSecret(candidate.writerSecret, {
            writerCore: candidate.writerCore || candidate.autobaseLocal
        });
        inspected.push({
            label: candidate.label,
            writerCore: candidate.writerCore,
            autobaseLocal: candidate.autobaseLocal,
            writerCoreSource: candidate.writerCoreSource,
            coreKeyHex: candidate.coreKeyHex,
            signerKeyHex: candidate.signerKeyHex,
            coreMatchesSigner: candidate.coreMatchesSigner,
            hasWriterSecret: !!candidate.writerSecret,
            writerSecretLen: candidate.writerSecret ? candidate.writerSecret.length : 0,
            valid: validation.valid
        });
        if (validation.valid && !selected) {
            selected = candidate;
        }
    }

    if (stage) {
        console.log('[RelayAdapter][WriterMaterial] candidate selection', {
            stage,
            relayKey,
            inspected,
            selected: selected ? selected.label : null,
            fallback: fallback ? fallback.label : null
        });
    }

    return { selected, fallback, inspected };
}

function applyJoinMetadata(profile, {
    writerSecret = null,
    writerCore = null,
    expectedWriterKey = null,
    relayManager = null,
    blindPeer = null,
    coreRefs = null
} = {}) {
    const updated = { ...profile };
    const localKeyHex = relayManager?.relay?.local?.key
        ? b4a.toString(relayManager.relay.local.key, 'hex')
        : null;
    const expectedWriterKeyBuffer = decodeWriterKey(expectedWriterKey);
    const expectedHexFull = expectedWriterKeyBuffer
        ? b4a.toString(expectedWriterKeyBuffer, 'hex')
        : null;
    const resolvedCoreKeyHex = expectedHexFull || localKeyHex || null;
    const normalizedRefs = normalizeCoreRefs(coreRefs);
    const existingRefs = normalizeCoreRefs(profile.core_refs || profile.coreRefs);
    const mergedRefs = mergeCoreRefLists(existingRefs, normalizedRefs);
    const blindPeerMeta = sanitizeBlindPeerMeta(blindPeer);

    const existingExpectedKey = decodeWriterKey(
        profile.writer_core ||
        profile.writerCore ||
        profile.writer_core_hex ||
        profile.autobase_local ||
        null
    );
    const existingWriterValid = validateWriterSecret(profile.writer_secret || profile.writerSecret, {
        expectedWriterKey: existingExpectedKey
    }).valid;
    const incomingWriterValid = validateWriterSecret(writerSecret, {
        writerCore,
        expectedWriterKey
    }).valid;

    const shouldUpdateWriterMaterial = incomingWriterValid && !existingWriterValid;

    const beforeWriterSnapshot = shouldUpdateWriterMaterial ? snapshotWriterMaterial(profile) : null;

    if (writerSecret && shouldUpdateWriterMaterial) updated.writer_secret = writerSecret;
    if (writerCore && shouldUpdateWriterMaterial) updated.writer_core = writerCore;
    if (resolvedCoreKeyHex && shouldUpdateWriterMaterial) updated.writer_core_hex = resolvedCoreKeyHex;
    if (resolvedCoreKeyHex && shouldUpdateWriterMaterial) updated.autobase_local = resolvedCoreKeyHex;
    if (blindPeerMeta) updated.blind_peer = blindPeerMeta;
    if (mergedRefs.length) updated.core_refs = mergedRefs;

    if (
        (writerSecret && shouldUpdateWriterMaterial) ||
        (writerCore && shouldUpdateWriterMaterial) ||
        (resolvedCoreKeyHex && shouldUpdateWriterMaterial) ||
        blindPeerMeta ||
        mergedRefs.length
    ) {
        updated.updated_at = new Date().toISOString();
    }

    if (shouldUpdateWriterMaterial && expectedHexFull && !resolvedCoreKeyHex) {
        console.warn('[RelayAdapter][WriterMaterial] Skipping writer_core_hex update; core key unavailable', {
            relayKey: profile.relay_key || profile.relayKey || relayManager?.relay?.key || null,
            expectedWriterHex: expectedHexFull
        });
    }

    if (shouldUpdateWriterMaterial) {
        const afterWriterSnapshot = snapshotWriterMaterial(updated);
        logWriterMaterialChange({
            stage: 'join-metadata-update',
            relayKey: profile.relay_key || profile.relayKey || relayManager?.relay?.key || null,
            before: beforeWriterSnapshot,
            after: afterWriterSnapshot,
            extra: {
                incomingWriterValid,
                existingWriterValid,
                expectedWriterKey: expectedHexFull,
                expectedWriterKeyRaw: expectedWriterKeyBuffer ? b4a.toString(expectedWriterKeyBuffer, 'hex') : expectedWriterKey || null,
                resolvedCoreKeyHex,
                localKeyHex
            }
        });
    }

    return updated;
}

function extractLocalWriterProfileFields(relayManager) {
    const core = relayManager?.relay?.localWriter?.core
        || relayManager?.relay?.local
        || relayManager?.relay?.core
        || null;
    if (!core) {
        return { writerSecret: null, writerCore: null, autobaseLocal: null };
    }

    const keyInfo = resolveCoreKeyMaterial(core);
    const autobaseLocal = keyInfo.coreKeyHex;
    const writerCore = keyInfo.writerCore;

    const secretKey = core.keyPair?.secretKey || core.secretKey || null;
    const writerSecret = secretKey
        ? (typeof secretKey === 'string' ? secretKey : b4a.toString(secretKey, 'hex'))
        : null;

    return {
        writerSecret,
        writerCore,
        autobaseLocal,
        coreKeyHex: keyInfo.coreKeyHex,
        signerKeyHex: keyInfo.signerKeyHex,
        writerCoreSource: keyInfo.writerCoreSource,
        coreMatchesSigner: keyInfo.coreMatchesSigner
    };
}

async function recoverLocalWriterMaterial({ relayKey, profile, config, preferBootstrapLocal = false }) {
    const attempts = [];
    if (profile?.relay_storage) {
        const localStore = createLocalCorestore(profile.relay_storage, relayKey);
        if (localStore) {
            attempts.push({ source: 'local-storage', store: localStore });
        }
    }

    const sharedStore = getRelayCorestore(relayKey, { storageBase: config?.storage || null });
    if (sharedStore && typeof sharedStore.get === 'function') {
        attempts.push({ source: 'shared-storage', store: sharedStore });
    }

    const profileAutobaseKey = decodeWriterKey(profile?.autobase_local || null);
    const profileCoreHexKey = decodeWriterKey(profile?.writer_core_hex || null);
    const profileWriterCoreKey = decodeWriterKey(profile?.writer_core || profile?.writerCore || null);
    let localKey = profileAutobaseKey || profileCoreHexKey || null;
    const profileLocalKey = localKey;
    const legacyWriterCoreKey = !localKey && profileWriterCoreKey ? profileWriterCoreKey : null;

    if (!localKey) {
        console.warn('[RelayAdapter][WriterMaterial] No autobase local key stored; will rely on bootstrap lookup', {
            relayKey,
            hasWriterCore: !!profileWriterCoreKey,
            hasWriterCoreHex: !!profileCoreHexKey
        });
    }

    for (const attempt of attempts) {
        const relayCorestore = attempt.store;
        if (!relayCorestore || typeof relayCorestore.get !== 'function') continue;

        let resolvedLocalKey = localKey;
        if (preferBootstrapLocal || !resolvedLocalKey) {
            const bootstrapKey = decodeWriterKey(relayKey);
            if (bootstrapKey) {
                try {
                    const bootstrapCore = relayCorestore.get({ key: bootstrapKey, compat: false, active: false });
                    await bootstrapCore.ready();
                    const storedLocal = await bootstrapCore.getUserData('autobase/local');
                    if (storedLocal) {
                        const bootstrapHex = b4a.toString(storedLocal, 'hex');
                        const profileHex = resolvedLocalKey ? b4a.toString(resolvedLocalKey, 'hex') : null;
                        if (!resolvedLocalKey || !b4a.equals(storedLocal, resolvedLocalKey)) {
                            console.warn('[RelayAdapter] Autobase local key mismatch; preferring bootstrap local', {
                                relayKey,
                                source: attempt.source,
                                preferBootstrapLocal,
                                profileAutobaseLocal: profileHex,
                                bootstrapAutobaseLocal: bootstrapHex
                            });
                        }
                        resolvedLocalKey = storedLocal;
                    }
                } catch (error) {
                    console.warn('[RelayAdapter] Failed to read autobase/local metadata for writer recovery', {
                        relayKey,
                        source: attempt.source,
                        error: error?.message || error
                    });
                }
            }
        }

        if (!resolvedLocalKey && legacyWriterCoreKey) {
            resolvedLocalKey = legacyWriterCoreKey;
            console.warn('[RelayAdapter][WriterMaterial] Falling back to writer_core as autobase local key (legacy profile)', {
                relayKey,
                source: attempt.source,
                writerCoreHex: b4a.toString(legacyWriterCoreKey, 'hex')
            });
        }

        if (!resolvedLocalKey) continue;

        try {
            const localCore = relayCorestore.get({ key: resolvedLocalKey, compat: false, active: false });
            await localCore.ready();
            const secretKey = localCore?.keyPair?.secretKey || localCore?.secretKey || null;
            if (!secretKey) {
                continue;
            }
            const writerSecret = typeof secretKey === 'string' ? secretKey : b4a.toString(secretKey, 'hex');
            const autobaseLocal = b4a.toString(resolvedLocalKey, 'hex');
            const keyInfo = resolveCoreKeyMaterial(localCore);
            let writerCore = keyInfo.writerCore;
            let writerCoreSource = keyInfo.writerCoreSource;
            let signerKeyHex = keyInfo.signerKeyHex;

            if (!writerCore && secretKey) {
                const secretBuf = Buffer.isBuffer(secretKey) ? secretKey : Buffer.from(secretKey);
                if (secretBuf.length >= 32) {
                    try {
                        const candidate = hypercoreCrypto.keyPair(secretBuf.subarray(0, 32));
                        if (candidate?.publicKey) {
                            writerCore = HypercoreId.encode(candidate.publicKey);
                            signerKeyHex = b4a.toString(candidate.publicKey, 'hex');
                            writerCoreSource = 'derived-secret';
                        }
                    } catch (_) {
                        // ignore
                    }
                }
            }

            const usedLegacyWriterCore = legacyWriterCoreKey && resolvedLocalKey
                ? b4a.equals(resolvedLocalKey, legacyWriterCoreKey)
                : false;
            console.log('[RelayAdapter][WriterMaterial] Recovered local writer core material', {
                relayKey,
                source: attempt.source,
                resolvedLocalKey: autobaseLocal,
                coreKeyHex: keyInfo.coreKeyHex,
                signerKeyHex,
                writerCoreSource,
                coreMatchesSigner: keyInfo.coreMatchesSigner,
                usedLegacyWriterCore
            });
            return {
                writerSecret,
                writerCore,
                autobaseLocal,
                source: attempt.source,
                corestore: relayCorestore,
                preferBootstrapLocal,
                profileAutobaseLocal: profileLocalKey ? b4a.toString(profileLocalKey, 'hex') : null,
                coreKeyHex: keyInfo.coreKeyHex,
                signerKeyHex,
                writerCoreSource,
                coreMatchesSigner: keyInfo.coreMatchesSigner,
                usedLegacyWriterCore
            };
        } catch (error) {
            console.warn('[RelayAdapter] Failed to recover local writer material from corestore', {
                relayKey,
                source: attempt.source,
                error: error?.message || error
            });
        }
    }

    return null;
}

export async function getRelayMetadata(relayKey, publicIdentifier = null) {
    const manager = activeRelays.get(relayKey);
    if (!manager || typeof manager.queryEvents !== 'function') {
        return null;
    }

    try {
        const filter = { kinds: [39000], limit: 50 };
        if (publicIdentifier) {
            filter['#d'] = [publicIdentifier];
        }

        const events = await manager.queryEvents(filter);
        if (!Array.isArray(events) || events.length === 0) {
            return null;
        }

        events.sort((a, b) => (b?.created_at || 0) - (a?.created_at || 0));
        const latest = events[0];
        const parsed = parseRelayMetadataEvent(latest);
        if (parsed && !parsed.identifier && publicIdentifier) {
            parsed.identifier = publicIdentifier;
        }
        return parsed;
    } catch (error) {
        console.error(`[RelayAdapter] Failed to load metadata for relay ${relayKey}:`, error);
        return null;
    }
}

function getGatewayWebsocketProtocol(config) {
    return config?.proxy_websocket_protocol === 'ws' ? 'ws' : 'wss';
}

function buildGatewayWebsocketBase(config) {
    const protocol = getGatewayWebsocketProtocol(config);
    const host = config?.proxy_server_address || 'localhost';
    return `${protocol}://${host}`;
}

function buildRelayConnectionUrls(config, { relayKey, publicIdentifier = null, authToken = null } = {}) {
    const normalizedIdentifier = normalizeRelayIdentifier(publicIdentifier || '') || (publicIdentifier || relayKey || '');
    const identifierPath = normalizedIdentifier.includes(':')
        ? normalizedIdentifier.replace(':', '/')
        : normalizedIdentifier;
    const baseUrl = `${buildGatewayWebsocketBase(config)}/${identifierPath}`;
    const token = typeof authToken === 'string' ? authToken.trim() : '';
    const connectionUrl = token ? `${baseUrl}?token=${token}` : baseUrl;
    return { baseUrl, connectionUrl, identifierPath };
}

export function setRelayMapping(relayKey, publicIdentifier) {
    if (!relayKey) return;
    if (publicIdentifier) {
        publicToKey.set(publicIdentifier, relayKey);
        keyToPublic.set(relayKey, publicIdentifier);
    } else {
        const existing = keyToPublic.get(relayKey);
        if (existing) publicToKey.delete(existing);
        keyToPublic.delete(relayKey);
    }
}

export function removeRelayMapping(relayKey, publicIdentifier) {
    const pid = publicIdentifier || keyToPublic.get(relayKey);
    if (pid) publicToKey.delete(pid);
    if (relayKey) keyToPublic.delete(relayKey);
}

export async function loadRelayKeyMappings() {
    await ensureProfilesInitialized(globalUserKey);
    publicToKey.clear();
    keyToPublic.clear();
    const profiles = await getAllRelayProfiles(globalUserKey);
    for (const p of profiles) {
        if (p.relay_key && p.public_identifier) {
            publicToKey.set(p.public_identifier, p.relay_key);
            keyToPublic.set(p.relay_key, p.public_identifier);
        }
    }
    return { publicToKey, keyToPublic };
}

export function setRelayMembers(relayKey, members = [], adds = null, removes = null) {
    relayMembers.set(relayKey, members);
    if (adds) relayMemberAdds.set(relayKey, adds);
    if (removes) relayMemberRemoves.set(relayKey, removes);
}

export function registerVirtualRelay(relayKey, manager, options = {}) {
    if (!relayKey) {
        throw new Error('relayKey is required to register a virtual relay');
    }
    if (!manager || typeof manager.handleMessage !== 'function') {
        throw new Error('manager with handleMessage implementation is required for virtual relay');
    }

    const {
        publicIdentifier = relayKey,
        members = [],
        metadata = {},
        logger = console
    } = options;

    const existing = activeRelays.get(relayKey);
    if (existing && existing !== manager) {
        try {
            existing.close?.();
        } catch (error) {
            logger?.warn?.('[RelayAdapter][VirtualRelay] Failed to close existing manager', {
                relayKey,
                error: error?.message
            });
        }
    }

    activeRelays.set(relayKey, manager);
    virtualRelayKeys.add(relayKey);

    setRelayMapping(relayKey, publicIdentifier);
    setRelayMembers(relayKey, members);
    relayMemberAdds.set(relayKey, []);
    relayMemberRemoves.set(relayKey, []);
    if (publicIdentifier && publicIdentifier !== relayKey) {
        setRelayMembers(publicIdentifier, members);
        relayMemberAdds.set(publicIdentifier, []);
        relayMemberRemoves.set(publicIdentifier, []);
    }

    logger?.info?.('[RelayAdapter][VirtualRelay] Registered virtual relay', {
        relayKey,
        publicIdentifier,
        metadata
    });

    return {
        relayKey,
        publicIdentifier,
        metadata
    };
}

export async function unregisterVirtualRelay(relayKey, options = {}) {
    if (!relayKey) return;

    const { publicIdentifier = keyToPublic.get(relayKey), logger = console } = options;

    const manager = activeRelays.get(relayKey);
    if (manager) {
        try {
            await manager.close?.();
        } catch (error) {
            logger?.warn?.('[RelayAdapter][VirtualRelay] Failed to close virtual relay manager', {
                relayKey,
                error: error?.message
            });
        }
        activeRelays.delete(relayKey);
    }

    if (virtualRelayKeys.has(relayKey)) {
        virtualRelayKeys.delete(relayKey);
    }

    removeRelayMapping(relayKey, publicIdentifier);
    relayMembers.delete(relayKey);
    relayMemberAdds.delete(relayKey);
    relayMemberRemoves.delete(relayKey);
    if (publicIdentifier) {
        relayMembers.delete(publicIdentifier);
        relayMemberAdds.delete(publicIdentifier);
        relayMemberRemoves.delete(publicIdentifier);
    }

    logger?.info?.('[RelayAdapter][VirtualRelay] Unregistered virtual relay', {
        relayKey,
        publicIdentifier
    });
}

// Store config reference
let globalConfig = null;
let globalUserKey = null;

// Initialize profile storage on module load
let profilesInitialized = false;

async function ensureProfilesInitialized(userKey = null) {
    if (!profilesInitialized) {
        await initRelayProfilesStorage(userKey || globalUserKey);
        profilesInitialized = true;
    }
}

/**
 * Create a new relay
 * @param {Object} options - Creation options
 * @param {string} options.name - Relay name
 * @param {string} options.description - Relay description
 * @param {string} options.storageDir - Optional storage directory
 * @param {Object} options.config - Configuration object
 * @returns {Promise<Object>} - Result object with relay information
 */
export async function createRelay(options = {}) {
    const { name, description, isPublic = false, isOpen = false, storageDir, config } = options;
    
    // Store config and user key globally if provided
    if (config) {
        globalConfig = config;
        globalUserKey = config.userKey;
    }
    
    try {
        await ensureProfilesInitialized(globalUserKey);
        
        // Generate relay key components
        const timestamp = Date.now();
        const userStorageBase = join(config.storage || './data', 'relays');
        const defaultStorageDir = storageDir || join(userStorageBase, `relay-${timestamp}`);
        
        // Ensure storage directory exists
        await fs.mkdir(defaultStorageDir, { recursive: true });
        
        // Create relay manager instance
        const relayManager = new RelayManager(defaultStorageDir, null);
        await relayManager.initialize();

        const relayKey = relayManager.getPublicKey();
        activeRelays.set(relayKey, relayManager);

        const localWriterInfo = extractLocalWriterProfileFields(relayManager);
        const writerCandidates = collectWriterMaterialCandidates(relayManager);
        const writerSelection = selectValidWriterMaterial(writerCandidates, {
            relayKey,
            stage: 'create-relay'
        });
        const selectedWriterInfo = writerSelection.selected || null;
        const fallbackWriterInfo = writerSelection.fallback || null;
        
        // Generate public identifier
        const npub = config.nostr_npub || (config.nostr_pubkey_hex ? 
            NostrUtils.hexToNpub(config.nostr_pubkey_hex) : null);
        
        const publicIdentifier = npub && name ? 
            generatePublicIdentifier(npub, name) : null;
        
        // Auth token will be generated and added in relay-server.mjs
        // to ensure a single, consistent token source.
        const authToken = null; // No token generated here.
        const auth_adds = []; // Initially empty.
        
        // Create relay profile with both internal and public identifiers
        const profileInfo = {
            name: name || `Relay ${relayKey.substring(0, 8)}`,
            description: description || `Created on ${new Date().toLocaleString()}`,
            nostr_pubkey_hex: config.nostr_pubkey_hex || generateHexKey(),
            admin_pubkey: config.nostr_pubkey_hex || null,
            members: config.nostr_pubkey_hex ? [config.nostr_pubkey_hex] : [],
            member_adds: config.nostr_pubkey_hex ? [{ pubkey: config.nostr_pubkey_hex, ts: Date.now() }] : [],
            member_removes: [],
            relay_nostr_id: null,
            relay_key: relayKey, // Internal key
            public_identifier: publicIdentifier, // New public-facing identifier
            relay_storage: defaultStorageDir,
            created_at: new Date().toISOString(),
            auto_connect: true,
            is_active: true,
            isPublic,
            isOpen,
            auth_config: {
                requiresAuth: true,
                tokenProtected: true,
                authorizedUsers: auth_adds, // This will be recalculated by saveRelayProfile
                auth_adds: auth_adds,
                auth_removes: []
            }
        };

        const beforeWriterSnapshot = snapshotWriterMaterial(profileInfo);

        if (selectedWriterInfo?.writerSecret) {
            profileInfo.writer_secret = selectedWriterInfo.writerSecret;
            if (selectedWriterInfo.writerCore) {
                profileInfo.writer_core = selectedWriterInfo.writerCore;
            } else if (selectedWriterInfo.autobaseLocal) {
                profileInfo.writer_core_hex = selectedWriterInfo.autobaseLocal;
            }
        } else if (fallbackWriterInfo?.autobaseLocal) {
            profileInfo.writer_core_hex = fallbackWriterInfo.autobaseLocal;
        }
        if (selectedWriterInfo?.autobaseLocal) {
            profileInfo.autobase_local = selectedWriterInfo.autobaseLocal;
        } else if (fallbackWriterInfo?.autobaseLocal) {
            profileInfo.autobase_local = fallbackWriterInfo.autobaseLocal;
        }

        const afterWriterSnapshot = snapshotWriterMaterial(profileInfo);
        logWriterMaterialChange({
            stage: 'create-relay-profile',
            relayKey,
            before: beforeWriterSnapshot,
            after: afterWriterSnapshot,
            extra: {
                selectedWriter: selectedWriterInfo ? selectedWriterInfo.label : null,
                selectedWriterMeta: selectedWriterInfo
                    ? {
                        writerCore: selectedWriterInfo.writerCore,
                        autobaseLocal: selectedWriterInfo.autobaseLocal,
                        coreKeyHex: selectedWriterInfo.coreKeyHex,
                        signerKeyHex: selectedWriterInfo.signerKeyHex,
                        writerCoreSource: selectedWriterInfo.writerCoreSource,
                        coreMatchesSigner: selectedWriterInfo.coreMatchesSigner
                    }
                    : null,
                fallbackWriter: fallbackWriterInfo ? fallbackWriterInfo.label : null,
                fallbackWriterMeta: fallbackWriterInfo
                    ? {
                        writerCore: fallbackWriterInfo.writerCore,
                        autobaseLocal: fallbackWriterInfo.autobaseLocal,
                        coreKeyHex: fallbackWriterInfo.coreKeyHex,
                        signerKeyHex: fallbackWriterInfo.signerKeyHex,
                        writerCoreSource: fallbackWriterInfo.writerCoreSource,
                        coreMatchesSigner: fallbackWriterInfo.coreMatchesSigner
                    }
                    : null,
                extractedLocalWriter: snapshotWriterMaterial(localWriterInfo),
                extractedLocalWriterMeta: localWriterInfo
                    ? {
                        coreKeyHex: localWriterInfo.coreKeyHex,
                        signerKeyHex: localWriterInfo.signerKeyHex,
                        writerCoreSource: localWriterInfo.writerCoreSource,
                        coreMatchesSigner: localWriterInfo.coreMatchesSigner
                    }
                    : null
            }
        });

        if (!selectedWriterInfo?.writerSecret) {
            console.warn('[RelayAdapter] Writer material not persisted (invalid or missing); relying on recovery', {
                relayKey,
                selectedWriter: selectedWriterInfo ? selectedWriterInfo.label : null,
                fallbackWriter: fallbackWriterInfo ? fallbackWriterInfo.label : null
            });
        }
        
        // Save relay profile
        const saved = await saveRelayProfile(profileInfo);
        if (!saved) {
            console.log('[RelayAdapter] Warning: Failed to save relay profile');
        }

        // Import auth data to the auth store
        if (authToken && config.nostr_pubkey_hex) {
            const { getRelayAuthStore } = await import('./relay-auth-store.mjs');
            const authStore = getRelayAuthStore();
            
            authStore.addAuth(relayKey, config.nostr_pubkey_hex, authToken);
            if (publicIdentifier) {
                authStore.addAuth(publicIdentifier, config.nostr_pubkey_hex, authToken);
            }
            
            console.log('[RelayAdapter] Added auth token to auth store');
        }

        // Load members into in-memory map
        setRelayMembers(relayKey, profileInfo.members || [], profileInfo.member_adds || [], profileInfo.member_removes || []);
        if (publicIdentifier) {
            setRelayMembers(publicIdentifier, profileInfo.members || [], profileInfo.member_adds || [], profileInfo.member_removes || []);
        }
        
        console.log('[RelayAdapter] Created relay:', relayKey);
        const gatewayBase = buildGatewayWebsocketBase(config);
        console.log(`[RelayAdapter] Connect at: ${gatewayBase}/${relayKey}`);
        
        // Build the authenticated relay URL
        const { baseUrl, connectionUrl: authenticatedUrl } = buildRelayConnectionUrls(config, {
            relayKey,
            publicIdentifier,
            authToken
        });
        
        // Send relay initialized message for newly created relay
        if (global.sendMessage) {
            console.log(`[RelayAdapter] createRelay() -> Sending relay-initialized for ${relayKey} with URL ${authenticatedUrl}`);
            global.sendMessage({
                type: 'relay-initialized',
                relayKey: relayKey, // Internal key for worker
                publicIdentifier: publicIdentifier, // Public identifier for external use
                gatewayUrl: authenticatedUrl,
                name: profileInfo.name,
                isNew: true,
                timestamp: new Date().toISOString()
            });
        }
        
        return {
            success: true,
            relayKey,
            publicIdentifier,
            connectionUrl: baseUrl, // Base URL without token
            authToken: authToken, // Return the token separately
            relayUrl: authenticatedUrl, // Full authenticated URL
            profile: profileInfo,
            storageDir: defaultStorageDir
        };
        
    } catch (error) {
        console.error('[RelayAdapter] Error creating relay:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Helper function to generate public identifier
function generatePublicIdentifier(npub, relayName) {
    const camelCaseName = relayName
        .split(' ')
        .map((word, index) => {
            if (index === 0) {
                return word.toLowerCase();
            }
            return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
        })
        .join('');
    
    return `${npub}:${camelCaseName}`;
}

function emitRelayLoadingEvent({ relayKey, publicIdentifier = null, name = '' }, stage = 'connecting', extra = {}) {
    if (!global.sendMessage) return;
    try {
        const payload = {
            type: 'relay-loading',
            relayKey,
            publicIdentifier,
            name,
            stage,
            timestamp: new Date().toISOString()
        };
        if (typeof extra.totalRelays === 'number') {
            payload.total = extra.totalRelays;
        }
        if (typeof extra.count === 'number') {
            payload.count = extra.count;
        }
        global.sendMessage({
            ...payload
        });
    } catch (error) {
        console.warn('[RelayAdapter] Failed to emit relay-loading event:', error?.message || error);
    }
}

/**
 * Join an existing relay
 * @param {Object} options - Join options
 * @param {string} options.relayKey - The relay key to join
 * @param {string} options.name - Optional name for the relay
 * @param {string} options.description - Optional description
 * @param {string} options.storageDir - Optional storage directory
 * @param {Object} options.config - Configuration object
 * @param {boolean} options.fromAutoConnect - Whether called from auto-connect
 * @returns {Promise<Object>} - Result object with relay information
 */
export async function joinRelay(options = {}) {
    const {
        relayKey,
        name,
        description,
        publicIdentifier,
        authToken = null,
        storageDir,
        config,
        fromAutoConnect = false,
        isOpen = null,
        writerSecret = null,
        writerCore = null,
        writerCoreHex = null,
        autobaseLocal = null,
        expectedWriterKey: expectedWriterOverride = null,
        fastForward = null,
        blindPeer = null,
        coreRefs = null,
        suppressInitMessage = false,
        useSharedCorestore = false,
        corestore = null
    } = options;
    
    // Store config globally if provided
    if (config) {
        globalConfig = config;
        globalUserKey = config.userKey;
    }
    
    if (!relayKey) {
        return {
            success: false,
            error: 'Relay key is required'
        };
    }

    let writerKeyPair = null;
    const writerSignerKey = decodeWriterKey(writerCore);
    const writerSignerHex = writerSignerKey ? b4a.toString(writerSignerKey, 'hex') : null;
    let expectedWriterKey = decodeWriterKey(writerCoreHex || autobaseLocal || expectedWriterOverride || null);
    let expectedWriterHex = expectedWriterKey ? b4a.toString(expectedWriterKey, 'hex') : null;
    let expectedWriterSource = null;
    if (writerCoreHex) {
        expectedWriterSource = 'writerCoreHex';
    } else if (autobaseLocal) {
        expectedWriterSource = 'autobaseLocal';
    } else if (expectedWriterOverride) {
        expectedWriterSource = 'expectedWriterOverride';
    }
    if (!expectedWriterKey && writerSignerKey) {
        expectedWriterKey = writerSignerKey;
        expectedWriterHex = writerSignerHex;
        expectedWriterSource = 'writerCore';
    }
    const expectsCoreKey = expectedWriterSource && expectedWriterSource !== 'writerCore';
    const fastForwardCheckpoint = normalizeFastForwardCheckpoint(fastForward);
    const fastForwardKeyHex = fastForwardCheckpoint?.key
        ? b4a.toString(fastForwardCheckpoint.key, 'hex').slice(0, 16)
        : null;

    console.log('[RelayAdapter][WriterMaterial] Join relay writer expectations', {
        relayKey,
        publicIdentifier,
        writerCore,
        writerCoreHex,
        autobaseLocal,
        expectedWriterOverride,
        writerSignerHex,
        expectedWriterKey: expectedWriterHex,
        expectedWriterSource,
        hasFastForward: !!fastForwardCheckpoint,
        fastForwardKey: fastForwardKeyHex,
        fastForwardLength: fastForwardCheckpoint?.length ?? null,
        fastForwardSignedLength: fastForwardCheckpoint?.signedLength ?? null
    });
    if (!expectedWriterKey && (writerCoreHex || autobaseLocal || expectedWriterOverride)) {
        console.warn('[RelayAdapter][WriterMaterial] Failed to decode expected writer key', {
            relayKey,
            writerCoreHex,
            autobaseLocal,
            expectedWriterOverride
        });
    }

    if (writerSecret) {
        try {
            const secretKey = Buffer.from(String(writerSecret), 'hex');
            const expectedSignerKey = expectsCoreKey ? null : writerSignerKey;
            const expectedSignerHex = expectedSignerKey ? b4a.toString(expectedSignerKey, 'hex') : null;
            const expectedCoreKey = expectsCoreKey ? expectedWriterKey : null;
            const manifestVersion = 0;

            if (expectedSignerKey) {
                console.log('[RelayAdapter] Invite writer signer decoded', {
                    relayKey,
                    writerCore: String(writerCore).slice(0, 16),
                    writerSignerHex: expectedSignerHex ? expectedSignerHex.slice(0, 16) : null
                });
            }

            const seedCandidates = [];
            if (secretKey.length >= 32) seedCandidates.push(secretKey.subarray(0, 32));
            if (secretKey.length === 64 && expectedSignerKey) {
                const secretTail = secretKey.subarray(32, 64);
                const tailMatches = b4a.equals(secretTail, expectedSignerKey);
                console.log('[RelayAdapter] Invite writer secret inspection', {
                    relayKey,
                    secretLen: secretKey.length,
                    tailMatchesSigner: tailMatches,
                    expectedSignerHex: expectedSignerHex?.slice(0, 16) || null
                });
            } else if (secretKey.length === 64 && expectedCoreKey) {
                const secretTail = secretKey.subarray(32, 64);
                const { key: derivedCore } = deriveCoreKeyFromSignerKey(secretTail, manifestVersion);
                const tailMatchesCore = derivedCore ? b4a.equals(derivedCore, expectedCoreKey) : null;
                console.log('[RelayAdapter] Invite writer secret inspection', {
                    relayKey,
                    secretLen: secretKey.length,
                    tailMatchesCore,
                    expectedWriterSource
                });
            }

            let derivedPair = null;
            for (const seed of seedCandidates) {
                try {
                    const candidate = hypercoreCrypto.keyPair(seed);
                    if (!candidate?.publicKey || !candidate?.secretKey) continue;
                    if (expectedSignerKey && !b4a.equals(candidate.publicKey, expectedSignerKey)) {
                        console.warn('[RelayAdapter] Invite writer keypair mismatch with expected signer; retrying with alternate seed');
                        continue;
                    }
                    if (expectedCoreKey) {
                        const { key: derivedCore } = deriveCoreKeyFromSignerKey(candidate.publicKey, manifestVersion);
                        if (!derivedCore || !b4a.equals(derivedCore, expectedCoreKey)) {
                            console.warn('[RelayAdapter] Invite writer keypair mismatch with expected core; retrying with alternate seed', {
                                relayKey,
                                expectedWriterSource
                            });
                            continue;
                        }
                    }
                    derivedPair = { publicKey: candidate.publicKey, secretKey: candidate.secretKey };
                    break;
                } catch (err) {
                    // try next seed form
                }
            }

            if (!derivedPair && secretKey.length === 64) {
                if (expectedSignerKey) {
                    const candidate = { publicKey: expectedSignerKey, secretKey };
                    if (hypercoreCrypto.validateKeyPair(candidate)) {
                        derivedPair = candidate;
                        console.warn('[RelayAdapter] Using invite secretKey directly (validated against writerCore)');
                    } else {
                        console.warn('[RelayAdapter] Invite writer secretKey does not validate against writerCore; skipping keyPair injection');
                    }
                } else if (expectedCoreKey) {
                    const candidatePublic = secretKey.subarray(32, 64);
                    const { key: derivedCore } = deriveCoreKeyFromSignerKey(candidatePublic, manifestVersion);
                    if (derivedCore && b4a.equals(derivedCore, expectedCoreKey)) {
                        const candidate = { publicKey: candidatePublic, secretKey };
                        if (hypercoreCrypto.validateKeyPair(candidate)) {
                            derivedPair = candidate;
                            console.warn('[RelayAdapter] Using invite secretKey directly (validated against expected core)');
                        }
                    }
                    if (!derivedPair) {
                        console.warn('[RelayAdapter] Invite writer secretKey does not validate against expected core; skipping keyPair injection');
                    }
                }
            }

            if (derivedPair) {
                writerKeyPair = derivedPair;
                console.log('[RelayAdapter] Decoded invite writer keypair for relay', {
                    relayKey,
                    hasExpectedSigner: !!expectedSignerKey,
                    secretLen: secretKey.length,
                    derivedPublicHex: b4a.toString(derivedPair.publicKey, 'hex').slice(0, 16),
                    expectedSignerHex: expectedSignerHex?.slice(0, 16) || null,
                    expectedWriterSource
                });
            } else {
                console.warn('[RelayAdapter] Provided writerSecret but failed to decode/derive writerCore/publicKey; skipping keyPair injection');
            }
        } catch (err) {
            console.warn('[RelayAdapter] Failed to build writer keyPair from invite', err?.message || err);
        }
    } else {
        console.log('[RelayAdapter] No writerSecret supplied for joinRelay', { relayKey, publicIdentifier });
    }

    try {
        await ensureProfilesInitialized(globalUserKey);
        
        // Check if already connected
        if (activeRelays.has(relayKey)) {
            console.log(`[RelayAdapter] Already connected to relay ${relayKey}`);

            // Load profile to determine auth token
            let userAuthToken = null;
            let profileInfo = await getRelayProfileByKey(relayKey);
            if (profileInfo?.auth_config?.requiresAuth && config.nostr_pubkey_hex) {
                const userAuth = profileInfo.auth_config.authorizedUsers.find(
                    u => u.pubkey === config.nostr_pubkey_hex
                );
                userAuthToken = userAuth?.token || null;
            }

            if (authToken) {
                userAuthToken = authToken;
            }

            const { connectionUrl } = buildRelayConnectionUrls(config, {
                relayKey,
                publicIdentifier: profileInfo?.public_identifier,
                authToken: userAuthToken
            });

            // Still send initialized message since the UI might be waiting
            if (global.sendMessage && !suppressInitMessage) {
                console.log(`[RelayAdapter] [1] joinRelay() ->Sending relay-initialized for ${relayKey} with URL ${connectionUrl}`);
                global.sendMessage({
                    type: 'relay-initialized',
                    relayKey: relayKey,
                    publicIdentifier: profileInfo?.public_identifier,
                    gatewayUrl: connectionUrl,
                    connectionUrl,
                    alreadyActive: true,
                    requiresAuth: profileInfo?.auth_config?.requiresAuth || false,
                    userAuthToken: userAuthToken,
                    timestamp: new Date().toISOString()
                });
            } else if (global.sendMessage && suppressInitMessage) {
                console.log('[RelayAdapter] Suppressing relay-initialized (already active)', {
                    relayKey
                });
            }
            
            return {
                success: false,
                error: 'Already connected to this relay'
            };
        }
        
        // Set default storage directory
        const defaultStorageDir = storageDir || join(config.storage || './data', 'relays', relayKey);
        
        // Ensure storage directory exists
        await fs.mkdir(defaultStorageDir, { recursive: true });

        let relayCorestore = corestore;
        if (!relayCorestore && useSharedCorestore) {
            relayCorestore = getRelayCorestore(relayKey, { storageBase: config?.storage || null });
        }
        if (relayCorestore) {
            console.log('[RelayAdapter] Using shared corestore for relay', {
                relayKey,
                storageDir: defaultStorageDir,
                corestoreId: relayCorestore.__ht_id || null,
                corestorePath: relayCorestore.__ht_storage_path || null
            });
        } else {
            console.log('[RelayAdapter] Using relay-local corestore', {
                relayKey,
                storageDir: defaultStorageDir
            });
        }

        if (writerKeyPair?.publicKey) {
            const manifestVersion = Number.isInteger(relayCorestore?.manifestVersion)
                ? relayCorestore.manifestVersion
                : 0;
            const { key: derivedKey, error: deriveError } = deriveCoreKeyFromSignerKey(
                writerKeyPair.publicKey,
                manifestVersion
            );
            const derivedKeyHex = derivedKey ? b4a.toString(derivedKey, 'hex') : null;
            const expectedMatchesDerived = expectedWriterKey && derivedKey
                ? b4a.equals(expectedWriterKey, derivedKey)
                : null;
            if (derivedKey) {
                if (!expectedWriterKey || expectedWriterSource === 'writerCore') {
                    expectedWriterKey = derivedKey;
                    expectedWriterHex = derivedKeyHex;
                    expectedWriterSource = 'derived-signer';
                } else if (expectedWriterKey && expectedMatchesDerived === false) {
                    console.warn('[RelayAdapter][WriterMaterial] Expected writer core key differs from derived core key', {
                        relayKey,
                        expectedWriterKey: expectedWriterHex,
                        derivedWriterKey: derivedKeyHex,
                        expectedWriterSource
                    });
                }
            } else {
                console.warn('[RelayAdapter][WriterMaterial] Failed to derive core key from signer', {
                    relayKey,
                    expectedWriterKey: expectedWriterHex,
                    expectedWriterSource,
                    manifestVersion,
                    error: deriveError?.message || deriveError
                });
            }
            console.log('[RelayAdapter][WriterMaterial] Derived writer core key from signer', {
                relayKey,
                expectedWriterKey: expectedWriterHex,
                expectedWriterSource,
                derivedWriterKey: derivedKeyHex,
                manifestVersion,
                corestoreId: relayCorestore?.__ht_id || null,
                corestorePath: relayCorestore?.__ht_storage_path || null
            });
        }
        
        // Create relay manager instance
        if (writerKeyPair) {
            console.log('[RelayAdapter] Using invite-provided writer keypair for relay', relayKey);
        }

        const relayManager = new RelayManager(defaultStorageDir, relayKey, {
            keyPair: writerKeyPair,
            expectedWriterKey,
            corestore: relayCorestore,
            fastForward: fastForwardCheckpoint
        });
        await relayManager.initialize();

        if (fastForwardCheckpoint) {
            const fastForwardResult = await applyFastForwardCheckpoint({
                relayManager,
                relayKey,
                checkpoint: fastForwardCheckpoint,
                reason: 'join-relay'
            });
            console.log('[RelayAdapter] Fast-forward checkpoint applied', {
                relayKey,
                status: fastForwardResult?.status || null,
                reason: fastForwardResult?.reason || null,
                elapsedMs: fastForwardResult?.elapsedMs ?? null,
                keyMatchesSystem: fastForwardResult?.keyMatchesSystem ?? null,
                error: fastForwardResult?.error || null
            });
        }
        
        activeRelays.set(relayKey, relayManager);
        
        // Check if profile already exists
        let profileInfo = await getRelayProfileByKey(relayKey);
        
        if (!profileInfo) {
            // Create new profile
            profileInfo = {
                name: name || `Joined Relay ${relayKey.substring(0, 8)}`,
                description: description || `Relay joined on ${new Date().toLocaleString()}`,
                nostr_pubkey_hex: config.nostr_pubkey_hex || generateHexKey(),
                admin_pubkey: config.nostr_pubkey_hex || null,
                members: config.nostr_pubkey_hex ? [config.nostr_pubkey_hex] : [],
                member_adds: config.nostr_pubkey_hex ? [{ pubkey: config.nostr_pubkey_hex, ts: Date.now() }] : [],
                member_removes: [],
                relay_nostr_id: null,
                relay_key: relayKey,
                public_identifier: publicIdentifier || null,
                relay_storage: defaultStorageDir,
                joined_at: new Date().toISOString(),
                auto_connect: true,
                is_active: true
            };
            if (typeof isOpen === 'boolean') {
                profileInfo.isOpen = isOpen;
            }

            profileInfo = applyJoinMetadata(profileInfo, {
                writerSecret,
                writerCore,
                expectedWriterKey,
                relayManager,
                blindPeer,
                coreRefs
            });
            console.log('[RelayAdapter] Stored join metadata for new relay profile', {
                relayKey,
                hasWriterSecret: !!writerSecret,
                hasWriterCore: !!writerCore,
                hasWriterCoreHex: !!writerCoreHex,
                hasAutobaseLocal: !!autobaseLocal,
                hasBlindPeer: !!blindPeer,
                coreRefsCount: Array.isArray(coreRefs) ? coreRefs.length : 0,
                autobaseLocal: profileInfo.autobase_local ? profileInfo.autobase_local.slice(0, 16) : null,
                expectedWriterKey: expectedWriterHex
            });

            await saveRelayProfile(profileInfo);
        } else {
            // Update existing profile
            profileInfo.relay_storage = defaultStorageDir;
            profileInfo.last_joined_at = new Date().toISOString();
            profileInfo.is_active = true;
            if (name) profileInfo.name = name;
            if (description) profileInfo.description = description;
            if (publicIdentifier && !profileInfo.public_identifier) {
                profileInfo.public_identifier = publicIdentifier;
            }
            if (typeof isOpen === 'boolean') {
                profileInfo.isOpen = isOpen;
            }

            profileInfo = applyJoinMetadata(profileInfo, {
                writerSecret,
                writerCore,
                expectedWriterKey,
                relayManager,
                blindPeer,
                coreRefs
            });
            console.log('[RelayAdapter] Stored join metadata for existing relay profile', {
                relayKey,
                hasWriterSecret: !!writerSecret,
                hasWriterCore: !!writerCore,
                hasWriterCoreHex: !!writerCoreHex,
                hasAutobaseLocal: !!autobaseLocal,
                hasBlindPeer: !!blindPeer,
                coreRefsCount: Array.isArray(coreRefs) ? coreRefs.length : 0,
                autobaseLocal: profileInfo.autobase_local ? profileInfo.autobase_local.slice(0, 16) : null,
                expectedWriterKey: expectedWriterHex
            });

            await saveRelayProfile(profileInfo);
        }

        // Load members into in-memory map
        setRelayMembers(relayKey, profileInfo.members || [], profileInfo.member_adds || [], profileInfo.member_removes || []);
        if (profileInfo.public_identifier) {
            setRelayMembers(profileInfo.public_identifier, profileInfo.members || [], profileInfo.member_adds || [], profileInfo.member_removes || []);
        }
        
        const postJoinCoreRefs = normalizeCoreRefs(profileInfo.core_refs || profileInfo.coreRefs);
        let postJoinSync = null;
        if (typeof global.syncActiveRelayCoreRefs === 'function' && postJoinCoreRefs.length) {
            try {
                postJoinSync = await global.syncActiveRelayCoreRefs({
                    relayKey,
                    publicIdentifier: profileInfo.public_identifier || publicIdentifier,
                    coreRefs: postJoinCoreRefs,
                    reason: 'post-join'
                });
            } catch (error) {
                console.warn('[RelayAdapter] Post-join writer sync failed', {
                    relayKey,
                    error: error?.message || error
                });
            }
        }

        const writerSample = collectActiveWriterSample(relayManager);
        const activeWriters = relayManager?.relay?.activeWriters;
        const writerCount = typeof activeWriters?.size === 'number'
            ? activeWriters.size
            : Array.isArray(activeWriters)
                ? activeWriters.length
                : null;
        console.log('[RelayAdapter] Writer set before subscriptions', {
            relayKey,
            writerCount,
            writerSample,
            coreRefsCount: postJoinCoreRefs.length,
            coreRefsPreview: postJoinCoreRefs.slice(0, 3),
            expectedWriter: expectedWriterHex,
            expectedWriterSource,
            writerSyncStatus: postJoinSync?.writerSummary?.status ?? null,
            writerAdded: postJoinSync?.writerSummary?.added ?? 0
        });

        if (postJoinSync?.writerSummary?.added > 0 && typeof global.requestRelaySubscriptionRefresh === 'function') {
            try {
                const refreshSummary = await global.requestRelaySubscriptionRefresh({
                    relayKey,
                    reason: 'post-join-writer-sync'
                });
                console.log('[RelayAdapter] Subscription refresh scheduled', {
                    relayKey,
                    status: refreshSummary?.status ?? null,
                    updated: refreshSummary?.updated ?? null,
                    failed: refreshSummary?.failed ?? null
                });
            } catch (error) {
                console.warn('[RelayAdapter] Subscription refresh failed', {
                    relayKey,
                    error: error?.message || error
                });
            }
        }

        if (profileInfo.isOpen === true && typeof global.appendOpenJoinMirrorCores === 'function') {
            global.appendOpenJoinMirrorCores({
                relayKey,
                publicIdentifier: profileInfo.public_identifier || publicIdentifier,
                relayManager,
                reason: 'post-join'
            }).then((appendSummary) => {
                console.log('[RelayAdapter] Open join mirror append scheduled', {
                    relayKey,
                    status: appendSummary?.status ?? null,
                    added: appendSummary?.data?.added ?? null,
                    ignored: appendSummary?.data?.ignored ?? null,
                    rejected: appendSummary?.data?.rejected ?? null
                });
            }).catch((error) => {
                console.warn('[RelayAdapter] Open join mirror append failed', {
                    relayKey,
                    error: error?.message || error
                });
            });
        }

        console.log('[RelayAdapter] Joined relay:', relayKey);
        
        // Send relay initialized message for joined relay ONLY if not from auto-connect
        if (!fromAutoConnect && global.sendMessage && !suppressInitMessage) {
            const { connectionUrl: gw } = buildRelayConnectionUrls(config, {
                relayKey,
                publicIdentifier: profileInfo.public_identifier,
                authToken
            });
            console.log(`[RelayAdapter] [3] joinRelay -> Sending relay-initialized for ${relayKey} with URL ${gw}`);
            global.sendMessage({
                type: 'relay-initialized',
                relayKey: relayKey,
                publicIdentifier: profileInfo.public_identifier,
                gatewayUrl: gw,
                name: profileInfo.name,
                connectionUrl: gw,
                isJoined: true,
                timestamp: new Date().toISOString()
            });
        } else if (!fromAutoConnect && global.sendMessage && suppressInitMessage) {
            console.log('[RelayAdapter] Suppressing relay-initialized (join flow)', {
                relayKey,
                publicIdentifier: profileInfo.public_identifier || null
            });
        }
        
        const { connectionUrl: returnConnectionUrl } = buildRelayConnectionUrls(config, {
            relayKey,
            publicIdentifier: profileInfo.public_identifier,
            authToken
        });
        return {
            success: true,
            relayKey,
            publicIdentifier: profileInfo.public_identifier || null,
            connectionUrl: returnConnectionUrl,
            profile: profileInfo,
            storageDir: defaultStorageDir
        };
        
    } catch (error) {
        console.error('[RelayAdapter] Error joining relay:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Disconnect from a relay
 * @param {string} relayKey - The relay key to disconnect from
 * @returns {Promise<Object>} - Result object
 */
export async function disconnectRelay(relayKey) {
    if (!relayKey) {
        return {
            success: false,
            error: 'Relay key is required'
        };
    }
    
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
        return {
            success: false,
            error: 'Relay not active'
        };
    }
    
    try {
        await ensureProfilesInitialized();
        
        // Close the relay
        await relayManager.close();
        activeRelays.delete(relayKey);
        
        // Update profile
        relayMembers.delete(relayKey);
        const profileInfo = await getRelayProfileByKey(relayKey);
        if (profileInfo && profileInfo.public_identifier) {
            relayMembers.delete(profileInfo.public_identifier);
        }
        // Update profile
        if (profileInfo) {
            profileInfo.last_disconnected_at = new Date().toISOString();
            profileInfo.is_active = false;
            await saveRelayProfile(profileInfo);
        }
        
        console.log('[RelayAdapter] Disconnected from relay:', relayKey);
        
        return {
            success: true,
            message: `Disconnected from relay ${relayKey}`
        };
        
    } catch (error) {
        console.error('[RelayAdapter] Error disconnecting relay:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

/**
 * Get all relay profiles
 * @returns {Promise<Array>} - Array of relay profiles
 */
export async function getRelayProfiles() {
    await ensureProfilesInitialized(globalUserKey);
    return getAllRelayProfiles(globalUserKey);
}

/**
 * Auto-connect to stored relays
 * @param {Object} config - Configuration object
 * @returns {Promise<Array>} - Array of connected relay keys
 */
export async function autoConnectStoredRelays(config) {
    try {
        // Extract user key from config
        const userKey = config.userKey;
        await ensureProfilesInitialized(userKey);
        
        console.log('[RelayAdapter] Starting auto-connection to stored relays for user:', userKey);
        
        const relayProfiles = await getAllRelayProfiles(userKey);
        if (!relayProfiles || relayProfiles.length === 0) {
            console.log('[RelayAdapter] No stored relay profiles found');
            
            // Notify that there are no relays to initialize
            if (global.sendMessage) {
                global.sendMessage({
                    type: 'all-relays-initialized',
                    count: 0,
                    message: 'No stored relays to initialize'
                });
            }
            return [];
        }
        
        console.log(`[RelayAdapter] Found ${relayProfiles.length} stored relay profiles`);
        
        // Import auth store for loading auth configurations
        const { getRelayAuthStore } = await import('./relay-auth-store.mjs');
        const authStore = getRelayAuthStore();

        if (global.sendMessage) {
            try {
                global.sendMessage({
                    type: 'relay-loading',
                    stage: 'relay-count',
                    total: relayProfiles.length,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.warn('[RelayAdapter] Failed to emit relay-count event:', error?.message || error);
            }
        }

        const connectedRelays = [];
        const failedRelays = [];

        const connectTasks = relayProfiles.map((profile) =>
            connectStoredRelayProfile(profile, config, authStore, { totalRelays: relayProfiles.length })
        );

        const settledResults = await Promise.allSettled(connectTasks);

        for (const outcome of settledResults) {
            if (outcome.status === 'fulfilled') {
                const info = outcome.value || {};
                if (info.success) {
                    if (info.relayKey) {
                        connectedRelays.push(info.relayKey);
                    }
                } else if (info.skipped) {
                    console.log(`[RelayAdapter] Auto-connect skipped for ${info.relayKey}: ${info.reason || 'auto-connect disabled'}`);
                } else if (info.relayKey) {
                    failedRelays.push({
                        relayKey: info.relayKey,
                        error: info.error || 'Unknown error'
                    });
                }
            } else {
                const reason = outcome.reason || {};
                failedRelays.push({
                    relayKey: reason.relayKey || null,
                    error: reason.error || reason.message || String(reason)
                });
            }
        }

        console.log(`[RelayAdapter] Auto-connection complete:`);
        console.log(`[RelayAdapter] - Connected: ${connectedRelays.length} relays`);
        console.log(`[RelayAdapter] - Failed: ${failedRelays.length} relays`);

        const authProtectedCount = relayProfiles.filter(p => p.auth_config?.requiresAuth).length;
        console.log(`[RelayAdapter] - Auth-protected: ${authProtectedCount} relays`);

        if (global.sendMessage) {
            global.sendMessage({
                type: 'all-relays-initialized',
                count: connectedRelays.length,
                connected: connectedRelays,
                failed: failedRelays,
                total: relayProfiles.length,
                authProtectedCount,
                timestamp: new Date().toISOString()
            });
        }

        return connectedRelays;
        
    } catch (error) {
        console.error('[RelayAdapter] Error during auto-connection:', error);
        
        // Send error message
        if (global.sendMessage) {
            global.sendMessage({
                type: 'relay-auto-connect-error',
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
        
        return [];
    }
}

async function connectStoredRelayProfile(profile, config, authStore, options = {}) {
    const relayKey = profile?.relay_key;
    if (!relayKey) {
        return { success: false, relayKey: null, error: 'Missing relay key' };
    }

    const publicIdentifier = profile.public_identifier || null;
    const displayName = profile.name || `Relay ${relayKey.substring(0, 8)}`;
    const isAlreadyActive = activeRelays.has(relayKey);

    emitRelayLoadingEvent({
        relayKey,
        publicIdentifier,
        name: displayName
    }, isAlreadyActive ? 'already-active' : 'connecting', options);

    try {
        if (isAlreadyActive) {
            console.log(`[RelayAdapter] Relay ${relayKey} already active, syncing metadata`);

            if (profile.auth_config && profile.auth_config.requiresAuth) {
                const authData = {};
                const authorizedUsers = calculateAuthorizedUsers(
                    profile.auth_config.auth_adds || [],
                    profile.auth_config.auth_removes || []
                );
                authorizedUsers.forEach(user => {
                    authData[user.pubkey] = {
                        token: user.token,
                        createdAt: Date.now(),
                        lastUsed: Date.now()
                    };
                });

                authStore.importRelayAuth(relayKey, authData);

                const canonicalPublicIdentifier = publicIdentifier ? normalizeRelayIdentifier(publicIdentifier) : null;
                if (canonicalPublicIdentifier) {
                    authStore.importRelayAuth(canonicalPublicIdentifier, authData);
                }
            }

            let userAuthToken = null;
            if (profile.auth_config?.requiresAuth && config.nostr_pubkey_hex) {
                const authorizedUsers = calculateAuthorizedUsers(
                    profile.auth_config.auth_adds || [],
                    profile.auth_config.auth_removes || []
                );
                const userAuth = authorizedUsers.find(u => u.pubkey === config.nostr_pubkey_hex);
                userAuthToken = userAuth?.token || null;
            }

            const { connectionUrl } = buildRelayConnectionUrls(config, {
                relayKey,
                publicIdentifier,
                authToken: userAuthToken
            });

            if (global.sendMessage) {
                global.sendMessage({
                    type: 'relay-initialized',
                    relayKey,
                    publicIdentifier,
                    gatewayUrl: connectionUrl,
                    name: profile.name,
                    connectionUrl,
                    alreadyActive: true,
                    requiresAuth: profile.auth_config?.requiresAuth || false,
                    userAuthToken,
                    timestamp: new Date().toISOString()
                });
            }

            return { success: true, relayKey, alreadyActive: true };
        }

        if (profile.auto_connect === false) {
            emitRelayLoadingEvent({ relayKey, publicIdentifier, name: displayName }, 'skipped', options);
            return {
                success: false,
                relayKey,
                skipped: true,
                reason: 'auto-connect-disabled'
            };
        }

        if (profile.auth_config && profile.auth_config.requiresAuth) {
            console.log(`[RelayAdapter] Loading auth configuration for relay ${relayKey}`);

            const authorizedUsers = calculateAuthorizedUsers(
                profile.auth_config.auth_adds || [],
                profile.auth_config.auth_removes || []
            );
            const authData = {};
            authorizedUsers.forEach(user => {
                authData[user.pubkey] = {
                    token: user.token,
                    createdAt: Date.now(),
                    lastUsed: Date.now()
                };
            });

            authStore.importRelayAuth(relayKey, authData);

            const canonicalPublicIdentifier = publicIdentifier ? normalizeRelayIdentifier(publicIdentifier) : null;
            if (canonicalPublicIdentifier) {
                authStore.importRelayAuth(canonicalPublicIdentifier, authData);
            }
        }

        setRelayMembers(
            relayKey,
            profile.members || [],
            profile.member_adds || [],
            profile.member_removes || []
        );

        if (publicIdentifier) {
            setRelayMembers(
                publicIdentifier,
                profile.members || [],
                profile.member_adds || [],
                profile.member_removes || []
            );
        }

        let storedWriterSecret = profile.writer_secret || profile.writerSecret || null;
        let storedWriterCore =
            profile.writer_core ||
            profile.writerCore ||
            profile.writer_core_hex ||
            profile.autobase_local ||
            null;
        let storedExpectedWriter =
            profile.autobase_local ||
            profile.writer_core_hex ||
            profile.writer_core ||
            null;
        let storedBlindPeer = profile.blind_peer || profile.blindPeer || null;
        const initialCoreRefs = normalizeCoreRefs(profile.core_refs || profile.coreRefs);

        const expectedWriterKey = decodeWriterKey(storedWriterCore || storedExpectedWriter || null);
        let storedWriterValid = false;
        let storedWriterInvalid = false;
        if (storedWriterSecret) {
            storedWriterValid = validateWriterSecret(storedWriterSecret, {
                expectedWriterKey,
                writerCore: storedWriterCore || storedExpectedWriter || null
            }).valid;
            if (!storedWriterValid) {
                const beforeWriterSnapshot = snapshotWriterMaterial(profile);
                const afterWriterSnapshot = {
                    ...beforeWriterSnapshot,
                    writer_secret: null
                };
                logWriterMaterialChange({
                    stage: 'auto-connect-invalid-stored-writer',
                    relayKey,
                    before: beforeWriterSnapshot,
                    after: afterWriterSnapshot,
                    extra: {
                        expectedWriterKey: expectedWriterKey ? b4a.toString(expectedWriterKey, 'hex') : null
                    }
                });
                console.warn('[RelayAdapter] Stored writer secret invalid; discarding before auto-connect', {
                    relayKey
                });
                storedWriterInvalid = true;
                storedWriterSecret = null;
            }
        }

        let recoveredCorestore = null;
        if (!storedWriterSecret) {
            const recovered = await recoverLocalWriterMaterial({
                relayKey,
                profile,
                config,
                preferBootstrapLocal: storedWriterInvalid
            });
            if (recovered?.writerSecret) {
                const recoveredValid = validateWriterSecret(recovered.writerSecret, {
                    expectedWriterKey: decodeWriterKey(recovered.writerCore || recovered.autobaseLocal || null)
                }).valid;
                if (recoveredValid) {
                    const beforeWriterSnapshot = snapshotWriterMaterial(profile);
                    storedWriterSecret = recovered.writerSecret;
                    storedWriterCore = recovered.writerCore || recovered.autobaseLocal || storedWriterCore;
                    storedExpectedWriter = recovered.autobaseLocal || storedExpectedWriter;
                    storedWriterValid = true;
                    recoveredCorestore = recovered.source === 'local-storage' ? recovered.corestore : null;

                    const updatedProfile = { ...profile };
                    updatedProfile.writer_secret = recovered.writerSecret;
                    if (recovered.writerCore && recovered.writerCore !== updatedProfile.writer_core) {
                        updatedProfile.writer_core = recovered.writerCore;
                    } else if (recovered.autobaseLocal && !updatedProfile.writer_core_hex) {
                        updatedProfile.writer_core_hex = recovered.autobaseLocal;
                    }
                    if (recovered.autobaseLocal && recovered.autobaseLocal !== updatedProfile.autobase_local) {
                        updatedProfile.autobase_local = recovered.autobaseLocal;
                    }
                    updatedProfile.updated_at = new Date().toISOString();
                    await saveRelayProfile(updatedProfile);
                    profile = updatedProfile;
                    const afterWriterSnapshot = snapshotWriterMaterial(updatedProfile);
                    logWriterMaterialChange({
                        stage: 'auto-connect-recovered-writer',
                        relayKey,
                        before: beforeWriterSnapshot,
                        after: afterWriterSnapshot,
                        extra: {
                            source: recovered.source || null,
                            preferBootstrapLocal: recovered.preferBootstrapLocal,
                            profileAutobaseLocal: recovered.profileAutobaseLocal,
                            recoveredCoreKeyHex: recovered.coreKeyHex || null,
                            recoveredSignerKeyHex: recovered.signerKeyHex || null,
                            recoveredWriterCoreSource: recovered.writerCoreSource || null,
                            recoveredCoreMatchesSigner: recovered.coreMatchesSigner,
                            usedLegacyWriterCore: recovered.usedLegacyWriterCore || false
                        }
                    });
                    console.log('[RelayAdapter] Restored local writer secret for auto-connect', {
                        relayKey,
                        writerCore: recovered.writerCore ? recovered.writerCore.slice(0, 16) : null,
                        autobaseLocal: recovered.autobaseLocal ? recovered.autobaseLocal.slice(0, 16) : null,
                        source: recovered.source || null
                    });
                } else {
                    console.warn('[RelayAdapter] Recovered writer secret failed validation; skipping', {
                        relayKey,
                        source: recovered.source || null
                    });
                }
            }
        }

        let mirrorFetchStatus = 'skipped';
        if (typeof global.fetchAndApplyRelayMirrorMetadata === 'function') {
            try {
                const mirrorResult = await global.fetchAndApplyRelayMirrorMetadata({
                    relayKey,
                    publicIdentifier,
                    reason: 'auto-connect'
                });
                mirrorFetchStatus = mirrorResult?.status || 'error';
            } catch (error) {
                mirrorFetchStatus = 'error';
                console.warn('[RelayAdapter] Auto-connect: mirror metadata fetch failed', {
                    relayKey,
                    error: error?.message || error
                });
            }
        }

        if (mirrorFetchStatus === 'ok') {
            const refreshedProfile = await getRelayProfileByKey(relayKey);
            if (refreshedProfile) {
                profile = refreshedProfile;
                storedBlindPeer = profile.blind_peer || profile.blindPeer || storedBlindPeer;
            }
        }

        const storedCoreRefs = normalizeCoreRefs(profile.core_refs || profile.coreRefs);
        const storedFastForward = profile.fast_forward || profile.fastForward || null;
        let mergedCoreRefs = storedCoreRefs;
        if (typeof global.resolveRelayMirrorCoreRefs === 'function') {
            mergedCoreRefs = await global.resolveRelayMirrorCoreRefs(
                relayKey,
                publicIdentifier,
                storedCoreRefs
            );
        }

        const cachedCoreRefs = typeof global.getRelayMirrorCoreRefsCache === 'function'
            ? await global.getRelayMirrorCoreRefsCache(relayKey)
            : [];
        const allowPrefetch = !!storedBlindPeer
            && (mirrorFetchStatus === 'ok' || cachedCoreRefs.length > 0);

        const prefersLocalCorestore = storedWriterValid && !!profile.relay_storage;
        let relayCorestore = null;
        if (storedBlindPeer) {
            if (prefersLocalCorestore) {
                relayCorestore = recoveredCorestore || createLocalCorestore(profile.relay_storage, relayKey);
            } else {
                relayCorestore = getRelayCorestore(relayKey, { storageBase: config?.storage || null });
            }
        }

        if (storedBlindPeer && mergedCoreRefs.length && allowPrefetch) {
            const manager = global.blindPeeringManager || null;
            if (manager?.started) {
                console.log('[RelayAdapter] Auto-connect: prefetching relay cores from blind-peer mirror', {
                    relayKey,
                    publicIdentifier,
                    coreRefsCount: mergedCoreRefs.length,
                    mirrorKey: storedBlindPeer?.publicKey ? String(storedBlindPeer.publicKey).slice(0, 16) : null,
                    mirrorStatus: mirrorFetchStatus
                });
                if (storedBlindPeer?.publicKey) {
                    manager.markTrustedMirrors([String(storedBlindPeer.publicKey)]);
                }
                manager.ensureRelayMirror({
                    relayKey,
                    publicIdentifier,
                    coreRefs: mergedCoreRefs,
                    corestore: relayCorestore
                });
                await manager.refreshFromBlindPeers('auto-connect');
                if (typeof manager.primeRelayCoreRefs === 'function' && mergedCoreRefs.length) {
                    const primeSummary = await manager.primeRelayCoreRefs({
                        relayKey,
                        publicIdentifier,
                        coreRefs: mergedCoreRefs,
                        timeoutMs: AUTO_CONNECT_REHYDRATION_TIMEOUT_MS,
                        reason: 'auto-connect',
                        corestore: relayCorestore
                    });
                    console.log('[RelayAdapter] Auto-connect: core prefetch completed', {
                        relayKey,
                        status: primeSummary?.status ?? null,
                        synced: primeSummary?.synced ?? null,
                        failed: primeSummary?.failed ?? null,
                        connected: primeSummary?.connected ?? null
                    });
                }
                const rehydrateSummary = await manager.rehydrateMirrors({
                    reason: 'auto-connect',
                    timeoutMs: AUTO_CONNECT_REHYDRATION_TIMEOUT_MS
                });
                console.log('[RelayAdapter] Auto-connect: rehydration completed', {
                    relayKey,
                    status: rehydrateSummary?.status ?? null,
                    synced: rehydrateSummary?.synced ?? null,
                    failed: rehydrateSummary?.failed ?? null
                });
            } else {
                console.warn('[RelayAdapter] Auto-connect: blind-peering manager unavailable; skipping mirror rehydration', {
                    relayKey
                });
            }
        } else if (storedBlindPeer && !allowPrefetch) {
            console.warn('[RelayAdapter] Auto-connect: mirror metadata unavailable; skipping prefetch to avoid shrinking core refs', {
                relayKey,
                publicIdentifier,
                initialCoreRefs: initialCoreRefs.length,
                storedCoreRefs: storedCoreRefs.length,
                mirrorStatus: mirrorFetchStatus
            });
        }

        const joinResult = await joinRelay({
            relayKey,
            name: profile.name,
            description: profile.description,
            storageDir: profile.relay_storage,
            config,
            fromAutoConnect: true,
            writerSecret: storedWriterSecret,
            writerCore: storedWriterCore,
            expectedWriterKey: storedExpectedWriter,
            blindPeer: storedBlindPeer,
            coreRefs: mergedCoreRefs,
            fastForward: storedFastForward,
            useSharedCorestore: !prefersLocalCorestore && !!relayCorestore,
            corestore: relayCorestore
        });

        if (!joinResult.success) {
            console.error(`[RelayAdapter] Failed to connect to relay ${relayKey}: ${joinResult.error}`);
            if (global.sendMessage) {
                global.sendMessage({
                    type: 'relay-initialization-failed',
                    relayKey,
                    error: joinResult.error,
                    timestamp: new Date().toISOString()
                });
            }
            emitRelayLoadingEvent({ relayKey, publicIdentifier, name: displayName }, 'relay-error', options);
            return {
                success: false,
                relayKey,
                error: joinResult.error
            };
        }

        profile.auto_connected = true;
        profile.last_connected_at = new Date().toISOString();
        await saveRelayProfile(profile);

        let userAuthToken = null;
        if (profile.auth_config?.requiresAuth && config.nostr_pubkey_hex) {
            const authorizedUsers = calculateAuthorizedUsers(
                profile.auth_config.auth_adds || [],
                profile.auth_config.auth_removes || []
            );
            const userAuth = authorizedUsers.find(u => u.pubkey === config.nostr_pubkey_hex);
            userAuthToken = userAuth?.token || null;
        }

        const { connectionUrl } = buildRelayConnectionUrls(config, {
            relayKey,
            publicIdentifier,
            authToken: userAuthToken
        });

        if (global.sendMessage) {
            global.sendMessage({
                type: 'relay-initialized',
                relayKey,
                publicIdentifier,
                gatewayUrl: connectionUrl,
                name: displayName,
                connectionUrl,
                requiresAuth: profile.auth_config?.requiresAuth || false,
                userAuthToken,
                timestamp: new Date().toISOString()
            });
        }

        emitRelayLoadingEvent({ relayKey, publicIdentifier, name: displayName }, 'initialized', options);

        return { success: true, relayKey };
    } catch (error) {
        console.error(`[RelayAdapter] Error auto-connecting to ${relayKey}:`, error);
        if (global.sendMessage) {
            global.sendMessage({
                type: 'relay-initialization-failed',
                relayKey,
                error: error.message,
                timestamp: new Date().toISOString()
            });
        }
        emitRelayLoadingEvent({ relayKey, publicIdentifier, name: displayName }, 'relay-error', { ...options, count: options.totalRelays });
        return {
            success: false,
            relayKey,
            error: error.message
        };
    }
}

/**
 * Handle relay messages
 * @param {string} relayKey - The relay key
 * @param {Array} message - The NOSTR message
 * @param {Function} sendResponse - Response callback
 * @param {string} connectionKey - Connection identifier
 * @returns {Promise<void>}
 */
export async function handleRelayMessage(relayKey, message, sendResponse, connectionKey, clientId = null) {
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
        throw new Error(`Relay not found: ${relayKey}`);
    }
    
    return relayManager.handleMessage(message, sendResponse, connectionKey, clientId);
}

/**
 * Handle relay subscription
 * @param {string} relayKey - The relay key
 * @param {string} connectionKey - Connection identifier
 * @returns {Promise<Array>}
 */
export async function handleRelaySubscription(relayKey, connectionKey) {
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
        throw new Error(`Relay not found: ${relayKey}`);
    }
    
    return relayManager.handleSubscription(connectionKey);
}

/**
 * Update relay subscription
 */
export async function updateRelaySubscriptions(relayKey, connectionKey, activeSubscriptionsUpdated) {
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
      throw new Error(`Relay not found: ${relayKey}`);
    }
    
    return relayManager.updateSubscriptions(connectionKey, activeSubscriptionsUpdated);
  }

export async function getRelaySubscriptions(relayKey, connectionKey) {
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
      throw new Error(`Relay not found: ${relayKey}`);
    }

    return relayManager.getSubscriptions(connectionKey);
}

export async function getRelayClientSubscriptions(relayKey, clientId) {
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
      throw new Error(`Relay not found: ${relayKey}`);
    }

    return relayManager.getClientSubscriptions(clientId);
}

export async function updateRelayClientSubscriptions(relayKey, clientId, subscriptionObject) {
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
      throw new Error(`Relay not found: ${relayKey}`);
    }

    return relayManager.updateClientSubscriptions(clientId, subscriptionObject);
}

export async function rehydrateRelaySubscriptions(relayKey, fromKey, toKey, { clientId = null } = {}) {
    const relayManager = activeRelays.get(relayKey);
    if (!relayManager) {
      throw new Error(`Relay not found: ${relayKey}`);
    }

    const existing = await relayManager.getSubscriptions(fromKey);
    if (!existing || !existing.subscriptions) {
      return {
        ok: false,
        reason: 'no-subscriptions',
        subscriptionCount: 0
      };
    }

    const subscriptionCount = Object.keys(existing.subscriptions).length;
    if (subscriptionCount === 0) {
      return {
        ok: false,
        reason: 'empty-subscriptions',
        subscriptionCount
      };
    }

    const updated = {
      ...existing,
      connection: toKey
    };

    const timestamps = Object.values(updated.subscriptions || {})
      .map((subscription) => subscription?.last_returned_event_timestamp)
      .filter((value) => typeof value === 'number');
    const lastReturned = timestamps.length ? Math.max(...timestamps) : null;

    await relayManager.updateSubscriptions(toKey, updated);
    if (clientId) {
      await relayManager.updateClientSubscriptions(clientId, {
        ...updated,
        clientId
      });
    }

    return {
      ok: true,
      subscriptionCount,
      lastReturned
    };
}

/**
 * Get the members list for a relay
 * @param {string} relayKey - Relay key
 * @returns {Promise<Array<string>>} - Array of pubkeys
 */
export async function getRelayMembers(relayKey) {
    await ensureProfilesInitialized(globalUserKey);
    if (relayMembers.has(relayKey)) return relayMembers.get(relayKey);

    const profile = await getRelayProfileByKey(relayKey);
    if (profile) {
        const members = calculateMembers(profile.member_adds || [], profile.member_removes || []);
        setRelayMembers(relayKey, members, profile.member_adds || [], profile.member_removes || []);
        if (profile.public_identifier) {
            setRelayMembers(profile.public_identifier, members, profile.member_adds || [], profile.member_removes || []);
        }
        return members;
    }
    return [];
}

/**
 * Get active relays information with full details
 * @returns {Promise<Array>} - Array of active relay information
 */
export async function getActiveRelays() {
    await ensureProfilesInitialized();
    
    const activeRelayList = [];
    const profiles = await getAllRelayProfiles();
    const activeRelayKeys = new Set();
    
    for (const [key, manager] of activeRelays.entries()) {
        activeRelayKeys.add(key);
        // Get peer count if available
        let peerCount = 0;
        if (manager && manager.peers && manager.peers.size) {
            peerCount = manager.peers.size;
        }

        // Find the profile for this relay
        const profile = profiles.find(p => p.relay_key === key);

        const { connectionUrl } = buildRelayConnectionUrls(
            globalConfig || { proxy_server_address: 'localhost', proxy_websocket_protocol: 'wss' },
            { relayKey: key, publicIdentifier: profile?.public_identifier }
        );

        activeRelayList.push({
            relayKey: key,
            publicIdentifier: profile?.public_identifier || null,
            peerCount,
            name: profile?.name || `Relay ${key.substring(0, 8)}`,
            description: profile?.description || '',
            connectionUrl,
            createdAt: profile?.created_at || profile?.joined_at || null,
            isActive: true,
            writable: manager?.relay?.writable === true,
            isOpen: profile?.isOpen === true,
            isPublic: profile?.isPublic === true,
            isHosted: !!profile?.created_at,
            isJoined: !!profile?.joined_at && !profile?.created_at
        });
    }

    // Include profile-backed relays that may not currently be hydrated in-memory yet.
    // This keeps UI relay metadata stable across restarts/recovery and post-create races.
    for (const profile of profiles) {
        const relayKey = profile?.relay_key;
        if (!relayKey || activeRelayKeys.has(relayKey)) continue;
        if (profile?.is_active === false) continue;

        const { connectionUrl } = buildRelayConnectionUrls(
            globalConfig || { proxy_server_address: 'localhost', proxy_websocket_protocol: 'wss' },
            { relayKey, publicIdentifier: profile?.public_identifier }
        );

        activeRelayList.push({
            relayKey,
            publicIdentifier: profile?.public_identifier || null,
            peerCount: 0,
            name: profile?.name || `Relay ${relayKey.substring(0, 8)}`,
            description: profile?.description || '',
            connectionUrl,
            createdAt: profile?.created_at || profile?.joined_at || null,
            isActive: true,
            writable: false,
            isOpen: profile?.isOpen === true,
            isPublic: profile?.isPublic === true,
            isHosted: !!profile?.created_at,
            isJoined: !!profile?.joined_at && !profile?.created_at
        });
    }
    
    return activeRelayList;
}

/**
 * Cleanup all active relays
 * @returns {Promise<void>}
 */
export async function cleanupRelays() {
    console.log('[RelayAdapter] Cleaning up all active relays...');
    
    for (const [key, manager] of activeRelays.entries()) {
        try {
            await manager.close();
            console.log(`[RelayAdapter] Closed relay: ${key}`);
        } catch (error) {
            console.error(`[RelayAdapter] Error closing relay ${key}:`, error);
        }
    }
    
    activeRelays.clear();
}

// Helper function to generate hex keys
function generateHexKey() {
    return nodeCrypto.randomBytes(32).toString('hex');
}

// Export the active relays map for direct access if needed
export {
    activeRelays,
    relayMembers,
    relayMemberAdds,
    relayMemberRemoves,
    publicToKey,
    keyToPublic,
    virtualRelayKeys
};
