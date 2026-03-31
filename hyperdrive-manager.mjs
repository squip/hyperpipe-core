// hyperpipe-worker/hyperdrive-manager.mjs

import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import Hyperswarm from 'hyperswarm'
import b4a from 'b4a'
import { setTimeout as scheduleTimeout, clearTimeout } from 'node:timers'
import { join } from 'node:path'
import crypto from 'node:crypto'

let store = null
let drive = null
let localDriveKeyHex = null
let pfpDrive = null
let pfpDriveKeyHex = null
let pfpStore = null
let storageDir = null
let replicationSwarm = null
const topicCache = new Map() // key -> { discovery, refCount, lastUsed, readyPromise, timer }
const pfpTopicCache = new Map()
let replicationConnectionsOpen = 0
let replicationConnectionsTotal = 0
const relayStores = new Map()
let corestoreCounter = 0

function ensureCorestoreId (target, prefix = 'corestore') {
  if (!target) return null
  if (!target.__ht_id) {
    corestoreCounter += 1
    target.__ht_id = `${prefix}-${corestoreCounter}`
  }
  return target.__ht_id
}

function attachCorestoreMetadata (target, storagePath = null, relayKey = null) {
  if (!target) return null
  ensureCorestoreId(target)
  if (storagePath) target.__ht_storage_path = storagePath
  if (relayKey) target.__ht_relay_key = relayKey
  return target
}

function topicKey (discoveryKey) {
  return b4a.toString(discoveryKey, 'hex')
}

async function acquireRemoteTopic (remoteDrive, ttlMs = 90000) {
  const swarm = await ensureReplicationSwarm()
  const key = topicKey(remoteDrive.discoveryKey)
  const now = Date.now()

  let entry = topicCache.get(key)
  if (entry) {
    entry.refCount += 1
    entry.lastUsed = now
    if (entry.timer) {
      try { clearTimeout(entry.timer) } catch (_) {}
      entry.timer = null
    }
    await entry.readyPromise
    console.log(`[Topic] reuse join dkey=${key} refCount=${entry.refCount}`)
    return () => releaseTopic(key, ttlMs)
  }

  const discovery = swarm.join(remoteDrive.discoveryKey)
  const readyPromise = discovery.flushed()
  entry = { discovery, refCount: 1, lastUsed: now, readyPromise, timer: null }
  topicCache.set(key, entry)
  console.log(`[Topic] first join dkey=${key} refCount=1`)
  await readyPromise
  return () => releaseTopic(key, ttlMs)
}

function releaseTopic (key, ttlMs) {
  const entry = topicCache.get(key)
  if (!entry) return
  entry.refCount = Math.max(0, entry.refCount - 1)
  entry.lastUsed = Date.now()
  console.log(`[Topic] release dkey=${key} refCount=${entry.refCount}`)
  if (entry.refCount === 0 && !entry.timer) {
    entry.timer = setTimeoutEvict(key, ttlMs)
  }
}

function setTimeoutEvict (key, ttlMs) {
  const timer = scheduleTimeout(async () => {
    try {
      const entry = topicCache.get(key)
      if (!entry || entry.refCount > 0) return
      try { entry.discovery.destroy() } catch (_) {}
      topicCache.delete(key)
      console.log(`[Topic] evicted dkey=${key}`)
    } catch (_) {}
  }, ttlMs)
  timer?.unref?.()
  return timer
}

async function withJoinTimeout (promise, timeoutMs = 8000) {
  const ms = Number.isFinite(timeoutMs) ? Math.max(250, Math.trunc(timeoutMs)) : 8000
  let timeoutId = null
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeoutId = scheduleTimeout(() => reject(new Error(`topic-join-timeout:${ms}`)), ms)
      })
    ])
  } finally {
    if (timeoutId) clearTimeout(timeoutId)
  }
}

async function withReadTimeout (promise, timeoutMs = 10000) {
  const ms = Number.isFinite(timeoutMs) ? Math.max(250, Math.trunc(timeoutMs)) : 10000
  let timeoutId = null
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeoutId = scheduleTimeout(() => reject(new Error(`drive-read-timeout:${ms}`)), ms)
      })
    ])
  } finally {
    if (timeoutId) clearTimeout(timeoutId)
  }
}

export function getCorestore() {
  return store
}

export function getRelayCorestore (relayKey, { storageBase = null } = {}) {
  const normalized = normalizeIdentifier(relayKey)
  if (!normalized) return store
  const base = storageBase || storageDir
  if (!base) {
    console.warn('[Hyperdrive] Relay corestore unavailable (storage base missing)', {
      relayKey: normalized
    })
    return store
  }
  let entry = relayStores.get(normalized)
  const storagePath = join(base, 'relays', normalized)
  if (!entry || entry.storagePath !== storagePath) {
    const relayStore = new Corestore(storagePath)
    attachCorestoreMetadata(relayStore, storagePath, normalized)
    entry = { store: relayStore, storagePath }
    relayStores.set(normalized, entry)
    console.log('[Hyperdrive] Relay corestore created', {
      relayKey: normalized,
      storagePath,
      corestoreId: relayStore.__ht_id
    })
  } else {
    attachCorestoreMetadata(entry.store, entry.storagePath, normalized)
    console.log('[Hyperdrive] Relay corestore reused', {
      relayKey: normalized,
      storagePath: entry.storagePath,
      corestoreId: entry.store?.__ht_id || null
    })
  }
  return entry.store
}

export async function removeRelayCorestore (relayKey) {
  const normalized = normalizeIdentifier(relayKey)
  if (!normalized) return false
  const entry = relayStores.get(normalized)
  if (!entry?.store) {
    relayStores.delete(normalized)
    return false
  }
  relayStores.delete(normalized)
  try {
    await entry.store.close?.()
  } catch (error) {
    console.warn('[Hyperdrive] Failed to close relay corestore during removal', {
      relayKey: normalized,
      error: error?.message || error
    })
  }
  return true
}

export function getLocalDrive() {
  return drive
}

export function getPfpDrive() {
  return pfpDrive
}

function getPfpTopicCache() {
  return pfpTopicCache
}

function isHex64 (s) {
  return typeof s === 'string' && /^[a-fA-F0-9]{64}$/.test(s)
}

export function normalizeIdentifier(id) {
  if (!id) return ''
  if (typeof id === 'string') {
    // Keep public identifiers as-is (npub:alias), normalize relayKey hex to lowercase
    return isHex64(id) ? id.toLowerCase() : id
  }
  if (id instanceof Uint8Array || Buffer.isBuffer(id)) {
    return Buffer.from(id).toString('hex')
  }
  return String(id)
}

export const relayPath = (identifier) => `/${normalizeIdentifier(identifier)}`
export const relayFilePath = (identifier, fileHash) => `${relayPath(identifier)}/${fileHash}`

export async function ensureRelayFolder(identifier) {
  const path = relayPath(identifier)
  try {
    // Hyperdrive is key-based and does not require explicit directory creation.
    // We intentionally no-op here since folder prefixes are implicit.
    await drive.ready()
    console.log(`[Hyperdrive] ensureRelayFolder ready path=${path}`)
  } catch (_) {}
}

async function ensureReplicationSwarm () {
  if (replicationSwarm) return replicationSwarm
  if (!store) throw new Error('Corestore not initialized')
  replicationSwarm = new Hyperswarm()
  console.log('[Hyperdrive] replication swarm initialized')
  replicationSwarm.on('connection', (conn, info) => {
    replicationConnectionsOpen++
    replicationConnectionsTotal++
    const peerKey = info?.publicKey ? b4a.toString(info.publicKey, 'hex').slice(0, 16) : 'unknown'
    console.log(`[Hyperdrive] connection opened peer=${peerKey} open=${replicationConnectionsOpen}`)
    try { store.replicate(conn) } catch (err) { console.error('[Hyperdrive] replicate error:', err) }
    try {
      conn.once?.('close', () => {
        replicationConnectionsOpen = Math.max(0, replicationConnectionsOpen - 1)
        console.log(`[Hyperdrive] connection closed peer=${peerKey} open=${replicationConnectionsOpen}`)
      })
      conn.once?.('end', () => {
        replicationConnectionsOpen = Math.max(0, replicationConnectionsOpen - 1)
        console.log(`[Hyperdrive] connection ended peer=${peerKey} open=${replicationConnectionsOpen}`)
      })
      conn.once?.('error', () => {
        replicationConnectionsOpen = Math.max(0, replicationConnectionsOpen - 1)
        console.log(`[Hyperdrive] connection error peer=${peerKey} open=${replicationConnectionsOpen}`)
      })
    } catch (_) {}
  })
  return replicationSwarm
}

/**
 * Join the discovery topic for a remote Hyperdrive using the shared replication swarm.
 * Returns a release function that decrements the refcount and eventually evicts the topic.
 * @param {import('hyperdrive').default} remoteDrive
 * @param {number} ttlMs
 * @returns {Promise<() => void>}
 */
export async function joinRemoteDriveTopic (remoteDrive, ttlMs = 90000) {
  return acquireRemoteTopic(remoteDrive, ttlMs)
}

/**
 * Initialize a Hyperdrive instance for this worker.
 * @param {object} config - Worker configuration including storage path.
 * @returns {Promise<void>}
 */
export async function initializeHyperdrive(config) {
  storageDir = config.storage
  store = new Corestore(storageDir)
  attachCorestoreMetadata(store, storageDir, 'hyperdrive')
  drive = new Hyperdrive(store)
  await drive.ready()
  config.driveKey = drive.key.toString('hex')
  localDriveKeyHex = config.driveKey
  console.log(`[Hyperdrive] local drive ready key=${config.driveKey} dkey=${b4a.toString(drive.discoveryKey, 'hex')}`)

  // Start replication swarm and announce our local drive
  const swarm = await ensureReplicationSwarm()
  const done = drive.findingPeers()
  const discovery = swarm.join(drive.discoveryKey)
  await discovery.flushed().then(done, done)
  console.log('[Hyperdrive] local drive announced to swarm')

  if (Array.isArray(config.relays)) {
    for (const relay of config.relays) {
      const relayKey = relay?.relayKey || relay
      if (!relayKey) continue
      await ensureRelayFolder(relayKey)
    }
  }
}

function ensureHexKey(key) {
  if (!key || typeof key !== 'string') return null
  return /^[a-fA-F0-9]{64}$/.test(key) ? key.toLowerCase() : null
}

async function announceDriveOnSwarm(targetDrive, cache) {
  if (!targetDrive) return
  const swarm = await ensureReplicationSwarm()
  const done = targetDrive.findingPeers()
  const discovery = swarm.join(targetDrive.discoveryKey)
  await discovery.flushed().then(done, done)
  const key = b4a.toString(targetDrive.discoveryKey, 'hex')
  cache.set(key, { discovery })
  console.log(`[Hyperdrive] announced drive key=${targetDrive.key.toString('hex')} dkey=${key}`)
}

function releaseAnnouncedDrive(cache, targetDrive) {
  try {
    const key = targetDrive ? b4a.toString(targetDrive.discoveryKey, 'hex') : null
    if (!key) return
    const entry = cache.get(key)
    if (entry?.discovery) {
      try { entry.discovery.destroy() } catch (_) {}
      cache.delete(key)
    }
  } catch (_) {}
}

async function getPfpStore(config) {
  if (!store) {
    storageDir = config.storage
    store = new Corestore(storageDir)
  }
  if (!pfpStore) {
    pfpStore = store.namespace('pfp')
    try {
      await pfpStore.ready?.()
    } catch (_) {}
  }
  return pfpStore
}

function ensurePfpPath(owner) {
  if (!owner) return ''
  const trimmed = String(owner).trim()
  if (!trimmed) return ''
  return trimmed.startsWith('/') ? trimmed.replace(/\/+/g, '/') : `/${trimmed}`
}

function buildPfpFilePath(owner, fileHash) {
  const prefix = ensurePfpPath(owner)
  const normalizedHash = fileHash.startsWith('/') ? fileHash.slice(1) : fileHash
  return prefix ? `${prefix}/${normalizedHash}` : `/${normalizedHash}`
}

export async function initializePfpHyperdrive(config) {
  if (!config || !config.storage) throw new Error('Missing config storage for pfp hyperdrive')

  const existingKey = ensureHexKey(config.pfpDriveKey)
  const coreStore = await getPfpStore(config)
  pfpDrive = existingKey ? new Hyperdrive(coreStore, existingKey) : new Hyperdrive(coreStore)
  await pfpDrive.ready()
  pfpDriveKeyHex = pfpDrive.key.toString('hex')
  config.pfpDriveKey = pfpDriveKeyHex
  console.log(`[Hyperdrive] pfp drive ready key=${pfpDriveKeyHex} dkey=${b4a.toString(pfpDrive.discoveryKey, 'hex')}`)

  await announceDriveOnSwarm(pfpDrive, getPfpTopicCache())
}

function isClosingCoreError (err) {
  const msg = err?.message || ''
  const code = err?.code || ''
  return code === 'SESSION_CLOSED' || /SESSION_CLOSED|closing core/i.test(msg)
}

function isStoreClosedError (err) {
  const msg = err?.message || ''
  return /corestore is closed/i.test(msg)
}

async function announceLocalDriveOnSwarm () {
  try {
    const swarm = await ensureReplicationSwarm()
    const done = drive.findingPeers()
    const discovery = swarm.join(drive.discoveryKey)
    await discovery.flushed().then(done, done)
  } catch (e) {
    console.error('[Hyperdrive] announceLocalDriveOnSwarm failed:', e)
  }
}

async function restartLocalHyperdrive () {
  if (!storageDir || !localDriveKeyHex) return false
  try {
    store = new Corestore(storageDir)
    const reopened = new Hyperdrive(store, localDriveKeyHex)
    await reopened.ready()
    drive = reopened
    await announceLocalDriveOnSwarm()
    console.warn('[Hyperdrive] restartLocalHyperdrive: store/drive recreated')
    return true
  } catch (e) {
    console.error('[Hyperdrive] restartLocalHyperdrive failed:', e)
    return false
  }
}

async function restartPfpHyperdrive () {
  if (!storageDir || !pfpDriveKeyHex) return false
  try {
    store = new Corestore(storageDir)
    const reopened = new Hyperdrive(store, pfpDriveKeyHex)
    await reopened.ready()
    pfpDrive = reopened
    await announceDriveOnSwarm(pfpDrive, getPfpTopicCache())
    console.warn('[Hyperdrive] restartPfpHyperdrive: store/drive recreated')
    return true
  } catch (e) {
    console.error('[Hyperdrive] restartPfpHyperdrive failed:', e)
    return false
  }
}

async function reopenLocalDriveIfClosing () {
  if (!store || !localDriveKeyHex) return false
  try {
    const reopened = new Hyperdrive(store, localDriveKeyHex)
    await reopened.ready()
    drive = reopened
    return true
  } catch (e) {
    // If the shared store has been closed, recreate it and the drive
    if (isStoreClosedError(e)) {
      return await restartLocalHyperdrive()
    } else {
      console.error('[Hyperdrive] reopenLocalDrive failed:', e)
      return false
    }
  }
}

async function reopenPfpDriveIfClosing () {
  if (!store || !pfpDriveKeyHex) return false
  try {
    const reopened = new Hyperdrive(store, pfpDriveKeyHex)
    await reopened.ready()
    pfpDrive = reopened
    return true
  } catch (e) {
    if (isStoreClosedError(e)) {
      return await restartPfpHyperdrive()
    } else {
      console.error('[Hyperdrive] reopenPfpDrive failed:', e)
      return false
    }
  }
}

/**
 * Store a file and its metadata under the relay's directory.
 * @param {string} identifier - Relay publicIdentifier (npub:alias) or legacy relayKey.
 * @param {string} fileHash - Hash of the file's raw data.
 * @param {Uint8Array|Buffer} data - Raw file data.
 * @param {object} metadata - Additional metadata (e.g. mime type).
 */
export async function storeFile(identifier, fileHash, data, metadata) {
  const hash = crypto.createHash('sha256').update(data).digest('hex')
  if (hash !== fileHash) {
    throw new Error('Hash mismatch')
  }

  const path = relayFilePath(identifier, fileHash)
  let exists = false
  try {
    exists = await drive.exists(path)
  } catch (err) {
    if (isClosingCoreError(err)) {
      console.warn('[Hyperdrive] storeFile detected closing core; reopening local drive...')
      const ok = await reopenLocalDriveIfClosing()
      if (ok) exists = await drive.exists(path)
      else throw err
    } else {
      throw err
    }
  }
  if (exists) {
    console.log(`[Hyperdrive] storeFile skip exists path=${path}`)
    return
  }
  const t0 = Date.now()
  try {
    await drive.put(path, data, { metadata })
  } catch (err) {
    if (isClosingCoreError(err)) {
      console.warn('[Hyperdrive] storeFile.put detected closing core; reopening local drive...')
      const ok = await reopenLocalDriveIfClosing()
      if (ok) {
        await drive.put(path, data, { metadata })
      } else {
        throw err
      }
    } else {
      throw err
    }
  }
  console.log(`[Hyperdrive] storeFile wrote path=${path} bytes=${data?.length || 0} ms=${Date.now() - t0}`)
}

async function ensurePfpDriveReady () {
  if (!pfpDrive) throw new Error('Pfp Hyperdrive not initialized')
  await pfpDrive.ready()
}

export function getPfpDriveKey () {
  return pfpDriveKeyHex
}

export async function storePfpFile(owner, fileHash, data, metadata) {
  await ensurePfpDriveReady()
  const hash = crypto.createHash('sha256').update(data).digest('hex')
  if (hash !== fileHash) {
    throw new Error('Hash mismatch')
  }

  const path = buildPfpFilePath(owner, fileHash)
  let exists = false
  try {
    exists = await pfpDrive.exists(path)
  } catch (err) {
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (isClosing) {
      console.warn('[Hyperdrive] storePfpFile detected closing core; reopening...')
      const ok = await reopenPfpDriveIfClosing()
      if (ok) exists = await pfpDrive.exists(path)
      else throw err
    } else {
      throw err
    }
  }

  if (exists) {
    console.log(`[Hyperdrive] storePfpFile skip exists path=${path}`)
    return
  }

  const t0 = Date.now()
  try {
    await pfpDrive.put(path, data, { metadata })
  } catch (err) {
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (isClosing) {
      console.warn('[Hyperdrive] storePfpFile.put detected closing core; reopening...')
      const ok = await reopenPfpDriveIfClosing()
      if (ok) {
        await pfpDrive.put(path, data, { metadata })
      } else {
        throw err
      }
    } else {
      throw err
    }
  }

  console.log(`[Hyperdrive] storePfpFile wrote path=${path} bytes=${data?.length || 0} ms=${Date.now() - t0}`)
}

export async function getPfpFile(owner, fileHash) {
  await ensurePfpDriveReady()
  const path = buildPfpFilePath(owner, fileHash)
  try {
    const buf = await pfpDrive.get(path)
    console.log(`[Hyperdrive] getPfpFile path=${path} found=${!!buf} bytes=${buf?.length || 0}`)
    return buf || null
  } catch (err) {
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (isClosing) {
      console.warn('[Hyperdrive] getPfpFile detected closing core; reopening...')
      const ok = await reopenPfpDriveIfClosing()
      if (ok) {
        try {
          const buf2 = await pfpDrive.get(path)
          console.log(`[Hyperdrive] getPfpFile(after reopen) path=${path} found=${!!buf2} bytes=${buf2?.length || 0}`)
          return buf2 || null
        } catch (err2) {
          console.error('[Hyperdrive] getPfpFile reopen failed:', err2)
          return null
        }
      }
    }
    console.error('[Hyperdrive] getPfpFile error:', err)
    return null
  }
}

export async function pfpFileExists(owner, fileHash) {
  await ensurePfpDriveReady()
  const path = buildPfpFilePath(owner, fileHash)
  try {
    return await pfpDrive.exists(path)
  } catch (err) {
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (isClosing) {
      console.warn('[Hyperdrive] pfpFileExists detected closing core; reopening...')
      const ok = await reopenPfpDriveIfClosing()
      if (ok) {
        try {
          return await pfpDrive.exists(path)
        } catch (err2) {
          console.error('[Hyperdrive] pfpFileExists reopen failed:', err2)
          return false
        }
      }
    }
    console.error('[Hyperdrive] pfpFileExists error:', err)
    return false
  }
}

/**
 * Fetch a file from the local Hyperdrive instance.
 * @param {string} identifier - Relay folder identifier (publicIdentifier or relayKey).
 * @param {string} fileHash - Identifier of the file.
 * @returns {Promise<Uint8Array|null>}
 */
export async function getFile(identifier, fileHash) {
  // Hyperdrive.get returns the blob Buffer directly or null
  const path = relayFilePath(identifier, fileHash)
  try {
    const buf = await drive.get(path)
    console.log(`[Hyperdrive] getFile path=${path} found=${!!buf} bytes=${buf?.length || 0}`)
    return buf || null
  } catch (err) {
    // Handle cases where the underlying core is closing/closed
    const msg = err?.message || ''
    const code = err?.code || ''
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (isClosing && (store || storageDir) && localDriveKeyHex) {
      try {
        console.warn('[Hyperdrive] getFile detected closing core; reopening local drive...')
        // Reopen the local drive using the same key
        const ok = await reopenLocalDriveIfClosing()
        if (!ok) throw err
        const buf2 = await drive.get(path)
        console.log(`[Hyperdrive] getFile(after reopen) path=${path} found=${!!buf2} bytes=${buf2?.length || 0}`)
        return buf2 || null
      } catch (e2) {
        console.error('[Hyperdrive] getFile reopen failed:', e2)
        return null
      }
    }
    console.error('[Hyperdrive] getFile error:', err)
    return null
  }
}

/**
 * Lightweight existence check for a file path without reading the blob.
 * @param {string} identifier
 * @param {string} fileHash
 * @returns {Promise<boolean>}
 */
export async function fileExists(identifier, fileHash) {
  try {
    const path = relayFilePath(identifier, fileHash)
    let ok = false
    try {
      ok = await drive.exists(path)
    } catch (err) {
      const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
      if (isClosing && (store || storageDir) && localDriveKeyHex) {
        console.warn('[Hyperdrive] fileExists detected closing core; reopening local drive...')
        try {
          const ok2 = await reopenLocalDriveIfClosing()
          if (!ok2) return false
          ok = await drive.exists(path)
        } catch (e2) {
          console.error('[Hyperdrive] fileExists reopen failed:', e2)
          return false
        }
      } else {
        throw err
      }
    }
    return ok
  } catch (_) {
    return false
  }
}

/**
 * Delete one local relay file (identifier + file hash) from Hyperdrive.
 * Returns deleted=false when the file does not exist locally.
 * @param {string} identifier
 * @param {string} fileHash
 * @returns {Promise<{deleted:boolean, reason?:string}>}
 */
export async function deleteRelayFile (identifier, fileHash) {
  const normalizedIdentifier = normalizeIdentifier(identifier)
  const normalizedHash = String(fileHash || '').trim().toLowerCase()
  if (!normalizedIdentifier || !normalizedHash) {
    return { deleted: false, reason: 'invalid-identifier-or-file-hash' }
  }
  if (!drive) throw new Error('Hyperdrive not initialized')

  const key = relayFilePath(normalizedIdentifier, normalizedHash)
  let exists = false
  try {
    exists = await drive.exists(key)
  } catch (err) {
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (!isClosing || !(store || storageDir) || !localDriveKeyHex) throw err
    const ok = await reopenLocalDriveIfClosing()
    if (!ok) throw err
    exists = await drive.exists(key)
  }

  if (!exists) return { deleted: false, reason: 'not-found' }

  try {
    await drive.del(key)
    return { deleted: true }
  } catch (err) {
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (!isClosing || !(store || storageDir) || !localDriveKeyHex) throw err
    const ok = await reopenLocalDriveIfClosing()
    if (!ok) throw err
    await drive.del(key)
    return { deleted: true }
  }
}

export async function deleteRelayFilesByIdentifierPrefix (identifier) {
  const normalizedIdentifier = normalizeIdentifier(identifier)
  if (!normalizedIdentifier) return { deletedCount: 0 }
  if (!drive) throw new Error('Hyperdrive not initialized')

  const prefix = relayPath(normalizedIdentifier)
  let deletedCount = 0
  let keys = []
  try {
    for await (const entry of drive.list(prefix, { recursive: true })) {
      if (!entry?.key) continue
      keys.push(entry.key)
    }
  } catch (err) {
    const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
    if (isClosing && (store || storageDir) && localDriveKeyHex) {
      console.warn('[Hyperdrive] deleteRelayFilesByIdentifierPrefix detected closing core; reopening local drive...')
      const ok = await reopenLocalDriveIfClosing()
      if (ok) {
        keys = []
        for await (const entry of drive.list(prefix, { recursive: true })) {
          if (!entry?.key) continue
          keys.push(entry.key)
        }
      } else {
        throw err
      }
    } else {
      throw err
    }
  }

  for (const key of keys) {
    try {
      await drive.del(key)
      deletedCount += 1
    } catch (err) {
      const isClosing = isClosingCoreError(err) || isStoreClosedError(err)
      if (isClosing && (store || storageDir) && localDriveKeyHex) {
        const ok = await reopenLocalDriveIfClosing()
        if (!ok) throw err
        await drive.del(key)
        deletedCount += 1
      } else {
        throw err
      }
    }
  }

  return { deletedCount }
}

export async function fetchFileFromDrive(driveKey, identifier, fileHash) {
  const normalizedDriveKey = ensureHexKey(driveKey)
  const path = relayFilePath(identifier, fileHash)
  if (drive && normalizedDriveKey && localDriveKeyHex && normalizedDriveKey === localDriveKeyHex) {
    let local = await drive.get(path, { wait: false }).catch(() => null)
    if (!local) {
      local = await withReadTimeout(drive.get(path), 5000).catch(() => null)
    }
    return local || null
  }

  const remote = new Hyperdrive(store, driveKey)
  await remote.ready()
  let release = null
  try {
    // Join the remote drive topic (cached) to discover peers holding it
    const done = remote.findingPeers()
    try {
      release = await withJoinTimeout(acquireRemoteTopic(remote), 8000)
    } catch (error) {
      console.warn('[Fetch] remote topic join timeout, continuing without join lock', {
        remoteKey: driveKey,
        error: error?.message || error
      })
    }
    console.log(`[Fetch] join topic remoteKey=${driveKey} dkey=${b4a.toString(remote.discoveryKey, 'hex')} ident=/${normalizeIdentifier(identifier)} file=${fileHash}`)
    done()
    const t0 = Date.now()
    let buf = await remote.get(path, { wait: false }).catch(() => null)
    if (!buf) {
      buf = await withReadTimeout(remote.get(path), 10000).catch((error) => {
        console.warn('[Fetch] remote.get timed out', {
          path,
          remoteKey: driveKey,
          error: error?.message || error
        })
        return null
      })
    }
    console.log(`[Fetch] remote.get path=${path} found=${!!buf} bytes=${buf?.length || 0} ms=${Date.now() - t0}`)
    return buf || null
  } catch (_) {
    return null
  } finally {
    try {
      await remote.close()
      console.log(`[Fetch] remote drive closed key=${driveKey}`)
    } catch (_) {}
    try { release?.() } catch (_) {}
  }
}

export async function fetchPfpFileFromDrive(driveKey, owner, fileHash) {
  if (!driveKey) return null
  const core = pfpStore || store
  const remote = new Hyperdrive(core, driveKey)
  await remote.ready()
  let release = null
  try {
    const done = remote.findingPeers()
    try {
      release = await withJoinTimeout(acquireRemoteTopic(remote), 8000)
    } catch (error) {
      console.warn('[FetchPfp] remote topic join timeout, continuing without join lock', {
        remoteKey: driveKey,
        error: error?.message || error
      })
    }
    done()
    const path = buildPfpFilePath(owner, fileHash)
    const t0 = Date.now()
    let buf = await remote.get(path, { wait: false }).catch(() => null)
    if (!buf) {
      buf = await withReadTimeout(remote.get(path), 10000).catch((error) => {
        console.warn('[FetchPfp] remote.get timed out', {
          path,
          remoteKey: driveKey,
          error: error?.message || error
        })
        return null
      })
    }
    console.log(`[FetchPfp] remote.get path=${path} found=${!!buf} bytes=${buf?.length || 0} ms=${Date.now() - t0}`)
    return buf || null
  } catch (err) {
    console.error('[FetchPfp] error fetching from remote drive:', err?.message || err)
    return null
  } finally {
    try { await remote.close() } catch (_) {}
    try { release?.() } catch (_) {}
  }
}

export async function mirrorPfpDrive(remoteKeyHex) {
  if (!remoteKeyHex) return
  if (!pfpDrive) throw new Error('Pfp Hyperdrive not initialized')

  const core = pfpStore || store
  const remote = new Hyperdrive(core, remoteKeyHex)
  await remote.ready()
  let release = null
  try {
    if (typeof remote.mirror !== 'function') {
      console.warn('[PfpMirror] remote.mirror not available for key', remoteKeyHex)
      return
    }
    const done = remote.findingPeers()
    try {
      release = await withJoinTimeout(acquireRemoteTopic(remote), 8000)
    } catch (error) {
      console.warn('[PfpMirror] remote topic join timeout, continuing without join lock', {
        remoteKey: remoteKeyHex,
        error: error?.message || error
      })
    }
    done()
    const mirror = remote.mirror(pfpDrive, {
      prune: false,
      includeEquals: false,
      filter: () => true
    })
    console.log(`[PfpMirror] start remote=${remoteKeyHex.slice(0, 12)}`)
    for await (const _diff of mirror) {
      // No per-file logging to keep noise low
    }
    console.log(`[PfpMirror] complete remote=${remoteKeyHex.slice(0, 12)} files=${mirror.count?.files ?? 'n/a'}`)
  } catch (err) {
    console.error('[PfpMirror] mirror error for', remoteKeyHex, err)
  } finally {
    try { release?.() } catch (_) {}
    try { await remote.close() } catch (_) {}
  }
}

export function watchDrive (onChange) {
  if (!drive) throw new Error('Hyperdrive not initialized')
  let stopped = false
  let currentWatcher = null

  async function runWatcherLoop () {
    while (!stopped) {
      try {
        currentWatcher = drive.watch('/')
        console.log('[Hyperdrive] watch registered for /')
        for await (const [curr, prev] of currentWatcher) {
          try {
            console.log(`[Hyperdrive] update prev=${prev?.version} curr=${curr?.version}`)
            let c = 0
            for await (const diff of drive.diff(prev.version, '/')) {
              const entry = diff.left || diff.right
              if (!entry) continue
              const type = diff.left && !diff.right ? 'add' : (!diff.left && diff.right ? 'del' : 'update')
              try {
                if (c < 20) console.log(`[Hyperdrive] diff type=${type} key=${entry.key}`)
                c++
                await onChange({ type, path: entry.key })
              } catch (cbErr) {
                console.error('[Hyperdrive] watch callback error:', cbErr)
              }
            }
          } catch (loopErr) {
            if (isClosingCoreError(loopErr)) {
              console.warn('[Hyperdrive] diff loop detected closing core; attempting reopen...')
              const ok = await reopenLocalDriveIfClosing()
              if (!ok) throw loopErr
              // After reopen, break to restart outer while and re-create watcher
              break
            } else {
              console.error('[Hyperdrive] watch diff error:', loopErr)
            }
          }
        }
        if (!stopped) {
          // Watcher ended unexpectedly (destroyed or stream finished); restart
          console.warn('[Hyperdrive] watcher ended; restarting...')
        }
      } catch (err) {
        if (isClosingCoreError(err)) {
          console.warn('[Hyperdrive] watch detected closing core; attempting reopen...')
          const ok = await reopenLocalDriveIfClosing()
          if (!ok) {
            console.error('[Hyperdrive] watch reopen failed; aborting watcher loop')
            break
          }
          // loop continues to restart watcher
        } else {
          console.error('[Hyperdrive] watch error:', err)
          break
        }
      }
    }
  }

  runWatcherLoop().catch(err => console.error('[Hyperdrive] watcher loop error:', err))

  // Return the first watcher for compatibility (not used by callers currently)
  return currentWatcher
}

/**
 * Get replication health metrics for the local Hyperdrive.
 * @returns {Object}
 */
export function getReplicationHealth () {
  const topics = []
  for (const [key, entry] of topicCache.entries()) {
    topics.push({
      discoveryKey: key,
      refCount: entry.refCount,
      lastUsed: entry.lastUsed
    })
  }
  return {
    driveKey: drive ? b4a.toString(drive.key, 'hex') : null,
    discoveryKey: drive ? b4a.toString(drive.discoveryKey, 'hex') : null,
    openConnections: replicationConnectionsOpen,
    totalConnections: replicationConnectionsTotal,
    topicsJoined: topicCache.size,
    topics
  }
}

// Test-only cleanup helper to avoid dangling Hyperdrive/Hyperswarm handles.
export async function shutdownHyperdriveForTests () {
  for (const cache of [topicCache, pfpTopicCache]) {
    for (const entry of cache.values()) {
      try { entry?.discovery?.destroy?.() } catch (_) {}
      if (entry?.timer) {
        try { clearTimeout(entry.timer) } catch (_) {}
      }
    }
    cache.clear()
  }

  for (const entry of relayStores.values()) {
    try { await entry?.store?.close?.() } catch (_) {}
  }
  relayStores.clear()

  try { await pfpDrive?.close?.() } catch (_) {}
  try { await drive?.close?.() } catch (_) {}

  if (pfpStore && pfpStore !== store) {
    try { await pfpStore.close?.() } catch (_) {}
  }
  try { await store?.close?.() } catch (_) {}
  try { await replicationSwarm?.destroy?.() } catch (_) {}

  store = null
  drive = null
  localDriveKeyHex = null
  pfpDrive = null
  pfpDriveKeyHex = null
  pfpStore = null
  storageDir = null
  replicationSwarm = null
  replicationConnectionsOpen = 0
  replicationConnectionsTotal = 0
}
