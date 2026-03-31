// hyperpipe-worker/mirror-sync-manager.mjs
// Mirrors selected subtrees from remote Hyperdrives into the local Hyperdrive
// using Hyperdrive's built-in drive.mirror (MirrorDrive) and watch-based triggers.

import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import { getCorestore, getLocalDrive, joinRemoteDriveTopic } from './hyperdrive-manager.mjs'

// Map key: `${remoteKeyHex}:${folder}` -> state
const mirrorStates = new Map()

function keyOf (remoteKeyHex, folder) {
  return `${remoteKeyHex}:${folder}`
}

function isRelayFolderMatch (key, folder) {
  if (!folder || folder === '/') return true
  if (!key || key === '/') return false
  return key === folder || key.startsWith(folder.endsWith('/') ? folder : folder + '/')
}

/**
 * Ensure a continuous mirror from a remote drive into the local drive for a given folder prefix.
 * This sets up initial full mirror and a watcher that re-runs the mirror on changes.
 *
 * @param {string} remoteKeyHex - 64-hex remote drive key
 * @param {string} folder - subtree on the remote to mirror (e.g., `/${identifier}`)
 */
export async function ensureRemoteMirror (remoteKeyHex, folder) {
  const store = getCorestore()
  const localDrive = getLocalDrive()
  if (!store || !localDrive) throw new Error('Hyperdrive not initialized')

  const k = keyOf(remoteKeyHex, folder)
  if (mirrorStates.has(k)) {
    // eslint-disable-next-line no-console
    console.log(`[Mirror] reuse existing state for ${remoteKeyHex.substring(0, 12)} ${folder}`)
    return mirrorStates.get(k)
  }

  // Normalize folder prefix to start with '/'
  const prefix = folder && folder.startsWith('/') ? folder : `/${folder || ''}`

  const remoteDrive = new Hyperdrive(store, remoteKeyHex)
  await remoteDrive.ready()
  console.log(`[Mirror] remote drive ready key=${remoteKeyHex} dkey=${b4a.toString(remoteDrive.discoveryKey, 'hex')}`)

  // eslint-disable-next-line no-console
  console.log(`[Mirror] init for ${remoteKeyHex.substring(0, 12)} folder=${prefix}`)
  const release = await joinRemoteDriveTopic(remoteDrive)
  const doneFinding = remoteDrive.findingPeers()
  // We rely on joinRemoteDriveTopic to have joined the topic on shared swarm
  doneFinding()
  await remoteDrive.update({ wait: true }).catch(() => {})

  let running = false
  let pending = false
  let closed = false
  const watcher = remoteDrive.watch(prefix)

  async function runMirror () {
    if (closed) return
    if (running) { pending = true; return }
    running = true
    try {
      if (typeof remoteDrive.mirror !== 'function') {
        console.error('[Mirror] remoteDrive.mirror is not available — check Hyperdrive version')
        return
      }
      const t0 = Date.now()
      // Use built-in mirror (MirrorDrive). We only filter keys under prefix.
      const mirror = remoteDrive.mirror(localDrive, {
        // Multiple providers mirror into the same relay folder. Pruning per-provider
        // can delete files that only exist on another provider.
        prune: false,
        batch: true,
        includeEquals: false,
        filter: (key) => isRelayFolderMatch(key, prefix)
      })
      console.log(`[Mirror] start run remote=${remoteKeyHex.substring(0, 12)} prefix=${prefix}`)
      for await (const _diff of mirror) {
        // No-op per-file; rely on count summary below for logging elsewhere if needed.
      }
      const elapsed = Date.now() - t0
      // eslint-disable-next-line no-console
      console.log(`[Mirror] ${remoteKeyHex.substring(0, 12)} ${prefix}: files=${mirror.count.files} add=${mirror.count.add} remove=${mirror.count.remove} change=${mirror.count.change} ms=${elapsed}`)
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[Mirror] Error while mirroring ${remoteKeyHex} ${prefix}:`, err)
    } finally {
      running = false
      if (pending) {
        pending = false
        runMirror().catch(() => {})
      }
    }
  }

  // Initial sync
  await runMirror()

  ;(async () => {
    try {
      await watcher.ready()
      // eslint-disable-next-line no-console
      console.log(`[Mirror] watcher ready for ${remoteKeyHex.substring(0, 12)} ${prefix}`)
      for await (const _ of watcher) {
        if (closed) break
        // Debounce by coalescing if a run is active
        runMirror().catch(() => {})
      }
    } catch (err) {
      console.error(`[Mirror] watcher error for ${remoteKeyHex} ${prefix}:`, err)
    }
  })().catch(err => console.error(`[Mirror] watcher loop error for ${remoteKeyHex} ${prefix}:`, err))

  const state = {
    remoteKeyHex,
    folder: prefix,
    remoteDrive,
    release,
    watcher,
    stop: async () => {
      closed = true
      try { await watcher.destroy() } catch (_) {}
      // Do NOT close the shared Corestore-backed remoteDrive here to avoid
      // inadvertently closing the shared corestore used by the app.
      // Just release the topic so replication stops; the drive instance will
      // be GC'ed or kept dormant.
      try { release?.() } catch (_) {}
      mirrorStates.delete(k)
    }
  }

  mirrorStates.set(k, state)
  return state
}

/**
 * Ensure mirrors for a set of provider drives for a given relay identifier.
 * @param {Iterable<string>} remoteKeysHex
 * @param {string} identifier - Relay identifier (publicIdentifier or relayKey)
 */
export async function ensureMirrorsForProviders (remoteKeysHex, identifier) {
  const folder = identifier.startsWith('/') ? identifier : `/${identifier}`
  // eslint-disable-next-line no-console
  console.log(`[Mirror] ensure for identifier=${folder} providers=${Array.from(remoteKeysHex || []).length}`)
  const tasks = []
  for (const keyHex of remoteKeysHex) {
    // Skip invalid keys
    if (!/^[a-fA-F0-9]{64}$/.test(keyHex)) continue
    // eslint-disable-next-line no-console
    console.log(`[Mirror] schedule ${keyHex.substring(0, 12)} for ${folder}`)
    tasks.push(ensureRemoteMirror(keyHex.toLowerCase(), folder))
  }
  await Promise.allSettled(tasks)
}

export async function stopAllMirrors () {
  const stops = []
  for (const state of mirrorStates.values()) {
    stops.push(state.stop().catch(() => {}))
  }
  await Promise.allSettled(stops)
}
