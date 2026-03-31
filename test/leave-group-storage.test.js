import test from 'brittle'
import fs from 'node:fs/promises'
import path from 'node:path'
import os from 'node:os'
import crypto from 'node:crypto'

import {
  initializeHyperdrive,
  ensureRelayFolder,
  storeFile,
  getFile,
  deleteRelayFilesByIdentifierPrefix,
  getRelayCorestore,
  removeRelayCorestore,
  shutdownHyperdriveForTests
} from '../hyperdrive-manager.mjs'

function sha256Hex(input) {
  return crypto.createHash('sha256').update(input).digest('hex')
}

test('deleteRelayFilesByIdentifierPrefix removes only matching relay entries', async (t) => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'leave-group-storage-'))
  const previousUserConfig = global.userConfig
  const previousStorageEnv = process.env.STORAGE_DIR

  global.userConfig = { storage: tmp }
  process.env.STORAGE_DIR = tmp

  try {
    await initializeHyperdrive({ storage: tmp, relays: [] })

    const relayA = 'group-a'
    const relayB = 'group-b'
    await ensureRelayFolder(relayA)
    await ensureRelayFolder(relayB)

    const relayAData1 = Buffer.from('relay-a-file-1')
    const relayAHash1 = sha256Hex(relayAData1)
    const relayAData2 = Buffer.from('relay-a-file-2')
    const relayAHash2 = sha256Hex(relayAData2)
    const relayBData = Buffer.from('relay-b-file-1')
    const relayBHash = sha256Hex(relayBData)

    await storeFile(relayA, relayAHash1, relayAData1, { test: true })
    await storeFile(relayA, relayAHash2, relayAData2, { test: true })
    await storeFile(relayB, relayBHash, relayBData, { test: true })

    const deleted = await deleteRelayFilesByIdentifierPrefix(relayA)
    t.is(deleted.deletedCount, 2)

    t.is(await getFile(relayA, relayAHash1), null)
    t.is(await getFile(relayA, relayAHash2), null)
    t.alike(await getFile(relayB, relayBHash), relayBData)
  } finally {
    await shutdownHyperdriveForTests()
    global.userConfig = previousUserConfig
    if (previousStorageEnv === undefined) delete process.env.STORAGE_DIR
    else process.env.STORAGE_DIR = previousStorageEnv
    await fs.rm(tmp, { recursive: true, force: true })
  }
})

test('removeRelayCorestore closes and evicts relay corestore handle', async (t) => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'leave-group-corestore-'))
  try {
    const relayKey = 'a'.repeat(64)
    const relayStore = getRelayCorestore(relayKey, { storageBase: tmp })
    await relayStore.ready()

    const removed = await removeRelayCorestore(relayKey)
    t.is(removed, true)

    const removedAgain = await removeRelayCorestore(relayKey)
    t.is(removedAgain, false)
  } finally {
    await fs.rm(tmp, { recursive: true, force: true })
  }
})
