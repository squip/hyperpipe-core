import test from 'brittle'
import fs from 'fs/promises'
import path from 'path'
import os from 'os'
import crypto from 'crypto'

import {
  initializeHyperdrive,
  ensureRelayFolder,
  storeFile,
  getFile,
  fetchFileFromDrive,
  shutdownHyperdriveForTests
} from '../hyperdrive-manager.mjs'

test('fetchFileFromDrive retrieves and stores file', async t => {
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'sync-'))
  const previousUserConfig = global.userConfig
  const previousStorageEnv = process.env.STORAGE_DIR
  global.userConfig = { storage: tmp }
  process.env.STORAGE_DIR = tmp
  const config = { storage: tmp, relays: [] }
  try {
    await initializeHyperdrive(config)
    const relayKey = 'relay1'
    const data = Buffer.from('hello world')
    const hash = crypto.createHash('sha256').update(data).digest('hex')
    await ensureRelayFolder(relayKey)
    await storeFile(relayKey, hash, data, {})

    const fetched = await fetchFileFromDrive(config.driveKey, relayKey, hash)
    t.alike(fetched, data)

    const stored = await getFile(relayKey, hash)
    t.alike(stored, data)

    // Second store should be a no-op and not throw
    await storeFile(relayKey, hash, fetched, {})
  } finally {
    await shutdownHyperdriveForTests()
    global.userConfig = previousUserConfig
    if (previousStorageEnv === undefined) delete process.env.STORAGE_DIR
    else process.env.STORAGE_DIR = previousStorageEnv
    await fs.rm(tmp, { recursive: true, force: true })
  }
})
