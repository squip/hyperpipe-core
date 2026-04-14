import test from 'brittle'
import fs from 'fs/promises'
import os from 'os'
import path from 'path'
import Corestore from 'corestore'

import HypercoreId from 'hypercore-id-encoding'
import BlindPeeringManager from '../blind-peering-manager.mjs'

const quietLogger = {
  debug () {},
  info () {},
  warn () {}
}

test('blind peering manager disabled by default', t => {
  const manager = new BlindPeeringManager({ logger: quietLogger })
  manager.configure({})
  const status = manager.getStatus()
  t.is(manager.enabled, false)
  t.is(status.running, false)
  t.is(status.trustedMirrors, 0)
})

test('blind peering manager tracks trusted mirrors', async t => {
  const manager = new BlindPeeringManager({
    logger: quietLogger,
    settingsProvider: () => ({
      blindPeerEnabled: true,
      blindPeerKeys: [
        HypercoreId.encode(Buffer.alloc(32, 1)),
        ` ${HypercoreId.encode(Buffer.alloc(32, 2))} `
      ]
    })
  })

  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-peering-'))
  const store = new Corestore(tmp)

  manager.configure()
  await manager.start({ corestore: store })

  t.is(manager.enabled, true)
  t.is(manager.started, true)
  t.is(manager.getStatus().trustedMirrors, 2)

  manager.markTrustedMirrors([
    HypercoreId.encode(Buffer.alloc(32, 3)),
    HypercoreId.encode(Buffer.alloc(32, 1))
  ])
  t.is(manager.getStatus().trustedMirrors, 3)

  await manager.stop()
  await store.close()
  await fs.rm(tmp, { recursive: true, force: true })
  t.is(manager.started, false)
})

test('blind peering manager merges manual and dispatcher metadata', async t => {
  const manualKey = HypercoreId.encode(Buffer.alloc(32, 4))
  const handshakeKey = HypercoreId.encode(Buffer.alloc(32, 5))
  const manager = new BlindPeeringManager({
    logger: quietLogger,
    settingsProvider: () => ({
      blindPeerEnabled: true,
      blindPeerManualKeys: [manualKey],
      blindPeerKeys: [handshakeKey]
    })
  })

  manager.configure()
  const status = manager.getStatus()
  t.is(status.handshakeMirrors, 1)
  t.is(status.manualMirrors, 1)
  t.is(status.trustedMirrors, 2)

  const snapshot = manager.getMirrorMetadata()
  t.ok(snapshot)
  t.is(typeof status.refreshBackoff, 'object')
})

test('blind peering manager exposes a local blind peer key after start', async t => {
  const manager = new BlindPeeringManager({
    logger: quietLogger,
    settingsProvider: () => ({
      blindPeerEnabled: true,
      blindPeerKeys: []
    })
  })

  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-peering-local-key-'))
  const store = new Corestore(tmp)
  const announcedKeys = []

  manager.on('local-key-available', (key) => {
    announcedKeys.push(key)
  })

  manager.configure()
  await manager.start({ corestore: store })

  const localBlindPeerKey = manager.getLocalBlindPeerPublicKey()
  t.is(typeof localBlindPeerKey, 'string')
  t.ok(localBlindPeerKey.length > 0)
  t.alike(announcedKeys, [localBlindPeerKey])

  await manager.stop()
  await store.close()
  await fs.rm(tmp, { recursive: true, force: true })
})

test('blind peering manager falls back to active blind peer stream key when default keypair is unavailable', t => {
  const manager = new BlindPeeringManager({
    logger: quietLogger,
    settingsProvider: () => ({
      blindPeerEnabled: true,
      blindPeerKeys: []
    })
  })

  const streamKey = HypercoreId.encode(Buffer.alloc(32, 7))
  const announcedKeys = []

  manager.started = true
  manager.blindPeering = {
    blindPeersByKey: new Map([
      ['mirror-a', {
        peer: {
          stream: {
            publicKey: HypercoreId.decode(streamKey)
          }
        }
      }]
    ])
  }

  manager.on('local-key-available', (key) => {
    announcedKeys.push(key)
  })

  const localBlindPeerKey = manager.getLocalBlindPeerPublicKey()
  t.is(localBlindPeerKey, streamKey)
  t.alike(announcedKeys, [streamKey])
})
