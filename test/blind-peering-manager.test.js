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
  t.is(manager.getStatus().runtimeMirrors, 2)

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

test('blind peering manager primes relay system cores with the autobase wakeup referrer', async t => {
  const manager = new BlindPeeringManager({
    logger: quietLogger,
    settingsProvider: () => ({
      blindPeerEnabled: true,
      blindPeerKeys: []
    })
  })

  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-peering-referrer-'))
  const store = new Corestore(tmp)
  const wakeupKey = Buffer.alloc(32, 8)
  const systemKey = Buffer.alloc(32, 9)
  const relayKey = HypercoreId.encode(Buffer.alloc(32, 10))
  const mirrorKey = HypercoreId.encode(Buffer.alloc(32, 11))
  const systemCore = store.get({ key: systemKey, valueEncoding: 'binary', sparse: true })
  const addAutobaseCalls = []
  const addCoreCalls = []
  const addCoreBackgroundCalls = []

  manager.started = true
  manager.runtime = { corestore: store }
  manager.blindPeering = {
    addAutobaseBackground: (...args) => {
      addAutobaseCalls.push(args)
    },
    addCore: (...args) => {
      addCoreCalls.push(args)
      return [true]
    },
    addCoreBackground: (...args) => {
      addCoreBackgroundCalls.push(args)
    }
  }

  try {
    manager.ensureRelayMirror({
      relayKey,
      corestore: store,
      mirrorKeys: [mirrorKey],
      autobase: {
        system: { core: systemCore },
        wakeupCapability: { key: wakeupKey }
      }
    })

    t.is(addAutobaseCalls.length, 1)
    t.ok(addCoreCalls.length >= 1)

    const systemCoreCall = addCoreCalls.find(([core]) => Buffer.compare(core?.key || Buffer.alloc(0), systemKey) === 0)
    t.ok(systemCoreCall, 'expected the lease-critical system core to be primed')
    const systemCoreBackgroundCall = addCoreBackgroundCalls.find(([core]) => Buffer.compare(core?.key || Buffer.alloc(0), systemKey) === 0)
    t.is(systemCoreBackgroundCall, undefined, 'system core should use explicit mirror publish, not background-only scheduling')

    const [, target, options] = systemCoreCall
    t.alike(target, wakeupKey)
    t.is(options?.referrer, HypercoreId.encode(wakeupKey))
    t.alike(options?.mirrors, [HypercoreId.decode(mirrorKey)])

    const [, autobaseTarget, autobaseOptions] = addAutobaseCalls[0]
    t.alike(autobaseTarget, wakeupKey)
    t.alike(autobaseOptions?.mirrors, [HypercoreId.decode(mirrorKey)])
  } finally {
    await store.close()
    await fs.rm(tmp, { recursive: true, force: true })
  }
})

test('blind peering manager retries lease-critical system core publish when no mirror acknowledgement arrives', async t => {
  const manager = new BlindPeeringManager({
    logger: quietLogger,
    settingsProvider: () => ({
      blindPeerEnabled: true,
      blindPeerKeys: []
    })
  })

  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'blind-peering-system-retry-'))
  const store = new Corestore(tmp)
  const wakeupKey = Buffer.alloc(32, 12)
  const systemKey = Buffer.alloc(32, 13)
  const relayKey = HypercoreId.encode(Buffer.alloc(32, 14))
  const mirrorKey = HypercoreId.encode(Buffer.alloc(32, 15))
  const systemCore = store.get({ key: systemKey, valueEncoding: 'binary', sparse: true })
  const addCoreCalls = []

  manager.started = true
  manager.runtime = { corestore: store }
  manager.systemCorePublishConfig.retryDelayMs = 1
  manager.systemCorePublishConfig.maxAttempts = 3
  manager.blindPeering = {
    addAutobaseBackground: () => {},
    addCore: (...args) => {
      addCoreCalls.push(args)
      return addCoreCalls.length === 1 ? [false] : [true]
    },
    addCoreBackground: () => {}
  }

  try {
    manager.ensureRelayMirror({
      relayKey,
      corestore: store,
      mirrorKeys: [mirrorKey],
      autobase: {
        system: { core: systemCore },
        wakeupCapability: { key: wakeupKey }
      }
    })

    await new Promise((resolve) => setTimeout(resolve, 20))

    t.ok(addCoreCalls.length >= 2, 'expected explicit system-core publish to retry after a missing acknowledgement')
    const firstCall = addCoreCalls[0]
    const secondCall = addCoreCalls[1]
    t.alike(firstCall[1], wakeupKey)
    t.alike(secondCall[1], wakeupKey)
    t.is(firstCall[2]?.referrer, HypercoreId.encode(wakeupKey))
    t.is(secondCall[2]?.referrer, HypercoreId.encode(wakeupKey))
  } finally {
    await manager.stop()
    await store.close()
    await fs.rm(tmp, { recursive: true, force: true })
  }
})
