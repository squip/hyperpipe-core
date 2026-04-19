import test from 'brittle'
import { Buffer } from 'node:buffer'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
const BlindPeering = require('../vendor/blind-peering/index.js')

function createBlindPeering() {
  return new BlindPeering(
    { dht: { on() {} } },
    { replicate() {} },
    { mirrors: [] }
  )
}

test('blind-peering replicates a late-added core onto an existing mirror stream', async t => {
  const blind = createBlindPeering()
  const stream = { destroyed: false, destroying: false, userData: null }
  const replicated = []
  const ref = {
    refs: 0,
    gc: 0,
    uploaded: 0,
    cores: new Map(),
    peer: {
      stream,
      addCore: async () => ({ ok: true }),
      isReplicating: async () => false
    }
  }
  const core = {
    id: 'late-core',
    key: Buffer.alloc(32, 1),
    closing: false,
    closed: false,
    opened: true,
    ready: async () => {},
    on() {},
    replicate(target) {
      replicated.push(target)
    }
  }

  blind._getBlindPeer = () => ref
  blind._releaseMirror = () => {}

  const result = await blind._mirrorCore(Buffer.alloc(32, 2), core, false, Buffer.alloc(32, 3), 1)

  t.alike(result, { ok: true })
  t.is(replicated.length, 1)
  t.is(replicated[0], stream)
})

test('blind-peering mirrors late-added base writers onto an existing mirror stream', async t => {
  const blind = createBlindPeering()
  const stream = { destroyed: false, destroying: false, userData: null }
  const replicated = []
  const ref = {
    refs: 0,
    gc: 0,
    uploaded: 0,
    cores: new Map(),
    peer: {
      stream,
      addCore: async () => ({ ok: true }),
      isReplicating: async () => false
    }
  }
  const core = {
    id: 'base-writer-core',
    key: Buffer.alloc(32, 4),
    on() {},
    replicate(target) {
      replicated.push(target)
    }
  }
  const base = {
    wakeupCapability: { key: Buffer.alloc(32, 5) }
  }

  blind._releaseMirror = () => {}

  await blind._mirrorBaseWriter(ref, base, core, true)

  t.is(replicated.length, 1)
  t.is(replicated[0], stream)
})
