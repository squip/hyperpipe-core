import test from 'brittle'
import { mkdtemp } from 'node:fs/promises'
import { rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Hypercore from 'hypercore'
import Hyperbee from 'hyperbee'
import b4a from 'b4a'

import PublicGatewayHyperbeeAdapter from '@hyperpipe/bridge/public-gateway/PublicGatewayHyperbeeAdapter'

const EVENTS = [
  {
    id: '1'.repeat(64),
    kind: 1,
    pubkey: 'a'.repeat(64),
    created_at: 1700000000,
    tags: [['e', 'ref1'], ['p', 'peer1']],
    content: 'alpha'
  },
  {
    id: '2'.repeat(64),
    kind: 1,
    pubkey: 'b'.repeat(64),
    created_at: 1700000100,
    tags: [['e', 'ref2']],
    content: 'beta'
  },
  {
    id: '3'.repeat(64),
    kind: 42,
    pubkey: 'c'.repeat(64),
    created_at: 1700000200,
    tags: [['t', 'topic']],
    content: 'gamma'
  }
];

function padNumber(num, length) {
  return String(num).padStart(length, '0')
}

function padTimestamp(ts) {
  return String(ts).padStart(10, '0')
}

async function withAdapter(t, events, run) {
  const dir = await mkdtemp(join(tmpdir(), 'hyperbee-adapter-'))
  const cleanup = async () => {
    await rm(dir, { recursive: true, force: true })
  }

  const core = new Hypercore(dir, { valueEncoding: 'binary', sparse: false })
  await core.ready()
  const db = new Hyperbee(core, { keyEncoding: 'binary', valueEncoding: 'utf-8' })
  await db.ready()

  for (const event of events) {
    await db.put(b4a.from(event.id, 'hex'), JSON.stringify(event))
    await db.put(b4a.from(`created_at:${padTimestamp(event.created_at)}:id:${event.id}`, 'utf8'), event.id)
    await db.put(b4a.from(`kind:${padNumber(event.kind, 5)}:created_at:${padTimestamp(event.created_at)}:id:${event.id}`, 'utf8'), event.id)
    await db.put(b4a.from(`pubkey:${event.pubkey}:created_at:${padTimestamp(event.created_at)}:id:${event.id}`, 'utf8'), event.id)
    for (const tag of event.tags || []) {
      if (tag.length < 2) continue
      await db.put(b4a.from(`tagKey:${tag[0]}:tagValue:${tag[1]}:created_at:${padTimestamp(event.created_at)}:id:${event.id}`, 'utf8'), event.id)
    }
  }

  const relayClient = {
    getHyperbee: () => db,
    getCore: () => core
  }
  const adapter = new PublicGatewayHyperbeeAdapter({
    relayClient,
    logger: { debug: () => {} },
    maxIndexScan: 1024
  })

  try {
    await run(adapter)
  } finally {
    await db.close()
    await core.close()
    await cleanup()
  }
}

test('adapter returns events matching kind filter', async t => {
  await withAdapter(t, EVENTS, async (adapter) => {
    const { events } = await adapter.query([{ kinds: [1] }])
    t.is(events.length, 2)
    t.alike(events[0].id, EVENTS[1].id)
    t.alike(events[1].id, EVENTS[0].id)
  })
})

test('adapter enforces tag filters', async t => {
  await withAdapter(t, EVENTS, async (adapter) => {
    const { events } = await adapter.query([{ '#e': ['ref1'] }])
    t.is(events.length, 1)
    t.is(events[0].id, EVENTS[0].id)
  })
})

test('adapter applies since/until constraints', async t => {
  await withAdapter(t, EVENTS, async (adapter) => {
    const { events } = await adapter.query([
      { kinds: [1], since: 1700000050, until: 1700000150 }
    ])
    t.is(events.length, 1)
    t.is(events[0].id, EVENTS[1].id)
  })
})

test('adapter handles ids filter', async t => {
  await withAdapter(t, EVENTS, async (adapter) => {
    const { events } = await adapter.query([
      { ids: [EVENTS[2].id], kinds: [42] }
    ])
    t.is(events.length, 1)
    t.is(events[0].content, 'gamma')
  })
})
