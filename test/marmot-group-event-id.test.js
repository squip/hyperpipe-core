import test from 'brittle'

import MarmotService from '../marmot-service.mjs'

function createLogger() {
  return {
    info() {},
    warn() {},
    error() {},
    debug() {}
  }
}

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(String(hex), 'hex'))
}

test('syncConversation queries relay events with the embedded nostr group id', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const localGroupId = 'cd9a3eb5f961292ab0928fb6b8f49e2e72bd036819c7b1ee21428bcb1029c6de'
  const nostrGroupId = '2b352acf4419f484aa3289494b98a152e6f3c1347d6d0f428217be722b0e2390'
  const captured = []

  service.client = {
    getGroup: async () => ({
      idStr: localGroupId,
      relays: ['wss://relay.test'],
      groupData: {
        name: 'Chat',
        description: '',
        adminPubkeys: [],
        nostrGroupId: hexToBytes(nostrGroupId)
      },
      state: {}
    })
  }

  service.network = {
    request: async (_relays, filter) => {
      captured.push(filter)
      return []
    }
  }

  await service.syncConversation(localGroupId)

  t.alike(captured, [
    {
      kinds: [445],
      '#h': [nostrGroupId]
    }
  ])
})

test('deriveInvitePreview queries metadata with the embedded nostr group id', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const localGroupId = 'cd9a3eb5f961292ab0928fb6b8f49e2e72bd036819c7b1ee21428bcb1029c6de'
  const nostrGroupId = '2b352acf4419f484aa3289494b98a152e6f3c1347d6d0f428217be722b0e2390'
  const captured = []

  service.pubkey = 'a'.repeat(64)
  service.relays = ['wss://relay.test']
  service.network = {
    request: async (_relays, filter) => {
      captured.push(filter)
      return []
    }
  }

  const previewClient = {
    joinGroupFromWelcome: async () => ({
      group: {
        idStr: localGroupId,
        relays: ['wss://relay.test'],
        groupData: {
          name: 'Chat',
          description: '',
          adminPubkeys: ['a'.repeat(64)],
          nostrGroupId: hexToBytes(nostrGroupId)
        },
        state: {
          ratchetTree: []
        }
      }
    })
  }

  const preview = await service.deriveInvitePreview({
    id: 'invite-1',
    senderPubkey: 'b'.repeat(64),
    welcomeRumor: { id: 'welcome-1' }
  }, previewClient)

  t.is(preview?.conversationId, localGroupId)
  t.alike(captured, [
    {
      kinds: [445],
      '#h': [nostrGroupId],
      limit: 400
    },
    {
      kinds: [445],
      limit: 400
    }
  ])
})

test('syncConversation falls back to client-side h-tag filtering when relays return no #h matches', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const localGroupId = 'cd9a3eb5f961292ab0928fb6b8f49e2e72bd036819c7b1ee21428bcb1029c6de'
  const nostrGroupId = '2b352acf4419f484aa3289494b98a152e6f3c1347d6d0f428217be722b0e2390'
  const foreignGroupId = '5032ead91764353a1cee69d15b4314d50b9209084b4d3d9e6261f22533f599a9'
  const captured = []
  let ingested = null

  const matchingEvent = {
    id: 'event-1',
    created_at: 100,
    tags: [['h', nostrGroupId]]
  }
  const foreignEvent = {
    id: 'event-2',
    created_at: 101,
    tags: [['h', foreignGroupId]]
  }

  service.client = {
    getGroup: async () => ({
      idStr: localGroupId,
      relays: ['wss://relay.test'],
      groupData: {
        name: 'Chat',
        description: '',
        adminPubkeys: [],
        nostrGroupId: hexToBytes(nostrGroupId)
      },
      state: {},
      ingest: async function * (events) {
        ingested = events
      }
    })
  }

  service.network = {
    request: async (_relays, filter) => {
      captured.push(filter)
      if ('#h' in filter) return []
      return [foreignEvent, matchingEvent]
    }
  }

  service.lastSyncAtByConversation.set(localGroupId, 120)
  await service.syncConversation(localGroupId)

  t.alike(captured, [
    {
      kinds: [445],
      '#h': [nostrGroupId],
      since: 100
    },
    {
      kinds: [445],
      since: 100,
      limit: 400
    }
  ])
  t.alike(ingested, [matchingEvent])
})

test('syncConversation accepts wrapped applicationMessage ingest results from current marmot-ts', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const localGroupId = 'cd9a3eb5f961292ab0928fb6b8f49e2e72bd036819c7b1ee21428bcb1029c6de'
  const nostrGroupId = '2b352acf4419f484aa3289494b98a152e6f3c1347d6d0f428217be722b0e2390'
  const remotePubkey = 'b'.repeat(64)
  const event = {
    id: 'event-1',
    created_at: 123,
    pubkey: remotePubkey,
    tags: [['h', nostrGroupId]]
  }
  const rumor = {
    id: 'rumor-1',
    kind: 14,
    pubkey: remotePubkey,
    created_at: 123,
    content: 'hello from remote',
    tags: []
  }
  const encodedRumor = new TextEncoder().encode(JSON.stringify(rumor))

  service.client = {
    getGroup: async () => ({
      idStr: localGroupId,
      relays: ['wss://relay.test'],
      groupData: {
        name: 'Chat',
        description: '',
        adminPubkeys: [],
        nostrGroupId: hexToBytes(nostrGroupId)
      },
      state: {},
      ingest: async function * () {
        yield {
          kind: 'processed',
          event,
          result: {
            kind: 'applicationMessage',
            message: encodedRumor
          }
        }
      }
    })
  }

  service.network = {
    request: async () => [event]
  }

  const syncResult = await service.syncConversation(localGroupId)
  const storedMessages = service.getMessages(localGroupId)

  t.is(syncResult.changed, true)
  t.is(syncResult.newMessages.length, 1)
  t.is(storedMessages.length, 1)
  t.is(storedMessages[0].id, rumor.id)
  t.is(storedMessages[0].content, rumor.content)
  t.is(service.lastSyncAtByConversation.get(localGroupId), 123)
})
