import test from 'brittle'

import MarmotService from '../marmot-service.mjs'

function createLogger() {
  return {
    info() {},
    warn() {},
    error() {}
  }
}

test('refreshGroupsMap quarantines unreadable client state and continues loading valid groups', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const quarantined = []
  service.groupStateStorageBackend = {
    quarantineItem: async (groupId, reason) => {
      quarantined.push({ groupId, reason })
      return `/tmp/${groupId}.${reason}.bin`
    }
  }

  service.client = {
    groupStateStore: {
      list: async () => ['good-group', 'bad-group']
    },
    getGroup: async (groupId) => {
      if (groupId === 'bad-group') {
        throw new Error(
          'Failed to deserialize ClientState: This error should never occur, if you see this please submit a bug report. Message: The last node in the ratchet tree must be non-blank.'
        )
      }

      return {
        idStr: groupId,
        relays: ['wss://relay.test'],
        groupData: { name: 'Chat', description: '', adminPubkeys: [] },
        state: {}
      }
    },
    clearGroupInstance: () => {}
  }

  await service.refreshGroupsMap()

  t.alike(Array.from(service.groupsById.keys()), ['good-group'])
  t.alike(quarantined, [
    {
      groupId: 'bad-group',
      reason: 'deserialize-failure'
    }
  ])
})

test('refreshGroupsMap rethrows non-deserialization errors', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  service.groupStateStorageBackend = {
    quarantineItem: async () => null
  }

  service.client = {
    groupStateStore: {
      list: async () => ['bad-group']
    },
    getGroup: async () => {
      throw new Error('network exploded')
    },
    clearGroupInstance: () => {}
  }

  await t.exception(
    service.refreshGroupsMap(),
    /network exploded/
  )
})
