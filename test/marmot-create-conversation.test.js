import test from 'brittle'

import MarmotService from '../marmot-service.mjs'

function hex64 (char) {
  return String(char).repeat(64)
}

function createDeferred () {
  let resolve = null
  let reject = null
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

function createLogger () {
  return {
    info () {},
    warn () {},
    error () {}
  }
}

function buildConversationSummary (service, group) {
  return {
    id: group.idStr,
    protocol: 'marmot',
    participants: [service.pubkey, hex64('b')],
    adminPubkeys: [service.pubkey],
    canInviteMembers: true,
    title: 'Chat',
    description: null,
    imageUrl: null,
    unreadCount: 0,
    lastMessageAt: 0,
    lastReadAt: 0
  }
}

test('createConversationShell returns before invite and sync completion, then emits background phases', async (t) => {
  const workerMessages = []
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: (message) => workerMessages.push(message),
    logger: createLogger()
  })

  const group = {
    idStr: 'conv-shell-1',
    relays: ['wss://relay.test'],
    groupData: {
      name: 'Chat',
      description: '',
      adminPubkeys: [hex64('a')]
    },
    state: {}
  }

  service.pubkey = hex64('a')
  service.relays = ['wss://relay.test']
  service.schedulePersist = () => {}
  service.client = {
    createGroup: async () => group,
    getGroup: async () => group
  }
  service.buildConversationSummary = (value) => buildConversationSummary(service, value)

  const inviteDeferred = createDeferred()
  service.inviteMembers = async (conversationId, members) => {
    t.is(conversationId, 'conv-shell-1')
    t.alike(members, [hex64('b')])
    await inviteDeferred.promise
    return {
      conversationId,
      invited: [hex64('b')],
      failed: [],
      conversation: buildConversationSummary(service, group)
    }
  }
  service.syncConversation = async (conversationId) => {
    t.is(conversationId, 'conv-shell-1')
  }

  const shell = await service.createConversationShell({
    title: 'Chat',
    members: [hex64('b')],
    relayUrls: ['wss://relay.test']
  })

  t.is(shell.conversation.id, 'conv-shell-1')
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-conversation-updated' && message.data?.conversation?.id === 'conv-shell-1'
    )
  )

  const finalizePromise = service.finalizeCreatedConversation({
    operationId: 'op-shell-1',
    conversationId: 'conv-shell-1',
    members: [hex64('b')]
  })

  await Promise.resolve()

  const invitePhase = workerMessages.find(
    (message) =>
      message.type === 'marmot-create-conversation-operation'
      && message.data?.operationId === 'op-shell-1'
      && message.data?.phase === 'invitingMembers'
  )
  t.ok(invitePhase, 'emits invitingMembers before inviteMembers resolves')

  inviteDeferred.resolve()
  const result = await finalizePromise

  t.alike(result.invited, [hex64('b')])
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-create-conversation-operation'
        && message.data?.operationId === 'op-shell-1'
        && message.data?.phase === 'syncingConversation'
    )
  )
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-create-conversation-operation'
        && message.data?.operationId === 'op-shell-1'
        && message.data?.phase === 'completed'
    )
  )
})

test('createConversationShell failures do not emit background operation phases', async (t) => {
  const workerMessages = []
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: (message) => workerMessages.push(message),
    logger: createLogger()
  })

  service.pubkey = hex64('a')
  service.relays = ['wss://relay.test']
  service.schedulePersist = () => {}
  service.client = {
    createGroup: async () => {
      throw new Error('create failed')
    }
  }
  service.buildConversationSummary = (group) => buildConversationSummary(service, group)

  await t.exception(
    async () => {
      await service.createConversationShell({
        title: 'Chat',
        members: [hex64('b')]
      })
    },
    /create failed/
  )

  t.is(
    workerMessages.find((message) => message.type === 'marmot-create-conversation-operation'),
    undefined
  )
})

test('createConversationShell uses the selected relays as the authoritative publish target set', async (t) => {
  let receivedRelays = null
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const group = {
    idStr: 'conv-shell-2',
    relays: ['wss://custom-relay.test'],
    groupData: {
      name: 'Chat',
      description: '',
      adminPubkeys: [hex64('a')]
    },
    state: {}
  }

  service.pubkey = hex64('a')
  service.relays = ['wss://default-one.test', 'wss://default-two.test']
  service.schedulePersist = () => {}
  service.client = {
    createGroup: async (_title, options = {}) => {
      receivedRelays = options.relays
      return group
    },
    getGroup: async () => group
  }
  service.buildConversationSummary = (value) => buildConversationSummary(service, value)

  const shell = await service.createConversationShell({
    title: 'Chat',
    members: [hex64('b')],
    relayUrls: ['wss://custom-relay.test']
  })

  t.is(shell.conversation.id, 'conv-shell-2')
  t.alike(receivedRelays, ['wss://custom-relay.test/'])
})

test('inviteMembers reports a failure when welcome delivery is not acknowledged by any relay', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const group = {
    idStr: 'conv-invite-ack',
    inviteByKeyPackageEvent: async () => ({
      'wss://relay.test': {
        ok: false,
        message: 'publish timed out'
      }
    })
  }

  service.pubkey = hex64('a')
  service.relays = ['wss://relay.test']
  service.schedulePersist = () => {}
  service.groupsById.set(group.idStr, group)
  service.fetchLatestKeyPackageEvent = async () => ({
    id: 'key-package-1',
    kind: 443,
    pubkey: hex64('b')
  })
  service.buildConversationSummary = () => ({
    id: group.idStr,
    protocol: 'marmot'
  })
  service.emitConversationUpdated = async () => {}

  const result = await service.inviteMembers(group.idStr, [hex64('b')])

  t.alike(result.invited, [])
  t.is(result.failed.length, 1)
  t.is(result.failed[0].pubkey, hex64('b'))
  t.ok(result.failed[0].error.includes('not acknowledged'))
  t.ok(result.failed[0].error.includes('publish timed out'))
})
