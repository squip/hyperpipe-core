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

async function flushTasks () {
  await new Promise((resolve) => setImmediate(resolve))
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

function buildInvite (id) {
  return {
    id,
    senderPubkey: hex64('b'),
    createdAt: 1,
    receivedAt: 1,
    status: 'pending',
    error: null,
    keyPackageEventId: null,
    relays: ['wss://relay.test'],
    conversationId: null,
    welcomeRumor: {
      id: `welcome-${id}`,
      kind: 445,
      tags: [],
      pubkey: hex64('b')
    },
    title: 'Chat invite',
    description: null,
    imageUrl: null,
    memberPubkeys: [hex64('b')]
  }
}

test('runInitialSyncOperation emits phased progress and completes after background sync', async (t) => {
  const workerMessages = []
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: (message) => workerMessages.push(message),
    logger: createLogger()
  })

  const syncDeferred = createDeferred()
  service.ensureLocalKeyPackagePublished = async () => {}
  service.syncConversations = async () => {
    await syncDeferred.promise
  }
  service.syncInvites = async () => []

  const operationPromise = service.runInitialSyncOperation('init-op-1')

  await flushTasks()

  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-init-operation'
        && message.data?.operationId === 'init-op-1'
        && message.data?.phase === 'publishingIdentity'
    )
  )
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-init-operation'
        && message.data?.operationId === 'init-op-1'
        && message.data?.phase === 'syncingConversations'
    )
  )
  t.absent(
    workerMessages.find(
      (message) =>
        message.type === 'marmot-init-operation'
        && message.data?.operationId === 'init-op-1'
        && message.data?.phase === 'completed'
    )
  )

  syncDeferred.resolve()
  await operationPromise

  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-init-operation'
        && message.data?.operationId === 'init-op-1'
        && message.data?.phase === 'syncingInvites'
    )
  )
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-init-operation'
        && message.data?.operationId === 'init-op-1'
        && message.data?.phase === 'completed'
    )
  )
})

test('runAcceptInviteOperation emits joinedConversation before sync completion', async (t) => {
  const workerMessages = []
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: (message) => workerMessages.push(message),
    logger: createLogger()
  })

  const group = {
    idStr: 'conv-join-1',
    relays: ['wss://relay.test'],
    groupData: {
      name: 'Chat',
      description: '',
      adminPubkeys: [hex64('a')]
    },
    state: {}
  }

  const syncDeferred = createDeferred()
  service.pubkey = hex64('a')
  service.relays = ['wss://relay.test']
  service.schedulePersist = () => {}
  service.invitesById.set('invite-1', buildInvite('invite-1'))
  service.client = {
    joinGroupFromWelcome: async () => group,
    getGroup: async () => group
  }
  service.buildConversationSummary = (value) => buildConversationSummary(service, value)
  service.emitConversationUpdated = async (conversationId, reason = 'update') => {
    workerMessages.push({
      type: 'marmot-conversation-updated',
      data: {
        conversation: buildConversationSummary(service, group),
        conversationId,
        reason
      }
    })
  }
  service.syncConversation = async (conversationId) => {
    t.is(conversationId, 'conv-join-1')
    await syncDeferred.promise
  }

  const operationPromise = service.runAcceptInviteOperation('join-op-1', 'invite-1')

  await flushTasks()

  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-accept-invite-operation'
        && message.data?.operationId === 'join-op-1'
        && message.data?.phase === 'joinedConversation'
        && message.data?.conversationId === 'conv-join-1'
    )
  )
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-accept-invite-operation'
        && message.data?.operationId === 'join-op-1'
        && message.data?.phase === 'syncingConversation'
    )
  )
  t.absent(
    workerMessages.find(
      (message) =>
        message.type === 'marmot-accept-invite-operation'
        && message.data?.operationId === 'join-op-1'
        && message.data?.phase === 'completed'
    )
  )

  syncDeferred.resolve()
  const result = await operationPromise

  t.is(result.conversation.id, 'conv-join-1')
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-accept-invite-operation'
        && message.data?.operationId === 'join-op-1'
        && message.data?.phase === 'completed'
    )
  )
})

test('runAcceptInviteOperation keeps the invite joined when post-join sync fails', async (t) => {
  const workerMessages = []
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: (message) => workerMessages.push(message),
    logger: createLogger()
  })

  const group = {
    idStr: 'conv-join-2',
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
  service.invitesById.set('invite-2', buildInvite('invite-2'))
  service.client = {
    joinGroupFromWelcome: async () => group,
    getGroup: async () => group
  }
  service.buildConversationSummary = (value) => buildConversationSummary(service, value)
  service.emitConversationUpdated = async () => {}
  service.syncConversation = async () => {
    throw new Error('sync failed')
  }

  await t.exception(
    async () => {
      await service.runAcceptInviteOperation('join-op-2', 'invite-2')
    },
    /sync failed/
  )

  const invite = service.invitesById.get('invite-2')
  t.is(invite?.status, 'joined')
  t.is(invite?.error, null)
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-accept-invite-operation'
        && message.data?.operationId === 'join-op-2'
        && message.data?.phase === 'failed'
        && message.data?.conversationId === 'conv-join-2'
    )
  )
  t.absent(
    workerMessages.find(
      (message) =>
        message.type === 'marmot-invite-updated'
        && message.data?.invite?.id === 'invite-2'
        && message.data?.reason === 'failed'
    )
  )
})
