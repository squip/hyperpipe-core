import test from 'brittle'

import { getWelcome } from 'marmot-ts'

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

const LEGACY_RAW_WELCOME_BASE64 = 'AAFAdiB7FkWYCMcH4Y/7ONIMdVDOVmQEIS+ROHw+D2/Ng1yPvyCFkjUAhZpg3yfh5oDKHvqvvilFJlSq6Ot4mqQL98xbKDNjPjAuv6UZGmp4KzhA/tDtfNS5ctFPh6L0ZttHhT9ciQ1loFeRyvZvBNnWItFByCje8mBEH+R1gty6A0vY0cnE8eUtwhP35bUUEUIR0hW/aRuJU/aViC2QLEN9KlBPQOWzyFF+4zLqUFJ7fZQu+zoHrrIEbxnA1AseAZe0Q+izdTkj4KjEyspjB4VDe/ZS9yk4YgoZvesszyTQ7oO2k/PM99vQUTj4DmVvIktP2rUCZfkInksrNozPHh/5fcdECrW5UlTHCfKIxpyiCQj66f0upIxI4rinQr9767WHKIikABytfoA4xJ9XmsNat55epiZikdMsPIKdLSkc1GBFHLWvnoTACwUjfpSaXfqBaxCYOuUw63SM12WelS0V+d14no+B5xqVyaypn4H6oI4pWfXaVlDRmVeR40yusjal2iTjlguKYPvVn9iljO9kSA46G8RPSdxVavTqX981ewNZfNIG00IwnVRQXJB+dlWnzTdWZK8Nf75QvogEox1AmXn50L0wCehYtKKlQK1Mx6bSEaV8Y+Q1K0s/xdX88G7leHii/HqqypzgoGxlVHms6HenZ23l62r+niEcI8leS54IHqysknZLZOGD6ZWChbbbg/EFMUVvxYpft65JEwyATk4QTxoeqYdR7Ls+OGK6SelaZOUhbwBeTNRHVYv9vqCp4jU5/aSCowQFzWbW9g1AAL8BPhtjNFxR04O5WT8zHmjZOg7O2jQrAu+yVWgvq/vaELrkNcMIr/pupZFN7+IDACQs9kevVzw1fY2iVA7gWpLi1YASHkt3RKZ9RuFnea8Oq0XBmtcmQRGdn3R3ZZu5aHtS3F2uKI5NLrik47L4X3aEQj9dd+y/vXbqGf08cCDNIadUFHx+3ka/JV2+7FdFEvG4XeZFb0xh0pr+BgHc5OIEjlSmBb9r2TfqnG7UfCeQmzdUEwdLa70o1xkWj08N8POvmjV5qIC16kKS+XyMPhaB8OQ0XOem15bD43QWTa5hwf87RbJzrDLuc1nfVlJ6o4rZFC1jHC0AKYYsu9fMxFjK1wkDwviliJRbFZN7knfUxs3UBX8KjqkK2vxeYaoNHl0h3tJ+OC6MPMv9/Qk2miqs8jkbcsKdeZMoIjURA6bNgeBQHgoO4ssVWnQysJkO6fqBvfD3S+codKquXvS6MlxwcNPAclRuEhg3mHK7SenqgCG4fs+3VMXZgNHBK3PH04BehJf8VPVjMvA+cBjan31DUHRcaUVqqyCsD+FNUBdQa/NM0gxQ6KzvwRqDMdUNzQEDMZe3cB+2b8lz4e7ypjKHbJ5fh7ADWQ1MEyxNvvL1phva0+z3G9XAp1b9fV/bVGn77B7CTlhvkP+TScBQzW8DzN7E6WKdzCizsWVyyJvBXfLB6TNJB8lyNpTUhgDADFf4bhiEjo+EkxIEwDOl1ENX6xyeFec5G751+Dvy4XZf++lAVY8+c7N22CMmvbvbJPj/KVxt1IUE'

function buildLegacyRawWelcomeInvite (id) {
  return {
    id,
    senderPubkey: hex64('b'),
    createdAt: 1,
    receivedAt: 1,
    status: 'pending',
    error: null,
    keyPackageEventId: hex64('d'),
    relays: ['wss://relay.test'],
    conversationId: null,
    welcomeRumor: {
      id: `welcome-${id}`,
      kind: 444,
      created_at: 1,
      tags: [
        ['relays', 'wss://relay.test'],
        ['encoding', 'base64'],
        ['e', hex64('d')]
      ],
      content: LEGACY_RAW_WELCOME_BASE64,
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
    joinGroupFromWelcome: async () => ({ group }),
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
    joinGroupFromWelcome: async () => ({ group }),
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

test('runAcceptInviteOperation repairs legacy raw welcome rumors before joining', async (t) => {
  const workerMessages = []
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: (message) => workerMessages.push(message),
    logger: createLogger()
  })

  const rawInvite = buildLegacyRawWelcomeInvite('invite-legacy')
  const group = {
    idStr: 'conv-join-legacy',
    relays: ['wss://relay.test'],
    groupData: {
      name: 'Chat',
      description: '',
      adminPubkeys: [hex64('a')]
    },
    state: {}
  }

  t.exception(() => getWelcome(rawInvite.welcomeRumor), /Failed to decode welcome message/)

  service.pubkey = hex64('a')
  service.relays = ['wss://relay.test']
  service.schedulePersist = () => {}
  service.invitesById.set('invite-legacy', rawInvite)
  service.client = {
    joinGroupFromWelcome: async ({ welcomeRumor }) => {
      const welcome = getWelcome(welcomeRumor)
      t.is(welcome.secrets.length, 1)
      return { group }
    },
    getGroup: async () => group
  }
  service.buildConversationSummary = (value) => buildConversationSummary(service, value)
  service.emitConversationUpdated = async () => {}
  service.syncConversation = async () => {}

  const result = await service.runAcceptInviteOperation('join-op-legacy', 'invite-legacy')

  t.is(result.conversation.id, 'conv-join-legacy')

  const storedInvite = service.invitesById.get('invite-legacy')
  t.ok(storedInvite?.welcomeRumor)
  t.is(getWelcome(storedInvite.welcomeRumor).secrets.length, 1)
  t.ok(
    workerMessages.some(
      (message) =>
        message.type === 'marmot-accept-invite-operation'
        && message.data?.operationId === 'join-op-legacy'
        && message.data?.phase === 'completed'
    )
  )
})

test('ensureLocalKeyPackagePublished creates a key package for fresh profiles', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const calls = []
  service.signer = { getPublicKey: async () => hex64('a') }
  service.relays = ['wss://relay.test']
  service.publishKeyPackageRelayList = async () => {
    calls.push({ type: 'relay-list' })
  }
  service.client = {
    keyPackages: {
      list: async () => [],
      create: async (options) => {
        calls.push({ type: 'create', options })
        return { keyPackageRef: new Uint8Array([1]) }
      },
      rotate: async () => {
        calls.push({ type: 'rotate' })
      }
    }
  }

  await service.ensureLocalKeyPackagePublished()

  t.alike(
    calls,
    [
      {
        type: 'create',
        options: {
          relays: ['wss://relay.test'],
          client: 'hyperpipe-worker'
        }
      },
      {
        type: 'relay-list'
      }
    ]
  )
})

test('ensureLocalKeyPackagePublished rotates unpublished local key packages', async (t) => {
  const service = new MarmotService({
    storageRoot: '/tmp/hyperpipe-worker-test',
    getConfig: () => ({}),
    sendMessage: () => {},
    logger: createLogger()
  })

  const calls = []
  service.signer = { getPublicKey: async () => hex64('a') }
  service.relays = ['wss://relay.test']
  service.publishKeyPackageRelayList = async () => {
    calls.push({ type: 'relay-list' })
  }
  service.client = {
    keyPackages: {
      list: async () => [
        {
          keyPackageRef: new Uint8Array([1, 2, 3]),
          publicPackage: {},
          published: []
        }
      ],
      create: async () => {
        calls.push({ type: 'create' })
      },
      rotate: async (ref, options) => {
        calls.push({ type: 'rotate', ref: Array.from(ref), options })
      }
    }
  }

  await service.ensureLocalKeyPackagePublished()

  t.alike(
    calls,
    [
      {
        type: 'rotate',
        ref: [1, 2, 3],
        options: {
          relays: ['wss://relay.test'],
          client: 'hyperpipe-worker'
        }
      },
      {
        type: 'relay-list'
      }
    ]
  )
})
