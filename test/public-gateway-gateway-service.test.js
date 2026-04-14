import test from 'brittle'
import { EventEmitter } from 'node:events'
import WebSocket from 'ws'

import { GatewayService } from '../gateway/GatewayService.mjs'

function createSocket() {
  const ws = new EventEmitter()
  ws.readyState = WebSocket.OPEN
  ws.sent = []
  ws.send = (payload) => {
    ws.sent.push(JSON.parse(payload))
  }
  return ws
}

async function waitFor(predicate, { timeoutMs = 1200, intervalMs = 10 } = {}) {
  const start = Date.now()
  while ((Date.now() - start) < timeoutMs) {
    if (predicate()) return true
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
  return false
}

function createServiceForReqTests({ lag = 0, queryResult = null } = {}) {
  const service = new GatewayService({ publicGateway: { enabled: true } })
  service.publicGatewaySettings.enabled = true
  service.publicGatewayRelayState.set('public-gateway:hyperbee', {
    metadata: {
      gatewayRelay: {
        hyperbeeKey: 'gateway-key'
      }
    }
  })
  service.activeRelays.set('public-gateway:hyperbee', {
    metadata: {
      gatewayRelay: {
        hyperbeeKey: 'gateway-key'
      }
    },
    peers: new Set()
  })
  service.publicGatewayRelayClient = {
    getHyperbeeKey: () => 'gateway-key',
    close: async () => {}
  }
  service.startEventChecking = async () => {}
  service.hyperbeeAdapter = {
    hasReplica: () => true,
    getReplicaStats: async () => ({ lag }),
    query: async () => queryResult || ({
      events: [{ id: 'e1', created_at: 1, pubkey: 'p', kind: 1, tags: [] }],
      stats: { served: true, truncated: false }
    })
  }
  return service
}

test('GatewayService serves REQ locally when replica ready', async t => {
  const service = createServiceForReqTests()
  const ws = createSocket()

  try {
    service.handleWebSocket(ws, 'public-gateway:hyperbee')
    ws.emit('message', JSON.stringify(['REQ', 'sub', { kinds: [1] }]))

    const receivedFrames = await waitFor(() => ws.sent.length >= 2)
    t.ok(receivedFrames, 'expected local EVENT/EOSE frames')
    t.alike(ws.sent[0], ['EVENT', 'sub', { id: 'e1', created_at: 1, pubkey: 'p', kind: 1, tags: [] }])
    t.alike(ws.sent[1], ['EOSE', 'sub'])
  } finally {
    ws.emit('close')
    await service.publicGatewayRelayClient?.close?.()
    service.connectionPool?.destroy?.()
  }
})

test('GatewayService defers to peers when replica lag is high', async t => {
  let queryInvoked = false
  const service = createServiceForReqTests({
    lag: 5,
    queryResult: {
      events: [],
      stats: { served: true, truncated: false }
    }
  })
  service.publicGatewaySettings.dispatcherReassignLagBlocks = 1
  service.hyperbeeAdapter.query = async () => {
    queryInvoked = true
    return { events: [], stats: { served: true, truncated: false } }
  }

  const ws = createSocket()
  try {
    service.handleWebSocket(ws, 'public-gateway:hyperbee')
    ws.emit('message', JSON.stringify(['REQ', 'sub', { kinds: [1] }]))

    const receivedNotice = await waitFor(() => ws.sent.length >= 1)
    t.ok(receivedNotice, 'expected deferral notice frame')
    t.alike(ws.sent[0], ['NOTICE', 'No healthy peers available for this relay'])
    t.is(queryInvoked, false)
  } finally {
    ws.emit('close')
    await service.publicGatewayRelayClient?.close?.()
    service.connectionPool?.destroy?.()
  }
})

test('GatewayService skips public-gateway registration for direct-join-only relays', async t => {
  const service = new GatewayService({ publicGateway: { enabled: true } })
  const registerCalls = []
  const unregisterCalls = []

  service.publicGatewaySettings.enabled = true
  service.publicGatewayRegistrar = {
    isEnabled: () => true,
    registerRelay: async (...args) => {
      registerCalls.push(args)
      return { success: true }
    },
    unregisterRelay: async (...args) => {
      unregisterCalls.push(args)
      return { success: true }
    }
  }

  try {
    const response = await service.registerPeerMetadata({
      publicKey: 'peer-direct-join-only',
      mode: 'hyperswarm',
      relays: [
        {
          identifier: 'npubdirect:group-a',
          directJoinOnly: true,
          isPublic: true,
          isOpen: true
        }
      ]
    }, {
      source: 'test',
      skipConnect: true
    })

    t.is(response?.relayCount, 1)
    const relayData = service.activeRelays.get('npubdirect:group-a')
    t.ok(relayData, 'expected relay metadata to be tracked locally')
    t.is(relayData?.metadata?.directJoinOnly, true, 'expected directJoinOnly metadata to be preserved')

    await service.syncPublicGatewayRelay('npubdirect:group-a')
    await new Promise((resolve) => setTimeout(resolve, 50))

    t.is(registerCalls.length, 0, 'expected no public-gateway registerRelay calls')
    t.is(unregisterCalls.length, 0, 'expected no public-gateway unregisterRelay calls')
  } finally {
    service.connectionPool?.destroy?.()
  }
})

test('GatewayService registers joined relays with public gateway for presence tracking', async t => {
  const service = new GatewayService({ publicGateway: { enabled: true } })
  const registerCalls = []

  service.publicGatewaySettings.enabled = true
  service.publicGatewaySettings.baseUrl = 'https://gateway.test'
  service.publicGatewaySettings.sharedSecret = 'test-shared-secret'
  service.discoveredGateways = [{
    publicUrl: 'https://gateway.test',
    authMethod: 'shared-secret-v1',
    sharedSecret: 'test-shared-secret'
  }]
  service.publicGatewayLegacyRegistrars.set('https://gateway.test::test-shared-secret', {
    isEnabled: () => true,
    registerRelay: async (...args) => {
      registerCalls.push(args)
      return { success: true }
    },
    unregisterRelay: async () => ({ success: true }),
    updateOpenJoinPool: async () => ({ success: true }),
    issueGatewayToken: async () => ({ success: true }),
    refreshGatewayToken: async () => ({ success: true }),
    revokeGatewayToken: async () => ({ success: true })
  })

  try {
    const response = await service.registerPeerMetadata({
      publicKey: 'peer-joined-relay',
      mode: 'hyperswarm',
      relays: [
        {
          identifier: 'npubjoined:group-a',
          name: 'Joined Group A',
          isHosted: false,
          isJoined: true,
          directJoinOnly: false,
          isPublic: false,
          isOpen: false
        }
      ]
    }, {
      source: 'test',
      skipConnect: true
    })

    t.is(response?.relayCount, 1)
    const relayData = service.activeRelays.get('npubjoined:group-a')
    t.ok(relayData, 'expected joined relay metadata to be tracked locally')
    t.is(relayData?.metadata?.isJoined, true, 'expected joined relay metadata to be preserved')

    await service.syncPublicGatewayRelay('npubjoined:group-a')
    await new Promise((resolve) => setTimeout(resolve, 50))

    t.ok(registerCalls.length >= 1, 'expected joined relay to register with public gateway')
    if (registerCalls.length) {
      const [relayIdentifier, relayPayload] = registerCalls[registerCalls.length - 1]
      t.is(relayIdentifier, 'npubjoined:group-a')
      t.alike(relayPayload?.peers, ['peer-joined-relay'])
      t.is(relayPayload?.metadata?.isJoined, true)
    }
  } finally {
    service.connectionPool?.destroy?.()
  }
})

test('GatewayService forwards blind peering key in hosted relay registration payload', async t => {
  const service = new GatewayService({ publicGateway: { enabled: true } })
  const registerCalls = []

  service.publicGatewaySettings.enabled = true
  service.publicGatewaySettings.baseUrl = 'https://gateway.test'
  service.publicGatewaySettings.sharedSecret = 'test-shared-secret'
  service.discoveredGateways = [{
    publicUrl: 'https://gateway.test',
    authMethod: 'shared-secret-v1',
    sharedSecret: 'test-shared-secret'
  }]
  service.publicGatewayLegacyRegistrars.set('https://gateway.test::test-shared-secret', {
    isEnabled: () => true,
    registerRelay: async (...args) => {
      registerCalls.push(args)
      return { success: true }
    },
    unregisterRelay: async () => ({ success: true }),
    updateOpenJoinPool: async () => ({ success: true }),
    issueGatewayToken: async () => ({ success: true }),
    refreshGatewayToken: async () => ({ success: true }),
    revokeGatewayToken: async () => ({ success: true })
  })

  try {
    const response = await service.registerPeerMetadata({
      publicKey: 'peer-hosted-relay',
      blindPeeringPublicKey: 'k44683wpzchhqfhwaq83qhqt59g4ymdz139hdk9hnhonc9h3ozxy',
      mode: 'hyperswarm',
      relays: [
        {
          identifier: 'npubhosted:group-a',
          name: 'Hosted Group A',
          isHosted: true,
          isJoined: false,
          directJoinOnly: false,
          isPublic: true,
          isOpen: true
        }
      ]
    }, {
      source: 'test',
      skipConnect: true
    })

    t.is(response?.relayCount, 1)

    await service.syncPublicGatewayRelay('npubhosted:group-a')
    await new Promise((resolve) => setTimeout(resolve, 50))

    t.ok(registerCalls.length >= 1, 'expected hosted relay to register with public gateway')
    if (registerCalls.length) {
      const [relayIdentifier, relayPayload] = registerCalls[registerCalls.length - 1]
      t.is(relayIdentifier, 'npubhosted:group-a')
      t.is(relayPayload?.metadata?.blindPeeringPublicKey, 'k44683wpzchhqfhwaq83qhqt59g4ymdz139hdk9hnhonc9h3ozxy')
    }
  } finally {
    service.connectionPool?.destroy?.()
  }
})

test('GatewayService prefers manual shared-secret settings over discovered bearer auth for the same gateway origin', async t => {
  const service = new GatewayService({ publicGateway: { enabled: true } })
  const legacyRegisterCalls = []
  const controlRegisterCalls = []

  service.publicGatewaySettings.enabled = true
  service.publicGatewaySettings.selectionMode = 'manual'
  service.publicGatewaySettings.baseUrl = 'https://gateway.test'
  service.publicGatewaySettings.sharedSecret = 'manual-shared-secret'
  service.publicGatewaySettings.authMethod = 'shared-secret-v1'
  service.publicGatewaySettings.resolvedAuthMethod = 'shared-secret-v1'
  service.discoveredGateways = [{
    gatewayId: 'gw-bearer-test',
    publicUrl: 'https://gateway.test',
    authMethod: 'relay-scoped-bearer-v1'
  }]
  service.publicGatewayLegacyRegistrars.set('https://gateway.test::manual-shared-secret', {
    isEnabled: () => true,
    registerRelay: async (...args) => {
      legacyRegisterCalls.push(args)
      return { success: true }
    },
    unregisterRelay: async () => ({ success: true }),
    updateOpenJoinPool: async () => ({ success: true }),
    issueGatewayToken: async () => ({ success: true }),
    refreshGatewayToken: async () => ({ success: true }),
    revokeGatewayToken: async () => ({ success: true })
  })
  service.publicGatewayControlClients.set('https://gateway.test', {
    isEnabled: () => true,
    registerRelay: async (...args) => {
      controlRegisterCalls.push(args)
      return { success: true }
    },
    unregisterRelay: async () => ({ success: true }),
    updateOpenJoinPool: async () => ({ success: true }),
    issueGatewayToken: async () => ({ success: true }),
    refreshGatewayToken: async () => ({ success: true }),
    revokeGatewayToken: async () => ({ success: true })
  })

  try {
    await service.registerPeerMetadata({
      publicKey: 'peer-manual-shared-secret',
      mode: 'hyperswarm',
      relays: [
        {
          identifier: 'npubmanual:group-a',
          name: 'Manual Shared Secret Group',
          isHosted: true,
          isJoined: false,
          directJoinOnly: false,
          isPublic: true,
          isOpen: true,
          gatewayOrigin: 'https://gateway.test'
        }
      ]
    }, {
      source: 'test',
      skipConnect: true
    })

    await service.syncPublicGatewayRelay('npubmanual:group-a')
    await new Promise((resolve) => setTimeout(resolve, 50))

    t.ok(legacyRegisterCalls.length >= 1, 'expected manual shared-secret route to use legacy registrar')
    t.is(controlRegisterCalls.length, 0, 'expected manual shared-secret route to avoid bearer control client')
    if (legacyRegisterCalls.length) {
      const [relayIdentifier] = legacyRegisterCalls[legacyRegisterCalls.length - 1]
      t.is(relayIdentifier, 'npubmanual:group-a')
    }
  } finally {
    service.connectionPool?.destroy?.()
  }
})
