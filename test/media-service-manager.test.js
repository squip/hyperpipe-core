import EventEmitter from 'node:events'
import os from 'node:os'
import path from 'node:path'
import { promises as fs } from 'node:fs'

import test from 'brittle'

import MediaServiceManager from '../media/MediaServiceManager.mjs'

class FakeSignalingTransport extends EventEmitter {
  constructor() {
    super()
    this.attachCalls = []
    this.detachCalls = []
    this.publishCalls = []
    this.closed = false
  }

  async attachSession({ sessionId, relayUrls = [] } = {}) {
    this.attachCalls.push({ sessionId, relayUrls })
    return {
      sessionId,
      relays: Array.isArray(relayUrls) ? relayUrls : [],
      refCount: 1,
      reused: false
    }
  }

  async detachSession({ sessionId } = {}) {
    this.detachCalls.push({ sessionId })
    return {
      sessionId,
      detached: true
    }
  }

  async publishSignal(signal, { relayUrls = [] } = {}) {
    this.publishCalls.push({ signal, relayUrls })
    return {
      eventId: `fake-${this.publishCalls.length}`,
      relays: Array.isArray(relayUrls) ? relayUrls : [],
      results: []
    }
  }

  getStatus() {
    return {
      enabled: true,
      fake: true
    }
  }

  async close() {
    this.closed = true
    this.removeAllListeners()
  }
}

const QUIET_LOGGER = {
  info() {},
  warn() {},
  error() {},
  debug() {}
}

async function waitForTick() {
  await new Promise((resolve) => setTimeout(resolve, 15))
}

test('MediaServiceManager forwards plugin signals to transport and ingests remote transport signal', async (t) => {
  const storageRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'media-service-manager-'))
  const sentMessages = []
  const transport = new FakeSignalingTransport()

  const manager = new MediaServiceManager({
    storageRoot,
    sendMessage: (message) => sentMessages.push(message),
    logger: QUIET_LOGGER,
    signalingTransport: transport
  })

  try {
    await manager.handleCommand('media-create-session', {
      sessionId: 'session-a',
      metadata: {
        signaling: {
          relayUrls: ['wss://relay.damus.io']
        }
      }
    }, { sourceType: 'plugin', permissions: ['media.session'] })

    await manager.handleCommand('media-join-session', {
      sessionId: 'session-a',
      peerId: 'peer-local',
      metadata: { role: 'local' }
    }, { sourceType: 'plugin', permissions: ['media.session'] })

    await manager.handleCommand('media-join-session', {
      sessionId: 'session-a',
      peerId: 'peer-target',
      metadata: { role: 'target' }
    }, { sourceType: 'plugin', permissions: ['media.session'] })

    transport.publishCalls = []

    const localSignalResult = await manager.handleCommand('media-send-signal', {
      sessionId: 'session-a',
      fromPeerId: 'peer-local',
      toPeerId: 'peer-target',
      signalType: 'offer',
      payload: { sdp: 'v=0...' }
    }, { sourceType: 'plugin', permissions: ['p2p.session'] })

    t.is(localSignalResult.signal.signalType, 'offer')
    t.is(transport.publishCalls.length, 1)
    t.is(transport.publishCalls[0].signal.signalType, 'offer')

    transport.emit('signal', {
      id: 'remote-signal-1',
      sessionId: 'session-a',
      fromPeerId: 'peer-remote',
      toPeerId: 'peer-local',
      signalType: 'answer',
      payload: { sdp: 'v=0 remote' },
      createdAt: Date.now(),
      source: 'nostr'
    })
    await waitForTick()

    const session = manager.signalingBridge.getSession('session-a')
    t.ok(Array.isArray(session.participants))
    t.ok(session.participants.some((participant) => participant.peerId === 'peer-remote'))

    const remoteSignalEvent = sentMessages.find(
      (message) =>
        message?.type === 'media-session-signal' &&
        message?.signal?.id === 'remote-signal-1'
    )
    t.ok(Boolean(remoteSignalEvent))
    t.is(remoteSignalEvent.signal.signalType, 'answer')
  } finally {
    await manager.stop()
    await fs.rm(storageRoot, { recursive: true, force: true }).catch(() => {})
  }
})

test('MediaServiceManager rejects reserved signal types from plugin commands', async (t) => {
  const storageRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'media-service-manager-'))
  const transport = new FakeSignalingTransport()

  const manager = new MediaServiceManager({
    storageRoot,
    sendMessage: () => {},
    logger: QUIET_LOGGER,
    signalingTransport: transport
  })

  try {
    await manager.handleCommand('media-create-session', {
      sessionId: 'session-b'
    }, { sourceType: 'plugin', permissions: ['media.session'] })

    await manager.handleCommand('media-join-session', {
      sessionId: 'session-b',
      peerId: 'peer-local'
    }, { sourceType: 'plugin', permissions: ['media.session'] })

    await t.exception(async () => {
      await manager.handleCommand('media-send-signal', {
        sessionId: 'session-b',
        fromPeerId: 'peer-local',
        signalType: '__presence_join',
        payload: null
      }, { sourceType: 'plugin', permissions: ['p2p.session'] })
    }, /reserved/)
  } finally {
    await manager.stop()
    await fs.rm(storageRoot, { recursive: true, force: true }).catch(() => {})
  }
})
