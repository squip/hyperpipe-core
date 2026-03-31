import NostrSignalingTransport from './NostrSignalingTransport.mjs'
import RecordingService from './RecordingService.mjs'
import SignalingBridge from './SignalingBridge.mjs'

const COMMAND_PERMISSION_MAP = {
  'media-create-session': 'media.session',
  'media-join-session': 'media.session',
  'media-leave-session': 'media.session',
  'media-list-sessions': 'media.session',
  'media-get-session': 'media.session',
  'media-update-stream-metadata': 'media.session',
  'media-send-signal': 'p2p.session',
  'media-start-recording': 'media.record',
  'media-stop-recording': 'media.record',
  'media-list-recordings': 'media.record',
  'media-export-recording': 'media.record',
  'media-transcode-recording': 'media.transcode',
  'media-get-service-status': 'media.session',
  'media-get-stats': 'media.session'
}

const PRESENCE_JOIN_SIGNAL_TYPE = '__presence_join'
const PRESENCE_LEAVE_SIGNAL_TYPE = '__presence_leave'
const RESERVED_SIGNAL_TYPES = new Set([
  PRESENCE_JOIN_SIGNAL_TYPE,
  PRESENCE_LEAVE_SIGNAL_TYPE
])

function asString(value) {
  return typeof value === 'string' ? value.trim() : ''
}

function asObject(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null
  return value
}

function normalizePermissionSet(permissions) {
  return new Set(Array.isArray(permissions) ? permissions.map((value) => String(value || '')) : [])
}

function normalizeSourceType(sourceType) {
  const value = typeof sourceType === 'string' ? sourceType.trim().toLowerCase() : ''
  return value || 'host'
}

function toRelayCandidates(input) {
  if (!Array.isArray(input)) return []
  const out = []
  for (const entry of input) {
    if (typeof entry === 'string') {
      out.push(entry)
      continue
    }
    if (!entry || typeof entry !== 'object') continue
    out.push(entry.url, entry.relayUrl, entry.connectionUrl)
  }
  return out
}

function dedupeRelayUrls(input = []) {
  const seen = new Set()
  const out = []
  for (const entry of input) {
    const relay = asString(entry)
    if (!relay || seen.has(relay)) continue
    seen.add(relay)
    out.push(relay)
  }
  return out
}

export default class MediaServiceManager {
  constructor({
    storageRoot,
    sendMessage,
    logger = console,
    getConfig = null,
    maxConcurrentSessions = 8,
    maxParticipantsPerSession = 32,
    transcodeEnabled = false,
    enableRemoteSignaling = true,
    signalingTransport = null
  } = {}) {
    if (!storageRoot || typeof storageRoot !== 'string') {
      throw new Error('MediaServiceManager requires storageRoot')
    }
    if (typeof sendMessage !== 'function') {
      throw new Error('MediaServiceManager requires sendMessage callback')
    }

    this.storageRoot = storageRoot
    this.sendMessage = sendMessage
    this.logger = logger
    this.getConfig = typeof getConfig === 'function' ? getConfig : () => ({})
    this.maxConcurrentSessions = Math.max(1, Number(maxConcurrentSessions) || 8)

    this.signalingBridge = new SignalingBridge({
      logger,
      maxParticipantsPerSession
    })

    this.recordingService = new RecordingService({
      storageRoot,
      logger,
      transcodeEnabled
    })

    this.sessionTransportState = new Map()
    this.signalingTransport = null
    if (enableRemoteSignaling !== false) {
      this.signalingTransport = signalingTransport || new NostrSignalingTransport({
        logger,
        getConfig
      })
    }

    this.startedAt = Date.now()
    this.commandCount = 0
    this._bindBridgeEvents()
    this._bindTransportEvents()
  }

  _bindBridgeEvents() {
    this.onSessionCreated = ({ session }) => {
      this.sendMessage({
        type: 'media-session-created',
        session
      })
    }
    this.onParticipantJoined = ({ sessionId, peerId, session }) => {
      this.sendMessage({
        type: 'media-session-participant-joined',
        sessionId,
        peerId,
        session
      })
    }
    this.onParticipantLeft = ({ sessionId, peerId, session }) => {
      this.sendMessage({
        type: 'media-session-participant-left',
        sessionId,
        peerId,
        session
      })
    }
    this.onStreamUpdated = ({ sessionId, peerId, stream, session }) => {
      this.sendMessage({
        type: 'media-session-stream-updated',
        sessionId,
        peerId,
        stream,
        session
      })
    }
    this.onSignal = (signal) => {
      this.sendMessage({
        type: 'media-session-signal',
        signal
      })
    }

    this.signalingBridge.on('session-created', this.onSessionCreated)
    this.signalingBridge.on('participant-joined', this.onParticipantJoined)
    this.signalingBridge.on('participant-left', this.onParticipantLeft)
    this.signalingBridge.on('stream-updated', this.onStreamUpdated)
    this.signalingBridge.on('signal', this.onSignal)
  }

  _bindTransportEvents() {
    if (!this.signalingTransport) return
    this.onTransportSignal = (signal) => {
      this.handleRemoteSignal(signal).catch((error) => {
        this.sendMessage({
          type: 'media-error',
          command: 'media-send-signal',
          requestId: null,
          error: error?.message || String(error)
        })
      })
    }
    this.signalingTransport.on('signal', this.onTransportSignal)
  }

  resolveRelayHints(payload = {}, sessionId = '') {
    const candidates = []
    const payloadObj = asObject(payload) || {}
    const metadata = asObject(payloadObj.metadata) || {}
    const signaling = asObject(payloadObj.signaling) || {}
    const metadataSignaling = asObject(metadata.signaling) || {}

    candidates.push(
      ...toRelayCandidates(payloadObj.relayUrls),
      ...toRelayCandidates(payloadObj.relays),
      ...toRelayCandidates(signaling.relayUrls),
      ...toRelayCandidates(signaling.relays),
      ...toRelayCandidates(metadata.relayUrls),
      ...toRelayCandidates(metadata.relays),
      ...toRelayCandidates(metadataSignaling.relayUrls),
      ...toRelayCandidates(metadataSignaling.relays)
    )

    const sessionState = sessionId ? this.sessionTransportState.get(sessionId) : null
    if (sessionState?.relayUrls?.length) {
      candidates.push(...sessionState.relayUrls)
    }

    if (sessionId) {
      const session = this.signalingBridge.getSession(sessionId)
      const sessionMetadata = asObject(session?.metadata) || {}
      const sessionSignaling = asObject(sessionMetadata.signaling) || {}
      candidates.push(
        ...toRelayCandidates(sessionMetadata.relayUrls),
        ...toRelayCandidates(sessionMetadata.relays),
        ...toRelayCandidates(sessionSignaling.relayUrls),
        ...toRelayCandidates(sessionSignaling.relays)
      )
    }

    return dedupeRelayUrls(candidates)
  }

  getSessionTransportState(sessionId) {
    const normalizedSessionId = asString(sessionId)
    if (!normalizedSessionId) return null
    let state = this.sessionTransportState.get(normalizedSessionId)
    if (!state) {
      state = {
        localPeerIds: new Set(),
        relayUrls: []
      }
      this.sessionTransportState.set(normalizedSessionId, state)
    }
    return state
  }

  async attachRemoteSession(sessionId, peerId, payload = {}) {
    if (!this.signalingTransport) {
      return {
        enabled: false
      }
    }

    const normalizedSessionId = asString(sessionId)
    const normalizedPeerId = asString(peerId)
    if (!normalizedSessionId || !normalizedPeerId) {
      throw new Error('attachRemoteSession requires sessionId + peerId')
    }

    const state = this.getSessionTransportState(normalizedSessionId)
    state.localPeerIds.add(normalizedPeerId)
    const relayHints = this.resolveRelayHints(payload, normalizedSessionId)
    if (relayHints.length) {
      state.relayUrls = relayHints
    }

    const attach = await this.signalingTransport.attachSession({
      sessionId: normalizedSessionId,
      relayUrls: state.relayUrls
    })

    const presencePayload = {
      metadata: asObject(payload?.metadata) || null
    }
    const presenceResult = await this.publishTransportSignal({
      sessionId: normalizedSessionId,
      fromPeerId: normalizedPeerId,
      signalType: PRESENCE_JOIN_SIGNAL_TYPE,
      payload: presencePayload
    }, {
      relayUrls: attach.relays,
      propagateError: false
    })

    return {
      enabled: true,
      attach,
      presence: presenceResult
    }
  }

  async detachRemoteSession(sessionId, peerId) {
    if (!this.signalingTransport) {
      return {
        enabled: false
      }
    }

    const normalizedSessionId = asString(sessionId)
    const normalizedPeerId = asString(peerId)
    const state = this.sessionTransportState.get(normalizedSessionId)
    if (!state) {
      return {
        enabled: true,
        detached: false,
        reason: 'not-attached'
      }
    }

    if (normalizedPeerId) {
      state.localPeerIds.delete(normalizedPeerId)
      await this.publishTransportSignal({
        sessionId: normalizedSessionId,
        fromPeerId: normalizedPeerId,
        signalType: PRESENCE_LEAVE_SIGNAL_TYPE,
        payload: null
      }, {
        relayUrls: state.relayUrls,
        propagateError: false
      })
    }

    if (state.localPeerIds.size > 0) {
      return {
        enabled: true,
        detached: false,
        reason: 'peer-retained',
        peers: state.localPeerIds.size
      }
    }

    this.sessionTransportState.delete(normalizedSessionId)
    const detach = await this.signalingTransport.detachSession({
      sessionId: normalizedSessionId
    })
    return {
      enabled: true,
      detached: true,
      transport: detach
    }
  }

  async publishTransportSignal(signal, { relayUrls = [], propagateError = false } = {}) {
    if (!this.signalingTransport) {
      return { enabled: false }
    }

    try {
      const publish = await this.signalingTransport.publishSignal(signal, { relayUrls })
      return {
        enabled: true,
        success: true,
        ...publish
      }
    } catch (error) {
      const errorMessage = error?.message || String(error)
      this.logger?.warn?.('[MediaServiceManager] Failed to publish remote signal', errorMessage)
      this.sendMessage({
        type: 'media-error',
        command: 'media-send-signal',
        requestId: null,
        error: errorMessage
      })
      if (propagateError) throw error
      return {
        enabled: true,
        success: false,
        error: errorMessage
      }
    }
  }

  sessionHasParticipant(sessionId, peerId) {
    const session = this.signalingBridge.getSession(sessionId)
    if (!session || !Array.isArray(session.participants)) return false
    return session.participants.some((entry) => entry?.peerId === peerId)
  }

  ensureSessionForRemoteSignal(sessionId, signal = null) {
    if (this.signalingBridge.hasSession(sessionId)) return
    const sessionMetadata = {
      signaling: {
        transport: 'nostr',
        source: asString(signal?.source) || 'remote'
      }
    }
    this.signalingBridge.createSession({
      sessionId,
      metadata: sessionMetadata
    })
  }

  async handleRemoteSignal(signal) {
    if (!signal || typeof signal !== 'object') return
    const sessionId = asString(signal.sessionId)
    const fromPeerId = asString(signal.fromPeerId)
    const signalType = asString(signal.signalType)
    if (!sessionId || !fromPeerId || !signalType) return

    this.ensureSessionForRemoteSignal(sessionId, signal)

    if (signalType === PRESENCE_JOIN_SIGNAL_TYPE) {
      const payloadObj = asObject(signal.payload) || {}
      this.signalingBridge.upsertParticipant({
        sessionId,
        peerId: fromPeerId,
        metadata: asObject(payloadObj.metadata) || null,
        emitJoined: true
      })
      return
    }

    if (signalType === PRESENCE_LEAVE_SIGNAL_TYPE) {
      if (this.sessionHasParticipant(sessionId, fromPeerId)) {
        this.signalingBridge.leaveSession({
          sessionId,
          peerId: fromPeerId
        })
      }
      return
    }

    this.signalingBridge.ingestSignal({
      id: asString(signal.id) || undefined,
      sessionId,
      fromPeerId,
      toPeerId: asString(signal.toPeerId) || null,
      signalType,
      payload: signal.payload ?? null,
      createdAt: Number.isFinite(signal.createdAt) ? Number(signal.createdAt) : Date.now(),
      source: asString(signal.source) || 'remote',
      sessionMetadata: {
        signaling: {
          transport: 'nostr',
          originPubkey: asString(signal.originPubkey) || null
        }
      },
      fromMetadata: null
    })
  }

  assertSignalTypeAllowed(signalType) {
    const normalizedSignalType = asString(signalType)
    if (!normalizedSignalType) {
      throw new Error('signalType is required')
    }
    if (RESERVED_SIGNAL_TYPES.has(normalizedSignalType)) {
      throw new Error(`signalType is reserved: ${normalizedSignalType}`)
    }
  }

  assertPermission(commandType, context = {}) {
    const requiredPermission = COMMAND_PERMISSION_MAP[commandType]
    if (!requiredPermission) return

    const sourceType = normalizeSourceType(context.sourceType || context.source || 'host')
    if (sourceType !== 'plugin') return

    const permissions = normalizePermissionSet(context.permissions)
    if (!permissions.has(requiredPermission)) {
      throw new Error(`Plugin permission denied for ${commandType}: missing ${requiredPermission}`)
    }
  }

  assertSessionCapacity(commandType) {
    if (commandType !== 'media-create-session') return
    if (this.signalingBridge.getSessionCount() >= this.maxConcurrentSessions) {
      throw new Error(`Media session limit reached (${this.maxConcurrentSessions})`)
    }
  }

  async handleCommand(commandType, payload = {}, context = {}) {
    if (!commandType || typeof commandType !== 'string') {
      throw new Error('Media command type is required')
    }

    this.assertPermission(commandType, context)
    this.assertSessionCapacity(commandType)
    this.commandCount += 1

    const normalizedPayload = payload && typeof payload === 'object' ? payload : {}

    switch (commandType) {
      case 'media-create-session': {
        const session = this.signalingBridge.createSession(normalizedPayload)
        return { session }
      }
      case 'media-join-session': {
        const sessionId = asString(normalizedPayload?.sessionId)
        if (!sessionId) throw new Error('sessionId is required')
        if (!this.signalingBridge.hasSession(sessionId)) {
          if (this.signalingBridge.getSessionCount() >= this.maxConcurrentSessions) {
            throw new Error(`Media session limit reached (${this.maxConcurrentSessions})`)
          }
          this.signalingBridge.createSession({
            sessionId,
            metadata: asObject(normalizedPayload?.metadata) || null
          })
        }

        const session = this.signalingBridge.joinSession(normalizedPayload)
        const peerId = asString(normalizedPayload?.peerId)
        const transport = await this.attachRemoteSession(sessionId, peerId, normalizedPayload)
        return { session, transport }
      }
      case 'media-leave-session': {
        const session = this.signalingBridge.leaveSession(normalizedPayload)
        const sessionId = asString(normalizedPayload?.sessionId)
        const peerId = asString(normalizedPayload?.peerId)
        const transport = await this.detachRemoteSession(sessionId, peerId)
        return { session, transport }
      }
      case 'media-list-sessions': {
        return { sessions: this.signalingBridge.listSessions() }
      }
      case 'media-get-session': {
        const sessionId = normalizedPayload?.sessionId
        const session = this.signalingBridge.getSession(sessionId)
        if (!session) throw new Error(`Session not found: ${sessionId || '<unknown>'}`)
        return { session }
      }
      case 'media-update-stream-metadata': {
        const session = this.signalingBridge.updateStreamMetadata(normalizedPayload)
        return { session }
      }
      case 'media-send-signal': {
        this.assertSignalTypeAllowed(normalizedPayload?.signalType)
        const signal = this.signalingBridge.publishSignal(normalizedPayload)
        const sessionId = asString(signal?.sessionId)
        const relayHints = this.resolveRelayHints(normalizedPayload, sessionId)
        const transport = await this.publishTransportSignal(signal, {
          relayUrls: relayHints,
          propagateError: false
        })
        return { signal, transport }
      }
      case 'media-start-recording': {
        const recording = await this.recordingService.startRecording(normalizedPayload)
        this.sendMessage({
          type: 'media-recording-started',
          recording
        })
        return { recording }
      }
      case 'media-stop-recording': {
        const recording = await this.recordingService.stopRecording(normalizedPayload)
        this.sendMessage({
          type: 'media-recording-stopped',
          recording
        })
        return { recording }
      }
      case 'media-list-recordings': {
        const recordings = await this.recordingService.listRecordings(normalizedPayload)
        return { recordings }
      }
      case 'media-export-recording': {
        const exported = await this.recordingService.exportRecording(normalizedPayload)
        this.sendMessage({
          type: 'media-recording-exported',
          exported
        })
        return { exported }
      }
      case 'media-transcode-recording': {
        const job = await this.recordingService.transcodeRecording(normalizedPayload)
        this.sendMessage({
          type: 'media-recording-transcoded',
          job
        })
        return { job }
      }
      case 'media-get-service-status': {
        return {
          status: {
            startedAt: this.startedAt,
            maxConcurrentSessions: this.maxConcurrentSessions,
            sessions: this.signalingBridge.getSessionCount(),
            remoteSignaling: this.signalingTransport?.getStatus?.() || { enabled: false },
            recording: this.recordingService.getServiceStatus()
          }
        }
      }
      case 'media-get-stats': {
        return {
          stats: {
            startedAt: this.startedAt,
            commandCount: this.commandCount,
            signaling: this.signalingBridge.getStats(),
            remoteSignaling: this.signalingTransport?.getStatus?.() || { enabled: false },
            recording: this.recordingService.getServiceStatus()
          }
        }
      }
      default:
        throw new Error(`Unsupported media command: ${commandType}`)
    }
  }

  async stop() {
    this.signalingBridge.off('session-created', this.onSessionCreated)
    this.signalingBridge.off('participant-joined', this.onParticipantJoined)
    this.signalingBridge.off('participant-left', this.onParticipantLeft)
    this.signalingBridge.off('stream-updated', this.onStreamUpdated)
    this.signalingBridge.off('signal', this.onSignal)
    this.signalingBridge.close()

    if (this.signalingTransport) {
      if (this.onTransportSignal) {
        this.signalingTransport.off('signal', this.onTransportSignal)
      }
      await this.signalingTransport.close()
    }

    this.sessionTransportState.clear()
  }
}
