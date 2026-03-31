import EventEmitter from 'node:events'
import nodeCrypto from 'node:crypto'

function createId(prefix = 'id') {
  if (typeof nodeCrypto.randomUUID === 'function') {
    return `${prefix}-${nodeCrypto.randomUUID()}`
  }
  return `${prefix}-${nodeCrypto.randomBytes(12).toString('hex')}`
}

function sanitizeId(value, label) {
  if (typeof value !== 'string' || !value.trim()) {
    throw new Error(`${label} is required`)
  }
  return value.trim()
}

function asString(value) {
  return typeof value === 'string' ? value.trim() : ''
}

function cloneSession(session) {
  const participants = Array.from(session.participants.values()).map((entry) => ({
    peerId: entry.peerId,
    joinedAt: entry.joinedAt,
    lastSeenAt: entry.lastSeenAt,
    metadata: entry.metadata || null,
    stream: entry.stream || null
  }))

  return {
    sessionId: session.sessionId,
    createdAt: session.createdAt,
    updatedAt: session.updatedAt,
    metadata: session.metadata || null,
    participants
  }
}

export default class SignalingBridge extends EventEmitter {
  constructor({ logger = console, maxParticipantsPerSession = 32 } = {}) {
    super()
    this.logger = logger
    this.maxParticipantsPerSession = Math.max(1, Number(maxParticipantsPerSession) || 32)
    this.sessions = new Map()
    this.signalCount = 0
  }

  createSession({ sessionId = null, metadata = null } = {}) {
    const normalizedSessionId = sessionId ? sanitizeId(sessionId, 'sessionId') : createId('media-session')
    if (this.sessions.has(normalizedSessionId)) {
      throw new Error(`Session already exists: ${normalizedSessionId}`)
    }

    const now = Date.now()
    const session = {
      sessionId: normalizedSessionId,
      createdAt: now,
      updatedAt: now,
      metadata: metadata && typeof metadata === 'object' ? { ...metadata } : null,
      participants: new Map()
    }

    this.sessions.set(normalizedSessionId, session)
    const summary = cloneSession(session)
    this.emit('session-created', { session: summary })
    return summary
  }

  ensureSession({ sessionId, metadata = null } = {}) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    const existing = this.sessions.get(normalizedSessionId)
    if (existing) {
      if (metadata && typeof metadata === 'object') {
        existing.metadata = {
          ...(existing.metadata && typeof existing.metadata === 'object' ? existing.metadata : {}),
          ...metadata
        }
        existing.updatedAt = Date.now()
      }
      return cloneSession(existing)
    }
    return this.createSession({
      sessionId: normalizedSessionId,
      metadata
    })
  }

  hasSession(sessionId) {
    return this.sessions.has(sessionId)
  }

  getSession(sessionId) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    const session = this.sessions.get(normalizedSessionId)
    if (!session) return null
    return cloneSession(session)
  }

  listSessions() {
    return Array.from(this.sessions.values()).map((session) => cloneSession(session))
  }

  getSessionCount() {
    return this.sessions.size
  }

  upsertParticipant({
    sessionId,
    peerId,
    metadata = null,
    emitJoined = true
  } = {}) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    const normalizedPeerId = sanitizeId(peerId, 'peerId')
    const session = this.sessions.get(normalizedSessionId)
    if (!session) throw new Error(`Session not found: ${normalizedSessionId}`)

    if (!session.participants.has(normalizedPeerId) &&
      session.participants.size >= this.maxParticipantsPerSession) {
      throw new Error(`Session participant limit reached (${this.maxParticipantsPerSession})`)
    }

    const now = Date.now()
    const existing = session.participants.get(normalizedPeerId)
    const participant = {
      peerId: normalizedPeerId,
      joinedAt: existing?.joinedAt || now,
      lastSeenAt: now,
      metadata: metadata && typeof metadata === 'object' ? { ...metadata } : existing?.metadata || null,
      stream: existing?.stream || null
    }
    session.participants.set(normalizedPeerId, participant)
    session.updatedAt = now

    if (emitJoined) {
      const summary = cloneSession(session)
      this.emit('participant-joined', {
        sessionId: normalizedSessionId,
        peerId: normalizedPeerId,
        session: summary
      })
      return summary
    }

    return cloneSession(session)
  }

  joinSession({ sessionId, peerId, metadata = null } = {}) {
    return this.upsertParticipant({
      sessionId,
      peerId,
      metadata,
      emitJoined: true
    })
  }

  leaveSession({ sessionId, peerId } = {}) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    const normalizedPeerId = sanitizeId(peerId, 'peerId')
    const session = this.sessions.get(normalizedSessionId)
    if (!session) throw new Error(`Session not found: ${normalizedSessionId}`)

    session.participants.delete(normalizedPeerId)
    session.updatedAt = Date.now()

    const summary = cloneSession(session)
    this.emit('participant-left', {
      sessionId: normalizedSessionId,
      peerId: normalizedPeerId,
      session: summary
    })

    return summary
  }

  updateStreamMetadata({ sessionId, peerId, stream = null } = {}) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    const normalizedPeerId = sanitizeId(peerId, 'peerId')
    const session = this.sessions.get(normalizedSessionId)
    if (!session) throw new Error(`Session not found: ${normalizedSessionId}`)
    const participant = session.participants.get(normalizedPeerId)
    if (!participant) throw new Error(`Participant not found: ${normalizedPeerId}`)

    participant.stream = stream && typeof stream === 'object' ? { ...stream } : null
    participant.lastSeenAt = Date.now()
    session.updatedAt = Date.now()

    const summary = cloneSession(session)
    this.emit('stream-updated', {
      sessionId: normalizedSessionId,
      peerId: normalizedPeerId,
      stream: participant.stream,
      session: summary
    })

    return summary
  }

  publishSignal({
    sessionId,
    fromPeerId,
    toPeerId = null,
    signalType,
    payload = null
  } = {}) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    const normalizedFrom = sanitizeId(fromPeerId, 'fromPeerId')
    const normalizedSignalType = sanitizeId(signalType, 'signalType')
    const session = this.sessions.get(normalizedSessionId)
    if (!session) throw new Error(`Session not found: ${normalizedSessionId}`)

    if (!session.participants.has(normalizedFrom)) {
      throw new Error(`Sender not part of session: ${normalizedFrom}`)
    }

    const normalizedToPeerId = toPeerId ? sanitizeId(toPeerId, 'toPeerId') : null

    if (normalizedToPeerId && !session.participants.has(normalizedToPeerId)) {
      throw new Error(`Target not part of session: ${normalizedToPeerId}`)
    }

    const now = Date.now()
    const signal = {
      id: createId('signal'),
      sessionId: normalizedSessionId,
      fromPeerId: normalizedFrom,
      toPeerId: normalizedToPeerId,
      signalType: normalizedSignalType,
      payload,
      createdAt: now
    }
    session.updatedAt = now
    this.signalCount += 1
    this.emit('signal', signal)
    return signal
  }

  ingestSignal({
    id = null,
    sessionId,
    fromPeerId,
    toPeerId = null,
    signalType,
    payload = null,
    createdAt = null,
    source = 'remote',
    sessionMetadata = null,
    fromMetadata = null
  } = {}) {
    const normalizedSessionId = sanitizeId(sessionId, 'sessionId')
    const normalizedFrom = sanitizeId(fromPeerId, 'fromPeerId')
    const normalizedSignalType = sanitizeId(signalType, 'signalType')
    const normalizedToPeerId = toPeerId ? sanitizeId(toPeerId, 'toPeerId') : null

    this.ensureSession({
      sessionId: normalizedSessionId,
      metadata: sessionMetadata
    })
    this.upsertParticipant({
      sessionId: normalizedSessionId,
      peerId: normalizedFrom,
      metadata: fromMetadata,
      emitJoined: true
    })
    if (normalizedToPeerId) {
      this.upsertParticipant({
        sessionId: normalizedSessionId,
        peerId: normalizedToPeerId,
        metadata: null,
        emitJoined: false
      })
    }

    const session = this.sessions.get(normalizedSessionId)
    if (!session) throw new Error(`Session not found: ${normalizedSessionId}`)
    const timestamp = Number.isFinite(createdAt) ? Number(createdAt) : Date.now()
    const signal = {
      id: id ? sanitizeId(id, 'id') : createId('signal'),
      sessionId: normalizedSessionId,
      fromPeerId: normalizedFrom,
      toPeerId: normalizedToPeerId,
      signalType: normalizedSignalType,
      payload,
      createdAt: timestamp,
      source: asString(source) || 'remote'
    }
    session.updatedAt = Date.now()
    this.signalCount += 1
    this.emit('signal', signal)
    return signal
  }

  getStats() {
    return {
      sessionCount: this.sessions.size,
      signalCount: this.signalCount,
      participants: Array.from(this.sessions.values()).reduce(
        (acc, session) => acc + session.participants.size,
        0
      )
    }
  }

  close() {
    this.sessions.clear()
  }
}
