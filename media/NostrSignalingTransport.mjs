import EventEmitter from 'node:events'
import nodeCrypto from 'node:crypto'

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { SimplePool } from 'nostr-tools/pool'
import { finalizeEvent, getPublicKey } from 'nostr-tools/pure'

const DEFAULT_SIGNAL_KIND = 27250
const DEFAULT_LOOKBACK_SECONDS = 120
const DEFAULT_MAX_RELAYS = 8
const MAX_SEEN_EVENT_IDS = 4096
const SIGNAL_NAMESPACE = 'hyperpipe-media-signal'
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band'
]

function asString(value) {
  return typeof value === 'string' ? value.trim() : ''
}

function normalizeHex64(value) {
  const normalized = asString(value).toLowerCase()
  return /^[a-f0-9]{64}$/.test(normalized) ? normalized : ''
}

function createId(prefix = 'id') {
  if (typeof nodeCrypto.randomUUID === 'function') {
    return `${prefix}-${nodeCrypto.randomUUID()}`
  }
  return `${prefix}-${nodeCrypto.randomBytes(12).toString('hex')}`
}

function ensureWebCryptoAvailable(logger = console) {
  const hasGlobalCrypto =
    typeof globalThis.crypto !== 'undefined' &&
    typeof globalThis.crypto?.getRandomValues === 'function' &&
    typeof globalThis.crypto?.subtle !== 'undefined'

  if (hasGlobalCrypto) return
  const webcrypto = nodeCrypto?.webcrypto || null
  if (!webcrypto) return

  try {
    if (typeof globalThis.crypto === 'undefined') {
      Object.defineProperty(globalThis, 'crypto', {
        value: webcrypto,
        configurable: true,
        writable: true
      })
    } else {
      globalThis.crypto = webcrypto
    }
  } catch (error) {
    logger?.warn?.('[NostrSignalingTransport] Failed to install WebCrypto shim', error?.message || error)
  }
}

function normalizeRelayUrl(candidate) {
  const raw = asString(candidate)
  if (!raw) return ''
  try {
    const parsed = new URL(raw)
    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') return ''
    parsed.pathname = parsed.pathname.replace(/\/+/g, '/')
    if (parsed.pathname.endsWith('/') && parsed.pathname !== '/') {
      parsed.pathname = parsed.pathname.slice(0, -1)
    }
    if (
      (parsed.protocol === 'ws:' && parsed.port === '80') ||
      (parsed.protocol === 'wss:' && parsed.port === '443')
    ) {
      parsed.port = ''
    }
    parsed.searchParams.sort()
    parsed.hash = ''
    return parsed.toString()
  } catch (_) {
    return ''
  }
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
    out.push(
      entry.url,
      entry.relayUrl,
      entry.connectionUrl,
      entry.wsUrl,
      entry.websocketUrl
    )
  }
  return out
}

function uniqueRelays(input = [], { fallback = DEFAULT_RELAYS, maxRelays = DEFAULT_MAX_RELAYS } = {}) {
  const out = []
  const seen = new Set()

  for (const candidate of input) {
    const relay = normalizeRelayUrl(candidate)
    if (!relay || seen.has(relay)) continue
    out.push(relay)
    seen.add(relay)
    if (out.length >= maxRelays) return out
  }

  for (const candidate of fallback) {
    const relay = normalizeRelayUrl(candidate)
    if (!relay || seen.has(relay)) continue
    out.push(relay)
    seen.add(relay)
    if (out.length >= maxRelays) break
  }

  return out
}

function readTag(tags, tagName) {
  if (!Array.isArray(tags) || !tagName) return ''
  for (const row of tags) {
    if (!Array.isArray(row)) continue
    if (row[0] !== tagName) continue
    if (typeof row[1] === 'string' && row[1]) return row[1]
  }
  return ''
}

function normalizeSessionId(value) {
  const sessionId = asString(value)
  if (!sessionId) {
    throw new Error('sessionId is required')
  }
  if (sessionId.length > 160) {
    throw new Error('sessionId exceeds max length (160)')
  }
  return sessionId
}

function relayFingerprint(relays) {
  return Array.isArray(relays) ? relays.join('|') : ''
}

export default class NostrSignalingTransport extends EventEmitter {
  constructor({
    getConfig = null,
    logger = console,
    signalKind = DEFAULT_SIGNAL_KIND,
    lookbackSeconds = DEFAULT_LOOKBACK_SECONDS,
    maxRelays = DEFAULT_MAX_RELAYS,
    defaultRelays = DEFAULT_RELAYS,
    instanceId = createId('media-instance')
  } = {}) {
    super()
    ensureWebCryptoAvailable(logger)
    this.logger = logger
    this.getConfig = typeof getConfig === 'function' ? getConfig : () => ({})
    this.signalKind = Number.isFinite(signalKind) ? Number(signalKind) : DEFAULT_SIGNAL_KIND
    this.lookbackSeconds = Math.max(0, Number(lookbackSeconds) || DEFAULT_LOOKBACK_SECONDS)
    this.maxRelays = Math.max(1, Number(maxRelays) || DEFAULT_MAX_RELAYS)
    this.defaultRelays = Array.isArray(defaultRelays) && defaultRelays.length
      ? defaultRelays
      : DEFAULT_RELAYS
    this.instanceId = asString(instanceId) || createId('media-instance')

    this.pool = new SimplePool({
      enablePing: true,
      enableReconnect: true
    })
    this.subscriptions = new Map()
    this.seenEventIds = new Set()
    this.seenEventQueue = []
    this.startedAt = Date.now()
  }

  resolveConfig() {
    try {
      const config = this.getConfig()
      return config && typeof config === 'object' ? config : {}
    } catch (error) {
      this.logger?.warn?.('[NostrSignalingTransport] Failed to resolve config', error?.message || error)
      return {}
    }
  }

  resolveCredentials() {
    const config = this.resolveConfig()
    const privateKeyHex = normalizeHex64(
      config?.nostr_nsec_hex ||
      config?.nostrPrivateKeyHex ||
      config?.nostr_privkey_hex
    )
    if (!privateKeyHex) {
      return null
    }

    let pubkeyHex = normalizeHex64(
      config?.nostr_pubkey_hex ||
      config?.nostrPubkeyHex ||
      config?.nostr_pubkey
    )
    if (!pubkeyHex) {
      try {
        pubkeyHex = bytesToHex(getPublicKey(hexToBytes(privateKeyHex)))
      } catch (error) {
        this.logger?.warn?.('[NostrSignalingTransport] Failed to derive pubkey', error?.message || error)
        return null
      }
    }

    return {
      privateKeyHex,
      pubkeyHex
    }
  }

  resolveRelayUrls(explicitRelays = []) {
    const config = this.resolveConfig()
    const candidates = [
      ...toRelayCandidates(explicitRelays),
      ...toRelayCandidates(config?.media?.signaling?.relayUrls),
      ...toRelayCandidates(config?.media?.signaling?.relays),
      ...toRelayCandidates(config?.nostr?.relays),
      ...toRelayCandidates(config?.relays)
    ]
    return uniqueRelays(candidates, {
      fallback: this.defaultRelays,
      maxRelays: this.maxRelays
    })
  }

  trackSeenEvent(eventId) {
    const id = asString(eventId)
    if (!id) return
    if (this.seenEventIds.has(id)) return
    this.seenEventIds.add(id)
    this.seenEventQueue.push(id)
    if (this.seenEventQueue.length <= MAX_SEEN_EVENT_IDS) return
    const removeCount = this.seenEventQueue.length - MAX_SEEN_EVENT_IDS
    const removed = this.seenEventQueue.splice(0, removeCount)
    removed.forEach((entry) => this.seenEventIds.delete(entry))
  }

  buildSignalEvent(signal) {
    const credentials = this.resolveCredentials()
    if (!credentials) {
      throw new Error('Nostr credentials unavailable for signaling transport')
    }

    const sessionId = normalizeSessionId(signal?.sessionId)
    const fromPeerId = asString(signal?.fromPeerId)
    const signalType = asString(signal?.signalType)
    if (!fromPeerId) throw new Error('fromPeerId is required for transport signal')
    if (!signalType) throw new Error('signalType is required for transport signal')

    const payload = {
      v: 1,
      sessionId,
      fromPeerId,
      toPeerId: asString(signal?.toPeerId) || null,
      signalType,
      payload: signal?.payload ?? null,
      sourceInstanceId: this.instanceId,
      sentAt: Date.now()
    }

    const tags = [
      ['t', SIGNAL_NAMESPACE],
      ['d', sessionId],
      ['from', fromPeerId],
      ['signal', signalType],
      ['instance', this.instanceId]
    ]
    if (payload.toPeerId) {
      tags.push(['to', payload.toPeerId])
    }

    const unsignedEvent = {
      kind: this.signalKind,
      created_at: Math.floor(Date.now() / 1000),
      tags,
      content: JSON.stringify(payload)
    }

    return finalizeEvent(unsignedEvent, hexToBytes(credentials.privateKeyHex))
  }

  async publishSignal(signal, { relayUrls = [] } = {}) {
    const relays = this.resolveRelayUrls(relayUrls)
    if (!relays.length) {
      throw new Error('No relay URLs available for signaling transport')
    }

    const event = this.buildSignalEvent(signal)
    this.trackSeenEvent(event.id)

    const publishes = this.pool.publish(relays, event, { maxWait: 12000 })
    const results = await Promise.all(
      relays.map(async (relay, index) => {
        try {
          const message = await publishes[index]
          const text = asString(message)
          const ok = !text || text.toLowerCase() === 'ok'
          return {
            relay,
            ok,
            message: text || null
          }
        } catch (error) {
          return {
            relay,
            ok: false,
            message: error?.message || String(error)
          }
        }
      })
    )

    return {
      eventId: event.id,
      relays,
      results
    }
  }

  async attachSession({ sessionId, relayUrls = [] } = {}) {
    const normalizedSessionId = normalizeSessionId(sessionId)
    const resolvedRelays = this.resolveRelayUrls(relayUrls)
    if (!resolvedRelays.length) {
      throw new Error(`No relay URLs available to subscribe for session ${normalizedSessionId}`)
    }

    const existing = this.subscriptions.get(normalizedSessionId)
    const newFingerprint = relayFingerprint(resolvedRelays)
    if (existing && existing.relayFingerprint === newFingerprint) {
      existing.refCount += 1
      return {
        sessionId: normalizedSessionId,
        relays: [...existing.relays],
        refCount: existing.refCount,
        reused: true
      }
    }

    if (existing) {
      this.closeSessionSubscription(normalizedSessionId, 'relay-updated')
    }

    const filter = {
      kinds: [this.signalKind],
      '#d': [normalizedSessionId],
      '#t': [SIGNAL_NAMESPACE],
      since: Math.floor(Date.now() / 1000) - this.lookbackSeconds
    }

    const closer = this.pool.subscribeMany(resolvedRelays, filter, {
      onevent: (event) => this.handleIncomingEvent(event),
      onclose: (reason) => {
        this.logger?.info?.('[NostrSignalingTransport] Session subscription closed', {
          sessionId: normalizedSessionId,
          reason: reason || null
        })
      }
    })

    this.subscriptions.set(normalizedSessionId, {
      sessionId: normalizedSessionId,
      relays: resolvedRelays,
      relayFingerprint: newFingerprint,
      refCount: 1,
      closer
    })

    return {
      sessionId: normalizedSessionId,
      relays: resolvedRelays,
      refCount: 1,
      reused: false
    }
  }

  async detachSession({ sessionId } = {}) {
    const normalizedSessionId = normalizeSessionId(sessionId)
    const entry = this.subscriptions.get(normalizedSessionId)
    if (!entry) {
      return {
        sessionId: normalizedSessionId,
        detached: false,
        reason: 'not-subscribed'
      }
    }

    entry.refCount -= 1
    if (entry.refCount > 0) {
      return {
        sessionId: normalizedSessionId,
        detached: false,
        refCount: entry.refCount,
        reason: 'refcount-retained'
      }
    }

    this.closeSessionSubscription(normalizedSessionId, 'detached')
    return {
      sessionId: normalizedSessionId,
      detached: true,
      refCount: 0
    }
  }

  closeSessionSubscription(sessionId, reason = 'closed') {
    const entry = this.subscriptions.get(sessionId)
    if (!entry) return
    this.subscriptions.delete(sessionId)
    try {
      entry.closer?.close?.(reason)
    } catch (_) {
      // no-op
    }
  }

  parseSignalFromEvent(event) {
    if (!event || typeof event !== 'object') return null
    if (Number(event.kind) !== this.signalKind) return null

    const eventId = asString(event.id)
    if (!eventId) return null
    if (this.seenEventIds.has(eventId)) return null

    const tags = Array.isArray(event.tags) ? event.tags : []
    const topic = readTag(tags, 't')
    if (topic !== SIGNAL_NAMESPACE) return null

    const contentRaw = asString(event.content)
    let payload = {}
    if (contentRaw) {
      try {
        payload = JSON.parse(contentRaw)
      } catch (_) {
        payload = {}
      }
    }

    const sourceInstanceId = asString(payload?.sourceInstanceId || readTag(tags, 'instance'))
    if (sourceInstanceId && sourceInstanceId === this.instanceId) return null

    const sessionId = asString(payload?.sessionId || readTag(tags, 'd'))
    const fromPeerId = asString(payload?.fromPeerId || readTag(tags, 'from'))
    const signalType = asString(payload?.signalType || readTag(tags, 'signal'))
    if (!sessionId || !fromPeerId || !signalType) return null

    const createdAt =
      Number.isFinite(event.created_at) && Number(event.created_at) > 0
        ? Number(event.created_at) * 1000
        : Date.now()

    return {
      id: `nostr-${eventId}`,
      eventId,
      sessionId,
      fromPeerId,
      toPeerId: asString(payload?.toPeerId || readTag(tags, 'to')) || null,
      signalType,
      payload: payload?.payload ?? null,
      createdAt,
      source: 'nostr',
      sourceInstanceId: sourceInstanceId || null,
      originPubkey: asString(event.pubkey) || null
    }
  }

  handleIncomingEvent(event) {
    const signal = this.parseSignalFromEvent(event)
    if (!signal) return
    this.trackSeenEvent(signal.eventId)
    this.emit('signal', signal)
  }

  getStatus() {
    return {
      enabled: true,
      signalKind: this.signalKind,
      startedAt: this.startedAt,
      sessionSubscriptions: this.subscriptions.size,
      instanceId: this.instanceId
    }
  }

  async close() {
    for (const sessionId of Array.from(this.subscriptions.keys())) {
      this.closeSessionSubscription(sessionId, 'shutdown')
    }
    this.subscriptions.clear()
    this.seenEventIds.clear()
    this.seenEventQueue = []
    this.pool.destroy()
  }
}
