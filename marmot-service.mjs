import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import nodeCrypto from 'node:crypto'
import { serialize as v8Serialize, deserialize as v8Deserialize } from 'node:v8'

import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { unlockGiftWrap } from 'applesauce-common/helpers/gift-wrap'
import {
  GROUP_EVENT_KIND,
  KEY_PACKAGE_KIND,
  KEY_PACKAGE_RELAY_LIST_KIND,
  KeyPackageStore,
  KeyValueGroupStateBackend,
  MarmotClient,
  Proposals,
  WELCOME_EVENT_KIND,
  createWelcomeRumor,
  decodeContent,
  createKeyPackageRelayListEvent,
  deserializeApplicationRumor,
  getWelcome,
  hasAck,
  getGroupMembers
} from 'marmot-ts'
import * as nip44 from 'nostr-tools/nip44'
import { SimplePool } from 'nostr-tools/pool'
import { finalizeEvent, getEventHash, getPublicKey } from 'nostr-tools/pure'
import { decode } from 'ts-mls'
import { welcomeDecoder } from 'ts-mls/welcome.js'

const GIFT_WRAP_KIND = 1059
const MESSAGE_KIND_TEXT = 14
const MESSAGE_KIND_REACTION = 7
const MESSAGE_KIND_META = 39000
const POLL_INTERVAL_MS = 3000
const MAX_MESSAGES_PER_CONVERSATION = 5000
const DEFAULT_RELAYS = [
  'wss://relay.damus.io',
  'wss://nos.lol',
  'wss://relay.nostr.band'
]

function ensureWebCryptoAvailable(logger = console) {
  const hasGlobalCrypto =
    typeof globalThis.crypto !== 'undefined'
    && typeof globalThis.crypto?.getRandomValues === 'function'
    && typeof globalThis.crypto?.subtle !== 'undefined'

  if (hasGlobalCrypto) return globalThis.crypto

  const webcrypto = nodeCrypto?.webcrypto || null
  if (!webcrypto) {
    throw new Error('WebCrypto is unavailable in worker runtime')
  }

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
  } catch {
    // ignore assignment failures; we validate below
  }

  const ready =
    typeof globalThis.crypto !== 'undefined'
    && typeof globalThis.crypto?.getRandomValues === 'function'
    && typeof globalThis.crypto?.subtle !== 'undefined'

  if (!ready) {
    throw new Error('Failed to initialize WebCrypto global for Marmot runtime')
  }

  logger.info?.('[MarmotService] WebCrypto shim initialized for worker runtime')
  return globalThis.crypto
}

function normalizeRelayUrl(candidate) {
  if (typeof candidate !== 'string') return null
  const trimmed = candidate.trim()
  if (!trimmed) return null
  try {
    const parsed = new URL(trimmed)
    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') return null

    parsed.pathname = parsed.pathname.replace(/\/+/g, '/')
    if (parsed.pathname.endsWith('/') && parsed.pathname !== '/') {
      parsed.pathname = parsed.pathname.slice(0, -1)
    }
    if ((parsed.protocol === 'ws:' && parsed.port === '80') || (parsed.protocol === 'wss:' && parsed.port === '443')) {
      parsed.port = ''
    }
    parsed.searchParams.sort()
    parsed.hash = ''
    return parsed.toString()
  } catch {
    return null
  }
}

function uniqueRelays(input = [], { includeDefaults = true } = {}) {
  const relays = Array.isArray(input) ? input : []
  const seen = new Set()
  const out = []
  for (const relay of relays) {
    const normalized = normalizeRelayUrl(relay)
    if (!normalized || seen.has(normalized)) continue
    seen.add(normalized)
    out.push(normalized)
  }
  if (out.length === 0 && includeDefaults) {
    for (const fallback of DEFAULT_RELAYS) {
      if (!seen.has(fallback)) {
        seen.add(fallback)
        out.push(fallback)
      }
    }
  }
  return out
}

function resolveNostrGroupEventId(group) {
  const nostrGroupId = group?.groupData?.nostrGroupId
  if (nostrGroupId instanceof Uint8Array && nostrGroupId.length > 0) {
    return bytesToHex(nostrGroupId)
  }
  if (Array.isArray(nostrGroupId) && nostrGroupId.length > 0) {
    try {
      return bytesToHex(Uint8Array.from(nostrGroupId))
    } catch {
      // fall through to the local group id
    }
  }
  return typeof group?.idStr === 'string' ? group.idStr : null
}

function eventMatchesGroupEventId(event, groupEventId) {
  const normalizedGroupEventId = sanitizeString(groupEventId, 256)?.toLowerCase() || null
  if (!normalizedGroupEventId) return false
  for (const tag of ensureArray(event?.tags)) {
    if (!Array.isArray(tag) || tag[0] !== 'h') continue
    const candidate = sanitizeString(tag[1], 256)?.toLowerCase() || null
    if (candidate === normalizedGroupEventId) return true
  }
  return false
}

function filterEventsByGroupEventId(events, groupEventId) {
  return ensureArray(events).filter((event) => eventMatchesGroupEventId(event, groupEventId))
}

function normalizePubkey(pubkey) {
  if (typeof pubkey !== 'string') return null
  const trimmed = pubkey.trim().toLowerCase()
  return /^[a-f0-9]{64}$/.test(trimmed) ? trimmed : null
}

function ensureArray(value) {
  return Array.isArray(value) ? value : []
}

function normalizePubkeyList(values = []) {
  return Array.from(
    new Set(
      ensureArray(values)
        .map((value) => normalizePubkey(value))
        .filter(Boolean)
    )
  )
}

function sameNormalizedPubkeyList(leftValues = [], rightValues = []) {
  const left = normalizePubkeyList(leftValues).slice().sort()
  const right = normalizePubkeyList(rightValues).slice().sort()
  if (left.length !== right.length) return false
  for (let idx = 0; idx < left.length; idx += 1) {
    if (left[idx] !== right[idx]) return false
  }
  return true
}

function nowSeconds() {
  return Math.floor(Date.now() / 1000)
}

function sortEventsChronological(events) {
  return [...events].sort((a, b) => {
    const aTs = Number(a?.created_at) || 0
    const bTs = Number(b?.created_at) || 0
    if (aTs !== bTs) return aTs - bTs
    return String(a?.id || '').localeCompare(String(b?.id || ''))
  })
}

function readApplicationRumorFromIngestResult(result) {
  if (!result || typeof result !== 'object') return null

  let messageBytes = null
  if (result.kind === 'applicationMessage') {
    messageBytes = result.message
  } else if (
    result.kind === 'processed'
    && result.result
    && typeof result.result === 'object'
    && result.result.kind === 'applicationMessage'
  ) {
    messageBytes = result.result.message
  }

  if (!(messageBytes instanceof Uint8Array)) return null

  try {
    const rumor = deserializeApplicationRumor(messageBytes)
    return rumor && rumor.id ? rumor : null
  } catch {
    return null
  }
}

function readTag(tags, name) {
  const row = ensureArray(tags).find((tag) => Array.isArray(tag) && tag[0] === name)
  return row && typeof row[1] === 'string' ? row[1] : undefined
}

function listWelcomeRelays(welcomeRumor) {
  const relaysTag = ensureArray(welcomeRumor?.tags).find(
    (tag) => Array.isArray(tag) && tag[0] === 'relays'
  )

  return relaysTag ? relaysTag.slice(1).filter((value) => typeof value === 'string') : []
}

function formatPublishAckFailure(publishResult = {}) {
  const failures = Object.entries(publishResult)
    .map(([relay, result]) => {
      if (result?.ok) return null
      const message =
        typeof result?.message === 'string' && result.message.trim()
          ? result.message.trim()
          : 'no relay acknowledged'
      return `${relay}: ${message}`
    })
    .filter(Boolean)

  return failures.length ? failures.join('; ') : 'no relay acknowledged'
}

function normalizeWelcomeRumorPayload(welcomeRumor) {
  if (!welcomeRumor || typeof welcomeRumor !== 'object') return welcomeRumor
  if (Number(welcomeRumor.kind) !== WELCOME_EVENT_KIND) return welcomeRumor

  try {
    getWelcome(welcomeRumor)
    return welcomeRumor
  } catch {
    const encoding = readTag(welcomeRumor.tags, 'encoding')
    if (encoding !== 'base64') return welcomeRumor

    let rawWelcome = null
    try {
      rawWelcome = decode(welcomeDecoder, decodeContent(welcomeRumor.content, encoding))
    } catch {
      return welcomeRumor
    }

    if (!rawWelcome) return welcomeRumor

    const repaired = createWelcomeRumor({
      welcome: rawWelcome,
      author: normalizePubkey(welcomeRumor.pubkey) || welcomeRumor.pubkey,
      groupRelays: listWelcomeRelays(welcomeRumor),
      keyPackageEventId: readTag(welcomeRumor.tags, 'e')
    })

    const next = {
      ...welcomeRumor,
      content: repaired.content,
      tags: repaired.tags
    }

    return {
      ...next,
      id: getEventHash({
        kind: Number(next.kind),
        pubkey: next.pubkey,
        created_at: Number(next.created_at) || nowSeconds(),
        content: next.content,
        tags: next.tags
      })
    }
  }
}

function summarizeFilter(filter = {}) {
  if (!filter || typeof filter !== 'object') return {}
  const summary = {}
  if (Array.isArray(filter.kinds) && filter.kinds.length) summary.kinds = filter.kinds
  if (Array.isArray(filter.authors) && filter.authors.length) summary.authors = filter.authors.slice(0, 6)
  if (Array.isArray(filter.ids) && filter.ids.length) summary.ids = filter.ids.slice(0, 6)
  if (Array.isArray(filter['#h']) && filter['#h'].length) summary.h = filter['#h'].slice(0, 6)
  if (Array.isArray(filter['#p']) && filter['#p'].length) summary.p = filter['#p'].slice(0, 6)
  if (Number.isFinite(filter.since)) summary.since = Number(filter.since)
  if (Number.isFinite(filter.until)) summary.until = Number(filter.until)
  if (Number.isFinite(filter.limit)) summary.limit = Number(filter.limit)
  return summary
}

function isPublishResultSuccessful(message) {
  if (typeof message !== 'string') return true
  const normalized = message.trim().toLowerCase()
  if (!normalized) return true
  if (normalized.startsWith('ok')) return true

  const failureIndicators = [
    'connection failure',
    'failed',
    'error',
    'timeout',
    'closed',
    'rejected',
    'not defined'
  ]
  return !failureIndicators.some((indicator) => normalized.includes(indicator))
}

function normalizeAttachmentEnvelope(raw = {}) {
  if (!raw || typeof raw !== 'object') return null
  const url = typeof raw.url === 'string' ? raw.url.trim() : null
  const gatewayUrl = typeof raw.gatewayUrl === 'string' ? raw.gatewayUrl.trim() : null
  if (!url && !gatewayUrl) return null
  return {
    url: url || gatewayUrl,
    gatewayUrl: gatewayUrl || null,
    mime: typeof raw.mime === 'string' ? raw.mime : null,
    size: Number.isFinite(raw.size) ? Number(raw.size) : null,
    width: Number.isFinite(raw.width) ? Number(raw.width) : null,
    height: Number.isFinite(raw.height) ? Number(raw.height) : null,
    blurhash: typeof raw.blurhash === 'string' ? raw.blurhash : null,
    fileName: typeof raw.fileName === 'string' ? raw.fileName : null,
    sha256: typeof raw.sha256 === 'string' ? raw.sha256.toLowerCase() : null,
    driveKey: normalizePubkey(raw.driveKey),
    ownerPubkey: normalizePubkey(raw.ownerPubkey),
    fileId: typeof raw.fileId === 'string' ? raw.fileId : null
  }
}

function parseAttachmentTag(tag) {
  if (!Array.isArray(tag) || tag[0] !== 'file' || typeof tag[1] !== 'string') return null
  try {
    const parsed = JSON.parse(tag[1])
    return normalizeAttachmentEnvelope(parsed)
  } catch {
    return null
  }
}

function sanitizeString(value, maxLen = 2048) {
  if (typeof value !== 'string') return ''
  const trimmed = value.trim()
  if (!trimmed) return ''
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed
}

function makeConversationSearchIndex(conversation) {
  const fields = [
    conversation?.title,
    conversation?.description,
    conversation?.lastMessagePreview,
    ...(Array.isArray(conversation?.participants) ? conversation.participants : [])
  ]
  return fields
    .map((field) => String(field || '').trim().toLowerCase())
    .filter(Boolean)
    .join(' ')
}

class FileKeyValueBackend {
  constructor(baseDir) {
    this.baseDir = baseDir
  }

  async ensureDir() {
    await fs.mkdir(this.baseDir, { recursive: true })
  }

  pathForKey(key) {
    return join(this.baseDir, `${encodeURIComponent(String(key))}.bin`)
  }

  decodeKeyFromFile(fileName) {
    if (!fileName.endsWith('.bin')) return null
    const encoded = fileName.slice(0, -4)
    try {
      return decodeURIComponent(encoded)
    } catch {
      return null
    }
  }

  async getItem(key) {
    await this.ensureDir()
    try {
      const data = await fs.readFile(this.pathForKey(key))
      return v8Deserialize(data)
    } catch (error) {
      if (error?.code === 'ENOENT') return null
      throw error
    }
  }

  async setItem(key, value) {
    await this.ensureDir()
    const filePath = this.pathForKey(key)
    const tmpPath = `${filePath}.tmp`
    const payload = v8Serialize(value)
    await fs.writeFile(tmpPath, payload)
    await fs.rename(tmpPath, filePath)
    return value
  }

  async removeItem(key) {
    await this.ensureDir()
    try {
      await fs.unlink(this.pathForKey(key))
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error
    }
  }

  async quarantineItem(key, reason = 'corrupt') {
    await this.ensureDir()
    const filePath = this.pathForKey(key)
    const quarantineDir = join(this.baseDir, '..', 'group-state-quarantine')
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-')
    const targetPath = join(
      quarantineDir,
      `${encodeURIComponent(String(key))}.${reason}.${timestamp}.bin`
    )

    try {
      await fs.mkdir(quarantineDir, { recursive: true })
      await fs.rename(filePath, targetPath)
      return targetPath
    } catch (error) {
      if (error?.code === 'ENOENT') return null
      throw error
    }
  }

  async clear() {
    await this.ensureDir()
    const files = await fs.readdir(this.baseDir)
    await Promise.all(
      files
        .filter((fileName) => fileName.endsWith('.bin'))
        .map((fileName) => fs.unlink(join(this.baseDir, fileName)).catch(() => {}))
    )
  }

  async keys() {
    await this.ensureDir()
    const files = await fs.readdir(this.baseDir)
    return files
      .map((fileName) => this.decodeKeyFromFile(fileName))
      .filter((key) => typeof key === 'string')
  }
}

class InMemoryKeyValueBackend {
  constructor() {
    this.store = new Map()
  }

  async getItem(key) {
    const normalizedKey = String(key)
    return this.store.has(normalizedKey) ? this.store.get(normalizedKey) : null
  }

  async setItem(key, value) {
    this.store.set(String(key), value)
    return value
  }

  async removeItem(key) {
    this.store.delete(String(key))
  }

  async clear() {
    this.store.clear()
  }

  async keys() {
    return Array.from(this.store.keys())
  }
}

class WorkerMarmotNetwork {
  constructor({ pool, getRelays, logger }) {
    this.pool = pool
    this.getRelays = getRelays
    this.logger = logger || console
  }

  normalizeRelays(inputRelays) {
    const base = Array.isArray(inputRelays) && inputRelays.length ? inputRelays : this.getRelays()
    return uniqueRelays(base)
  }

  async publish(relays, event) {
    const targets = this.normalizeRelays(relays)
    const results = {}
    if (!targets.length) return results

    const startedAt = Date.now()
    this.logger.info?.('[MarmotNetwork] publish start', {
      eventId: event?.id || null,
      kind: Number.isFinite(event?.kind) ? Number(event.kind) : null,
      relayCount: targets.length,
      relays: targets
    })

    const publishes = this.pool.publish(targets, event, { maxWait: 12000 })
    await Promise.all(
      targets.map(async (relay, index) => {
        const publishPromise = publishes[index]
        const relayStartedAt = Date.now()
        try {
          const message = await publishPromise
          const ok = isPublishResultSuccessful(message)
          results[relay] = {
            from: relay,
            ok,
            message: typeof message === 'string' ? message : undefined,
            elapsedMs: Date.now() - relayStartedAt
          }
        } catch (error) {
          results[relay] = {
            from: relay,
            ok: false,
            message: error?.message || String(error),
            elapsedMs: Date.now() - relayStartedAt
          }
        }
      })
    )

    const relayResults = targets.map((relay) => ({
      relay,
      ok: results?.[relay]?.ok === true,
      elapsedMs: Number(results?.[relay]?.elapsedMs) || null,
      message: results?.[relay]?.message || null
    }))
    this.logger.info?.('[MarmotNetwork] publish complete', {
      eventId: event?.id || null,
      kind: Number.isFinite(event?.kind) ? Number(event.kind) : null,
      relayResults,
      okCount: relayResults.filter((row) => row.ok).length,
      errorCount: relayResults.filter((row) => !row.ok).length,
      elapsedMs: Date.now() - startedAt
    })

    return results
  }

  async request(relays, filters) {
    const targets = this.normalizeRelays(relays)
    if (!targets.length) return []

    const filterList = Array.isArray(filters) ? filters : [filters]
    const eventsById = new Map()

    for (const filter of filterList) {
      if (!filter || typeof filter !== 'object') continue
      const filterStartedAt = Date.now()
      this.logger.info?.('[MarmotNetwork] request start', {
        relayCount: targets.length,
        filter: summarizeFilter(filter)
      })

      const relayResults = await Promise.all(
        targets.map(async (relay) => {
          const relayStartedAt = Date.now()
          try {
            const events = await this.pool.querySync([relay], filter, { maxWait: 10000 })
            for (const event of events) {
              if (!event?.id) continue
              eventsById.set(event.id, event)
            }
            return {
              relay,
              ok: true,
              eventCount: Array.isArray(events) ? events.length : 0,
              elapsedMs: Date.now() - relayStartedAt
            }
          } catch (error) {
            return {
              relay,
              ok: false,
              eventCount: 0,
              elapsedMs: Date.now() - relayStartedAt,
              error: error?.message || String(error)
            }
          }
        })
      )

      this.logger.info?.('[MarmotNetwork] request complete', {
        relayResults,
        filter: summarizeFilter(filter),
        okCount: relayResults.filter((row) => row.ok).length,
        errorCount: relayResults.filter((row) => !row.ok).length,
        elapsedMs: Date.now() - filterStartedAt,
        uniqueEvents: eventsById.size
      })
    }

    return sortEventsChronological(Array.from(eventsById.values()))
  }

  subscription(relays, filters) {
    const targets = this.normalizeRelays(relays)
    const filterList = Array.isArray(filters) ? filters : [filters]

    return {
      subscribe: (observer = {}) => {
        const closers = []
        const onEvent = typeof observer.next === 'function' ? observer.next : null
        const onError = typeof observer.error === 'function' ? observer.error : null

        for (const relay of targets) {
          for (const filter of filterList) {
            if (!filter || typeof filter !== 'object') continue
            const filterSummary = summarizeFilter(filter)
            this.logger.info?.('[MarmotNetwork] subscription start', {
              relay,
              filter: filterSummary
            })
            const closer = this.pool.subscribeMany([relay], filter, {
              onevent: (event) => {
                if (!onEvent) return
                try {
                  onEvent(event)
                } catch (error) {
                  onError?.(error)
                }
              },
              onclose: (reason) => {
                this.logger.info?.('[MarmotNetwork] subscription closed', {
                  relay,
                  filter: filterSummary,
                  reason: reason || null
                })
              }
            })
            closers.push(closer)
          }
        }

        return {
          unsubscribe: () => {
            for (const closer of closers) {
              try {
                closer?.close?.('unsubscribe')
              } catch (_) {
                // no-op
              }
            }
            observer.complete?.()
          }
        }
      }
    }
  }

  async getUserInboxRelays(pubkey) {
    const normalizedPubkey = normalizePubkey(pubkey)
    if (!normalizedPubkey) return this.normalizeRelays([])

    const relays = this.normalizeRelays([])
    const events = await this.request(relays, {
      kinds: [KEY_PACKAGE_RELAY_LIST_KIND],
      authors: [normalizedPubkey],
      limit: 10
    })

    const latest = events.at(-1)
    if (!latest) return relays

    const listed = ensureArray(latest.tags)
      .filter((tag) => Array.isArray(tag) && tag[0] === 'relay' && typeof tag[1] === 'string')
      .map((tag) => tag[1])

    const normalizedRelays = uniqueRelays(listed)
    return normalizedRelays.length ? normalizedRelays : relays
  }
}

export class MarmotService {
  constructor({
    storageRoot,
    getConfig,
    sendMessage,
    logger = console,
    getPublicGatewayOrigins = null,
    onConversationFileObserved = null
  }) {
    ensureWebCryptoAvailable(logger)

    this.storageRoot = storageRoot
    this.getConfig = getConfig
    this.emitWorkerMessage = typeof sendMessage === 'function' ? sendMessage : () => {}
    this.logger = logger
    this.getPublicGatewayOrigins = getPublicGatewayOrigins
    this.onConversationFileObserved = onConversationFileObserved

    this.initialized = false
    this.initPromise = null
    this.pool = new SimplePool({ enablePing: true, enableReconnect: true })

    this.relays = []
    this.pubkey = null
    this.secretKey = null
    this.signer = null

    this.client = null
    this.network = null
    this.groupStateStorageBackend = null

    this.groupsById = new Map()
    this.messagesByConversation = new Map()
    this.readStateByConversation = new Map()
    this.metadataByConversation = new Map()
    this.invitesById = new Map()
    this.lastSyncAtByConversation = new Map()
    this.lastInviteSyncAt = 0

    this.pollTimer = null
    this.syncInFlight = null
    this.persistTimer = null
    this.persistInFlight = null
    this.lastKeyPackagePublishedAt = 0
    this.corruptGroupStateIds = new Set()

    this.stateFile = join(storageRoot, 'marmot', 'state.json')
  }

  emit(type, data = null) {
    try {
      this.emitWorkerMessage({ type, data })
    } catch (error) {
      this.logger.warn('[MarmotService] Failed to emit worker message', {
        type,
        error: error?.message || error
      })
    }
  }

  async ensureStorageReady() {
    const baseDir = join(this.storageRoot, 'marmot')
    await fs.mkdir(baseDir, { recursive: true })
    await fs.mkdir(join(baseDir, 'group-state'), { recursive: true })
    await fs.mkdir(join(baseDir, 'key-packages'), { recursive: true })
  }

  relaysChanged(nextRelays) {
    if (this.relays.length !== nextRelays.length) return true
    for (let i = 0; i < this.relays.length; i += 1) {
      if (this.relays[i] !== nextRelays[i]) return true
    }
    return false
  }

  resolveRelayInput(relaysInput = undefined) {
    const hasRelayOverride = Array.isArray(relaysInput) && relaysInput.length > 0
    if (hasRelayOverride) {
      const parsed = uniqueRelays(relaysInput, { includeDefaults: false })
      if (parsed.length > 0) {
        return parsed
      }
      if (this.relays.length > 0) {
        this.logger.warn('[MarmotService] Ignoring invalid relay override; retaining active relays', {
          requestedCount: relaysInput.length,
          activeRelayCount: this.relays.length
        })
        return [...this.relays]
      }
    }

    if (this.relays.length > 0) {
      return [...this.relays]
    }
    return uniqueRelays(relaysInput || [])
  }

  buildSignerFromConfig(config) {
    const nsecHex = normalizePubkey(config?.nostr_nsec_hex)
    const pubkeyHex = normalizePubkey(config?.nostr_pubkey_hex)
    if (!nsecHex || !pubkeyHex) {
      throw new Error('Marmot requires nostr_pubkey_hex and nostr_nsec_hex')
    }

    const secretKey = hexToBytes(nsecHex)
    const derivedPubkey = getPublicKey(secretKey)
    if (derivedPubkey !== pubkeyHex) {
      this.logger.warn('[MarmotService] nsec/pubkey mismatch. Using pubkey derived from nsec.', {
        provided: pubkeyHex.slice(0, 12),
        derived: derivedPubkey.slice(0, 12)
      })
    }

    const signer = {
      getPublicKey: async () => derivedPubkey,
      signEvent: async (draft) => {
        const prepared = {
          ...draft,
          pubkey: derivedPubkey,
          tags: ensureArray(draft?.tags),
          created_at: Number.isFinite(draft?.created_at) ? Number(draft.created_at) : nowSeconds(),
          content: typeof draft?.content === 'string' ? draft.content : ''
        }
        return finalizeEvent(prepared, secretKey)
      },
      nip44: {
        encrypt: async (pubkey, plaintext) => {
          const targetPubkey = normalizePubkey(pubkey)
          if (!targetPubkey) throw new Error('Invalid pubkey for NIP-44 encrypt')
          const conversationKey = nip44.getConversationKey(secretKey, targetPubkey)
          return nip44.encrypt(String(plaintext || ''), conversationKey)
        },
        decrypt: async (pubkey, ciphertext) => {
          const targetPubkey = normalizePubkey(pubkey)
          if (!targetPubkey) throw new Error('Invalid pubkey for NIP-44 decrypt')
          const conversationKey = nip44.getConversationKey(secretKey, targetPubkey)
          return nip44.decrypt(String(ciphertext || ''), conversationKey)
        }
      }
    }

    return {
      signer,
      pubkey: derivedPubkey,
      secretKey
    }
  }

  async loadStateFromDisk() {
    try {
      const raw = await fs.readFile(this.stateFile, 'utf8')
      const parsed = JSON.parse(raw)
      const messages = parsed?.messagesByConversation || {}
      const readStates = parsed?.readStateByConversation || {}
      const metadata = parsed?.metadataByConversation || {}
      const invites = parsed?.invitesById || {}
      const lastSync = parsed?.lastSyncAtByConversation || {}

      for (const [conversationId, rows] of Object.entries(messages)) {
        if (!Array.isArray(rows)) continue
        const normalized = rows
          .map((row) => this.normalizeThreadMessage(conversationId, row))
          .filter(Boolean)
        if (!normalized.length) continue
        this.messagesByConversation.set(conversationId, normalized)
      }

      for (const [conversationId, row] of Object.entries(readStates)) {
        const normalized = this.normalizeReadState(conversationId, row)
        if (normalized) this.readStateByConversation.set(conversationId, normalized)
      }

      for (const [conversationId, row] of Object.entries(metadata)) {
        const normalized = this.normalizeMetadata(conversationId, row)
        if (normalized) this.metadataByConversation.set(conversationId, normalized)
      }

      for (const [inviteId, row] of Object.entries(invites)) {
        const normalized = this.normalizeInvite(inviteId, row)
        if (normalized) this.invitesById.set(inviteId, normalized)
      }

      for (const [conversationId, ts] of Object.entries(lastSync)) {
        const parsedTs = Number(ts)
        if (Number.isFinite(parsedTs) && parsedTs > 0) {
          this.lastSyncAtByConversation.set(conversationId, Math.floor(parsedTs))
        }
      }

      if (Number.isFinite(parsed?.lastInviteSyncAt)) {
        this.lastInviteSyncAt = Math.max(0, Math.floor(parsed.lastInviteSyncAt))
      }
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        this.logger.warn('[MarmotService] Failed to load state from disk', {
          error: error?.message || error
        })
      }
    }
  }

  reindexObservedFilesFromCache() {
    for (const [conversationId, messages] of this.messagesByConversation.entries()) {
      for (const message of ensureArray(messages)) {
        this.observeConversationFilesFromMessage(conversationId, message, 'state-reindex')
      }
    }
  }

  serializeStateForDisk() {
    return {
      version: 1,
      updatedAt: Date.now(),
      messagesByConversation: Object.fromEntries(this.messagesByConversation),
      readStateByConversation: Object.fromEntries(this.readStateByConversation),
      metadataByConversation: Object.fromEntries(this.metadataByConversation),
      invitesById: Object.fromEntries(this.invitesById),
      lastSyncAtByConversation: Object.fromEntries(this.lastSyncAtByConversation),
      lastInviteSyncAt: this.lastInviteSyncAt
    }
  }

  schedulePersist() {
    if (this.persistTimer) return
    this.persistTimer = setTimeout(() => {
      this.persistTimer = null
      this.persistState().catch((error) => {
        this.logger.warn('[MarmotService] Failed persisting state', {
          error: error?.message || error
        })
      })
    }, 250)
  }

  async persistState() {
    if (this.persistInFlight) {
      await this.persistInFlight
      return
    }

    this.persistInFlight = (async () => {
      await this.ensureStorageReady()
      const payload = this.serializeStateForDisk()
      const tmp = `${this.stateFile}.tmp`
      await fs.writeFile(tmp, JSON.stringify(payload, null, 2), 'utf8')
      await fs.rename(tmp, this.stateFile)
    })()

    try {
      await this.persistInFlight
    } finally {
      this.persistInFlight = null
    }
  }

  normalizeThreadMessage(conversationId, input) {
    if (!input || typeof input !== 'object') return null
    const id = typeof input.id === 'string' ? input.id : null
    if (!id) return null

    const timestamp = Number(input.timestamp)
    const senderPubkey = normalizePubkey(input.senderPubkey)
    if (!Number.isFinite(timestamp) || !senderPubkey) return null

    const attachments = ensureArray(input.attachments)
      .map((attachment) => {
        return normalizeAttachmentEnvelope(attachment)
      })
      .filter(Boolean)

    return {
      id,
      conversationId,
      senderPubkey,
      content: typeof input.content === 'string' ? input.content : '',
      timestamp: Math.floor(timestamp),
      type: ['text', 'media', 'reaction', 'system'].includes(input.type) ? input.type : 'text',
      replyTo: typeof input.replyTo === 'string' ? input.replyTo : null,
      attachments,
      tags: ensureArray(input.tags)
        .filter((tag) => Array.isArray(tag))
        .map((tag) => tag.map((item) => String(item ?? ''))),
      protocol: 'marmot'
    }
  }

  normalizeReadState(conversationId, input) {
    if (!input || typeof input !== 'object') return null
    const lastReadAt = Number(input.lastReadAt)
    const updatedAt = Number(input.updatedAt)
    return {
      conversationId,
      lastReadMessageId:
        typeof input.lastReadMessageId === 'string' && input.lastReadMessageId
          ? input.lastReadMessageId
          : null,
      lastReadAt: Number.isFinite(lastReadAt) ? Math.floor(lastReadAt) : 0,
      updatedAt: Number.isFinite(updatedAt) ? Math.floor(updatedAt) : nowSeconds()
    }
  }

  normalizeMetadata(conversationId, input) {
    if (!input || typeof input !== 'object') return null
    const title = sanitizeString(input.title, 256)
    const description = sanitizeString(input.description, 1024)
    const imageUrl = sanitizeString(input.imageUrl, 2048)
    const updatedAt = Number(input.updatedAt)

    return {
      conversationId,
      title: title || null,
      description: description || null,
      imageUrl: imageUrl || null,
      updatedAt: Number.isFinite(updatedAt) ? Math.floor(updatedAt) : nowSeconds()
    }
  }

  normalizeInvite(inviteId, input) {
    if (!input || typeof input !== 'object') return null
    const senderPubkey = normalizePubkey(input.senderPubkey)
    const createdAt = Number(input.createdAt)
    const receivedAt = Number(input.receivedAt)
    if (!senderPubkey || !Number.isFinite(createdAt)) return null

    const status = ['pending', 'joining', 'joined', 'failed'].includes(input.status)
      ? input.status
      : 'pending'

    const welcomeRumor = input.welcomeRumor && typeof input.welcomeRumor === 'object'
      ? normalizeWelcomeRumorPayload(input.welcomeRumor)
      : null
    const memberPubkeys = normalizePubkeyList(input.memberPubkeys || [])

    return {
      id: inviteId,
      senderPubkey,
      createdAt: Math.floor(createdAt),
      receivedAt: Number.isFinite(receivedAt) ? Math.floor(receivedAt) : Math.floor(createdAt),
      status,
      error: typeof input.error === 'string' ? input.error : null,
      keyPackageEventId: typeof input.keyPackageEventId === 'string' ? input.keyPackageEventId : null,
      relays: uniqueRelays(input.relays || []),
      conversationId:
        typeof input.conversationId === 'string' && input.conversationId ? input.conversationId : null,
      welcomeRumor,
      title: sanitizeString(input.title, 256) || null,
      description: sanitizeString(input.description, 1024) || null,
      imageUrl: sanitizeString(input.imageUrl, 2048) || null,
      memberPubkeys
    }
  }

  toPublicInvite(invite) {
    return {
      id: invite.id,
      senderPubkey: invite.senderPubkey,
      createdAt: invite.createdAt,
      receivedAt: invite.receivedAt,
      status: invite.status,
      error: invite.error,
      keyPackageEventId: invite.keyPackageEventId,
      relays: invite.relays,
      conversationId: invite.conversationId,
      title: invite.title,
      description: invite.description,
      imageUrl: invite.imageUrl,
      memberPubkeys: normalizePubkeyList(invite.memberPubkeys || []),
      protocol: 'marmot'
    }
  }

  emitInitOperation(operationId, phase, { error = null } = {}) {
    if (!operationId || !phase) return
    this.emit('marmot-init-operation', {
      operationId,
      phase,
      error
    })
  }

  emitAcceptInviteOperation(
    operationId,
    inviteId,
    phase,
    { conversationId = null, conversation = null, error = null } = {}
  ) {
    if (!operationId || !inviteId || !phase) return
    this.emit('marmot-accept-invite-operation', {
      operationId,
      inviteId,
      phase,
      conversationId,
      conversation,
      error
    })
  }

  buildInitSnapshot({ operationId = null, search = '' } = {}) {
    return {
      operationId,
      initialized: true,
      pubkey: this.pubkey,
      relays: this.relays,
      conversations: this.listConversationSummaries({ search }),
      invites: this.listInvites({ search })
    }
  }

  async initialize({ relays } = {}) {
    ensureWebCryptoAvailable(this.logger)

    if (this.initialized) {
      const nextRelays = this.resolveRelayInput(relays)
      if (this.relaysChanged(nextRelays)) {
        this.logger.info?.('[MarmotService] Relay set updated', {
          previous: this.relays,
          next: nextRelays
        })
        this.relays = nextRelays
      }
      return
    }

    if (this.initPromise) {
      await this.initPromise
      return
    }

    this.initPromise = (async () => {
      await this.ensureStorageReady()
      await this.loadStateFromDisk()
      this.reindexObservedFilesFromCache()

      const cfg = this.getConfig?.()
      const signerInfo = this.buildSignerFromConfig(cfg)
      this.signer = signerInfo.signer
      this.secretKey = signerInfo.secretKey
      this.pubkey = signerInfo.pubkey
      this.relays = this.resolveRelayInput(relays)
      this.logger.info?.('[MarmotService] Initialized relay set', {
        relayCount: this.relays.length,
        relays: this.relays
      })

      this.network = new WorkerMarmotNetwork({
        pool: this.pool,
        getRelays: () => this.relays,
        logger: this.logger
      })

      this.groupStateStorageBackend = new FileKeyValueBackend(join(this.storageRoot, 'marmot', 'group-state'))
      const groupStateBackend = new KeyValueGroupStateBackend(this.groupStateStorageBackend)
      const keyPackageStore = new KeyPackageStore(
        new FileKeyValueBackend(join(this.storageRoot, 'marmot', 'key-packages'))
      )

      this.client = new MarmotClient({
        signer: this.signer,
        groupStateBackend,
        keyPackageStore,
        network: this.network
      })

      await this.refreshGroupsMap()
      this.initialized = true
      this.startPolling()
    })()

    try {
      await this.initPromise
    } finally {
      this.initPromise = null
    }
  }

  async runInitialSyncOperation(operationId) {
    if (!operationId) return

    try {
      this.emitInitOperation(operationId, 'publishingIdentity')
      try {
        await this.ensureLocalKeyPackagePublished()
      } catch (error) {
        this.logger.warn?.('[MarmotService] Initial identity publish failed', {
          operationId,
          error: error?.message || error
        })
      }

      this.emitInitOperation(operationId, 'syncingConversations')
      await this.syncConversations({ emit: true, reason: 'init' })

      this.emitInitOperation(operationId, 'syncingInvites')
      await this.syncInvites({ emit: true })

      this.emitInitOperation(operationId, 'completed')
    } catch (error) {
      this.emitInitOperation(operationId, 'failed', {
        error: error?.message || String(error)
      })
      throw error
    }
  }

  startPolling() {
    if (this.pollTimer) return
    this.pollTimer = setInterval(() => {
      this.syncAll({ emit: true, reason: 'poll' }).catch((error) => {
        this.logger.warn('[MarmotService] background sync failed', {
          error: error?.message || error
        })
      })
    }, POLL_INTERVAL_MS)
  }

  async stop() {
    if (this.pollTimer) {
      clearInterval(this.pollTimer)
      this.pollTimer = null
    }
    if (this.persistTimer) {
      clearTimeout(this.persistTimer)
      this.persistTimer = null
    }
    await this.persistState().catch(() => {})
    this.pool.destroy()
  }

  async refreshGroupsMap() {
    if (!this.client) return
    this.groupsById.clear()

    const groupIds = await this.client.groupStateStore.list()
    for (const groupId of groupIds) {
      try {
        const group = await this.client.getGroup(groupId)
        if (group?.idStr) {
          this.groupsById.set(group.idStr, group)
        }
      } catch (error) {
        if (this.isRecoverableClientStateError(error)) {
          await this.quarantineCorruptGroupState(groupId, error)
          continue
        }
        throw error
      }
    }
  }

  isRecoverableClientStateError(error) {
    const message = error?.message || String(error || '')
    return message.includes('Failed to deserialize ClientState')
  }

  async quarantineCorruptGroupState(groupId, error) {
    const normalizedGroupId =
      typeof groupId === 'string'
        ? groupId
        : groupId instanceof Uint8Array
          ? bytesToHex(groupId)
          : String(groupId || '')
    if (!normalizedGroupId) return
    if (this.corruptGroupStateIds.has(normalizedGroupId)) return
    this.corruptGroupStateIds.add(normalizedGroupId)

    let quarantinedPath = null
    try {
      quarantinedPath = await this.groupStateStorageBackend?.quarantineItem(
        normalizedGroupId,
        'deserialize-failure'
      )
    } catch (quarantineError) {
      this.logger.warn?.('[MarmotService] Failed to quarantine corrupt group state', {
        groupId: normalizedGroupId,
        error: quarantineError?.message || quarantineError
      })
    }

    try {
      this.client?.clearGroupInstance?.(groupId)
    } catch {}

    this.groupsById.delete(normalizedGroupId)
    this.lastSyncAtByConversation.delete(normalizedGroupId)

    this.logger.warn?.('[MarmotService] Quarantined unreadable local Marmot group state', {
      groupId: normalizedGroupId,
      error: error?.message || error,
      quarantinedPath
    })
  }

  async ensureLocalKeyPackagePublished() {
    if (!this.client || !this.signer) return

    const now = Date.now()
    if (now - this.lastKeyPackagePublishedAt < 30_000) return

    const existingPackages = await this.client.keyPackages.list()
    const publishedPackages = existingPackages.filter(
      (keyPackage) => Array.isArray(keyPackage.published) && keyPackage.published.length > 0
    )

    if (!existingPackages.length) {
      await this.client.keyPackages.create({
        relays: this.relays,
        client: 'hyperpipe-worker'
      })
    } else if (!publishedPackages.length) {
      await this.client.keyPackages.rotate(existingPackages[0].keyPackageRef, {
        relays: this.relays,
        client: 'hyperpipe-worker'
      })
    }

    await this.publishKeyPackageRelayList()
    this.lastKeyPackagePublishedAt = now
  }

  async publishKeyPackageRelayList() {
    if (!this.signer || !this.network) return
    const relayListEvent = createKeyPackageRelayListEvent({
      pubkey: this.pubkey,
      relays: this.relays,
      client: 'hyperpipe-worker'
    })
    const signed = await this.signer.signEvent(relayListEvent)
    await this.network.publish(this.relays, signed)
  }

  getMessages(conversationId) {
    return this.messagesByConversation.get(conversationId) || []
  }

  observeConversationFile(conversationId, attachment = null, source = 'message') {
    if (!this.onConversationFileObserved || !attachment || typeof attachment !== 'object') return
    const fileHash = sanitizeString(attachment.sha256 || '', 128)
    if (!fileHash) return
    try {
      this.onConversationFileObserved({
        conversationId,
        fileHash,
        fileId: sanitizeString(attachment.fileId || '', 512) || null,
        driveKey: normalizePubkey(attachment.driveKey),
        ownerPubkey: normalizePubkey(attachment.ownerPubkey) || normalizePubkey(attachment.senderPubkey),
        url: sanitizeString(attachment.url || '', 4096) || null,
        mime: sanitizeString(attachment.mime || '', 256) || null,
        size: Number.isFinite(attachment.size) ? Number(attachment.size) : null,
        source
      })
    } catch (error) {
      this.logger.debug?.('[MarmotService] Failed to observe conversation file', {
        conversationId,
        fileHash,
        source,
        error: error?.message || error
      })
    }
  }

  observeConversationFilesFromMessage(conversationId, message, source = 'message') {
    const attachments = ensureArray(message?.attachments)
    for (const attachment of attachments) {
      this.observeConversationFile(conversationId, attachment, source)
    }
  }

  upsertMessage(conversationId, message) {
    const list = this.getMessages(conversationId)
    const existingIdx = list.findIndex((row) => row.id === message.id)
    if (existingIdx >= 0) {
      return false
    }

    list.push(message)
    list.sort((a, b) => {
      if (a.timestamp !== b.timestamp) return a.timestamp - b.timestamp
      return a.id.localeCompare(b.id)
    })

    if (list.length > MAX_MESSAGES_PER_CONVERSATION) {
      list.splice(0, list.length - MAX_MESSAGES_PER_CONVERSATION)
    }

    this.messagesByConversation.set(conversationId, list)
    this.observeConversationFilesFromMessage(conversationId, message, 'thread-message')
    this.schedulePersist()
    return true
  }

  computeUnreadCount(conversationId) {
    const list = this.getMessages(conversationId)
    const read = this.readStateByConversation.get(conversationId)
    const lastReadAt = Number(read?.lastReadAt) || 0
    return list.filter((message) => {
      if (message.senderPubkey === this.pubkey) return false
      return message.timestamp > lastReadAt
    }).length
  }

  setReadState(conversationId, { lastReadMessageId = null, lastReadAt = 0 } = {}) {
    const current = this.readStateByConversation.get(conversationId)
    const next = {
      conversationId,
      lastReadMessageId: typeof lastReadMessageId === 'string' && lastReadMessageId ? lastReadMessageId : null,
      lastReadAt: Number.isFinite(lastReadAt) ? Math.floor(lastReadAt) : 0,
      updatedAt: nowSeconds()
    }

    if (
      current
      && current.lastReadMessageId === next.lastReadMessageId
      && current.lastReadAt === next.lastReadAt
    ) {
      return current
    }

    this.readStateByConversation.set(conversationId, next)
    this.schedulePersist()
    this.emit('marmot-readstate-updated', {
      conversationId,
      readState: next,
      unreadCount: this.computeUnreadCount(conversationId)
    })

    return next
  }

  getMetadata(conversationId) {
    return this.metadataByConversation.get(conversationId) || null
  }

  setMetadata(conversationId, patch = {}) {
    const existing = this.getMetadata(conversationId) || {
      conversationId,
      title: null,
      description: null,
      imageUrl: null,
      updatedAt: nowSeconds()
    }

    const next = {
      ...existing,
      title: patch.title !== undefined ? sanitizeString(patch.title, 256) || null : existing.title,
      description:
        patch.description !== undefined
          ? sanitizeString(patch.description, 1024) || null
          : existing.description,
      imageUrl: patch.imageUrl !== undefined ? sanitizeString(patch.imageUrl, 2048) || null : existing.imageUrl,
      updatedAt: nowSeconds()
    }

    const changed =
      next.title !== existing.title
      || next.description !== existing.description
      || next.imageUrl !== existing.imageUrl

    if (!changed) return existing

    this.metadataByConversation.set(conversationId, next)
    this.schedulePersist()
    return next
  }

  rumorToThreadMessage(conversationId, rumor) {
    const tags = ensureArray(rumor.tags)
      .filter((tag) => Array.isArray(tag))
      .map((tag) => tag.map((item) => String(item ?? '')))

    const attachmentRows = tags
      .map((tag) => parseAttachmentTag(tag))
      .filter(Boolean)

    const replyTo =
      tags.find((tag) => tag[0] === 'e' && (tag[2] === 'reply' || tag[3] === 'reply'))?.[1]
      || tags.find((tag) => tag[0] === 'e')?.[1]
      || null

    const reactionTag = tags.find((tag) => tag[0] === 'reaction')
    const type = reactionTag || rumor.kind === MESSAGE_KIND_REACTION
      ? 'reaction'
      : attachmentRows.length > 0
        ? 'media'
        : 'text'

    return this.normalizeThreadMessage(conversationId, {
      id: rumor.id,
      senderPubkey: rumor.pubkey,
      content: typeof rumor.content === 'string' ? rumor.content : '',
      timestamp: Number(rumor.created_at) || nowSeconds(),
      type,
      replyTo,
      attachments: attachmentRows,
      tags
    })
  }

  isMetadataRumor(rumor) {
    if (!rumor || typeof rumor !== 'object') return false
    if (Number(rumor.kind) === MESSAGE_KIND_META) return true
    const tags = ensureArray(rumor.tags)
    return tags.some((tag) => Array.isArray(tag) && tag[0] === 'marmot-meta')
  }

  extractMetadataFromRumor(rumor) {
    if (!this.isMetadataRumor(rumor)) return null

    let parsed = {}
    if (typeof rumor.content === 'string' && rumor.content.trim()) {
      try {
        const json = JSON.parse(rumor.content)
        if (json && typeof json === 'object') parsed = json
      } catch {
        parsed = {}
      }
    }

    const tags = ensureArray(rumor.tags)
    const parsedRecord = parsed && typeof parsed === 'object' ? parsed : {}
    const hasOwn = (key) => Object.prototype.hasOwnProperty.call(parsedRecord, key)

    const titleTag = readTag(tags, 'title')
    const descriptionTag = readTag(tags, 'description')
    const imageTag = readTag(tags, 'image')
    const imageFileTag = tags.find((tag) => (
      Array.isArray(tag)
      && tag[0] === 'image-file'
      && typeof tag[1] === 'string'
    ))

    const parsedImageFile = normalizeAttachmentEnvelope(parsedRecord.imageFile)
      || (() => {
        if (!imageFileTag) return null
        try {
          return normalizeAttachmentEnvelope(JSON.parse(imageFileTag[1]))
        } catch {
          return null
        }
      })()

    const hasTitle = hasOwn('title') || typeof titleTag === 'string'
    const hasDescription = hasOwn('description') || typeof descriptionTag === 'string'
    const hasImage =
      hasOwn('imageUrl')
      || hasOwn('imageFile')
      || typeof imageTag === 'string'
      || Boolean(imageFileTag)

    const title = hasTitle
      ? sanitizeString(hasOwn('title') ? parsedRecord.title : titleTag, 256) || null
      : undefined

    const description = hasDescription
      ? sanitizeString(hasOwn('description') ? parsedRecord.description : descriptionTag, 1024) || null
      : undefined

    const rawImageUrl = hasOwn('imageUrl')
      ? parsedRecord.imageUrl
      : imageTag || parsedImageFile?.url || parsedImageFile?.gatewayUrl || null
    const imageUrl = hasImage ? sanitizeString(rawImageUrl, 2048) || null : undefined

    return {
      title,
      description,
      imageUrl,
      imageAttachment: parsedImageFile
    }
  }

  applyMetadataRumor(conversationId, rumor) {
    const parsed = this.extractMetadataFromRumor(rumor)
    if (!parsed) return false

    const patch = {}
    if (parsed.title !== undefined) patch.title = parsed.title
    if (parsed.description !== undefined) patch.description = parsed.description
    if (parsed.imageUrl !== undefined) patch.imageUrl = parsed.imageUrl
    if (!Object.keys(patch).length) return false

    const next = this.setMetadata(conversationId, patch)
    if (parsed.imageAttachment) {
      this.observeConversationFile(conversationId, parsed.imageAttachment, 'metadata-rumor')
    }
    return !!next
  }

  extractReplyToFromPayload(payload) {
    const replyTo = sanitizeString(payload?.replyTo || payload?.replyToId || '', 128)
    return replyTo || null
  }

  buildRumor({
    kind,
    content,
    tags,
    createdAt = nowSeconds()
  }) {
    const rumor = {
      kind,
      pubkey: this.pubkey,
      created_at: Number.isFinite(createdAt) ? Math.floor(createdAt) : nowSeconds(),
      tags: ensureArray(tags),
      content: typeof content === 'string' ? content : ''
    }
    rumor.id = getEventHash(rumor)
    return rumor
  }

  resolveGatewayOrigins() {
    const explicit = this.getPublicGatewayOrigins?.() || []
    const normalized = new Set()

    for (const candidate of explicit) {
      try {
        if (!candidate) continue
        const url = new URL(candidate)
        if (url.protocol === 'ws:') url.protocol = 'http:'
        if (url.protocol === 'wss:') url.protocol = 'https:'
        normalized.add(url.origin)
      } catch {
        // skip invalid candidates
      }
    }

    if (!normalized.size) {
      normalized.add('http://127.0.0.1:8443')
    }

    return Array.from(normalized)
  }

  enrichAttachmentEnvelope(attachment, conversationId) {
    if (!attachment || typeof attachment !== 'object') return null

    const url = sanitizeString(attachment.url, 2048)
    const gatewayUrl = sanitizeString(attachment.gatewayUrl, 2048)
    const primaryUrl = url || gatewayUrl
    if (!primaryUrl) return null

    return {
      url: primaryUrl,
      gatewayUrl: gatewayUrl || null,
      mime: sanitizeString(attachment.mime, 256) || null,
      size: Number.isFinite(attachment.size) ? Number(attachment.size) : null,
      width: Number.isFinite(attachment.width) ? Number(attachment.width) : null,
      height: Number.isFinite(attachment.height) ? Number(attachment.height) : null,
      blurhash: sanitizeString(attachment.blurhash, 256) || null,
      fileName: sanitizeString(attachment.fileName, 256) || null,
      sha256: sanitizeString(attachment.sha256, 128) || null,
      driveKey: normalizePubkey(attachment.driveKey),
      ownerPubkey: normalizePubkey(attachment.ownerPubkey) || this.pubkey,
      fileId: sanitizeString(attachment.fileId, 512) || null,
      conversationId: sanitizeString(conversationId, 256) || null
    }
  }

  inviteNeedsPreview(invite) {
    if (!invite || typeof invite !== 'object') return false
    if (!invite.welcomeRumor) return false

    if (!invite.conversationId) return true
    if (!Array.isArray(invite.memberPubkeys) || invite.memberPubkeys.length === 0) return true
    if (!invite.title && !invite.description && !invite.imageUrl) return true

    return false
  }

  invitePreviewChanged(invite, preview) {
    if (!invite || !preview) return false
    if ((preview.conversationId || null) !== (invite.conversationId || null)) return true
    if ((preview.title || null) !== (invite.title || null)) return true
    if ((preview.description || null) !== (invite.description || null)) return true
    if ((preview.imageUrl || null) !== (invite.imageUrl || null)) return true
    if (!sameNormalizedPubkeyList(preview.memberPubkeys || [], invite.memberPubkeys || [])) return true
    return false
  }

  async createInvitePreviewClient() {
    if (!this.client || !this.signer || !this.network) {
      throw new Error('Invite preview client unavailable before Marmot init')
    }

    const previewKeyValueStore = new InMemoryKeyValueBackend()
    const previewGroupStateBackend = new KeyValueGroupStateBackend(new InMemoryKeyValueBackend())
    const previewKeyPackageStore = new KeyPackageStore(previewKeyValueStore)
    const previewClient = new MarmotClient({
      signer: this.signer,
      network: this.network,
      groupStateBackend: previewGroupStateBackend,
      keyPackageStore: previewKeyPackageStore
    })

    const localKeyPackages = await this.client.keyPackages.list()
    for (const listedPackage of localKeyPackages) {
      const privatePackage = await this.client.keyPackages.getPrivateKey(listedPackage.keyPackageRef)
      if (!privatePackage) continue
      await previewKeyPackageStore.add({
        publicPackage: listedPackage.publicPackage,
        privatePackage
      })
    }

    return previewClient
  }

  async deriveInvitePreview(invite, previewClient) {
    if (!invite?.welcomeRumor || !previewClient || !this.network) return null

    const { group } = await previewClient.joinGroupFromWelcome({
      welcomeRumor: invite.welcomeRumor,
      keyPackageEventId: invite.keyPackageEventId || undefined
    })

    let title = sanitizeString(group?.groupData?.name || '', 256) || null
    let description = sanitizeString(group?.groupData?.description || '', 1024) || null
    let imageUrl = null

    const cachedMetadata = this.getMetadata(group.idStr)
    if (cachedMetadata) {
      if (!title && cachedMetadata.title) title = cachedMetadata.title
      if (!description && cachedMetadata.description) description = cachedMetadata.description
      if (cachedMetadata.imageUrl) imageUrl = cachedMetadata.imageUrl
    }

    const relays = uniqueRelays(group.relays || this.relays)
    const groupEventId = resolveNostrGroupEventId(group)
    try {
      let events = await this.network.request(relays, {
        kinds: [GROUP_EVENT_KIND],
        '#h': groupEventId ? [groupEventId] : [group.idStr],
        limit: 400
      })
      if (!events.length && groupEventId) {
        const fallbackEvents = await this.network.request(relays, {
          kinds: [GROUP_EVENT_KIND],
          limit: 400
        })
        events = filterEventsByGroupEventId(fallbackEvents, groupEventId)
      }

      if (events.length) {
        for await (const result of group.ingest(sortEventsChronological(events))) {
          const rumor = readApplicationRumorFromIngestResult(result)
          if (!rumor || !this.isMetadataRumor(rumor)) continue

          const parsedMetadata = this.extractMetadataFromRumor(rumor)
          if (!parsedMetadata) continue

          if (parsedMetadata.title !== undefined) title = parsedMetadata.title
          if (parsedMetadata.description !== undefined) description = parsedMetadata.description
          if (parsedMetadata.imageUrl !== undefined) imageUrl = parsedMetadata.imageUrl
        }
      }
    } catch (error) {
      this.logger.debug?.('[MarmotService] Failed to derive invite metadata from group events', {
        inviteId: invite.id,
        conversationId: group.idStr,
        error: error?.message || error
      })
    }

    const memberPubkeys = normalizePubkeyList(getGroupMembers(group.state))
    return {
      conversationId: group.idStr,
      title: title || null,
      description: description || null,
      imageUrl: imageUrl || sanitizeString(invite.imageUrl, 2048) || null,
      memberPubkeys: memberPubkeys.length ? memberPubkeys : normalizePubkeyList([invite.senderPubkey])
    }
  }

  async syncInvites({ emit = false } = {}) {
    if (!this.network || !this.signer) return []

    const since = this.lastInviteSyncAt > 0 ? Math.max(0, this.lastInviteSyncAt - 20) : undefined
    const filters = {
      kinds: [GIFT_WRAP_KIND],
      '#p': [this.pubkey],
      ...(since ? { since } : {})
    }

    const events = await this.network.request(this.relays, filters)
    let maxSeen = this.lastInviteSyncAt
    const changedInvitesById = new Map()
    const markInviteChanged = (invite) => {
      if (!invite?.id) return
      changedInvitesById.set(invite.id, invite)
    }
    let previewClient = null
    let previewClientUnavailable = false

    for (const event of sortEventsChronological(events)) {
      const createdAt = Number(event.created_at) || 0
      if (createdAt > maxSeen) maxSeen = createdAt

      const inviteId = String(event.id || '')
      if (!inviteId) continue
      const existing = this.invitesById.get(inviteId)
      if (existing && existing.status === 'joined') continue

      let welcomeRumor = existing?.welcomeRumor || null
      if (!welcomeRumor) {
        try {
          welcomeRumor = await unlockGiftWrap(event, this.signer)
        } catch (error) {
          this.logger.debug?.('[MarmotService] Failed to unlock giftwrap', {
            inviteId,
            error: error?.message || error
          })
          continue
        }
      }

      if (!welcomeRumor || Number(welcomeRumor.kind) !== WELCOME_EVENT_KIND) continue

      const relaysTag = ensureArray(welcomeRumor.tags).find(
        (tag) => Array.isArray(tag) && tag[0] === 'relays'
      )
      let invite = this.normalizeInvite(inviteId, {
        ...existing,
        id: inviteId,
        senderPubkey: normalizePubkey(welcomeRumor.pubkey),
        createdAt: createdAt || Number(welcomeRumor.created_at) || nowSeconds(),
        receivedAt: existing?.receivedAt || existing?.createdAt || nowSeconds(),
        status: existing?.status || 'pending',
        keyPackageEventId:
          readTag(welcomeRumor.tags, 'e')
          || existing?.keyPackageEventId
          || null,
        relays: relaysTag ? relaysTag.slice(1) : existing?.relays || [],
        welcomeRumor,
        error: existing?.error || null
      })

      if (!invite) continue

      if (this.inviteNeedsPreview(invite)) {
        if (!previewClient && !previewClientUnavailable) {
          try {
            previewClient = await this.createInvitePreviewClient()
          } catch (error) {
            previewClientUnavailable = true
            this.logger.debug?.('[MarmotService] Invite preview client unavailable', {
              inviteId,
              error: error?.message || error
            })
          }
        }

        if (previewClient) {
          try {
            const preview = await this.deriveInvitePreview(invite, previewClient)
            if (preview) {
              const enrichedInvite = this.normalizeInvite(inviteId, {
                ...invite,
                ...preview
              })
              if (enrichedInvite) invite = enrichedInvite
            }
          } catch (error) {
            this.logger.debug?.('[MarmotService] Failed to derive invite preview', {
              inviteId,
              error: error?.message || error
            })
          }
        }
      }

      this.invitesById.set(inviteId, invite)
      markInviteChanged(invite)
    }

    const pendingInviteIds = Array.from(this.invitesById.keys())
    for (const inviteId of pendingInviteIds) {
      const invite = this.invitesById.get(inviteId)
      if (!invite || invite.status === 'joined') continue
      if (!this.inviteNeedsPreview(invite)) continue

      if (!previewClient && !previewClientUnavailable) {
        try {
          previewClient = await this.createInvitePreviewClient()
        } catch (error) {
          previewClientUnavailable = true
          this.logger.debug?.('[MarmotService] Invite preview client unavailable', {
            inviteId,
            error: error?.message || error
          })
        }
      }

      if (!previewClient) continue

      try {
        const preview = await this.deriveInvitePreview(invite, previewClient)
        if (!preview || !this.invitePreviewChanged(invite, preview)) continue

        const enrichedInvite = this.normalizeInvite(inviteId, {
          ...invite,
          ...preview
        })
        if (!enrichedInvite) continue

        this.invitesById.set(inviteId, enrichedInvite)
        markInviteChanged(enrichedInvite)
      } catch (error) {
        this.logger.debug?.('[MarmotService] Failed to derive invite preview', {
          inviteId,
          error: error?.message || error
        })
      }
    }

    if (maxSeen > this.lastInviteSyncAt) {
      this.lastInviteSyncAt = maxSeen
    }

    const changedInvites = Array.from(changedInvitesById.values())
    if (changedInvites.length) {
      this.schedulePersist()
      if (emit) {
        for (const invite of changedInvites) {
          this.emit('marmot-invite-updated', {
            invite: this.toPublicInvite(invite),
            reason: 'sync'
          })
        }
      }
    }

    return changedInvites
  }

  async syncConversation(groupId, { emit = false, reason = 'sync' } = {}) {
    const group = this.groupsById.get(groupId) || (await this.client.getGroup(groupId))
    if (!group) return { changed: false, newMessages: [] }

    this.groupsById.set(group.idStr, group)

    const relays = uniqueRelays(group.relays || this.relays)
    const groupEventId = resolveNostrGroupEventId(group)
    const lastSync = this.lastSyncAtByConversation.get(group.idStr) || 0

    const since = lastSync > 0 ? Math.max(0, lastSync - 20) : undefined

    let events = await this.network.request(relays, {
      kinds: [GROUP_EVENT_KIND],
      '#h': groupEventId ? [groupEventId] : [group.idStr],
      ...(since ? { since } : {})
    })

    if (!events.length && groupEventId && since) {
      const fallbackEvents = await this.network.request(relays, {
        kinds: [GROUP_EVENT_KIND],
        since,
        limit: 400
      })
      events = filterEventsByGroupEventId(fallbackEvents, groupEventId)
    }

    if (!events.length) {
      return { changed: false, newMessages: [] }
    }

    let maxSeen = lastSync
    for (const event of events) {
      const createdAt = Number(event.created_at) || 0
      if (createdAt > maxSeen) maxSeen = createdAt
    }

    const newMessages = []
    let metadataChanged = false

    for await (const result of group.ingest(sortEventsChronological(events))) {
      const rumor = readApplicationRumorFromIngestResult(result)
      if (!rumor) continue

      if (this.isMetadataRumor(rumor)) {
        const changed = this.applyMetadataRumor(group.idStr, rumor)
        metadataChanged = metadataChanged || changed
        continue
      }

      const message = this.rumorToThreadMessage(group.idStr, rumor)
      if (!message) continue
      const added = this.upsertMessage(group.idStr, message)
      if (added) newMessages.push(message)
    }

    if (maxSeen > lastSync) {
      this.lastSyncAtByConversation.set(group.idStr, maxSeen)
    }

    const changed = newMessages.length > 0 || metadataChanged
    if (changed) {
      this.schedulePersist()
      if (emit) {
        if (newMessages.length) {
          this.emit('marmot-thread-updated', {
            conversationId: group.idStr,
            messages: newMessages,
            reason
          })
        }
        await this.emitConversationUpdated(group.idStr, reason)
      }
    }

    return { changed, newMessages }
  }

  async syncConversations({ emit = false, reason = 'sync' } = {}) {
    if (!this.client || !this.network) return

    await this.refreshGroupsMap()

    for (const groupId of this.groupsById.keys()) {
      try {
        await this.syncConversation(groupId, { emit, reason })
      } catch (error) {
        this.logger.warn('[MarmotService] Failed syncing conversation', {
          groupId,
          error: error?.message || error
        })
      }
    }
  }

  async syncAll({ emit = false, reason = 'sync' } = {}) {
    if (!this.client || !this.network) return

    if (this.syncInFlight) {
      await this.syncInFlight
      return
    }

    this.syncInFlight = (async () => {
      await this.syncConversations({ emit, reason })
      await this.syncInvites({ emit })
    })()

    try {
      await this.syncInFlight
    } finally {
      this.syncInFlight = null
    }
  }

  getLastMessagePreview(message) {
    if (!message) return ''
    if (message.type === 'reaction') return `Reacted: ${message.content || '+'}`
    if (message.type === 'media') {
      if (message.content) return message.content
      return '[Attachment]'
    }
    return message.content || 'Encrypted message'
  }

  resolveConversationTitle(group, conversationId, participants = []) {
    const metadata = this.getMetadata(conversationId)
    if (metadata?.title) return metadata.title

    const groupName = sanitizeString(group?.groupData?.name || '', 256)
    if (groupName) return groupName

    const others = participants.filter((pubkey) => pubkey !== this.pubkey)
    if (!others.length) return 'Me'
    if (others.length === 1) return others[0]
    return `${others[0]} +${others.length - 1}`
  }

  getGroupAdminPubkeys(group) {
    return normalizePubkeyList(group?.groupData?.adminPubkeys || [])
  }

  buildConversationSummary(group) {
    const conversationId = group.idStr
    const participants = getGroupMembers(group.state)
    const adminPubkeys = this.getGroupAdminPubkeys(group)
    const actorPubkey = normalizePubkey(this.pubkey)
    const metadata = this.getMetadata(conversationId)
    const messages = this.getMessages(conversationId)
    const lastMessage = messages.at(-1) || null
    const readState = this.readStateByConversation.get(conversationId) || null

    return {
      id: conversationId,
      protocol: 'marmot',
      participants,
      title: this.resolveConversationTitle(group, conversationId, participants),
      description: metadata?.description || sanitizeString(group?.groupData?.description || '', 1024) || null,
      imageUrl: metadata?.imageUrl || null,
      unreadCount: this.computeUnreadCount(conversationId),
      lastMessageAt: lastMessage?.timestamp || 0,
      lastMessageId: lastMessage?.id || null,
      lastMessageSenderPubkey: lastMessage?.senderPubkey || null,
      lastMessagePreview: this.getLastMessagePreview(lastMessage),
      lastReadAt: readState?.lastReadAt || 0,
      lastReadMessageId: readState?.lastReadMessageId || null,
      adminPubkeys,
      canInviteMembers: !!actorPubkey && adminPubkeys.includes(actorPubkey),
      relayCount: Array.isArray(group.relays) ? group.relays.length : this.relays.length,
      updatedAt: nowSeconds()
    }
  }

  async emitConversationUpdated(conversationId, reason = 'update') {
    const group = this.groupsById.get(conversationId)
    if (!group) return
    const conversation = this.buildConversationSummary(group)
    this.emit('marmot-conversation-updated', {
      conversation,
      reason
    })
  }

  listConversationSummaries({ search = '' } = {}) {
    const normalizedSearch = sanitizeString(search, 256).toLowerCase()

    let conversations = Array.from(this.groupsById.values()).map((group) => this.buildConversationSummary(group))

    if (normalizedSearch) {
      conversations = conversations.filter((conversation) =>
        makeConversationSearchIndex(conversation).includes(normalizedSearch)
      )
    }

    conversations.sort((a, b) => {
      if (a.lastMessageAt !== b.lastMessageAt) return b.lastMessageAt - a.lastMessageAt
      return a.id.localeCompare(b.id)
    })

    return conversations
  }

  listInvites({ search = '' } = {}) {
    const normalizedSearch = sanitizeString(search, 256).toLowerCase()

    let invites = Array.from(this.invitesById.values()).map((invite) => this.toPublicInvite(invite))

    if (normalizedSearch) {
      invites = invites.filter((invite) => {
        const haystack = [
          invite.id,
          invite.senderPubkey,
          invite.title,
          invite.description,
          invite.conversationId,
          ...(Array.isArray(invite.memberPubkeys) ? invite.memberPubkeys : [])
        ]
          .map((value) => String(value || '').toLowerCase())
          .join(' ')
        return haystack.includes(normalizedSearch)
      })
    }

    invites.sort((a, b) => {
      if (a.createdAt !== b.createdAt) return b.createdAt - a.createdAt
      return a.id.localeCompare(b.id)
    })

    return invites
  }

  async fetchLatestKeyPackageEvent(targetPubkey) {
    const pubkey = normalizePubkey(targetPubkey)
    if (!pubkey) {
      throw new Error(`Invalid invitee pubkey: ${targetPubkey}`)
    }

    const relayCandidates = new Set(this.relays)
    try {
      const inboxRelays = await this.network.getUserInboxRelays(pubkey)
      for (const relay of inboxRelays) relayCandidates.add(relay)
    } catch (_) {
      // fallback to configured relays
    }

    const candidateRelays = Array.from(relayCandidates)
    const events = await this.network.request(candidateRelays, {
      kinds: [KEY_PACKAGE_KIND],
      authors: [pubkey],
      limit: 25
    })

    if (!events.length) {
      this.logger.warn?.('[MarmotService] keyPackage lookup empty', {
        targetPubkey: pubkey,
        relayCount: candidateRelays.length,
        relays: candidateRelays
      })
      throw new Error(`No key package event found for ${pubkey}`)
    }

    const latest = sortEventsChronological(events).at(-1)
    if (!latest) {
      throw new Error(`No key package event found for ${pubkey}`)
    }

    return latest
  }

  async inviteMembers(conversationId, members = []) {
    const group = this.groupsById.get(conversationId) || (await this.client.getGroup(conversationId))
    if (!group) throw new Error(`Conversation ${conversationId} not found`)

    const normalizedMembers = Array.from(
      new Set(
        members
          .map((member) => normalizePubkey(member))
          .filter((member) => !!member && member !== this.pubkey)
      )
    )

    this.logger.info?.('[MarmotService] inviteMembers start', {
      conversationId,
      requestedMembers: ensureArray(members).length,
      normalizedMembers: normalizedMembers.length
    })

    const invited = []
    const failed = []

    for (const memberPubkey of normalizedMembers) {
      try {
        const keyPackageEvent = await this.fetchLatestKeyPackageEvent(memberPubkey)
        const publishResult = await group.inviteByKeyPackageEvent(keyPackageEvent)
        if (!hasAck(publishResult)) {
          throw new Error(
            `Welcome publish was not acknowledged by any relay (${formatPublishAckFailure(publishResult)})`
          )
        }
        invited.push(memberPubkey)
      } catch (error) {
        failed.push({
          pubkey: memberPubkey,
          error: error?.message || String(error)
        })
      }
    }

    this.groupsById.set(group.idStr, group)
    this.logger.info?.('[MarmotService] inviteMembers complete', {
      conversationId: group.idStr,
      invitedCount: invited.length,
      failedCount: failed.length
    })
    if (failed.length) {
      this.logger.warn?.('[MarmotService] inviteMembers failures', {
        conversationId: group.idStr,
        failures: failed
      })
    }
    this.schedulePersist()
    await this.emitConversationUpdated(group.idStr, 'invite-members')

    return {
      conversationId: group.idStr,
      invited,
      failed,
      conversation: this.buildConversationSummary(group)
    }
  }

  async grantAdmin(conversationId, targetPubkey) {
    const normalizedConversationId = sanitizeString(conversationId, 256)
    if (!normalizedConversationId) {
      throw new Error('Conversation id is required')
    }

    const normalizedTargetPubkey = normalizePubkey(targetPubkey)
    if (!normalizedTargetPubkey) {
      throw new Error(`Invalid target pubkey: ${targetPubkey}`)
    }

    try {
      await this.syncConversation(normalizedConversationId, {
        emit: false,
        reason: 'grant-admin-presync'
      })
    } catch (error) {
      this.logger.warn?.('[MarmotService] grantAdmin pre-sync failed', {
        conversationId: normalizedConversationId,
        targetPubkey: normalizedTargetPubkey,
        error: error?.message || error
      })
    }

    const group =
      this.groupsById.get(normalizedConversationId)
      || (await this.client.getGroup(normalizedConversationId))
    if (!group) throw new Error(`Conversation ${normalizedConversationId} not found`)

    const members = normalizePubkeyList(getGroupMembers(group.state))
    if (!members.includes(normalizedTargetPubkey)) {
      throw new Error(`Target pubkey ${normalizedTargetPubkey} is not a member of this chat`)
    }

    const actorPubkey = normalizePubkey(this.pubkey)
    const currentAdminPubkeys = this.getGroupAdminPubkeys(group)
    if (!actorPubkey || !currentAdminPubkeys.includes(actorPubkey)) {
      throw new Error('Not a chat admin. Cannot grant admin permissions.')
    }

    if (currentAdminPubkeys.includes(normalizedTargetPubkey)) {
      return {
        conversationId: group.idStr,
        promotedPubkey: normalizedTargetPubkey,
        alreadyAdmin: true,
        conversation: this.buildConversationSummary(group)
      }
    }

    const nextAdminPubkeys = normalizePubkeyList([
      ...currentAdminPubkeys,
      normalizedTargetPubkey
    ])

    this.logger.info?.('[MarmotService] grantAdmin start', {
      conversationId: group.idStr,
      actorPubkey,
      targetPubkey: normalizedTargetPubkey,
      currentAdminCount: currentAdminPubkeys.length,
      nextAdminCount: nextAdminPubkeys.length
    })

    await group.commit({
      extraProposals: [
        Proposals.proposeUpdateMetadata({
          adminPubkeys: nextAdminPubkeys
        })
      ]
    })

    this.groupsById.set(group.idStr, group)
    this.schedulePersist()
    await this.emitConversationUpdated(group.idStr, 'grant-admin')

    return {
      conversationId: group.idStr,
      promotedPubkey: normalizedTargetPubkey,
      alreadyAdmin: false,
      conversation: this.buildConversationSummary(group)
    }
  }

  resolveConversationCreateRequest({
    title,
    description,
    members,
    imageUrl,
    relayUrls
  } = {}) {
    const normalizedTitle = sanitizeString(title || 'Chat', 256) || 'Chat'
    const normalizedDescription = sanitizeString(description, 1024) || ''
    const normalizedImageUrl = sanitizeString(imageUrl, 2048) || null
    const selectedRelays = uniqueRelays(relayUrls || [], { includeDefaults: false })
    const defaultRelays = uniqueRelays(this.relays || [], { includeDefaults: true })
    const effectiveRelays = selectedRelays.length ? selectedRelays : defaultRelays

    return {
      normalizedTitle,
      normalizedDescription,
      normalizedImageUrl,
      selectedRelays,
      defaultRelays,
      effectiveRelays,
      members: ensureArray(members)
    }
  }

  emitCreateConversationOperation(
    operationId,
    conversationId,
    phase,
    { conversation = null, invited = undefined, failed = undefined, error = null } = {}
  ) {
    if (!operationId || !conversationId || !phase) return
    this.emit('marmot-create-conversation-operation', {
      operationId,
      conversationId,
      phase,
      conversation,
      invited,
      failed,
      error
    })
  }

  async createConversationShell({
    title,
    description,
    members,
    imageUrl,
    relayUrls
  } = {}) {
    const {
      normalizedTitle,
      normalizedDescription,
      normalizedImageUrl,
      selectedRelays,
      effectiveRelays
    } = this.resolveConversationCreateRequest({
      title,
      description,
      members,
      imageUrl,
      relayUrls
    })

    this.logger.info?.('[MarmotService] createConversation start', {
      titleLength: normalizedTitle.length,
      descriptionLength: normalizedDescription.length,
      requestedMembers: ensureArray(members).length,
      requestedRelayCount: selectedRelays.length,
      effectiveRelayCount: effectiveRelays.length,
      relayCount: this.relays.length,
      relays: this.relays,
      effectiveRelays
    })

    const group = await this.client.createGroup(normalizedTitle, {
      description: normalizedDescription,
      relays: effectiveRelays,
      adminPubkeys: [this.pubkey]
    })

    this.groupsById.set(group.idStr, group)
    this.lastSyncAtByConversation.set(group.idStr, nowSeconds())
    this.schedulePersist()

    if (normalizedImageUrl) {
      this.setMetadata(group.idStr, { imageUrl: normalizedImageUrl })
    }

    const conversation = this.buildConversationSummary(group)
    this.emit('marmot-conversation-updated', {
      conversation,
      reason: 'created'
    })

    return {
      conversation,
      members: ensureArray(members)
    }
  }

  async finalizeCreatedConversation({
    operationId = null,
    conversationId,
    members = []
  } = {}) {
    const normalizedConversationId = sanitizeString(conversationId, 256)
    if (!normalizedConversationId) {
      throw new Error('Conversation id is required')
    }

    let inviteResult = {
      invited: [],
      failed: []
    }

    try {
      this.emitCreateConversationOperation(
        operationId,
        normalizedConversationId,
        'invitingMembers'
      )
      inviteResult = await this.inviteMembers(normalizedConversationId, ensureArray(members))
      this.emitCreateConversationOperation(
        operationId,
        normalizedConversationId,
        'syncingConversation'
      )
      await this.syncConversation(normalizedConversationId, { emit: false, reason: 'create' })

      const group =
        this.groupsById.get(normalizedConversationId)
        || (await this.client.getGroup(normalizedConversationId))
      if (!group) {
        throw new Error(`Conversation ${normalizedConversationId} not found after create`)
      }

      this.groupsById.set(group.idStr, group)
      this.schedulePersist()

      const conversation = this.buildConversationSummary(group)
      this.logger.info?.('[MarmotService] createConversation complete', {
        conversationId: group.idStr,
        invitedCount: inviteResult.invited.length,
        failedInviteCount: inviteResult.failed.length
      })
      this.emit('marmot-conversation-updated', {
        conversation,
        reason: 'created'
      })
      this.emitCreateConversationOperation(operationId, normalizedConversationId, 'completed', {
        conversation,
        invited: inviteResult.invited,
        failed: inviteResult.failed
      })

      return {
        conversation,
        invited: inviteResult.invited,
        failed: inviteResult.failed
      }
    } catch (error) {
      this.emitCreateConversationOperation(operationId, normalizedConversationId, 'failed', {
        invited: inviteResult.invited,
        failed: inviteResult.failed,
        error: error?.message || String(error)
      })
      throw error
    }
  }

  async createConversation({
    title,
    description,
    members,
    imageUrl,
    relayUrls
  } = {}) {
    const shell = await this.createConversationShell({
      title,
      description,
      members,
      imageUrl,
      relayUrls
    })

    return await this.finalizeCreatedConversation({
      conversationId: shell.conversation.id,
      members: shell.members
    })
  }

  async runAcceptInviteOperation(operationId, inviteId) {
    const invite = this.invitesById.get(inviteId)
    if (!invite) {
      const error = new Error(`Invite ${inviteId} not found`)
      this.emitAcceptInviteOperation(operationId, inviteId, 'failed', {
        error: error.message
      })
      throw error
    }

    if (!invite.welcomeRumor) {
      const error = new Error(`Invite ${inviteId} does not contain a welcome payload`)
      this.emitAcceptInviteOperation(operationId, inviteId, 'failed', {
        error: error.message
      })
      throw error
    }

    const normalizedWelcomeRumor = normalizeWelcomeRumorPayload(invite.welcomeRumor)
    if (normalizedWelcomeRumor !== invite.welcomeRumor) {
      invite.welcomeRumor = normalizedWelcomeRumor
      this.invitesById.set(inviteId, invite)
      this.schedulePersist()
      this.logger.info?.('[MarmotService] repaired legacy welcome rumor payload', {
        inviteId,
        welcomeId: normalizedWelcomeRumor?.id || null
      })
    }

    invite.status = 'joining'
    invite.error = null
    this.invitesById.set(inviteId, invite)
    this.emitAcceptInviteOperation(operationId, inviteId, 'joiningConversation')
    this.emit('marmot-invite-updated', {
      invite: this.toPublicInvite(invite),
      reason: 'joining'
    })

    let conversationId = null

    try {
      const { group } = await this.client.joinGroupFromWelcome({
        welcomeRumor: normalizedWelcomeRumor,
        keyPackageEventId: invite.keyPackageEventId || undefined
      })

      invite.status = 'joined'
      invite.conversationId = group.idStr
      invite.error = null
      this.invitesById.set(inviteId, invite)

      this.groupsById.set(group.idStr, group)
      conversationId = group.idStr
      this.lastSyncAtByConversation.set(
        group.idStr,
        Math.max(
          Number(invite.createdAt) || 0,
          Number(normalizedWelcomeRumor?.created_at) || 0,
          nowSeconds()
        )
      )
      this.schedulePersist()

      const shellConversation = this.buildConversationSummary(group)
      this.emit('marmot-invite-updated', {
        invite: this.toPublicInvite(invite),
        reason: 'joined'
      })
      await this.emitConversationUpdated(group.idStr, 'joined')
      this.emitAcceptInviteOperation(operationId, inviteId, 'joinedConversation', {
        conversationId,
        conversation: shellConversation
      })
      this.emitAcceptInviteOperation(operationId, inviteId, 'syncingConversation', {
        conversationId,
        conversation: shellConversation
      })

      await this.syncConversation(group.idStr, { emit: true, reason: 'accept-invite' })

      const nextGroup =
        this.groupsById.get(group.idStr) || (await this.client.getGroup(group.idStr)) || group
      this.groupsById.set(nextGroup.idStr, nextGroup)
      this.schedulePersist()

      const finalConversation = this.buildConversationSummary(nextGroup)
      this.emitAcceptInviteOperation(operationId, inviteId, 'completed', {
        conversationId,
        conversation: finalConversation
      })

      return {
        invite: this.toPublicInvite(invite),
        conversation: finalConversation
      }
    } catch (error) {
      const errorMessage = error?.message || String(error)
      if (!conversationId) {
        invite.status = 'failed'
        invite.error = errorMessage
      } else {
        invite.status = 'joined'
        invite.error = null
      }
      this.invitesById.set(inviteId, invite)
      this.schedulePersist()
      if (!conversationId) {
        this.emit('marmot-invite-updated', {
          invite: this.toPublicInvite(invite),
          reason: 'failed'
        })
      }
      this.emitAcceptInviteOperation(operationId, inviteId, 'failed', {
        conversationId,
        error: errorMessage
      })
      throw error
    }
  }

  async acceptInvite(inviteId) {
    return await this.runAcceptInviteOperation(null, inviteId)
  }

  async sendMessage({
    conversationId,
    content,
    replyTo = null,
    type = 'text',
    attachments = [],
    clientMessageId = null
  }) {
    const group = this.groupsById.get(conversationId) || (await this.client.getGroup(conversationId))
    if (!group) throw new Error(`Conversation ${conversationId} not found`)

    const normalizedContent = sanitizeString(content, 6000)
    const replyEventId = sanitizeString(replyTo, 128) || null
    const normalizedAttachments = ensureArray(attachments)
      .map((attachment) => this.enrichAttachmentEnvelope(attachment, conversationId))
      .filter(Boolean)

    this.logger.info?.('[MarmotService] sendMessage start', {
      conversationId,
      type,
      contentLength: normalizedContent.length,
      replyTo: replyEventId || null,
      attachmentCount: normalizedAttachments.length,
      clientMessageId: clientMessageId || null
    })

    if (!normalizedContent && normalizedAttachments.length === 0 && type !== 'reaction') {
      throw new Error('Message content is empty')
    }

    const tags = []
    if (replyEventId) {
      tags.push(['e', replyEventId, '', 'reply'])
    }

    for (const attachment of normalizedAttachments) {
      tags.push(['file', JSON.stringify(attachment)])
    }

    if (type === 'reaction') {
      tags.push(['reaction', '1'])
    }

    const rumor = this.buildRumor({
      kind: type === 'reaction' ? MESSAGE_KIND_REACTION : MESSAGE_KIND_TEXT,
      content: normalizedContent,
      tags
    })

    if (clientMessageId) {
      this.emit('marmot-message-send-status', {
        conversationId,
        clientMessageId,
        messageId: rumor.id,
        status: 'sending'
      })
    }

    try {
      const publishStartedAt = Date.now()
      await group.sendApplicationRumor(rumor)
      this.logger.info?.('[MarmotService] sendMessage publish complete', {
        conversationId,
        rumorId: rumor.id,
        elapsedMs: Date.now() - publishStartedAt
      })
      this.groupsById.set(group.idStr, group)

      const message = this.rumorToThreadMessage(conversationId, rumor)
      this.upsertMessage(conversationId, message)
      this.logger.info?.('[MarmotService] sendMessage local upsert complete', {
        conversationId,
        messageId: message?.id || null,
        messageCount: this.getMessages(conversationId).length
      })
      this.setReadState(conversationId, {
        lastReadMessageId: message.id,
        lastReadAt: message.timestamp
      })

      this.emit('marmot-thread-updated', {
        conversationId,
        messages: [message],
        reason: 'local-send'
      })
      await this.emitConversationUpdated(conversationId, 'local-send')

      if (clientMessageId) {
        this.emit('marmot-message-send-status', {
          conversationId,
          clientMessageId,
          messageId: rumor.id,
          status: 'sent'
        })
      }

      return {
        message,
        conversation: this.buildConversationSummary(group)
      }
    } catch (error) {
      if (clientMessageId) {
        this.emit('marmot-message-send-status', {
          conversationId,
          clientMessageId,
          messageId: rumor.id,
          status: 'failed',
          error: error?.message || String(error)
        })
      }
      this.logger.warn?.('[MarmotService] sendMessage failed', {
        conversationId,
        rumorId: rumor.id,
        clientMessageId: clientMessageId || null,
        error: error?.message || String(error)
      })
      throw error
    }
  }

  async sendMetadataMessage(conversationId, metadata = {}) {
    const group = this.groupsById.get(conversationId) || (await this.client.getGroup(conversationId))
    if (!group) throw new Error(`Conversation ${conversationId} not found`)

    const payload = {}
    if (metadata.title !== undefined) payload.title = sanitizeString(metadata.title, 256) || null
    if (metadata.description !== undefined) {
      payload.description = sanitizeString(metadata.description, 1024) || null
    }
    if (metadata.imageUrl !== undefined) payload.imageUrl = sanitizeString(metadata.imageUrl, 2048) || null

    const imageAttachment = this.enrichAttachmentEnvelope(metadata.imageAttachment, conversationId)
    if (imageAttachment) {
      payload.imageFile = imageAttachment
      if (!payload.imageUrl) {
        payload.imageUrl = imageAttachment.url
      }
    }

    const tags = [['marmot-meta', '1']]
    if (payload.title) tags.push(['title', payload.title])
    if (payload.description) tags.push(['description', payload.description])
    if (payload.imageUrl) tags.push(['image', payload.imageUrl])
    if (imageAttachment) tags.push(['image-file', JSON.stringify(imageAttachment)])

    const rumor = this.buildRumor({
      kind: MESSAGE_KIND_META,
      content: JSON.stringify(payload),
      tags
    })

    await group.sendApplicationRumor(rumor)
    this.groupsById.set(group.idStr, group)

    this.applyMetadataRumor(conversationId, rumor)
    await this.emitConversationUpdated(conversationId, 'metadata-message')
  }

  async loadThread({
    conversationId,
    limit = 200,
    beforeTimestamp = null,
    afterTimestamp = null,
    sync = true
  }) {
    const group = this.groupsById.get(conversationId) || (await this.client.getGroup(conversationId))
    if (!group) throw new Error(`Conversation ${conversationId} not found`)

    this.groupsById.set(group.idStr, group)

    if (sync !== false) {
      await this.syncConversation(conversationId, { emit: false, reason: 'load-thread' })
    }

    let messages = [...this.getMessages(conversationId)]

    if (Number.isFinite(beforeTimestamp)) {
      const before = Math.floor(Number(beforeTimestamp))
      messages = messages.filter((message) => message.timestamp < before)
    }

    if (Number.isFinite(afterTimestamp)) {
      const after = Math.floor(Number(afterTimestamp))
      messages = messages.filter((message) => message.timestamp > after)
    }

    const numericLimit = Number(limit)
    if (Number.isFinite(numericLimit) && numericLimit > 0) {
      messages = messages.slice(-Math.floor(numericLimit))
    }

    const readState = this.readStateByConversation.get(conversationId) || {
      conversationId,
      lastReadMessageId: null,
      lastReadAt: 0,
      updatedAt: nowSeconds()
    }

    return {
      conversationId,
      messages,
      readState,
      unreadCount: this.computeUnreadCount(conversationId)
    }
  }

  async markRead({ conversationId, lastReadMessageId = null, lastReadAt = null }) {
    const messages = this.getMessages(conversationId)

    let effectiveReadMessageId = sanitizeString(lastReadMessageId, 128) || null
    let effectiveReadAt = Number.isFinite(lastReadAt) ? Math.floor(Number(lastReadAt)) : 0

    if (!effectiveReadMessageId || !effectiveReadAt) {
      const fallbackMessage =
        (effectiveReadMessageId
          ? messages.find((message) => message.id === effectiveReadMessageId)
          : messages.at(-1)) || null
      if (fallbackMessage) {
        effectiveReadMessageId = fallbackMessage.id
        effectiveReadAt = fallbackMessage.timestamp
      }
    }

    const readState = this.setReadState(conversationId, {
      lastReadMessageId: effectiveReadMessageId,
      lastReadAt: effectiveReadAt
    })

    await this.emitConversationUpdated(conversationId, 'mark-read')

    return {
      conversationId,
      readState,
      unreadCount: this.computeUnreadCount(conversationId)
    }
  }

  async updateConversationMetadata({
    conversationId,
    title,
    description,
    imageUrl,
    imageAttachment = null,
    publish = true
  }) {
    const metadata = this.setMetadata(conversationId, { title, description, imageUrl })

    if (publish) {
      try {
        await this.sendMetadataMessage(conversationId, {
          title,
          description,
          imageUrl,
          imageAttachment
        })
      } catch (error) {
        this.logger.warn('[MarmotService] Metadata publish failed', {
          conversationId,
          error: error?.message || error
        })
      }
    }

    await this.emitConversationUpdated(conversationId, 'metadata')

    return {
      conversationId,
      metadata,
      conversation: this.buildConversationSummary(this.groupsById.get(conversationId))
    }
  }

  async handleCommand(type, payload = {}) {
    await this.initialize({ relays: payload?.relays })

    switch (type) {
      case 'marmot-init': {
        return this.buildInitSnapshot({ search: payload.search || '' })
      }

      case 'marmot-list-conversations': {
        this.syncAll({ emit: true, reason: 'list-conversations' }).catch((error) => {
          this.logger.warn('[MarmotService] background conversation sync failed', {
            error: error?.message || error
          })
        })
        return {
          conversations: this.listConversationSummaries({ search: payload.search || '' })
        }
      }

      case 'marmot-list-invites': {
        this.syncAll({ emit: true, reason: 'list-invites' }).catch((error) => {
          this.logger.warn('[MarmotService] background invite sync failed', {
            error: error?.message || error
          })
        })
        return {
          invites: this.listInvites({ search: payload.search || '' })
        }
      }

      case 'marmot-create-conversation': {
        const result = await this.createConversation({
          title: payload.title,
          description: payload.description,
          members: payload.members || payload.memberPubkeys || [],
          imageUrl: payload.imageUrl || null,
          relayUrls: payload.relayUrls || payload.relays || []
        })
        return result
      }

      case 'marmot-invite-members': {
        return await this.inviteMembers(payload.conversationId, payload.members || payload.memberPubkeys || [])
      }

      case 'marmot-grant-admin': {
        return await this.grantAdmin(payload.conversationId, payload.targetPubkey || payload.pubkey)
      }

      case 'marmot-accept-invite': {
        return await this.acceptInvite(payload.inviteId || payload.id)
      }

      case 'marmot-load-thread': {
        return await this.loadThread({
          conversationId: payload.conversationId,
          limit: payload.limit,
          beforeTimestamp: payload.beforeTimestamp,
          afterTimestamp: payload.afterTimestamp,
          sync: payload.sync
        })
      }

      case 'marmot-send-message': {
        return await this.sendMessage({
          conversationId: payload.conversationId,
          content: payload.content,
          replyTo: payload.replyTo || payload.replyToId,
          type: payload.type || 'text',
          attachments: payload.attachments || [],
          clientMessageId: payload.clientMessageId || null
        })
      }

      case 'marmot-send-media-message': {
        return await this.sendMessage({
          conversationId: payload.conversationId,
          content: payload.content,
          replyTo: payload.replyTo || payload.replyToId,
          type: payload.type || 'media',
          attachments: payload.attachments || [],
          clientMessageId: payload.clientMessageId || null
        })
      }

      case 'marmot-mark-read': {
        return await this.markRead({
          conversationId: payload.conversationId,
          lastReadMessageId: payload.lastReadMessageId,
          lastReadAt: payload.lastReadAt
        })
      }

      case 'marmot-update-conversation-metadata': {
        return await this.updateConversationMetadata({
          conversationId: payload.conversationId,
          title: payload.title,
          description: payload.description,
          imageUrl: payload.imageUrl,
          imageAttachment: payload.imageAttachment || null,
          publish: payload.publish !== false
        })
      }

      case 'marmot-subscribe-conversation': {
        await this.syncConversation(payload.conversationId, {
          emit: false,
          reason: 'subscribe'
        })
        return {
          conversationId: payload.conversationId,
          subscribed: true
        }
      }

      case 'marmot-unsubscribe-conversation': {
        return {
          conversationId: payload.conversationId,
          subscribed: false
        }
      }

      default:
        throw new Error(`Unsupported Marmot command: ${type}`)
    }
  }
}

export default MarmotService
