import { promises as fs } from 'node:fs'
import { join } from 'node:path'

const INDEX_VERSION = 1
const INDEX_FILE_NAME = 'conversation-file-index.json'
const PERSIST_DELAY_MS = 300

function normalizeString(value, maxLen = 512) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.length > maxLen ? trimmed.slice(0, maxLen) : trimmed
}

function normalizeHex64(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  return /^[a-f0-9]{64}$/.test(trimmed) ? trimmed : null
}

function parseFileHashCandidate(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  const base = trimmed.split('?')[0].split('#')[0].split('/').pop() || ''
  const candidate = base.split('.')[0]
  return /^[a-fA-F0-9]{64}$/.test(candidate) ? candidate.toLowerCase() : null
}

function parseDrivePath(url) {
  if (typeof url !== 'string' || !url.trim()) return null
  try {
    const parsed = new URL(url)
    const segments = parsed.pathname.split('/').filter(Boolean)
    if (segments.length < 3) return null
    if (segments[0] !== 'drive') return null
    const identifier = decodeURIComponent(segments[1] || '').trim()
    const fileId = decodeURIComponent(segments.slice(2).join('/')).trim()
    if (!identifier || !fileId) return null
    return { identifier, fileId }
  } catch {
    return null
  }
}

function deriveFileHash({ fileHash, fileId, url }) {
  return (
    normalizeHex64(fileHash)
    || parseFileHashCandidate(fileId)
    || parseFileHashCandidate(url)
    || null
  )
}

function deriveFileId({ fileId, url, fileHash }) {
  const explicit = normalizeString(fileId, 512)
  if (explicit) return explicit
  const fromUrl = parseDrivePath(url)?.fileId || null
  if (fromUrl) return fromUrl
  const hash = normalizeHex64(fileHash)
  return hash || null
}

function normalizeSize(value) {
  const numeric = Number(value)
  return Number.isFinite(numeric) && numeric >= 0 ? Math.floor(numeric) : null
}

export default class ConversationFileIndex {
  constructor({
    storageRoot,
    logger = console,
    fileName = INDEX_FILE_NAME
  } = {}) {
    this.logger = logger || console
    this.storageRoot = storageRoot || process.cwd()
    this.filePath = join(this.storageRoot, fileName)
    this.records = new Map()
    this.loaded = false
    this.persistTimer = null
    this.persistInFlight = null
    this.dirty = false
  }

  #recordKey(conversationId, fileHash) {
    return `${conversationId}:${fileHash}`
  }

  #providerKey(driveKey, ownerPubkey) {
    if (driveKey) return `drive:${driveKey}`
    if (ownerPubkey) return `owner:${ownerPubkey}`
    return 'unknown'
  }

  async load() {
    if (this.loaded) return
    try {
      const raw = await fs.readFile(this.filePath, 'utf8')
      const parsed = JSON.parse(raw)
      const rows = Array.isArray(parsed?.records) ? parsed.records : []
      for (const row of rows) {
        const normalized = this.#normalizeRecordInput(row)
        if (!normalized) continue
        const key = this.#recordKey(normalized.conversationId, normalized.fileHash)
        this.records.set(key, normalized)
      }
      this.logger.info?.('[ConversationFileIndex] Loaded', {
        path: this.filePath,
        records: this.records.size
      })
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        this.logger.warn?.('[ConversationFileIndex] Failed loading index', {
          path: this.filePath,
          error: error?.message || error
        })
      }
    } finally {
      this.loaded = true
    }
  }

  async close() {
    if (this.persistTimer) {
      clearTimeout(this.persistTimer)
      this.persistTimer = null
    }
    await this.persist()
  }

  #schedulePersist() {
    this.dirty = true
    if (this.persistTimer) return
    this.persistTimer = setTimeout(() => {
      this.persistTimer = null
      this.persist().catch((error) => {
        this.logger.warn?.('[ConversationFileIndex] Persist task failed', {
          error: error?.message || error
        })
      })
    }, PERSIST_DELAY_MS)
    this.persistTimer.unref?.()
  }

  async persist() {
    if (!this.loaded || !this.dirty) return
    if (this.persistInFlight) {
      await this.persistInFlight
      return
    }

    this.persistInFlight = (async () => {
      const payload = {
        version: INDEX_VERSION,
        updatedAt: Date.now(),
        records: Array.from(this.records.values()).map((row) => ({
          conversationId: row.conversationId,
          fileHash: row.fileHash,
          fileId: row.fileId || null,
          url: row.url || null,
          mime: row.mime || null,
          size: normalizeSize(row.size),
          updatedAt: row.updatedAt || Date.now(),
          providers: Array.from(row.providers.values()).map((provider) => ({
            key: provider.key,
            driveKey: provider.driveKey || null,
            ownerPubkey: provider.ownerPubkey || null,
            fileId: provider.fileId || null,
            source: provider.source || null,
            lastSeenAt: provider.lastSeenAt || Date.now()
          }))
        }))
      }
      const tmpPath = `${this.filePath}.tmp`
      await fs.mkdir(this.storageRoot, { recursive: true })
      await fs.writeFile(tmpPath, JSON.stringify(payload, null, 2), 'utf8')
      await fs.rename(tmpPath, this.filePath)
      this.dirty = false
    })()

    try {
      await this.persistInFlight
    } finally {
      this.persistInFlight = null
    }
  }

  #normalizeRecordInput(input) {
    if (!input || typeof input !== 'object') return null
    const conversationId = normalizeString(input.conversationId, 256)
    const fileHash = normalizeHex64(input.fileHash)
    if (!conversationId || !fileHash) return null

    const providers = new Map()
    const providerRows = Array.isArray(input.providers) ? input.providers : []
    for (const provider of providerRows) {
      if (!provider || typeof provider !== 'object') continue
      const driveKey = normalizeHex64(provider.driveKey)
      const ownerPubkey = normalizeHex64(provider.ownerPubkey)
      const key = this.#providerKey(driveKey, ownerPubkey)
      providers.set(key, {
        key,
        driveKey,
        ownerPubkey,
        fileId: deriveFileId({
          fileId: provider.fileId,
          url: input.url,
          fileHash
        }),
        source: normalizeString(provider.source, 128),
        lastSeenAt: Number.isFinite(provider.lastSeenAt) ? Number(provider.lastSeenAt) : Date.now()
      })
    }

    return {
      conversationId,
      fileHash,
      fileId: deriveFileId({ fileId: input.fileId, url: input.url, fileHash }),
      url: normalizeString(input.url, 4096),
      mime: normalizeString(input.mime, 256),
      size: normalizeSize(input.size),
      updatedAt: Number.isFinite(input.updatedAt) ? Number(input.updatedAt) : Date.now(),
      providers
    }
  }

  upsert({
    conversationId,
    fileHash,
    fileId = null,
    driveKey = null,
    ownerPubkey = null,
    url = null,
    mime = null,
    size = null,
    source = null
  } = {}) {
    let normalizedConversationId = normalizeString(conversationId, 256)
    const normalizedUrl = normalizeString(url, 4096)
    const parsedPath = parseDrivePath(normalizedUrl)
    if (!normalizedConversationId && parsedPath?.identifier) {
      normalizedConversationId = parsedPath.identifier
    }
    if (!normalizedConversationId) return null

    const normalizedFileHash = deriveFileHash({
      fileHash,
      fileId,
      url: normalizedUrl
    })
    if (!normalizedFileHash) return null

    const normalizedFileId = deriveFileId({
      fileId: fileId || parsedPath?.fileId || null,
      url: normalizedUrl,
      fileHash: normalizedFileHash
    })
    const normalizedDriveKey = normalizeHex64(driveKey)
    const normalizedOwner = normalizeHex64(ownerPubkey)
    const providerKey = this.#providerKey(normalizedDriveKey, normalizedOwner)

    const mapKey = this.#recordKey(normalizedConversationId, normalizedFileHash)
    const now = Date.now()
    const existing = this.records.get(mapKey) || {
      conversationId: normalizedConversationId,
      fileHash: normalizedFileHash,
      fileId: normalizedFileId,
      url: normalizedUrl,
      mime: normalizeString(mime, 256),
      size: normalizeSize(size),
      updatedAt: now,
      providers: new Map()
    }

    existing.fileId = normalizedFileId || existing.fileId || normalizedFileHash
    existing.url = normalizedUrl || existing.url || null
    existing.mime = normalizeString(mime, 256) || existing.mime || null
    existing.size = normalizeSize(size) ?? existing.size ?? null
    existing.updatedAt = now

    const providerExisting = existing.providers.get(providerKey) || {
      key: providerKey,
      driveKey: normalizedDriveKey,
      ownerPubkey: normalizedOwner,
      fileId: normalizedFileId || null,
      source: normalizeString(source, 128),
      lastSeenAt: now
    }
    providerExisting.driveKey = normalizedDriveKey || providerExisting.driveKey || null
    providerExisting.ownerPubkey = normalizedOwner || providerExisting.ownerPubkey || null
    providerExisting.fileId = normalizedFileId || providerExisting.fileId || null
    providerExisting.source = normalizeString(source, 128) || providerExisting.source || null
    providerExisting.lastSeenAt = now

    existing.providers.set(providerKey, providerExisting)
    this.records.set(mapKey, existing)
    this.#schedulePersist()
    return existing
  }

  getRecord(conversationId, fileHash) {
    const normalizedConversationId = normalizeString(conversationId, 256)
    const normalizedFileHash = normalizeHex64(fileHash)
    if (!normalizedConversationId || !normalizedFileHash) return null
    return this.records.get(this.#recordKey(normalizedConversationId, normalizedFileHash)) || null
  }

  getProviders(conversationId, fileHash) {
    const record = this.getRecord(conversationId, fileHash)
    if (!record) return []
    return Array.from(record.providers.values())
      .filter((provider) => provider && provider.driveKey)
      .sort((left, right) => (right.lastSeenAt || 0) - (left.lastSeenAt || 0))
  }
}

