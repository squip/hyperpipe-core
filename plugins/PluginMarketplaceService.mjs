import path from 'node:path'
import { promises as fs } from 'node:fs'
import nodeCrypto from 'node:crypto'
import Hyperswarm from 'hyperswarm'
import Corestore from 'corestore'
import Hyperdrive from 'hyperdrive'
import b4a from 'b4a'
import { SimplePool } from 'nostr-tools/pool'

const DEFAULT_MARKETPLACE_RELAYS = [
  'wss://relay.nostr.band',
  'wss://relay.damus.io',
  'wss://nos.lol'
]

const DEFAULT_MARKETPLACE_KINDS = [37130]
const DEFAULT_DISCOVERY_LIMIT = 200
const DEFAULT_TIMEOUT_MS = 12_000
const DEFAULT_ARCHIVE_DOWNLOAD_TIMEOUT_MS = 120_000
const MAX_ARCHIVE_DOWNLOAD_BYTES = 128 * 1024 * 1024

function asString(value, fallback = '') {
  return typeof value === 'string' ? value.trim() : fallback
}

function asArray(value) {
  return Array.isArray(value) ? value : []
}

function parseJsonSafe(value) {
  if (typeof value !== 'string') return null
  try {
    const parsed = JSON.parse(value)
    return parsed && typeof parsed === 'object' ? parsed : null
  } catch (_) {
    return null
  }
}

function normalizeRelayUrl(value) {
  const url = asString(value)
  if (!url) return ''
  if (!url.startsWith('ws://') && !url.startsWith('wss://')) return ''
  return url
}

function normalizeHex64(value) {
  const next = asString(value).toLowerCase()
  return /^[a-f0-9]{64}$/.test(next) ? next : ''
}

function normalizePluginId(value) {
  const id = asString(value).toLowerCase()
  return /^[a-z0-9]+([.-][a-z0-9]+)+$/.test(id) ? id : ''
}

function normalizePermissionList(value) {
  if (Array.isArray(value)) {
    return value.map((entry) => asString(entry)).filter(Boolean)
  }
  if (typeof value === 'string') {
    return value
      .split(',')
      .map((entry) => asString(entry))
      .filter(Boolean)
  }
  return []
}

function normalizePath(value, fallback = '/manifest.json') {
  const next = asString(value)
  if (!next) return fallback
  if (!next.startsWith('/')) return `/${next}`
  return next
}

function parseTagValues(tags = []) {
  const map = new Map()
  for (const tag of tags) {
    if (!Array.isArray(tag) || tag.length < 2) continue
    const key = asString(tag[0]).toLowerCase()
    if (!key) continue
    const value = asString(tag[1])
    if (!map.has(key)) map.set(key, [])
    map.get(key).push(value)
  }
  return map
}

function firstTag(tagsMap, keys = []) {
  for (const key of keys) {
    const values = tagsMap.get(key)
    if (values && values.length) return values[0]
  }
  return ''
}

function parseHyperdriveUrl(value) {
  const source = asString(value)
  if (!source.startsWith('hyper://')) return null
  try {
    const parsed = new URL(source)
    const driveKey = normalizeHex64(parsed.hostname)
    if (!driveKey) return null
    const manifestPath = normalizePath(parsed.pathname || '/manifest.json')
    return {
      url: `hyper://${driveKey}${manifestPath}`,
      driveKey,
      manifestPath
    }
  } catch (_) {
    return null
  }
}

function normalizeArchivePath(pathname = '') {
  const next = normalizePath(pathname || '/')
  if (!next.endsWith('.tgz')) return ''
  return next
}

function parseArchiveSource(sourceValue) {
  const source = asString(sourceValue)
  if (!source) return null

  if (source.startsWith('http://') || source.startsWith('https://')) {
    return {
      type: 'http',
      source,
      label: source
    }
  }

  if (source.startsWith('hyper://')) {
    try {
      const parsed = new URL(source)
      const driveKey = normalizeHex64(parsed.hostname)
      const archivePath = normalizeArchivePath(parsed.pathname || '/')
      if (!driveKey || !archivePath) return null
      return {
        type: 'hyper',
        source,
        label: source,
        driveKey,
        archivePath
      }
    } catch (_) {
      return null
    }
  }

  if (source.startsWith('/')) {
    const archivePath = normalizeArchivePath(source)
    if (!archivePath) return null
    return {
      type: 'file',
      source: archivePath,
      label: archivePath,
      filePath: archivePath
    }
  }

  return null
}

function toArchiveFilename({ pluginId, version, digest, sourceLabel }) {
  const safePluginId = normalizePluginId(pluginId) || 'plugin'
  const safeVersion = asString(version || '0.0.0').replace(/[^a-zA-Z0-9._-]/g, '-') || '0.0.0'
  const sourceSeed = asString(sourceLabel || '').replace(/[^a-zA-Z0-9._-]/g, '-')
  const digestPrefix = asString(digest).slice(0, 12) || 'archive'
  const parts = [safePluginId, safeVersion, digestPrefix]
  if (sourceSeed) parts.push(sourceSeed.slice(-24))
  return `${parts.join('-')}.htplugin.tgz`
}

function withTimeout(promise, timeoutMs, label = 'operation') {
  const timeout = Math.max(1000, Number(timeoutMs) || DEFAULT_TIMEOUT_MS)
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error(`${label} timed out after ${timeout}ms`)), timeout)
    })
  ])
}

function createManifestFromHints(hints = {}) {
  const id = normalizePluginId(hints.id || hints.pluginId || hints.identifier)
  if (!id) return null
  const version = asString(hints.version || hints.pluginVersion || '0.0.0')
  const name = asString(hints.name || hints.title || id)
  const hyper = parseHyperdriveUrl(hints.hyperdriveUrl || hints.sourceUrl || '')
  const manifest = {
    id,
    name,
    version,
    engines: {
      hyperpipe: asString(hints?.engines?.hyperpipe || '^1.0.0'),
      worker: asString(hints?.engines?.worker || '^1.0.0'),
      renderer: asString(hints?.engines?.renderer || '^1.0.0'),
      mediaApi: asString(hints?.engines?.mediaApi || '^1.0.0')
    },
    entrypoints: {
      runner: asString(hints?.entrypoints?.runner || 'dist/runner.mjs')
    },
    permissions: normalizePermissionList(hints.permissions),
    contributions: {
      navItems: asArray(hints?.contributions?.navItems),
      routes: asArray(hints?.contributions?.routes),
      mediaFeatures: asArray(hints?.contributions?.mediaFeatures)
    },
    integrity: {
      bundleSha256: asString(hints?.integrity?.bundleSha256 || hints.bundleSha256).toLowerCase(),
      sourceSha256: asString(hints?.integrity?.sourceSha256 || hints.sourceSha256).toLowerCase()
    },
    source: {
      hyperdriveUrl: hyper?.url || asString(hints?.source?.hyperdriveUrl || hints.hyperdriveUrl),
      path: asString(hints?.source?.path || hints.path || '/')
    },
    marketplace: {
      publisherPubkey: asString(hints?.marketplace?.publisherPubkey || hints.publisherPubkey).toLowerCase(),
      tags: normalizePermissionList(hints?.marketplace?.tags || hints.tags || [])
    }
  }
  return manifest
}

export default class PluginMarketplaceService {
  constructor({
    logger = console,
    storageRoot,
    fetchImpl = globalThis.fetch?.bind(globalThis)
  } = {}) {
    this.logger = logger
    this.storageRoot = storageRoot || path.join(process.cwd(), '.marketplace-cache')
    this.fetch = typeof fetchImpl === 'function' ? fetchImpl : null
  }

  #buildArchiveCandidates({ listing = null, bundleUrl = '', archiveUrl = '' } = {}) {
    const candidates = []
    const seen = new Set()
    const listingObj = listing && typeof listing === 'object' ? listing : {}
    const manifest = listingObj?.manifest && typeof listingObj.manifest === 'object'
      ? listingObj.manifest
      : {}
    const metadata = listingObj?.metadata && typeof listingObj.metadata === 'object'
      ? listingObj.metadata
      : {}

    const addCandidate = (value, sourceType) => {
      const parsed = parseArchiveSource(value)
      if (!parsed) return
      const key = `${parsed.type}:${parsed.source}`
      if (seen.has(key)) return
      seen.add(key)
      candidates.push({
        ...parsed,
        sourceType
      })
    }

    addCandidate(bundleUrl, 'payload.bundleUrl')
    addCandidate(archiveUrl, 'payload.archiveUrl')
    addCandidate(metadata.bundleUrl, 'listing.metadata.bundleUrl')
    addCandidate(metadata.archiveUrl, 'listing.metadata.archiveUrl')
    addCandidate(metadata.bundle_url, 'listing.metadata.bundle_url')
    addCandidate(metadata.archive_url, 'listing.metadata.archive_url')
    addCandidate(manifest?.source?.bundleUrl, 'listing.manifest.source.bundleUrl')
    addCandidate(manifest?.source?.archiveUrl, 'listing.manifest.source.archiveUrl')

    const hyperdriveUrl = asString(metadata.hyperdriveUrl || manifest?.source?.hyperdriveUrl)
    const manifestSourcePath = asString(manifest?.source?.path || '')
    if (hyperdriveUrl && manifestSourcePath && manifestSourcePath.endsWith('.tgz')) {
      const normalizedHyper = hyperdriveUrl.endsWith('/') ? hyperdriveUrl.slice(0, -1) : hyperdriveUrl
      addCandidate(`${normalizedHyper}${manifestSourcePath.startsWith('/') ? '' : '/'}${manifestSourcePath}`, 'listing.manifest.source.path')
    }

    return candidates
  }

  async #downloadArchiveFromHttp(url, { timeoutMs, maxBytes }) {
    if (!this.fetch) {
      throw new Error('Global fetch() is unavailable for HTTP archive download')
    }

    const response = await withTimeout(
      this.fetch(url, {
        method: 'GET'
      }),
      timeoutMs,
      'archive-http-download'
    )
    if (!response.ok) {
      throw new Error(`Archive download failed (${response.status})`)
    }

    const contentLength = Number(response.headers?.get?.('content-length') || 0)
    if (Number.isFinite(contentLength) && contentLength > 0 && contentLength > maxBytes) {
      throw new Error(`Archive exceeds max size limit (${contentLength} > ${maxBytes})`)
    }

    const arrayBuffer = await response.arrayBuffer()
    const bytes = Buffer.from(arrayBuffer)
    if (!bytes.length) {
      throw new Error('Archive download returned empty payload')
    }
    if (bytes.length > maxBytes) {
      throw new Error(`Archive exceeds max size limit (${bytes.length} > ${maxBytes})`)
    }
    return bytes
  }

  async #downloadArchiveFromFile(filePath, { maxBytes }) {
    const stats = await fs.stat(filePath)
    if (!stats.isFile()) {
      throw new Error('Archive path does not point to a file')
    }
    if (stats.size <= 0) {
      throw new Error('Archive file is empty')
    }
    if (stats.size > maxBytes) {
      throw new Error(`Archive exceeds max size limit (${stats.size} > ${maxBytes})`)
    }
    return fs.readFile(filePath)
  }

  async #downloadArchiveFromHyperdrive(driveKey, archivePath, { timeoutMs, maxBytes }) {
    const fileBuffer = await this.#readHyperdriveFile(driveKey, archivePath, timeoutMs)
    if (!fileBuffer || !fileBuffer.length) {
      throw new Error('Hyperdrive archive was not found')
    }
    if (fileBuffer.length > maxBytes) {
      throw new Error(`Archive exceeds max size limit (${fileBuffer.length} > ${maxBytes})`)
    }
    return fileBuffer
  }

  async #fetchArchiveCandidate(candidate, options = {}) {
    if (!candidate || typeof candidate !== 'object') {
      throw new Error('Archive candidate is invalid')
    }

    if (candidate.type === 'http') {
      return this.#downloadArchiveFromHttp(candidate.source, options)
    }
    if (candidate.type === 'file') {
      return this.#downloadArchiveFromFile(candidate.filePath, options)
    }
    if (candidate.type === 'hyper') {
      return this.#downloadArchiveFromHyperdrive(candidate.driveKey, candidate.archivePath, options)
    }
    throw new Error(`Unsupported archive candidate type: ${candidate.type}`)
  }

  async downloadArchive(options = {}) {
    const listing = options && typeof options === 'object' ? options.listing : null
    const timeoutMs = Math.max(
      1_000,
      Math.min(Number(options?.timeoutMs) || DEFAULT_ARCHIVE_DOWNLOAD_TIMEOUT_MS, 5 * 60_000)
    )
    const maxBytes = Math.max(
      1 * 1024 * 1024,
      Math.min(Number(options?.maxBytes) || MAX_ARCHIVE_DOWNLOAD_BYTES, 256 * 1024 * 1024)
    )
    const candidates = this.#buildArchiveCandidates({
      listing,
      bundleUrl: options?.bundleUrl,
      archiveUrl: options?.archiveUrl
    })

    if (!candidates.length) {
      throw new Error('No plugin archive source found in marketplace listing')
    }

    const warnings = []
    let selectedCandidate = null
    let archiveBytes = null
    for (const candidate of candidates) {
      try {
        archiveBytes = await this.#fetchArchiveCandidate(candidate, { timeoutMs, maxBytes })
        selectedCandidate = candidate
        break
      } catch (error) {
        const warning = `${candidate.sourceType}: ${error?.message || error}`
        warnings.push(warning)
      }
    }

    if (!archiveBytes || !selectedCandidate) {
      throw new Error(`Failed to download plugin archive (${warnings.join('; ')})`)
    }

    const listingManifest = listing?.manifest && typeof listing.manifest === 'object'
      ? listing.manifest
      : {}
    const pluginId = normalizePluginId(listingManifest?.id || options?.pluginId || 'plugin')
    const version = asString(listingManifest?.version || options?.version || '0.0.0')
    const archiveSha256 = nodeCrypto.createHash('sha256').update(archiveBytes).digest('hex')

    const downloadsRoot = path.join(this.storageRoot, 'plugin-marketplace-cache', 'downloads')
    await fs.mkdir(downloadsRoot, { recursive: true })
    const fileName = toArchiveFilename({
      pluginId,
      version,
      digest: archiveSha256,
      sourceLabel: selectedCandidate.sourceType
    })
    const archivePath = path.join(downloadsRoot, fileName)
    await fs.writeFile(archivePath, archiveBytes)

    return {
      archivePath,
      sizeBytes: archiveBytes.length,
      sha256: archiveSha256,
      source: selectedCandidate.label,
      sourceType: selectedCandidate.sourceType,
      warnings
    }
  }

  async discover(options = {}) {
    const relays = (Array.isArray(options.relays) ? options.relays : DEFAULT_MARKETPLACE_RELAYS)
      .map((relay) => normalizeRelayUrl(relay))
      .filter(Boolean)
    const kinds = (Array.isArray(options.kinds) ? options.kinds : DEFAULT_MARKETPLACE_KINDS)
      .map((value) => Number(value))
      .filter((value) => Number.isFinite(value))
    const authors = asArray(options.authors).map((author) => normalizeHex64(author)).filter(Boolean)
    const limit = Math.max(1, Math.min(Number(options.limit) || DEFAULT_DISCOVERY_LIMIT, 500))
    const timeoutMs = Math.max(1000, Math.min(Number(options.timeoutMs) || DEFAULT_TIMEOUT_MS, 60_000))

    if (!relays.length) {
      return {
        relays: [],
        listings: [],
        warnings: ['No valid marketplace relays configured']
      }
    }

    const filter = {
      kinds: kinds.length ? kinds : DEFAULT_MARKETPLACE_KINDS,
      limit
    }
    if (authors.length) filter.authors = authors
    if (Number.isFinite(options.since)) filter.since = Number(options.since)
    if (Number.isFinite(options.until)) filter.until = Number(options.until)

    const pool = new SimplePool()
    const abortController = new AbortController()
    const timeoutId = setTimeout(() => abortController.abort('marketplace-timeout'), timeoutMs)
    let rawEvents = []
    try {
      rawEvents = await pool.querySync(relays, filter, {
        maxWait: timeoutMs,
        abort: abortController.signal
      })
    } catch (error) {
      this.logger?.warn?.('[PluginMarketplaceService] Failed to query marketplace relays', {
        error: error?.message || error
      })
    } finally {
      clearTimeout(timeoutId)
      try {
        pool.destroy()
      } catch (_) {}
    }

    const events = asArray(rawEvents)
      .filter((event) => event && typeof event === 'object')
      .sort((a, b) => Number(b.created_at || 0) - Number(a.created_at || 0))

    const listings = []
    const warnings = []
    for (const event of events) {
      try {
        const listing = await this.#parseEventListing(event, { timeoutMs })
        if (!listing) continue
        listings.push(listing)
      } catch (error) {
        warnings.push(`Failed to parse marketplace event ${event?.id || '<unknown>'}: ${error?.message || error}`)
      }
    }

    return {
      relays,
      listings,
      warnings
    }
  }

  async #parseEventListing(event, { timeoutMs }) {
    const content = parseJsonSafe(event.content || '') || {}
    const tagsMap = parseTagValues(event.tags || [])

    const hyperdriveTag = firstTag(tagsMap, ['hyperdrive', 'source', 'bundle'])
    const manifestTag = firstTag(tagsMap, ['manifest', 'manifest_url', 'url'])
    const manifestPathTag = firstTag(tagsMap, ['manifest_path'])

    const metadata = {
      eventId: asString(event.id),
      kind: Number(event.kind) || null,
      pubkey: asString(event.pubkey),
      createdAt: Number(event.created_at) || 0,
      relays: asArray(content.relays).map((relay) => normalizeRelayUrl(relay)).filter(Boolean),
      hyperdriveUrl: asString(content.hyperdriveUrl || hyperdriveTag),
      manifestUrl: asString(content.manifestUrl || manifestTag),
      manifestPath: normalizePath(content.manifestPath || manifestPathTag || '/manifest.json'),
      bundleUrl: asString(content.bundleUrl || firstTag(tagsMap, ['bundle', 'bundle_url'])),
      social: {
        recommendCount: Number(content.recommendCount || firstTag(tagsMap, ['recommend_count']) || 0) || 0,
        installCount: Number(content.installCount || firstTag(tagsMap, ['install_count']) || 0) || 0,
        flagCount: Number(content.flagCount || firstTag(tagsMap, ['flag_count']) || 0) || 0
      }
    }

    let manifest = content.manifest && typeof content.manifest === 'object'
      ? content.manifest
      : null

    if (!manifest && metadata.manifestUrl) {
      manifest = await this.#fetchManifestFromUrl(metadata.manifestUrl, {
        timeoutMs,
        fallbackPath: metadata.manifestPath
      })
    }

    if (!manifest && metadata.hyperdriveUrl) {
      const hyper = parseHyperdriveUrl(
        metadata.hyperdriveUrl.includes('/')
          ? metadata.hyperdriveUrl
          : `${metadata.hyperdriveUrl}${metadata.manifestPath}`
      )
      if (hyper) {
        manifest = await this.#fetchManifestFromHyperdrive(hyper.driveKey, hyper.manifestPath, timeoutMs)
      }
    }

    if (!manifest) {
      manifest = createManifestFromHints({
        id: content.id || content.pluginId || firstTag(tagsMap, ['id', 'plugin_id']),
        name: content.name || content.title || firstTag(tagsMap, ['name', 'title']),
        version: content.version || firstTag(tagsMap, ['version']),
        permissions: content.permissions || firstTag(tagsMap, ['permissions']),
        hyperdriveUrl: metadata.hyperdriveUrl,
        bundleSha256: content.bundleSha256 || firstTag(tagsMap, ['bundle_sha256']),
        sourceSha256: content.sourceSha256 || firstTag(tagsMap, ['source_sha256']),
        publisherPubkey: content.publisherPubkey || metadata.pubkey,
        tags: asArray(event.tags || []).map((tag) => (Array.isArray(tag) ? tag.join(':') : String(tag)))
      })
    }

    if (!manifest || typeof manifest !== 'object') return null

    manifest.marketplace = {
      ...(manifest.marketplace && typeof manifest.marketplace === 'object' ? manifest.marketplace : {}),
      publisherPubkey:
        asString(manifest?.marketplace?.publisherPubkey || metadata.pubkey).toLowerCase(),
      tags: asArray(manifest?.marketplace?.tags).length
        ? asArray(manifest.marketplace.tags)
        : asArray(event.tags || []).map((tag) => (Array.isArray(tag) ? tag.join(':') : String(tag)))
    }
    manifest.source = {
      ...(manifest.source && typeof manifest.source === 'object' ? manifest.source : {}),
      hyperdriveUrl: asString(manifest?.source?.hyperdriveUrl || metadata.hyperdriveUrl),
      path: asString(manifest?.source?.path || '/')
    }

    return {
      manifest,
      metadata
    }
  }

  async #fetchManifestFromUrl(url, { timeoutMs, fallbackPath = '/manifest.json' } = {}) {
    const target = asString(url)
    if (!target) return null
    if (target.startsWith('hyper://')) {
      const parsed = parseHyperdriveUrl(target.includes('/') ? target : `${target}${fallbackPath}`)
      if (!parsed) return null
      return this.#fetchManifestFromHyperdrive(parsed.driveKey, parsed.manifestPath, timeoutMs)
    }
    if (!this.fetch) return null
    if (!target.startsWith('http://') && !target.startsWith('https://')) return null

    try {
      const response = await withTimeout(
        this.fetch(target, {
          method: 'GET',
          headers: { accept: 'application/json' }
        }),
        timeoutMs,
        'manifest-fetch'
      )
      if (!response.ok) throw new Error(`Manifest fetch failed (${response.status})`)
      const payload = await response.json()
      return payload && typeof payload === 'object' ? payload : null
    } catch (error) {
      this.logger?.warn?.('[PluginMarketplaceService] Manifest URL fetch failed', {
        url: target,
        error: error?.message || error
      })
      return null
    }
  }

  async #readHyperdriveFile(driveKey, targetPath = '/manifest.json', timeoutMs = DEFAULT_TIMEOUT_MS) {
    const normalizedDriveKey = normalizeHex64(driveKey)
    if (!normalizedDriveKey) return null
    const normalizedPath = normalizePath(targetPath || '/manifest.json')

    const cacheRoot = path.join(this.storageRoot, 'plugin-marketplace-cache', normalizedDriveKey.slice(0, 16))
    await fs.mkdir(cacheRoot, { recursive: true })

    const store = new Corestore(cacheRoot)
    let swarm = null
    let discovery = null
    let drive = null
    try {
      await store.ready()
      drive = new Hyperdrive(store, b4a.from(normalizedDriveKey, 'hex'))
      await drive.ready()

      swarm = new Hyperswarm()
      swarm.on('connection', (connection) => {
        try {
          store.replicate(connection)
        } catch (_) {}
      })
      discovery = swarm.join(drive.discoveryKey, { client: true, server: false })
      await discovery.flushed()

      const entry = await withTimeout(
        drive.get(normalizedPath),
        timeoutMs,
        'hyperdrive-file-fetch'
      )
      if (!entry) return null
      if (Buffer.isBuffer(entry)) return entry
      if (entry instanceof Uint8Array) return Buffer.from(entry)
      return Buffer.from(String(entry), 'utf8')
    } catch (error) {
      this.logger?.debug?.('[PluginMarketplaceService] Hyperdrive manifest fetch failed', {
        driveKey: normalizedDriveKey.slice(0, 12),
        path: normalizedPath,
        error: error?.message || error
      })
      return null
    } finally {
      try {
        await discovery?.destroy?.()
      } catch (_) {}
      try {
        await swarm?.destroy?.()
      } catch (_) {}
      try {
        await drive?.close?.()
      } catch (_) {}
      try {
        await store?.close?.()
      } catch (_) {}
    }
  }

  async #fetchManifestFromHyperdrive(driveKey, manifestPath = '/manifest.json', timeoutMs = DEFAULT_TIMEOUT_MS) {
    const fileBuffer = await this.#readHyperdriveFile(driveKey, manifestPath, timeoutMs)
    if (!fileBuffer) return null
    const parsed = parseJsonSafe(fileBuffer.toString('utf8'))
    return parsed && typeof parsed === 'object' ? parsed : null
  }
}
