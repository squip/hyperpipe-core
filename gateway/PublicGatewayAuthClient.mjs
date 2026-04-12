import { schnorr } from '@noble/curves/secp256k1.js'

function normalizeBaseUrl(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.replace(/\/+$/, '')
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) return null
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function toHex(bytes) {
  return Buffer.from(bytes).toString('hex')
}

function normalizePubkey(value) {
  if (typeof value !== 'string') return ''
  const trimmed = value.trim().toLowerCase()
  return /^[0-9a-f]{64}$/.test(trimmed) ? trimmed : ''
}

function safeLogger(logger = null) {
  const noop = () => {}
  const value = logger && typeof logger === 'object' ? logger : {}
  return {
    debug: typeof value.debug === 'function' ? value.debug.bind(value) : noop,
    info: typeof value.info === 'function' ? value.info.bind(value) : noop,
    warn: typeof value.warn === 'function' ? value.warn.bind(value) : noop,
    error: typeof value.error === 'function' ? value.error.bind(value) : noop
  }
}

async function parseResponsePayload(response) {
  const text = await response.text().catch(() => '')
  if (!text) return {}
  try {
    return JSON.parse(text)
  } catch {
    return { raw: text }
  }
}

function clonePayload(value) {
  return value && typeof value === 'object'
    ? JSON.parse(JSON.stringify(value))
    : value
}

export default class PublicGatewayAuthClient {
  constructor({
    baseUrl = null,
    fetchImpl = globalThis.fetch,
    logger = null,
    getAuthContext = null
  } = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl)
    this.fetchImpl = typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch
    this.logger = safeLogger(logger)
    this.getAuthContext = typeof getAuthContext === 'function' ? getAuthContext : null
    this.tokenCache = new Map()
  }

  isEnabled() {
    return Boolean(this.baseUrl && this.fetchImpl && this.getAuthContext)
  }

  setBaseUrl(baseUrl) {
    const next = normalizeBaseUrl(baseUrl)
    if (next === this.baseUrl) return
    this.baseUrl = next
    this.tokenCache.clear()
  }

  invalidateToken({ scope = null, relayKey = null } = {}) {
    if (!scope) {
      this.tokenCache.clear()
      return
    }
    const cachePrefix = this.#buildCachePrefix(scope, relayKey)
    for (const cacheKey of this.tokenCache.keys()) {
      if (cacheKey.startsWith(cachePrefix)) {
        this.tokenCache.delete(cacheKey)
      }
    }
  }

  async issueBearerToken({ scope = 'gateway:relay-register', relayKey = null, forceRefresh = false } = {}) {
    const response = await this.issueBearerTokenResponse({ scope, relayKey, forceRefresh })
    return response.token
  }

  async issueBearerTokenResponse({ scope = 'gateway:relay-register', relayKey = null, forceRefresh = false } = {}) {
    if (!this.isEnabled()) {
      throw new Error('public-gateway-auth-disabled')
    }
    const authContext = this.getAuthContext() || {}
    const pubkey = normalizePubkey(authContext.pubkey)
    const nsecHex = typeof authContext.nsecHex === 'string' ? authContext.nsecHex.trim() : ''
    if (!pubkey) {
      throw new Error('public-gateway-auth-context-invalid')
    }

    const cacheKey = this.#buildCacheKey(scope, relayKey, pubkey)
    if (!forceRefresh) {
      const cached = this.tokenCache.get(cacheKey)
      if (cached && cached.token && cached.expiresAt > Date.now() + 2_000) {
        return clonePayload(cached.response)
      }
    }
    const secretBytes = hexToBytes(nsecHex)
    if (!secretBytes) {
      throw new Error('public-gateway-auth-context-invalid')
    }

    const challengePayload = await this.#request('/api/auth/challenge', {
      pubkey,
      scope,
      relayKey: relayKey || null
    })
    const challengeId = typeof challengePayload.challengeId === 'string' ? challengePayload.challengeId.trim() : ''
    const nonce = typeof challengePayload.nonce === 'string' ? challengePayload.nonce : ''
    if (!challengeId || !nonce) {
      throw new Error('public-gateway-auth-challenge-invalid')
    }

    const signature = toHex(await schnorr.sign(new TextEncoder().encode(nonce), secretBytes))
    const verifyPayload = await this.#request('/api/auth/verify', {
      challengeId,
      pubkey,
      signature,
      scope,
      relayKey: relayKey || null
    })
    const token = typeof verifyPayload.token === 'string' ? verifyPayload.token.trim() : ''
    if (!token) {
      throw new Error('public-gateway-auth-token-missing')
    }
    const expiresIn = Number.isFinite(Number(verifyPayload.expiresIn))
      ? Math.max(1, Math.trunc(Number(verifyPayload.expiresIn)))
      : 60
    const response = {
      token,
      expiresIn,
      expiresAt: Number.isFinite(Number(verifyPayload.expiresAt))
        ? Math.trunc(Number(verifyPayload.expiresAt))
        : (Date.now() + (expiresIn * 1000)),
      operatorIdentity: verifyPayload.operatorIdentity && typeof verifyPayload.operatorIdentity === 'object'
        ? clonePayload(verifyPayload.operatorIdentity)
        : null
    }
    this.tokenCache.set(cacheKey, {
      token,
      expiresAt: response.expiresAt,
      subjectPubkey: pubkey,
      response
    })
    return clonePayload(response)
  }

  #buildCachePrefix(scope, relayKey) {
    const normalizedScope = typeof scope === 'string' ? scope.trim() : ''
    const normalizedRelay = typeof relayKey === 'string' ? relayKey.trim() : ''
    return `${normalizedScope}::${normalizedRelay || '*'}::`
  }

  #buildCacheKey(scope, relayKey, pubkey = '') {
    return `${this.#buildCachePrefix(scope, relayKey)}${normalizePubkey(pubkey) || '*'}`
  }

  async #request(pathname, payload) {
    if (!this.baseUrl || !this.fetchImpl) {
      throw new Error('public-gateway-auth-disabled')
    }
    const url = `${this.baseUrl}${pathname}`
    const response = await this.fetchImpl(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify(payload || {})
    })
    const data = await parseResponsePayload(response)
    if (!response.ok) {
      const message = typeof data.error === 'string' ? data.error : `HTTP ${response.status}`
      this.logger.warn('Public gateway auth request failed', { pathname, status: response.status, message })
      throw new Error(message)
    }
    return data
  }
}
