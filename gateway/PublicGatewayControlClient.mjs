function normalizeBaseUrl(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.replace(/\/+$/, '')
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

function createTraceId(prefix = 'pg-ctl') {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(16).slice(2, 8)}`
}

function previewValue(value, length = 24) {
  if (typeof value !== 'string') return value ?? null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.length > length ? trimmed.slice(0, length) : trimmed
}

function summarizeBody(body) {
  if (!body || typeof body !== 'object') return null
  const registration = body.registration && typeof body.registration === 'object'
    ? body.registration
    : null
  const payload = body.payload && typeof body.payload === 'object'
    ? body.payload
    : null
  return {
    keys: Object.keys(body),
    relayKey: previewValue(
      registration?.relayKey
      || payload?.relayKey
      || body?.relayKey
      || null
    ),
    relayCount: Array.isArray(registration?.relays) ? registration.relays.length : null,
    peerCount: Array.isArray(registration?.peers) ? registration.peers.length : null,
    hasBlindPeeringPublicKey: Boolean(
      registration?.blindPeeringPublicKey
      || registration?.blind_peering_public_key
      || registration?.metadata?.blindPeeringPublicKey
      || registration?.metadata?.blind_peering_public_key
    ),
    entryCount: Array.isArray(payload?.entries) ? payload.entries.length : null
  }
}

export default class PublicGatewayControlClient {
  constructor({
    baseUrl = null,
    authClient = null,
    fetchImpl = globalThis.fetch,
    logger = null
  } = {}) {
    this.baseUrl = normalizeBaseUrl(baseUrl)
    this.authClient = authClient || null
    this.fetchImpl = typeof fetchImpl === 'function' ? fetchImpl : globalThis.fetch
    this.logger = safeLogger(logger)
  }

  isEnabled() {
    return Boolean(this.baseUrl && this.fetchImpl)
  }

  setBaseUrl(baseUrl) {
    const next = normalizeBaseUrl(baseUrl)
    if (next === this.baseUrl) return
    this.baseUrl = next
    if (this.authClient && typeof this.authClient.setBaseUrl === 'function') {
      this.authClient.setBaseUrl(next)
    }
  }

  async registerRelay(relayKey, payload = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth('/api/relays', {
      method: 'POST',
      body: {
        registration: {
          relayKey: relayIdentifier || null,
          ...(payload && typeof payload === 'object' ? payload : {})
        }
      },
      scope: 'gateway:relay-register',
      relayKey: relayIdentifier || null
    })

    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async unregisterRelay(relayKey) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth(`/api/relays/${encodeURIComponent(relayIdentifier)}`, {
      method: 'DELETE',
      scope: 'gateway:relay-unregister',
      relayKey: relayIdentifier || null
    })

    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async updateOpenJoinPool(relayKey, entries = [], options = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth(`/api/relays/${encodeURIComponent(relayIdentifier)}/open-join/pool`, {
      method: 'POST',
      body: {
        payload: {
          relayKey: relayIdentifier || null,
          entries: Array.isArray(entries) ? entries : [],
          ...(options && typeof options === 'object' ? options : {})
        }
      },
      scope: 'relay:open-join-pool-update',
      relayKey: relayIdentifier || null
    })

    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async authorizeRelayMember(relayKey, payload = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth(`/api/relays/${encodeURIComponent(relayIdentifier)}/members/authorize`, {
      method: 'POST',
      body: payload || {},
      scope: 'relay:member-authorize',
      relayKey: relayIdentifier || null
    })
    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async revokeRelayMember(relayKey, payload = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth(`/api/relays/${encodeURIComponent(relayIdentifier)}/members/revoke`, {
      method: 'POST',
      body: payload || {},
      scope: 'relay:member-revoke',
      relayKey: relayIdentifier || null
    })
    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async issueGatewayToken(relayKey, payload = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth('/api/relay-tokens/issue', {
      method: 'POST',
      body: {
        relayKey: relayIdentifier || null,
        ...(payload && typeof payload === 'object' ? payload : {})
      },
      scope: 'gateway:relay-register',
      relayKey: relayIdentifier || null
    })
    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async refreshGatewayToken(relayKey, payload = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth('/api/relay-tokens/refresh', {
      method: 'POST',
      body: {
        relayKey: relayIdentifier || null,
        ...(payload && typeof payload === 'object' ? payload : {})
      },
      scope: 'gateway:relay-register',
      relayKey: relayIdentifier || null
    })
    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async revokeGatewayToken(relayKey, payload = {}) {
    const relayIdentifier = typeof relayKey === 'string' ? relayKey.trim() : ''
    const response = await this.#requestWithAuth('/api/relay-tokens/revoke', {
      method: 'POST',
      body: {
        relayKey: relayIdentifier || null,
        ...(payload && typeof payload === 'object' ? payload : {})
      },
      scope: 'gateway:relay-unregister',
      relayKey: relayIdentifier || null
    })
    return {
      success: response.ok,
      statusCode: response.status,
      ...(response.payload && typeof response.payload === 'object' ? response.payload : {})
    }
  }

  async #requestWithAuth(pathname, { method = 'GET', body = null, scope = null, relayKey = null } = {}) {
    if (!this.baseUrl || !this.fetchImpl) {
      throw new Error('public-gateway-control-disabled')
    }
    const traceId = createTraceId()

    const isAuthEnabled = Boolean(
      this.authClient
      && typeof this.authClient.isEnabled === 'function'
      && this.authClient.isEnabled()
    )
    this.logger.info('Public gateway control request start', {
      traceId,
      baseUrl: this.baseUrl,
      pathname,
      method,
      scope: scope || null,
      relayKey: relayKey || null,
      isAuthEnabled,
      body: summarizeBody(body)
    })

    const sendRequest = async (forceRefresh = false) => {
      const headers = {
        'content-type': 'application/json',
        'x-hyperpipe-client-trace-id': traceId
      }
      if (isAuthEnabled && typeof this.authClient.issueBearerToken === 'function') {
        const token = await this.authClient.issueBearerToken({
          scope,
          relayKey,
          forceRefresh
        })
        if (typeof token === 'string' && token.trim()) {
          headers.authorization = `Bearer ${token.trim()}`
          this.logger.info('Public gateway control auth token attached', {
            traceId,
            pathname,
            scope: scope || null,
            relayKey: relayKey || null,
            forceRefresh,
            token: previewValue(token)
          })
        }
      }

      const response = await this.fetchImpl(`${this.baseUrl}${pathname}`, {
        method,
        headers,
        body: body == null ? undefined : JSON.stringify(body)
      })
      const payload = await parseResponsePayload(response)
      this.logger.info('Public gateway control request response', {
        traceId,
        baseUrl: this.baseUrl,
        pathname,
        method,
        scope: scope || null,
        relayKey: relayKey || null,
        forceRefresh,
        status: response.status,
        ok: response.ok,
        payloadKeys: payload && typeof payload === 'object' ? Object.keys(payload) : [],
        error: typeof payload?.error === 'string' ? payload.error : null,
        success: payload?.success === true,
        statusField: payload?.status || null,
        hasBlindPeer: !!payload?.blindPeer,
        hasHyperbee: !!payload?.hyperbee
      })
      return {
        ok: response.ok,
        status: response.status,
        payload
      }
    }

    let result = await sendRequest(false)
    if (result.status === 401 && isAuthEnabled) {
      this.logger.warn('Public gateway control request retrying after 401', {
        traceId,
        pathname,
        scope: scope || null,
        relayKey: relayKey || null
      })
      if (typeof this.authClient.invalidateToken === 'function') {
        this.authClient.invalidateToken({ scope, relayKey })
      }
      result = await sendRequest(true)
    }
    if (!result.ok) {
      this.logger.warn('Public gateway control request failed', {
        traceId,
        pathname,
        status: result.status,
        relayKey,
        scope: scope || null,
        error: typeof result?.payload?.error === 'string' ? result.payload.error : null
      })
    }
    return result
  }
}
