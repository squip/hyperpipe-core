import test from 'brittle'
import { schnorr } from '@noble/curves/secp256k1'

import PublicGatewayAuthClient from '../gateway/PublicGatewayAuthClient.mjs'
import PublicGatewayControlClient from '../gateway/PublicGatewayControlClient.mjs'

function jsonResponse(status, payload) {
  const body = JSON.stringify(payload)
  return {
    ok: status >= 200 && status < 300,
    status,
    async text() {
      return body
    },
    async json() {
      return payload
    }
  }
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) return null
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

test('PublicGatewayAuthClient caches bearer by scope + relayKey + pubkey', async t => {
  const nsecHex = '3'.repeat(64)
  const pubkey = Buffer.from(schnorr.getPublicKey(hexToBytes(nsecHex))).toString('hex')
  const calls = []

  const fetchImpl = async (url, options = {}) => {
    const pathname = new URL(String(url)).pathname
    calls.push({ pathname, method: options?.method || 'GET' })
    if (pathname === '/api/auth/challenge') {
      return jsonResponse(200, {
        challengeId: 'challenge-1',
        nonce: 'nonce-1'
      })
    }
    if (pathname === '/api/auth/verify') {
      return jsonResponse(200, {
        token: 'bearer-token-1',
        expiresIn: 120
      })
    }
    return jsonResponse(404, { error: 'not-found' })
  }

  const client = new PublicGatewayAuthClient({
    baseUrl: 'https://gateway.example',
    fetchImpl,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    getAuthContext: () => ({ pubkey, nsecHex })
  })

  const first = await client.issueBearerToken({ scope: 'gateway:relay-register', relayKey: 'relay:test' })
  const second = await client.issueBearerToken({ scope: 'gateway:relay-register', relayKey: 'relay:test' })

  t.is(first, 'bearer-token-1')
  t.is(second, 'bearer-token-1')
  t.is(calls.length, 2)
  t.alike(calls.map((entry) => entry.pathname), ['/api/auth/challenge', '/api/auth/verify'])
})

test('PublicGatewayAuthClient preserves operator identity in richer auth responses', async t => {
  const nsecHex = '8'.repeat(64)
  const pubkey = Buffer.from(schnorr.getPublicKey(hexToBytes(nsecHex))).toString('hex')
  let verifyCount = 0

  const fetchImpl = async (url) => {
    const pathname = new URL(String(url)).pathname
    if (pathname === '/api/auth/challenge') {
      return jsonResponse(200, {
        challengeId: 'challenge-operator',
        nonce: 'nonce-operator'
      })
    }
    if (pathname === '/api/auth/verify') {
      verifyCount += 1
      return jsonResponse(200, {
        token: 'bearer-token-operator',
        expiresIn: 120,
        expiresAt: Date.now() + 120_000,
        operatorIdentity: {
          pubkey: '1'.repeat(64),
          attestation: {
            version: 1,
            payload: {
              purpose: 'gateway-operator-attestation',
              operatorPubkey: '1'.repeat(64),
              gatewayId: '2'.repeat(64),
              publicUrl: 'https://gateway.example',
              issuedAt: Date.now(),
              expiresAt: Date.now() + 120_000
            },
            signature: '3'.repeat(128)
          }
        }
      })
    }
    return jsonResponse(404, { error: 'not-found' })
  }

  const client = new PublicGatewayAuthClient({
    baseUrl: 'https://gateway.example',
    fetchImpl,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    getAuthContext: () => ({ pubkey, nsecHex })
  })

  const first = await client.issueBearerTokenResponse({ scope: 'gateway:relay-register', relayKey: 'relay:test' })
  const second = await client.issueBearerTokenResponse({ scope: 'gateway:relay-register', relayKey: 'relay:test' })

  t.is(first.token, 'bearer-token-operator')
  t.is(first.operatorIdentity.pubkey, '1'.repeat(64))
  t.is(second.operatorIdentity.attestation.payload.gatewayId, '2'.repeat(64))
  t.is(verifyCount, 1)
})

test('PublicGatewayAuthClient isolates cache by active pubkey', async t => {
  const nsecHexA = '5'.repeat(64)
  const pubkeyA = Buffer.from(schnorr.getPublicKey(hexToBytes(nsecHexA))).toString('hex')
  const nsecHexB = '6'.repeat(64)
  const pubkeyB = Buffer.from(schnorr.getPublicKey(hexToBytes(nsecHexB))).toString('hex')
  let challengeCount = 0
  let verifyCount = 0
  let authContext = { pubkey: pubkeyA, nsecHex: nsecHexA }

  const fetchImpl = async (url, options = {}) => {
    const pathname = new URL(String(url)).pathname
    const payload = JSON.parse(options?.body || '{}')
    if (pathname === '/api/auth/challenge') {
      challengeCount += 1
      return jsonResponse(200, {
        challengeId: `challenge-${challengeCount}`,
        nonce: `nonce-${challengeCount}`
      })
    }
    if (pathname === '/api/auth/verify') {
      verifyCount += 1
      return jsonResponse(200, {
        token: `bearer-${payload.pubkey.slice(0, 8)}-${verifyCount}`,
        expiresIn: 120
      })
    }
    return jsonResponse(404, { error: 'not-found' })
  }

  const client = new PublicGatewayAuthClient({
    baseUrl: 'https://gateway.example',
    fetchImpl,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    getAuthContext: () => authContext
  })

  const firstA = await client.issueBearerToken({ scope: 'gateway:relay-register', relayKey: 'relay:test' })
  authContext = { pubkey: pubkeyB, nsecHex: nsecHexB }
  const firstB = await client.issueBearerToken({ scope: 'gateway:relay-register', relayKey: 'relay:test' })
  authContext = { pubkey: pubkeyA, nsecHex: nsecHexA }
  const secondA = await client.issueBearerToken({ scope: 'gateway:relay-register', relayKey: 'relay:test' })

  t.is(challengeCount, 2)
  t.is(verifyCount, 2)
  t.unlike(firstA, firstB)
  t.is(secondA, firstA)
})

test('PublicGatewayAuthClient isolates cache by scope', async t => {
  const nsecHex = '4'.repeat(64)
  const pubkey = Buffer.from(schnorr.getPublicKey(hexToBytes(nsecHex))).toString('hex')
  let challengeCount = 0
  let verifyCount = 0

  const fetchImpl = async (url) => {
    const pathname = new URL(String(url)).pathname
    if (pathname === '/api/auth/challenge') {
      challengeCount += 1
      return jsonResponse(200, {
        challengeId: `challenge-${challengeCount}`,
        nonce: `nonce-${challengeCount}`
      })
    }
    if (pathname === '/api/auth/verify') {
      verifyCount += 1
      return jsonResponse(200, {
        token: `bearer-${verifyCount}`,
        expiresIn: 120
      })
    }
    return jsonResponse(404, { error: 'not-found' })
  }

  const client = new PublicGatewayAuthClient({
    baseUrl: 'https://gateway.example',
    fetchImpl,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
    getAuthContext: () => ({ pubkey, nsecHex })
  })

  const a = await client.issueBearerToken({ scope: 'gateway:relay-register', relayKey: 'relay:test' })
  const b = await client.issueBearerToken({ scope: 'gateway:open-join-pool', relayKey: 'relay:test' })

  t.is(a, 'bearer-1')
  t.is(b, 'bearer-2')
  t.is(challengeCount, 2)
  t.is(verifyCount, 2)
})

test('PublicGatewayControlClient retries once on 401 with forced refresh', async t => {
  const issued = []
  const invalidated = []
  let requestCount = 0

  const authClient = {
    isEnabled: () => true,
    setBaseUrl: () => {},
    async issueBearerToken({ scope, relayKey = null, forceRefresh = false } = {}) {
      issued.push({ scope, relayKey, forceRefresh })
      return forceRefresh ? 'fresh-token' : 'stale-token'
    },
    invalidateToken({ scope, relayKey = null } = {}) {
      invalidated.push({ scope, relayKey })
    }
  }

  const fetchImpl = async (_url, options = {}) => {
    requestCount += 1
    const authHeader = options?.headers?.authorization || null
    if (requestCount === 1) {
      t.is(authHeader, 'Bearer stale-token')
      return {
        ok: false,
        status: 401,
        async text() {
          return JSON.stringify({ error: 'token-expired' })
        }
      }
    }
    t.is(authHeader, 'Bearer fresh-token')
    return jsonResponse(200, { status: 'ok' })
  }

  const control = new PublicGatewayControlClient({
    baseUrl: 'https://gateway.example',
    authClient,
    fetchImpl,
    logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} }
  })

  const result = await control.registerRelay('relay:test', {
    metadata: { identifier: 'relay:test' }
  })

  t.is(result.success, true)
  t.is(requestCount, 2)
  t.is(invalidated.length, 1)
  t.alike(issued, [
    { scope: 'gateway:relay-register', relayKey: 'relay:test', forceRefresh: false },
    { scope: 'gateway:relay-register', relayKey: 'relay:test', forceRefresh: true }
  ])
})
