import { createHash, randomUUID } from 'node:crypto'
import { schnorr } from '@noble/curves/secp256k1.js'

function normalizeHex64(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim().toLowerCase()
  return /^[a-f0-9]{64}$/.test(trimmed) ? trimmed : null
}

function normalizeString(value) {
  if (typeof value !== 'string') return null
  const trimmed = value.trim()
  return trimmed.length ? trimmed : null
}

function sha256Hex(input) {
  return createHash('sha256').update(String(input || ''), 'utf8').digest('hex')
}

function hexToBytes(value) {
  return Buffer.from(String(value || ''), 'hex')
}

function canonicalizeEnvelopePayload(input = {}) {
  const leaseId = normalizeString(input.leaseId) || randomUUID()
  const relayKey = normalizeHex64(input.relayKey)
  const publicIdentifier = normalizeString(input.publicIdentifier) || relayKey
  const inviteePubkey = normalizeHex64(input.inviteePubkey)
  const tokenHash = normalizeString(input.tokenHash)?.toLowerCase() || null
  const writerCore = normalizeString(input.writerCore)
  const writerCoreHex = normalizeString(input.writerCoreHex)
  const autobaseLocal = normalizeString(input.autobaseLocal)
  const writerSecret = normalizeString(input.writerSecret)
  const issuedAt = Number.isFinite(Number(input.issuedAt)) ? Number(input.issuedAt) : Date.now()
  const expiresAt = Number.isFinite(Number(input.expiresAt))
    ? Number(input.expiresAt)
    : issuedAt + (3 * 24 * 60 * 60 * 1000)
  const issuerPubkey = normalizeHex64(input.issuerPubkey)
  const issuerSwarmPeerKey = normalizeHex64(input.issuerSwarmPeerKey || input.issuerPeerKey)
  const coreRefs = Array.isArray(input.coreRefs)
    ? input.coreRefs.map((entry) => normalizeString(entry)).filter(Boolean)
    : []
  const fastForward = input.fastForward && typeof input.fastForward === 'object'
    ? { ...input.fastForward }
    : null

  if (!relayKey || !publicIdentifier || !inviteePubkey) return null
  if (!tokenHash || !writerCore || !writerSecret) return null
  if (!issuerPubkey) return null
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || expiresAt <= issuedAt) return null

  return {
    version: 1,
    leaseId,
    relayKey,
    publicIdentifier,
    inviteePubkey,
    tokenHash,
    writerCore,
    writerCoreHex: writerCoreHex || null,
    autobaseLocal: autobaseLocal || null,
    writerSecret,
    coreRefs,
    fastForward,
    issuedAt,
    expiresAt,
    issuerPubkey,
    issuerSwarmPeerKey: issuerSwarmPeerKey || null
  }
}

function serializePayload(payload) {
  return JSON.stringify({
    version: payload.version,
    leaseId: payload.leaseId,
    relayKey: payload.relayKey,
    publicIdentifier: payload.publicIdentifier,
    inviteePubkey: payload.inviteePubkey,
    tokenHash: payload.tokenHash,
    writerCore: payload.writerCore,
    writerCoreHex: payload.writerCoreHex || null,
    autobaseLocal: payload.autobaseLocal || null,
    writerSecret: payload.writerSecret,
    coreRefs: Array.isArray(payload.coreRefs) ? payload.coreRefs : [],
    fastForward: payload.fastForward || null,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    issuerPubkey: payload.issuerPubkey,
    issuerSwarmPeerKey: payload.issuerSwarmPeerKey || null
  })
}

function buildVerifyResult(ok, reason, envelope = null) {
  return {
    ok,
    reason,
    envelope: ok ? envelope : null
  }
}

export function computeWriterLeaseTokenHash(inviteToken) {
  const token = normalizeString(inviteToken)
  if (!token) return null
  return sha256Hex(token)
}

export function createWriterLeaseEnvelope(input = {}) {
  const issuerPrivkey = normalizeHex64(input.issuerPrivkey || input.issuerPrivateKey)
  if (!issuerPrivkey) {
    throw new Error('invalid-issuer-private-key')
  }
  const issuerPubkey = normalizeHex64(input.issuerPubkey)
  if (!issuerPubkey) {
    throw new Error('invalid-issuer-pubkey')
  }
  const tokenHash = computeWriterLeaseTokenHash(input.inviteToken)
  const payload = canonicalizeEnvelopePayload({
    ...input,
    issuerPubkey,
    tokenHash
  })
  if (!payload) {
    throw new Error('invalid-writer-lease-envelope')
  }

  const digest = sha256Hex(serializePayload(payload))
  const digestBytes = hexToBytes(digest)
  const issuerPrivkeyBytes = hexToBytes(issuerPrivkey)
  const signature = Buffer.from(schnorr.sign(digestBytes, issuerPrivkeyBytes)).toString('hex')
  return {
    ...payload,
    signature
  }
}

export function verifyWriterLeaseEnvelope(envelope, context = {}) {
  const payload = canonicalizeEnvelopePayload(envelope || {})
  if (!payload) return buildVerifyResult(false, 'invalid-envelope')

  const signature = normalizeString(envelope?.signature)
  if (!signature) return buildVerifyResult(false, 'missing-signature')

  const expectedIssuer = normalizeHex64(context.writerIssuerPubkey)
  if (expectedIssuer && payload.issuerPubkey !== expectedIssuer) {
    return buildVerifyResult(false, 'issuer-mismatch')
  }

  const expectedRelayKey = normalizeHex64(context.expectedRelayKey)
  if (expectedRelayKey && payload.relayKey !== expectedRelayKey) {
    return buildVerifyResult(false, 'relay-mismatch')
  }

  const expectedInvitee = normalizeHex64(context.inviteePubkey)
  if (expectedInvitee && payload.inviteePubkey !== expectedInvitee) {
    return buildVerifyResult(false, 'invitee-mismatch')
  }

  const expectedTokenHash = normalizeString(context.tokenHash)?.toLowerCase() || null
  if (expectedTokenHash && payload.tokenHash !== expectedTokenHash) {
    return buildVerifyResult(false, 'token-mismatch')
  }

  const nowMs = Number.isFinite(Number(context.nowMs)) ? Number(context.nowMs) : Date.now()
  if (payload.expiresAt <= nowMs) {
    return buildVerifyResult(false, 'expired')
  }

  const digest = sha256Hex(serializePayload(payload))
  const digestBytes = hexToBytes(digest)
  const signatureBytes = hexToBytes(signature)
  const issuerPubkeyBytes = hexToBytes(payload.issuerPubkey)
  const verified = schnorr.verify(signatureBytes, digestBytes, issuerPubkeyBytes)
  if (!verified) {
    return buildVerifyResult(false, 'signature-invalid')
  }

  return buildVerifyResult(true, 'ok', payload)
}

export function writerLeaseEnvelopeToPoolEntry(envelope, source = 'unknown') {
  const payload = canonicalizeEnvelopePayload(envelope || {})
  if (!payload) return null

  return {
    leaseId: payload.leaseId,
    relayKey: payload.relayKey,
    publicIdentifier: payload.publicIdentifier,
    inviteePubkey: payload.inviteePubkey,
    tokenHash: payload.tokenHash,
    writerCore: payload.writerCore,
    writerCoreHex: payload.writerCoreHex || null,
    autobaseLocal: payload.autobaseLocal || null,
    writerSecret: payload.writerSecret,
    issuerPubkey: payload.issuerPubkey,
    issuerSwarmPeerKey: payload.issuerSwarmPeerKey || null,
    issuedAt: payload.issuedAt,
    expiresAt: payload.expiresAt,
    source: normalizeString(source) || 'unknown',
    envelope: {
      ...payload,
      signature: normalizeString(envelope?.signature) || null
    }
  }
}
