import test from 'brittle'
import { schnorr } from '@noble/curves/secp256k1'
import {
  computeWriterLeaseTokenHash,
  createWriterLeaseEnvelope,
  verifyWriterLeaseEnvelope,
  writerLeaseEnvelopeToPoolEntry
} from '../writer-lease-envelope.mjs'

const relayKey = 'a'.repeat(64)
const inviteePubkey = 'b'.repeat(64)
const issuerPrivkey = '1'.repeat(64)
const issuerPubkey = Buffer.from(schnorr.getPublicKey(Buffer.from(issuerPrivkey, 'hex'))).toString('hex')

test('writer lease envelope roundtrip verifies with expected context', (t) => {
  const inviteToken = 'invite-token-123'
  const envelope = createWriterLeaseEnvelope({
    relayKey,
    publicIdentifier: 'npub1example:group',
    inviteePubkey,
    inviteToken,
    writerCore: 'writer-core-ref',
    writerCoreHex: 'c'.repeat(64),
    writerSecret: 'd'.repeat(64),
    issuerPubkey,
    issuerPrivkey,
    issuerPeerKey: 'e'.repeat(64)
  })

  const verified = verifyWriterLeaseEnvelope(envelope, {
    writerIssuerPubkey: issuerPubkey,
    expectedRelayKey: relayKey,
    inviteePubkey,
    tokenHash: computeWriterLeaseTokenHash(inviteToken)
  })

  t.is(verified.ok, true)
  t.is(verified.reason, 'ok')
  t.ok(verified.envelope?.leaseId, 'lease id present')
})

test('writer lease verification rejects token mismatch', (t) => {
  const envelope = createWriterLeaseEnvelope({
    relayKey,
    inviteePubkey,
    inviteToken: 'invite-token-abc',
    writerCore: 'writer-core-ref',
    writerCoreHex: 'c'.repeat(64),
    writerSecret: 'd'.repeat(64),
    issuerPubkey,
    issuerPrivkey
  })

  const verified = verifyWriterLeaseEnvelope(envelope, {
    writerIssuerPubkey: issuerPubkey,
    expectedRelayKey: relayKey,
    inviteePubkey,
    tokenHash: computeWriterLeaseTokenHash('different-token')
  })

  t.is(verified.ok, false)
  t.is(verified.reason, 'token-mismatch')
})

test('writer lease verification rejects expired envelope', (t) => {
  const issuedAt = Date.now() - 60_000
  const envelope = createWriterLeaseEnvelope({
    relayKey,
    inviteePubkey,
    inviteToken: 'invite-token-expired',
    writerCore: 'writer-core-ref',
    writerCoreHex: 'c'.repeat(64),
    writerSecret: 'd'.repeat(64),
    issuedAt,
    expiresAt: issuedAt + 1_000,
    issuerPubkey,
    issuerPrivkey
  })

  const verified = verifyWriterLeaseEnvelope(envelope, {
    writerIssuerPubkey: issuerPubkey,
    expectedRelayKey: relayKey,
    inviteePubkey,
    tokenHash: computeWriterLeaseTokenHash('invite-token-expired'),
    nowMs: Date.now()
  })

  t.is(verified.ok, false)
  t.is(verified.reason, 'expired')
})

test('writer lease envelope converts to writer pool entry', (t) => {
  const envelope = createWriterLeaseEnvelope({
    relayKey,
    inviteePubkey,
    inviteToken: 'invite-token-pool',
    writerCore: 'writer-core-ref',
    writerCoreHex: 'c'.repeat(64),
    writerSecret: 'd'.repeat(64),
    issuerPubkey,
    issuerPrivkey
  })
  const poolEntry = writerLeaseEnvelopeToPoolEntry(envelope, 'test')

  t.ok(poolEntry, 'pool entry created')
  t.is(poolEntry.leaseId, envelope.leaseId)
  t.is(poolEntry.tokenHash, envelope.tokenHash)
  t.is(poolEntry.writerSecret, envelope.writerSecret)
  t.is(poolEntry.source, 'test')
})
