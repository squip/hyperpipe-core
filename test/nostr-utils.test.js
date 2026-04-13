import test from 'brittle'
import { NostrUtils } from '../nostr-utils.js'

test('NostrUtils signs and verifies events from hex string inputs', async (t) => {
  const privateKey = '1'.repeat(64)
  const pubkey = NostrUtils.getPublicKey(privateKey)

  t.is(typeof pubkey, 'string')
  t.is(pubkey.length, 64)

  const event = await NostrUtils.signEvent({
    kind: 1,
    content: 'hello',
    created_at: 1,
    tags: [],
    pubkey
  }, privateKey)

  t.is(typeof event.id, 'string')
  t.is(event.id.length, 64)
  t.is(typeof event.sig, 'string')
  t.is(event.sig.length, 128)

  const verified = await NostrUtils.verifySignature(event)
  t.ok(verified)
})
