import test from 'brittle'
import b4a from 'b4a'

import { parseNostrMessagePayload } from '../relay-message-parser.mjs'

test('parseNostrMessagePayload handles string payloads', (t) => {
  const payload = '["EVENT",{"id":"123"}]'
  const result = parseNostrMessagePayload(payload)
  t.ok(Array.isArray(result))
  t.is(result[0], 'EVENT')
})

test('parseNostrMessagePayload handles buffer payloads', (t) => {
  const bufferPayload = { type: 'Buffer', data: Array.from(b4a.from('["REQ","sub"]', 'utf8')) }
  const result = parseNostrMessagePayload(bufferPayload)
  t.ok(Array.isArray(result))
  t.is(result[0], 'REQ')
})

test('parseNostrMessagePayload rejects empty payload', (t) => {
  t.exception(() => parseNostrMessagePayload('   '), /Empty NOSTR message payload/)
})
