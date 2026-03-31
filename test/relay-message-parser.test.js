import test from 'node:test';
import assert from 'node:assert/strict';
import b4a from 'b4a';

import { parseNostrMessagePayload } from '../relay-server.mjs';

test('parseNostrMessagePayload handles string payloads', () => {
  const payload = '["EVENT",{"id":"123"}]';
  const result = parseNostrMessagePayload(payload);
  assert.ok(Array.isArray(result));
  assert.equal(result[0], 'EVENT');
});

test('parseNostrMessagePayload handles buffer payloads', () => {
  const bufferPayload = { type: 'Buffer', data: Array.from(b4a.from('["REQ","sub"]', 'utf8')) };
  const result = parseNostrMessagePayload(bufferPayload);
  assert.ok(Array.isArray(result));
  assert.equal(result[0], 'REQ');
});

test('parseNostrMessagePayload rejects empty payload', () => {
  assert.throws(() => parseNostrMessagePayload('   '), /Empty NOSTR message payload/);
});
