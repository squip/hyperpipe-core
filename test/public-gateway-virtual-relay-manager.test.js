import test from 'brittle';
import PublicGatewayVirtualRelayManager from '../gateway/PublicGatewayVirtualRelayManager.mjs';
import {
  registerVirtualRelay,
  unregisterVirtualRelay,
  activeRelays,
  publicToKey
} from '../hyperpipe-relay-manager-adapter.mjs';

const RELAY_KEY = 'public-gateway:hyperbee';

function createAdapter(events = []) {
  return {
    hasReplica: () => true,
    async query() {
      return { events };
    },
    async getReplicaStats() {
      return {
        length: events.length,
        downloaded: events.length,
        lag: 0
      };
    }
  };
}

test('virtual relay manager serves subscriptions from Hyperbee adapter', async (t) => {
  const event = { id: 'evt-1', created_at: 1700000000, kind: 1, content: 'hello' };
  const adapter = createAdapter([event]);
  const manager = new PublicGatewayVirtualRelayManager({
    identifier: RELAY_KEY,
    hyperbeeAdapter: adapter
  });

  const responses = [];
  await manager.handleMessage(['REQ', 'sub-1', { kinds: [1] }], (frame) => responses.push(frame), 'conn-1');
  t.is(responses.length, 2);
  t.is(responses[0][0], 'NOTICE');
  t.alike(responses[1], ['ACK', 'sub-1', 'registered']);

  const [frames, update] = await manager.handleSubscription('conn-1');
  t.is(frames.length, 2);
  t.alike(frames[0], ['EVENT', 'sub-1', event]);
  t.alike(frames[1], ['EOSE', 'sub-1']);
  t.ok(update);
  t.is(update.subscriptions['sub-1'].last_returned_event_timestamp, event.created_at);

  const [secondFrames, secondUpdate] = await manager.handleSubscription('conn-1');
  t.alike(secondFrames, [['EOSE', 'sub-1']]);
  t.ok(secondUpdate);
  t.is(secondUpdate.subscriptions['sub-1'].last_returned_event_timestamp, event.created_at);

  await manager.close();
});

test('virtual relay manager rejects EVENT writes and unregisters cleanly', async (t) => {
  await unregisterVirtualRelay(RELAY_KEY).catch(() => {});

  const adapter = createAdapter();
  const manager = new PublicGatewayVirtualRelayManager({
    identifier: RELAY_KEY,
    hyperbeeAdapter: adapter
  });

  registerVirtualRelay(RELAY_KEY, manager, { publicIdentifier: RELAY_KEY });
  t.ok(activeRelays.has(RELAY_KEY));
  t.is(publicToKey.get(RELAY_KEY), RELAY_KEY);

  const responses = [];
  await manager.handleMessage(['EVENT', { id: 'evt-write' }], (frame) => responses.push(frame), 'conn-2');
  t.is(responses.length, 1);
  t.is(responses[0][0], 'OK');
  t.is(responses[0][2], false);

  await unregisterVirtualRelay(RELAY_KEY, { publicIdentifier: RELAY_KEY });
  t.is(activeRelays.has(RELAY_KEY), false);
  t.is(publicToKey.has(RELAY_KEY), false);
});

test('virtual relay manager retains lastReturnedAt across re-subscriptions', async (t) => {
  const event = { id: 'evt-2', created_at: 1700000100, kind: 1, content: 'world' };
  const adapter = createAdapter([event]);
  const manager = new PublicGatewayVirtualRelayManager({
    identifier: RELAY_KEY,
    hyperbeeAdapter: adapter
  });

  await manager.handleMessage(['REQ', 'sub-2', { kinds: [1] }], () => {}, 'conn-2');
  const [frames] = await manager.handleSubscription('conn-2');
  t.is(frames.length, 2);

  // Send the REQ again to simulate client reconnect / filter refresh.
  await manager.handleMessage(['REQ', 'sub-2', { kinds: [1] }], () => {}, 'conn-2');
  const [framesRepeat, updateRepeat] = await manager.handleSubscription('conn-2');
  t.alike(framesRepeat, [['EOSE', 'sub-2']]);
  t.is(updateRepeat.subscriptions['sub-2'].last_returned_event_timestamp, event.created_at);

  await manager.close();
});
