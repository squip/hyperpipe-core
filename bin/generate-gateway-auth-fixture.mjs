#!/usr/bin/env node

import { createHash, randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import {
  finalizeEvent,
  getPublicKey,
  nip19,
  SimplePool,
  utils
} from 'nostr-tools';
import WebSocket from 'ws';

const DEFAULT_RELAYS = [
  'wss://relay.damus.io/',
  'wss://relay.primal.net/',
  'wss://nos.lol/'
];

const DEFAULT_OUTPUT = './test-logs/gateway-auth-fixture/manifest.json';
const DEFAULT_PROFILE_PREFIX = 'ht-gateway-fixture';
const DEFAULT_DEPTH2_MIN_FOLLOWERS = 2;
const DEFAULT_VERIFY_TIMEOUT_MS = 15_000;
const KIND_METADATA = 0;
const KIND_CONTACT_LIST = 3;

if (typeof globalThis.WebSocket === 'undefined') {
  globalThis.WebSocket = WebSocket;
}

function usage() {
  return [
    'Usage:',
    '  node ./bin/generate-gateway-auth-fixture.mjs [options]',
    '',
    'Options:',
    '  --seed <value>                    Stable seed for deterministic account generation.',
    '  --relays <csv>                   Comma-separated target relay URLs.',
    '  --out <path>                     Output manifest path.',
    '  --profile-prefix <value>         Prefix used in kind 0 profile names.',
    '  --depth2-min-followers <number>  Follower threshold used for the depth-2 pass/fail pair.',
    '  --publish <true|false>           Publish kind 0 / kind 3 events. Default: true.',
    '  --verify <true|false>            Read the events back and validate the final graph. Default: true when publish=true.',
    '  --verify-timeout-ms <number>     Max time to wait for verification readback.',
    '  --help                           Show this message.',
    '',
    'Notes:',
    '  - For the full depth-2 pass/fail matrix, use a threshold of 2 or higher.',
    '  - The generated allowlist recommendations include the operator for pure allowlist tests.',
    '  - Scenario "not in allowlist, but is in wot" is covered by the depth-1 and depth-2-pass accounts.'
  ].join('\n');
}

function parseBoolean(value, fallback) {
  if (value === undefined) return fallback;
  if (typeof value === 'boolean') return value;
  const normalized = String(value).trim().toLowerCase();
  if (['1', 'true', 'yes', 'y', 'on'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'n', 'off'].includes(normalized)) return false;
  return fallback;
}

function normalizeRelayUrl(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const url = new URL(trimmed);
    if (url.protocol !== 'ws:' && url.protocol !== 'wss:') return null;
    url.hash = '';
    if (url.pathname.length > 1 && url.pathname.endsWith('/')) {
      url.pathname = url.pathname.slice(0, -1);
    }
    return url.toString();
  } catch (_) {
    return null;
  }
}

function parseRelayList(value) {
  const items = typeof value === 'string' && value.trim()
    ? value.split(',')
    : DEFAULT_RELAYS;
  return Array.from(new Set(items.map((entry) => normalizeRelayUrl(entry)).filter(Boolean)));
}

function parsePositiveInteger(value, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(0, Math.trunc(numeric));
}

function deriveSecretHex(masterSeed, role) {
  return createHash('sha256')
    .update(`hyperpipe-gateway-auth-fixture:v1:${masterSeed}:${role}`)
    .digest('hex');
}

function buildAccount(role, label, masterSeed) {
  const secretHex = deriveSecretHex(masterSeed, role);
  const secretBytes = utils.hexToBytes(secretHex);
  const pubkeyHex = getPublicKey(secretBytes).toLowerCase();
  return {
    role,
    label,
    secretHex,
    pubkeyHex,
    npub: nip19.npubEncode(pubkeyHex),
    nsec: nip19.nsecEncode(secretBytes),
    follows: [],
    scenarios: []
  };
}

function buildFixtureGraph(masterSeed, depth2MinFollowers) {
  if (depth2MinFollowers < 2) {
    throw new Error('depth2-min-followers must be 2 or higher for the full pass/fail validation matrix');
  }

  const accounts = [];
  const push = (role, label, scenarios = []) => {
    const account = buildAccount(role, label, masterSeed);
    account.scenarios = [...scenarios];
    accounts.push(account);
    return account;
  };

  const operator = push('operator', 'Gateway Operator', ['gateway-operator']);
  const allowlistOnly = push(
    'allowlist_only',
    'Allowlist Only',
    ['allowlist-only', 'in-allowlist']
  );
  const wotDepth1 = push(
    'wot_depth1',
    'WoT Depth 1',
    ['wot-depth-1', 'in-wot', 'not-in-allowlist-but-in-wot']
  );

  const anchors = [];
  for (let index = 0; index < depth2MinFollowers; index += 1) {
    anchors.push(
      push(
        `wot_anchor_${index + 1}`,
        `WoT Anchor ${index + 1}`,
        ['helper', 'wot-depth-1-anchor']
      )
    );
  }

  const wotDepth2Pass = push(
    'wot_depth2_pass',
    `WoT Depth 2 Pass (>= ${depth2MinFollowers} follows)`,
    ['wot-depth-2', 'wot-depth-2-pass', 'in-wot', 'not-in-allowlist-but-in-wot']
  );
  const wotDepth2Fail = push(
    'wot_depth2_fail',
    `WoT Depth 2 Fail (< ${depth2MinFollowers} follows)`,
    ['wot-depth-2', 'wot-depth-2-fail']
  );
  const wotDepth3 = push(
    'wot_depth3',
    'WoT Depth 3',
    ['wot-depth-3']
  );
  const outsider = push(
    'outsider',
    'Outside Allowlist And WoT',
    ['not-in-allowlist-or-wot']
  );

  operator.follows = [wotDepth1.role, ...anchors.map((anchor) => anchor.role)];
  for (let index = 0; index < anchors.length; index += 1) {
    anchors[index].follows = [wotDepth2Pass.role];
    if (index < (depth2MinFollowers - 1)) {
      anchors[index].follows.push(wotDepth2Fail.role);
    }
  }
  wotDepth2Pass.follows = [wotDepth3.role];

  return {
    operator,
    allowlistOnly,
    wotDepth1,
    anchors,
    wotDepth2Pass,
    wotDepth2Fail,
    wotDepth3,
    outsider,
    accounts
  };
}

function buildPolicyMatrix(roles, depth2MinFollowers) {
  const allow = 'ALLOW';
  const deny = 'DENY';
  const note = (value, reason) => ({ result: value, reason });

  const rows = {};
  rows.operator = {
    open: note(allow, 'Open policy approves everyone'),
    allowlist: note(allow, 'Allowlisted for pure allowlist validation'),
    wotDepth1: note(allow, 'Operator pubkey is auto-approved by WoT evaluator'),
    wotDepth2Threshold: note(allow, 'Operator pubkey is auto-approved by WoT evaluator'),
    allowlistPlusWot: note(allow, 'Approved via WoT operator shortcut')
  };
  rows.allowlist_only = {
    open: note(allow, 'Open policy approves everyone'),
    allowlist: note(allow, 'Explicit allowlist account'),
    wotDepth1: note(deny, 'Not in WoT graph'),
    wotDepth2Threshold: note(deny, 'Not in WoT graph'),
    allowlistPlusWot: note(allow, 'Approved through allowlist branch')
  };
  rows.wot_depth1 = {
    open: note(allow, 'Open policy approves everyone'),
    allowlist: note(deny, 'Not allowlisted'),
    wotDepth1: note(allow, 'Direct follow from operator'),
    wotDepth2Threshold: note(allow, 'Depth 1 is always inside maxDepth=2'),
    allowlistPlusWot: note(allow, 'Approved via WoT branch')
  };
  rows.wot_depth2_pass = {
    open: note(allow, 'Open policy approves everyone'),
    allowlist: note(deny, 'Not allowlisted'),
    wotDepth1: note(deny, 'Depth 2 exceeds maxDepth=1'),
    wotDepth2Threshold: note(allow, `Depth 2 with ${depth2MinFollowers} in-graph followers`),
    allowlistPlusWot: note(allow, 'Approved via WoT branch')
  };
  rows.wot_depth2_fail = {
    open: note(allow, 'Open policy approves everyone'),
    allowlist: note(deny, 'Not allowlisted'),
    wotDepth1: note(deny, 'Depth 2 exceeds maxDepth=1'),
    wotDepth2Threshold: note(deny, `Depth 2 with ${Math.max(0, depth2MinFollowers - 1)} in-graph followers`),
    allowlistPlusWot: note(deny, 'Not allowlisted and fails WoT follower threshold')
  };
  rows.wot_depth3 = {
    open: note(allow, 'Open policy approves everyone'),
    allowlist: note(deny, 'Not allowlisted'),
    wotDepth1: note(deny, 'Depth 3 exceeds maxDepth=1'),
    wotDepth2Threshold: note(deny, 'Depth 3 exceeds maxDepth=2'),
    allowlistPlusWot: note(deny, 'Not allowlisted and outside WoT depth')
  };
  rows.outsider = {
    open: note(allow, 'Open policy approves everyone'),
    allowlist: note(deny, 'Not allowlisted'),
    wotDepth1: note(deny, 'Not in WoT graph'),
    wotDepth2Threshold: note(deny, 'Not in WoT graph'),
    allowlistPlusWot: note(deny, 'Neither allowlisted nor in WoT')
  };

  for (const role of roles) {
    if (rows[role]) continue;
    rows[role] = {
      open: note(allow, 'Open policy approves everyone'),
      allowlist: note(deny, 'Helper account is not meant for allowlist validation'),
      wotDepth1: note(allow, 'Direct follow from operator'),
      wotDepth2Threshold: note(allow, 'Direct follow from operator'),
      allowlistPlusWot: note(allow, 'Approved via WoT branch')
    };
  }

  return rows;
}

function buildMetadataEvent(account, profilePrefix) {
  const content = JSON.stringify({
    name: `${profilePrefix}-${account.role}`,
    display_name: account.label,
    about: `Hyperpipe gateway auth fixture account: ${account.role}`,
    website: 'https://hypertuna.com'
  });

  return finalizeEvent({
    kind: KIND_METADATA,
    created_at: Math.floor(Date.now() / 1000),
    tags: [],
    content
  }, utils.hexToBytes(account.secretHex));
}

function buildContactListEvent(account, accountMap) {
  const tags = account.follows
    .map((role) => accountMap.get(role))
    .filter(Boolean)
    .map((target) => ['p', target.pubkeyHex]);

  return finalizeEvent({
    kind: KIND_CONTACT_LIST,
    created_at: Math.floor(Date.now() / 1000),
    tags,
    content: ''
  }, utils.hexToBytes(account.secretHex));
}

async function publishEvent(pool, relays, event) {
  const writes = pool.publish(relays, event, { maxWait: 10_000 });
  const results = await Promise.allSettled(writes);
  const ok = results.some((entry) => entry.status === 'fulfilled');
  const outcome = results.map((entry, index) => {
    if (entry.status === 'fulfilled') {
      return { relay: relays[index], ok: true, error: null };
    }
    return {
      relay: relays[index],
      ok: false,
      error: entry.reason instanceof Error ? entry.reason.message : String(entry.reason)
    };
  });
  if (!ok) {
    const errors = outcome.filter((entry) => !entry.ok).map((entry) => `${entry.relay}: ${entry.error}`);
    throw new Error(`failed to publish event ${event.kind}:${event.id} to all relays: ${errors.join('; ')}`);
  }
  return outcome;
}

function formatAllowlistEnv(pubkeys) {
  return pubkeys.join(',');
}

function sortStrings(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function selectPreferredEvent(existing, next) {
  if (!existing) return next;
  const existingCreated = Number(existing.created_at) || 0;
  const nextCreated = Number(next.created_at) || 0;
  if (nextCreated > existingCreated) return next;
  if (nextCreated < existingCreated) return existing;
  return String(next.id || '').localeCompare(String(existing.id || '')) > 0 ? next : existing;
}

function buildExpectedGraphSnapshot(accounts, accountMap, depth2MinFollowers) {
  const expected = {
    followsByRole: {},
    depthByRole: {},
    reachableFollowerCountByRole: {
      wot_depth2_pass: depth2MinFollowers,
      wot_depth2_fail: Math.max(0, depth2MinFollowers - 1)
    }
  };

  for (const account of accounts) {
    expected.followsByRole[account.role] = sortStrings(
      account.follows
        .map((role) => accountMap.get(role)?.pubkeyHex || null)
        .filter(Boolean)
    );
  }

  expected.depthByRole.operator = 0;
  expected.depthByRole.wot_depth1 = 1;
  expected.depthByRole.wot_depth2_pass = 2;
  expected.depthByRole.wot_depth2_fail = 2;
  expected.depthByRole.wot_depth3 = 3;
  expected.depthByRole.allowlist_only = null;
  expected.depthByRole.outsider = null;
  for (const account of accounts) {
    if (account.role.startsWith('wot_anchor_')) {
      expected.depthByRole[account.role] = 1;
    }
  }

  return expected;
}

async function collectFixtureEvents(pool, relays, pubkeys, {
  since,
  timeoutMs = DEFAULT_VERIFY_TIMEOUT_MS,
  expectedCount
} = {}) {
  return await new Promise((resolve) => {
    const latest = new Map();
    const rawEvents = [];
    let settled = false;

    const finish = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        subscription?.close?.('fixture-verification-complete');
      } catch (_) {}
      resolve({
        rawEvents,
        latestEvents: Array.from(latest.values())
      });
    };

    const timer = setTimeout(finish, Math.max(1_000, timeoutMs));
    const subscription = pool.subscribeMany(
      relays,
      {
        authors: pubkeys,
        kinds: [KIND_METADATA, KIND_CONTACT_LIST],
        since,
        limit: Math.max(expectedCount * 3, 32)
      },
      {
        onevent: (event) => {
          rawEvents.push(event);
          const key = `${event.pubkey}:${event.kind}`;
          latest.set(key, selectPreferredEvent(latest.get(key), event));
          if (latest.size >= expectedCount) {
            finish();
          }
        },
        oneose: finish,
        onclose: finish
      }
    );
  });
}

function reconstructGraphVerification({
  accounts,
  accountMap,
  latestEvents,
  depth2MinFollowers
}) {
  const verification = {
    ok: true,
    metadataByRole: {},
    followsByRole: {},
    depthByRole: {},
    reachableFollowerCountByRole: {},
    errors: []
  };
  const latestByKey = new Map(latestEvents.map((event) => [`${event.pubkey}:${event.kind}`, event]));
  const expected = buildExpectedGraphSnapshot(accounts, accountMap, depth2MinFollowers);
  const actualFollowMap = new Map();

  for (const account of accounts) {
    const metadataEvent = latestByKey.get(`${account.pubkeyHex}:${KIND_METADATA}`) || null;
    const contactEvent = latestByKey.get(`${account.pubkeyHex}:${KIND_CONTACT_LIST}`) || null;

    verification.metadataByRole[account.role] = metadataEvent
      ? {
          eventId: metadataEvent.id,
          createdAt: metadataEvent.created_at
        }
      : null;
    verification.followsByRole[account.role] = [];

    if (!metadataEvent) {
      verification.errors.push(`missing kind 0 metadata for ${account.role}`);
    }
    if (!contactEvent) {
      verification.errors.push(`missing kind 3 contact list for ${account.role}`);
      actualFollowMap.set(account.pubkeyHex, []);
      continue;
    }

    let follows = (Array.isArray(contactEvent.tags) ? contactEvent.tags : [])
      .filter((tag) => Array.isArray(tag) && tag[0] === 'p' && typeof tag[1] === 'string')
      .map((tag) => String(tag[1]).trim().toLowerCase())
      .filter((value) => /^[0-9a-f]{64}$/.test(value));
    follows = sortStrings(Array.from(new Set(follows)));
    verification.followsByRole[account.role] = follows;
    actualFollowMap.set(account.pubkeyHex, follows);

    const expectedFollows = expected.followsByRole[account.role] || [];
    if (JSON.stringify(follows) !== JSON.stringify(expectedFollows)) {
      verification.errors.push(
        `follow-set mismatch for ${account.role}: expected ${expectedFollows.join(', ') || '(none)'} got ${follows.join(', ') || '(none)'}`
      );
    }
  }

  const visited = new Map();
  const queue = [{ pubkey: accounts.find((account) => account.role === 'operator')?.pubkeyHex || null, depth: 0 }];
  while (queue.length > 0) {
    const current = queue.shift();
    if (!current?.pubkey) continue;
    if (visited.has(current.pubkey)) continue;
    visited.set(current.pubkey, current.depth);
    const neighbors = actualFollowMap.get(current.pubkey) || [];
    for (const neighbor of neighbors) {
      if (!visited.has(neighbor)) {
        queue.push({ pubkey: neighbor, depth: current.depth + 1 });
      }
    }
  }

  const reachableFollowers = new Map();
  for (const [sourcePubkey, follows] of actualFollowMap.entries()) {
    if (!visited.has(sourcePubkey)) continue;
    for (const targetPubkey of follows) {
      const current = reachableFollowers.get(targetPubkey) || 0;
      reachableFollowers.set(targetPubkey, current + 1);
    }
  }

  for (const account of accounts) {
    const actualDepth = visited.has(account.pubkeyHex) ? visited.get(account.pubkeyHex) : null;
    verification.depthByRole[account.role] = actualDepth;
    const expectedDepth = Object.prototype.hasOwnProperty.call(expected.depthByRole, account.role)
      ? expected.depthByRole[account.role]
      : null;
    if (expectedDepth !== actualDepth) {
      verification.errors.push(
        `depth mismatch for ${account.role}: expected ${expectedDepth == null ? 'unreachable' : expectedDepth} got ${actualDepth == null ? 'unreachable' : actualDepth}`
      );
    }
  }

  for (const [role, expectedCount] of Object.entries(expected.reachableFollowerCountByRole)) {
    const account = accountMap.get(role);
    const actualCount = account ? (reachableFollowers.get(account.pubkeyHex) || 0) : 0;
    verification.reachableFollowerCountByRole[role] = actualCount;
    if (actualCount !== expectedCount) {
      verification.errors.push(
        `reachable follower-count mismatch for ${role}: expected ${expectedCount} got ${actualCount}`
      );
    }
  }

  verification.ok = verification.errors.length === 0;
  return verification;
}

function renderMarkdownSummary({
  manifest,
  depth2MinFollowers
}) {
  const lines = [];
  lines.push('# Gateway Auth Fixture');
  lines.push('');
  lines.push(`Generated: ${manifest.generatedAt}`);
  lines.push(`Relays: ${manifest.relays.join(', ')}`);
  lines.push(`Depth-2 min followers: ${depth2MinFollowers}`);
  lines.push('');
  lines.push('## Recommended Allowlist Values');
  lines.push('');
  lines.push(`- Pure allowlist: \`${manifest.recommendedEnv.allowlistOnly}\``);
  lines.push(`- Allowlist + WoT: \`${manifest.recommendedEnv.allowlistPlusWot}\``);
  lines.push('');
  lines.push('## Verification');
  lines.push('');
  if (manifest.verification?.dryRun) {
    lines.push('- Verification skipped because publish or verify was disabled.');
  } else if (manifest.verification?.ok) {
    lines.push('- Verification succeeded: metadata and contact lists were fetched back and the reconstructed graph matched the expected fixture.');
  } else {
    lines.push('- Verification failed.');
    for (const error of manifest.verification?.errors || []) {
      lines.push(`- ${error}`);
    }
  }
  lines.push('');
  lines.push('## Accounts');
  lines.push('');
  lines.push('| Role | Pubkey | npub | Scenarios |');
  lines.push('| ---- | ------ | ---- | --------- |');
  for (const account of manifest.accounts) {
    lines.push(`| ${account.role} | \`${account.pubkeyHex}\` | \`${account.npub}\` | ${account.scenarios.join(', ')} |`);
  }
  lines.push('');
  lines.push('## Notes');
  lines.push('');
  lines.push('- `wot_depth1` and `wot_depth2_pass` are the two non-allowlisted-but-in-WoT validation accounts.');
  lines.push(`- ` + '`wot_depth2_pass`' + ` is followed by ${depth2MinFollowers} depth-1 anchor accounts.`);
  lines.push(`- ` + '`wot_depth2_fail`' + ` is followed by ${Math.max(0, depth2MinFollowers - 1)} depth-1 anchor accounts.`);
  lines.push('- `wot_depth3` is only reachable through `wot_depth2_pass` and should remain outside maxDepth=2.');
  return `${lines.join('\n')}\n`;
}

async function main() {
  const { values } = parseArgs({
    options: {
      seed: { type: 'string' },
      relays: { type: 'string' },
      out: { type: 'string' },
      'profile-prefix': { type: 'string' },
      'depth2-min-followers': { type: 'string' },
      publish: { type: 'string' },
      verify: { type: 'string' },
      'verify-timeout-ms': { type: 'string' },
      help: { type: 'boolean' }
    },
    allowPositionals: false
  });

  if (values.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }

  const publish = parseBoolean(values.publish, true);
  const verify = parseBoolean(values.verify, publish);
  const seed = typeof values.seed === 'string' && values.seed.trim()
    ? values.seed.trim()
    : randomBytes(16).toString('hex');
  const relays = parseRelayList(values.relays);
  const outPath = resolve(String(values.out || DEFAULT_OUTPUT));
  const profilePrefix = typeof values['profile-prefix'] === 'string' && values['profile-prefix'].trim()
    ? values['profile-prefix'].trim()
    : DEFAULT_PROFILE_PREFIX;
  const depth2MinFollowers = parsePositiveInteger(values['depth2-min-followers'], DEFAULT_DEPTH2_MIN_FOLLOWERS);
  const verifyTimeoutMs = parsePositiveInteger(values['verify-timeout-ms'], DEFAULT_VERIFY_TIMEOUT_MS);

  if (publish && relays.length === 0) {
    throw new Error('At least one relay URL is required when publish=true');
  }

  const graph = buildFixtureGraph(seed, depth2MinFollowers);
  const accountMap = new Map(graph.accounts.map((account) => [account.role, account]));
  const policyMatrix = buildPolicyMatrix(
    graph.accounts.map((account) => account.role),
    depth2MinFollowers
  );

  const manifest = {
    generatedAt: new Date().toISOString(),
    seed,
    relays,
    depth2MinFollowers,
    profilePrefix,
    aliases: {
      notInAllowlistButInWot: ['wot_depth1', 'wot_depth2_pass']
    },
    recommendedEnv: {
      operatorPubkey: graph.operator.pubkeyHex,
      wotRootPubkey: graph.operator.pubkeyHex,
      allowlistOnly: formatAllowlistEnv([graph.operator.pubkeyHex, graph.allowlistOnly.pubkeyHex]),
      allowlistPlusWot: formatAllowlistEnv([graph.allowlistOnly.pubkeyHex])
    },
    policyMatrix,
    accounts: graph.accounts.map((account) => ({
      role: account.role,
      label: account.label,
      pubkeyHex: account.pubkeyHex,
      npub: account.npub,
      secretHex: account.secretHex,
      nsec: account.nsec,
      scenarios: account.scenarios,
      follows: account.follows
    })),
    published: null,
    verification: null
  };

  if (publish) {
    const pool = new SimplePool({ enableReconnect: true });
    try {
      const publication = [];
      const orderedAccounts = [...graph.accounts];
      const publishSince = Math.floor(Date.now() / 1000) - 5;
      for (const account of orderedAccounts) {
        const metadataEvent = buildMetadataEvent(account, profilePrefix);
        const metadataResults = await publishEvent(pool, relays, metadataEvent);
        const contactEvent = buildContactListEvent(account, accountMap);
        const contactResults = await publishEvent(pool, relays, contactEvent);
        publication.push({
          role: account.role,
          metadataEventId: metadataEvent.id,
          metadataResults,
          contactEventId: contactEvent.id,
          contactResults
        });
      }
      manifest.published = {
        ok: true,
        accounts: publication
      };

      if (verify) {
        const collected = await collectFixtureEvents(
          pool,
          relays,
          graph.accounts.map((account) => account.pubkeyHex),
          {
            since: publishSince,
            timeoutMs: verifyTimeoutMs,
            expectedCount: graph.accounts.length * 2
          }
        );
        manifest.verification = {
          ...reconstructGraphVerification({
            accounts: graph.accounts,
            accountMap,
            latestEvents: collected.latestEvents,
            depth2MinFollowers
          }),
          timeoutMs: verifyTimeoutMs,
          rawEventCount: collected.rawEvents.length,
          latestEventCount: collected.latestEvents.length
        };
      } else {
        manifest.verification = {
          ok: false,
          dryRun: true
        };
      }
    } finally {
      pool.destroy();
    }
  } else {
    manifest.published = {
      ok: false,
      dryRun: true
    };
    manifest.verification = {
      ok: false,
      dryRun: true
    };
  }

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, JSON.stringify(manifest, null, 2));

  const markdownPath = outPath.replace(/\.json$/i, '.md');
  const markdown = renderMarkdownSummary({ manifest, depth2MinFollowers });
  await writeFile(markdownPath, markdown);

  process.stdout.write([
    `Fixture written: ${outPath}`,
    `Summary written: ${markdownPath}`,
    `Operator pubkey: ${graph.operator.pubkeyHex}`,
    `Allowlist-only env value: ${manifest.recommendedEnv.allowlistOnly}`,
    `Allowlist+WoT env value: ${manifest.recommendedEnv.allowlistPlusWot}`,
    publish ? 'Published kind 0 and kind 3 events to target relays.' : 'Dry run only; no events were published.',
    manifest.verification?.dryRun
      ? 'Verification skipped.'
      : (manifest.verification?.ok ? 'Verification succeeded.' : 'Verification failed.')
  ].join('\n'));
  process.stdout.write('\n');

  if (publish && verify && !manifest.verification?.ok) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
