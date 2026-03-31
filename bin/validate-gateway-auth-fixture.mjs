#!/usr/bin/env node

import { readFile, mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { parseArgs } from 'node:util';

import { schnorr } from '@noble/curves/secp256k1';

const DEFAULT_MANIFEST = './test-logs/gateway-auth-fixture/manifest.json';
const DEFAULT_SCOPE = 'gateway:relay-register';
const DEFAULT_TIMEOUT_MS = 30_000;

function usage() {
  return [
    'Usage:',
    '  node ./bin/validate-gateway-auth-fixture.mjs --gateway-origin <https://gateway.example> --policy-column <column> [options]',
    '',
    'Options:',
    '  --manifest <path>          Fixture manifest JSON path. Default: ./test-logs/gateway-auth-fixture/manifest.json',
    '  --gateway-origin <url>     Public gateway HTTP origin to probe.',
    '  --policy-column <column>   Policy column from manifest.policyMatrix.',
    '                            Supported: open, allowlist, wotDepth1, wotDepth2Threshold, allowlistPlusWot',
    '  --roles <csv>             Optional subset of account roles to validate.',
    '  --scope <value>           Auth scope to request. Default: gateway:relay-register',
    '  --timeout-ms <number>     Per-request timeout. Default: 30000',
    '  --out <path>              Optional JSON report output path.',
    '  --help                    Show this message.',
    '',
    'Example:',
    '  node ./bin/validate-gateway-auth-fixture.mjs \\',
    '    --manifest ../test-logs/gateway-auth-fixture/manifest.json \\',
    '    --gateway-origin https://hypertuna.com \\',
    '    --policy-column wotDepth2Threshold'
  ].join('\n');
}

function normalizeHttpOrigin(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return null;
    parsed.pathname = '';
    parsed.search = '';
    parsed.hash = '';
    return parsed.origin;
  } catch {
    return null;
  }
}

function parsePositiveInteger(value, fallback) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.max(1, Math.trunc(numeric));
}

function parseRoleList(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  return Array.from(new Set(
    value.split(',')
      .map((entry) => entry.trim())
      .filter(Boolean)
  ));
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

async function readManifest(manifestPath) {
  const raw = await readFile(manifestPath, 'utf8');
  const parsed = JSON.parse(raw);
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('invalid-manifest-json');
  }
  if (!Array.isArray(parsed.accounts)) {
    throw new Error('manifest-missing-accounts');
  }
  if (!parsed.policyMatrix || typeof parsed.policyMatrix !== 'object') {
    throw new Error('manifest-missing-policy-matrix');
  }
  return parsed;
}

async function postJson(url, payload, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      const text = await response.text().catch(() => '');
      let body = {};
      try {
        body = text ? JSON.parse(text) : {};
      } catch {
        body = { raw: text };
      }
      return {
        status: response.status,
        ok: response.ok,
        body
      };
    } catch (error) {
      const isAbort = error?.name === 'AbortError';
      return {
        status: 0,
        ok: false,
        body: {
          error: isAbort ? 'request-timeout' : 'request-failed',
          message: error?.message || String(error)
        }
      };
    }
  } finally {
    clearTimeout(timer);
  }
}

async function probeGatewayAccount({ gatewayOrigin, account, scope, timeoutMs }) {
  const challenge = await postJson(`${gatewayOrigin}/api/auth/challenge`, {
    pubkey: account.pubkeyHex,
    scope
  }, timeoutMs);

  if (!challenge.ok) {
    return {
      challenge,
      verify: null,
      allowed: false,
      classification: 'challenge-error'
    };
  }

  const challengeId = typeof challenge.body?.challengeId === 'string' ? challenge.body.challengeId : '';
  const nonce = typeof challenge.body?.nonce === 'string' ? challenge.body.nonce : '';
  if (!challengeId || !nonce) {
    return {
      challenge,
      verify: null,
      allowed: false,
      classification: 'challenge-invalid'
    };
  }

  const signatureBytes = await schnorr.sign(
    new TextEncoder().encode(nonce),
    hexToBytes(account.secretHex)
  );
  const verify = await postJson(`${gatewayOrigin}/api/auth/verify`, {
    challengeId,
    pubkey: account.pubkeyHex,
    signature: Buffer.from(signatureBytes).toString('hex'),
    scope
  }, timeoutMs);

  let classification = 'verify-error';
  if (verify.status === 200 && typeof verify.body?.token === 'string') {
    classification = 'approved';
  } else if (verify.status === 0 && verify.body?.error === 'request-timeout') {
    classification = 'verify-timeout';
  } else if (verify.status === 403) {
    classification = 'denied';
  } else if (verify.status === 401) {
    classification = 'invalid-signature-or-challenge';
  }

  return {
    challenge,
    verify,
    allowed: classification === 'approved',
    classification
  };
}

function buildMarkdownReport(report) {
  const lines = [];
  lines.push('# Gateway Auth Validation Report');
  lines.push('');
  lines.push(`- Generated: ${report.generatedAt}`);
  lines.push(`- Gateway origin: ${report.gatewayOrigin}`);
  lines.push(`- Policy column: ${report.policyColumn}`);
  lines.push(`- Scope: ${report.scope}`);
  lines.push(`- Manifest: ${report.manifestPath}`);
  lines.push(`- Success: ${report.ok ? 'true' : 'false'}`);
  lines.push('');
  lines.push('| Role | Expected | Actual | Status | Classification |');
  lines.push('| ---- | -------- | ------ | ------ | -------------- |');
  for (const row of report.results) {
    lines.push(`| ${row.role} | ${row.expected} | ${row.actual} | ${row.status} | ${row.classification} |`);
  }
  if (Array.isArray(report.failures) && report.failures.length) {
    lines.push('');
    lines.push('## Failures');
    lines.push('');
    for (const failure of report.failures) {
      lines.push(`- ${failure.role}: expected ${failure.expected}, got ${failure.actual} (${failure.classification})`);
    }
  }
  return `${lines.join('\n')}\n`;
}

async function main() {
  const { values } = parseArgs({
    options: {
      manifest: { type: 'string' },
      'gateway-origin': { type: 'string' },
      'policy-column': { type: 'string' },
      roles: { type: 'string' },
      scope: { type: 'string' },
      'timeout-ms': { type: 'string' },
      out: { type: 'string' },
      help: { type: 'boolean' }
    },
    allowPositionals: false
  });

  if (values.help) {
    process.stdout.write(`${usage()}\n`);
    process.exit(0);
  }

  const manifestPath = resolve(String(values.manifest || DEFAULT_MANIFEST));
  const gatewayOrigin = normalizeHttpOrigin(values['gateway-origin']);
  const policyColumn = typeof values['policy-column'] === 'string' ? values['policy-column'].trim() : '';
  const scope = typeof values.scope === 'string' && values.scope.trim() ? values.scope.trim() : DEFAULT_SCOPE;
  const timeoutMs = parsePositiveInteger(values['timeout-ms'], DEFAULT_TIMEOUT_MS);
  const selectedRoles = parseRoleList(values.roles);
  const outPath = typeof values.out === 'string' && values.out.trim()
    ? resolve(values.out)
    : null;

  if (!gatewayOrigin) {
    throw new Error('--gateway-origin is required');
  }
  if (!policyColumn) {
    throw new Error('--policy-column is required');
  }

  const manifest = await readManifest(manifestPath);
  const accounts = manifest.accounts.filter((account) => {
    if (!account || typeof account !== 'object') return false;
    if (selectedRoles && !selectedRoles.includes(String(account.role || ''))) return false;
    return true;
  });

  if (!accounts.length) {
    throw new Error('no-matching-accounts');
  }

  const results = [];
  const failures = [];

  for (const account of accounts) {
    const role = String(account.role || '').trim();
    const expectedResult = manifest.policyMatrix?.[role]?.[policyColumn]?.result || null;
    if (!expectedResult) {
      continue;
    }
    const outcome = await probeGatewayAccount({
      gatewayOrigin,
      account,
      scope,
      timeoutMs
    });
    const actual = outcome.allowed ? 'ALLOW' : 'DENY';
    const row = {
      role,
      expected: expectedResult,
      actual,
      status: outcome.verify?.status ?? outcome.challenge?.status ?? 0,
      classification: outcome.classification,
      challenge: outcome.challenge,
      verify: outcome.verify
    };
    results.push(row);
    if (expectedResult !== actual) {
      failures.push(row);
    }
  }

  const report = {
    generatedAt: new Date().toISOString(),
    manifestPath,
    gatewayOrigin,
    policyColumn,
    scope,
    ok: failures.length === 0,
    results,
    failures
  };

  if (outPath) {
    await mkdir(dirname(outPath), { recursive: true });
    await writeFile(outPath, JSON.stringify(report, null, 2), 'utf8');
    await writeFile(outPath.replace(/\.json$/i, '.md'), buildMarkdownReport(report), 'utf8');
  }

  process.stdout.write(`${buildMarkdownReport(report)}\n`);

  if (!report.ok) {
    process.exit(1);
  }
}

main().catch((error) => {
  process.stderr.write(`${error?.message || String(error)}\n`);
  process.exit(1);
});
