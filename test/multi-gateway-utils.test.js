import test from 'brittle'
import {
  compareGatewayStatusResults,
  rankGatewayStatusProbes,
  evaluateFanoutResults,
  evaluateJoinPerformanceTelemetry
} from '../gateway/MultiGatewayJoinUtils.mjs'

test('compareGatewayStatusResults ranks by freshness tuple then latency', (t) => {
  const probes = [
    {
      origin: 'https://g1.example',
      latencyMs: 40,
      metrics: {
        latestViewLength: 10,
        updatedAt: 100,
        writerCount: 2
      }
    },
    {
      origin: 'https://g2.example',
      latencyMs: 100,
      metrics: {
        latestViewLength: 12,
        updatedAt: 90,
        writerCount: 1
      }
    },
    {
      origin: 'https://g3.example',
      latencyMs: 20,
      metrics: {
        latestViewLength: 10,
        updatedAt: 100,
        writerCount: 2
      }
    }
  ]

  probes.sort(compareGatewayStatusResults)
  t.alike(probes.map((entry) => entry.origin), [
    'https://g2.example',
    'https://g3.example',
    'https://g1.example'
  ])
})

test('rankGatewayStatusProbes returns healthy ordered origins and drift signal', (t) => {
  const ranked = rankGatewayStatusProbes([
    {
      result: 'ok',
      origin: 'https://g1.example',
      latencyMs: 80,
      metrics: {
        latestViewLength: 50,
        updatedAt: 1000,
        writerCount: 3,
        coreRefsHash: 'aaa'
      }
    },
    {
      result: 'ok',
      origin: 'https://g2.example',
      latencyMs: 25,
      metrics: {
        latestViewLength: 52,
        updatedAt: 1001,
        writerCount: 3,
        coreRefsHash: 'bbb'
      }
    },
    {
      result: 'error',
      origin: 'https://g3.example',
      reason: 'timeout'
    }
  ], ['https://fallback.example'])

  t.alike(ranked.rankedOrigins, ['https://g2.example', 'https://g1.example'])
  t.is(ranked.healthy.length, 2)
  t.is(ranked.driftDetected, true)
  t.alike(ranked.coreRefsHashes.sort(), ['aaa', 'bbb'])
})

test('evaluateFanoutResults enforces at least one success', (t) => {
  const passing = evaluateFanoutResults([
    { origin: 'https://g1.example', status: 'error' },
    { origin: 'https://g2.example', status: 'ok' }
  ], { minimumSuccess: 1 })

  t.is(passing.successCount, 1)
  t.is(passing.failedCount, 1)
  t.is(passing.passesThreshold, true)

  const failing = evaluateFanoutResults([
    { origin: 'https://g1.example', status: 'error' },
    { origin: 'https://g2.example', status: 'error' }
  ], { minimumSuccess: 1 })

  t.is(failing.successCount, 0)
  t.is(failing.passesThreshold, false)
})

test('evaluateJoinPerformanceTelemetry flags SLA failures and fail-fast reasons', (t) => {
  const passing = evaluateJoinPerformanceTelemetry([
    { eventType: 'JOIN_START', elapsedMs: 0 },
    { eventType: 'JOIN_WRITER_MATERIAL_APPLIED', elapsedMs: 12000 },
    { eventType: 'JOIN_FAST_FORWARD_APPLIED', elapsedMs: 14000 },
    { eventType: 'JOIN_WRITABLE_CONFIRMED', elapsedMs: 42000 }
  ])

  t.is(passing.pass, true)
  t.is(passing.writerMaterialPass, true)
  t.is(passing.fastForwardPass, true)
  t.is(passing.writableHardPass, true)

  const failing = evaluateJoinPerformanceTelemetry([
    { eventType: 'JOIN_START', elapsedMs: 0 },
    { eventType: 'JOIN_WRITER_MATERIAL_APPLIED', elapsedMs: 50000 },
    { eventType: 'JOIN_FAST_FORWARD_APPLIED', elapsedMs: 45000 },
    { eventType: 'JOIN_WRITABLE_CONFIRMED', elapsedMs: 130000 },
    { eventType: 'JOIN_FAIL_FAST_ABORT', reasonCode: 'join-writable-timeout' }
  ])

  t.is(failing.pass, false)
  t.alike(failing.failures, [
    'writer-material-sla-failed',
    'fast-forward-sla-failed',
    'join-writable-hard-sla-failed',
    'fail-fast:join-writable-timeout'
  ])
})
