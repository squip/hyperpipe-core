function asNumber(value, fallback = 0) {
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function normalizeOrigin(value) {
  if (typeof value !== 'string') return ''
  return value.trim()
}

function readMetrics(entry) {
  const metrics = entry && typeof entry === 'object' && entry.metrics && typeof entry.metrics === 'object'
    ? entry.metrics
    : {}
  return {
    latestViewLength: asNumber(metrics.latestViewLength, -1),
    updatedAt: asNumber(metrics.updatedAt, -1),
    writerCount: asNumber(metrics.writerCount, -1),
    coreRefsHash: typeof metrics.coreRefsHash === 'string' ? metrics.coreRefsHash.trim() : ''
  }
}

export function compareGatewayStatusResults(left, right) {
  const leftMetrics = readMetrics(left)
  const rightMetrics = readMetrics(right)

  if (rightMetrics.latestViewLength !== leftMetrics.latestViewLength) {
    return rightMetrics.latestViewLength - leftMetrics.latestViewLength
  }
  if (rightMetrics.updatedAt !== leftMetrics.updatedAt) {
    return rightMetrics.updatedAt - leftMetrics.updatedAt
  }
  if (rightMetrics.writerCount !== leftMetrics.writerCount) {
    return rightMetrics.writerCount - leftMetrics.writerCount
  }

  const leftLatency = asNumber(left?.latencyMs, Number.POSITIVE_INFINITY)
  const rightLatency = asNumber(right?.latencyMs, Number.POSITIVE_INFINITY)
  if (leftLatency !== rightLatency) return leftLatency - rightLatency

  return normalizeOrigin(left?.origin).localeCompare(normalizeOrigin(right?.origin))
}

export function rankGatewayStatusProbes(probes = [], fallbackOrigins = []) {
  const healthy = (Array.isArray(probes) ? probes : [])
    .filter((entry) => entry && entry.result === 'ok' && normalizeOrigin(entry.origin))
    .sort(compareGatewayStatusResults)

  const rankedOrigins = healthy.length
    ? Array.from(new Set(healthy.map((entry) => normalizeOrigin(entry.origin)).filter(Boolean)))
    : Array.from(new Set((Array.isArray(fallbackOrigins) ? fallbackOrigins : []).map(normalizeOrigin).filter(Boolean)))

  const coreRefsHashes = Array.from(
    new Set(
      healthy
        .map((entry) => readMetrics(entry).coreRefsHash)
        .filter(Boolean)
    )
  )

  return {
    healthy,
    rankedOrigins,
    driftDetected: coreRefsHashes.length > 1,
    coreRefsHashes
  }
}

export function evaluateFanoutResults(results = [], options = {}) {
  const minimumSuccess = Math.max(1, Math.trunc(asNumber(options.minimumSuccess, 1)))
  const entries = Array.isArray(results) ? results : []
  const successCount = entries.filter((entry) => entry && entry.status === 'ok').length
  const failedCount = entries.length - successCount

  return {
    minimumSuccess,
    successCount,
    failedCount,
    passesThreshold: successCount >= minimumSuccess
  }
}

export function evaluateJoinPerformanceTelemetry(events = [], options = {}) {
  const entries = Array.isArray(events) ? events : []
  const writerMaterialSlaMs = Math.max(1, Math.trunc(asNumber(options.writerMaterialSlaMs, 30_000)))
  const fastForwardSlaMs = Math.max(1, Math.trunc(asNumber(options.fastForwardSlaMs, 30_000)))
  const writableHardSlaMs = Math.max(1, Math.trunc(asNumber(options.writableHardSlaMs, 120_000)))

  const readElapsed = (eventType) => {
    const match = entries.find((entry) => entry && entry.eventType === eventType)
    return match ? asNumber(match.elapsedMs, Number.POSITIVE_INFINITY) : Number.POSITIVE_INFINITY
  }

  const writerMaterialElapsedMs = readElapsed('JOIN_WRITER_MATERIAL_APPLIED')
  const fastForwardElapsedMs = readElapsed('JOIN_FAST_FORWARD_APPLIED')
  const writableHardElapsedMs = readElapsed('JOIN_WRITABLE_CONFIRMED')

  const writerMaterialPass = writerMaterialElapsedMs <= writerMaterialSlaMs
  const fastForwardPass = fastForwardElapsedMs <= fastForwardSlaMs
  const writableHardPass = writableHardElapsedMs <= writableHardSlaMs

  const failures = []
  if (!writerMaterialPass) failures.push('writer-material-sla-failed')
  if (!fastForwardPass) failures.push('fast-forward-sla-failed')
  if (!writableHardPass) failures.push('join-writable-hard-sla-failed')

  for (const entry of entries) {
    if (!entry || entry.eventType !== 'JOIN_FAIL_FAST_ABORT') continue
    const reason = typeof entry.reasonCode === 'string' ? entry.reasonCode.trim() : ''
    failures.push(`fail-fast:${reason || 'unknown'}`)
  }

  return {
    pass: failures.length === 0,
    failures,
    writerMaterialPass,
    fastForwardPass,
    writableHardPass,
    writerMaterialElapsedMs,
    fastForwardElapsedMs,
    writableHardElapsedMs
  }
}
