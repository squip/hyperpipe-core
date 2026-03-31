import { inspect } from 'node:util'

const LEVEL_ORDER = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
  trace: 4
}

const SENSITIVE_KEY_PATTERN = /(authorization|cookie|token|secret|password|passphrase|session|bearer|api[-_]?key|private[-_]?key|shared[-_]?secret|invite[-_]?code|invite[-_]?secret|nostr[-_]?nsec|nsec)/i
const DEFAULT_SUPPRESSED_MARKERS = [
  '[Topic]',
  '[Mirror]',
  '[Hyperdrive]',
  '[Fetch]',
  '[FetchPfp]',
  '[PfpMirror]',
  '[Recover]',
  '[Worker][relay-update]',
  '[Worker] Sending message:',
  '[Worker] Received from parent:',
  '[Worker] Stored parent config',
  '[Worker][addAuthInfoToRelays]',
  '[Worker] Join probe candidate',
  '[RelayServer][waitForPeerProtocol]',
  '[RelayServer][Checkpoint]',
  '[RelayServer] probeJoinCapabilities',
  '[RelayServer] Subscription refresh',
  '[RelayServer] Starting keepalive',
  '[RelayServer] Keepalive check'
]

const LOGGER_STATE_KEY = Symbol.for('hyperpipe.core.logger.state')

function isEnvEnabled(value, defaultValue = false) {
  if (typeof value !== 'string') return defaultValue
  const normalized = value.trim().toLowerCase()
  if (!normalized) return defaultValue
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on') return true
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') return false
  return defaultValue
}

function normalizeLevel(value, fallback = 'info') {
  const normalized = typeof value === 'string' ? value.trim().toLowerCase() : ''
  return normalized in LEVEL_ORDER ? normalized : fallback
}

function resolveConfiguredLevel() {
  if (typeof process.env.HYPERPIPE_CORE_LOG_LEVEL === 'string' && process.env.HYPERPIPE_CORE_LOG_LEVEL.trim()) {
    return normalizeLevel(process.env.HYPERPIPE_CORE_LOG_LEVEL, 'info')
  }

  if (isEnvEnabled(process.env.HYPERPIPE_CORE_VERBOSE, false)) {
    return 'debug'
  }

  return process.env.NODE_ENV === 'development' ? 'debug' : 'info'
}

function resolveSuppressedMarkers() {
  const extra = String(process.env.HYPERPIPE_CORE_SUPPRESS_TAGS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)
  return new Set([...DEFAULT_SUPPRESSED_MARKERS, ...extra])
}

function isPlainObject(value) {
  if (!value || typeof value !== 'object') return false
  const proto = Object.getPrototypeOf(value)
  return proto === Object.prototype || proto === null
}

function isSensitiveKey(key) {
  return typeof key === 'string' && SENSITIVE_KEY_PATTERN.test(key)
}

function redactSensitiveString(value) {
  if (typeof value !== 'string' || !value) return value

  return value
    .replace(/\b(nsec1[023456789acdefghjklmnpqrstuvwxyz]+)\b/gi, '[REDACTED_NSEC]')
    .replace(/(Bearer\s+)[^\s,]+/gi, '$1[REDACTED]')
    .replace(/([?&](?:token|auth|authorization|secret|sharedSecret|inviteCode|inviteSecret)=)[^&\s]+/gi, '$1[REDACTED]')
    .replace(/((?:nostr[_-]?nsec[_-]?hex|shared[_-]?secret|invite[_-]?(?:code|secret)|authorization|cookie|token|password)\s*[:=]\s*)([A-Za-z0-9._~+/=-]{6,})/gi, '$1[REDACTED]')
}

function summarizeError(error, seen, depth) {
  const summary = {
    name: error.name,
    message: redactSensitiveString(error.message),
    stack: redactSensitiveString(error.stack || '')
  }

  for (const [key, value] of Object.entries(error)) {
    if (key in summary) continue
    summary[key] = redactValue(value, {
      key,
      depth: depth + 1,
      seen
    })
  }

  return summary
}

function redactValue(value, { key = '', depth = 0, seen = new WeakMap() } = {}) {
  if (value == null) return value

  if (typeof value === 'string') {
    return isSensitiveKey(key) ? '[REDACTED]' : redactSensitiveString(value)
  }

  if (typeof value === 'number' || typeof value === 'boolean') return value
  if (typeof value === 'bigint') return value.toString()
  if (typeof value === 'function') return `[Function ${value.name || 'anonymous'}]`

  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return `[${value.constructor?.name || 'Uint8Array'} length=${value.length}]`
  }

  if (value instanceof Date) return value.toISOString()
  if (value instanceof URL) return redactSensitiveString(value.toString())
  if (value instanceof Error) return summarizeError(value, seen, depth)

  if (typeof value !== 'object') return value
  if (depth >= 6) return `[${value.constructor?.name || 'Object'} depth-limit]`

  if (seen.has(value)) return '[Circular]'

  if (Array.isArray(value)) {
    const clone = []
    seen.set(value, clone)
    for (const entry of value) {
      clone.push(redactValue(entry, { depth: depth + 1, seen }))
    }
    return clone
  }

  if (value instanceof Map) {
    const clone = {}
    seen.set(value, clone)
    for (const [entryKey, entryValue] of value.entries()) {
      clone[String(entryKey)] = redactValue(entryValue, {
        key: String(entryKey),
        depth: depth + 1,
        seen
      })
    }
    return clone
  }

  if (value instanceof Set) {
    const clone = []
    seen.set(value, clone)
    for (const entry of value.values()) {
      clone.push(redactValue(entry, { depth: depth + 1, seen }))
    }
    return clone
  }

  if (!isPlainObject(value)) {
    return redactSensitiveString(inspect(value, { depth: 3, breakLength: Infinity, compact: true }))
  }

  const clone = {}
  seen.set(value, clone)

  for (const [entryKey, entryValue] of Object.entries(value)) {
    clone[entryKey] = redactValue(entryValue, {
      key: entryKey,
      depth: depth + 1,
      seen
    })
  }

  return clone
}

function redactArgs(args) {
  const seen = new WeakMap()
  return args.map((value, index) => redactValue(value, {
    key: index === 0 ? 'message' : '',
    depth: 0,
    seen
  }))
}

function collectSearchableText(args) {
  const values = []
  for (const arg of args) {
    if (typeof arg === 'string') {
      values.push(arg)
      continue
    }

    if (arg instanceof Error) {
      values.push(arg.message || '')
      values.push(arg.stack || '')
      continue
    }

    if (!arg || typeof arg !== 'object') continue

    try {
      values.push(inspect(arg, { depth: 2, breakLength: Infinity, compact: true }))
    } catch {
      values.push(String(arg))
    }
  }
  return values.join('\n')
}

function shouldSuppressNoise(level, args, suppressedMarkers, suppressNoise) {
  if (!suppressNoise) return false
  if (level === 'warn' || level === 'error') return false
  const haystack = collectSearchableText(args)
  if (!haystack) return false
  for (const marker of suppressedMarkers) {
    if (haystack.includes(marker)) return true
  }
  return false
}

function isLevelEnabled(targetLevel, configuredLevel) {
  return LEVEL_ORDER[targetLevel] <= LEVEL_ORDER[configuredLevel]
}

function installCoreLogger() {
  if (globalThis[LOGGER_STATE_KEY]) {
    return globalThis[LOGGER_STATE_KEY]
  }

  const originalConsole = {
    error: console.error.bind(console),
    warn: console.warn.bind(console),
    info: console.info.bind(console),
    log: console.log.bind(console),
    debug: console.debug.bind(console)
  }

  const state = {
    level: resolveConfiguredLevel(),
    suppressNoise: isEnvEnabled(process.env.HYPERPIPE_CORE_SUPPRESS_NOISE, true),
    suppressedMarkers: resolveSuppressedMarkers(),
    originalConsole
  }

  function emit(level, args, { force = false } = {}) {
    const method = level === 'trace' ? 'debug' : (level === 'info' ? 'info' : level)
    if (!force && !isLevelEnabled(level, state.level)) return
    const redactedArgs = redactArgs(args)
    if (!force && shouldSuppressNoise(level, redactedArgs, state.suppressedMarkers, state.suppressNoise)) return
    originalConsole[method](...redactedArgs)
  }

  console.error = (...args) => emit('error', args)
  console.warn = (...args) => emit('warn', args)
  console.info = (...args) => emit('info', args)
  console.log = (...args) => emit('info', args)
  console.debug = (...args) => emit('debug', args)

  state.emit = emit
  globalThis[LOGGER_STATE_KEY] = state
  return state
}

function scopedLogger(scope) {
  const state = installCoreLogger()

  function prefixArgs(args) {
    if (!scope) return args
    if (!args.length) return [`[${scope}]`]
    const [first, ...rest] = args
    if (typeof first === 'string') {
      return first.startsWith(`[${scope}]`) ? args : [`[${scope}] ${first}`, ...rest]
    }
    return [`[${scope}]`, ...args]
  }

  return {
    error: (...args) => state.emit('error', prefixArgs(args)),
    warn: (...args) => state.emit('warn', prefixArgs(args)),
    info: (...args) => state.emit('info', prefixArgs(args)),
    debug: (...args) => state.emit('debug', prefixArgs(args)),
    trace: (...args) => state.emit('trace', prefixArgs(args)),
    lifecycle: (...args) => state.emit('info', prefixArgs(args), { force: true })
  }
}

export {
  installCoreLogger,
  redactValue,
  scopedLogger
}
