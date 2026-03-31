export function isHex64(value) {
  return typeof value === 'string' && /^[a-fA-F0-9]{64}$/.test(value)
}

export function normalizeCoreConfigPayload(payload) {
  if (!payload || typeof payload !== 'object') return null
  const base =
    payload.type === 'config' && payload.data && typeof payload.data === 'object'
      ? payload.data
      : payload
  const normalized = { ...base }

  if (!normalized.nostr_pubkey_hex && normalized.nostrPubkeyHex) {
    normalized.nostr_pubkey_hex = normalized.nostrPubkeyHex
  }
  if (!normalized.nostr_nsec_hex && normalized.nostrNsecHex) {
    normalized.nostr_nsec_hex = normalized.nostrNsecHex
  }
  if (!normalized.userKey && normalized.user_key) {
    normalized.userKey = normalized.user_key
  }

  return normalized
}

export function validateCoreConfigPayload(payload) {
  if (!payload) return null
  if (!isHex64(payload.nostr_pubkey_hex) || !isHex64(payload.nostr_nsec_hex)) {
    return 'Invalid core config: expected nostr_pubkey_hex and nostr_nsec_hex (64-char hex)'
  }
  if (!payload.userKey || typeof payload.userKey !== 'string') {
    return 'Invalid core config: userKey is required for per-account isolation'
  }
  return null
}
