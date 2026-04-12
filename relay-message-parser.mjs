import b4a from 'b4a'

export function parseNostrMessagePayload(message) {
  if (typeof message === 'string') {
    const trimmed = message.trim()
    if (!trimmed.length) {
      throw new Error('Empty NOSTR message payload')
    }
    return JSON.parse(trimmed)
  }

  if (message && message.type === 'Buffer' && Array.isArray(message.data)) {
    const messageStr = b4a.from(message.data).toString('utf8')
    if (!messageStr.trim().length) {
      throw new Error('Empty NOSTR message payload')
    }
    return JSON.parse(messageStr)
  }

  return message
}
