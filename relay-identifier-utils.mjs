// Utility helpers for relay identifier normalization across worker modules.

/**
 * Normalize relay identifiers so colon-based public identifiers are restored
 * even if they arrive URL encoded or with path separators.
 * @param {string} identifier
 * @returns {string}
 */
export function normalizeRelayIdentifier(identifier) {
  if (!identifier) return '';

  let normalized = identifier.trim();

  // Strip query string if present
  const queryIndex = normalized.indexOf('?');
  if (queryIndex !== -1) {
    normalized = normalized.slice(0, queryIndex);
  }

  // Decode percent-encoded characters (e.g. npub%3Arelay)
  try {
    normalized = decodeURIComponent(normalized);
  } catch (_) {}

  // Convert path-style identifiers (npub/.../relay) back to colon form
  if (!normalized.includes(':')) {
    const segments = normalized.split('/').filter(Boolean);
    if (segments.length >= 2) {
      normalized = `${segments[0]}:${segments.slice(1).join('/')}`;
    }
  }

  return normalized;
}
