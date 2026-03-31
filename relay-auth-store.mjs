// relay-auth-store.mjs - In-memory token management for relay authentication

import { promises as fs } from 'node:fs';
import { join } from 'node:path';

/**
 * In-memory store for relay authentication tokens
 */
export class RelayAuthStore {
  constructor() {
    // Map of relayKey -> Map of pubkey -> auth data
    this.relayAuths = new Map();
  }

/**
 * Get auth by token (searches all users in a relay)
 * @param {string} relayKey - Relay identifier
 * @param {string} token - Auth token
 * @returns {Object|null} - Auth data with pubkey or null
 */
getAuthByToken(relayKey, token) {
    const relayAuth = this.relayAuths.get(relayKey);
    if (!relayAuth) return null;
    
    for (const [pubkey, auth] of relayAuth) {
      if (auth.token === token) {
        return { pubkey, ...auth };
      }
    }
    
    return null;
  }
  
  /**
   * Add or update authentication for a user
   * @param {string} relayKey - Relay identifier
   * @param {string} pubkey - User public key
   * @param {string} token - Authentication token
   */
  addAuth(relayKey, pubkey, token) {
    if (!this.relayAuths.has(relayKey)) {
      this.relayAuths.set(relayKey, new Map());
    }

    const relayAuth = this.relayAuths.get(relayKey);
    relayAuth.set(pubkey, {
      token,
      createdAt: Date.now(),
      lastUsed: Date.now()
    });
    
    console.log(`[RelayAuthStore] Added auth for ${pubkey.substring(0, 8)}... on relay ${relayKey}`);
  }
  
  
  /**
   * Verify a token for a relay
   * @param {string} relayKey - Relay identifier
   * @param {string} token - Auth token
   * @returns {Object|null} - User auth data or null
   */
  verifyAuth(relayKey, token) {
    const relayAuth = this.relayAuths.get(relayKey);
    if (!relayAuth) return null;

    // Find user by token
    for (const [pubkey, auth] of relayAuth) {
      if (auth.token === token) {
        auth.lastUsed = Date.now();
        return { pubkey, ...auth };
      }
    }
    
    return null;
  }
  
  /**
   * Get auth by pubkey
   * @param {string} relayKey - Relay identifier
   * @param {string} pubkey - User public key
   * @returns {Object|null} - Auth data or null
   */
  getAuthByPubkey(relayKey, pubkey) {
    const relayAuth = this.relayAuths.get(relayKey);
    if (!relayAuth) return null;
    
    return relayAuth.get(pubkey) || null;
  }
  
  /**
   * Check if pubkey is authorized (has valid auth)
   * @param {string} relayKey - Relay identifier
   * @param {string} pubkey - User public key
   * @returns {boolean}
   */
  isAuthorized(relayKey, pubkey) {
    const auth = this.getAuthByPubkey(relayKey, pubkey);
    return auth !== null;
  }
  
  /**
   * Remove authentication
   * @param {string} relayKey - Relay identifier
   * @param {string} pubkey - User public key
   */
  removeAuth(relayKey, pubkey) {
    const relayAuth = this.relayAuths.get(relayKey);
    if (relayAuth) {
      relayAuth.delete(pubkey);
      console.log(`[RelayAuthStore] Removed auth for ${pubkey.substring(0, 8)}... on relay ${relayKey}`);
    }
  }
  
  /**
   * Get all authorized pubkeys for a relay
   * @param {string} relayKey - Relay identifier
   * @returns {Array<string>} - Array of pubkeys
   */
  getAuthorizedPubkeys(relayKey) {
    const relayAuth = this.relayAuths.get(relayKey);
    if (!relayAuth) return [];
    
    return Array.from(relayAuth.keys());
  }
  
  /**
   * Export auth data for persistence
   * @param {string} relayKey - Relay identifier
   * @returns {Object} - Serializable auth data
   */
  exportRelayAuth(relayKey) {
    const relayAuth = this.relayAuths.get(relayKey);
    if (!relayAuth) return {};
    
    const exported = {};
    for (const [pubkey, auth] of relayAuth) {
      exported[pubkey] = {
        token: auth.token,
        createdAt: auth.createdAt,
        lastUsed: auth.lastUsed
      };
    }
    
    return exported;
  }
  
  /**
   * Import auth data from persistence
   * @param {string} relayKey - Relay identifier
   * @param {Object} authData - Auth data to import
   */
  importRelayAuth(relayKey, authData) {
    const relayAuth = new Map();

    for (const [pubkey, auth] of Object.entries(authData)) {
      relayAuth.set(pubkey, {
        token: auth.token,
        createdAt: auth.createdAt,
        lastUsed: auth.lastUsed
      });
    }
    
    this.relayAuths.set(relayKey, relayAuth);
    console.log(`[RelayAuthStore] Imported ${relayAuth.size} auths for relay ${relayKey}`);
  }
  
  /**
   * Clear all auth for a relay
   * @param {string} relayKey - Relay identifier
   */
  clearRelayAuth(relayKey) {
    this.relayAuths.delete(relayKey);
    console.log(`[RelayAuthStore] Cleared all auth for relay ${relayKey}`);
  }
}

// Singleton instance
let authStoreInstance = null;

export function getRelayAuthStore() {
  if (!authStoreInstance) {
    authStoreInstance = new RelayAuthStore();
  }
  return authStoreInstance;
}
