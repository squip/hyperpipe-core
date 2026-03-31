// challenge-manager.mjs - Challenge generation and verification for relay authentication

import crypto from 'node:crypto';
import b4a from 'b4a';
import { nobleSecp256k1 } from './pure-secp256k1.js';
import { normalizeRelayIdentifier } from './relay-identifier-utils.mjs';

/**
 * Challenge store for managing authentication challenges
 */
export class ChallengeStore {
  constructor() {
    this.challenges = new Map();
    this.TTL = 5 * 60 * 1000; // 5 minutes TTL
    this.cleanupInterval = null;
    
    // Start periodic cleanup
    this.startCleanup();
  }
  
  /**
   * Start periodic cleanup of expired challenges
   */
  startCleanup() {
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [pubkey, data] of this.challenges) {
        if (now - data.timestamp > this.TTL) {
          console.log(`[ChallengeStore] Removing expired challenge for ${pubkey.substring(0, 8)}...`);
          this.challenges.delete(pubkey);
        }
      }
    }, 60000); // Clean every minute
  }
  
  /**
   * Store a challenge for a pubkey
   * @param {string} pubkey - User's public key
   * @param {string} challenge - Generated challenge
   * @param {string} relayPubkey - Relay's public key for ECDH
   * @param {string} identifier - Relay identifier
   * @returns {void}
   */
  store(pubkey, challenge, relayPubkey, identifier) {
    this.challenges.set(pubkey, {
      challenge,
      relayPubkey,
      identifier,
      timestamp: Date.now(),
      attempts: 0
    });
    
    console.log(`[ChallengeStore] Stored challenge for ${pubkey.substring(0, 8)}...`);
  }
  
  /**
   * Retrieve a challenge for a pubkey
   * @param {string} pubkey - User's public key
   * @returns {Object|null} - Challenge data or null if not found/expired
   */
  retrieve(pubkey) {
    const entry = this.challenges.get(pubkey);
    if (!entry) return null;
    
    const now = Date.now();
    if (now - entry.timestamp > this.TTL) {
      this.challenges.delete(pubkey);
      return null;
    }
    
    // Increment attempts
    entry.attempts++;
    
    // Max 5 attempts
    if (entry.attempts > 5) {
      console.log(`[ChallengeStore] Max attempts exceeded for ${pubkey.substring(0, 8)}...`);
      this.challenges.delete(pubkey);
      return null;
    }
    
    return entry;
  }
  
  /**
   * Remove a challenge
   * @param {string} pubkey - User's public key
   */
  remove(pubkey) {
    this.challenges.delete(pubkey);
  }
  
  /**
   * Cleanup and destroy
   */
  destroy() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.challenges.clear();
  }
}

/**
 * Challenge manager for handling ECDH authentication
 */
export class ChallengeManager {
  constructor(relayPrivateKey) {
    this.store = new ChallengeStore();
    this.relayPrivateKey = relayPrivateKey;
    
    // Get relay public key from private key
    this.relayPublicKey = this.getPublicKeyFromPrivate(relayPrivateKey);
    console.log(`[ChallengeManager] Initialized with relay pubkey: ${this.relayPublicKey}`);
  }
  
  /**
   * Get public key from private key
   * @param {string} privateKeyHex - Private key in hex
   * @returns {string} - Public key in hex (33 bytes compressed without prefix)
   */
  getPublicKeyFromPrivate(privateKeyHex) {
    const pubKeyBytes = nobleSecp256k1.getPublicKey(privateKeyHex, true);
    // Remove the compression prefix (first byte) for x-only pubkey
    return b4a.toString(pubKeyBytes.slice(1), 'hex');
  }
  
  /**
   * Generate a random challenge
   * @returns {string} - Hex encoded challenge
   */
  generateChallenge() {
    return crypto.randomBytes(32).toString('hex');
  }
  
  /**
   * Create challenge for authentication
   * @param {string} pubkey - User's public key
   * @param {string} identifier - Relay identifier
   * @returns {Object} - Challenge and relay public key
   */
  createChallenge(pubkey, identifier) {
    const challenge = this.generateChallenge();
    const canonicalIdentifier = normalizeRelayIdentifier(identifier);
    
    // Store challenge with relay public key
    this.store.store(pubkey, challenge, this.relayPublicKey, canonicalIdentifier);
    
    return {
      challenge,
      relayPubkey: this.relayPublicKey,
      identifier: canonicalIdentifier
    };
  }
  
  /**
   * Verify challenge response using ECDH
   * @param {string} pubkey - User's public key
   * @param {string} ciphertext - Base64 encoded ciphertext
   * @param {string} iv - Base64 encoded IV
   * @returns {Object} - Verification result
   */
  async verifyChallenge(pubkey, ciphertext, iv) {
    try {
      // Retrieve stored challenge
      const stored = this.store.retrieve(pubkey);
      if (!stored) {
        console.warn(`[ChallengeManager] No challenge found for ${pubkey.substring(0, 8)}...`);
        return {
          success: false,
          error: 'Challenge not found or expired'
        };
      }
      
      console.log(`[ChallengeManager] Verifying challenge for ${pubkey.substring(0, 8)}...`);
      
      // Compute ECDH shared secret
      let sharedSecret = await nobleSecp256k1.getSharedSecret(
        this.relayPrivateKey,
        '02' + pubkey, // Add compression prefix
        true
      );

      // noble-secp256k1 may return a 33 byte buffer with a leading 0x00.
      // Slice the first byte so the derived AES key matches the client's.
      if (sharedSecret.length === 33) sharedSecret = sharedSecret.slice(1);

      const keyBuffer = b4a.from(sharedSecret);
      
      console.log(`[ChallengeManager] Shared key: ${keyBuffer.toString('hex').substring(0, 16)}...`);
      
      // Decrypt the challenge
      const decrypted = this.aesDecrypt(keyBuffer, ciphertext, iv);
      
      console.log(`[ChallengeManager] Decrypted: ${decrypted}`);
      console.log(`[ChallengeManager] Expected: ${stored.challenge}`);
      
      if (decrypted === stored.challenge) {
        // Success - remove challenge and return auth token
        this.store.remove(pubkey);
        
        // Generate auth token
        const token = this.generateAuthToken(pubkey);
        
        console.log('[ChallengeManager] Challenge verified successfully');
        const canonicalIdentifier = normalizeRelayIdentifier(stored.identifier);
        return {
          success: true,
          token,
          identifier: canonicalIdentifier
        };
      } else {
        console.error('[ChallengeManager] Challenge mismatch');
        return {
          success: false,
          error: 'Challenge verification failed'
        };
      }
      
    } catch (error) {
      console.error(`[ChallengeManager] Verification error:`, error);
      return {
        success: false,
        error: `Verification error: ${error.message}`
      };
    }
  }
  
  /**
   * AES decrypt using the shared secret
   * @param {Buffer} keyBuffer - 32-byte key
   * @param {string} ciphertext - Base64 encoded ciphertext
   * @param {string} ivBase64 - Base64 encoded IV
   * @returns {string} - Decrypted text
   */
  aesDecrypt(keyBuffer, ciphertext, ivBase64) {
    const iv = b4a.from(ivBase64, 'base64');
    const ciphertextBuffer = b4a.from(ciphertext, 'base64');
    
    // Use the AES implementation from pure-secp256k1.js
    const decrypted = nobleSecp256k1.aes.decrypt(ciphertextBuffer, keyBuffer, iv);
    
    // Convert to string
    return b4a.toString(decrypted, 'utf8');
  }
  
  /**
   * Generate authentication token
   * @param {string} pubkey - User's public key
   * @returns {string} - Auth token
   */
  generateAuthToken(pubkey) {
    const secret = this.relayPrivateKey; // Use relay private key as secret
    const data = secret + pubkey + Date.now();
    return crypto.createHash('sha256').update(data).digest('hex');
  }
  
  /**
   * Cleanup
   */
  destroy() {
    this.store.destroy();
  }
}

// Export a singleton instance manager
let managerInstance = null;

export function initializeChallengeManager(relayPrivateKey) {
  if (managerInstance) {
    managerInstance.destroy();
  }
  managerInstance = new ChallengeManager(relayPrivateKey);
  return managerInstance;
}

export function getChallengeManager() {
  if (!managerInstance) {
    throw new Error('ChallengeManager not initialized');
  }
  return managerInstance;
}

function deriveSharedKey(senderPrivkeyHex, recipientPubkeyHex) {
  if (!senderPrivkeyHex || !recipientPubkeyHex) {
    throw new Error('Missing keys for shared secret derivation');
  }

  let sharedSecret = nobleSecp256k1.getSharedSecret(
    senderPrivkeyHex,
    `02${recipientPubkeyHex}`,
    true
  );

  if (sharedSecret.length === 33) {
    sharedSecret = sharedSecret.slice(1);
  }

  return b4a.from(sharedSecret);
}

export function encryptWithSharedSecret(senderPrivkeyHex, recipientPubkeyHex, plaintext) {
  const keyBuffer = deriveSharedKey(senderPrivkeyHex, recipientPubkeyHex);
  const iv = crypto.randomBytes(16);
  const payload = b4a.from(String(plaintext ?? ''), 'utf8');
  const ciphertext = nobleSecp256k1.aes.encrypt(payload, keyBuffer, iv);

  return {
    ciphertext: b4a.toString(ciphertext, 'base64'),
    iv: iv.toString('base64')
  };
}

export function decryptWithSharedSecret(senderPrivkeyHex, recipientPubkeyHex, ciphertextBase64, ivBase64) {
  const keyBuffer = deriveSharedKey(senderPrivkeyHex, recipientPubkeyHex);
  const iv = b4a.from(ivBase64, 'base64');
  const cipherBuffer = b4a.from(ciphertextBase64, 'base64');
  const decrypted = nobleSecp256k1.aes.decrypt(cipherBuffer, keyBuffer, iv);
  return b4a.toString(decrypted, 'utf8');
}

export function encryptSharedSecretToString(senderPrivkeyHex, recipientPubkeyHex, plaintext) {
  const { ciphertext, iv } = encryptWithSharedSecret(senderPrivkeyHex, recipientPubkeyHex, plaintext);
  return `${ciphertext}?iv=${iv}`;
}

export function decryptSharedSecretFromString(senderPrivkeyHex, recipientPubkeyHex, payload) {
  if (typeof payload !== 'string') {
    throw new Error('Ciphertext payload must be a string');
  }

  const [ciphertext, iv] = payload.split('?iv=');
  if (!ciphertext || !iv) {
    throw new Error('Ciphertext payload missing IV segment');
  }

  return decryptWithSharedSecret(senderPrivkeyHex, recipientPubkeyHex, ciphertext, iv);
}
