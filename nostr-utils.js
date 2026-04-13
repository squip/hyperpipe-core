/**
 * NostrUtils.js
 * Core utilities for nostr operations
 * Using nobleSecp256k1 for cryptography
 */

// Import from local module if available, otherwise try window object
import { nobleSecp256k1 } from './crypto-libraries.js';
import { schnorr as nobleSchnorr } from '@noble/curves/secp256k1.js';
import b4a from 'b4a';

export class NostrUtils {
    static normalizeBytes(value, label = 'value') {
        if (value instanceof Uint8Array) {
            return value;
        }
        if (Buffer.isBuffer(value)) {
            return new Uint8Array(value);
        }
        if (typeof value === 'string') {
            const normalized = value.trim().toLowerCase();
            if (!normalized.length || normalized.length % 2 !== 0 || /[^a-f0-9]/i.test(normalized)) {
                throw new Error(`Invalid ${label}: expected hex string`);
            }
            return this.hexToBytes(normalized);
        }
        throw new Error(`Invalid ${label}: expected Uint8Array or hex string`);
    }

    /**
     * Bech32 helpers (minimal BIP-173 implementation)
     */
    static bech32Charset() {
        return 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    }

    static bech32Polymod(values) {
        const GENERATOR = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        let chk = 1;
        for (const value of values) {
            const top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ value;
            for (let i = 0; i < 5; i += 1) {
                if ((top >> i) & 1) chk ^= GENERATOR[i];
            }
        }
        return chk;
    }

    static bech32HrpExpand(hrp) {
        const ret = [];
        for (let i = 0; i < hrp.length; i += 1) {
            ret.push(hrp.charCodeAt(i) >> 5);
        }
        ret.push(0);
        for (let i = 0; i < hrp.length; i += 1) {
            ret.push(hrp.charCodeAt(i) & 31);
        }
        return ret;
    }

    static bech32CreateChecksum(hrp, data) {
        const values = this.bech32HrpExpand(hrp).concat(data);
        values.push(0, 0, 0, 0, 0, 0);
        const mod = this.bech32Polymod(values) ^ 1;
        const ret = [];
        for (let p = 0; p < 6; p += 1) {
            ret.push((mod >> (5 * (5 - p))) & 31);
        }
        return ret;
    }

    static bech32Encode(hrp, data) {
        const combined = data.concat(this.bech32CreateChecksum(hrp, data));
        const charset = this.bech32Charset();
        let ret = `${hrp}1`;
        for (const value of combined) {
            ret += charset[value];
        }
        return ret;
    }

    static convertBits(data, from, to, pad) {
        let acc = 0;
        let bits = 0;
        const ret = [];
        const maxv = (1 << to) - 1;
        for (const value of data) {
            if (value < 0 || (value >> from) !== 0) return null;
            acc = (acc << from) | value;
            bits += from;
            while (bits >= to) {
                bits -= to;
                ret.push((acc >> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0) {
                ret.push((acc << (to - bits)) & maxv);
            }
        } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
            return null;
        }
        return ret;
    }

    /**
     * Convert hex string to Uint8Array
     * @param {string} hex - Hex string
     * @returns {Uint8Array}
     */
    static hexToBytes(hex) {
        const normalized = String(hex || '').trim();
        if (!normalized.length || normalized.length % 2 !== 0 || /[^a-f0-9]/i.test(normalized)) {
            throw new Error('Invalid hex string');
        }
        return new Uint8Array(
            (normalized.match(/.{1,2}/g) || []).map(byte => parseInt(byte, 16))
        );
    }
    
    /**
     * Convert Uint8Array to hex string
     * @param {Uint8Array} bytes - Bytes to convert
     * @returns {string} - Hex string
     */
    static bytesToHex(bytes) {
        return Array.from(bytes)
            .map(byte => byte.toString(16).padStart(2, '0'))
            .join('');
    }

    /**
     * Convert hex public key to npub format
     * @param {string} hex - Hex encoded public key
     * @returns {string} - Bech32 encoded npub string
     */
    static hexToNpub(hex) {
        try {
            const bytes = this.hexToBytes(hex);
            const words = this.convertBits(bytes, 8, 5, true);
            if (!words) throw new Error('Invalid hex for npub');
            return this.bech32Encode('npub', words);
        } catch (e) {
            console.error('Error encoding npub:', e);
            return null;
        }
    }

    /**
     * Convert hex private key to nsec format
     * @param {string} hex - Hex encoded private key
     * @returns {string} - Bech32 encoded nsec string
     */
    static hexToNsec(hex) {
        try {
            const bytes = this.hexToBytes(hex);
            const words = this.convertBits(bytes, 8, 5, true);
            if (!words) throw new Error('Invalid hex for nsec');
            return this.bech32Encode('nsec', words);
        } catch (e) {
            console.error('Error encoding nsec:', e);
            return null;
        }
    }
    
    /**
     * Generate a new private key
     * @returns {string} - Hex-encoded private key
     */
    static generatePrivateKey() {
        // Access nobleSecp256k1 from either the import or window global
        const secp = nobleSecp256k1;
        if (!secp) {
            throw new Error('Noble Secp256k1 library not available');
        }
        return this.bytesToHex(secp.utils.randomPrivateKey());
    }
    
    /**
     * Get public key from private key
     * @param {string} privateKey - Hex-encoded private key
     * @returns {string} - Hex-encoded public key (without compression prefix)
     */
    static getPublicKey(privateKey) {
        const privateKeyBytes = this.normalizeBytes(privateKey, 'private key');
        if (nobleSchnorr?.getPublicKey) {
            const pubKeyBytes = nobleSchnorr.getPublicKey(privateKeyBytes);
            return this.bytesToHex(pubKeyBytes);
        }

        // Fallback to local secp implementation if noble schnorr is unavailable
        const secp = nobleSecp256k1;
        if (!secp) {
            throw new Error('Noble Secp256k1 library not available');
        }

        // Get the compressed public key (33 bytes)
        const pubKeyBytes = secp.getPublicKey(privateKeyBytes, true);

        // Convert to hex and remove the compression prefix (first 2 hex chars)
        // This returns only the x-coordinate (32 bytes = 64 hex chars)
        const pubKeyHex = this.bytesToHex(pubKeyBytes);
        return pubKeyHex.substring(2);
    }
    
    /**
     * Sign an event with a private key
     * @param {Object} event - Unsigned event
     * @param {string} privateKey - Private key
     * @returns {Promise<Object>} - Signed event
     */
    static async signEvent(event, privateKey) {
        // Prepare the event for signing
        const eventData = JSON.stringify([
            0,
            event.pubkey,
            event.created_at,
            event.kind,
            event.tags,
            event.content
        ]);
        
        // Generate the event ID (sha256 returns Uint8Array)
        const secp = nobleSecp256k1;
        if (!secp) {
            throw new Error('Noble Secp256k1 library not available');
        }
        const hashBytes = await secp.utils.sha256(
            b4a.from(eventData, 'utf8')
        );
        event.id = this.bytesToHex(hashBytes);
        
        if (!nobleSchnorr?.sign) {
            throw new Error('Noble Schnorr signer not available');
        }

        // Sign the event (schnorr.sign returns Uint8Array)
        const sigBytes = await nobleSchnorr.sign(
            this.normalizeBytes(event.id, 'event id'),
            this.normalizeBytes(privateKey, 'private key')
        );
        event.sig = this.bytesToHex(sigBytes);
        
        return event;
    }
    
    /**
     * Verify an event signature
     * @param {Object} event - Signed event
     * @returns {Promise<boolean>} - Whether the signature is valid
     */
    static async verifySignature(event) {
        try {
            if (!nobleSchnorr?.verify) {
                throw new Error('Noble Schnorr verifier not available');
            }
            
            // Recreate the event ID
            const eventData = JSON.stringify([
                0,
                event.pubkey,
                event.created_at,
                event.kind,
                event.tags,
                event.content
            ]);
            
            const secp = nobleSecp256k1;
            if (!secp) {
                throw new Error('Noble Secp256k1 library not available');
            }
            const hashBytes = await secp.utils.sha256(
                b4a.from(eventData, 'utf8')
            );
            const id = this.bytesToHex(hashBytes);
            
            // Check if the ID matches
            if (id !== event.id) {
                return false;
            }
            
            // Verify the signature
            // Note: Schnorr signatures in Nostr use x-only pubkeys (32 bytes)
            // So we don't need to add the '02' prefix
            return nobleSchnorr.verify(
                this.normalizeBytes(event.sig, 'signature'),
                this.normalizeBytes(event.id, 'event id'),
                this.normalizeBytes(event.pubkey, 'pubkey')
            );
        } catch (error) {
            console.error('Error verifying signature:', error);
            return false;
        }
    }
    
    /**
     * Convert base64 to hex
     * @param {string} str - Base64 string
     * @returns {string} - Hex string
     */
    static base64ToHex(str) {
        var raw = atob(str);
        var result = '';
        for (var i = 0; i < raw.length; i++) {
            var hex = raw.charCodeAt(i).toString(16);
            result += (hex.length === 2 ? hex : '0' + hex);
        }
        return result;
    }
    
    /**
     * Format timestamp to human-readable time
     * @param {number} timestamp - Unix timestamp
     * @returns {string} - Formatted time string
     */
    static formatTime(timestamp) {
        const date = new Date(timestamp * 1000);
        return date.toLocaleString();
    }
    
    /**
     * Truncate pubkey for display
     * @param {string} pubkey - Public key
     * @returns {string} - Truncated public key
     */
    static truncatePubkey(pubkey) {
        if (!pubkey) return '';
        return pubkey.substring(0, 6) + '...' + pubkey.substring(pubkey.length - 4);
    }
    
    /**
     * Generate a random ID (for group IDs, etc.)
     * @returns {string} - Random ID
     */
    static generateRandomId() {
        const chars = 'abcdefghijklmnopqrstuvwxyz0123456789-_';
        let result = '';
        for (let i = 0; i < 12; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }
    
    /**
     * Generate a random invite code
     * @returns {string} - Invite code
     */
    static generateInviteCode() {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        let result = '';
        for (let i = 0; i < 10; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return result;
    }
    
    /**
     * Get previous event references for timeline threading
     * @param {Array} events - Array of events
     * @param {string} currentPubkey - Current user's pubkey
     * @returns {Array} - Array of event IDs to reference
     */
    static getPreviousEventRefs(events, currentPubkey) {
        // Get last 50 events excluding the current user's events
        const filteredEvents = events
            .filter(e => e.pubkey !== currentPubkey)
            .sort((a, b) => b.created_at - a.created_at)
            .slice(0, 50);
        
        // Take 3 random events from those or all if less than 3
        const numRefs = Math.min(3, filteredEvents.length);
        const refs = [];
        
        // If we have less than 3 events, use all of them
        if (filteredEvents.length <= 3) {
            refs.push(...filteredEvents.map(e => e.id.substring(0, 8)));
        } else {
            // Otherwise pick 3 random ones
            const indices = new Set();
            while (indices.size < numRefs) {
                indices.add(Math.floor(Math.random() * filteredEvents.length));
            }
            
            indices.forEach(index => {
                refs.push(filteredEvents[index].id.substring(0, 8));
            });
        }
        
        return refs;
    }
}
