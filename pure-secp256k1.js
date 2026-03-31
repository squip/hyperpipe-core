/**
 * pure-secp256k1.js
 * Pure JavaScript implementation with Schnorr signatures, ECDH, and AES-256-CBC
 */

import crypto from 'node:crypto';
import b4a from 'b4a';

// secp256k1 curve parameters
const CURVE = {
  p: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  Gy: 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n,
  a: 0n,
  b: 7n
};

// Modular arithmetic
const mod = (n, m = CURVE.p) => ((n % m) + m) % m;

const modInverse = (a, m = CURVE.p) => {
  let [old_r, r] = [a, m];
  let [old_s, s] = [1n, 0n];
  
  while (r !== 0n) {
    const quotient = old_r / r;
    [old_r, r] = [r, old_r - quotient * r];
    [old_s, s] = [s, old_s - quotient * s];
  }
  
  if (old_r !== 1n) throw new Error('No modular inverse');
  return mod(old_s, m);
};

const modPow = (base, exp, m) => {
  let result = 1n;
  base = mod(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m);
    exp >>= 1n;
    base = mod(base * base, m);
  }
  return result;
};

// Point operations
class Point {
  constructor(x, y) {
    this.x = x;
    this.y = y;
    this.infinity = x === null && y === null;
  }
  
  static ZERO = new Point(null, null);
  
  isZero() {
    return this.infinity;
  }
  
  equals(other) {
    if (this.isZero() && other.isZero()) return true;
    if (this.isZero() || other.isZero()) return false;
    return this.x === other.x && this.y === other.y;
  }
  
  negate() {
    if (this.isZero()) return this;
    return new Point(this.x, mod(-this.y));
  }
  
  double() {
    if (this.isZero()) return this;
    
    const { x, y } = this;
    const s = mod(3n * x * x * modInverse(2n * y));
    const x3 = mod(s * s - 2n * x);
    const y3 = mod(s * (x - x3) - y);
    
    return new Point(x3, y3);
  }
  
  add(other) {
    if (this.isZero()) return other;
    if (other.isZero()) return this;
    if (this.equals(other)) return this.double();
    if (this.x === other.x) return Point.ZERO;
    
    const dx = mod(other.x - this.x);
    const dy = mod(other.y - this.y);
    const s = mod(dy * modInverse(dx));
    const x3 = mod(s * s - this.x - other.x);
    const y3 = mod(s * (this.x - x3) - this.y);
    
    return new Point(x3, y3);
  }
  
  multiply(k) {
    if (k === 0n) return Point.ZERO;
    if (k === 1n) return this;
    
    let result = Point.ZERO;
    let base = this;
    
    while (k > 0n) {
      if (k & 1n) result = result.add(base);
      base = base.double();
      k >>= 1n;
    }
    
    return result;
  }
}

// Generator point
const G = new Point(CURVE.Gx, CURVE.Gy);

// Helper functions
function bytesToBigInt(bytes) {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

function bigIntToBytes(num, length = 32) {
  const bytes = new Uint8Array(length);
  let temp = num;
  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

function concatBytes(...arrays) {
  const totalLength = arrays.reduce((acc, arr) => acc + arr.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

// BIP340 tagged hash
function taggedHash(tag, ...data) {
  const tagHash = crypto.createHash('sha256').update(tag).digest();
  return crypto.createHash('sha256')
    .update(tagHash)
    .update(tagHash)
    .update(concatBytes(...data))
    .digest();
}

// Lift x to point
function liftX(x) {
  if (x >= CURVE.p) return null;
  
  const y2 = mod(x * x * x + CURVE.b);
  const y = modPow(y2, (CURVE.p + 1n) / 4n, CURVE.p);
  
  if (mod(y * y) !== y2) return null;
  
  // Always return the even y
  return new Point(x, y % 2n === 0n ? y : CURVE.p - y);
}

// Pure JavaScript AES-256-CBC implementation
class AES256CBC {
  constructor() {
    // AES S-box
    this.sbox = new Uint8Array([
      0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
      0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
      0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
      0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
      0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
      0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
      0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
      0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
      0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
      0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
      0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
      0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
      0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
      0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
      0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
      0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]);
    
    // Inverse S-box
    this.invSbox = new Uint8Array(256);
    for (let i = 0; i < 256; i++) {
      this.invSbox[this.sbox[i]] = i;
    }
    
    // Round constant
    this.rcon = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);
  }
  
  // Galois field multiplication
  gmul(a, b) {
    let p = 0;
    for (let i = 0; i < 8; i++) {
      if (b & 1) p ^= a;
      const hiBit = a & 0x80;
      a = (a << 1) & 0xff;
      if (hiBit) a ^= 0x1b;
      b >>= 1;
    }
    return p;
  }
  
  // Key expansion for AES-256
  expandKey(key) {
    const Nk = 8; // 256-bit key = 32 bytes = 8 words
    const Nr = 14; // Number of rounds for AES-256
    const Nb = 4; // Block size in words
    
    const w = new Uint32Array((Nr + 1) * Nb);
    
    // Copy key into first Nk words
    for (let i = 0; i < Nk; i++) {
      w[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
    }
    
    // Generate remaining words
    for (let i = Nk; i < (Nr + 1) * Nb; i++) {
      let temp = w[i - 1];
      
      if (i % Nk === 0) {
        // RotWord and SubWord
        temp = ((temp << 8) | (temp >>> 24)) >>> 0;
        temp = (this.sbox[(temp >>> 24) & 0xff] << 24) |
               (this.sbox[(temp >>> 16) & 0xff] << 16) |
               (this.sbox[(temp >>> 8) & 0xff] << 8) |
               this.sbox[temp & 0xff];
        temp ^= (this.rcon[(i / Nk) - 1] << 24);
      } else if (Nk > 6 && i % Nk === 4) {
        // SubWord for AES-256
        temp = (this.sbox[(temp >>> 24) & 0xff] << 24) |
               (this.sbox[(temp >>> 16) & 0xff] << 16) |
               (this.sbox[(temp >>> 8) & 0xff] << 8) |
               this.sbox[temp & 0xff];
      }
      
      w[i] = (w[i - Nk] ^ temp) >>> 0;
    }
    
    return w;
  }
  
  // Convert state array to/from matrix
  stateToMatrix(state) {
    const matrix = [];
    for (let c = 0; c < 4; c++) {
      matrix[c] = [];
      for (let r = 0; r < 4; r++) {
        matrix[c][r] = state[r * 4 + c];
      }
    }
    return matrix;
  }
  
  matrixToState(matrix) {
    const state = new Uint8Array(16);
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        state[r * 4 + c] = matrix[c][r];
      }
    }
    return state;
  }
  
  // AES round functions
  subBytes(state) {
    for (let i = 0; i < 16; i++) {
      state[i] = this.sbox[state[i]];
    }
  }
  
  invSubBytes(state) {
    for (let i = 0; i < 16; i++) {
      state[i] = this.invSbox[state[i]];
    }
  }
  
  shiftRows(state) {
    const s = this.stateToMatrix(state);
    const ns = [[],[],[],[]];
    
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        ns[c][r] = s[(c + r) % 4][r];
      }
    }
    
    return this.matrixToState(ns);
  }
  
  invShiftRows(state) {
    const s = this.stateToMatrix(state);
    const ns = [[],[],[],[]];
    
    for (let r = 0; r < 4; r++) {
      for (let c = 0; c < 4; c++) {
        ns[(c + r) % 4][r] = s[c][r];
      }
    }
    
    return this.matrixToState(ns);
  }
  
  mixColumns(state) {
    const s = this.stateToMatrix(state);
    const ns = [[],[],[],[]];
    
    for (let c = 0; c < 4; c++) {
      ns[c][0] = this.gmul(s[c][0], 2) ^ this.gmul(s[c][1], 3) ^ s[c][2] ^ s[c][3];
      ns[c][1] = s[c][0] ^ this.gmul(s[c][1], 2) ^ this.gmul(s[c][2], 3) ^ s[c][3];
      ns[c][2] = s[c][0] ^ s[c][1] ^ this.gmul(s[c][2], 2) ^ this.gmul(s[c][3], 3);
      ns[c][3] = this.gmul(s[c][0], 3) ^ s[c][1] ^ s[c][2] ^ this.gmul(s[c][3], 2);
    }
    
    return this.matrixToState(ns);
  }
  
  invMixColumns(state) {
    const s = this.stateToMatrix(state);
    const ns = [[],[],[],[]];
    
    for (let c = 0; c < 4; c++) {
      ns[c][0] = this.gmul(s[c][0], 14) ^ this.gmul(s[c][1], 11) ^ this.gmul(s[c][2], 13) ^ this.gmul(s[c][3], 9);
      ns[c][1] = this.gmul(s[c][0], 9) ^ this.gmul(s[c][1], 14) ^ this.gmul(s[c][2], 11) ^ this.gmul(s[c][3], 13);
      ns[c][2] = this.gmul(s[c][0], 13) ^ this.gmul(s[c][1], 9) ^ this.gmul(s[c][2], 14) ^ this.gmul(s[c][3], 11);
      ns[c][3] = this.gmul(s[c][0], 11) ^ this.gmul(s[c][1], 13) ^ this.gmul(s[c][2], 9) ^ this.gmul(s[c][3], 14);
    }
    
    return this.matrixToState(ns);
  }
  
  addRoundKey(state, roundKey) {
    for (let i = 0; i < 16; i++) {
      state[i] ^= roundKey[i];
    }
  }
  
  // Get round key from expanded key
  getRoundKey(w, round) {
    const key = new Uint8Array(16);
    for (let i = 0; i < 4; i++) {
      const word = w[round * 4 + i];
      key[i * 4] = (word >>> 24) & 0xff;
      key[i * 4 + 1] = (word >>> 16) & 0xff;
      key[i * 4 + 2] = (word >>> 8) & 0xff;
      key[i * 4 + 3] = word & 0xff;
    }
    return key;
  }
  
  // AES block cipher
  encryptBlock(input, expandedKey) {
    const state = new Uint8Array(input);
    const Nr = 14; // Number of rounds for AES-256
    
    // Initial round
    this.addRoundKey(state, this.getRoundKey(expandedKey, 0));
    
    // Main rounds
    for (let round = 1; round < Nr; round++) {
      this.subBytes(state);
      const shifted = this.shiftRows(state);
      const mixed = this.mixColumns(shifted);
      state.set(mixed);
      this.addRoundKey(state, this.getRoundKey(expandedKey, round));
    }
    
    // Final round
    this.subBytes(state);
    const shifted = this.shiftRows(state);
    state.set(shifted);
    this.addRoundKey(state, this.getRoundKey(expandedKey, Nr));
    
    return state;
  }
  
  decryptBlock(input, expandedKey) {
    const state = new Uint8Array(input);
    const Nr = 14; // Number of rounds for AES-256
    
    // Initial round
    this.addRoundKey(state, this.getRoundKey(expandedKey, Nr));
    
    // Main rounds
    for (let round = Nr - 1; round > 0; round--) {
      const shifted = this.invShiftRows(state);
      state.set(shifted);
      this.invSubBytes(state);
      this.addRoundKey(state, this.getRoundKey(expandedKey, round));
      const mixed = this.invMixColumns(state);
      state.set(mixed);
    }
    
    // Final round
    const shifted = this.invShiftRows(state);
    state.set(shifted);
    this.invSubBytes(state);
    this.addRoundKey(state, this.getRoundKey(expandedKey, 0));
    
    return state;
  }
  
  // CBC mode
  encrypt(plaintext, key, iv) {
    if (key.length !== 32) throw new Error('Key must be 32 bytes for AES-256');
    if (iv.length !== 16) throw new Error('IV must be 16 bytes');
    
    const expandedKey = this.expandKey(key);
    let blocks = Math.ceil(plaintext.length / 16);
    if (plaintext.length % 16 === 0) {
      blocks += 1;
    }
    const padded = new Uint8Array(blocks * 16);
    padded.set(plaintext);

    // PKCS#7 padding
    const paddingLength = padded.length - plaintext.length;
    for (let i = plaintext.length; i < padded.length; i++) {
      padded[i] = paddingLength;
    }
    
    const ciphertext = new Uint8Array(padded.length);
    let previousBlock = iv;
    
    for (let i = 0; i < blocks; i++) {
      const block = padded.slice(i * 16, (i + 1) * 16);
      
      // XOR with previous ciphertext block (or IV for first block)
      for (let j = 0; j < 16; j++) {
        block[j] ^= previousBlock[j];
      }
      
      const encrypted = this.encryptBlock(block, expandedKey);
      ciphertext.set(encrypted, i * 16);
      previousBlock = encrypted;
    }
    
    return ciphertext;
  }
  
  decrypt(ciphertext, key, iv) {
    if (key.length !== 32) throw new Error('Key must be 32 bytes for AES-256');
    if (iv.length !== 16) throw new Error('IV must be 16 bytes');
    if (ciphertext.length % 16 !== 0) throw new Error('Ciphertext must be multiple of 16 bytes');
    
    const expandedKey = this.expandKey(key);
    const blocks = ciphertext.length / 16;
    const plaintext = new Uint8Array(ciphertext.length);
    let previousBlock = iv;
    
    for (let i = 0; i < blocks; i++) {
      const block = ciphertext.slice(i * 16, (i + 1) * 16);
      const decrypted = this.decryptBlock(block, expandedKey);
      
      // XOR with previous ciphertext block (or IV for first block)
      for (let j = 0; j < 16; j++) {
        decrypted[j] ^= previousBlock[j];
      }
      
      plaintext.set(decrypted, i * 16);
      previousBlock = block;
    }
    
    // Remove PKCS#7 padding
    const paddingLength = plaintext[plaintext.length - 1];
    return plaintext.slice(0, plaintext.length - paddingLength);
  }
}

// Main exports with Noble-compatible API
const nobleSecp256k1 = {
  utils: {
    randomPrivateKey: () => {
      let privKey;
      do {
        privKey = crypto.randomBytes(32);
        const k = bytesToBigInt(privKey);
        if (k > 0n && k < CURVE.n) return privKey;
      } while (true);
    },
    
    sha256: (data) => {
      return crypto.createHash('sha256').update(data).digest();
    },
    
    bytesToHex: (bytes) => {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    },
    
    hexToBytes: (hex) => {
      const bytes = new Uint8Array(hex.length / 2);
      for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
      }
      return bytes;
    }
  },
  
  getPublicKey: (privateKey, compressed = true) => {
    const privBytes = typeof privateKey === 'string' 
      ? nobleSecp256k1.utils.hexToBytes(privateKey)
      : privateKey;
    
    const k = bytesToBigInt(privBytes);
    if (k === 0n || k >= CURVE.n) {
      throw new Error('Invalid private key');
    }
    
    const point = G.multiply(k);
    const xBytes = bigIntToBytes(point.x);
    
    if (compressed) {
      const prefix = point.y % 2n === 0n ? 0x02 : 0x03;
      return concatBytes(new Uint8Array([prefix]), xBytes);
    } else {
      const yBytes = bigIntToBytes(point.y);
      return concatBytes(new Uint8Array([0x04]), xBytes, yBytes);
    }
  },
  
  // ECDH implementation
  getSharedSecret: (privateKey, publicKey) => {
    const privBytes = typeof privateKey === 'string' 
      ? nobleSecp256k1.utils.hexToBytes(privateKey)
      : privateKey;
    const pubBytes = typeof publicKey === 'string' 
      ? nobleSecp256k1.utils.hexToBytes(publicKey)
      : publicKey;
    
    const k = bytesToBigInt(privBytes);
    if (k === 0n || k >= CURVE.n) {
      throw new Error('Invalid private key');
    }
    
    // Parse public key
    let point;
    if (pubBytes.length === 33 && (pubBytes[0] === 0x02 || pubBytes[0] === 0x03)) {
      // Compressed public key
      const x = bytesToBigInt(pubBytes.slice(1));
      const lifted = liftX(x);
      if (!lifted) throw new Error('Invalid public key');
      
      // Check if we need to negate y based on prefix
      if ((lifted.y % 2n === 0n && pubBytes[0] === 0x03) || 
          (lifted.y % 2n === 1n && pubBytes[0] === 0x02)) {
        point = new Point(lifted.x, CURVE.p - lifted.y);
      } else {
        point = lifted;
      }
    } else if (pubBytes.length === 65 && pubBytes[0] === 0x04) {
      // Uncompressed public key
      const x = bytesToBigInt(pubBytes.slice(1, 33));
      const y = bytesToBigInt(pubBytes.slice(33, 65));
      point = new Point(x, y);
    } else if (pubBytes.length === 32) {
      // x-only public key (BIP340 style)
      const x = bytesToBigInt(pubBytes);
      const lifted = liftX(x);
      if (!lifted) throw new Error('Invalid public key');
      point = lifted;
    } else {
      throw new Error('Invalid public key format');
    }
    
    // Verify point is on curve
    const y2 = mod(point.x * point.x * point.x + CURVE.b);
    if (mod(point.y * point.y) !== y2) {
      throw new Error('Public key point not on curve');
    }
    
    // Compute shared secret: k * P
    const shared = point.multiply(k);
    if (shared.isZero()) {
      throw new Error('Invalid shared secret');
    }
    
    // Return x-coordinate as shared secret
    return bigIntToBytes(shared.x);
  },
  
  schnorr: {
    sign: async (messageHash, privateKey) => {
      const privBytes = typeof privateKey === 'string' 
        ? nobleSecp256k1.utils.hexToBytes(privateKey)
        : privateKey;
      const msgBytes = typeof messageHash === 'string' 
        ? nobleSecp256k1.utils.hexToBytes(messageHash)
        : messageHash;
      
      const d = bytesToBigInt(privBytes);
      if (d === 0n || d >= CURVE.n) {
        throw new Error('Invalid private key');
      }
      
      // Get public key point
      const P = G.multiply(d);
      
      // BIP340: Use the private key negated if the public key y is odd
      const d_ = P.y % 2n === 0n ? d : CURVE.n - d;
      
      // Generate deterministic nonce
      const aux = crypto.randomBytes(32);
      const t = d_ ^ bytesToBigInt(taggedHash('BIP0340/aux', aux));
      const rand = taggedHash('BIP0340/nonce', bigIntToBytes(t), bigIntToBytes(P.x), msgBytes);
      const k_ = mod(bytesToBigInt(rand), CURVE.n);
      
      if (k_ === 0n) {
        throw new Error('Failure to generate nonce');
      }
      
      // R = k'⋅G
      const R = G.multiply(k_);
      
      // BIP340: Use k negated if R.y is odd
      const k = R.y % 2n === 0n ? k_ : CURVE.n - k_;
      
      // e = int(hash(R.x || P.x || m)) mod n
      const e = mod(
        bytesToBigInt(taggedHash('BIP0340/challenge', bigIntToBytes(R.x), bigIntToBytes(P.x), msgBytes)),
        CURVE.n
      );
      
      // s = (k + ed') mod n
      const s = mod(k + e * d_, CURVE.n);
      
      // Signature: R.x || s
      return concatBytes(bigIntToBytes(R.x), bigIntToBytes(s));
    },
    
    verify: async (signature, messageHash, publicKey) => {
      try {
        const sigBytes = typeof signature === 'string' 
          ? nobleSecp256k1.utils.hexToBytes(signature)
          : signature;
        const msgBytes = typeof messageHash === 'string' 
          ? nobleSecp256k1.utils.hexToBytes(messageHash)
          : messageHash;
        const pubBytes = typeof publicKey === 'string' 
          ? nobleSecp256k1.utils.hexToBytes(publicKey)
          : publicKey;
        
        if (sigBytes.length !== 64) return false;
        
        const r = bytesToBigInt(sigBytes.slice(0, 32));
        const s = bytesToBigInt(sigBytes.slice(32, 64));
        
        if (r >= CURVE.p || s >= CURVE.n) return false;
        
        // Extract public key x-coordinate
        let Px;
        if (pubBytes.length === 32) {
          Px = bytesToBigInt(pubBytes);
        } else if (pubBytes.length === 33 && (pubBytes[0] === 0x02 || pubBytes[0] === 0x03)) {
          Px = bytesToBigInt(pubBytes.slice(1));
        } else {
          return false;
        }
        
        // Lift x to point P
        const P = liftX(Px);
        if (!P) return false;
        
        // e = int(hash(r || P.x || m)) mod n
        const e = mod(
          bytesToBigInt(taggedHash('BIP0340/challenge', bigIntToBytes(r), bigIntToBytes(P.x), msgBytes)),
          CURVE.n
        );
        
        // R = s⋅G - e⋅P
        const sG = G.multiply(s);
        const eP = P.multiply(e);
        const R = sG.add(eP.negate());
        
        // Verification: R ≠ ∞ ∧ R.y is even ∧ R.x = r
        if (R.isZero() || R.y % 2n !== 0n || R.x !== r) {
          return false;
        }
        
        return true;
      } catch (error) {
        return false;
      }
    }
  },
  
  // AES-256-CBC
  aes: {
    encrypt: (plaintext, key, iv) => {
      const aes = new AES256CBC();
      const plaintextBytes = typeof plaintext === 'string'
        ? b4a.from(plaintext, 'utf8')
        : plaintext;
      const keyBytes = typeof key === 'string' 
        ? nobleSecp256k1.utils.hexToBytes(key)
        : key;
      const ivBytes = typeof iv === 'string' 
        ? nobleSecp256k1.utils.hexToBytes(iv)
        : iv;
      
      return aes.encrypt(plaintextBytes, keyBytes, ivBytes);
    },
    
    decrypt: (ciphertext, key, iv) => {
      const aes = new AES256CBC();
      const ciphertextBytes = typeof ciphertext === 'string' 
        ? nobleSecp256k1.utils.hexToBytes(ciphertext)
        : ciphertext;
      const keyBytes = typeof key === 'string' 
        ? nobleSecp256k1.utils.hexToBytes(key)
        : key;
      const ivBytes = typeof iv === 'string' 
        ? nobleSecp256k1.utils.hexToBytes(iv)
        : iv;
      
      return aes.decrypt(ciphertextBytes, keyBytes, ivBytes);
    }
  }
};

export { nobleSecp256k1 };

console.log('Pure JavaScript secp256k1 with AES-256-CBC and ECDH loaded successfully');
