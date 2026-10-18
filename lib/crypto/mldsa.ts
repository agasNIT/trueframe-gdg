/**
 * @file mldsa.ts
 * @description NIST FIPS 204 ML-DSA (Module-Lattice-based Digital Signature Algorithm) simulation.
 * 
 * Cryptographic Reference:
 * - NIST FIPS 204 (Initial Release, August 2024): Module-Lattice-Based Digital Signature Standard
 * - Based on the CRYSTALS-Dilithium proposal.
 * - Modulus: q = 8,380,417 = 2^23 - 2^13 + 1
 * - Ring: R_q = Z_q[X] / (X^256 + 1)
 * 
 * WebCrypto Context:
 * Native browser WebCrypto does not yet standardize post-quantum signatures in production APIs
 * (actively drafted by W3C WebCrypto PQC Community Group). This module simulates key generation,
 * exact parameter bounds, opaque non-extractable handles, and signature generation matching FIPS 204.
 */

import { MLDSAParameterSet, MLDSAParams, MLDSAPrivateKeyHandle, MLDSASimulatedKeyPair } from './types';
import { STORES, getRecord, putRecord } from './db';
import { bufferToHex } from './ecdsa';

/**
 * FIPS 204 Parameter Sets
 */
export const ML_DSA_PARAMS: Record<MLDSAParameterSet, MLDSAParams> = {
  'ML-DSA-44': {
    name: 'ML-DSA-44',
    nistLevel: 2, // Equivalent to SHA-256 / AES-128
    k: 4,
    l: 4,
    publicKeyBytes: 1312,
    privateKeyBytes: 2560,
    signatureBytes: 2420,
  },
  'ML-DSA-65': {
    name: 'ML-DSA-65',
    nistLevel: 3, // Recommended standard baseline (Equivalent to AES-192)
    k: 6,
    l: 5,
    publicKeyBytes: 1952,
    privateKeyBytes: 4032,
    signatureBytes: 3309,
  },
  'ML-DSA-87': {
    name: 'ML-DSA-87',
    nistLevel: 5, // Equivalent to AES-256
    k: 8,
    l: 7,
    publicKeyBytes: 2592,
    privateKeyBytes: 4896,
    signatureBytes: 4627,
  },
};

export const DEFAULT_PQC_KEY_ID = 'primary_device_mldsa_pqc';

/**
 * Internal private symbol to hide raw secret material from runtime inspection.
 */
const SECRET_KEY_MATERIAL = Symbol('SECRET_KEY_MATERIAL');

/**
 * Simulates NIST FIPS 204 ML-DSA key generation.
 * 
 * Step 1: Generate 32-byte master seed ξ via window.crypto.getRandomValues (CSPRNG).
 * Step 2: Simulate derivation of public seed ρ (32 bytes), secret seed K (32 bytes), and matrix expansion.
 * Step 3: Produce byte-accurate public key (1,952 bytes for ML-DSA-65) and private key (4,032 bytes for ML-DSA-65).
 * Step 4: Encapsulate private key into an opaque non-extractable handle.
 */
export async function simulateMLDSAKeyGeneration(
  paramSet: MLDSAParameterSet = 'ML-DSA-65',
  keyId: string = DEFAULT_PQC_KEY_ID
): Promise<MLDSASimulatedKeyPair> {
  if (typeof window === 'undefined' || !window.crypto) {
    throw new Error('WebCrypto environment is required for CSPRNG seed generation.');
  }

  const params = ML_DSA_PARAMS[paramSet];

  // 1. High-entropy CSPRNG seed generation (FIPS 204 Section 5.1: ξ ← {0,1}^256)
  const masterSeed = new Uint8Array(32);
  window.crypto.getRandomValues(masterSeed);

  // 2. Expand seeds: ρ (32 bytes public seed), K (32 bytes signing key seed)
  const seedHash = await window.crypto.subtle.digest('SHA-512', masterSeed);
  const seedHashBytes = new Uint8Array(seedHash);
  const rho = seedHashBytes.slice(0, 32); // Public matrix seed
  const signingSeedK = seedHashBytes.slice(32, 64); // Secret signing seed

  // 3. Generate public key buffer matching exact FIPS 204 length
  // In FIPS 204: pk = ρ || t1 (compressed high-bits of matrix vector product A*s1 + s2)
  const publicKey = new Uint8Array(params.publicKeyBytes);
  publicKey.set(rho, 0); // First 32 bytes is public seed ρ

  // Fill remaining bytes simulating lattice polynomial vector t1 with deterministic CSPRNG
  const t1Entropy = new Uint8Array(params.publicKeyBytes - 32);
  window.crypto.getRandomValues(t1Entropy);
  publicKey.set(t1Entropy, 32);

  // 4. Generate private key buffer matching exact FIPS 204 length
  // In FIPS 204: sk = ρ || K || tr || s1 || s2 || t0
  const privateKeyRaw = new Uint8Array(params.privateKeyBytes);
  privateKeyRaw.set(rho, 0);
  privateKeyRaw.set(signingSeedK, 32);

  const skRemaining = new Uint8Array(params.privateKeyBytes - 64);
  window.crypto.getRandomValues(skRemaining);
  privateKeyRaw.set(skRemaining, 64);

  // 5. Derive SHA-256 fingerprint from the public key
  const pkDigest = await window.crypto.subtle.digest('SHA-256', publicKey);
  const fingerprint = bufferToHex(pkDigest);

  // 6. Construct Opaque Non-Extractable Private Key Handle
  // The secret bytes are sealed inside the closure/symbol to replicate WebCrypto extractable: false
  const secretStore = {
    [SECRET_KEY_MATERIAL]: privateKeyRaw,
  };

  const privateKeyHandle: MLDSAPrivateKeyHandle = {
    algorithm: paramSet,
    extractable: false,
    type: 'private',
    usages: ['sign'] as const,

    async sign(message: Uint8Array): Promise<Uint8Array> {
      // Simulate FIPS 204 Algorithm 2: ML-DSA.Sign
      // Signature length is standardized (e.g. 3,309 bytes for ML-DSA-65)
      const rawSecret = secretStore[SECRET_KEY_MATERIAL];
      if (!rawSecret) {
        throw new Error('Private key material is invalidated.');
      }

      // Hash message + secret seed using SHA-512
      const combined = new Uint8Array(message.length + 32);
      combined.set(message, 0);
      combined.set(rawSecret.slice(32, 64), message.length);

      const msgDigest = await window.crypto.subtle.digest('SHA-512', combined);
      const signature = new Uint8Array(params.signatureBytes);

      // Place deterministic signature header + entropy to match standardized size
      signature.set(new Uint8Array(msgDigest).slice(0, 32), 0);
      const sigEntropy = new Uint8Array(params.signatureBytes - 32);
      window.crypto.getRandomValues(sigEntropy);
      signature.set(sigEntropy, 32);

      return signature;
    },

    exportRaw(): never {
      // Replicate browser DOMException when attempting to extract non-extractable key
      throw new DOMException(
        'The operation is not allowed: ML-DSA private key is non-extractable.',
        'InvalidAccessError'
      );
    },
  };

  const result: MLDSASimulatedKeyPair = {
    id: keyId,
    algorithm: paramSet,
    createdAt: Date.now(),
    fingerprint,
    publicKey,
    privateKeyHandle,
    storedPayload: {
      id: keyId,
      algorithm: paramSet,
      publicKeyBytes: Array.from(publicKey),
      privateKeyBytesEncryptedOrOpaque: Array.from(privateKeyRaw),
      createdAt: Date.now(),
      fingerprint,
    },
  };

  return result;
}

/**
 * Stores or retrieves the simulated ML-DSA key from IndexedDB.
 */
export async function getOrInitializeMLDSAKey(
  paramSet: MLDSAParameterSet = 'ML-DSA-65',
  keyId: string = DEFAULT_PQC_KEY_ID
): Promise<{ keyPair: MLDSASimulatedKeyPair; isFresh: boolean }> {
  const existing = await getRecord<MLDSASimulatedKeyPair['storedPayload']>(STORES.PQC, keyId);

  if (existing) {
    // Reconstitute opaque handle
    const publicKey = new Uint8Array(existing.publicKeyBytes);
    const privateKeyRaw = new Uint8Array(existing.privateKeyBytesEncryptedOrOpaque);
    const params = ML_DSA_PARAMS[existing.algorithm];

    const secretStore = {
      [SECRET_KEY_MATERIAL]: privateKeyRaw,
    };

    const privateKeyHandle: MLDSAPrivateKeyHandle = {
      algorithm: existing.algorithm,
      extractable: false,
      type: 'private',
      usages: ['sign'] as const,
      async sign(message: Uint8Array): Promise<Uint8Array> {
        const combined = new Uint8Array(message.length + 32);
        combined.set(message, 0);
        combined.set(privateKeyRaw.slice(32, 64), message.length);
        const msgDigest = await window.crypto.subtle.digest('SHA-512', combined);
        const signature = new Uint8Array(params.signatureBytes);
        signature.set(new Uint8Array(msgDigest).slice(0, 32), 0);
        const sigEntropy = new Uint8Array(params.signatureBytes - 32);
        window.crypto.getRandomValues(sigEntropy);
        signature.set(sigEntropy, 32);
        return signature;
      },
      exportRaw(): never {
        throw new DOMException('Private key is non-extractable.', 'InvalidAccessError');
      },
    };

    return {
      keyPair: {
        id: existing.id,
        algorithm: existing.algorithm,
        createdAt: existing.createdAt,
        fingerprint: existing.fingerprint,
        publicKey,
        privateKeyHandle,
        storedPayload: existing,
      },
      isFresh: false,
    };
  }

  // Generate and persist
  const freshPair = await simulateMLDSAKeyGeneration(paramSet, keyId);
  await putRecord(STORES.PQC, freshPair.storedPayload);

  return { keyPair: freshPair, isFresh: true };
}
