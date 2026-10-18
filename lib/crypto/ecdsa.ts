/**
 * @file ecdsa.ts
 * @description WebCrypto ECDSA P-256 (FIPS 186-5) key generation, non-extractability enforcement,
 *              public key thumbprint derivation, digital signature, and verification.
 */

import { StoredECDSAKeyRecord, ECDSAIdentity } from './types';
import { STORES, getRecord, putRecord } from './db';

export const DEFAULT_ECDSA_KEY_ID = 'primary_device_ecdsa_p256';

/**
 * Utility: Convert ArrayBuffer to Hex string.
 */
export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Utility: Convert ArrayBuffer to Base64 string.
 */
export function bufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

/**
 * Derives a SHA-256 fingerprint (thumbprint) from an exported public key (SPKI).
 */
export async function computePublicKeyFingerprint(spkiBuffer: ArrayBuffer): Promise<string> {
  const digest = await window.crypto.subtle.digest('SHA-256', spkiBuffer);
  return bufferToHex(digest);
}

/**
 * Generates an ECDSA P-256 key pair with a strictly non-extractable private key.
 * 
 * Cryptographic Invariant:
 * - `extractable: false` prevents the private key from ever being exported as
 *   PKCS#8, JWK, or raw bytes into JavaScript runtime memory or external sinks.
 * - The public key remains extractable (`true` per W3C specification) to permit
 *   distribution (e.g. SPKI / X.509 / JWK) to verifiers.
 */
export async function generateNonExtractableECDSAKey(): Promise<CryptoKeyPair> {
  if (typeof window === 'undefined' || !window.crypto?.subtle) {
    throw new Error('WebCrypto subtle API is unavailable in this environment.');
  }

  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256', // ANSI X9.62 / NIST FIPS 186-5 / secp256r1
    },
    false, // extractable: false for private key
    ['sign', 'verify']
  );

  return keyPair;
}

/**
 * Formats a StoredECDSAKeyRecord into a public-safe ECDSAIdentity object.
 */
export function toECDSAIdentity(record: StoredECDSAKeyRecord): ECDSAIdentity {
  return {
    id: record.id,
    fingerprint: record.fingerprint,
    publicKeyBase64: record.publicKeyRawHex,
    publicKeyHex: record.publicKeyRawHex,
    createdAt: record.createdAt,
    isPrivateExtractable: record.keyPair.privateKey.extractable, // Always false
  };
}

/**
 * Initializes or loads the non-extractable ECDSA P-256 key pair from IndexedDB.
 * 
 * First Load Behavior:
 * 1. Checks IndexedDB for existing key under `keyId`.
 * 2. If absent:
 *    - Generates non-extractable CryptoKeyPair via `crypto.subtle.generateKey`.
 *    - Derives SPKI representation of the public key and its SHA-256 fingerprint.
 *    - Persists the live CryptoKeyPair directly into IndexedDB via Structured Clone.
 * 3. If present:
 *    - Reconstitutes the structured-cloned CryptoKeyPair.
 *    - Returns existing identity without re-generating.
 */
export async function getOrInitializeECDSAKey(
  keyId: string = DEFAULT_ECDSA_KEY_ID
): Promise<{ record: StoredECDSAKeyRecord; isFresh: boolean }> {
  // 1. Check existing record
  const existingRecord = await getRecord<StoredECDSAKeyRecord>(STORES.ECDSA, keyId);
  if (existingRecord) {
    return { record: existingRecord, isFresh: false };
  }

  // 2. Generate fresh non-extractable key pair
  const keyPair = await generateNonExtractableECDSAKey();

  // 3. Export public key as SPKI and raw uncompressed point for fingerprinting
  const spkiBuffer = await window.crypto.subtle.exportKey('spki', keyPair.publicKey);
  const rawPublicBuffer = await window.crypto.subtle.exportKey('raw', keyPair.publicKey);

  const fingerprint = await computePublicKeyFingerprint(spkiBuffer);
  const publicKeyRawHex = bufferToHex(rawPublicBuffer);

  const newRecord: StoredECDSAKeyRecord = {
    id: keyId,
    algorithm: 'ECDSA-P256',
    namedCurve: 'P-256',
    createdAt: Date.now(),
    fingerprint,
    publicKeyRawHex,
    keyPair,
  };

  // 4. Persist to IndexedDB via Structured Clone
  await putRecord(STORES.ECDSA, newRecord);

  return { record: newRecord, isFresh: true };
}

/**
 * Signs data using the non-extractable private key.
 * Signature is output in standard IEEE P1363 (r || s, 64 bytes) format.
 */
export async function signWithECDSA(
  privateKey: CryptoKey,
  data: BufferSource
): Promise<ArrayBuffer> {
  return window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    privateKey,
    data
  );
}

/**
 * Verifies an IEEE P1363 ECDSA signature against the public key.
 */
export async function verifyWithECDSA(
  publicKey: CryptoKey,
  signature: BufferSource,
  data: BufferSource
): Promise<boolean> {
  return window.crypto.subtle.verify(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    publicKey,
    signature,
    data
  );
}

/**
 * Security Assertion: Proves to callers / security auditors that the private key
 * is physically non-extractable from the browser execution context.
 * 
 * Returns true if export correctly throws a DOMException / OperationError.
 */
export async function testNonExtractability(privateKey: CryptoKey): Promise<{
  isNonExtractable: boolean;
  securityMessage: string;
}> {
  try {
    // Attempting export on a non-extractable key must fail per W3C specification
    await window.crypto.subtle.exportKey('pkcs8', privateKey);
    return {
      isNonExtractable: false,
      securityMessage: 'CRITICAL WARNING: Private key was extractable! Hardware/software isolation failed.',
    };
  } catch (err: unknown) {
    const error = err as DOMException;
    return {
      isNonExtractable: true,
      securityMessage: `Confirmed Non-Extractable: WebCrypto rejected export with ${error.name}: "${error.message}". Key is safely isolated.`,
    };
  }
}
