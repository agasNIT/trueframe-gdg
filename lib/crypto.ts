import localforage from 'localforage';
export * from './crypto/index';

/**
 * Storage key identifier for persisting the TrueFrame device CryptoKeyPair.
 */
const DEVICE_KEY_STORAGE_KEY = 'trueframe_device_keypair';

/**
 * Utility: Converts an ArrayBuffer or Uint8Array into a lowercase hexadecimal string.
 */
function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Retrieves an existing non-extractable ECDSA P-256 key pair from localforage,
 * or generates and persists a new one on first load per the TrueFrame specification.
 *
 * Cryptographic Attributes:
 * - Algorithm: ECDSA
 * - Named Curve: P-256 (FIPS 186-5 / secp256r1)
 * - Extractable: false (Hardware / browser sandbox sealed private key)
 * - Key Usages: ['sign', 'verify']
 *
 * @returns Promise<CryptoKeyPair> The loaded or newly generated CryptoKeyPair.
 */
export async function getOrCreateDeviceKey(): Promise<CryptoKeyPair> {
  if (typeof window === 'undefined' || !window.crypto?.subtle) {
    throw new Error('WebCrypto API (window.crypto.subtle) is only available in a browser execution environment.');
  }

  // 1. Check localforage for existing CryptoKeyPair
  const existingKey = await localforage.getItem<CryptoKeyPair>(DEVICE_KEY_STORAGE_KEY);
  if (existingKey?.privateKey && existingKey?.publicKey) {
    return existingKey;
  }

  // 2. Generate non-extractable ECDSA P-256 key pair
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256',
    },
    false, // extractable: false seals the private key permanently
    ['sign', 'verify']
  );

  // 3. Persist CryptoKeyPair directly into IndexedDB via localforage structured clone
  await localforage.setItem(DEVICE_KEY_STORAGE_KEY, keyPair);

  return keyPair;
}

/**
 * Exports an ECDSA P-256 public key as a SubjectPublicKeyInfo (SPKI) hexadecimal string.
 *
 * @param publicKey The CryptoKey public key to export.
 * @returns Promise<string> Hexadecimal representation of the SPKI byte sequence.
 */
export async function exportPublicKeyHex(publicKey: CryptoKey): Promise<string> {
  if (typeof window === 'undefined' || !window.crypto?.subtle) {
    throw new Error('WebCrypto API (window.crypto.subtle) is only available in a browser execution environment.');
  }

  const spkiBuffer = await window.crypto.subtle.exportKey('spki', publicKey);
  return bufferToHex(spkiBuffer);
}

/**
 * Recursively sorts object keys alphabetically to guarantee deterministic JSON serialization
 * adhering to the RFC 8785 JSON Canonicalization Scheme (JCS).
 *
 * @param obj The object or record to canonicalize.
 * @returns string Deterministic, canonical JSON string.
 */
export function canonicalStringify(obj: Record<string, any>): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return `[${obj.map((item) => canonicalStringify(item)).join(',')}]`;
  }

  const sortedKeys = Object.keys(obj).sort();
  const entries = sortedKeys.map((key) => {
    const value = obj[key];
    return `${JSON.stringify(key)}:${canonicalStringify(value)}`;
  });

  return `{${entries.join(',')}}`;
}

/**
 * Converts a canonical JSON payload to UTF-8 bytes, signs it using ECDSA SHA-256
 * with the non-extractable device private key, and returns the signature in hexadecimal format (IEEE P1363).
 *
 * @param payload The JavaScript object representing the payload to sign.
 * @param privateKey The non-extractable ECDSA P-256 private CryptoKey.
 * @returns Promise<string> Hexadecimal representation of the digital signature.
 */
export async function signPayload(payload: object, privateKey: CryptoKey): Promise<string> {
  if (typeof window === 'undefined' || !window.crypto?.subtle) {
    throw new Error('WebCrypto API (window.crypto.subtle) is only available in a browser execution environment.');
  }

  // 1. Deterministic JSON serialization
  const canonicalJson = canonicalStringify(payload as Record<string, any>);

  // 2. UTF-8 byte encoding
  const encoder = new TextEncoder();
  const data = encoder.encode(canonicalJson);

  // 3. Digital signature with WebCrypto ECDSA SHA-256
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' },
    },
    privateKey,
    data
  );

  // 4. Return as hexadecimal string
  return bufferToHex(signatureBuffer);
}


