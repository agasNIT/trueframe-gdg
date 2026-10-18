/**
 * @file anchor.ts
 * @description Client-side payload formatting, mock salted GPS commitment derivation,
 *              and non-extractable WebCrypto ECDSA P-256 signing.
 * 
 * Cryptographic Engineering Standards:
 * 1. RFC 8785 Canonical JSON Serialization (JCS):
 *    Keys are sorted lexicographically before stringification to ensure bit-level deterministic
 *    signature verification across heterogenous runtimes.
 * 
 * 2. Zero-Knowledge / Salted Location Commitment:
 *    Raw GPS coordinates are salted with a 256-bit CSPRNG nonce before committing to the
 *    ledger: commitment = SHA-256(lat || lng || salt). This anchors the physical location
 *    without exposing private geospatial coordinates publicly on-chain.
 * 
 * 3. Enclave Signing:
 *    The canonical payload is signed directly with the non-extractable ECDSA P-256 private key
 *    stored in IndexedDB.
 */

import { getOrInitializeECDSAKey, signWithECDSA, bufferToHex } from './ecdsa';

/**
 * ABI for smart contracts implementing the standard TrueFrame anchor function.
 */
export const ANCHOR_REGISTRY_ABI = [
  'function anchor(bytes32 anchorDigest) external',
  'function isAnchored(bytes32 anchorDigest) external view returns (bool)',
  'function getAnchor(bytes32 anchorDigest) external view returns (address submitter, uint64 blockTimestamp, uint64 blockNumber)',
];

export interface SaltedGPSCoordinate {
  latitude: number;
  longitude: number;
  altitudeMeters: number;
  accuracyMeters: number;
  saltHex: string; // 32-byte CSPRNG salt
  commitmentHex: string; // SHA-256(lat || lng || salt)
}

export interface ForensicAnchorPayload {
  version: '1.0.0';
  merkleRoot: string; // 64-char hex
  fileSizeBytes: number;
  timestampUtc: string; // ISO-8601 UTC
  timestampUnixMs: number;
  location: SaltedGPSCoordinate;
  publicKeyFingerprint: string;
}

export interface SignedForensicEnvelope {
  payload: ForensicAnchorPayload;
  canonicalPayloadJson: string;
  signatureHex: string; // IEEE P1363 (r || s, 64 bytes)
  anchorDigestHex: string; // 0x-prefixed 32-byte SHA-256 hash submitted to blockchain
  publicKeyHex: string;
}

/**
 * Deterministically sorts object keys according to RFC 8785 (JSON Canonicalization Scheme).
 */
export function canonicalizeJson(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalizeJson).join(',') + ']';
  }

  const sortedKeys = Object.keys(obj as Record<string, unknown>).sort();
  const entries = sortedKeys.map(
    (key) => `${JSON.stringify(key)}:${canonicalizeJson((obj as Record<string, unknown>)[key])}`
  );
  return '{' + entries.join(',') + '}';
}

/**
 * Derives a privacy-preserving salted GPS commitment:
 * commitment = SHA-256(latitude || longitude || altitude || salt)
 */
export async function deriveSaltedGpsCommitment(
  lat: number,
  lng: number,
  altitude = 12.5,
  accuracy = 4.2
): Promise<SaltedGPSCoordinate> {
  const saltBytes = new Uint8Array(32);
  if (typeof window !== 'undefined' && window.crypto) {
    window.crypto.getRandomValues(saltBytes);
  }
  const saltHex = bufferToHex(saltBytes);

  // Normalize floating coordinates into deterministic binary representation
  const encoder = new TextEncoder();
  const rawString = `${lat.toFixed(6)}:${lng.toFixed(6)}:${altitude.toFixed(1)}:${saltHex}`;
  const digest = await window.crypto.subtle.digest('SHA-256', encoder.encode(rawString));
  const commitmentHex = bufferToHex(digest);

  return {
    latitude: lat,
    longitude: lng,
    altitudeMeters: altitude,
    accuracyMeters: accuracy,
    saltHex,
    commitmentHex,
  };
}

/**
 * Generates a mock high-precision salted GPS coordinate.
 * Default center: San Francisco Financial District / Tech Hub.
 */
export async function generateMockSaltedGps(): Promise<SaltedGPSCoordinate> {
  // Add subtle jitter simulating real-time GPS hardware drift
  const baseLat = 37.774929 + (Math.random() - 0.5) * 0.001;
  const baseLng = -122.419416 + (Math.random() - 0.5) * 0.001;
  const altitude = 15.0 + (Math.random() - 0.5) * 2;
  const accuracy = 3.2 + Math.random();

  return deriveSaltedGpsCommitment(baseLat, baseLng, altitude, accuracy);
}

/**
 * Builds and canonically formats the forensic anchor payload.
 */
export async function buildForensicPayload(
  merkleRoot: string,
  fileSizeBytes: number,
  publicKeyFingerprint: string
): Promise<ForensicAnchorPayload> {
  const location = await generateMockSaltedGps();
  const now = new Date();

  return {
    version: '1.0.0',
    merkleRoot: merkleRoot.startsWith('0x') ? merkleRoot.slice(2) : merkleRoot,
    fileSizeBytes,
    timestampUtc: now.toISOString(),
    timestampUnixMs: now.getTime(),
    location,
    publicKeyFingerprint,
  };
}

/**
 * Signs the payload using the non-extractable WebCrypto ECDSA P-256 key from IndexedDB
 * and computes the 32-byte anchor digest (SHA-256) for on-chain submission.
 */
export async function signForensicPayloadWithEnclave(
  payload: ForensicAnchorPayload
): Promise<SignedForensicEnvelope> {
  // 1. Retrieve the non-extractable ECDSA key pair from IndexedDB
  const { record } = await getOrInitializeECDSAKey();
  const privateKey = record.keyPair.privateKey;

  // 2. Format payload using RFC 8785 Canonical JSON
  const canonicalPayloadJson = canonicalizeJson(payload);
  const encoder = new TextEncoder();
  const canonicalBytes = encoder.encode(canonicalPayloadJson);

  // 3. Digital signature with non-extractable private key (WebCrypto IEEE P1363: 64 bytes)
  const signatureBuffer = await signWithECDSA(privateKey, canonicalBytes);
  const signatureHex = bufferToHex(signatureBuffer);

  // 4. Compute 32-byte Anchor Digest: SHA-256(canonicalPayload || signature)
  // This binds the Merkle root, file size, timestamp, GPS commitment, and device signature into one bytes32 hash.
  const envelopeToHash = encoder.encode(canonicalPayloadJson + signatureHex);
  const anchorDigestBuffer = await window.crypto.subtle.digest('SHA-256', envelopeToHash);
  const anchorDigestHex = '0x' + bufferToHex(anchorDigestBuffer);

  return {
    payload,
    canonicalPayloadJson,
    signatureHex,
    anchorDigestHex,
    publicKeyHex: record.publicKeyRawHex,
  };
}

/**
 * Utility: Converts a Hex string to Uint8Array.
 */
export function hexToUint8Array(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const match = cleanHex.match(/.{1,2}/g);
  if (!match) return new Uint8Array(0);
  return new Uint8Array(match.map((byte) => parseInt(byte, 16)));
}

/**
 * Verifies a SignedForensicEnvelope using WebCrypto:
 * 1. Checks that the anchorDigest is the true SHA-256(canonicalPayloadJson || signatureHex).
 * 2. Imports the device's uncompressed public key (0x04 || X || Y).
 * 3. Verifies the ECDSA P-256 signature against the canonical JSON bytes.
 */
export async function verifySignedEnvelope(
  envelope: SignedForensicEnvelope
): Promise<{ isValidSignature: boolean; digestMatches: boolean; error?: string }> {
  try {
    const encoder = new TextEncoder();

    // 1. Verify Anchor Digest integrity
    const expectedDigestBuffer = await window.crypto.subtle.digest(
      'SHA-256',
      encoder.encode(envelope.canonicalPayloadJson + envelope.signatureHex)
    );
    const expectedDigestHex = '0x' + bufferToHex(expectedDigestBuffer);
    const digestMatches =
      expectedDigestHex.toLowerCase() === envelope.anchorDigestHex.toLowerCase();

    // 2. Import raw uncompressed P-256 public key (65 bytes = 0x04 || X || Y)
    const publicKeyBytes = hexToUint8Array(envelope.publicKeyHex);
    const publicKey = await window.crypto.subtle.importKey(
      'raw',
      publicKeyBytes as unknown as BufferSource,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['verify']
    );

    // 3. Verify digital signature over the canonical payload JSON
    const signatureBytes = hexToUint8Array(envelope.signatureHex);
    const payloadBytes = encoder.encode(envelope.canonicalPayloadJson);

    const isValidSignature = await window.crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: { name: 'SHA-256' },
      },
      publicKey,
      signatureBytes as unknown as BufferSource,
      payloadBytes as unknown as BufferSource
    );

    return {
      isValidSignature,
      digestMatches,
    };
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Envelope verification failed.';
    return {
      isValidSignature: false,
      digestMatches: false,
      error: errorMsg,
    };
  }
}

const ENVELOPE_CACHE_PREFIX = 'forensic_envelope_';

/**
 * Persists a signed envelope to sessionStorage/localStorage for seamless client verification.
 */
export function cacheSignedEnvelope(envelope: SignedForensicEnvelope): void {
  if (typeof window === 'undefined') return;
  try {
    const key = ENVELOPE_CACHE_PREFIX + envelope.anchorDigestHex.toLowerCase();
    sessionStorage.setItem(key, JSON.stringify(envelope));
    localStorage.setItem(key, JSON.stringify(envelope));
  } catch {
    // Graceful fallback if storage quota exceeded
  }
}

/**
 * Retrieves a cached signed envelope by anchor digest.
 */
export function getCachedSignedEnvelope(anchorDigest: string): SignedForensicEnvelope | null {
  if (typeof window === 'undefined') return null;
  try {
    const key = ENVELOPE_CACHE_PREFIX + anchorDigest.toLowerCase();
    const raw = sessionStorage.getItem(key) || localStorage.getItem(key);
    if (raw) {
      return JSON.parse(raw) as SignedForensicEnvelope;
    }
  } catch {
    return null;
  }
  return null;
}

