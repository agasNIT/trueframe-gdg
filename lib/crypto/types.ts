/**
 * @file types.ts
 * @description Cryptographic types and interfaces for WebCrypto ECDSA P-256 and NIST FIPS 204 ML-DSA.
 */

/**
 * Standard ECDSA P-256 (FIPS 186-5 / secp256r1) key record stored in IndexedDB.
 */
export interface StoredECDSAKeyRecord {
  id: string;
  algorithm: 'ECDSA-P256';
  namedCurve: 'P-256';
  createdAt: number;
  fingerprint: string; // SHA-256 hex thumbprint of the SPKI public key
  publicKeyRawHex: string; // Hex representation of uncompressed (0x04 || X || Y) public key
  keyPair: CryptoKeyPair; // Directly stored via HTML Structured Clone Algorithm (privateKey.extractable === false)
}

/**
 * Public exportable representation of an ECDSA P-256 key for distribution.
 */
export interface ECDSAIdentity {
  id: string;
  fingerprint: string;
  publicKeyBase64: string;
  publicKeyHex: string;
  createdAt: number;
  isPrivateExtractable: boolean; // Always false for secure enclave storage
}

/**
 * Supported ML-DSA (Module-Lattice-based Digital Signature Algorithm) parameter sets per NIST FIPS 204.
 */
export type MLDSAParameterSet = 'ML-DSA-44' | 'ML-DSA-65' | 'ML-DSA-87';

export interface MLDSAParams {
  name: MLDSAParameterSet;
  nistLevel: number;
  k: number; // Polynomial matrix rows
  l: number; // Polynomial matrix columns
  publicKeyBytes: number; // Size in bytes (1312, 1952, 2592)
  privateKeyBytes: number; // Size in bytes (2560, 4032, 4896)
  signatureBytes: number; // Size in bytes (2420, 3309, 4627)
}

/**
 * High-level opaque handle for a simulated non-extractable ML-DSA private key.
 * Mimics WebCrypto CryptoKey behavior by refusing raw material extraction.
 */
export interface MLDSAPrivateKeyHandle {
  readonly algorithm: MLDSAParameterSet;
  readonly extractable: false;
  readonly type: 'private';
  readonly usages: readonly ['sign'];
  /**
   * Internal sign operation without revealing secret matrix / polynomial coefficients.
   */
  sign(message: Uint8Array): Promise<Uint8Array>;
  /**
   * Throws DOMException mirroring WebCrypto non-extractable CryptoKey behavior.
   */
  exportRaw(): never;
}

/**
 * Full ML-DSA Post-Quantum Key Pair.
 */
export interface MLDSASimulatedKeyPair {
  id: string;
  algorithm: MLDSAParameterSet;
  createdAt: number;
  fingerprint: string; // SHA-256 thumbprint of the public key
  publicKey: Uint8Array; // Concrete public key vector bytes
  privateKeyHandle: MLDSAPrivateKeyHandle;
  // Opaque payload for storage in IndexedDB
  storedPayload: {
    id: string;
    algorithm: MLDSAParameterSet;
    publicKeyBytes: number[];
    privateKeyBytesEncryptedOrOpaque: number[];
    createdAt: number;
    fingerprint: string;
  };
}

/**
 * State of the client-side cryptographic subsystem.
 */
export interface CryptoSubsystemState {
  isInitialized: boolean;
  isLoading: boolean;
  error: string | null;
  ecdsaIdentity: ECDSAIdentity | null;
  pqcIdentity: {
    id: string;
    algorithm: MLDSAParameterSet;
    fingerprint: string;
    publicKeyHex: string;
    createdAt: number;
  } | null;
}
