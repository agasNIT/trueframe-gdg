/**
 * @file index.ts
 * @description Primary cryptographic orchestration facade.
 * 
 * Provides unified lifecycle management for:
 * 1. Hardware/sandbox-isolated ECDSA P-256 WebCrypto key pair.
 * 2. NIST FIPS 204 ML-DSA post-quantum lattice-based key pair simulation.
 * 3. Client-side IndexedDB persistence on first load.
 */

import { getOrInitializeECDSAKey, toECDSAIdentity, testNonExtractability, signWithECDSA, verifyWithECDSA, bufferToHex } from './ecdsa';
import { getOrInitializeMLDSAKey, simulateMLDSAKeyGeneration, ML_DSA_PARAMS } from './mldsa';
import { StoredECDSAKeyRecord, MLDSASimulatedKeyPair, ECDSAIdentity, MLDSAParameterSet } from './types';

export * from './types';
export * from './db';
export * from './ecdsa';
export * from './mldsa';
export * from './anchor';

export interface CryptoEngineSession {
  ecdsaRecord: StoredECDSAKeyRecord;
  ecdsaIdentity: ECDSAIdentity;
  pqcKeyPair: MLDSASimulatedKeyPair;
  isFirstLoad: boolean;
  nonExtractableVerified: boolean;
  securityMessage: string;
}

/**
 * Initializes the cryptographic subsystem on first load:
 * - Bootstraps or restores non-extractable ECDSA P-256 key pair from IndexedDB.
 * - Asserts cryptographic non-extractability.
 * - Bootstraps or restores simulated NIST FIPS 204 ML-DSA-65 post-quantum key pair.
 */
export async function initializeCryptoSubsystem(): Promise<CryptoEngineSession> {
  if (typeof window === 'undefined') {
    throw new Error('initializeCryptoSubsystem must be invoked in a browser client runtime.');
  }

  // 1. Initialize / retrieve ECDSA P-256 key
  const { record: ecdsaRecord, isFresh: isECDSAFresh } = await getOrInitializeECDSAKey();
  const ecdsaIdentity = toECDSAIdentity(ecdsaRecord);

  // 2. Perform security audit check on private key extractability
  const extractionAudit = await testNonExtractability(ecdsaRecord.keyPair.privateKey);

  // 3. Initialize / retrieve Post-Quantum ML-DSA-65 key
  const { keyPair: pqcKeyPair, isFresh: isPQCFresh } = await getOrInitializeMLDSAKey('ML-DSA-65');

  return {
    ecdsaRecord,
    ecdsaIdentity,
    pqcKeyPair,
    isFirstLoad: isECDSAFresh || isPQCFresh,
    nonExtractableVerified: extractionAudit.isNonExtractable,
    securityMessage: extractionAudit.securityMessage,
  };
}

/**
 * High-level helper: Sign a text string using the device's non-extractable ECDSA P-256 key.
 */
export async function signTextMessage(
  text: string,
  privateKey: CryptoKey
): Promise<{ signatureHex: string; signatureBytes: Uint8Array }> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const signatureBuffer = await signWithECDSA(privateKey, data);
  const signatureBytes = new Uint8Array(signatureBuffer);
  return {
    signatureHex: bufferToHex(signatureBytes),
    signatureBytes,
  };
}

/**
 * High-level helper: Verify a text string signature using the ECDSA P-256 public key.
 */
export async function verifyTextMessage(
  text: string,
  signatureBytes: Uint8Array,
  publicKey: CryptoKey
): Promise<boolean> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  return verifyWithECDSA(
    publicKey,
    signatureBytes as unknown as BufferSource,
    data as unknown as BufferSource
  );
}

/**
 * High-level helper: Sign a text message using the simulated ML-DSA post-quantum key.
 */
export async function signTextWithMLDSA(
  text: string,
  keyPair: MLDSASimulatedKeyPair
): Promise<{ signatureHex: string; byteLength: number }> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const sig = await keyPair.privateKeyHandle.sign(data);
  return {
    signatureHex: bufferToHex(sig),
    byteLength: sig.length,
  };
}
