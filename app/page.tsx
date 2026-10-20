'use client';

/**
 * @file app/page.tsx
 * @description High-assurance Cryptographic Dashboard demonstrating non-extractable WebCrypto ECDSA P-256
 *              and NIST FIPS 204 ML-DSA Post-Quantum Digital Signatures.
 */

import React, { useState } from 'react';
import { useCrypto } from '@/components/crypto-provider';
import { MLDSAParameterSet, ML_DSA_PARAMS } from '@/lib/crypto';
import { MediaCapture } from '@/components/media-capture';
import VideoRecorder from '@/components/VideoRecorder';

export default function Home() {
  const {
    isInitialized,
    isLoading,
    isFirstLoad,
    error,
    session,
    signECDSA,
    verifyECDSA,
    signMLDSA,
    regenerateMLDSA,
  } = useCrypto();

  const [message, setMessage] = useState<string>('Authorize Transaction: #TX-9021-X99 | Nonce: 1048291');
  
  // ECDSA Demo State
  const [ecdsaSignature, setEcdsaSignature] = useState<{ hex: string; bytes: Uint8Array } | null>(null);
  const [ecdsaVerified, setEcdsaVerified] = useState<boolean | null>(null);
  const [isSigningECDSA, setIsSigningECDSA] = useState(false);

  // ML-DSA Demo State
  const [mldsaSignature, setMldsaSignature] = useState<{ hex: string; byteLength: number } | null>(null);
  const [isSigningMLDSA, setIsSigningMLDSA] = useState(false);
  const [selectedPqcParam, setSelectedPqcParam] = useState<MLDSAParameterSet>('ML-DSA-65');
  const [activeTab, setActiveTab] = useState<'recorder' | 'capture' | 'crypto'>('recorder');

  const handleSignECDSA = async () => {
    try {
      setIsSigningECDSA(true);
      const res = await signECDSA(message);
      setEcdsaSignature({ hex: res.signatureHex, bytes: res.signatureBytes });
      const isValid = await verifyECDSA(message, res.signatureBytes);
      setEcdsaVerified(isValid);
    } catch (err) {
      console.error('ECDSA Signing failed:', err);
    } finally {
      setIsSigningECDSA(false);
    }
  };

  const handleSignMLDSA = async () => {
    try {
      setIsSigningMLDSA(true);
      const res = await signMLDSA(message);
      setMldsaSignature({ hex: res.signatureHex, byteLength: res.byteLength });
    } catch (err) {
      console.error('ML-DSA Signing failed:', err);
    } finally {
      setIsSigningMLDSA(false);
    }
  };

  const handleParamChange = async (param: MLDSAParameterSet) => {
    setSelectedPqcParam(param);
    setMldsaSignature(null);
    await regenerateMLDSA(param);
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6 md:p-12 max-w-6xl mx-auto flex flex-col gap-8">
      {/* Header & Cryptographic Status */}
      <header className="border-b border-zinc-800 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Polygon Amoy (80002)
            </span>
            <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-zinc-800 text-zinc-300 border border-zinc-700">
              Zero-Media Upload
            </span>
          </div>
          <h1 className="text-3xl md:text-4xl font-extrabold tracking-tight text-white">
            TrueFrame
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Client-Side Cryptographic Video Attestation &amp; Verification Protocol
          </p>
        </div>

        <div className="flex items-center gap-3 bg-zinc-900 border border-zinc-800 p-3.5 rounded-2xl">
          <div className="h-3 w-3 rounded-full bg-emerald-500 animate-pulse" />
          <div className="text-xs">
            <p className="font-semibold text-zinc-200">
              {isLoading ? 'Bootstrapping Keys...' : isInitialized ? 'Enclave Operational' : 'Offline'}
            </p>
            <p className="text-zinc-500">
              {isFirstLoad ? 'First Load: Fresh Keys Generated & Sealed' : 'Restored from Protected IndexedDB'}
            </p>
          </div>
        </div>
      </header>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/60 text-red-300 text-sm">
          <strong>Initialization Error:</strong> {error}
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-zinc-800 pb-3">
        <button
          onClick={() => setActiveTab('recorder')}
          className={`px-4 py-2 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'recorder'
              ? 'bg-neutral-100 text-neutral-900 shadow-lg'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          Record Video
        </button>
        <button
          onClick={() => setActiveTab('capture')}
          className={`px-4 py-2 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'capture'
              ? 'bg-emerald-600 text-white shadow-lg shadow-emerald-950/50'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          Watermark Studio
        </button>
        <button
          onClick={() => setActiveTab('crypto')}
          className={`px-4 py-2 text-xs font-semibold rounded-xl transition-all ${
            activeTab === 'crypto'
              ? 'bg-purple-600 text-white shadow-lg shadow-purple-950/50'
              : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900'
          }`}
        >
          Crypto Vault
        </button>
      </div>

      {/* Active Tab Subtitle & One-Line Description */}
      <div className="bg-zinc-900/50 border border-zinc-800/70 rounded-xl px-5 py-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-bold text-zinc-100 flex items-center gap-2">
            {activeTab === 'recorder' && (
              <>
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                TrueFrame Attestation Node
              </>
            )}
            {activeTab === 'capture' && (
              <>
                <span className="h-2 w-2 rounded-full bg-emerald-400" />
                Forensic Watermark Synthesizer
              </>
            )}
            {activeTab === 'crypto' && (
              <>
                <span className="h-2 w-2 rounded-full bg-purple-400" />
                WebCrypto &amp; Post-Quantum Vault
              </>
            )}
          </h2>
          <p className="text-xs text-zinc-400 mt-0.5">
            {activeTab === 'recorder' &&
              'Capture video locally with hardware-isolated WebCrypto P-256 signing, 256KB Merkle hashing, and Polygon Amoy anchoring.'}
            {activeTab === 'capture' &&
              'Synthesize real-time overt HUD telemetry and covert pixel steganography directly into the video stream.'}
            {activeTab === 'crypto' &&
              'Inspect non-extractable client keypairs and benchmark NIST FIPS 204 ML-DSA post-quantum lattice signatures.'}
          </p>
        </div>

        {activeTab === 'crypto' && (
          <div className="flex flex-wrap items-center gap-2 self-start sm:self-center">
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              WebCrypto Level 2 &amp; NIST FIPS 204
            </span>
            <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-blue-500/10 text-blue-400 border border-blue-500/20">
              IndexedDB Structured Clone
            </span>
          </div>
        )}
      </div>

      {activeTab === 'recorder' ? (
        <VideoRecorder />
      ) : activeTab === 'capture' ? (
        <MediaCapture />
      ) : (
        <>
          {/* Message Input Payload */}
          <section className="bg-zinc-900/60 border border-zinc-800/80 rounded-2xl p-6">
            <label htmlFor="message-payload" className="block text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">
              Message Payload to Sign
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <input
                id="message-payload"
                type="text"
                value={message}
                onChange={(e) => {
                  setMessage(e.target.value);
                  setEcdsaVerified(null);
                }}
                className="flex-1 bg-zinc-950 border border-zinc-700/80 rounded-xl px-4 py-2.5 text-sm text-zinc-200 focus:outline-none focus:ring-2 focus:ring-emerald-500/40 font-mono"
                placeholder="Enter payload message..."
              />
              <button
                onClick={() => setMessage('Transaction: #TX-' + Math.floor(Math.random() * 100000) + ' | Nonce: ' + Math.floor(Math.random() * 10000000))}
                className="px-4 py-2 bg-zinc-800 hover:bg-zinc-700 text-xs font-medium rounded-xl transition-colors text-zinc-300"
              >
                Randomize Nonce
              </button>
            </div>
          </section>

          {/* Cryptographic Primitives Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        {/* Module 1: ECDSA P-256 WebCrypto */}
        <div className="bg-zinc-900/60 border border-zinc-800/80 rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-emerald-400" />
                <h2 className="text-lg font-semibold text-zinc-100">ECDSA P-256 (WebCrypto)</h2>
              </div>
              <span className="text-xs font-mono text-zinc-400 bg-zinc-800/80 px-2 py-1 rounded-md">
                FIPS 186-5
              </span>
            </div>

            <div className="space-y-4 text-xs">
              <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800 space-y-2">
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Private Key Security Attribute:</span>
                  <span className="font-mono font-bold text-emerald-400">extractable: false</span>
                </div>
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Storage Mechanism:</span>
                  <span className="font-mono text-zinc-300">IndexedDB (Structured Clone)</span>
                </div>
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Curve / Algorithm:</span>
                  <span className="font-mono text-zinc-300">NIST P-256 (secp256r1)</span>
                </div>
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Public Key Fingerprint (SHA-256):</span>
                  <span className="font-mono text-zinc-300 truncate max-w-[200px]" title={session?.ecdsaIdentity.fingerprint}>
                    {session?.ecdsaIdentity.fingerprint || 'Computing...'}
                  </span>
                </div>
              </div>

              {/* Hardware Non-Extractability Guarantee Notice */}
              <div className="p-3 rounded-xl bg-emerald-950/20 border border-emerald-800/30 text-emerald-300/90 text-xs leading-relaxed">
                <p className="font-semibold mb-1">Hardware / Runtime Protection Invariant:</p>
                <p className="text-[11px] text-emerald-400/80">
                  {session?.securityMessage || 'Verifying non-extractability invariant...'}
                </p>
              </div>

              {/* Public Key Display */}
              <div>
                <p className="font-semibold text-zinc-400 mb-1">Public Key (Uncompressed Point 0x04 || X || Y):</p>
                <div className="bg-zinc-950 p-3 rounded-lg border border-zinc-800 font-mono text-[11px] text-zinc-400 break-all max-h-20 overflow-y-auto">
                  {session?.ecdsaIdentity.publicKeyHex || 'Loading...'}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-zinc-800 flex flex-col gap-3">
            <button
              onClick={handleSignECDSA}
              disabled={isSigningECDSA || !isInitialized}
              className="w-full py-2.5 px-4 bg-emerald-600 hover:bg-emerald-500 disabled:bg-zinc-800 text-white font-medium text-xs rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              {isSigningECDSA ? 'Executing WebCrypto Sign...' : 'Generate ECDSA Digital Signature'}
            </button>

            {ecdsaSignature && (
              <div className="bg-zinc-950 border border-zinc-800 p-3 rounded-xl text-xs space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-zinc-400">IEEE P1363 Signature (r || s, 64 bytes):</span>
                  {ecdsaVerified !== null && (
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${ecdsaVerified ? 'bg-emerald-500/20 text-emerald-400' : 'bg-red-500/20 text-red-400'}`}>
                      {ecdsaVerified ? 'VERIFIED' : 'VERIFICATION FAILED'}
                    </span>
                  )}
                </div>
                <p className="font-mono text-[10px] text-emerald-400 break-all bg-zinc-900/60 p-2 rounded">
                  {ecdsaSignature.hex}
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Module 2: ML-DSA NIST FIPS 204 Simulation */}
        <div className="bg-zinc-900/60 border border-zinc-800/80 rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full bg-purple-400" />
                <h2 className="text-lg font-semibold text-zinc-100">ML-DSA Post-Quantum (FIPS 204)</h2>
              </div>
              <span className="text-xs font-mono text-zinc-400 bg-zinc-800/80 px-2 py-1 rounded-md">
                Lattice-Based Standard
              </span>
            </div>

            <div className="space-y-4 text-xs">
              {/* Parameter Set Switcher */}
              <div className="flex items-center gap-2">
                <span className="text-zinc-400">Parameter Set:</span>
                {(['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'] as MLDSAParameterSet[]).map((param) => (
                  <button
                    key={param}
                    onClick={() => handleParamChange(param)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-mono transition-colors ${
                      selectedPqcParam === param
                        ? 'bg-purple-600 text-white font-semibold'
                        : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
                    }`}
                  >
                    {param}
                  </button>
                ))}
              </div>

              <div className="bg-zinc-950 p-4 rounded-xl border border-zinc-800 space-y-2">
                <div className="flex justify-between items-center text-zinc-400">
                  <span>NIST Security Category:</span>
                  <span className="font-mono font-bold text-purple-400">
                    Category {ML_DSA_PARAMS[selectedPqcParam].nistLevel} (Quantum-Resistant)
                  </span>
                </div>
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Matrix Dimension (k × l):</span>
                  <span className="font-mono text-zinc-300">
                    {ML_DSA_PARAMS[selectedPqcParam].k} × {ML_DSA_PARAMS[selectedPqcParam].l}
                  </span>
                </div>
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Public Key Size:</span>
                  <span className="font-mono text-zinc-300">
                    {ML_DSA_PARAMS[selectedPqcParam].publicKeyBytes.toLocaleString()} bytes
                  </span>
                </div>
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Private Key Size:</span>
                  <span className="font-mono text-zinc-300">
                    {ML_DSA_PARAMS[selectedPqcParam].privateKeyBytes.toLocaleString()} bytes
                  </span>
                </div>
                <div className="flex justify-between items-center text-zinc-400">
                  <span>Signature Size:</span>
                  <span className="font-mono text-zinc-300">
                    {ML_DSA_PARAMS[selectedPqcParam].signatureBytes.toLocaleString()} bytes
                  </span>
                </div>
              </div>

              {/* Public Key Fingerprint */}
              <div>
                <p className="font-semibold text-zinc-400 mb-1">
                  Public Key Thumbprint (SHA-256 of {ML_DSA_PARAMS[selectedPqcParam].publicKeyBytes} bytes):
                </p>
                <div className="bg-zinc-950 p-3 rounded-lg border border-zinc-800 font-mono text-[11px] text-zinc-400 break-all">
                  {session?.pqcKeyPair.fingerprint || 'Initializing...'}
                </div>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-zinc-800 flex flex-col gap-3">
            <button
              onClick={handleSignMLDSA}
              disabled={isSigningMLDSA || !isInitialized}
              className="w-full py-2.5 px-4 bg-purple-600 hover:bg-purple-500 disabled:bg-zinc-800 text-white font-medium text-xs rounded-xl transition-colors flex items-center justify-center gap-2"
            >
              {isSigningMLDSA ? 'Executing Lattice Sign...' : `Generate ${selectedPqcParam} Signature`}
            </button>

            {mldsaSignature && (
              <div className="bg-zinc-950 border border-zinc-800 p-3 rounded-xl text-xs space-y-2">
                <div className="flex justify-between items-center">
                  <span className="text-zinc-400">
                    FIPS 204 Signature ({mldsaSignature.byteLength} bytes):
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-500/20 text-purple-400">
                    LATTICE READY
                  </span>
                </div>
                <p className="font-mono text-[10px] text-purple-400 break-all bg-zinc-900/60 p-2 rounded max-h-24 overflow-y-auto">
                  {mldsaSignature.hex}
                </p>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  )}
    </div>
  );
}
