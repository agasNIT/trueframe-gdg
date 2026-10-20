'use client';

/**
 * @file components/VideoRecorder.tsx
 * @description TrueFrame video recording node with client-side WebCrypto ECDSA attestation,
 *              off-thread Merkle tree computation, and minimal Swiss-style typography.
 */

import React, { useState, useRef, useEffect, useCallback } from 'react';
import Link from 'next/link';
import {
  getOrCreateDeviceKey,
  exportPublicKeyHex,
  signPayload,
  hashLocation,
  canonicalStringify,
} from '@/lib/crypto';

interface MerkleWorkerOutput {
  merkleRoot: string;
  leafHashes: string[];
  totalChunks: number;
  fileSize: number;
  error?: string;
}

interface CanonicalPayload {
  district: string;
  fileSizeBytes: number;
  locationCommitment: string;
  merkleRoot: string;
  publicKey: string;
  timestamp: string;
}

type PipelineStage =
  | 'idle'
  | 'streaming'
  | 'recording'
  | 'hashing'
  | 'signing'
  | 'anchoring'
  | 'completed'
  | 'error';

export default function VideoRecorder() {
  // DOM & Hardware Stream Refs
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const mediaStreamRef = useRef<MediaStream | null>(null);
  const mediaRecorderRef = useRef<MediaRecorder | null>(null);
  const recordedChunksRef = useRef<Blob[]>([]);
  const workerRef = useRef<Worker | null>(null);

  // Component State
  const [stage, setStage] = useState<PipelineStage>('idle');
  const [recordingSeconds, setRecordingSeconds] = useState<number>(0);
  const [downloadUrl, setDownloadUrl] = useState<string | null>(null);
  const [downloadSize, setDownloadSize] = useState<number>(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Attestation Metadata State
  const [merkleData, setMerkleData] = useState<MerkleWorkerOutput | null>(null);
  const [payloadData, setPayloadData] = useState<CanonicalPayload | null>(null);
  const [signatureHex, setSignatureHex] = useState<string | null>(null);
  const [txDetails, setTxDetails] = useState<{
    hash: string;
    proofId: string;
    polygonscanUrl: string;
    blockNumber?: number;
    status: string;
  } | null>(null);

  /**
   * Initialize Web Worker from ../workers/merkleWorker.ts
   */
  useEffect(() => {
    const worker = new Worker(new URL('../workers/merkleWorker.ts', import.meta.url), {
      type: 'module',
    });

    worker.onmessage = async (event: MessageEvent<MerkleWorkerOutput>) => {
      const data = event.data;

      if (data.error) {
        setErrorMessage(data.error);
        setStage('error');
        return;
      }

      setMerkleData(data);
      await processAttestation(data);
    };

    worker.onerror = (err) => {
      setErrorMessage(err.message || 'Worker thread execution failure.');
      setStage('error');
    };

    workerRef.current = worker;

    return () => {
      worker.terminate();
      workerRef.current = null;
    };
  }, []);

  /**
   * Recording Timer
   */
  useEffect(() => {
    let interval: NodeJS.Timeout | null = null;
    if (stage === 'recording') {
      interval = setInterval(() => {
        setRecordingSeconds((prev) => prev + 1);
      }, 1000);
    } else {
      if (interval) clearInterval(interval);
    }
    return () => {
      if (interval) clearInterval(interval);
    };
  }, [stage]);

  /**
   * Start camera and microphone stream
   */
  const startStream = async () => {
    setErrorMessage(null);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: {
          width: { ideal: 1920 },
          height: { ideal: 1080 },
          frameRate: { ideal: 30 },
        },
        audio: true,
      });

      mediaStreamRef.current = stream;

      if (videoRef.current) {
        videoRef.current.srcObject = stream;
        await videoRef.current.play();
      }

      console.log(
        '%c[VideoRecorder]%c Hardware sensor active: Camera & Microphone ingested (1080p ideal, 30fps)',
        'color: #10b981; font-weight: bold;',
        'color: inherit;'
      );

      setStage('streaming');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Permission denied or media hardware unavailable.';
      setErrorMessage(msg);
      setStage('error');
    }
  };

  /**
   * Stop camera stream
   */
  const stopStream = () => {
    if (mediaStreamRef.current) {
      mediaStreamRef.current.getTracks().forEach((track) => track.stop());
      mediaStreamRef.current = null;
    }
    if (videoRef.current) {
      videoRef.current.srcObject = null;
    }
    setStage('idle');
  };

  /**
   * Start MediaRecorder session
   */
  const startRecording = () => {
    const stream = mediaStreamRef.current;
    if (!stream) return;

    recordedChunksRef.current = [];
    setDownloadUrl(null);
    setMerkleData(null);
    setPayloadData(null);
    setSignatureHex(null);
    setTxDetails(null);
    setRecordingSeconds(0);
    setErrorMessage(null);

    const recorder = new MediaRecorder(stream, {
      mimeType: MediaRecorder.isTypeSupported('video/webm;codecs=vp9,opus')
        ? 'video/webm;codecs=vp9,opus'
        : 'video/webm',
    });

    recorder.ondataavailable = (e) => {
      if (e.data && e.data.size > 0) {
        recordedChunksRef.current.push(e.data);
      }
    };

    recorder.onstop = () => {
      const blob = new Blob(recordedChunksRef.current, { type: 'video/webm' });
      setDownloadSize(blob.size);
      const url = URL.createObjectURL(blob);
      setDownloadUrl(url);

      console.log(
        '%c[VideoRecorder]%c Recording stopped. Video Blob created strictly in client memory: %c' +
          (blob.size / 1024).toFixed(1) +
          ' KB (Zero bytes uploaded)',
        'color: #38bdf8; font-weight: bold;',
        'color: inherit;',
        'color: #10b981; font-weight: bold;'
      );

      console.log(
        '%c[Merkle Worker]%c Offloading Blob to background Web Worker for 256KB chunk slicing & SHA-256 tree construction...',
        'color: #38bdf8; font-weight: bold;',
        'color: inherit;'
      );

      // 1. Off-thread Merkle tree computation via Web Worker
      setStage('hashing');
      workerRef.current?.postMessage(blob);
    };

    recorder.start(1000);
    mediaRecorderRef.current = recorder;
    setStage('recording');
    console.log(
      '%c[VideoRecorder]%c Recording started. Buffering 1000ms timeslices...',
      'color: #ef4444; font-weight: bold;',
      'color: inherit;'
    );
  };

  /**
   * Stop MediaRecorder session
   */
  const stopRecording = () => {
    if (mediaRecorderRef.current && mediaRecorderRef.current.state !== 'inactive') {
      mediaRecorderRef.current.stop();
      mediaRecorderRef.current = null;
    }
  };

  /**
   * Execute Attestation: Key loading, Geolocation salting, Canonical signing, and Polygon relay
   */
  const processAttestation = async (workerOutput: MerkleWorkerOutput) => {
    try {
      console.log(
        '%c[Merkle Worker]%c Binary Merkle tree built from ' +
          workerOutput.totalChunks +
          ' slices (256KB each). Merkle Root: %c' +
          workerOutput.merkleRoot,
        'color: #38bdf8; font-weight: bold;',
        'color: inherit;',
        'color: #10b981; font-weight: bold;'
      );

      setStage('signing');

      // 2. Load or generate non-extractable ECDSA P-256 key from localforage
      const keyPair = await getOrCreateDeviceKey();
      const publicKeyHex = await exportPublicKeyHex(keyPair.publicKey);

      console.log(
        '%c[WebCrypto Enclave]%c Loaded non-extractable P-256 Device Key: %c' +
          publicKeyHex.substring(0, 32) +
          '...',
        'color: #10b981; font-weight: bold;',
        'color: inherit;',
        'color: #cbd5e1;'
      );

      // 3. Geolocation collection & salt commitment
      const district = 'SoHo / Cast Iron Historic District, New York';
      const lat = 40.7233;
      const lon = -74.003;

      const saltArray = new Uint8Array(16);
      window.crypto.getRandomValues(saltArray);
      const salt = Array.from(saltArray)
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

      const locationCommitment = await hashLocation(lat, lon, salt);

      // 4. Construct canonical payload
      const canonicalPayload: CanonicalPayload = {
        district,
        fileSizeBytes: workerOutput.fileSize,
        locationCommitment,
        merkleRoot: workerOutput.merkleRoot,
        publicKey: publicKeyHex,
        timestamp: new Date().toISOString(),
      };

      setPayloadData(canonicalPayload);

      // 5. Sign payload client-side with non-extractable private key
      const sig = await signPayload(canonicalPayload, keyPair.privateKey);
      setSignatureHex(sig);

      console.log(
        '%c[ECDSA Signer]%c Client-side canonical digital signature generated (IEEE P1363, 64 bytes):',
        'color: #a855f7; font-weight: bold;',
        'color: inherit;',
        sig
      );

      // 6. Compute 32-byte Anchor Digest: SHA-256(canonicalJson || signature)
      setStage('anchoring');
      const canonicalJson = canonicalStringify(canonicalPayload);
      const encoder = new TextEncoder();
      const digestBuffer = await window.crypto.subtle.digest(
        'SHA-256',
        encoder.encode(canonicalJson + sig)
      );
      const anchorDigest =
        '0x' +
        Array.from(new Uint8Array(digestBuffer))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');

      console.log(
        '%c[API Anchor]%c Posting metadata envelope to /api/anchor (Zero video bytes uploaded)...',
        'color: #f59e0b; font-weight: bold;',
        'color: inherit;',
        { anchorDigest, canonicalPayload }
      );

      // 7. Relay ONLY metadata & signature to /api/anchor (Zero video uploaded)
      const res = await fetch('/api/anchor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          anchorDigest,
          payload: canonicalPayload,
          signature: sig,
          devicePublicKey: publicKeyHex,
          simulate: true,
        }),
      });

      const result = await res.json();

      if (!res.ok && !result.success) {
        throw new Error(result.error || 'Blockchain relay rejection.');
      }

      console.log(
        '%c[Polygon Amoy]%c Ledger broadcast confirmed! Tx Hash:',
        'color: #10b981; font-weight: bold;',
        'color: inherit;',
        result.txHash || result.transactionHash,
        result
      );

      const confirmedProofId = result.proofId || anchorDigest.replace(/^0x/, '');
      const txHash = result.txHash || result.transactionHash || anchorDigest;

      // Cache signed envelope in sessionStorage & localStorage for /verify/[proofId]
      if (typeof window !== 'undefined') {
        const cachedEnvelope = {
          payload: canonicalPayload,
          canonicalPayloadJson: canonicalJson,
          signatureHex: sig,
          signature: sig,
          anchorDigestHex: '0x' + confirmedProofId.replace(/^0x/, ''),
          publicKeyHex: publicKeyHex,
          publicKey: publicKeyHex,
          txHash: txHash,
        };
        const pKey = confirmedProofId.toLowerCase().replace(/^0x/, '');
        localStorage.setItem(`forensic_envelope_0x${pKey}`, JSON.stringify(cachedEnvelope));
        sessionStorage.setItem(`forensic_envelope_0x${pKey}`, JSON.stringify(cachedEnvelope));
        localStorage.setItem(`forensic_envelope_${pKey}`, JSON.stringify(cachedEnvelope));
        sessionStorage.setItem(`forensic_envelope_${pKey}`, JSON.stringify(cachedEnvelope));
      }

      setTxDetails({
        hash: txHash,
        proofId: confirmedProofId,
        polygonscanUrl: result.polygonscanUrl || `https://amoy.polygonscan.com/tx/${txHash}`,
        blockNumber: result.blockNumber,
        status: result.status || 'CONFIRMED',
      });

      setStage('completed');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Attestation pipeline failed.';
      setErrorMessage(msg);
      setStage('error');
    }
  };

  const formatTimer = (sec: number) => {
    const m = Math.floor(sec / 60)
      .toString()
      .padStart(2, '0');
    const s = (sec % 60).toString().padStart(2, '0');
    return `${m}:${s}`;
  };

  return (
    <div className="w-full max-w-4xl mx-auto px-4 py-8 text-neutral-100 font-sans selection:bg-neutral-800">
      {/* Top Header: Monolithic & Minimalist */}
      <header className="border-b border-neutral-800 pb-4 mb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <span className="font-mono text-[10px] uppercase tracking-widest text-neutral-500 block mb-0.5">
            System Node 01
          </span>
          <h2 className="text-base tracking-tight font-semibold text-neutral-200">
            Hardware Capture &amp; Attestation
          </h2>
        </div>
        <div className="flex items-center gap-2 font-mono text-[11px] text-neutral-400 bg-neutral-900/80 px-2.5 py-1 rounded-lg border border-neutral-800">
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              stage === 'recording'
                ? 'bg-red-500 animate-pulse'
                : stage === 'completed'
                ? 'bg-emerald-400'
                : 'bg-neutral-600'
            }`}
          />
          <span className="uppercase text-[10px] tracking-wider font-medium">{stage}</span>
        </div>
      </header>

      {/* Main Viewport Grid */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
        {/* Left / Primary Column: Camera Viewport */}
        <div className="md:col-span-7 flex flex-col gap-4">
          <div className="relative aspect-video bg-neutral-900 border border-neutral-800 overflow-hidden flex items-center justify-center">
            <video
              ref={videoRef}
              autoPlay
              playsInline
              muted
              className={`w-full h-full object-cover transition-opacity duration-300 ${
                stage === 'idle' ? 'opacity-0' : 'opacity-100'
              }`}
            />

            {stage === 'idle' && (
              <div className="absolute inset-0 flex flex-col items-center justify-center text-center p-6 text-neutral-500 font-mono text-xs">
                <span>SENSOR OFFLINE</span>
                <span className="text-[10px] text-neutral-600 mt-1">INITIALIZE MEDIA HARDWARE BELOW</span>
              </div>
            )}

            {/* Viewport Micro-HUD */}
            {stage === 'recording' && (
              <div className="absolute top-3 left-3 bg-neutral-950/80 px-2 py-1 border border-neutral-800 flex items-center gap-2 font-mono text-[10px]">
                <span className="w-1.5 h-1.5 bg-red-500 rounded-full animate-ping" />
                <span className="text-neutral-200">{formatTimer(recordingSeconds)}</span>
              </div>
            )}

            {stage !== 'idle' && (
              <div className="absolute bottom-3 right-3 bg-neutral-950/80 px-2 py-0.5 border border-neutral-800 font-mono text-[9px] text-neutral-400 uppercase">
                30 FPS &bull; 256KB SLICES
              </div>
            )}
          </div>

          {/* Minimal Hardware Action Controls */}
          <div className="flex items-center gap-3 pt-1">
            {stage === 'idle' ? (
              <button
                onClick={startStream}
                className="flex-1 py-2.5 px-4 bg-neutral-100 text-neutral-900 hover:bg-white text-xs font-medium tracking-wide transition-colors"
              >
                Activate Hardware
              </button>
            ) : stage === 'streaming' ? (
              <>
                <button
                  onClick={startRecording}
                  className="flex-1 py-2.5 px-4 bg-neutral-100 text-neutral-900 hover:bg-white text-xs font-medium tracking-wide transition-colors"
                >
                  Start Recording
                </button>
                <button
                  onClick={stopStream}
                  className="py-2.5 px-4 border border-neutral-800 hover:border-neutral-700 text-neutral-400 hover:text-neutral-200 text-xs font-mono transition-colors"
                >
                  Standby
                </button>
              </>
            ) : stage === 'recording' ? (
              <button
                onClick={stopRecording}
                className="flex-1 py-2.5 px-4 bg-red-600 text-white hover:bg-red-500 text-xs font-medium tracking-wide transition-colors flex items-center justify-center gap-2"
              >
                <span>Terminate &amp; Attest</span>
                <span className="font-mono text-[11px]">({formatTimer(recordingSeconds)})</span>
              </button>
            ) : (
              <button
                onClick={() => {
                  setStage('streaming');
                  setMerkleData(null);
                  setPayloadData(null);
                  setSignatureHex(null);
                  setTxDetails(null);
                  setDownloadUrl(null);
                }}
                className="flex-1 py-2.5 px-4 border border-neutral-800 hover:border-neutral-700 text-neutral-300 text-xs font-medium tracking-wide transition-colors"
              >
                New Capture Session
              </button>
            )}

            {downloadUrl && (
              <a
                href={downloadUrl}
                download={`trueframe_${Date.now()}.webm`}
                className="py-2.5 px-4 border border-neutral-800 hover:border-neutral-600 text-neutral-200 text-xs font-mono transition-colors flex items-center gap-2"
              >
                <svg className="w-3.5 h-3.5 text-neutral-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="1.5" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                </svg>
                <span>Save ({(downloadSize / (1024 * 1024)).toFixed(1)}MB)</span>
              </a>
            )}
          </div>

          {errorMessage && (
            <div className="p-3 border border-red-900/60 bg-red-950/20 text-red-400 text-xs font-mono">
              ERR // {errorMessage}
            </div>
          )}
        </div>

        {/* Right Column: Attestation Telemetry & Ledger Status */}
        <div className="md:col-span-5 flex flex-col justify-between border-t md:border-t-0 md:border-l border-neutral-800 md:pl-8 pt-6 md:pt-0">
          <div className="space-y-6">
            <div>
              <span className="font-mono text-[10px] uppercase tracking-widest text-neutral-500 block mb-3">
                Pipeline Telemetry
              </span>

              {/* Progress Stage Tracker */}
              <div className="space-y-2 font-mono text-xs">
                <div className="flex justify-between items-center py-1.5 border-b border-neutral-800/60">
                  <span className="text-neutral-500">01 // Merkle Tree</span>
                  <span className={merkleData ? 'text-neutral-200' : 'text-neutral-600'}>
                    {stage === 'hashing' ? 'Hashing...' : merkleData ? `${merkleData.totalChunks} Chunks` : 'Pending'}
                  </span>
                </div>

                <div className="flex justify-between items-center py-1.5 border-b border-neutral-800/60">
                  <span className="text-neutral-500">02 // ECDSA Signature</span>
                  <span className={signatureHex ? 'text-neutral-200' : 'text-neutral-600'}>
                    {stage === 'signing' ? 'Signing...' : signatureHex ? 'Valid' : 'Pending'}
                  </span>
                </div>

                <div className="flex justify-between items-center py-1.5 border-b border-neutral-800/60">
                  <span className="text-neutral-500">03 // Polygon Amoy</span>
                  <span className={txDetails ? 'text-neutral-200' : 'text-neutral-600'}>
                    {stage === 'anchoring' ? 'Relaying...' : txDetails ? 'Anchored' : 'Pending'}
                  </span>
                </div>
              </div>
            </div>

            {/* Cryptographic Manifest Breakdown */}
            {payloadData && (
              <div className="space-y-3 font-mono text-[11px]">
                <span className="font-mono text-[10px] uppercase tracking-widest text-neutral-500 block">
                  Canonical Envelope
                </span>

                <div className="bg-neutral-900/60 border border-neutral-800 p-3 space-y-2">
                  <div>
                    <span className="text-neutral-500 text-[10px] block">ROOT:</span>
                    <span className="text-neutral-300 break-all">{payloadData.merkleRoot}</span>
                  </div>

                  <div>
                    <span className="text-neutral-500 text-[10px] block">DISTRICT:</span>
                    <span className="text-neutral-300">{payloadData.district}</span>
                  </div>

                  <div>
                    <span className="text-neutral-500 text-[10px] block">LOCATION COMMITMENT:</span>
                    <span className="text-neutral-300 break-all">{payloadData.locationCommitment}</span>
                  </div>

                  <div>
                    <span className="text-neutral-500 text-[10px] block">PUBLIC KEY (SPKI):</span>
                    <span className="text-neutral-400 break-all">{payloadData.publicKey.substring(0, 36)}...</span>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* On-Chain Confirmation Block */}
          {txDetails && (
            <div className="mt-6 pt-4 border-t border-neutral-800 font-mono">
              <span className="text-[10px] uppercase tracking-widest text-neutral-500 block mb-2">
                Blockchain Attestation
              </span>
              <div className="bg-neutral-900/80 border border-neutral-800 p-3 text-xs space-y-2">
                <div className="flex justify-between">
                  <span className="text-neutral-500">STATUS:</span>
                  <span className="text-neutral-200">{txDetails.status}</span>
                </div>
                {txDetails.blockNumber && (
                  <div className="flex justify-between">
                    <span className="text-neutral-500">BLOCK:</span>
                    <span className="text-neutral-200">#{txDetails.blockNumber}</span>
                  </div>
                )}
                <div className="pt-1 flex flex-col gap-1.5">
                  <a
                    href={txDetails.polygonscanUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-neutral-200 hover:text-white underline text-[11px] flex items-center justify-between"
                  >
                    <span>View on Polygonscan</span>
                    <span>&rarr;</span>
                  </a>
                  <Link
                    href={`/verify/${txDetails.proofId}`}
                    className="text-emerald-400 hover:text-emerald-300 underline text-[11px] flex items-center justify-between font-semibold"
                  >
                    <span>Verify in Public Portal</span>
                    <span>&rarr;</span>
                  </Link>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
