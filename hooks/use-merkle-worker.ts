'use client';

/**
 * @file use-merkle-worker.ts
 * @description React hook to integrate the dedicated Merkle tree Web Worker into UI components.
 * 
 * Provides:
 * - Off-thread non-blocking file processing.
 * - Real-time hashing progress percentage and telemetry.
 * - Promise-based API for seamless async/await integration.
 * - Graceful cancellation and worker lifecycle termination.
 */

import { useState, useRef, useEffect, useCallback } from 'react';
import type {
  MerkleWorkerResponse,
  MerkleWorkerSuccessMessage,
  MerkleWorkerProgressMessage,
  MerkleWorkerErrorMessage,
} from '@/workers/merkle.worker';

export interface MerkleResult {
  merkleRoot: string;
  totalSize: number;
  chunkSize: number;
  totalChunks: number;
  treeDepth: number;
  durationMs: number;
}

export interface MerkleProgress {
  bytesProcessed: number;
  totalBytes: number;
  currentChunk: number;
  totalChunks: number;
  percentage: number;
}

export interface UseMerkleWorkerReturn {
  isProcessing: boolean;
  progress: MerkleProgress | null;
  result: MerkleResult | null;
  error: string | null;
  processBlob: (blob: Blob, fileId?: string) => Promise<MerkleResult>;
  cancelProcessing: () => void;
  reset: () => void;
}

export function useMerkleWorker(): UseMerkleWorkerReturn {
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [progress, setProgress] = useState<MerkleProgress | null>(null);
  const [result, setResult] = useState<MerkleResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const workerRef = useRef<Worker | null>(null);
  const activePromiseRef = useRef<{
    resolve: (res: MerkleResult) => void;
    reject: (err: Error) => void;
  } | null>(null);

  /**
   * Lazily spawns or returns the active Web Worker instance.
   */
  const getOrCreateWorker = useCallback((): Worker => {
    if (!workerRef.current) {
      // Standard Next.js Turbopack / Webpack ESM Worker instantiation
      const worker = new Worker(new URL('../workers/merkle.worker.ts', import.meta.url), {
        type: 'module',
      });

      worker.onmessage = (event: MessageEvent<MerkleWorkerResponse>) => {
        const msg = event.data;

        if (msg.type === 'PROGRESS') {
          const p = (msg as MerkleWorkerProgressMessage).payload;
          setProgress({
            bytesProcessed: p.bytesProcessed,
            totalBytes: p.totalBytes,
            currentChunk: p.currentChunk,
            totalChunks: p.totalChunks,
            percentage: p.progressPercentage,
          });
        } else if (msg.type === 'SUCCESS') {
          const s = (msg as MerkleWorkerSuccessMessage).payload;
          const finalResult: MerkleResult = {
            merkleRoot: s.merkleRoot,
            totalSize: s.totalSize,
            chunkSize: s.chunkSize,
            totalChunks: s.totalChunks,
            treeDepth: s.treeDepth,
            durationMs: s.durationMs,
          };
          setResult(finalResult);
          setIsProcessing(false);
          if (activePromiseRef.current) {
            activePromiseRef.current.resolve(finalResult);
            activePromiseRef.current = null;
          }
        } else if (msg.type === 'ERROR') {
          const e = (msg as MerkleWorkerErrorMessage).payload;
          setError(e.error);
          setIsProcessing(false);
          if (activePromiseRef.current) {
            activePromiseRef.current.reject(new Error(e.error));
            activePromiseRef.current = null;
          }
        }
      };

      worker.onerror = (err) => {
        const errMsg = err.message || 'Worker thread execution error.';
        setError(errMsg);
        setIsProcessing(false);
        if (activePromiseRef.current) {
          activePromiseRef.current.reject(new Error(errMsg));
          activePromiseRef.current = null;
        }
      };

      workerRef.current = worker;
    }

    return workerRef.current;
  }, []);

  /**
   * Dispatches a File or Blob to the worker thread for Merkle tree generation.
   */
  const processBlob = useCallback(
    (blob: Blob, fileId?: string): Promise<MerkleResult> => {
      setError(null);
      setResult(null);
      setProgress({
        bytesProcessed: 0,
        totalBytes: blob.size,
        currentChunk: 0,
        totalChunks: Math.max(1, Math.ceil(blob.size / (256 * 1024))),
        percentage: 0,
      });
      setIsProcessing(true);

      return new Promise<MerkleResult>((resolve, reject) => {
        activePromiseRef.current = { resolve, reject };

        try {
          const worker = getOrCreateWorker();
          worker.postMessage({
            type: 'PROCESS_BLOB',
            payload: { blob, fileId },
          });
        } catch (err: unknown) {
          const message = err instanceof Error ? err.message : 'Failed to post message to Web Worker.';
          setError(message);
          setIsProcessing(false);
          reject(new Error(message));
        }
      });
    },
    [getOrCreateWorker]
  );

  /**
   * Terminates the current worker thread and resets processing state.
   */
  const cancelProcessing = useCallback(() => {
    if (workerRef.current) {
      workerRef.current.terminate();
      workerRef.current = null;
    }
    if (activePromiseRef.current) {
      activePromiseRef.current.reject(new Error('Processing cancelled by user.'));
      activePromiseRef.current = null;
    }
    setIsProcessing(false);
    setProgress(null);
  }, []);

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
    setProgress(null);
    setIsProcessing(false);
  }, []);

  // Cleanup worker instance on unmount
  useEffect(() => {
    return () => {
      if (workerRef.current) {
        workerRef.current.terminate();
        workerRef.current = null;
      }
    };
  }, []);

  return {
    isProcessing,
    progress,
    result,
    error,
    processBlob,
    cancelProcessing,
    reset,
  };
}
