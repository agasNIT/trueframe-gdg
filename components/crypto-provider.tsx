'use client';

/**
 * @file crypto-provider.tsx
 * @description Client-side React context and provider that triggers non-extractable WebCrypto
 *              key generation and IndexedDB storage on initial load.
 */

import React, { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import {
  initializeCryptoSubsystem,
  CryptoEngineSession,
  signTextMessage,
  verifyTextMessage,
  signTextWithMLDSA,
  simulateMLDSAKeyGeneration,
  MLDSAParameterSet,
  putRecord,
  STORES,
  DEFAULT_PQC_KEY_ID,
} from '@/lib/crypto';

interface CryptoContextValue {
  isInitialized: boolean;
  isLoading: boolean;
  isFirstLoad: boolean;
  error: string | null;
  session: CryptoEngineSession | null;
  signECDSA: (message: string) => Promise<{ signatureHex: string; signatureBytes: Uint8Array }>;
  verifyECDSA: (message: string, signatureBytes: Uint8Array) => Promise<boolean>;
  signMLDSA: (message: string) => Promise<{ signatureHex: string; byteLength: number }>;
  regenerateMLDSA: (paramSet?: MLDSAParameterSet) => Promise<void>;
}

const CryptoContext = createContext<CryptoContextValue | undefined>(undefined);

export function CryptoProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<CryptoEngineSession | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isFirstLoad, setIsFirstLoad] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isMounted = true;

    // Register PWA Service Worker if supported
    if ('serviceWorker' in navigator && process.env.NODE_ENV === 'production') {
      window.addEventListener('load', () => {
        navigator.serviceWorker
          .register('/sw.js')
          .then((reg) => console.log('[PWA] Service Worker registered with scope:', reg.scope))
          .catch((err) => console.warn('[PWA] Service Worker registration failed:', err));
      });
    }

    // Initialize cryptographic subsystem on first load
    async function bootCrypto() {
      try {
        setIsLoading(true);
        const engineSession = await initializeCryptoSubsystem();
        console.log(
          '%c[TrueFrame Enclave]%c WebCrypto ECDSA P-256 Key Initialized',
          'color: #10b981; font-weight: bold;',
          'color: inherit;',
          {
            fingerprint: engineSession.ecdsaIdentity.fingerprint,
            storage: 'IndexedDB (Structured Clone)',
            protection: 'extractable: false',
            isFirstLoad: engineSession.isFirstLoad,
          }
        );
        if (isMounted) {
          setSession(engineSession);
          setIsFirstLoad(engineSession.isFirstLoad);
          setError(null);
        }
      } catch (err: unknown) {
        if (isMounted) {
          const message = err instanceof Error ? err.message : 'Unknown cryptographic initialization failure.';
          console.error('[CryptoSubsystem] Initialization failed:', err);
          setError(message);
        }
      } finally {
        if (isMounted) {
          setIsLoading(false);
        }
      }
    }

    bootCrypto();

    return () => {
      isMounted = false;
    };
  }, []);

  const signECDSA = async (message: string) => {
    if (!session) throw new Error('Cryptographic session is not yet initialized.');
    return signTextMessage(message, session.ecdsaRecord.keyPair.privateKey);
  };

  const verifyECDSA = async (message: string, signatureBytes: Uint8Array) => {
    if (!session) throw new Error('Cryptographic session is not yet initialized.');
    return verifyTextMessage(message, signatureBytes, session.ecdsaRecord.keyPair.publicKey);
  };

  const signMLDSA = async (message: string) => {
    if (!session) throw new Error('Cryptographic session is not yet initialized.');
    return signTextWithMLDSA(message, session.pqcKeyPair);
  };

  const regenerateMLDSA = async (paramSet: MLDSAParameterSet = 'ML-DSA-65') => {
    if (!session) throw new Error('Cryptographic session is not yet initialized.');
    setIsLoading(true);
    try {
      const freshPqc = await simulateMLDSAKeyGeneration(paramSet, DEFAULT_PQC_KEY_ID);
      await putRecord(STORES.PQC, freshPqc.storedPayload);
      setSession((prev: CryptoEngineSession | null) => (prev ? { ...prev, pqcKeyPair: freshPqc } : prev));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <CryptoContext.Provider
      value={{
        isInitialized: !!session,
        isLoading,
        isFirstLoad,
        error,
        session,
        signECDSA,
        verifyECDSA,
        signMLDSA,
        regenerateMLDSA,
      }}
    >
      {children}
    </CryptoContext.Provider>
  );
}

export function useCrypto(): CryptoContextValue {
  const context = useContext(CryptoContext);
  if (!context) {
    throw new Error('useCrypto must be used within a <CryptoProvider>');
  }
  return context;
}
