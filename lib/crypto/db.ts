/**
 * @file db.ts
 * @description Secure IndexedDB storage engine for WebCrypto non-extractable keys and PQC keys.
 * 
 * SECURITY ARCHITECTURE NOTE:
 * W3C Web Cryptography API & HTML Structured Clone Algorithm Specification:
 * CryptoKey objects with `extractable: false` are legal Structured Clone targets.
 * Browsers preserve the internal hardware / software enclave isolation of the key handle.
 * Even if an attacker executes malicious JavaScript in the application runtime (e.g. XSS),
 * they CANNOT export the raw private key bytes via `crypto.subtle.exportKey()`.
 * Retrieving the record from IndexedDB produces a live CryptoKey instance that can sign
 * but remains permanently non-extractable.
 */

const DB_NAME = 'pwa_crypto_vault';
const DB_VERSION = 1;

export const STORES = {
  ECDSA: 'ecdsa_keys',
  PQC: 'pqc_keys',
} as const;

let dbPromise: Promise<IDBDatabase> | null = null;

/**
 * Initializes and opens the IndexedDB connection with isolated object stores.
 */
export function getCryptoDatabase(): Promise<IDBDatabase> {
  if (typeof window === 'undefined' || !window.indexedDB) {
    return Promise.reject(new Error('IndexedDB is not available in the current execution context.'));
  }

  if (dbPromise) {
    return dbPromise;
  }

  dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
    const request = window.indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event: IDBVersionChangeEvent) => {
      const db = (event.target as IDBOpenDBRequest).result;

      // Object store for ECDSA P-256 key pairs (CryptoKey stored via Structured Clone)
      if (!db.objectStoreNames.contains(STORES.ECDSA)) {
        db.createObjectStore(STORES.ECDSA, { keyPath: 'id' });
      }

      // Object store for Post-Quantum ML-DSA keys
      if (!db.objectStoreNames.contains(STORES.PQC)) {
        db.createObjectStore(STORES.PQC, { keyPath: 'id' });
      }
    };

    request.onsuccess = () => {
      const db = request.result;
      db.onversionchange = () => {
        db.close();
        dbPromise = null;
      };
      resolve(db);
    };

    request.onerror = () => {
      dbPromise = null;
      reject(request.error || new Error('Failed to open crypto IndexedDB.'));
    };

    request.onblocked = () => {
      console.warn('[CryptoDB] Database upgrade blocked by open tab/connection.');
    };
  });

  return dbPromise;
}

/**
 * Generic transactional put operation.
 */
export async function putRecord<T extends { id: string }>(
  storeName: typeof STORES[keyof typeof STORES],
  record: T
): Promise<void> {
  const db = await getCryptoDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    const request = store.put(record);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error || new Error(`Failed to put record into ${storeName}`));
    transaction.onabort = () => reject(transaction.error || new Error(`Transaction aborted in ${storeName}`));
  });
}

/**
 * Generic transactional get operation.
 */
export async function getRecord<T>(
  storeName: typeof STORES[keyof typeof STORES],
  id: string
): Promise<T | null> {
  const db = await getCryptoDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readonly');
    const store = transaction.objectStore(storeName);
    const request = store.get(id);

    request.onsuccess = () => {
      resolve(request.result !== undefined ? (request.result as T) : null);
    };
    request.onerror = () => reject(request.error || new Error(`Failed to get record '${id}' from ${storeName}`));
  });
}

/**
 * Delete a key record by ID.
 */
export async function deleteRecord(
  storeName: typeof STORES[keyof typeof STORES],
  id: string
): Promise<void> {
  const db = await getCryptoDatabase();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    const request = store.delete(id);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error || new Error(`Failed to delete record '${id}' from ${storeName}`));
  });
}
