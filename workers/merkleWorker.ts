/**
 * @file workers/merkleWorker.ts
 * @description Dedicated Web Worker for computing SHA-256 Merkle trees from video Files/Blobs in 256 KB slices.
 * 
 * Invariants:
 * - Pure self-contained script with no external imports.
 * - Sequential memory-efficient streaming of 256 KB chunks.
 * - Hierarchical binary Merkle tree with odd-leaf padding.
 */

// Isolated module boundary
export {};

/**
 * Utility: Converts an ArrayBuffer or Uint8Array into a lowercase hexadecimal string.
 */
function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Utility: Converts a hexadecimal string into a Uint8Array byte sequence.
 */
function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Concatenates two 32-byte hexadecimal hashes as binary and computes their SHA-256 digest.
 */
async function hashNodePair(leftHex: string, rightHex: string): Promise<string> {
  const leftBytes = hexToBytes(leftHex);
  const rightBytes = hexToBytes(rightHex);

  const combined = new Uint8Array(leftBytes.length + rightBytes.length);
  combined.set(leftBytes, 0);
  combined.set(rightBytes, leftBytes.length);

  const digestBuffer = await crypto.subtle.digest('SHA-256', combined);
  return bufferToHex(digestBuffer);
}

/**
 * Builds a Merkle tree from an array of leaf hexadecimal hashes:
 * - Pairs up adjacent hashes.
 * - If the count is odd, pads with the last hash.
 * - Recursively reduces layer-by-layer until reaching a single 32-byte Merkle root.
 */
async function buildMerkleTree(leafHashes: string[]): Promise<string> {
  if (leafHashes.length === 0) {
    const emptyBuffer = new ArrayBuffer(0);
    const emptyDigest = await crypto.subtle.digest('SHA-256', emptyBuffer);
    return bufferToHex(emptyDigest);
  }

  let currentLevel = [...leafHashes];

  while (currentLevel.length > 1) {
    // Pad with the last hash if odd
    if (currentLevel.length % 2 !== 0) {
      currentLevel.push(currentLevel[currentLevel.length - 1]);
    }

    const nextLevel: string[] = [];
    for (let i = 0; i < currentLevel.length; i += 2) {
      const parentHash = await hashNodePair(currentLevel[i], currentLevel[i + 1]);
      nextLevel.push(parentHash);
    }

    currentLevel = nextLevel;
  }

  return currentLevel[0];
}

/**
 * Worker message listener.
 * Accepts a File, Blob, or an object containing a file/blob property.
 */
self.onmessage = async (event: MessageEvent<File | Blob | { file?: File | Blob; blob?: File | Blob; data?: File | Blob }>) => {
  try {
    const messageData = event.data;
    let fileOrBlob: Blob | null = null;

    if (messageData instanceof Blob) {
      fileOrBlob = messageData;
    } else if (typeof messageData === 'object' && messageData !== null) {
      fileOrBlob = messageData.file || messageData.blob || messageData.data || null;
    }

    if (!fileOrBlob || typeof fileOrBlob.slice !== 'function') {
      throw new Error('Invalid input: Expected a File or Blob payload.');
    }

    const fileSize = fileOrBlob.size;
    const CHUNK_SIZE = 256 * 1024; // 256 KB = 262,144 bytes
    const totalChunks = Math.max(1, Math.ceil(fileSize / CHUNK_SIZE));
    const leafHashes: string[] = [];

    let offset = 0;

    // Process file in sequential slices of 256 KB
    while (offset < fileSize) {
      const chunk = fileOrBlob.slice(offset, offset + CHUNK_SIZE);
      const buffer = await chunk.arrayBuffer();
      const digestBuffer = await crypto.subtle.digest('SHA-256', buffer);
      leafHashes.push(bufferToHex(digestBuffer));
      offset += CHUNK_SIZE;
    }

    // Handle 0-byte file edge case
    if (leafHashes.length === 0) {
      const emptyBuffer = new ArrayBuffer(0);
      const emptyDigest = await crypto.subtle.digest('SHA-256', emptyBuffer);
      leafHashes.push(bufferToHex(emptyDigest));
    }

    // Build the Merkle tree from the leaf chunk hashes
    const merkleRoot = await buildMerkleTree(leafHashes);

    // Post back the success payload
    self.postMessage({
      merkleRoot,
      leafHashes,
      totalChunks: leafHashes.length,
      fileSize,
    });
  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown Merkle worker error.';
    self.postMessage({
      error: errorMessage,
    });
  }
};
