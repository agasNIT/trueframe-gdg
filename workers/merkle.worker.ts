/**
 * @file merkle.worker.ts
 * @description Dedicated Web Worker for off-thread streaming Merkle tree computation.
 * 
 * Cryptographic Architecture & Threat Mitigation:
 * 1. Chunked Streaming Memory Invariant:
 *    Processes File/Blob in 256KB slices via `blob.slice(offset, offset + CHUNK_SIZE)`.
 *    Memory complexity is strictly O(1) in chunk size (~256KB), preventing mobile PWA OOM crashes.
 * 
 * 2. RFC 6962 Domain Separation:
 *    - Leaf Hash:     H(0x00 || chunk_bytes)
 *    - Internal Node: H(0x01 || left_hash || right_hash)
 *    Domain separation precludes second-preimage attacks where an internal node is substituted for a leaf.
 * 
 * 3. CVE-2012-2459 Malleability Mitigation:
 *    If a tree level has an odd number of nodes, the orphan node is promoted directly to the next level
 *    rather than duplicated. This eliminates duplicate-leaf tree malleability vulnerabilities.
 */

const CHUNK_SIZE = 256 * 1024; // 256 KB = 262,144 bytes

// Domain separation prefixes (RFC 6962)
const LEAF_PREFIX = new Uint8Array([0x00]);
const NODE_PREFIX = new Uint8Array([0x01]);

export interface MerkleWorkerInputMessage {
  type: 'PROCESS_BLOB';
  payload: {
    blob: Blob;
    fileId?: string;
  };
}

export interface MerkleWorkerProgressMessage {
  type: 'PROGRESS';
  payload: {
    fileId?: string;
    bytesProcessed: number;
    totalBytes: number;
    currentChunk: number;
    totalChunks: number;
    progressPercentage: number;
  };
}

export interface MerkleWorkerSuccessMessage {
  type: 'SUCCESS';
  payload: {
    fileId?: string;
    merkleRoot: string; // Hex representation
    totalSize: number;
    chunkSize: number;
    totalChunks: number;
    treeDepth: number;
    durationMs: number;
  };
}

export interface MerkleWorkerErrorMessage {
  type: 'ERROR';
  payload: {
    fileId?: string;
    error: string;
  };
}

export type MerkleWorkerResponse =
  | MerkleWorkerProgressMessage
  | MerkleWorkerSuccessMessage
  | MerkleWorkerErrorMessage;

function bufferToHex(buffer: Uint8Array): string {
  return Array.from(buffer)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Computes RFC 6962 Domain-Separated Leaf Hash: H(0x00 || chunk_bytes)
 */
async function hashLeaf(chunkBuffer: ArrayBuffer): Promise<Uint8Array> {
  const chunkBytes = new Uint8Array(chunkBuffer);
  const prefixed = new Uint8Array(1 + chunkBytes.length);
  prefixed.set(LEAF_PREFIX, 0);
  prefixed.set(chunkBytes, 1);

  const digest = await self.crypto.subtle.digest('SHA-256', prefixed);
  return new Uint8Array(digest);
}

/**
 * Computes RFC 6962 Domain-Separated Internal Node Hash: H(0x01 || left || right)
 */
async function hashInternalNode(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  const combined = new Uint8Array(1 + left.length + right.length);
  combined.set(NODE_PREFIX, 0);
  combined.set(left, 1);
  combined.set(right, 1 + left.length);

  const digest = await self.crypto.subtle.digest('SHA-256', combined);
  return new Uint8Array(digest);
}

/**
 * Main worker message handler.
 */
self.onmessage = async (event: MessageEvent<MerkleWorkerInputMessage>) => {
  const { type, payload } = event.data;

  if (type !== 'PROCESS_BLOB') {
    return;
  }

  const { blob, fileId } = payload;
  const startTime = performance.now();

  try {
    const totalSize = blob.size;
    const totalChunks = Math.max(1, Math.ceil(totalSize / CHUNK_SIZE));
    const leafHashes: Uint8Array[] = [];

    let offset = 0;
    let chunkIndex = 0;

    // Phase 1: Streamed Chunk Slicing & Leaf Hashing
    while (offset < totalSize) {
      const slice = blob.slice(offset, offset + CHUNK_SIZE);
      const arrayBuffer = await slice.arrayBuffer();
      const leafHash = await hashLeaf(arrayBuffer);
      leafHashes.push(leafHash);

      offset += CHUNK_SIZE;
      chunkIndex += 1;

      // Post progress updates to main thread
      const bytesProcessed = Math.min(offset, totalSize);
      const progressPercentage = Math.round((bytesProcessed / totalSize) * 100);

      const progressMsg: MerkleWorkerProgressMessage = {
        type: 'PROGRESS',
        payload: {
          fileId,
          bytesProcessed,
          totalBytes: totalSize,
          currentChunk: chunkIndex,
          totalChunks,
          progressPercentage,
        },
      };
      self.postMessage(progressMsg);
    }

    // Handle edge case of 0-byte file
    if (leafHashes.length === 0) {
      const emptyLeaf = await hashLeaf(new ArrayBuffer(0));
      leafHashes.push(emptyLeaf);
    }

    // Phase 2: Hierarchical Merkle Tree Reduction
    let currentLevel = leafHashes;
    let treeDepth = 1;

    while (currentLevel.length > 1) {
      const nextLevel: Uint8Array[] = [];
      for (let i = 0; i < currentLevel.length; i += 2) {
        if (i + 1 < currentLevel.length) {
          const parent = await hashInternalNode(currentLevel[i], currentLevel[i + 1]);
          nextLevel.push(parent);
        } else {
          // Promote orphan node to next level without duplication (CVE-2012-2459 mitigation)
          nextLevel.push(currentLevel[i]);
        }
      }
      currentLevel = nextLevel;
      treeDepth += 1;
    }

    const merkleRootBytes = currentLevel[0];
    const merkleRootHex = bufferToHex(merkleRootBytes);
    const durationMs = performance.now() - startTime;

    const successMsg: MerkleWorkerSuccessMessage = {
      type: 'SUCCESS',
      payload: {
        fileId,
        merkleRoot: merkleRootHex,
        totalSize,
        chunkSize: CHUNK_SIZE,
        totalChunks,
        treeDepth,
        durationMs,
      },
    };
    self.postMessage(successMsg);
  } catch (err: unknown) {
    const errorMsg = err instanceof Error ? err.message : 'Unknown error during Merkle tree generation.';
    const failureMsg: MerkleWorkerErrorMessage = {
      type: 'ERROR',
      payload: {
        fileId,
        error: errorMsg,
      },
    };
    self.postMessage(failureMsg);
  }
};
