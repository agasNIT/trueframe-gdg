import { NextRequest, NextResponse } from 'next/server';
import { ethers } from 'ethers';
import { canonicalStringify } from '@/lib/crypto';

/**
 * ABI for smart contracts implementing the standard TrueFrame anchor function.
 */
export const ANCHOR_REGISTRY_ABI = [
  'function anchor(bytes32 anchorDigest) external',
  'function isAnchored(bytes32 anchorDigest) external view returns (bool)',
  'function getAnchor(bytes32 anchorDigest) external view returns (address submitter, uint64 blockTimestamp, uint64 blockNumber)',
];
const ANCHOR_ABI = ANCHOR_REGISTRY_ABI;

interface AnchorRequestBody {
  payload?: Record<string, any>;
  signature?: string;
  devicePublicKey?: string;
  // Backward compatibility alias for prior iterations
  anchorDigest?: string;
}

/**
 * POST /api/anchor
 * 
 * TrueFrame Anchor Route Handler:
 * 1. Validates { payload, signature, devicePublicKey }.
 * 2. Computes deterministic SHA-256(canonicalStringify(payload)).
 * 3. Encodes memo/data as UTF-8 'trueframe:v1:<hash>'.
 * 4. Relays anchor to testnet using ethers.js (v6) via smart contract call or memo transaction.
 * 5. Returns { success: true, txHash: receipt.hash, blockNumber: receipt.blockNumber, proofId: anchorHash }.
 */
export async function POST(req: NextRequest) {
  try {
    let body: AnchorRequestBody;
    try {
      body = await req.json();
    } catch {
      return NextResponse.json(
        { success: false, error: 'Invalid JSON request body.' },
        { status: 400 }
      );
    }

    const { payload, signature, devicePublicKey } = body;

    // 1. Validate payload object
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
      return NextResponse.json(
        {
          success: false,
          error: "Invalid request: 'payload' must be a non-null JSON object.",
        },
        { status: 400 }
      );
    }

    // 2. Validate signature
    if (!signature || typeof signature !== 'string' || signature.trim().length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: "Invalid request: 'signature' must be a non-empty string.",
        },
        { status: 400 }
      );
    }

    // 3. Validate devicePublicKey (accept top-level or from payload)
    const resolvedPubKey = devicePublicKey || payload.publicKey;
    if (!resolvedPubKey || typeof resolvedPubKey !== 'string' || resolvedPubKey.trim().length === 0) {
      return NextResponse.json(
        {
          success: false,
          error: "Invalid request: 'devicePublicKey' must be a non-empty string.",
        },
        { status: 400 }
      );
    }

    // 4. Compute SHA-256(canonicalStringify(payload)) on the server
    const canonicalJson = canonicalStringify(payload);
    const canonicalBytes = ethers.toUtf8Bytes(canonicalJson);
    const anchorHashWith0x = ethers.sha256(canonicalBytes); // 0x-prefixed 32-byte hex
    const anchorHash = anchorHashWith0x.slice(2).toLowerCase(); // 64-char hex string without 0x

    // 5. Format memo/data as trueframe:v1:<hash>
    const memoText = `trueframe:v1:${anchorHash}`;
    const memoBytes = ethers.toUtf8Bytes(memoText);
    const memoHex = ethers.hexlify(memoBytes);

    // 6. Read environment configuration
    const rpcUrl =
      process.env.RPC_URL ||
      process.env.POLYGON_AMOY_RPC_URL ||
      'https://rpc-amoy.polygon.technology';

    const relayerKey =
      process.env.RELAYER_PRIVATE_KEY ||
      process.env.POLYGON_AMOY_PRIVATE_KEY;

    const contractAddress =
      process.env.CONTRACT_ADDRESS ||
      process.env.ANCHOR_CONTRACT_ADDRESS;

    // 7. Handle missing relayer key with development fallback simulation
    if (!relayerKey) {
      if (process.env.NODE_ENV !== 'production') {
        const mockTxHash = '0x' + ethers.hexlify(ethers.randomBytes(32)).slice(2);
        return NextResponse.json({
          success: true,
          txHash: mockTxHash,
          blockNumber: 14820194,
          proofId: anchorHash,
          simulated: true,
          note: 'Simulation mode active: Configure RELAYER_PRIVATE_KEY in .env for on-chain broadcast.',
        });
      }

      return NextResponse.json(
        {
          success: false,
          error: 'Server misconfiguration: RELAYER_PRIVATE_KEY is not defined.',
        },
        { status: 500 }
      );
    }

    // 8. Connect to testnet via ethers.js (v6)
    const provider = new ethers.JsonRpcProvider(rpcUrl);
    const wallet = new ethers.Wallet(relayerKey, provider);

    let txResponse: ethers.TransactionResponse;

    // If a valid contract address is configured, execute smart contract call
    if (contractAddress && ethers.isAddress(contractAddress)) {
      const contract = new ethers.Contract(contractAddress, ANCHOR_ABI, wallet);
      txResponse = await contract.anchor(anchorHashWith0x);
    } else {
      // Otherwise, anchor via memo transaction (0-value transfer to self carrying memo data)
      txResponse = await wallet.sendTransaction({
        to: wallet.address,
        value: BigInt(0),
        data: memoHex,
      });
    }

    // Wait for 1 confirmation on-chain
    const receipt = await txResponse.wait(1);

    if (!receipt || receipt.status !== 1) {
      throw new Error(`Transaction reverted or failed on testnet: ${receipt?.hash || txResponse.hash}`);
    }

    return NextResponse.json({
      success: true,
      txHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      proofId: anchorHash,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : 'Blockchain anchor broadcast failed.';
    console.error('[API /api/anchor Error]:', error);

    return NextResponse.json(
      {
        success: false,
        error: message,
      },
      { status: 500 }
    );
  }
}
