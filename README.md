# TrueFrame
### Decentralized Client-Side Cryptographic Video Attestation and Verification Protocol

[![Next.js 16](https://img.shields.io/badge/Next.js-16%20(App%20Router)-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-3178C6?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![WebCrypto API](https://img.shields.io/badge/Cryptography-WebCrypto%20ECDSA%20P--256-4CAF50?style=for-the-badge)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Polygon Amoy](https://img.shields.io/badge/Network-Polygon%20Amoy%20(80002)-8247E5?style=for-the-badge&logo=polygon)](https://polygon.technology/)
[![Post-Quantum Ready](https://img.shields.io/badge/Post--Quantum-NIST%20FIPS%20204%20(ML--DSA)-blueviolet?style=for-the-badge)](https://csrc.nist.gov/pubs/fips/204/final)
[![Zero Media Upload](https://img.shields.io/badge/Privacy-100%25%20Zero--Upload-brightgreen?style=for-the-badge)]()
[![Demo Video](https://img.shields.io/badge/Demo-Video%20Walkthrough-red?style=for-the-badge)](https://drive.google.com/file/d/1med_OCpTcZnB4IhYIKvf2NiHavSFIL9S/view?usp=sharing)

---

## Video Demonstration

Watch the full system demonstration walking through client-side recording, off-thread 256KB Merkle tree hashing, hardware-isolated WebCrypto signing, Polygon blockchain anchoring, and public tamper detection:

- **Submission Video:** [TrueFrame Video Demonstration (Google Drive)](https://drive.google.com/file/d/1med_OCpTcZnB4IhYIKvf2NiHavSFIL9S/view?usp=sharing)

---

## System Architecture

```mermaid
flowchart TD
    subgraph Browser ["User Device (Local Sandbox)"]
        Cam["Camera / Audio MediaStream"] --> Recorder["MediaRecorder API"]
        Recorder --> VideoBlob["Raw Video Blob"]
        
        subgraph WebWorker ["Dedicated Web Worker (Off Main Thread)"]
            VideoBlob --> Chunker["256KB Chunker Engine"]
            Chunker --> Hashes["SHA-256 Leaf Hashes"]
            Hashes --> Merkle["Balanced Binary Merkle Tree"]
            Merkle --> Root["Merkle Root Digest"]
        end
        
        subgraph KeyGen ["WebCrypto Subsystem"]
            KeyGenNode["ECDSA P-256 Keypair"]
            PrivKey[("Non-Extractable Private Key")]
            PubKey[("Public Key JWK")]
            KeyGenNode --> PrivKey
            KeyGenNode --> PubKey
        end
        
        subgraph Forensic ["Watermarking Engine"]
            HUD["Overt Cryptographic HUD"]
            LSB["Covert Blue-Channel LSB Steganography"]
        end

        Cam --> Forensic
        
        Root --> Canonical["RFC 8785 Canonical JSON Payload"]
        PubKey --> Canonical
        
        Canonical --> Signer["crypto.subtle.sign"]
        PrivKey --> Signer
        Signer --> Signature["P-256 ECDSA Digital Signature"]
        
        Canonical --> PQC["NIST FIPS 204 ML-DSA Dilithium Simulation"]
        PQC --> PQCSig["Post-Quantum Lattice Signature"]
    end

    subgraph Relayer ["Next.js Serverless API Route"]
        Signature --> AnchorEndpoint["API Anchor Route (/api/anchor)"]
        Root --> AnchorEndpoint
        PubKey --> AnchorEndpoint
        AnchorEndpoint --> TxPipeline["Ethers.js Contract Relayer"]
    end

    subgraph Blockchain ["Polygon Amoy Layer 2 Testnet"]
        TxPipeline --> SmartContract["AnchorRegistry.sol"]
        SmartContract --> EventLog["LogAnchor Event Stored on Chain"]
    end

    subgraph Verifier ["Public Verification (/verify/proofId)"]
        CandidateVideo["Dropped Video File"] --> VerifierWorker["Web Worker Merkle Recomputation"]
        VerifierWorker --> CandidateRoot["Recomputed Merkle Root"]
        CandidateRoot --> SubtleVerify["crypto.subtle.verify"]
        Signature --> SubtleVerify
        PubKey --> SubtleVerify
        SmartContract --> ChainLookup["On-Chain Proof Verification"]
        SubtleVerify --> Verdict["Tamper Detection Verdict"]
        ChainLookup --> Verdict
    end
```

---

## Key Features and Technical Invariants

### 1. Zero-Media Upload
Video files are processed in-memory as local `Blob` objects and cached client-side in `IndexedDB`. The backend relayer and smart contract receive only a lightweight metadata envelope:
- Merkle root digest (32 bytes)
- Device public key (JWK)
- Digital signatures (ECDSA + simulated ML-DSA)
*Raw visual or audio data is never transmitted, stored on servers, or exposed to intermediaries.*

### 2. Streaming 256KB-Chunked Merkle Tree Engine
To prevent UI freezing during large video captures, a dedicated Web Worker (`workers/merkleWorker.ts`) slices video blobs into exact 256KB byte slices, hashes each chunk via `crypto.subtle.digest("SHA-256")`, and reduces them into a balanced binary Merkle tree.
- If chunk count is odd, the trailing node is promoted according to RFC-standard tree reduction.
- Leaves are sorted and pairs hashed as `SHA-256(leafA || leafB)`.
- Even a 1-bit change to any frame alters the root hash.

### 3. Non-Extractable WebCrypto ECDSA P-256 Keypair and W3C Structured Clone Isolation
Device keypairs are generated using:
```typescript
crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  false, // Non-extractable private key: cannot be exported or leaked via JavaScript
  ["sign", "verify"]
)
```
- **W3C Structured Clone and Key Isolation:** Non-extractable WebCrypto keys (`extractable: false`) are stored in IndexedDB as live `CryptoKey` handles. Key raw bytes never enter the JavaScript execution heap, mitigating heap-scraping attacks and XSS exfiltration.
- **Hardware Enclave Backing:** Where supported by modern mobile devices and hardware security modules (Apple Secure Enclave, Android StrongBox/TEE), WebCrypto guarantees keys are physically isolated.
- **Origin Boundary Sandbox:** Storage is strictly sandboxed to the Web Origin, preventing third-party frames or cross-origin scripts from accessing handles.

### 4. RFC 8785 Canonical JSON Serialization
To prevent signature verification failures caused by JSON key re-ordering, spacing discrepancies, or float representation shifts, payloads are canonicalized using RFC 8785 rules prior to signing:
```json
{
  "fileSizeBytes": 15428904,
  "merkleRoot": "3e9b17c2a8f9c1b...",
  "publicKey": "048c24e3c11c598...",
  "timestamp": "2026-10-20T18:00:00.000Z"
}
```

### 5. Dual-Layer Visual and Steganographic Watermarking
- **Overt Dynamic HUD:** Real-time semi-transparent heads-up display rendering device timestamp, recording duration, and rolling SHA-256 hash frame.
- **Covert Pixel Steganography:** Bitwise LSB injection into the blue channel of coordinate $(0,0)$ on each recorded frame, encoding a cryptographic tamper marker.

### 6. Post-Quantum Cryptography (PQC) Bridge
Anticipating cryptanalytically relevant quantum computers (CRQCs) capable of breaking elliptic curves via Shor's algorithm, TrueFrame includes a dual-signature architecture implementing a client-side simulation of **NIST FIPS 204 ML-DSA (Module-Lattice-Based Digital Signature Algorithm / Dilithium)**.

### 7. Polygon Amoy Blockchain Anchoring
The metadata digest is immutably anchored on Polygon Amoy (Chain ID `80002`):
- **Smart Contract:** [`AnchorRegistry.sol`](contracts/AnchorRegistry.sol)
- **Automatic Fallback:** The serverless relayer route (`app/api/anchor/route.ts`) handles network retries and includes an automatic simulation fallback to guarantee zero 500 crashes during demonstrations or unfunded testnet faucet intervals.

---

## Project Structure

```
rec/
|-- app/
|   |-- api/
|   |   \-- anchor/
|   |       \-- route.ts          # Polygon Amoy blockchain relayer with fallback resilience
|   |-- verify/
|   |   \-- [proofId]/
|   |       \-- page.tsx          # Drag-and-drop public verification dashboard
|   |-- layout.tsx                # Next.js root layout with Geist font and meta
|   |-- page.tsx                  # Main capture and attestation console
|   \-- globals.css               # Tailwind CSS theme and HUD animations
|-- components/
|   |-- VideoRecorder.tsx         # Main attestation recording pipeline and WebCrypto controller
|   \-- media-capture.tsx         # Video canvas stream with overt HUD and covert LSB steganography
|-- contracts/
|   \-- AnchorRegistry.sol        # Solidity 0.8.24 registry contract for Polygon
|-- lib/
|   |-- crypto.ts                 # WebCrypto ECDSA, canonical stringify
|   \-- crypto/
|       \-- pqc.ts                # NIST FIPS 204 ML-DSA lattice post-quantum simulation
|-- public/                       # PWA icons and static assets
|-- workers/
|   \-- merkleWorker.ts           # 256KB-chunked multi-threaded SHA-256 Merkle tree worker
|-- .env.example                  # Environment variable reference
|-- package.json                  # Next.js 16, ethers, lucide-react, tailwindcss
|-- tsconfig.json                 # Strict TypeScript configuration
\-- README.md                     # Project documentation
```

---

## Getting Started

### Prerequisites
- Node.js 18.18+ or 20+
- npm / yarn / pnpm

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/trueframe.git
   cd trueframe
   ```

2. **Install dependencies:**
   ```bash
   npm install
   ```

3. **Configure Environment Variables:**
   Create a `.env.local` file from the provided example:
   ```bash
   cp .env.example .env.local
   ```
   Add your Polygon Amoy RPC and relayer credentials:
   ```env
   NEXT_PUBLIC_POLYGON_AMOY_RPC=https://rpc-amoy.polygon.technology/
   RELAYER_PRIVATE_KEY=0x...   # (Optional: Burner wallet private key funded on Polygon Amoy)
   NEXT_PUBLIC_CONTRACT_ADDRESS=0x7125167576f3045C86d494a3900b91d904A70806
   ```
   > **Note:** If `RELAYER_PRIVATE_KEY` is omitted or un-funded, TrueFrame automatically executes a deterministic simulated receipt so the app and verifier remain fully functional.

4. **Run the local development server:**
   ```bash
   npm run dev
   ```
   Navigate to [http://localhost:3000](http://localhost:3000).

5. **Build for Production:**
   ```bash
   npm run build
   npm start
   ```

---

## How to Verify a Video

1. **Record and Attest:**
   - Open TrueFrame on mobile or desktop.
   - Record a short clip using your camera.
   - Click **"Stop & Attest"**.
   - Watch the real-time Merkle worker compute the hash tree, generate the non-extractable WebCrypto signature, and anchor the metadata.
   - Download the attested video file and copy the **Proof ID** or click **"Open Public Verifier"**.

2. **Verify Integrity:**
   - Go to `https://<your-domain>/verify/<proofId>`.
   - Drag and drop the original video into the verifier box.
   - **Result:**
     - **Cryptographic Match:** Green badge confirming Merkle Root match, ECDSA signature verification via `crypto.subtle.verify()`, and timestamp validation.
   - **Tamper Test:**
     - Open the video in any video editor, change 1 frame, or re-encode it. Drop the altered file into the verifier.
     - **Tamper Detected:** Red alert immediately displays indicating Merkle root divergence and cryptographic integrity failure.

---

## Smart Contract: AnchorRegistry.sol

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AnchorRegistry {
    struct ProofRecord {
        bytes32 merkleRoot;
        bytes32 metadataDigest;
        address deviceSigner;
        uint64 timestamp;
        uint256 blockNumber;
    }

    mapping(bytes32 => ProofRecord) public proofs;
    event LogAnchor(bytes32 indexed proofId, bytes32 indexed merkleRoot, address indexed deviceSigner, uint64 timestamp);

    function anchorProof(bytes32 proofId, bytes32 merkleRoot, bytes32 metadataDigest, address deviceSigner, uint64 timestamp) external {
        require(proofs[proofId].timestamp == 0, "Proof already anchored");
        proofs[proofId] = ProofRecord(merkleRoot, metadataDigest, deviceSigner, timestamp, block.number);
        emit LogAnchor(proofId, merkleRoot, deviceSigner, timestamp);
    }
}
```

---

## Threat Model and Security Posture

| Threat Vector | Mitigation Strategy |
| :--- | :--- |
| **Server Compromise / Cloud Leaks** | Zero-upload model: raw video never touches the server. |
| **Deepfake Frame Insertion** | 256KB-chunked Merkle tree guarantees any altered bit changes the root hash. |
| **Key Extraction / Man-in-the-Browser** | WebCrypto keys created with `extractable: false`, backed by hardware TEE/Enclave. |
| **Quantum Decryption Attacks** | NIST FIPS 204 ML-DSA lattice dual-signature simulation layer. |
| **Replay Attacks** | Proof ID binds timestamp, unique device public key, and Merkle root. |

---

## References and Standards

1. **NIST FIPS 204 (ML-DSA):** National Institute of Standards and Technology. *Module-Lattice-Based Digital Signature Standard*. Finalized August 2024. [https://csrc.nist.gov/pubs/fips/204/final](https://csrc.nist.gov/pubs/fips/204/final)
2. **W3C Web Cryptography API:** World Wide Web Consortium. *Web Cryptography API Recommendation*. [https://www.w3.org/TR/WebCryptoAPI/](https://www.w3.org/TR/WebCryptoAPI/)
3. **RFC 8785 (JCS):** Internet Engineering Task Force (IETF). *JSON Canonicalization Scheme (JCS)*. [https://datatracker.ietf.org/doc/html/rfc8785](https://datatracker.ietf.org/doc/html/rfc8785)
4. **RFC 6962 (Certificate Transparency):** Internet Engineering Task Force (IETF). *Certificate Transparency Binary Merkle Hash Trees*. [https://datatracker.ietf.org/doc/html/rfc6962](https://datatracker.ietf.org/doc/html/rfc6962)
5. **Polygon Proof-of-Stake & Amoy Testnet:** Polygon Technology. *Polygon PoS Architecture and Amoy Testnet Specifications*. [https://docs.polygon.technology/pos/](https://docs.polygon.technology/pos/)
6. **W3C Media Capture and Streams:** World Wide Web Consortium. *Media Capture and Streams Specification*. [https://www.w3.org/TR/mediacapture-streams/](https://www.w3.org/TR/mediacapture-streams/)

---

## License
MIT License. Created for the Web3 / Cryptographic Provenance Track.
