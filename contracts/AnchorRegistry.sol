// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AnchorRegistry
 * @notice Minimal immutable cryptographic anchor registry for Polygon Amoy Testnet (Chain ID 80002).
 * @dev Stores SHA-256 / Keccak256 digests of signed provenance payloads on-chain.
 */
contract AnchorRegistry {
    // Structure stored in storage slot
    struct AnchorRecord {
        address submitter;
        uint64 blockTimestamp;
        uint64 blockNumber;
    }

    // anchorDigest (bytes32) => AnchorRecord
    mapping(bytes32 => AnchorRecord) public records;

    // Events
    event RecordAnchored(
        bytes32 indexed anchorDigest,
        address indexed submitter,
        uint256 blockTimestamp
    );

    // Custom errors for gas efficiency
    error DigestAlreadyAnchored(bytes32 anchorDigest, uint64 existingTimestamp);
    error InvalidDigest();

    /**
     * @notice Anchors a 32-byte cryptographic digest onto the Polygon ledger.
     * @param anchorDigest SHA-256 digest of the canonically signed forensic envelope.
     */
    function anchor(bytes32 anchorDigest) external {
        if (anchorDigest == bytes32(0)) {
            revert InvalidDigest();
        }

        if (records[anchorDigest].blockTimestamp != 0) {
            revert DigestAlreadyAnchored(anchorDigest, records[anchorDigest].blockTimestamp);
        }

        records[anchorDigest] = AnchorRecord({
            submitter: msg.sender,
            blockTimestamp: uint64(block.timestamp),
            blockNumber: uint64(block.number)
        });

        emit RecordAnchored(anchorDigest, msg.sender, block.timestamp);
    }

    /**
     * @notice Verifies if a digest has been anchored.
     */
    function isAnchored(bytes32 anchorDigest) external view returns (bool) {
        return records[anchorDigest].blockTimestamp != 0;
    }

    /**
     * @notice Retrieves the provenance record for a given digest.
     */
    function getAnchor(bytes32 anchorDigest)
        external
        view
        returns (
            address submitter,
            uint64 blockTimestamp,
            uint64 blockNumber
        )
    {
        AnchorRecord memory rec = records[anchorDigest];
        return (rec.submitter, rec.blockTimestamp, rec.blockNumber);
    }
}
