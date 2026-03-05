// MobileCoinSDKProtocol.swift
// VEIL — MobileCoin Payment Integration
//
// Protocol abstraction for the MobileCoin SDK, enabling compilation and
// testing without the real SDK binary. Follows the same pattern as CLibOQS
// for liboqs — production code depends on the protocol, not the concrete type.
//
// References: MobileCoin SDK, Veil Spec Section 8

import Foundation

// MARK: - SDK Protocol

/// Abstraction layer over the MobileCoin SDK.
/// Production builds inject the real SDK adapter; tests and CI use `MockMobileCoinSDK`.
public protocol MobileCoinSDKProtocol: Sendable {

    // MARK: Key Operations

    /// Validate that raw bytes form a valid Ristretto255 scalar (on the ed25519 curve).
    /// - Parameter scalarBytes: 32-byte scalar candidate.
    /// - Returns: `true` if the bytes represent a valid scalar mod l.
    func isValidRistrettoScalar(_ scalarBytes: Data) -> Bool

    /// Derive the public subaddress from spend and view public keys at a given index.
    /// - Parameters:
    ///   - spendPublicKey: 32-byte Ristretto255 public spend key.
    ///   - viewPublicKey: 32-byte Ristretto255 public view key.
    ///   - subaddressIndex: Subaddress index (default 0 for primary).
    /// - Returns: Serialized public address (typically 66 bytes).
    func derivePublicSubaddress(
        spendPublicKey: Data,
        viewPublicKey: Data,
        subaddressIndex: UInt64
    ) throws -> Data

    // MARK: Transaction Construction

    /// Build a signed transaction with ring signatures and Bulletproofs+ range proofs.
    /// - Parameters:
    ///   - inputs: Selected unspent TXOs with ring members.
    ///   - recipientAddress: Serialized recipient public address.
    ///   - outputAmount: Amount to send in picoMOB.
    ///   - changeAddress: Sender's change subaddress.
    ///   - changeAmount: Change amount in picoMOB.
    ///   - spendKey: Sender's private spend key (32 bytes).
    ///   - ringSize: Number of ring members per input (default 11).
    ///   - fee: Network fee in picoMOB.
    /// - Returns: Serialized signed transaction bytes.
    func buildTransaction(
        inputs: [SDKTXOInput],
        recipientAddress: Data,
        outputAmount: UInt64,
        changeAddress: Data,
        changeAmount: UInt64,
        spendKey: Data,
        ringSize: Int,
        fee: UInt64
    ) throws -> Data

    /// Compute the transaction hash (Blake2b-256) from serialized transaction bytes.
    /// - Parameter transactionBytes: Signed transaction.
    /// - Returns: 32-byte transaction hash.
    func computeTransactionHash(_ transactionBytes: Data) -> Data

    /// Validate a signed transaction (check ring signatures and range proofs).
    /// - Parameter transactionBytes: Signed transaction.
    /// - Returns: `true` if all cryptographic proofs are valid.
    func validateTransaction(_ transactionBytes: Data) -> Bool

    // MARK: Fog / Balance

    /// Compute the key image for a given TXO (used for spent detection).
    /// - Parameters:
    ///   - txoPublicKey: The TXO's one-time public key.
    ///   - spendKey: Owner's private spend key.
    /// - Returns: 32-byte key image.
    func computeKeyImage(txoPublicKey: Data, spendKey: Data) throws -> Data

    /// Attempt to decrypt a TXO amount using the view key and shared secret.
    /// - Parameters:
    ///   - encryptedAmount: The TXO's encrypted amount field.
    ///   - sharedSecret: ECDH shared secret for this TXO.
    ///   - viewKey: Recipient's private view key.
    /// - Returns: Decrypted amount in picoMOB, or nil if not ours.
    func decryptTXOAmount(
        encryptedAmount: Data,
        sharedSecret: Data,
        viewKey: Data
    ) -> UInt64?

    // MARK: Attestation

    /// Verify an SGX attestation report from a Fog node.
    /// - Parameters:
    ///   - report: Raw attestation report bytes.
    ///   - expectedMrEnclave: Expected MRENCLAVE measurement (32 bytes).
    /// - Returns: `true` if attestation is valid and enclave identity matches.
    func verifySGXAttestation(
        report: Data,
        expectedMrEnclave: Data
    ) -> Bool
}

// MARK: - SDK Input Types

/// Lightweight representation of a TXO input for SDK transaction building.
public struct SDKTXOInput: Sendable, Equatable {
    /// The TXO's one-time public key (identifies the output).
    public let txoPublicKey: Data
    /// Amount in picoMOB.
    public let amount: UInt64
    /// Ring members (public keys of decoy outputs).
    public let ringMembers: [Data]
    /// Membership proofs for ring members (Merkle proofs).
    public let membershipProofs: [Data]

    public init(
        txoPublicKey: Data,
        amount: UInt64,
        ringMembers: [Data],
        membershipProofs: [Data]
    ) {
        self.txoPublicKey = txoPublicKey
        self.amount = amount
        self.ringMembers = ringMembers
        self.membershipProofs = membershipProofs
    }
}

// MARK: - Mock SDK

/// Mock implementation for compilation and testing without the real MobileCoin SDK.
/// All cryptographic operations return deterministic placeholder values.
public struct MockMobileCoinSDK: MobileCoinSDKProtocol {

    public init() {}

    public func isValidRistrettoScalar(_ scalarBytes: Data) -> Bool {
        // Accept any 32-byte value in mock mode.
        // Real SDK would verify: scalar < curve order l.
        scalarBytes.count == 32
    }

    public func derivePublicSubaddress(
        spendPublicKey: Data,
        viewPublicKey: Data,
        subaddressIndex: UInt64
    ) throws -> Data {
        guard spendPublicKey.count == 32, viewPublicKey.count == 32 else {
            throw MobileCoinError.subaddressDerivationFailed
        }
        // Mock: concatenate keys + index as deterministic "address"
        var address = Data()
        address.append(spendPublicKey)
        address.append(viewPublicKey)
        withUnsafeBytes(of: subaddressIndex.littleEndian) { address.append(contentsOf: $0) }
        // SHA-256 to get fixed 32-byte output, then prefix with 0x01 version byte
        return mockHash(address, prefix: 0x01)
    }

    public func buildTransaction(
        inputs: [SDKTXOInput],
        recipientAddress: Data,
        outputAmount: UInt64,
        changeAddress: Data,
        changeAmount: UInt64,
        spendKey: Data,
        ringSize: Int,
        fee: UInt64
    ) throws -> Data {
        guard !inputs.isEmpty else {
            throw MobileCoinError.noUnspentTXOs
        }
        guard spendKey.count == 32 else {
            throw MobileCoinError.invalidSpendKey
        }
        // Mock: build a deterministic "transaction" from inputs
        var txData = Data()
        // Version byte
        txData.append(0x02)
        // Number of inputs
        withUnsafeBytes(of: UInt32(inputs.count).littleEndian) { txData.append(contentsOf: $0) }
        // Output amount
        withUnsafeBytes(of: outputAmount.littleEndian) { txData.append(contentsOf: $0) }
        // Change amount
        withUnsafeBytes(of: changeAmount.littleEndian) { txData.append(contentsOf: $0) }
        // Fee
        withUnsafeBytes(of: fee.littleEndian) { txData.append(contentsOf: $0) }
        // Recipient
        txData.append(recipientAddress.prefix(32))
        // Mock ring signature placeholder (64 bytes per input)
        for input in inputs {
            txData.append(mockHash(input.txoPublicKey, prefix: 0x03))
            txData.append(mockHash(input.txoPublicKey, prefix: 0x04))
        }
        // Mock Bulletproofs+ placeholder (32 bytes)
        txData.append(mockHash(txData, prefix: 0x05))
        return txData
    }

    public func computeTransactionHash(_ transactionBytes: Data) -> Data {
        mockHash(transactionBytes, prefix: 0x06)
    }

    public func validateTransaction(_ transactionBytes: Data) -> Bool {
        // Mock: any transaction with version byte 0x02 is "valid"
        guard let first = transactionBytes.first else { return false }
        return first == 0x02
    }

    public func computeKeyImage(txoPublicKey: Data, spendKey: Data) throws -> Data {
        guard txoPublicKey.count == 32, spendKey.count == 32 else {
            throw MobileCoinError.sdkError(detail: "Invalid key length for key image computation.")
        }
        var input = txoPublicKey
        input.append(spendKey)
        return mockHash(input, prefix: 0x07)
    }

    public func decryptTXOAmount(
        encryptedAmount: Data,
        sharedSecret: Data,
        viewKey: Data
    ) -> UInt64? {
        // Mock: XOR first 8 bytes of encrypted amount with first 8 bytes of shared secret
        guard encryptedAmount.count >= 8, sharedSecret.count >= 8 else { return nil }
        var result: UInt64 = 0
        let encBytes = Array(encryptedAmount.prefix(8))
        let secBytes = Array(sharedSecret.prefix(8))
        for i in 0..<8 {
            let byte = encBytes[i] ^ secBytes[i]
            result |= UInt64(byte) << (i * 8)
        }
        return result
    }

    public func verifySGXAttestation(
        report: Data,
        expectedMrEnclave: Data
    ) -> Bool {
        // Mock: accept if report contains the expected MRENCLAVE
        guard expectedMrEnclave.count == 32 else { return false }
        // In mock, just check non-empty report
        return !report.isEmpty
    }

    // MARK: - Mock Helpers

    /// Simple deterministic hash: SHA-256-like via Data manipulation.
    /// NOT cryptographically secure — for mock/test use only.
    private func mockHash(_ input: Data, prefix: UInt8) -> Data {
        var hash = Data(count: 32)
        hash[0] = prefix
        for (i, byte) in input.enumerated() {
            let idx = (i % 31) + 1
            hash[idx] ^= byte
            hash[idx] = hash[idx] &+ UInt8(i & 0xFF)
        }
        return hash
    }
}
