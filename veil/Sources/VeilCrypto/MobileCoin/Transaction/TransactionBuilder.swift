// TransactionBuilder.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-403: Construct MobileCoin transactions locally on-device.
// Orchestrates TXO selection → ring member acquisition → ring signature
// generation → Bulletproofs+ range proof → serialization.
//
// Performance target: < 3 seconds on iPhone 14.
// Ring size: 11 (MobileCoin default).
//
// References: Veil Spec Section 8.3, CryptoNote ring signatures, Bulletproofs+

import Foundation

// MARK: - Transaction Builder

/// Constructs signed MobileCoin transactions ready for submission.
///
/// The build process:
/// 1. Select TXOs via `TXOSelector`
/// 2. Acquire ring members for each input
/// 3. Build the signed transaction via `MobileCoinClient`
/// 4. Validate the result
/// 5. Return a `TransactionEnvelope`
public struct TransactionBuilder: Sendable {

    // MARK: Properties

    private let client: MobileCoinClient
    private let selector: TXOSelector
    private let ringProvider: RingMemberProvider

    // MARK: Initialization

    /// Create a transaction builder.
    /// - Parameters:
    ///   - client: MobileCoin client for SDK operations.
    ///   - selector: TXO selection strategy.
    ///   - ringProvider: Ring member provider for decoy outputs.
    public init(
        client: MobileCoinClient,
        selector: TXOSelector = TXOSelector(),
        ringProvider: RingMemberProvider = MockRingMemberProvider()
    ) {
        self.client = client
        self.selector = selector
        self.ringProvider = ringProvider
    }

    // MARK: Build Transaction

    /// Build a complete, signed transaction.
    ///
    /// - Parameters:
    ///   - amount: Payment amount in picoMOB.
    ///   - recipientAddress: Recipient's MobileCoin public subaddress.
    ///   - senderKeyPair: Sender's MobileCoin key pair (for signing and change).
    ///   - senderAddress: Sender's own subaddress (for change output).
    ///   - availableTXOs: All unspent TXOs in the wallet.
    ///   - memo: Optional memo (not included in on-chain transaction; for receipt only).
    /// - Returns: A `TransactionEnvelope` ready for submission.
    /// - Throws: `MobileCoinError` on insufficient balance, ring failure, or proof failure.
    public func buildTransaction(
        amount: UInt64,
        recipientAddress: PublicSubaddress,
        senderKeyPair: MobileCoinKeyPair,
        senderAddress: PublicSubaddress,
        availableTXOs: [UnspentTXO],
        memo: String = ""
    ) async throws -> TransactionEnvelope {
        // 1. Select TXOs
        let selection = try selector.select(
            targetAmount: amount,
            from: availableTXOs
        )

        // Verify selection invariant
        guard selection.isBalanced else {
            throw MobileCoinError.txoSelectionFailed(
                reason: "Selection is not balanced: \(selection.totalInputAmount) != \(amount) + \(selection.fee) + \(selection.change)"
            )
        }

        // 2. Acquire ring members for each selected TXO
        var txoInputs: [TXOInput] = []
        for txo in selection.selectedTXOs {
            let members = try await ringProvider.getRingMembers(
                for: txo,
                ringSize: MobileCoinConstants.defaultRingSize
            )
            txoInputs.append(TXOInput(
                realTXO: txo,
                ringMembers: members,
                realInputIndex: 0 // SDK will randomize position
            ))
        }

        // 3. Convert to SDK format
        let sdkInputs = txoInputs.map { $0.toSDKInput() }

        // 4. Build signed transaction via SDK
        let (txBytes, txHash) = try await client.buildTransaction(
            inputs: sdkInputs,
            recipientAddress: recipientAddress.address,
            outputAmount: amount,
            changeAddress: senderAddress.address,
            changeAmount: selection.change,
            spendKey: senderKeyPair.spendKey,
            fee: selection.fee
        )

        // 5. Validate transaction size
        guard txBytes.count <= MobileCoinConstants.maxTransactionSize else {
            throw MobileCoinError.transactionTooLarge(bytes: txBytes.count)
        }

        // 6. Validate cryptographic proofs
        let isValid = await client.validateTransaction(txBytes)
        guard isValid else {
            throw MobileCoinError.ringSignatureFailed(
                detail: "Built transaction failed self-validation."
            )
        }

        // 7. Construct envelope
        let outputs = [
            TXOOutput(
                recipientAddress: recipientAddress,
                amount: amount,
                isChange: false
            ),
            TXOOutput(
                recipientAddress: senderAddress,
                amount: selection.change,
                isChange: true
            ),
        ]

        return TransactionEnvelope(
            serializedTransaction: txBytes,
            txHash: txHash,
            outputs: outputs,
            fee: selection.fee,
            totalInputAmount: selection.totalInputAmount
        )
    }

    /// Estimate the fee for a transaction without building it.
    /// - Parameters:
    ///   - amount: Target payment amount in picoMOB.
    ///   - availableTXOs: Available unspent TXOs.
    /// - Returns: Estimated fee in picoMOB.
    public func estimateFee(
        amount: UInt64,
        availableTXOs: [UnspentTXO]
    ) throws -> UInt64 {
        let selection = try selector.select(
            targetAmount: amount,
            from: availableTXOs
        )
        return selection.fee
    }
}

// MARK: - Ring Member Provider Protocol

/// Abstraction for acquiring ring members (decoy outputs) for transaction construction.
/// Production implementation queries the ledger; mock provides deterministic members.
public protocol RingMemberProvider: Sendable {
    /// Get ring members for a given TXO.
    /// - Parameters:
    ///   - txo: The real TXO being spent.
    ///   - ringSize: Total ring size (real + decoys).
    /// - Returns: Array of `ringSize - 1` decoy ring members.
    func getRingMembers(
        for txo: UnspentTXO,
        ringSize: Int
    ) async throws -> [RingMember]
}

// MARK: - Mock Ring Member Provider

/// Provides deterministic ring members for testing and mock SDK mode.
public struct MockRingMemberProvider: RingMemberProvider {

    public init() {}

    public func getRingMembers(
        for txo: UnspentTXO,
        ringSize: Int
    ) async throws -> [RingMember] {
        let decoyCount = ringSize - 1

        return (0..<decoyCount).map { index in
            // Deterministic decoy: hash of real TXO key + index
            var keyData = txo.txoPublicKey
            withUnsafeBytes(of: UInt32(index).littleEndian) { keyData.append(contentsOf: $0) }

            var publicKey = Data(count: 32)
            for (i, byte) in keyData.enumerated() {
                let idx = i % 32
                publicKey[idx] ^= byte
                publicKey[idx] = publicKey[idx] &+ UInt8(index & 0xFF)
            }

            // Mock membership proof (32 bytes)
            var proof = Data(count: 32)
            proof[0] = UInt8(index & 0xFF)
            for (i, byte) in publicKey.enumerated() {
                let idx = (i + 1) % 32
                proof[idx] ^= byte
            }

            return RingMember(
                publicKey: publicKey,
                membershipProof: proof,
                blockIndex: txo.blockIndex > 0 ? txo.blockIndex - 1 : 0
            )
        }
    }
}

// MARK: - Ledger Ring Member Provider

/// Production ring member provider that queries the MobileCoin ledger.
/// Placeholder — requires Full-Service Node API for ring member selection.
public struct LedgerRingMemberProvider: RingMemberProvider {

    private let fullServiceNodeURL: URL

    public init(fullServiceNodeURL: URL) {
        self.fullServiceNodeURL = fullServiceNodeURL
    }

    public func getRingMembers(
        for txo: UnspentTXO,
        ringSize: Int
    ) async throws -> [RingMember] {
        // Production: POST to /full-service/get-ring-members
        // Request: { txo_public_key, ring_size }
        // Response: { ring_members: [{ public_key, membership_proof, block_index }] }
        //
        // For now, delegate to mock to allow compilation:
        let mock = MockRingMemberProvider()
        return try await mock.getRingMembers(for: txo, ringSize: ringSize)
    }
}
