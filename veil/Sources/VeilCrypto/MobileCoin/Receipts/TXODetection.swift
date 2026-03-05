// TXODetection.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-405 (continued): Locate incoming TXOs using the shared secret from
// a payment receipt combined with the recipient's view key.
//
// When a payment receipt arrives via the Triple Ratchet session:
// 1. Extract the shared secret from the receipt
// 2. Query Fog for incoming TXOs
// 3. Match the shared secret against Fog results
// 4. Decrypt the amount to confirm
// 5. Add to the wallet's unspent TXO set
//
// References: Veil Spec Section 8.5, CryptoNote view key scanning

import Foundation

// MARK: - TXO Detector

/// Detects and claims incoming TXOs from payment receipts.
///
/// After receiving an encrypted payment receipt, the recipient uses this
/// detector to locate the corresponding output on the MobileCoin ledger.
/// The shared secret in the receipt allows the view key to identify which
/// TXO belongs to this wallet.
public struct TXODetector: Sendable {

    // MARK: Properties

    private let mobClient: MobileCoinClient

    // MARK: Initialization

    public init(mobClient: MobileCoinClient) {
        self.mobClient = mobClient
    }

    // MARK: Detection

    /// Find the incoming TXO corresponding to a payment receipt.
    ///
    /// - Parameters:
    ///   - receipt: The received payment receipt.
    ///   - incomingTXOs: TXOs detected by Fog for this view key.
    ///   - viewKey: Recipient's private view key.
    /// - Returns: A `DetectedTXO` with the decrypted amount, or nil if not found.
    public func findIncomingTXO(
        receipt: PaymentReceiptMessage,
        incomingTXOs: [IncomingTXO],
        viewKey: SecureBytes
    ) async -> DetectedTXO? {
        guard let sharedSecretData = Data(base64Encoded: receipt.sharedSecret) else {
            return nil
        }

        // Search through incoming TXOs for a matching shared secret
        for txo in incomingTXOs {
            if txo.sharedSecret == sharedSecretData {
                // Decrypt the amount using the view key
                if let amount = await mobClient.decryptTXOAmount(
                    encryptedAmount: txo.encryptedAmount,
                    sharedSecret: sharedSecretData,
                    viewKey: viewKey
                ) {
                    return DetectedTXO(
                        txoPublicKey: txo.txoPublicKey,
                        amount: amount,
                        blockIndex: txo.blockIndex,
                        sharedSecret: sharedSecretData,
                        receiptTxHash: receipt.txHash,
                        memo: receipt.memo,
                        detectedAt: Date()
                    )
                }
            }
        }

        return nil
    }

    /// Scan a batch of receipts against incoming TXOs.
    ///
    /// - Parameters:
    ///   - receipts: Multiple payment receipts to process.
    ///   - incomingTXOs: All incoming TXOs from Fog.
    ///   - viewKey: Recipient's private view key.
    /// - Returns: Array of detected TXOs (one per matched receipt).
    public func batchDetect(
        receipts: [PaymentReceiptMessage],
        incomingTXOs: [IncomingTXO],
        viewKey: SecureBytes
    ) async -> [DetectedTXO] {
        var detected: [DetectedTXO] = []

        for receipt in receipts {
            if let txo = await findIncomingTXO(
                receipt: receipt,
                incomingTXOs: incomingTXOs,
                viewKey: viewKey
            ) {
                detected.append(txo)
            }
        }

        return detected
    }

    /// Convert a detected TXO to an UnspentTXO for wallet inclusion.
    ///
    /// - Parameters:
    ///   - detectedTXO: The TXO found via receipt matching.
    ///   - spendKey: Wallet's private spend key (for key image computation).
    /// - Returns: An `UnspentTXO` ready for the wallet's balance.
    public func toUnspentTXO(
        _ detectedTXO: DetectedTXO,
        spendKey: SecureBytes
    ) async throws -> UnspentTXO {
        // Compute key image for future spent detection
        let keyImage = try await mobClient.computeKeyImage(
            txoPublicKey: detectedTXO.txoPublicKey,
            spendKey: spendKey
        )

        return UnspentTXO(
            txoPublicKey: detectedTXO.txoPublicKey,
            amount: detectedTXO.amount,
            blockIndex: detectedTXO.blockIndex,
            detectedAt: detectedTXO.detectedAt,
            keyImage: keyImage,
            isSpent: false
        )
    }
}

// MARK: - Detected TXO

/// A TXO that has been matched to a payment receipt.
public struct DetectedTXO: Sendable, Equatable {

    /// TXO public key on the ledger (32 bytes).
    public let txoPublicKey: Data

    /// Decrypted amount in picoMOB.
    public let amount: UInt64

    /// Block index where this TXO was confirmed.
    public let blockIndex: UInt64

    /// The shared secret that was used to locate this TXO.
    public let sharedSecret: Data

    /// Transaction hash from the original receipt.
    public let receiptTxHash: String

    /// Memo from the receipt.
    public let memo: String

    /// When this TXO was detected.
    public let detectedAt: Date

    /// Amount formatted as MOB.
    public var amountInMOB: Double {
        Double(amount) / Double(MobileCoinConstants.picoMOBPerMOB)
    }
}
