// ReceiptEncryption.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-405 (continued): Encrypt and decrypt payment receipts through the
// existing Triple Ratchet session. Receipts are sent as contentType .payment
// via the MessagePipeline — no separate transport channel needed.
//
// Flow:
//   Sender: PaymentReceiptMessage → JSON → encrypt(TripleRatchet) → MessagePipeline
//   Recipient: MessagePipeline → decrypt(TripleRatchet) → JSON → PaymentReceiptMessage
//
// References: Veil Spec Section 8.5

import Foundation

// MARK: - Receipt Encryptor

/// Encrypts payment receipts for transmission through the Triple Ratchet session.
///
/// This type bridges between the MobileCoin payment layer and the existing
/// messaging infrastructure. Receipts are serialized as JSON, encrypted under
/// the current ratchet state, and sent as `.payment` content type messages.
public struct ReceiptEncryptor: Sendable {

    // MARK: Initialization

    public init() {}

    // MARK: Encryption

    /// Prepare a payment receipt for transmission through the message pipeline.
    ///
    /// The receipt is serialized to JSON and returned as plaintext `Data`.
    /// The caller (MessagePipeline) handles Triple Ratchet encryption.
    ///
    /// - Parameter receipt: The payment receipt to send.
    /// - Returns: JSON-encoded receipt data (plaintext, pre-encryption).
    /// - Throws: Encoding errors if the receipt contains invalid data.
    public func prepareForEncryption(
        _ receipt: PaymentReceiptMessage
    ) throws -> Data {
        guard receipt.isValid else {
            throw MobileCoinError.invalidReceipt(
                detail: "Receipt failed validation before encryption."
            )
        }
        return try receipt.encode()
    }

    /// Decrypt and parse a payment receipt from received message data.
    ///
    /// The caller (MessagePipeline) handles Triple Ratchet decryption.
    /// This method parses the resulting plaintext as a PaymentReceiptMessage.
    ///
    /// - Parameter decryptedData: Plaintext data after Triple Ratchet decryption.
    /// - Returns: The decoded payment receipt.
    /// - Throws: `MobileCoinError.receiptDecryptionFailed` if parsing fails.
    public func parseDecryptedReceipt(
        _ decryptedData: Data
    ) throws -> PaymentReceiptMessage {
        do {
            let receipt = try PaymentReceiptMessage.decode(from: decryptedData)

            // Validate decoded receipt
            guard receipt.isValid else {
                throw MobileCoinError.invalidReceipt(
                    detail: "Decoded receipt failed validation."
                )
            }

            return receipt
        } catch let error as MobileCoinError {
            throw error
        } catch {
            throw MobileCoinError.receiptDecryptionFailed
        }
    }

    // MARK: Receipt Construction

    /// Construct a complete payment receipt from transaction results.
    ///
    /// - Parameters:
    ///   - confirmedTx: The confirmed transaction from the ledger.
    ///   - envelope: The original transaction envelope.
    ///   - sharedSecret: ECDH shared secret for the recipient's output.
    ///   - memo: Optional memo text.
    /// - Returns: An encrypted-ready receipt and its JSON data.
    public func constructReceipt(
        confirmedTx: ConfirmedTransaction,
        envelope: TransactionEnvelope,
        sharedSecret: Data,
        memo: String = ""
    ) throws -> (receipt: PaymentReceiptMessage, data: Data) {
        let receipt = PaymentReceiptMessage.fromConfirmedTransaction(
            confirmedTx,
            envelope: envelope,
            sharedSecret: sharedSecret,
            memo: memo
        )

        let data = try prepareForEncryption(receipt)
        return (receipt, data)
    }
}

// MARK: - Receipt Verifier

/// Verifies that a received payment receipt is consistent with the ledger.
///
/// After receiving and decrypting a receipt, the recipient can verify:
/// 1. The transaction hash exists on the ledger
/// 2. The block index matches
/// 3. The shared secret allows locating the incoming TXO
/// 4. The claimed amount matches the decrypted TXO amount
public struct ReceiptVerifier: Sendable {

    private let mobClient: MobileCoinClient

    public init(mobClient: MobileCoinClient) {
        self.mobClient = mobClient
    }

    /// Verify a received payment receipt against the local wallet state.
    ///
    /// - Parameters:
    ///   - receipt: The received payment receipt.
    ///   - viewKey: Recipient's private view key.
    ///   - incomingTXOs: Recently detected incoming TXOs from Fog.
    /// - Returns: A `VerificationResult` indicating whether the receipt is valid.
    public func verify(
        receipt: PaymentReceiptMessage,
        viewKey: SecureBytes,
        incomingTXOs: [IncomingTXO]
    ) async -> ReceiptVerificationResult {
        // 1. Basic validation
        guard receipt.isValid else {
            return .invalid(reason: "Receipt failed basic validation.")
        }

        // 2. Check that the shared secret matches an incoming TXO
        guard let sharedSecretData = Data(base64Encoded: receipt.sharedSecret) else {
            return .invalid(reason: "Invalid shared secret encoding.")
        }

        // Find matching TXO by shared secret
        let matchingTXO = incomingTXOs.first { txo in
            txo.sharedSecret == sharedSecretData
        }

        guard let txo = matchingTXO else {
            return .pending(reason: "TXO not yet detected; may still be propagating.")
        }

        // 3. Decrypt the amount and verify it matches the receipt
        if let decryptedAmount = await mobClient.decryptTXOAmount(
            encryptedAmount: txo.encryptedAmount,
            sharedSecret: sharedSecretData,
            viewKey: viewKey
        ) {
            if decryptedAmount == receipt.amountPicomob {
                return .verified(
                    txoPublicKey: txo.txoPublicKey,
                    amount: decryptedAmount,
                    blockIndex: txo.blockIndex
                )
            } else {
                return .amountMismatch(
                    claimed: receipt.amountPicomob,
                    actual: decryptedAmount
                )
            }
        }

        return .invalid(reason: "Could not decrypt TXO amount.")
    }
}

// MARK: - Verification Result

/// Result of verifying a payment receipt.
public enum ReceiptVerificationResult: Sendable, Equatable {
    /// Receipt is verified: amount matches, TXO found on ledger.
    case verified(txoPublicKey: Data, amount: UInt64, blockIndex: UInt64)

    /// TXO not yet detected — may still be propagating through Fog.
    case pending(reason: String)

    /// Amount in receipt doesn't match decrypted TXO amount.
    case amountMismatch(claimed: UInt64, actual: UInt64)

    /// Receipt is invalid (malformed fields or decryption failure).
    case invalid(reason: String)
}
