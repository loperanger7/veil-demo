// PaymentReceiptMessage.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-405: Encrypted payment receipt sent through the Triple Ratchet session.
// The receipt contains all information the recipient needs to locate their
// incoming TXO using the shared secret and their view key.
//
// Wire format: JSON-encoded Codable (transported as MessagePipeline contentType .payment)
//
// References: Veil Spec Section 8.5

import Foundation

// MARK: - Payment Receipt Message

/// A payment notification sent through the encrypted messaging channel.
///
/// After a transaction is confirmed on the MobileCoin ledger, the sender
/// constructs this receipt and sends it via the Triple Ratchet session.
/// The recipient uses the `sharedSecret` combined with their view key
/// to locate and claim the incoming TXO on the ledger.
public struct PaymentReceiptMessage: Sendable, Codable, Equatable {

    // MARK: Properties

    /// Transaction hash on the MobileCoin ledger (32 bytes, hex-encoded).
    public let txHash: String

    /// ECDH shared secret for locating the recipient's TXO (base64-encoded).
    /// The recipient combines this with their view key to decrypt the amount
    /// and compute the one-time public key for spending.
    public let sharedSecret: String

    /// Payment amount in picoMOB.
    public let amountPicomob: UInt64

    /// Optional human-readable memo (max 256 characters).
    public let memo: String

    /// Serialized receipt proof (Bulletproofs+ commitment, base64-encoded).
    /// Allows the recipient to verify the amount without trusting the sender.
    public let receiptProof: String

    /// Block index where the transaction was confirmed.
    public let blockIndex: UInt64

    /// ISO 8601 timestamp of the payment.
    public let timestamp: String

    /// Protocol version for forward compatibility.
    public let version: Int

    // MARK: Initialization

    public init(
        txHash: String,
        sharedSecret: String,
        amountPicomob: UInt64,
        memo: String = "",
        receiptProof: String,
        blockIndex: UInt64,
        timestamp: Date = Date(),
        version: Int = 1
    ) {
        self.txHash = txHash
        self.sharedSecret = sharedSecret
        self.amountPicomob = amountPicomob
        self.memo = String(memo.prefix(256)) // Enforce max length
        self.receiptProof = receiptProof
        self.blockIndex = blockIndex
        self.version = version

        // ISO 8601 formatting
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        self.timestamp = formatter.string(from: timestamp)
    }

    // MARK: Factory Methods

    /// Create a receipt from a confirmed transaction and its construction context.
    /// - Parameters:
    ///   - confirmedTx: The confirmed transaction.
    ///   - envelope: The original transaction envelope.
    ///   - sharedSecret: ECDH shared secret for the recipient's output.
    ///   - memo: Optional memo text.
    /// - Returns: A receipt ready for encryption and sending.
    public static func fromConfirmedTransaction(
        _ confirmedTx: ConfirmedTransaction,
        envelope: TransactionEnvelope,
        sharedSecret: Data,
        memo: String = ""
    ) -> PaymentReceiptMessage {
        PaymentReceiptMessage(
            txHash: confirmedTx.txHash.hexEncodedString(),
            sharedSecret: sharedSecret.base64EncodedString(),
            amountPicomob: confirmedTx.amount,
            memo: memo,
            receiptProof: envelope.serializedTransaction.prefix(64).base64EncodedString(),
            blockIndex: confirmedTx.blockIndex
        )
    }

    // MARK: Serialization

    /// Encode the receipt as JSON data for transmission through the message pipeline.
    /// - Returns: JSON-encoded receipt data.
    public func encode() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    /// Decode a receipt from JSON data received through the message pipeline.
    /// - Parameter data: JSON-encoded receipt.
    /// - Returns: Decoded receipt message.
    public static func decode(from data: Data) throws -> PaymentReceiptMessage {
        let decoder = JSONDecoder()
        return try decoder.decode(PaymentReceiptMessage.self, from: data)
    }

    // MARK: Validation

    /// Validate receipt fields for consistency.
    /// - Returns: `true` if all fields are well-formed.
    public var isValid: Bool {
        // txHash must be 64 hex characters (32 bytes)
        guard txHash.count == 64, txHash.allSatisfy(\.isHexDigit) else {
            return false
        }
        // sharedSecret must be valid base64
        guard Data(base64Encoded: sharedSecret) != nil else {
            return false
        }
        // Amount must be positive
        guard amountPicomob > 0 else {
            return false
        }
        // Memo must not exceed 256 characters
        guard memo.count <= 256 else {
            return false
        }
        // Block index must be positive
        guard blockIndex > 0 else {
            return false
        }
        // Version must be recognized
        guard version >= 1 else {
            return false
        }
        return true
    }

    /// Amount formatted as MOB.
    public var amountInMOB: Double {
        Double(amountPicomob) / Double(MobileCoinConstants.picoMOBPerMOB)
    }
}

// MARK: - Data Hex Extension

extension Data {
    /// Convert data to a lowercase hex-encoded string.
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }

    /// Initialize from a hex-encoded string.
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else {
                return nil
            }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}
