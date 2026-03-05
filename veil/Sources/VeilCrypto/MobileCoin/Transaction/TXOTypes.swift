// TXOTypes.swift
// VEIL — MobileCoin Payment Integration
//
// Core data types for MobileCoin transaction inputs and outputs.
// TXO = Transaction Output (the fundamental unit of value in MobileCoin).
//
// References: MobileCoin Protocol, CryptoNote ring signatures

import Foundation

// MARK: - Unspent TXO

/// An unspent transaction output owned by the wallet.
/// These are the "coins" available for spending.
public struct UnspentTXO: Sendable, Equatable, Codable, Identifiable {

    /// Unique identifier for this TXO (derived from txoPublicKey).
    public var id: Data { txoPublicKey }

    /// The TXO's one-time public key (32 bytes).
    /// This uniquely identifies the output on the ledger.
    public let txoPublicKey: Data

    /// Amount in picoMOB (1 MOB = 10^12 picoMOB).
    public let amount: UInt64

    /// Block index where this TXO was created.
    public let blockIndex: UInt64

    /// Timestamp when this TXO was detected (local time).
    public let detectedAt: Date

    /// The subaddress index this TXO was received at.
    public let subaddressIndex: UInt64

    /// Key image (32 bytes). Used for double-spend detection.
    /// Computed lazily from txoPublicKey + spend key.
    public let keyImage: Data?

    /// Whether this TXO has been spent (key image appeared on ledger).
    public let isSpent: Bool

    public init(
        txoPublicKey: Data,
        amount: UInt64,
        blockIndex: UInt64,
        detectedAt: Date = Date(),
        subaddressIndex: UInt64 = 0,
        keyImage: Data? = nil,
        isSpent: Bool = false
    ) {
        self.txoPublicKey = txoPublicKey
        self.amount = amount
        self.blockIndex = blockIndex
        self.detectedAt = detectedAt
        self.subaddressIndex = subaddressIndex
        self.keyImage = keyImage
        self.isSpent = isSpent
    }

    /// Amount formatted as MOB (decimal).
    public var amountInMOB: Double {
        Double(amount) / Double(MobileCoinConstants.picoMOBPerMOB)
    }
}

// MARK: - TXO Input (for transaction construction)

/// A TXO selected as input for a new transaction, complete with ring members.
public struct TXOInput: Sendable, Equatable {

    /// The real TXO being spent.
    public let realTXO: UnspentTXO

    /// Ring members (decoy public keys) for this input.
    /// Count should be `ringSize - 1` (the real TXO is added by the SDK).
    public let ringMembers: [RingMember]

    /// Position of the real TXO within the ring (0-indexed).
    /// Set by the SDK during ring construction.
    public let realInputIndex: Int

    public init(
        realTXO: UnspentTXO,
        ringMembers: [RingMember],
        realInputIndex: Int = 0
    ) {
        self.realTXO = realTXO
        self.ringMembers = ringMembers
        self.realInputIndex = realInputIndex
    }

    /// Convert to SDK format for transaction building.
    public func toSDKInput() -> SDKTXOInput {
        SDKTXOInput(
            txoPublicKey: realTXO.txoPublicKey,
            amount: realTXO.amount,
            ringMembers: ringMembers.map(\.publicKey),
            membershipProofs: ringMembers.map(\.membershipProof)
        )
    }
}

// MARK: - Ring Member

/// A decoy TXO used in a ring signature to provide sender anonymity.
public struct RingMember: Sendable, Equatable {

    /// Public key of the decoy TXO (32 bytes).
    public let publicKey: Data

    /// Merkle membership proof for this TXO in the ledger.
    public let membershipProof: Data

    /// Block index where this TXO exists.
    public let blockIndex: UInt64

    public init(publicKey: Data, membershipProof: Data, blockIndex: UInt64) {
        self.publicKey = publicKey
        self.membershipProof = membershipProof
        self.blockIndex = blockIndex
    }
}

// MARK: - TXO Output

/// A planned output for a new transaction.
public struct TXOOutput: Sendable, Equatable {

    /// Recipient's public subaddress.
    public let recipientAddress: PublicSubaddress

    /// Amount to send in picoMOB.
    public let amount: UInt64

    /// Whether this is a change output (back to sender).
    public let isChange: Bool

    public init(recipientAddress: PublicSubaddress, amount: UInt64, isChange: Bool = false) {
        self.recipientAddress = recipientAddress
        self.amount = amount
        self.isChange = isChange
    }
}

// MARK: - Transaction Envelope

/// A fully constructed, signed transaction ready for submission.
public struct TransactionEnvelope: Sendable, Equatable {

    /// Serialized signed transaction bytes (wire format).
    public let serializedTransaction: Data

    /// Transaction hash (Blake2b-256, 32 bytes).
    public let txHash: Data

    /// Planned outputs (recipient + change).
    public let outputs: [TXOOutput]

    /// Total fee paid in picoMOB.
    public let fee: UInt64

    /// Total input amount in picoMOB.
    public let totalInputAmount: UInt64

    /// Timestamp when this transaction was constructed.
    public let constructedAt: Date

    public init(
        serializedTransaction: Data,
        txHash: Data,
        outputs: [TXOOutput],
        fee: UInt64,
        totalInputAmount: UInt64,
        constructedAt: Date = Date()
    ) {
        self.serializedTransaction = serializedTransaction
        self.txHash = txHash
        self.outputs = outputs
        self.fee = fee
        self.totalInputAmount = totalInputAmount
        self.constructedAt = constructedAt
    }

    /// Size of the serialized transaction in bytes.
    public var transactionSize: Int {
        serializedTransaction.count
    }

    /// Output amount (excluding change and fee).
    public var paymentAmount: UInt64 {
        outputs.filter { !$0.isChange }.reduce(0) { $0 + $1.amount }
    }

    /// Change amount.
    public var changeAmount: UInt64 {
        outputs.filter(\.isChange).reduce(0) { $0 + $1.amount }
    }
}

// MARK: - Confirmed Transaction

/// A transaction that has been confirmed on the MobileCoin ledger.
public struct ConfirmedTransaction: Sendable, Equatable, Codable {

    /// Transaction hash (32 bytes).
    public let txHash: Data

    /// Block index where the transaction was included.
    public let blockIndex: UInt64

    /// Number of subsequent blocks confirming this transaction.
    public let confirmations: UInt32

    /// Timestamp of confirmation.
    public let confirmedAt: Date

    /// Amount sent in picoMOB.
    public let amount: UInt64

    /// Fee paid in picoMOB.
    public let fee: UInt64

    public init(
        txHash: Data,
        blockIndex: UInt64,
        confirmations: UInt32 = 1,
        confirmedAt: Date = Date(),
        amount: UInt64,
        fee: UInt64
    ) {
        self.txHash = txHash
        self.blockIndex = blockIndex
        self.confirmations = confirmations
        self.confirmedAt = confirmedAt
        self.amount = amount
        self.fee = fee
    }
}

// MARK: - Incoming TXO

/// A TXO detected by Fog as belonging to our view key.
public struct IncomingTXO: Sendable, Equatable {

    /// TXO public key (32 bytes).
    public let txoPublicKey: Data

    /// Encrypted amount (decryptable with view key + shared secret).
    public let encryptedAmount: Data

    /// ECDH shared secret for this output.
    public let sharedSecret: Data

    /// Block index where this TXO appeared.
    public let blockIndex: UInt64

    /// Timestamp of detection.
    public let detectedAt: Date

    public init(
        txoPublicKey: Data,
        encryptedAmount: Data,
        sharedSecret: Data,
        blockIndex: UInt64,
        detectedAt: Date = Date()
    ) {
        self.txoPublicKey = txoPublicKey
        self.encryptedAmount = encryptedAmount
        self.sharedSecret = sharedSecret
        self.blockIndex = blockIndex
        self.detectedAt = detectedAt
    }
}
