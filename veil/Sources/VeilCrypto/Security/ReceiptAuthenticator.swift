// VEIL — ReceiptAuthenticator.swift
// Ticket: VEIL-901 — Security Hardening (Red Team Findings: Receipt Auth + Replay)
// Spec reference: Section 8.5 (Payment Receipts)
//
// CRITICAL FIX #1: Payment receipts previously had no cryptographic signature.
//   The receiptProof field was merely the first 64 bytes of the serialized
//   transaction (base64-encoded), not a real signature. An attacker could modify
//   amounts, memos, or forge entire receipts.
//
// CRITICAL FIX #2: No replay protection existed. The same receipt could be
//   replayed multiple times, making the recipient believe multiple payments
//   were received.
//
// This module adds:
//   1. Ed25519 signature over the receipt's critical fields
//   2. Per-receipt random nonce for replay detection
//   3. Bounded nonce tracker to detect replayed receipts

import Foundation
import CryptoKit

// MARK: - Receipt Signature

/// An Ed25519 signature over a payment receipt's critical fields.
///
/// Signs: txHash ‖ amountPicomob (LE) ‖ blockIndex (LE) ‖ memo (UTF-8) ‖ nonce
///
/// This ensures that any modification to the receipt's fields invalidates
/// the signature, preventing amount tampering and receipt forgery.
public struct ReceiptSignature: Sendable, Codable, Equatable {
    /// Ed25519 signature bytes (64 bytes, base64-encoded).
    public let signatureBase64: String

    /// Random nonce for replay protection (32 bytes, base64-encoded).
    public let nonceBase64: String

    public init(signatureBase64: String, nonceBase64: String) {
        self.signatureBase64 = signatureBase64
        self.nonceBase64 = nonceBase64
    }

    /// Decode the signature bytes.
    public var signatureData: Data? {
        Data(base64Encoded: signatureBase64)
    }

    /// Decode the nonce bytes.
    public var nonceData: Data? {
        Data(base64Encoded: nonceBase64)
    }
}

// MARK: - Authenticated Receipt

/// A payment receipt with cryptographic authentication.
///
/// Wraps a `PaymentReceiptMessage` with an Ed25519 signature and replay nonce.
/// The signature covers all critical fields, preventing forgery. The nonce
/// prevents replay attacks where the same receipt is submitted multiple times.
public struct AuthenticatedReceipt: Sendable, Codable, Equatable {
    /// The underlying payment receipt message.
    public let receipt: PaymentReceiptMessage

    /// Ed25519 signature + replay nonce.
    public let authentication: ReceiptSignature

    /// Protocol version for authenticated receipts.
    public let authVersion: Int

    public init(
        receipt: PaymentReceiptMessage,
        authentication: ReceiptSignature,
        authVersion: Int = 1
    ) {
        self.receipt = receipt
        self.authentication = authentication
        self.authVersion = authVersion
    }

    /// Encode to JSON for transmission.
    public func encode() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }

    /// Decode from JSON received through the message pipeline.
    public static func decode(from data: Data) throws -> AuthenticatedReceipt {
        let decoder = JSONDecoder()
        return try decoder.decode(AuthenticatedReceipt.self, from: data)
    }
}

// MARK: - Receipt Authenticator

/// Signs and verifies payment receipts with Ed25519 signatures.
///
/// **Signing (sender side):**
/// ```swift
/// let authenticator = ReceiptAuthenticator()
/// let authenticated = try authenticator.sign(receipt: receipt, signingKey: myPrivateKey)
/// ```
///
/// **Verification (recipient side):**
/// ```swift
/// let isValid = try authenticator.verify(
///     authenticatedReceipt: authenticated,
///     senderIdentityKey: senderPublicKey,
///     nonceTracker: tracker
/// )
/// ```
public struct ReceiptAuthenticator: Sendable {

    /// Domain separator for receipt signatures.
    private static let signatureDomain = "veil-receipt-sig-v1"

    public init() {}

    // MARK: - Signing

    /// Sign a payment receipt with the sender's Ed25519 private key.
    ///
    /// - Parameters:
    ///   - receipt: The payment receipt to sign.
    ///   - signingKey: The sender's Ed25519 signing key.
    /// - Returns: An authenticated receipt with signature and nonce.
    public func sign(
        receipt: PaymentReceiptMessage,
        signingKey: Curve25519.Signing.PrivateKey
    ) throws -> AuthenticatedReceipt {
        // Generate random nonce (32 bytes)
        var nonceBytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, 32, &nonceBytes)
        guard status == errSecSuccess else {
            throw ReceiptAuthError.randomGenerationFailed
        }
        let nonce = Data(nonceBytes)

        // Construct the signing payload
        let payload = constructSigningPayload(receipt: receipt, nonce: nonce)

        // Sign with Ed25519
        let signature = try signingKey.signature(for: payload)

        let auth = ReceiptSignature(
            signatureBase64: signature.base64EncodedString(),
            nonceBase64: nonce.base64EncodedString()
        )

        return AuthenticatedReceipt(
            receipt: receipt,
            authentication: auth
        )
    }

    // MARK: - Verification

    /// Verify an authenticated receipt's signature and check for replay.
    ///
    /// - Parameters:
    ///   - authenticatedReceipt: The receipt to verify.
    ///   - senderIdentityKey: The sender's Ed25519 public key.
    ///   - nonceTracker: Nonce tracker for replay detection (optional).
    /// - Returns: `true` if signature is valid and nonce is fresh.
    public func verify(
        authenticatedReceipt: AuthenticatedReceipt,
        senderIdentityKey: Curve25519.Signing.PublicKey,
        nonceTracker: ReceiptNonceTracker? = nil
    ) async throws -> Bool {
        let auth = authenticatedReceipt.authentication

        // Decode signature and nonce
        guard let signatureData = auth.signatureData,
              let nonceData = auth.nonceData else {
            return false
        }

        // Validate nonce size
        guard nonceData.count == 32 else {
            return false
        }

        // Check for replay
        if let tracker = nonceTracker {
            let isFresh = await tracker.checkAndRecord(nonce: nonceData)
            guard isFresh else {
                return false
            }
        }

        // Reconstruct signing payload
        let payload = constructSigningPayload(
            receipt: authenticatedReceipt.receipt,
            nonce: nonceData
        )

        // Verify Ed25519 signature
        return senderIdentityKey.isValidSignature(signatureData, for: payload)
    }

    /// Verify signature only (no replay check).
    public func verifySignature(
        authenticatedReceipt: AuthenticatedReceipt,
        senderIdentityKey: Curve25519.Signing.PublicKey
    ) -> Bool {
        let auth = authenticatedReceipt.authentication

        guard let signatureData = auth.signatureData,
              let nonceData = auth.nonceData else {
            return false
        }

        guard nonceData.count == 32 else {
            return false
        }

        let payload = constructSigningPayload(
            receipt: authenticatedReceipt.receipt,
            nonce: nonceData
        )

        return senderIdentityKey.isValidSignature(signatureData, for: payload)
    }

    // MARK: - Payload Construction

    /// Construct the canonical signing payload from receipt fields.
    ///
    /// Format: domain ‖ txHash (hex→bytes) ‖ amountPicomob (8 bytes LE)
    ///         ‖ blockIndex (8 bytes LE) ‖ memo (UTF-8) ‖ nonce (32 bytes)
    private func constructSigningPayload(
        receipt: PaymentReceiptMessage,
        nonce: Data
    ) -> Data {
        var payload = Data()

        // Domain separator
        payload.append(Data(Self.signatureDomain.utf8))

        // txHash as raw bytes (from hex)
        if let txHashBytes = Data(hexString: receipt.txHash) {
            payload.append(txHashBytes)
        } else {
            payload.append(Data(receipt.txHash.utf8))
        }

        // Amount as 8-byte little-endian
        var amount = receipt.amountPicomob.littleEndian
        payload.append(Data(bytes: &amount, count: 8))

        // Block index as 8-byte little-endian
        var block = receipt.blockIndex.littleEndian
        payload.append(Data(bytes: &block, count: 8))

        // Memo as UTF-8
        payload.append(Data(receipt.memo.utf8))

        // Nonce
        payload.append(nonce)

        return payload
    }
}

// MARK: - Nonce Tracker

/// Tracks processed receipt nonces to detect replay attacks.
///
/// Maintains a bounded set of seen nonces (default 100,000). When the set
/// reaches capacity, the oldest nonces are evicted (FIFO). This means
/// very old receipts could theoretically be replayed, but in practice
/// the nonce window far exceeds the useful lifetime of a receipt.
public actor ReceiptNonceTracker: Sendable {

    /// Maximum nonces to track before eviction.
    public let maxNonces: Int

    /// Set of seen nonces for O(1) lookup.
    private var seenNonces: Set<Data> = []

    /// Ordered list for FIFO eviction.
    private var nonceOrder: [Data] = []

    public init(maxNonces: Int = 100_000) {
        self.maxNonces = maxNonces
    }

    /// Check if a nonce is fresh and record it.
    ///
    /// - Parameter nonce: The 32-byte receipt nonce.
    /// - Returns: `true` if this nonce has never been seen, `false` if it's a replay.
    public func checkAndRecord(nonce: Data) -> Bool {
        // Check for replay
        guard !seenNonces.contains(nonce) else {
            return false
        }

        // Evict oldest if at capacity
        if seenNonces.count >= maxNonces {
            let oldest = nonceOrder.removeFirst()
            seenNonces.remove(oldest)
        }

        // Record
        seenNonces.insert(nonce)
        nonceOrder.append(nonce)

        return true
    }

    /// Check if a nonce has been seen (without recording).
    public func hasBeenSeen(nonce: Data) -> Bool {
        seenNonces.contains(nonce)
    }

    /// Number of tracked nonces.
    public var count: Int {
        seenNonces.count
    }

    /// Reset all state (for testing).
    public func reset() {
        seenNonces.removeAll()
        nonceOrder.removeAll()
    }
}

// MARK: - Errors

/// Errors during receipt authentication.
public enum ReceiptAuthError: Error, Sendable {
    /// Secure random generation failed.
    case randomGenerationFailed
    /// Invalid signature format.
    case invalidSignatureFormat
    /// Invalid nonce format.
    case invalidNonceFormat
    /// Nonce has been seen before (replay attack).
    case replayDetected
    /// Signature verification failed.
    case signatureInvalid
}

// MARK: - Backward Compatibility

/// Extension to handle legacy receipts without authentication.
extension PaymentReceiptMessage {
    /// Check if this receipt has authentication data.
    /// Legacy receipts (version 1 without auth) return false.
    public var requiresAuthentication: Bool {
        // Version 2+ requires authentication
        return version >= 2
    }
}
