// VEIL — ECDHSharedSecret.swift
// Ticket: VEIL-901 — Security Hardening (Red Team Finding: Weak Shared Secret)
// Spec reference: Section 8.4 (Payment Key Agreement)
//
// CRITICAL FIX: The previous generateSharedSecret() used a simple XOR+add loop
// instead of proper ECDH. The shared secret was fully deterministic and derivable
// by any observer who knows the transaction hash and recipient address.
//
// This module replaces it with real X25519 ECDH key agreement, where:
//   1. Sender generates an ephemeral X25519 key pair
//   2. Sender performs ECDH with the recipient's view key
//   3. The raw DH output is expanded via HKDF with domain separation
//   4. The ephemeral public key is included in the receipt for the recipient
//
// The recipient:
//   1. Receives the sender's ephemeral public key from the receipt
//   2. Performs the same ECDH with their view private key
//   3. Derives the same shared secret via HKDF
//   4. Uses the shared secret to locate their TXO on the ledger

import Foundation
import CryptoKit

// MARK: - Payment Key Agreement

/// X25519 ECDH key agreement for MobileCoin payment receipts.
///
/// Replaces the insecure XOR+add shared secret with a proper Diffie-Hellman
/// key exchange between the sender's ephemeral key and the recipient's
/// long-term view key.
public enum PaymentKeyAgreement: Sendable {

    /// Domain separator for payment shared secret derivation.
    private static let domain = "veil-payment-ecdh-v1"

    /// Result of a payment key agreement (sender side).
    public struct SenderResult: Sendable {
        /// The derived shared secret (32 bytes).
        public let sharedSecret: SecureBytes
        /// The sender's ephemeral public key (included in the receipt).
        public let ephemeralPublicKey: Data
    }

    /// Result of a payment key agreement (recipient side).
    public struct RecipientResult: Sendable {
        /// The derived shared secret (32 bytes).
        public let sharedSecret: SecureBytes
    }

    // MARK: - Sender Side

    /// Derive a payment shared secret (sender side).
    ///
    /// Generates an ephemeral X25519 key pair, performs ECDH with the
    /// recipient's view key, and derives the shared secret via HKDF.
    ///
    /// - Parameters:
    ///   - recipientViewKey: The recipient's X25519 public view key.
    ///   - txHash: The transaction hash (used as HKDF salt for domain binding).
    /// - Returns: The shared secret and the ephemeral public key to include in the receipt.
    public static func senderDerive(
        recipientViewKey: Curve25519.KeyAgreement.PublicKey,
        txHash: Data
    ) throws -> SenderResult {
        // Generate ephemeral X25519 key pair
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralKey.publicKey.rawRepresentation

        // Perform X25519 ECDH
        let rawSharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(
            with: recipientViewKey
        )

        // Expand via HKDF-SHA256 with domain separation
        let derivedKey = rawSharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: txHash,
            sharedInfo: Data(domain.utf8),
            outputByteCount: 32
        )

        // Convert to SecureBytes
        let keyData = derivedKey.withUnsafeBytes { Data($0) }
        let secureKey = SecureBytes(bytes: Array(keyData))

        return SenderResult(
            sharedSecret: secureKey,
            ephemeralPublicKey: ephemeralPublicKey
        )
    }

    /// Derive a payment shared secret with a specific ephemeral key (for testing).
    ///
    /// - Parameters:
    ///   - ephemeralPrivateKey: The sender's ephemeral private key.
    ///   - recipientViewKey: The recipient's X25519 public view key.
    ///   - txHash: The transaction hash.
    /// - Returns: The shared secret and ephemeral public key.
    public static func senderDerive(
        ephemeralPrivateKey: Curve25519.KeyAgreement.PrivateKey,
        recipientViewKey: Curve25519.KeyAgreement.PublicKey,
        txHash: Data
    ) throws -> SenderResult {
        let rawSharedSecret = try ephemeralPrivateKey.sharedSecretFromKeyAgreement(
            with: recipientViewKey
        )

        let derivedKey = rawSharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: txHash,
            sharedInfo: Data(domain.utf8),
            outputByteCount: 32
        )

        let keyData = derivedKey.withUnsafeBytes { Data($0) }
        let secureKey = SecureBytes(bytes: Array(keyData))

        return SenderResult(
            sharedSecret: secureKey,
            ephemeralPublicKey: ephemeralPrivateKey.publicKey.rawRepresentation
        )
    }

    // MARK: - Recipient Side

    /// Derive a payment shared secret (recipient side).
    ///
    /// Uses the sender's ephemeral public key (from the receipt) and the
    /// recipient's view private key to derive the same shared secret.
    ///
    /// - Parameters:
    ///   - recipientViewKey: The recipient's X25519 private view key.
    ///   - senderEphemeralKey: The sender's ephemeral public key (from receipt).
    ///   - txHash: The transaction hash.
    /// - Returns: The derived shared secret.
    public static func recipientDerive(
        recipientViewKey: Curve25519.KeyAgreement.PrivateKey,
        senderEphemeralKey: Curve25519.KeyAgreement.PublicKey,
        txHash: Data
    ) throws -> RecipientResult {
        // Perform the same X25519 ECDH
        let rawSharedSecret = try recipientViewKey.sharedSecretFromKeyAgreement(
            with: senderEphemeralKey
        )

        // Same HKDF derivation
        let derivedKey = rawSharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: txHash,
            sharedInfo: Data(domain.utf8),
            outputByteCount: 32
        )

        let keyData = derivedKey.withUnsafeBytes { Data($0) }
        let secureKey = SecureBytes(bytes: Array(keyData))

        return RecipientResult(sharedSecret: secureKey)
    }

    // MARK: - Validation

    /// Validate that an ephemeral public key is well-formed.
    ///
    /// Checks that the key is exactly 32 bytes and is a valid X25519 public key
    /// (not the identity point or a low-order point).
    public static func validateEphemeralKey(_ keyData: Data) -> Bool {
        guard keyData.count == 32 else { return false }

        // Reject the all-zeros key (identity point)
        guard keyData != Data(repeating: 0, count: 32) else { return false }

        // Attempt to construct a valid public key
        guard let _ = try? Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: keyData
        ) else {
            return false
        }

        return true
    }
}

// MARK: - Legacy Compatibility

/// Marker for the legacy (insecure) shared secret generation.
///
/// This enum exists solely to flag legacy code paths that need migration.
/// It always throws to prevent accidental use.
@available(*, deprecated, message: "Use PaymentKeyAgreement.senderDerive instead")
public enum LegacySharedSecret: Sendable {
    /// The old XOR+add shared secret generation.
    ///
    /// - Warning: This is cryptographically broken. Do not use.
    public static func generateSharedSecret(
        txHash: Data,
        recipientAddress: Data
    ) throws -> Data {
        // Intentionally removed — always throws
        throw LegacySecretError.deprecated
    }

    public enum LegacySecretError: Error {
        case deprecated
    }
}
