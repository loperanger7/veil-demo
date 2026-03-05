// VEIL — KEMKeyPair.swift
// Ticket: VEIL-102 — ML-KEM-1024 Integration
// Spec reference: Section 3.1, 3.2
//
// Protocol abstraction for Key Encapsulation Mechanisms.
// The protocol-oriented design allows swapping KEM implementations
// in tests without touching protocol logic.

import Foundation

/// Result of a KEM encapsulation operation.
public struct KEMEncapsulationResult: Sendable {
    /// The shared secret agreed upon by both parties (32 bytes for ML-KEM-1024).
    public let sharedSecret: SecureBytes

    /// The ciphertext to send to the decapsulating party.
    public let ciphertext: Data

    public init(sharedSecret: SecureBytes, ciphertext: Data) {
        self.sharedSecret = sharedSecret
        self.ciphertext = ciphertext
    }
}

/// A KEM key pair with encapsulation and decapsulation capabilities.
///
/// This protocol abstracts over the specific KEM algorithm, enabling
/// property-based testing with mock KEMs while using ML-KEM-1024 in production.
public protocol KEMKeyPairProtocol: Sendable {
    /// The public key bytes (for ML-KEM-1024: 1568 bytes).
    var publicKey: Data { get }

    /// Encapsulate: generate a shared secret and ciphertext from a public key.
    ///
    /// - Parameter recipientPublicKey: The recipient's KEM public key.
    /// - Returns: Shared secret + ciphertext.
    static func encapsulate(recipientPublicKey: Data) throws -> KEMEncapsulationResult

    /// Decapsulate: recover the shared secret from a ciphertext.
    ///
    /// - Parameter ciphertext: The ciphertext from the encapsulating party.
    /// - Returns: The shared secret.
    func decapsulate(ciphertext: Data) throws -> SecureBytes
}
