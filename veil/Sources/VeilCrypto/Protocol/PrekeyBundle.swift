// VEIL — PrekeyBundle.swift
// Ticket: VEIL-104 — PQXDH Key Agreement Protocol (supporting types)
// Spec reference: Section 3.2 (Prekey Bundle table)
//
// Prekey bundles are published to the Veil Relay Service and fetched
// by initiators to establish new sessions. Every bundle contains both
// classical and post-quantum prekeys, plus signatures binding them to
// the identity key.

import Foundation
import CryptoKit

/// A prekey bundle published by a Veil user for session establishment.
///
/// Spec: "Each user publishes a prekey bundle to the Veil Relay Service
/// containing the following components..."
public struct PrekeyBundle: Sendable {

    // MARK: - Identity

    /// Ed25519 identity public key (32 bytes).
    public let identityKeyEd25519: Data

    /// ML-DSA-65 identity public key (1952 bytes).
    public let identityKeyMLDSA: Data

    // MARK: - Signed Prekeys (rotated weekly)

    /// Signed prekey ID (for server-side identification).
    public let signedPrekeyId: UInt32

    /// X25519 signed prekey (32 bytes).
    public let signedPrekey: Data

    /// Ed25519 signature over `signedPrekey` by the identity key.
    public let signedPrekeySig: Data

    /// ML-KEM-1024 post-quantum signed prekey (1568 bytes).
    public let pqSignedPrekey: Data

    /// Ed25519 signature over `pqSignedPrekey` by the identity key.
    public let pqSignedPrekeySig: Data

    // MARK: - One-Time Prekeys (consumed on use)

    /// Classical X25519 one-time prekeys.
    public let oneTimePrekeys: [OneTimePrekey]

    /// Post-quantum ML-KEM-1024 one-time prekeys.
    public let pqOneTimePrekeys: [PQOneTimePrekey]

    // MARK: - Validation

    /// Verify all signatures in this bundle.
    ///
    /// **This MUST be called before using any keys from the bundle.**
    /// If either signature is invalid, the bundle is rejected and no
    /// session is established.
    ///
    /// - Returns: `true` if all signatures are valid.
    public func verifySignatures() -> Bool {
        guard let identityKey = try? Curve25519.Signing.PublicKey(
            rawRepresentation: identityKeyEd25519
        ) else { return false }

        // Verify signed prekey signature
        guard identityKey.isValidSignature(signedPrekeySig, for: signedPrekey) else {
            return false
        }

        // Verify PQ signed prekey signature
        guard identityKey.isValidSignature(pqSignedPrekeySig, for: pqSignedPrekey) else {
            return false
        }

        return true
    }
}

// MARK: - One-Time Prekey Types

/// A classical X25519 one-time prekey.
public struct OneTimePrekey: Sendable, Identifiable {
    public let id: UInt32
    public let publicKey: Data  // 32 bytes

    public init(id: UInt32, publicKey: Data) {
        self.id = id
        self.publicKey = publicKey
    }
}

/// A post-quantum ML-KEM-1024 one-time prekey.
public struct PQOneTimePrekey: Sendable, Identifiable {
    public let id: UInt32
    public let publicKey: Data  // 1568 bytes

    public init(id: UInt32, publicKey: Data) {
        self.id = id
        self.publicKey = publicKey
    }
}

/// A consumed prekey selection for the PQXDH initiator message.
/// Contains the IDs of which prekeys were used, so the recipient
/// knows which private keys to use for decapsulation/DH.
public struct PrekeySelection: Sendable, Codable {
    public let signedPrekeyId: UInt32
    public let oneTimePrekeyId: UInt32?
    public let pqOneTimePrekeyId: UInt32?

    public init(
        signedPrekeyId: UInt32,
        oneTimePrekeyId: UInt32? = nil,
        pqOneTimePrekeyId: UInt32? = nil
    ) {
        self.signedPrekeyId = signedPrekeyId
        self.oneTimePrekeyId = oneTimePrekeyId
        self.pqOneTimePrekeyId = pqOneTimePrekeyId
    }
}
