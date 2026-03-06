// VEIL — DHRatchet.swift
// Ticket: VEIL-106 — Diffie-Hellman Ratchet (Classical)
// Spec reference: Section 3.3.2
//
// The DH ratchet performs a new X25519 exchange each time the direction
// of communication changes. The DH output is mixed into the root key,
// producing new sending and receiving chain keys.
//
// (RK_{n+1}, CK_new) = HKDF-SHA-512(
//     salt = RK_n,
//     ikm  = X25519(ek_self, ek_peer),
//     info = "VeilDHRatchet"
// )
//
// This provides post-compromise security against classical adversaries:
// after a ratchet step, an attacker who previously compromised the device
// loses access to future messages.

import Foundation
import CryptoKit

/// The Diffie-Hellman ratchet for classical post-compromise security.
///
/// Each DH ratchet step generates a fresh ephemeral X25519 key pair,
/// computes a shared secret with the peer's latest ephemeral key, and
/// mixes the result into the root key to derive new chain keys.
public struct DHRatchet: Sendable {

    // MARK: - State

    /// Current root key (32 bytes). Updated on each DH ratchet step.
    private(set) var rootKey: SecureBytes

    /// Our current ephemeral X25519 key pair.
    private(set) var ephemeralKeyPair: Curve25519.KeyAgreement.PrivateKey

    /// The peer's most recent ephemeral public key.
    private(set) var peerEphemeralKey: Curve25519.KeyAgreement.PublicKey?

    /// Current sending chain ratchet.
    private(set) var sendingChain: SymmetricRatchet?

    /// Current receiving chain ratchet.
    private(set) var receivingChain: SymmetricRatchet?

    /// Number of DH ratchet steps performed (for SPQR scheduling).
    private(set) var ratchetCount: UInt32 = 0

    // MARK: - Initialization

    /// Initialize a DH ratchet with the session's initial root key.
    ///
    /// Called after PQXDH completes to set up the ratchet for ongoing
    /// message encryption.
    ///
    /// - Parameters:
    ///   - rootKey: The initial root key derived from PQXDH session key.
    ///   - ourEphemeralKey: Our initial ephemeral key pair.
    public init(rootKey: SecureBytes, ourEphemeralKey: Curve25519.KeyAgreement.PrivateKey) {
        self.rootKey = rootKey
        self.ephemeralKeyPair = ourEphemeralKey
    }

    /// Initialize the responder side with the peer's first ephemeral key.
    ///
    /// The responder receives the initiator's ephemeral key in the PQXDH
    /// message and uses it to set up the first receiving chain.
    ///
    /// - Parameters:
    ///   - rootKey: Initial root key from PQXDH.
    ///   - ourEphemeralKey: Our ephemeral key pair.
    ///   - peerEphemeralKey: The initiator's ephemeral public key.
    public init(
        rootKey: SecureBytes,
        ourEphemeralKey: Curve25519.KeyAgreement.PrivateKey,
        peerEphemeralKey: Curve25519.KeyAgreement.PublicKey
    ) throws {
        self.rootKey = rootKey
        self.ephemeralKeyPair = ourEphemeralKey
        self.peerEphemeralKey = peerEphemeralKey

        // Perform initial DH to establish receiving chain
        let dhOutput = try ourEphemeralKey.sharedSecretFromKeyAgreement(with: peerEphemeralKey)
        let dhBytes = SecureBytes(copying: dhOutput.withUnsafeBytes { Data($0) })

        let (newRootKey, receivingCK) = try VeilHKDF.deriveRatchetKeys(
            rootKey: rootKey,
            input: dhBytes,
            domain: .dhRatchet
        )

        self.rootKey = newRootKey
        self.receivingChain = SymmetricRatchet(chainKey: receivingCK)
    }

    // MARK: - Ratchet Step

    /// Perform a DH ratchet step when we are about to send.
    ///
    /// Generates a new ephemeral key, computes DH with the peer's key,
    /// and derives a new sending chain.
    ///
    /// - Returns: Our new ephemeral public key (included in message header).
    public mutating func ratchetForSending() throws -> Data {
        // Generate fresh ephemeral key
        let newEphemeral = Curve25519.KeyAgreement.PrivateKey()

        if let peerKey = peerEphemeralKey {
            // DH with peer's latest ephemeral key
            let dhOutput = try newEphemeral.sharedSecretFromKeyAgreement(with: peerKey)
            let dhBytes = SecureBytes(copying: dhOutput.withUnsafeBytes { Data($0) })

            let (newRootKey, sendingCK) = try VeilHKDF.deriveRatchetKeys(
                rootKey: rootKey,
                input: dhBytes,
                domain: .dhRatchet
            )

            self.rootKey = newRootKey
            self.sendingChain = SymmetricRatchet(chainKey: sendingCK)
        } else {
            // First message: derive sending chain from root key directly
            let dummyInput = SecureBytes(copying: newEphemeral.publicKey.rawRepresentation)
            let (newRootKey, sendingCK) = try VeilHKDF.deriveRatchetKeys(
                rootKey: rootKey,
                input: dummyInput,
                domain: .dhRatchet
            )
            self.rootKey = newRootKey
            self.sendingChain = SymmetricRatchet(chainKey: sendingCK)
        }

        ephemeralKeyPair = newEphemeral
        ratchetCount += 1

        return newEphemeral.publicKey.rawRepresentation
    }

    /// Perform a DH ratchet step when we receive a new ephemeral key from the peer.
    ///
    /// - Parameter peerPublicKey: The peer's new ephemeral public key from the message header.
    public mutating func ratchetForReceiving(peerPublicKey: Data) throws {
        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        self.peerEphemeralKey = peerKey

        // DH with our current ephemeral key and peer's new key
        let dhOutput = try ephemeralKeyPair.sharedSecretFromKeyAgreement(with: peerKey)
        let dhBytes = SecureBytes(copying: dhOutput.withUnsafeBytes { Data($0) })

        let (newRootKey, receivingCK) = try VeilHKDF.deriveRatchetKeys(
            rootKey: rootKey,
            input: dhBytes,
            domain: .dhRatchet
        )

        self.rootKey = newRootKey
        self.receivingChain = SymmetricRatchet(chainKey: receivingCK)
        ratchetCount += 1
    }

    // MARK: - Message Key Derivation

    /// Derive the next sending message key.
    public mutating func nextSendingKey() throws -> SecureBytes {
        if sendingChain == nil {
            _ = try ratchetForSending()
        }
        return try sendingChain!.advance()
    }

    /// Derive the next receiving message key, handling out-of-order delivery.
    ///
    /// - Parameters:
    ///   - messageIndex: The message index from the header.
    ///   - peerEphemeralKey: The peer's ephemeral key from the header.
    public mutating func receivingKey(
        forMessageIndex messageIndex: UInt32,
        peerEphemeralKey peerKey: Data
    ) throws -> SecureBytes {
        // Check if this is from a new DH ratchet epoch
        let incomingKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerKey)
        if peerEphemeralKey == nil || incomingKey.rawRepresentation != peerEphemeralKey!.rawRepresentation {
            try ratchetForReceiving(peerPublicKey: peerKey)
        }

        guard var chain = receivingChain else {
            throw VeilError.invalidSessionState(current: "no receiving chain", expected: "active receiving chain")
        }

        // Check for skipped key
        if let skippedKey = chain.consumeSkippedKey(at: messageIndex) {
            receivingChain = chain
            return skippedKey
        }

        // Skip ahead if needed
        if messageIndex > chain.index {
            try chain.skipTo(index: messageIndex)
        }

        let key = try chain.advance()
        receivingChain = chain
        return key
    }
}
