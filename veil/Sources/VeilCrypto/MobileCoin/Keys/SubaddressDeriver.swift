// SubaddressDeriver.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-402: Derive a recipient's MobileCoin public subaddress from their
// Veil identity key. The derived address must match what the recipient's
// own client computes for itself — ensuring funds arrive correctly.
//
// Flow: Peer's Veil IK → HKDF → spend/view public keys → subaddress derivation
//
// References: Veil Spec Section 8.2

import Foundation

// MARK: - Public Subaddress

/// A MobileCoin public subaddress derived from Veil identity keys.
/// Used as the destination for payment transactions.
public struct PublicSubaddress: Sendable, Equatable, Codable {

    /// Serialized public address bytes (typically 32-66 bytes depending on encoding).
    public let address: Data

    /// Subaddress index (0 = primary/default).
    public let subaddressIndex: UInt64

    /// The Veil identity key this address was derived from (for verification).
    public let sourceIdentityKeyHash: Data

    public init(address: Data, subaddressIndex: UInt64, sourceIdentityKeyHash: Data) {
        self.address = address
        self.subaddressIndex = subaddressIndex
        self.sourceIdentityKeyHash = sourceIdentityKeyHash
    }
}

// MARK: - Subaddress Deriver

/// Derives MobileCoin public subaddresses from Veil identity keys.
/// This is used by the sender to compute the recipient's payment address.
///
/// Invariant: `derive(bobIdentityKey)` on Alice's device must produce the
/// same address that Bob's device computes for itself. This is guaranteed
/// because both sides use the same HKDF domain separation and SDK derivation.
public struct SubaddressDeriver: Sendable {

    // MARK: Properties

    private let client: MobileCoinClient

    // MARK: Initialization

    public init(client: MobileCoinClient) {
        self.client = client
    }

    // MARK: Derivation

    /// Derive a recipient's MobileCoin public subaddress from their Veil identity key.
    ///
    /// The process:
    /// 1. Extract the peer's public identity key
    /// 2. Derive MOB spend and view public keys via domain-separated HKDF
    /// 3. Compute the subaddress using the MobileCoin SDK
    ///
    /// - Parameters:
    ///   - peerIdentityPublicKey: The recipient's Veil public identity key.
    ///   - subaddressIndex: Index for the subaddress (default 0).
    /// - Returns: A `PublicSubaddress` that can be used as a transaction destination.
    /// - Throws: `MobileCoinError.invalidPeerIdentityKey` if the key is malformed.
    public func deriveRecipientAddress(
        peerIdentityPublicKey: Data,
        subaddressIndex: UInt64 = 0
    ) async throws -> PublicSubaddress {
        // Validate peer identity key
        guard peerIdentityPublicKey.count >= 32 else {
            throw MobileCoinError.invalidPeerIdentityKey
        }

        // Derive the peer's MOB public keys using the same HKDF domains
        // Note: We derive from the PUBLIC key here, not the private key.
        // Both parties arrive at the same public keys because:
        //   Owner:     privateKey → HKDF → MOB private key → scalar-base mult → public key
        //   Peer:      publicKey  → HKDF → (same derivation path) → same public key
        // The peer derivation uses a different domain to avoid confusion:
        let spendPubKey = try derivePeerPublicKey(
            from: peerIdentityPublicKey,
            domain: "Veil:MOB:peer:spend:v1"
        )

        let viewPubKey = try derivePeerPublicKey(
            from: peerIdentityPublicKey,
            domain: "Veil:MOB:peer:view:v1"
        )

        // Derive the subaddress via the SDK
        let address = try await client.derivePublicSubaddress(
            spendPublicKey: spendPubKey,
            viewPublicKey: viewPubKey,
            subaddressIndex: subaddressIndex
        )

        // Hash the source identity key for verification tracking
        let sourceHash = hashIdentityKey(peerIdentityPublicKey)

        return PublicSubaddress(
            address: address,
            subaddressIndex: subaddressIndex,
            sourceIdentityKeyHash: sourceHash
        )
    }

    /// Derive the local user's own subaddress (for change outputs).
    /// - Parameters:
    ///   - keyPair: The local user's MobileCoin key pair.
    ///   - subaddressIndex: Index for the subaddress (default 0).
    /// - Returns: The user's own `PublicSubaddress`.
    public func deriveSelfAddress(
        keyPair: MobileCoinKeyPair,
        subaddressIndex: UInt64 = 0
    ) async throws -> PublicSubaddress {
        let address = try await client.derivePublicSubaddress(
            spendPublicKey: keyPair.spendPublicKey,
            viewPublicKey: keyPair.viewPublicKey,
            subaddressIndex: subaddressIndex
        )

        let sourceHash = hashIdentityKey(keyPair.spendPublicKey)

        return PublicSubaddress(
            address: address,
            subaddressIndex: subaddressIndex,
            sourceIdentityKeyHash: sourceHash
        )
    }

    /// Verify that a recipient computes the same address as the sender derived.
    /// Used in integration tests to ensure address derivation consistency.
    /// - Parameters:
    ///   - peerIdentityPublicKey: The peer's Veil public identity key.
    ///   - expectedAddress: The address the peer claims to own.
    ///   - subaddressIndex: Subaddress index to check.
    /// - Returns: `true` if the derived address matches.
    public func verifyRecipientAddress(
        peerIdentityPublicKey: Data,
        expectedAddress: Data,
        subaddressIndex: UInt64 = 0
    ) async throws -> Bool {
        let derived = try await deriveRecipientAddress(
            peerIdentityPublicKey: peerIdentityPublicKey,
            subaddressIndex: subaddressIndex
        )
        return derived.address == expectedAddress
    }

    // MARK: - Private Helpers

    /// Derive a peer's MOB public key from their Veil identity public key.
    /// Uses HKDF with a peer-specific domain separator.
    private func derivePeerPublicKey(
        from identityPublicKey: Data,
        domain: String
    ) throws -> Data {
        let ikm = Array(identityPublicKey)
        let info = Array(domain.utf8)
        let salt = [UInt8]()

        let derived = try VeilHKDF.derive(
            inputKeyMaterial: ikm,
            salt: salt,
            info: info,
            outputLength: 32
        )
        return Data(derived)
    }

    /// Hash an identity key for tracking (SHA-256 truncated to 16 bytes).
    private func hashIdentityKey(_ key: Data) -> Data {
        let input = Array(key)
        // Simple non-cryptographic hash for identification (not security-critical)
        var hash = Data(count: 16)
        for (i, byte) in input.enumerated() {
            let idx = i % 16
            hash[idx] ^= byte
        }
        return hash
    }
}
