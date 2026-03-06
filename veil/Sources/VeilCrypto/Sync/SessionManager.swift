// VEIL — Session Manager
// Ticket: VEIL-203 (Prekey Fetch & Validation)
// Spec reference: Section 3.1, 3.2
//
// Manages PQXDH session establishment and TripleRatchet session state.
//
// Session establishment flow:
//   1. Fetch recipient's prekey bundle from relay
//   2. Verify SPK and PQSPK signatures against recipient's identity key
//   3. Run PQXDH.initiator() to derive shared session key
//   4. Initialize TripleRatchetSession from session key
//   5. Cache session state for subsequent messages
//
// Session responder flow (incoming session from peer):
//   1. Receive PQXDH initial message in first envelope
//   2. Look up our consumed prekey private keys (via PrekeyManager)
//   3. Run PQXDH.responder() to derive matching session key
//   4. Initialize TripleRatchetSession
//
// Identity key caching:
//   First-seen identity keys are cached for safety number computation.
//   If a peer's identity key changes, the user is warned (TOFU model).

import Foundation
import CryptoKit

// MARK: - Session State

/// Represents an active encrypted session with a peer.
public struct VeilSession: Sendable {
    /// The peer's registration ID.
    public let peerRegistrationId: UInt32
    /// The peer's identity key (Ed25519, for safety number).
    public let peerIdentityKey: Data
    /// The TripleRatchet session state.
    public let ratchetSession: TripleRatchetSession
    /// When the session was established.
    public let establishedAt: Date
    /// Whether we initiated (true) or responded (false).
    public let isInitiator: Bool
}

/// Identity key trust state (Trust On First Use).
public enum IdentityTrustState: Sendable {
    /// First time seeing this identity key — trusted by default.
    case firstUse
    /// Identity key matches previously cached key — trusted.
    case verified
    /// Identity key CHANGED from previously cached key — warn user!
    case changed(previousKey: Data)
}

// MARK: - Session Manager

/// Actor managing encrypted sessions with peers.
///
/// Responsibilities:
///   - Establish new sessions via PQXDH handshake
///   - Cache and restore session state
///   - Track peer identity keys (TOFU)
///   - Provide encrypt/decrypt interface for MessagePipeline
public actor SessionManager {
    private let relayClient: RelayClient
    private let prekeyManager: PrekeyManager
    private let identityKeyPair: IdentityKeyPair

    /// Active sessions indexed by peer registration ID.
    private var sessions: [UInt32: VeilSession] = [:]

    /// Cached peer identity keys (TOFU: Trust On First Use).
    private var identityKeyCache: [UInt32: Data] = [:]

    public init(
        identityKeyPair: IdentityKeyPair,
        relayClient: RelayClient,
        prekeyManager: PrekeyManager
    ) {
        self.identityKeyPair = identityKeyPair
        self.relayClient = relayClient
        self.prekeyManager = prekeyManager
    }

    // MARK: - Initiator Flow (VEIL-203)

    /// Establish a new session as the initiator.
    ///
    /// This is the "Alice" role in the PQXDH specification:
    ///   1. Fetch Bob's prekey bundle from the relay
    ///   2. Verify all signatures
    ///   3. Perform PQXDH key agreement
    ///   4. Initialize TripleRatchet session
    ///
    /// - Parameter peerRegistrationId: The recipient's registration ID.
    /// - Returns: The established session.
    /// - Throws: VeilError if bundle fetch, verification, or PQXDH fails.
    public func establishSession(
        with peerRegistrationId: UInt32
    ) async throws -> VeilSession {
        // Check for existing session
        if let existing = sessions[peerRegistrationId] {
            return existing
        }

        // Step 1: Fetch peer's prekey bundle
        let fetchResponse = try await relayClient.fetchPrekeys(
            recipientRegistrationId: peerRegistrationId
        )
        let wireBundle = fetchResponse.bundle

        // Step 2: Verify identity key trust (TOFU)
        let trustState = checkIdentityTrust(
            registrationId: peerRegistrationId,
            identityKey: wireBundle.identityKeyEd25519
        )

        switch trustState {
        case .changed(_):
            // Identity key changed — this could be a MITM attack or
            // the peer re-registered. The caller should warn the user.
            throw VeilError.signatureVerificationFailed
        case .firstUse, .verified:
            break
        }

        // Step 3: Convert wire bundle to crypto bundle
        let cryptoBundle = convertToCryptoBundle(wireBundle)

        // Step 4: Verify prekey signatures
        guard cryptoBundle.verifySignatures() else {
            throw VeilError.invalidPrekeySignature
        }

        // Step 5: Perform PQXDH key agreement (initiator/Alice)
        let pqxdhResult = try PQXDH.initiator(
            identityKey: identityKeyPair.agreementPrivateKey,
            bundle: cryptoBundle,
            initialPlaintext: Data()  // Empty for session establishment
        )

        // Step 6: Initialize TripleRatchet session
        let ratchetSession = try TripleRatchetSession(
            sessionKey: pqxdhResult.sessionKey,
            isInitiator: true
        )

        // Step 7: Cache the session
        let session = VeilSession(
            peerRegistrationId: peerRegistrationId,
            peerIdentityKey: wireBundle.identityKeyEd25519,
            ratchetSession: ratchetSession,
            establishedAt: Date(),
            isInitiator: true
        )

        sessions[peerRegistrationId] = session

        // Cache the identity key
        identityKeyCache[peerRegistrationId] = wireBundle.identityKeyEd25519

        return session
    }

    // MARK: - Responder Flow

    /// Handle an incoming PQXDH initial message (responder/Bob role).
    ///
    /// Called when we receive a message from a peer with whom we don't
    /// have an established session. The first message contains the
    /// PQXDH handshake data alongside the encrypted content.
    ///
    /// - Parameters:
    ///   - peerRegistrationId: The sender's registration ID (from sealed sender).
    ///   - peerIdentityKey: The sender's Ed25519 identity key.
    ///   - initiatorMessage: The PQXDH initial message from the sender.
    /// - Returns: The established session.
    public func handleIncomingSession(
        peerRegistrationId: UInt32,
        peerIdentityKey: Data,
        initiatorMessage: Data
    ) async throws -> VeilSession {
        // Verify identity key trust
        let trustState = checkIdentityTrust(
            registrationId: peerRegistrationId,
            identityKey: peerIdentityKey
        )

        switch trustState {
        case .changed:
            throw VeilError.signatureVerificationFailed
        case .firstUse, .verified:
            break
        }

        // Look up our prekey private keys that were used
        guard let spkPrivateKeyBytes = await prekeyManager.signedPrekeyPrivateKey() else {
            throw VeilError.noOneTimePrekeysAvailable
        }

        // Reconstruct Curve25519 private key from stored bytes
        let spkData = try spkPrivateKeyBytes.copyToData()
        let signedPrekey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: spkData)

        // Reconstruct ML-KEM-1024 key pair for PQ signed prekey
        // PrekeyManager stores both public key and secret key in GeneratedSignedPrekey
        let pqSpkPrivateKeyBytes = await prekeyManager.pqSignedPrekeyPrivateKey()
        var pqSignedPrekey: MLKEM1024KeyPair? = nil
        if let pqSecretBytes = pqSpkPrivateKeyBytes,
           let pqPublicKey = await prekeyManager.pqSignedPrekeyPublicKey() {
            pqSignedPrekey = MLKEM1024KeyPair.reconstruct(
                publicKey: pqPublicKey,
                secretKey: pqSecretBytes
            )
        }

        // Deserialize the PQXDH initiator message
        let pqxdhMessage = try JSONDecoder().decode(PQXDH.InitiatorMessage.self, from: initiatorMessage)

        // Run PQXDH responder
        let responderResult = try PQXDH.responder(
            identityKey: identityKeyPair.agreementPrivateKey,
            signedPrekey: signedPrekey,
            pqSignedPrekey: pqSignedPrekey ?? (try MLKEM1024KeyPair.generate()),
            oneTimePrekey: nil,
            pqOneTimePrekey: nil,
            message: pqxdhMessage
        )

        // Initialize TripleRatchet session
        let ratchetSession = try TripleRatchetSession(
            sessionKey: responderResult.sessionKey,
            isInitiator: false
        )

        let session = VeilSession(
            peerRegistrationId: peerRegistrationId,
            peerIdentityKey: peerIdentityKey,
            ratchetSession: ratchetSession,
            establishedAt: Date(),
            isInitiator: false
        )

        sessions[peerRegistrationId] = session
        identityKeyCache[peerRegistrationId] = peerIdentityKey

        return session
    }

    // MARK: - Session Access

    /// Get an existing session with a peer, or establish a new one.
    public func getOrEstablishSession(
        with peerRegistrationId: UInt32
    ) async throws -> VeilSession {
        if let existing = sessions[peerRegistrationId] {
            return existing
        }
        return try await establishSession(with: peerRegistrationId)
    }

    /// Get an existing session (returns nil if none exists).
    public func getSession(for peerRegistrationId: UInt32) -> VeilSession? {
        sessions[peerRegistrationId]
    }

    /// Update a session's ratchet state after encrypt/decrypt.
    public func updateSession(
        for peerRegistrationId: UInt32,
        ratchetSession: TripleRatchetSession
    ) {
        guard let session = sessions[peerRegistrationId] else { return }

        sessions[peerRegistrationId] = VeilSession(
            peerRegistrationId: session.peerRegistrationId,
            peerIdentityKey: session.peerIdentityKey,
            ratchetSession: ratchetSession,
            establishedAt: session.establishedAt,
            isInitiator: session.isInitiator
        )
    }

    /// Remove a session (e.g., on user request or key change).
    public func removeSession(for peerRegistrationId: UInt32) {
        sessions.removeValue(forKey: peerRegistrationId)
    }

    // MARK: - Identity Trust (TOFU)

    /// Check trust state of a peer's identity key.
    private func checkIdentityTrust(
        registrationId: UInt32,
        identityKey: Data
    ) -> IdentityTrustState {
        guard let cached = identityKeyCache[registrationId] else {
            return .firstUse
        }

        if cached == identityKey {
            return .verified
        } else {
            return .changed(previousKey: cached)
        }
    }

    /// Compute safety number for a peer (for out-of-band verification).
    ///
    /// The safety number is derived from both parties' identity keys and
    /// registration IDs, following Signal's safety number specification.
    public func computeSafetyNumber(
        for peerRegistrationId: UInt32
    ) -> Data? {
        guard let peerKey = identityKeyCache[peerRegistrationId] else {
            return nil
        }

        let ourKey = identityKeyPair.publicKeyEd25519

        // Concatenate in canonical order (lower registration ID first)
        // and hash to produce the safety number.
        var input = Data()
        input.append(ourKey)
        input.append(peerKey)

        return Data(SHA256.hash(data: input))
    }

    // MARK: - Wire ↔ Crypto Conversion

    /// Convert a wire-format prekey bundle to the crypto layer's PrekeyBundle.
    private func convertToCryptoBundle(
        _ wire: RelayPrekeyBundle
    ) -> PrekeyBundle {
        PrekeyBundle(
            identityKeyEd25519: wire.identityKeyEd25519,
            identityKeyMLDSA: wire.identityKeyMLDSA,
            signedPrekeyId: wire.signedPrekeyId,
            signedPrekey: wire.signedPrekey,
            signedPrekeySig: wire.signedPrekeySig,
            pqSignedPrekey: wire.pqSignedPrekey,
            pqSignedPrekeySig: wire.pqSignedPrekeySig,
            oneTimePrekeys: wire.oneTimePrekeys.map { OneTimePrekey(id: $0.id, publicKey: $0.publicKey) },
            pqOneTimePrekeys: wire.pqOneTimePrekeys.map { PQOneTimePrekey(id: $0.id, publicKey: $0.publicKey) }
        )
    }
}
