// VEIL — PQXDH.swift
// Ticket: VEIL-104 — PQXDH Key Agreement Protocol
// Spec reference: Section 3.2
//
// Post-Quantum Extended Diffie-Hellman: the initial key agreement protocol.
//
// PQXDH establishes a shared session key SK between two parties (Alice and Bob)
// who may be mutually offline. It combines four X25519 DH exchanges with one
// or two ML-KEM-1024 KEM encapsulations, producing a hybrid shared secret.
//
// Security guarantee: an adversary must break BOTH the elliptic curve discrete
// logarithm problem AND the Module Learning with Errors problem to recover SK.

import Foundation
import CryptoKit

/// The PQXDH key agreement protocol.
///
/// Implements both the initiator (Alice) and responder (Bob) sides of the
/// handshake as specified in Section 3.2 of the Veil Protocol Specification.
public enum PQXDH: Sendable {

    // MARK: - Types

    /// The initial message sent from Alice to Bob to establish a session.
    public struct InitiatorMessage: Sendable {
        /// Alice's Ed25519 identity public key.
        public let identityKey: Data

        /// Alice's ephemeral X25519 public key (used for DH2, DH3, DH4).
        public let ephemeralKey: Data

        /// KEM ciphertext for Bob's PQ signed prekey.
        public let pqCiphertext: Data

        /// KEM ciphertext for Bob's PQ one-time prekey (nil if unavailable).
        public let pqOneTimeCiphertext: Data?

        /// Which of Bob's prekeys Alice used.
        public let prekeySelection: PrekeySelection

        /// The first encrypted message (encrypted under the derived SK).
        public let initialCiphertext: Data
    }

    /// Result of the initiator-side key agreement.
    public struct InitiatorResult: Sendable {
        /// The derived session key (64 bytes).
        public let sessionKey: SecureBytes

        /// The message to send to the responder.
        public let message: InitiatorMessage
    }

    /// Result of the responder-side key agreement.
    public struct ResponderResult: Sendable {
        /// The derived session key (64 bytes) — must equal initiator's SK.
        public let sessionKey: SecureBytes

        /// Alice's identity key (for safety number computation).
        public let peerIdentityKey: Data
    }

    // MARK: - Initiator (Alice)

    /// Perform the initiator side of PQXDH.
    ///
    /// Alice fetches Bob's prekey bundle, verifies signatures, performs
    /// four DH exchanges and one or two KEM encapsulations, and derives
    /// the shared session key SK.
    ///
    /// Spec Section 3.2:
    /// ```
    /// SK = HKDF-SHA-512(
    ///     salt = 0,
    ///     ikm  = DH1 || DH2 || DH3 || DH4 || ss || ss2,
    ///     info = "VeilPQXDH"
    /// )
    /// ```
    ///
    /// - Parameters:
    ///   - identityKey: Alice's Ed25519 identity private key.
    ///   - bundle: Bob's prekey bundle (fetched from relay).
    ///   - initialPlaintext: The first message to encrypt under SK.
    /// - Throws: `VeilError.invalidPrekeySignature` if bundle verification fails.
    /// - Returns: The session key and the initiator message for Bob.
    public static func initiator(
        identityKey: Curve25519.KeyAgreement.PrivateKey,
        bundle: PrekeyBundle,
        initialPlaintext: Data
    ) throws -> InitiatorResult {

        // Step 0: Verify all signatures in Bob's prekey bundle
        guard bundle.verifySignatures() else {
            throw VeilError.invalidPrekeySignature
        }

        // Step 1: Generate Alice's ephemeral key pair
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()

        // Step 2: Parse Bob's keys
        let bobIdentityKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: bundle.identityKeyEd25519
        )
        let bobSignedPrekey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: bundle.signedPrekey
        )

        // Step 3: Compute DH exchanges
        // DH1 = X25519(IK_A, SPK_B) — Alice identity, Bob signed prekey
        let dh1 = try identityKey.sharedSecretFromKeyAgreement(with: bobSignedPrekey)

        // DH2 = X25519(EK_A, IK_B) — Alice ephemeral, Bob identity
        let dh2 = try ephemeralKey.sharedSecretFromKeyAgreement(with: bobIdentityKey)

        // DH3 = X25519(EK_A, SPK_B) — Alice ephemeral, Bob signed prekey
        let dh3 = try ephemeralKey.sharedSecretFromKeyAgreement(with: bobSignedPrekey)

        // DH4 = X25519(EK_A, OPK_B) — Alice ephemeral, Bob one-time prekey (optional)
        var dh4Data = Data()
        var selectedOPKId: UInt32?
        if let opk = bundle.oneTimePrekeys.first {
            let bobOPK = try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: opk.publicKey
            )
            let dh4 = try ephemeralKey.sharedSecretFromKeyAgreement(with: bobOPK)
            dh4Data = dh4.withUnsafeBytes { Data($0) }
            selectedOPKId = opk.id
        }

        // Step 4: ML-KEM encapsulations
        // KEM encapsulation with Bob's PQ signed prekey
        let kemResult = try MLKEM1024KeyPair.encapsulate(
            recipientPublicKey: bundle.pqSignedPrekey
        )

        // KEM encapsulation with Bob's PQ one-time prekey (optional)
        var kemOneTimeResult: KEMEncapsulationResult?
        var selectedPQOPKId: UInt32?
        if let pqopk = bundle.pqOneTimePrekeys.first {
            kemOneTimeResult = try MLKEM1024KeyPair.encapsulate(
                recipientPublicKey: pqopk.publicKey
            )
            selectedPQOPKId = pqopk.id
        }

        // Step 5: Concatenate all shared secrets
        // ikm = DH1 || DH2 || DH3 || DH4 || ss || ss2
        var ikmBytes = Data()
        ikmBytes.append(dh1.withUnsafeBytes { Data($0) })
        ikmBytes.append(dh2.withUnsafeBytes { Data($0) })
        ikmBytes.append(dh3.withUnsafeBytes { Data($0) })
        ikmBytes.append(dh4Data)
        ikmBytes.append(try kemResult.sharedSecret.copyToData())
        if let kemOT = kemOneTimeResult {
            ikmBytes.append(try kemOT.sharedSecret.copyToData())
        }

        let ikm = SecureBytes(copying: ikmBytes)

        // Step 6: Derive session key
        let sessionKey = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm)

        // Step 7: Encrypt initial message under SK
        let messageKey = SecureBytes(copying: try sessionKey.copyToData().prefix(32))
        let initialCiphertext = try encryptInitialMessage(
            plaintext: initialPlaintext,
            key: messageKey
        )

        // Step 8: Zeroize intermediate values
        // (ikmBytes, dh outputs go out of scope and are freed by ARC;
        //  SecureBytes handles its own zeroization)

        let message = InitiatorMessage(
            identityKey: identityKey.publicKey.rawRepresentation,
            ephemeralKey: ephemeralKey.publicKey.rawRepresentation,
            pqCiphertext: kemResult.ciphertext,
            pqOneTimeCiphertext: kemOneTimeResult?.ciphertext,
            prekeySelection: PrekeySelection(
                signedPrekeyId: bundle.signedPrekeyId,
                oneTimePrekeyId: selectedOPKId,
                pqOneTimePrekeyId: selectedPQOPKId
            )
        )

        return InitiatorResult(sessionKey: sessionKey, message: message)
    }

    // MARK: - Responder (Bob)

    /// Perform the responder side of PQXDH.
    ///
    /// Bob receives Alice's initiator message, performs the corresponding
    /// DH computations and KEM decapsulations, and derives the same SK.
    ///
    /// - Parameters:
    ///   - identityKey: Bob's Ed25519 identity private key.
    ///   - signedPrekey: Bob's signed prekey private key.
    ///   - pqSignedPrekey: Bob's PQ signed prekey (ML-KEM-1024 key pair).
    ///   - oneTimePrekey: Bob's one-time prekey private key (if used).
    ///   - pqOneTimePrekey: Bob's PQ one-time prekey (if used).
    ///   - message: Alice's initiator message.
    /// - Throws: On DH/KEM failure.
    /// - Returns: The session key and Alice's identity.
    public static func responder(
        identityKey: Curve25519.KeyAgreement.PrivateKey,
        signedPrekey: Curve25519.KeyAgreement.PrivateKey,
        pqSignedPrekey: MLKEM1024KeyPair,
        oneTimePrekey: Curve25519.KeyAgreement.PrivateKey?,
        pqOneTimePrekey: MLKEM1024KeyPair?,
        message: InitiatorMessage
    ) throws -> ResponderResult {

        let aliceIdentity = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: message.identityKey
        )
        let aliceEphemeral = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: message.ephemeralKey
        )

        // DH1 = X25519(SPK_B, IK_A)
        let dh1 = try signedPrekey.sharedSecretFromKeyAgreement(with: aliceIdentity)

        // DH2 = X25519(IK_B, EK_A)
        let dh2 = try identityKey.sharedSecretFromKeyAgreement(with: aliceEphemeral)

        // DH3 = X25519(SPK_B, EK_A)
        let dh3 = try signedPrekey.sharedSecretFromKeyAgreement(with: aliceEphemeral)

        // DH4 = X25519(OPK_B, EK_A) if one-time prekey was used
        var dh4Data = Data()
        if let otk = oneTimePrekey {
            let dh4 = try otk.sharedSecretFromKeyAgreement(with: aliceEphemeral)
            dh4Data = dh4.withUnsafeBytes { Data($0) }
        }

        // KEM decapsulation with PQ signed prekey
        let kemSS = try pqSignedPrekey.decapsulate(ciphertext: message.pqCiphertext)

        // KEM decapsulation with PQ one-time prekey (if used)
        var kemOneTimeSS: SecureBytes?
        if let pqOTK = pqOneTimePrekey, let ct = message.pqOneTimeCiphertext {
            kemOneTimeSS = try pqOTK.decapsulate(ciphertext: ct)
        }

        // Concatenate all shared secrets (same order as initiator)
        var ikmBytes = Data()
        ikmBytes.append(dh1.withUnsafeBytes { Data($0) })
        ikmBytes.append(dh2.withUnsafeBytes { Data($0) })
        ikmBytes.append(dh3.withUnsafeBytes { Data($0) })
        ikmBytes.append(dh4Data)
        ikmBytes.append(try kemSS.copyToData())
        if let kemOTSS = kemOneTimeSS {
            ikmBytes.append(try kemOTSS.copyToData())
        }

        let ikm = SecureBytes(copying: ikmBytes)
        let sessionKey = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm)

        return ResponderResult(
            sessionKey: sessionKey,
            peerIdentityKey: message.identityKey
        )
    }

    // MARK: - Helpers

    /// Encrypt the initial message using AES-256-GCM.
    private static func encryptInitialMessage(
        plaintext: Data,
        key: SecureBytes
    ) throws -> Data {
        let keyData = try key.copyToData()
        let symmetricKey = SymmetricKey(data: keyData)
        let sealedBox = try AES.GCM.seal(plaintext, using: symmetricKey)
        guard let combined = sealedBox.combined else {
            throw VeilError.decryptionFailed(reason: "AES-GCM seal produced no output")
        }
        return combined
    }
}
