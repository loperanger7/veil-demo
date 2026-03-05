// VEIL — TripleRatchet.swift
// Ticket: VEIL-108 — Triple Ratchet Composition
// Spec reference: Section 3.3, Section 8.2
//
// The Triple Ratchet composes:
//   1. Symmetric chain ratchet   (per-message forward secrecy)
//   2. DH ratchet                (classical post-compromise security)
//   3. SPQR                      (quantum post-compromise security)
//
// This file provides the top-level `encrypt` and `decrypt` API for the
// Veil messaging protocol. It is the only interface that the rest of the
// application needs to interact with.
//
// State machine (spec Section 8.2):
//   {Idle, Sending, Receiving, DHRatcheting, SPQRAccumulating, SPQRComplete, Error}

import Foundation
import CryptoKit

/// The composed Triple Ratchet session providing encrypt/decrypt for messages.
///
/// Usage:
/// ```swift
/// // After PQXDH establishes a session key:
/// var session = try TripleRatchetSession(
///     sessionKey: pqxdhResult.sessionKey,
///     isInitiator: true
/// )
///
/// // Send a message:
/// let encrypted = try session.encrypt(plaintext: messageData)
///
/// // Receive a message:
/// let decrypted = try session.decrypt(envelope: receivedEnvelope)
/// ```
public struct TripleRatchetSession: Sendable {

    // MARK: - Types

    /// An encrypted message envelope containing all data needed for decryption.
    public struct Envelope: Sendable {
        /// Our ephemeral public key at time of encryption (for DH ratchet).
        public let ephemeralKey: Data

        /// Message index in the current sending chain.
        public let messageIndex: UInt32

        /// Number of messages in the previous sending chain (for skip handling).
        public let previousChainLength: UInt32

        /// SPQR fragment, if one is due in this message.
        public let spqrFragment: SPQRFragment?

        /// AES-256-GCM ciphertext (nonce || ciphertext || tag).
        public let ciphertext: Data

        /// Serialize for wire transmission.
        public var serialized: Data {
            var data = Data()

            // Ephemeral key (32 bytes, fixed)
            data.append(ephemeralKey)

            // Message index (4 bytes, big-endian)
            var mi = messageIndex.bigEndian
            data.append(Data(bytes: &mi, count: 4))

            // Previous chain length (4 bytes, big-endian)
            var pcl = previousChainLength.bigEndian
            data.append(Data(bytes: &pcl, count: 4))

            // SPQR fragment presence flag + data
            if let fragment = spqrFragment {
                data.append(0x01 as UInt8)
                let fragData = fragment.serialized
                var fragLen = UInt16(fragData.count).bigEndian
                data.append(Data(bytes: &fragLen, count: 2))
                data.append(fragData)
            } else {
                data.append(0x00 as UInt8)
            }

            // Ciphertext (remainder)
            data.append(ciphertext)

            return data
        }
    }

    /// Session state for the state machine.
    public enum State: String, Sendable {
        case idle
        case sending
        case receiving
        case error
    }

    // MARK: - State

    /// Current state machine state.
    private(set) var state: State = .idle

    /// The DH ratchet (manages root key, ephemeral keys, and chain derivation).
    private(set) var dhRatchet: DHRatchet

    /// The SPQR ratchet (parallel post-quantum ratchet).
    private(set) var spqrRatchet: SPQRRatchet

    /// Whether we are the session initiator (Alice) or responder (Bob).
    public let isInitiator: Bool

    /// Number of messages sent in the current sending chain.
    private(set) var currentSendingIndex: UInt32 = 0

    /// Length of the previous sending chain (for the header).
    private(set) var previousChainLength: UInt32 = 0

    // MARK: - Initialization

    /// Create a new Triple Ratchet session from a PQXDH session key.
    ///
    /// - Parameters:
    ///   - sessionKey: The 64-byte session key from PQXDH.
    ///   - isInitiator: Whether this side initiated the PQXDH handshake.
    ///   - peerEphemeralKey: The peer's ephemeral key from PQXDH (responder only).
    public init(
        sessionKey: SecureBytes,
        isInitiator: Bool,
        peerEphemeralKey: Data? = nil
    ) throws {
        self.isInitiator = isInitiator

        // Derive initial root key from session key
        let rootKey = try VeilHKDF.deriveKey(
            ikm: sessionKey,
            domain: .dhRatchet,
            outputByteCount: VeilConstants.rootKeySize
        )

        let ourEphemeral = Curve25519.KeyAgreement.PrivateKey()

        if isInitiator {
            // Initiator starts in sending mode
            self.dhRatchet = DHRatchet(
                rootKey: rootKey,
                ourEphemeralKey: ourEphemeral
            )
        } else if let peerKey = peerEphemeralKey {
            // Responder starts with peer's ephemeral key
            let peerPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerKey)
            self.dhRatchet = try DHRatchet(
                rootKey: rootKey,
                ourEphemeralKey: ourEphemeral,
                peerEphemeralKey: peerPubKey
            )
        } else {
            self.dhRatchet = DHRatchet(
                rootKey: rootKey,
                ourEphemeralKey: ourEphemeral
            )
        }

        self.spqrRatchet = SPQRRatchet()
    }

    // MARK: - Encrypt

    /// Encrypt a plaintext message.
    ///
    /// This performs the following steps:
    /// 1. If needed, performs a DH ratchet step (new ephemeral key).
    /// 2. Derives a message key from the sending chain.
    /// 3. Checks if an SPQR fragment should be attached.
    /// 4. Encrypts the plaintext with AES-256-GCM.
    /// 5. Pads the ciphertext to 256-byte boundaries.
    /// 6. Returns an `Envelope` containing all header and ciphertext data.
    ///
    /// - Parameter plaintext: The message plaintext.
    /// - Returns: An encrypted envelope ready for transmission.
    public mutating func encrypt(plaintext: Data) throws -> Envelope {
        state = .sending

        // Step 1: Ensure we have a sending chain (DH ratchet step if needed)
        if dhRatchet.sendingChain == nil {
            _ = try dhRatchet.ratchetForSending()
            previousChainLength = currentSendingIndex
            currentSendingIndex = 0
        }

        // Step 2: Derive message key from sending chain
        let messageKey = try dhRatchet.nextSendingKey()

        // Step 3: Check SPQR scheduling
        spqrRatchet.recordMessage()
        var spqrFragment: SPQRFragment? = nil
        if spqrRatchet.shouldInitiateStep {
            try spqrRatchet.initiateKeyDistribution()
        }
        spqrFragment = spqrRatchet.nextOutgoingFragment()

        // If SPQR completed, mix into root key
        if let pqSecret = spqrRatchet.consumeCompletedSecret() {
            try mixSPQRSecret(pqSecret)
        }

        // Step 4: Encrypt with AES-256-GCM
        let paddedPlaintext = pad(plaintext)
        let ciphertext = try aesGCMEncrypt(
            plaintext: paddedPlaintext,
            key: messageKey,
            associatedData: dhRatchet.ephemeralKeyPair.publicKey.rawRepresentation
        )

        let envelope = Envelope(
            ephemeralKey: dhRatchet.ephemeralKeyPair.publicKey.rawRepresentation,
            messageIndex: currentSendingIndex,
            previousChainLength: previousChainLength,
            spqrFragment: spqrFragment,
            ciphertext: ciphertext
        )

        currentSendingIndex += 1
        state = .idle

        return envelope
    }

    // MARK: - Decrypt

    /// Decrypt a received message envelope.
    ///
    /// This performs the following steps:
    /// 1. If the envelope contains a new ephemeral key, performs a DH ratchet step.
    /// 2. Derives the message key (handling out-of-order delivery).
    /// 3. Processes any SPQR fragment.
    /// 4. Decrypts and unpads the plaintext.
    ///
    /// - Parameter envelope: The received encrypted envelope.
    /// - Returns: The decrypted plaintext.
    public mutating func decrypt(envelope: Envelope) throws -> Data {
        state = .receiving

        // Step 1: DH ratchet step if peer has a new ephemeral key
        let messageKey = try dhRatchet.receivingKey(
            forMessageIndex: envelope.messageIndex,
            peerEphemeralKey: envelope.ephemeralKey
        )

        // Step 2: Process SPQR fragment if present
        if let fragment = envelope.spqrFragment {
            spqrRatchet.recordMessage()
            if let pqSecret = try spqrRatchet.processIncomingFragment(fragment) {
                try mixSPQRSecret(pqSecret)
            }
        } else {
            spqrRatchet.recordMessage()
        }

        // If SPQR completed, mix into root key
        if let pqSecret = spqrRatchet.consumeCompletedSecret() {
            try mixSPQRSecret(pqSecret)
        }

        // Step 3: Decrypt with AES-256-GCM
        let paddedPlaintext = try aesGCMDecrypt(
            ciphertext: envelope.ciphertext,
            key: messageKey,
            associatedData: envelope.ephemeralKey
        )

        let plaintext = unpad(paddedPlaintext)

        state = .idle
        return plaintext
    }

    // MARK: - SPQR Integration

    /// Mix a completed SPQR shared secret into the root key.
    ///
    /// Spec: `RK_new = HKDF(RK, ss_pq, "Veil:SPQR:v1")`
    private mutating func mixSPQRSecret(_ pqSecret: SecureBytes) throws {
        let (newRootKey, _) = try VeilHKDF.deriveRatchetKeys(
            rootKey: dhRatchet.rootKey,
            input: pqSecret,
            domain: .spqr
        )
        // Update the DH ratchet's root key with the PQ-mixed version
        dhRatchet = DHRatchet(
            rootKey: newRootKey,
            ourEphemeralKey: dhRatchet.ephemeralKeyPair
        )
    }

    // MARK: - AES-256-GCM

    /// Encrypt plaintext with AES-256-GCM.
    private func aesGCMEncrypt(
        plaintext: Data,
        key: SecureBytes,
        associatedData: Data
    ) throws -> Data {
        let keyData = try key.copyToData()
        let symmetricKey = SymmetricKey(data: keyData)

        let sealedBox = try AES.GCM.seal(
            plaintext,
            using: symmetricKey,
            authenticating: associatedData
        )

        guard let combined = sealedBox.combined else {
            throw VeilError.decryptionFailed(reason: "AES-GCM produced no output")
        }
        return combined
    }

    /// Decrypt ciphertext with AES-256-GCM.
    private func aesGCMDecrypt(
        ciphertext: Data,
        key: SecureBytes,
        associatedData: Data
    ) throws -> Data {
        let keyData = try key.copyToData()
        let symmetricKey = SymmetricKey(data: keyData)

        let sealedBox = try AES.GCM.SealedBox(combined: ciphertext)
        let plaintext = try AES.GCM.open(
            sealedBox,
            using: symmetricKey,
            authenticating: associatedData
        )

        return plaintext
    }

    // MARK: - Padding

    /// Pad plaintext to the nearest 256-byte boundary.
    ///
    /// Spec Section 5.3: "Constant-rate padding applied to message sizes
    /// to prevent traffic analysis from inferring message type."
    ///
    /// Format: [plaintext][random padding][2-byte length of plaintext (big-endian)]
    private func pad(_ plaintext: Data) -> Data {
        let blockSize = VeilConstants.messagePaddingBlockSize
        // Reserve 2 bytes for the length footer
        let contentSize = plaintext.count + 2
        let paddedSize = ((contentSize + blockSize - 1) / blockSize) * blockSize
        let paddingSize = paddedSize - contentSize

        var padded = Data(capacity: paddedSize)
        padded.append(plaintext)

        // Random padding bytes
        var randomPadding = [UInt8](repeating: 0, count: paddingSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, paddingSize, &randomPadding)
        padded.append(contentsOf: randomPadding)

        // 2-byte plaintext length footer (big-endian)
        var length = UInt16(plaintext.count).bigEndian
        padded.append(Data(bytes: &length, count: 2))

        return padded
    }

    /// Remove padding from decrypted data.
    private func unpad(_ padded: Data) -> Data {
        guard padded.count >= 2 else { return padded }
        let lengthBytes = padded.suffix(2)
        let length = Int(UInt16(bigEndian: lengthBytes.withUnsafeBytes { $0.load(as: UInt16.self) }))
        guard length <= padded.count - 2 else { return padded }
        return Data(padded.prefix(length))
    }
}
