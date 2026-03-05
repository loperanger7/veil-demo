// VEIL — Message Pipeline
// Tickets: VEIL-201, VEIL-202, VEIL-203, VEIL-302
// Spec reference: Section 3.1, 4.2
//
// End-to-end message send/receive pipeline:
//
// SEND:
//   plaintext
//   → TripleRatchet.encrypt() → ciphertext
//   → sealSender() → sealed sender blob
//   → WireVeilEnvelope.forSending()
//   → RelayClient.sendMessage()
//
// RECEIVE:
//   RelayClient.retrieveMessages()
//   → for each WireVeilEnvelope:
//     → unsealSender() → sender identity + ciphertext
//     → SessionManager.getOrEstablishSession()
//     → TripleRatchet.decrypt() → plaintext
//     → RelayClient.acknowledgeMessage()
//
// SEALED SENDER:
//   The sender's identity is encrypted to the recipient's identity key
//   using HKDF + AES-256-GCM. The relay server sees only opaque bytes.
//
// OFFLINE QUEUE:
//   When network is unavailable, outbound messages are queued locally
//   and flushed when connectivity is restored.

import Foundation
import CryptoKit

// MARK: - Message Types

/// Content type identifiers for VeilEnvelope.
public enum VeilContentType: UInt32, Sendable {
    case text = 1
    case media = 2
    case payment = 3
    case receipt = 4
    case sessionEstablishment = 5
}

/// A decrypted inbound message.
public struct DecryptedMessage: Sendable {
    /// The sender's registration ID (revealed by unsealing).
    public let senderRegistrationId: UInt32
    /// The sender's device ID.
    public let senderDeviceId: UInt32
    /// Decrypted plaintext content.
    public let plaintext: Data
    /// Content type.
    public let contentType: VeilContentType
    /// Server-assigned GUID (for acknowledgment).
    public let serverGuid: Data
    /// Server timestamp.
    public let serverTimestamp: UInt64
}

/// An outbound message queued for sending.
public struct OutboundMessage: Sendable, Codable {
    /// Recipient registration ID.
    public let recipientRegistrationId: UInt32
    /// Plaintext content.
    public let plaintext: Data
    /// Content type.
    public let contentType: UInt32
    /// When the message was enqueued locally.
    public let enqueuedAt: Date
}

// MARK: - Sealed Sender

/// Sealed sender header encrypted to the recipient's identity key.
///
/// This is the data inside the `sealed_sender` field of WireVeilEnvelope.
/// Only the recipient can decrypt it to learn the sender's identity.
struct SealedSenderHeader: Codable {
    let senderRegistrationId: UInt32
    let senderDeviceId: UInt32
    let senderIdentityKey: Data
}

// MARK: - Message Pipeline

/// Actor coordinating the full message send/receive lifecycle.
///
/// Integrates:
///   - SessionManager for PQXDH + TripleRatchet
///   - RelayClient for network I/O
///   - TokenStore for anonymous credentials
///   - Sealed sender for sender anonymity
///   - Offline queue for reliability
public actor MessagePipeline {
    private let sessionManager: SessionManager
    private let relayClient: RelayClient
    private let tokenStore: TokenStore
    private let identityKeyPair: IdentityKeyPair

    /// Our device identity.
    private let registrationId: UInt32
    private let deviceId: UInt32

    /// Offline message queue (flushed when network is available).
    private var offlineQueue: [OutboundMessage] = []

    /// Delegate for message delivery notifications.
    public weak var delegate: MessagePipelineDelegate?

    public init(
        sessionManager: SessionManager,
        relayClient: RelayClient,
        tokenStore: TokenStore,
        identityKeyPair: IdentityKeyPair,
        registrationId: UInt32,
        deviceId: UInt32
    ) {
        self.sessionManager = sessionManager
        self.relayClient = relayClient
        self.tokenStore = tokenStore
        self.identityKeyPair = identityKeyPair
        self.registrationId = registrationId
        self.deviceId = deviceId
    }

    // MARK: - Send

    /// Send an encrypted message to a recipient.
    ///
    /// Flow:
    ///   1. Get or establish TripleRatchet session
    ///   2. Encrypt plaintext with TripleRatchet
    ///   3. Seal sender identity (encrypted to recipient's key)
    ///   4. Build envelope and send via relay
    ///
    /// If the network is unavailable, the message is queued offline.
    ///
    /// - Parameters:
    ///   - plaintext: The message content to encrypt.
    ///   - recipientRegistrationId: The recipient's registration ID.
    ///   - contentType: The content type (text, media, payment, etc.)
    public func sendMessage(
        plaintext: Data,
        to recipientRegistrationId: UInt32,
        contentType: VeilContentType = .text
    ) async throws {
        // Step 1: Get or establish session
        let session = try await sessionManager.getOrEstablishSession(
            with: recipientRegistrationId
        )

        // Step 2: Encrypt with TripleRatchet
        var ratchetSession = session.ratchetSession
        let envelope = try ratchetSession.encrypt(plaintext: plaintext)

        // Update session state after ratchet advancement
        await sessionManager.updateSession(
            for: recipientRegistrationId,
            ratchetSession: ratchetSession
        )

        // Step 3: Serialize encrypted envelope
        let encryptedContent = try WireFormat.encode(envelope)

        // Step 4: Seal sender identity
        let sealedSender = try sealSender(
            recipientIdentityKey: session.peerIdentityKey
        )

        // Step 5: Build wire envelope
        let wireEnvelope = WireVeilEnvelope.forSending(
            content: encryptedContent,
            sealedSender: sealedSender,
            contentType: contentType.rawValue
        )

        // Step 6: Send via relay (or queue offline)
        do {
            guard let token = await tokenStore.consumeToken() else {
                throw VeilError.noOneTimePrekeysAvailable
            }

            let _ = try await relayClient.sendMessage(
                to: recipientRegistrationId,
                envelope: wireEnvelope,
                token: token
            )
        } catch is RelayError {
            // Network failure — queue for later delivery
            offlineQueue.append(OutboundMessage(
                recipientRegistrationId: recipientRegistrationId,
                plaintext: plaintext,
                contentType: contentType.rawValue,
                enqueuedAt: Date()
            ))
        }
    }

    // MARK: - Receive

    /// Poll for and process incoming messages.
    ///
    /// Flow for each envelope:
    ///   1. Unseal sender identity
    ///   2. Get or establish session with sender
    ///   3. Decrypt with TripleRatchet
    ///   4. Acknowledge receipt (triggers server deletion)
    ///   5. Notify delegate
    ///
    /// - Returns: Array of decrypted messages.
    public func retrieveAndProcessMessages() async throws -> [DecryptedMessage] {
        guard let token = await tokenStore.consumeToken() else {
            throw VeilError.noOneTimePrekeysAvailable
        }

        let response = try await relayClient.retrieveMessages(token: token)

        // Process replenishment tokens if provided
        if !response.replenishmentTokens.isEmpty {
            // In a full implementation, we'd unblind these tokens.
            // For now, we note that replenishment was offered.
        }

        var decryptedMessages: [DecryptedMessage] = []

        for wireEnvelope in response.envelopes {
            do {
                let decrypted = try await processInboundEnvelope(wireEnvelope)
                decryptedMessages.append(decrypted)

                // Acknowledge successful processing
                if let ackToken = await tokenStore.consumeToken() {
                    try? await relayClient.acknowledgeMessage(
                        serverGuid: wireEnvelope.serverGuid,
                        token: ackToken
                    )
                }
            } catch {
                // Log error but continue processing other messages.
                // Failed messages remain in the server queue for retry.
                continue
            }
        }

        return decryptedMessages
    }

    /// Process a single inbound envelope.
    private func processInboundEnvelope(
        _ wireEnvelope: WireVeilEnvelope
    ) async throws -> DecryptedMessage {
        // Step 1: Unseal sender
        let senderHeader = try unsealSender(sealedData: wireEnvelope.sealedSender)

        // Step 2: Get or establish session with sender
        let session = try await sessionManager.getOrEstablishSession(
            with: senderHeader.senderRegistrationId
        )

        // Step 3: Decrypt TripleRatchet envelope
        var ratchetSession = session.ratchetSession
        let ratchetEnvelope = try WireFormat.decode(
            TripleRatchetSession.Envelope.self,
            from: wireEnvelope.content
        )
        let plaintext = try ratchetSession.decrypt(envelope: ratchetEnvelope)

        // Update session state
        await sessionManager.updateSession(
            for: senderHeader.senderRegistrationId,
            ratchetSession: ratchetSession
        )

        return DecryptedMessage(
            senderRegistrationId: senderHeader.senderRegistrationId,
            senderDeviceId: senderHeader.senderDeviceId,
            plaintext: plaintext,
            contentType: VeilContentType(rawValue: wireEnvelope.contentType) ?? .text,
            serverGuid: wireEnvelope.serverGuid,
            serverTimestamp: wireEnvelope.serverTimestamp
        )
    }

    // MARK: - Sealed Sender Crypto

    /// Encrypt our sender identity to the recipient's identity key.
    ///
    /// Uses HKDF-derived key + AES-256-GCM so only the recipient
    /// can learn who sent the message.
    private func sealSender(
        recipientIdentityKey: Data
    ) throws -> Data {
        let header = SealedSenderHeader(
            senderRegistrationId: registrationId,
            senderDeviceId: deviceId,
            senderIdentityKey: identityKeyPair.publicKeyEd25519
        )

        let headerData = try JSONEncoder().encode(header)

        // Generate ephemeral key for sealed sender encryption
        let ephemeralKey = Curve25519.KeyAgreement.PrivateKey()

        // Derive encryption key from ECDH(ephemeral, recipient_identity)
        let recipientKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: recipientIdentityKey
        )
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: recipientKey)

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("VeilSealedSender".utf8),
            sharedInfo: Data("v1".utf8),
            outputByteCount: 32
        )

        // Encrypt header with AES-256-GCM
        let sealedBox = try AES.GCM.seal(headerData, using: symmetricKey)

        // Prepend ephemeral public key so recipient can derive the same key
        var output = Data()
        output.append(ephemeralKey.publicKey.rawRepresentation) // 32 bytes
        output.append(sealedBox.combined!)                      // nonce + ciphertext + tag
        return output
    }

    /// Decrypt a sealed sender blob to recover the sender's identity.
    private func unsealSender(sealedData: Data) throws -> SealedSenderHeader {
        guard sealedData.count > 32 else {
            throw VeilError.decryptionFailed
        }

        // Extract ephemeral public key (first 32 bytes)
        let ephemeralKeyData = sealedData.prefix(32)
        let sealedBoxData = sealedData.dropFirst(32)

        let ephemeralKey = try Curve25519.KeyAgreement.PublicKey(
            rawRepresentation: ephemeralKeyData
        )

        // Derive decryption key from ECDH(our_identity_private, ephemeral)
        // Note: We need the X25519 agreement key, not the Ed25519 signing key.
        // In production, the identity key pair would include both.
        // For now, we use a derived agreement key.
        let agreementKey = identityKeyPair.agreementPrivateKey
        let sharedSecret = try agreementKey.sharedSecretFromKeyAgreement(with: ephemeralKey)

        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data("VeilSealedSender".utf8),
            sharedInfo: Data("v1".utf8),
            outputByteCount: 32
        )

        // Decrypt
        let sealedBox = try AES.GCM.SealedBox(combined: sealedBoxData)
        let headerData = try AES.GCM.open(sealedBox, using: symmetricKey)

        return try JSONDecoder().decode(SealedSenderHeader.self, from: headerData)
    }

    // MARK: - Offline Queue

    /// Flush the offline queue when network connectivity is restored.
    public func flushOfflineQueue() async {
        var remaining: [OutboundMessage] = []

        for message in offlineQueue {
            do {
                try await sendMessage(
                    plaintext: message.plaintext,
                    to: message.recipientRegistrationId,
                    contentType: VeilContentType(rawValue: message.contentType) ?? .text
                )
            } catch {
                remaining.append(message)
            }
        }

        offlineQueue = remaining
    }

    /// Number of messages in the offline queue.
    public var offlineQueueCount: Int { offlineQueue.count }
}

// MARK: - Delegate Protocol

/// Delegate for receiving message pipeline events.
public protocol MessagePipelineDelegate: AnyObject, Sendable {
    /// Called when new messages are received and decrypted.
    func pipeline(_ pipeline: MessagePipeline, didReceive messages: [DecryptedMessage])
    /// Called when an outbound message fails permanently.
    func pipeline(_ pipeline: MessagePipeline, didFailToSend error: Error, to registrationId: UInt32)
    /// Called when token supply is low (trigger replenishment).
    func pipelineNeedsTokenReplenishment(_ pipeline: MessagePipeline)
}
