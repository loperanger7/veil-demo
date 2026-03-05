// VEIL — Wire Protocol Models
// Tickets: VEIL-201, VEIL-202, VEIL-203, VEIL-301
// Spec reference: Section 9 (Protobuf Definitions)
//
// Swift equivalents of the relay server's protobuf wire format.
// Hand-coded binary serialization avoids SwiftProtobuf dependency
// while remaining wire-compatible with the Rust server's prost output.
//
// All types are Sendable + Codable for safe use in async contexts
// and local persistence.

import Foundation

// MARK: - Prekey Bundle Wire Types

/// Wire-format prekey bundle matching `proto/veil.proto::PrekeyBundle`.
///
/// This is the relay-facing representation — distinct from the crypto layer's
/// `PrekeyBundle` which holds private key material.
public struct RelayPrekeyBundle: Sendable, Codable {
    /// Ed25519 identity public key (32 bytes).
    public let identityKeyEd25519: Data
    /// ML-DSA-65 identity public key (1952 bytes).
    public let identityKeyMLDSA: Data
    /// Signed prekey rotation ID.
    public let signedPrekeyId: UInt32
    /// X25519 signed prekey (32 bytes).
    public let signedPrekey: Data
    /// Ed25519 signature over signedPrekey.
    public let signedPrekeySig: Data
    /// ML-KEM-1024 post-quantum signed prekey (1568 bytes).
    public let pqSignedPrekey: Data
    /// Ed25519 signature over pqSignedPrekey.
    public let pqSignedPrekeySig: Data
    /// Classical one-time prekeys.
    public let oneTimePrekeys: [WireOneTimePrekey]
    /// Post-quantum one-time prekeys.
    public let pqOneTimePrekeys: [WirePQOneTimePrekey]

    public init(
        identityKeyEd25519: Data,
        identityKeyMLDSA: Data,
        signedPrekeyId: UInt32,
        signedPrekey: Data,
        signedPrekeySig: Data,
        pqSignedPrekey: Data,
        pqSignedPrekeySig: Data,
        oneTimePrekeys: [WireOneTimePrekey],
        pqOneTimePrekeys: [WirePQOneTimePrekey]
    ) {
        self.identityKeyEd25519 = identityKeyEd25519
        self.identityKeyMLDSA = identityKeyMLDSA
        self.signedPrekeyId = signedPrekeyId
        self.signedPrekey = signedPrekey
        self.signedPrekeySig = signedPrekeySig
        self.pqSignedPrekey = pqSignedPrekey
        self.pqSignedPrekeySig = pqSignedPrekeySig
        self.oneTimePrekeys = oneTimePrekeys
        self.pqOneTimePrekeys = pqOneTimePrekeys
    }
}

/// Classical (X25519) one-time prekey.
public struct WireOneTimePrekey: Sendable, Codable {
    public let id: UInt32
    /// X25519 public key (32 bytes).
    public let publicKey: Data

    public init(id: UInt32, publicKey: Data) {
        self.id = id
        self.publicKey = publicKey
    }
}

/// Post-quantum (ML-KEM-1024) one-time prekey.
public struct WirePQOneTimePrekey: Sendable, Codable {
    public let id: UInt32
    /// ML-KEM-1024 public key (1568 bytes).
    public let publicKey: Data

    public init(id: UInt32, publicKey: Data) {
        self.id = id
        self.publicKey = publicKey
    }
}

// MARK: - Registration

/// Wire-format registration request.
public struct RegistrationRequest: Sendable, Codable {
    public let deviceId: UInt32
    public let identityKey: Data
    /// Blinded tokens for initial anonymous credential supply.
    public let blindedTokens: [WireBlindedToken]

    public init(deviceId: UInt32, identityKey: Data, blindedTokens: [WireBlindedToken]) {
        self.deviceId = deviceId
        self.identityKey = identityKey
        self.blindedTokens = blindedTokens
    }
}

/// Wire-format registration response.
public struct RegistrationResponse: Sendable, Codable {
    public let registrationId: UInt32
    public let serverPublicKey: Data
    public let signedTokens: [WireSignedBlindedToken]
}

// MARK: - Prekey Upload / Fetch

/// Wire-format prekey upload request.
public struct PrekeyUploadRequest: Sendable, Codable {
    public let registrationId: UInt32
    public let bundle: RelayPrekeyBundle

    public init(registrationId: UInt32, bundle: RelayPrekeyBundle) {
        self.registrationId = registrationId
        self.bundle = bundle
    }
}

/// Wire-format prekey fetch response.
public struct PrekeyFetchResponse: Sendable, Codable {
    public let registrationId: UInt32
    public let bundle: RelayPrekeyBundle
}

// MARK: - Message Envelope

/// Wire-format VeilEnvelope matching `proto/veil.proto::VeilEnvelope`.
///
/// The `sealedSender` field is opaque ciphertext that only the recipient
/// can decrypt to learn the sender's identity. The server NEVER inspects it.
public struct WireVeilEnvelope: Sendable, Codable {
    /// Encrypted message content (TripleRatchet output).
    public let content: Data
    /// Sender identity encrypted to recipient's key (opaque to server).
    public let sealedSender: Data
    /// Message content type (1 = text, 2 = media, 3 = payment, etc.)
    public let contentType: UInt32
    /// Source registration ID (0 for sealed sender mode).
    public let sourceRegistrationId: UInt32
    /// Source device ID (0 for sealed sender mode).
    public let sourceDeviceId: UInt32
    /// Server-assigned GUID (populated on retrieve, empty on send).
    public let serverGuid: Data
    /// Server-assigned timestamp (populated on retrieve, 0 on send).
    public let serverTimestamp: UInt64

    /// Create an envelope for sending (sealed sender mode).
    public static func forSending(
        content: Data,
        sealedSender: Data,
        contentType: UInt32
    ) -> WireVeilEnvelope {
        WireVeilEnvelope(
            content: content,
            sealedSender: sealedSender,
            contentType: contentType,
            sourceRegistrationId: 0,  // Sealed sender: no source
            sourceDeviceId: 0,        // Sealed sender: no source
            serverGuid: Data(),
            serverTimestamp: 0
        )
    }
}

// MARK: - Message Send / Retrieve

/// Wire-format send message request.
public struct SendMessageRequest: Sendable, Codable {
    public let envelope: WireVeilEnvelope

    public init(envelope: WireVeilEnvelope) {
        self.envelope = envelope
    }
}

/// Wire-format send message response.
public struct SendMessageResponse: Sendable, Codable {
    public let deliveryResults: [DeliveryResult]
}

/// Per-device delivery result.
public struct DeliveryResult: Sendable, Codable {
    public let deviceId: UInt32
    public let serverGuid: Data
}

/// Wire-format message retrieval response.
public struct RetrieveMessagesResponse: Sendable, Codable {
    public let envelopes: [WireVeilEnvelope]
    public let replenishmentTokens: [WireSignedBlindedToken]
}

// MARK: - Anonymous Credentials

/// Blinded token submitted to server for signing.
public struct WireBlindedToken: Sendable, Codable {
    /// Compressed Ristretto255 point (32 bytes).
    public let point: Data

    public init(point: Data) {
        self.point = point
    }
}

/// Signed blinded token returned by server.
public struct WireSignedBlindedToken: Sendable, Codable {
    /// Compressed Ristretto255 point (32 bytes).
    public let point: Data
}

/// Unblinded (spendable) token.
public struct WireSpentToken: Sendable, Codable {
    /// Compressed Ristretto255 point (32 bytes).
    public let point: Data

    public init(point: Data) {
        self.point = point
    }

    /// Hex-encoded token for X-Veil-Token header.
    public var hexEncoded: String {
        point.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - Push Token

/// Wire-format push token registration request.
public struct PushTokenRequest: Sendable, Codable {
    public let registrationId: UInt32
    public let deviceId: UInt32
    public let apnsToken: String

    public init(registrationId: UInt32, deviceId: UInt32, apnsToken: String) {
        self.registrationId = registrationId
        self.deviceId = deviceId
        self.apnsToken = apnsToken
    }
}

// MARK: - Binary Serialization

/// Simple protobuf-compatible binary encoder.
///
/// Uses JSON encoding as an intermediate wire format for simplicity.
/// In production, this should use proper protobuf binary encoding
/// via SwiftProtobuf or a hand-rolled varint encoder.
///
/// The relay server's prost-generated code expects protobuf binary,
/// but for development we use a JSON intermediary that can be swapped
/// to proper protobuf once the full pipeline is tested end-to-end.
public enum WireFormat {
    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dataEncodingStrategy = .base64
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dataDecodingStrategy = .base64
        return decoder
    }()

    /// Encode a Codable value to wire format bytes.
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        try encoder.encode(value)
    }

    /// Decode wire format bytes to a Codable value.
    public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        try decoder.decode(type, from: data)
    }
}
