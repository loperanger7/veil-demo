// VEIL — Ciphertext Padding Layer
// Ticket: VEIL-602 — Traffic Padding
// Epic: 6 — Network & Transport Layer
//
// Integration layer that sits between the Triple Ratchet encryption
// and the network transport. Applies traffic padding to encrypted
// ciphertext before transmission and strips it after reception.
//
// Pipeline:
//   Encrypt: plaintext → TripleRatchet.encrypt → pad → transmit
//   Decrypt: receive → strip → TripleRatchet.decrypt → plaintext
//
// The padding is applied to the ciphertext, not the plaintext, so an
// observer only sees block-aligned sizes regardless of content type.

import Foundation

// MARK: - Padded Envelope

/// A padded ciphertext envelope ready for network transmission.
///
/// Contains the padded ciphertext and metadata for protocol versioning.
/// The envelope itself is transmitted as-is over the wire.
public struct PaddedEnvelope: Sendable, Equatable {
    /// Protocol version for the padding scheme.
    public static let currentVersion: UInt8 = 1

    /// Padding protocol version.
    public let version: UInt8
    /// Block-aligned padded ciphertext (includes length prefix + padding).
    public let paddedCiphertext: Data

    public init(version: UInt8 = PaddedEnvelope.currentVersion, paddedCiphertext: Data) {
        self.version = version
        self.paddedCiphertext = paddedCiphertext
    }

    /// Serialize the envelope for wire transmission.
    ///
    /// Format: [version (1 byte)] [paddedCiphertext]
    public func serialize() -> Data {
        var data = Data(capacity: 1 + paddedCiphertext.count)
        data.append(version)
        data.append(paddedCiphertext)
        return data
    }

    /// Deserialize an envelope from wire bytes.
    ///
    /// - Parameter data: The serialized envelope bytes.
    /// - Returns: The deserialized envelope.
    /// - Throws: `NetworkTransportError` on malformed data.
    public static func deserialize(from data: Data) throws -> PaddedEnvelope {
        guard data.count >= 1 else {
            throw NetworkTransportError.paddingValidationFailed(reason: "Envelope too short")
        }
        let version = data[data.startIndex]
        let ciphertext = data.dropFirst()
        return PaddedEnvelope(version: version, paddedCiphertext: Data(ciphertext))
    }
}

// MARK: - Ciphertext Padding Encoder

/// Encodes ciphertext with traffic padding for outgoing messages.
///
/// Thread-safe: all methods are stateless and can be called concurrently.
public struct CiphertextPaddingEncoder: Sendable {
    /// The padding scheme to apply.
    public let scheme: PaddingScheme

    public init(scheme: PaddingScheme = .production) {
        self.scheme = scheme
    }

    /// Pad ciphertext for transmission.
    ///
    /// - Parameter ciphertext: The encrypted ciphertext from the ratchet.
    /// - Returns: A padded envelope ready for wire transmission.
    /// - Throws: `NetworkTransportError` on padding failure.
    public func encode(_ ciphertext: Data) throws -> PaddedEnvelope {
        let paddedCiphertext = try TrafficPadder.pad(ciphertext, scheme: scheme)
        return PaddedEnvelope(paddedCiphertext: paddedCiphertext)
    }

    /// Convenience: pad and serialize in one step.
    ///
    /// - Parameter ciphertext: The encrypted ciphertext.
    /// - Returns: Wire-ready bytes.
    public func encodeToWire(_ ciphertext: Data) throws -> Data {
        try encode(ciphertext).serialize()
    }
}

// MARK: - Ciphertext Padding Decoder

/// Decodes padded envelopes and recovers the original ciphertext.
///
/// Thread-safe: all methods are stateless and can be called concurrently.
public struct CiphertextPaddingDecoder: Sendable {
    /// The padding scheme used (must match the encoder's scheme).
    public let scheme: PaddingScheme

    public init(scheme: PaddingScheme = .production) {
        self.scheme = scheme
    }

    /// Strip padding from a received envelope and recover the ciphertext.
    ///
    /// - Parameter envelope: The received padded envelope.
    /// - Returns: The original ciphertext bytes (ready for decryption).
    /// - Throws: `NetworkTransportError` on validation failure.
    public func decode(_ envelope: PaddedEnvelope) throws -> Data {
        // Version check — future-proof for scheme upgrades
        guard envelope.version == PaddedEnvelope.currentVersion else {
            throw NetworkTransportError.paddingValidationFailed(
                reason: "Unsupported padding version: \(envelope.version)"
            )
        }
        return try TrafficPadder.strip(envelope.paddedCiphertext, scheme: scheme)
    }

    /// Convenience: deserialize and decode in one step.
    ///
    /// - Parameter wireData: Raw bytes received from the network.
    /// - Returns: The original ciphertext bytes.
    public func decodeFromWire(_ wireData: Data) throws -> Data {
        let envelope = try PaddedEnvelope.deserialize(from: wireData)
        return try decode(envelope)
    }
}

// MARK: - Padding Statistics

/// Utility for computing padding overhead statistics.
public enum PaddingStats {
    /// Compute the padding overhead ratio for a message of the given length.
    ///
    /// - Parameters:
    ///   - messageLength: Original message length in bytes.
    ///   - blockSize: Block size for alignment.
    /// - Returns: Overhead ratio (0.0 = no overhead, 1.0 = 100% overhead).
    public static func overheadRatio(messageLength: Int, blockSize: Int) -> Double {
        let padded = TrafficPadder.paddedLength(for: messageLength, blockSize: blockSize)
        let overhead = padded - PaddingScheme.lengthPrefixSize - messageLength
        return Double(overhead) / Double(padded)
    }

    /// Compute the block utilization for a message of the given length.
    ///
    /// - Parameters:
    ///   - messageLength: Original message length.
    ///   - blockSize: Block size for alignment.
    /// - Returns: Utilization ratio (1.0 = perfectly fills block, low = wasted).
    public static func blockUtilization(messageLength: Int, blockSize: Int) -> Double {
        let padded = TrafficPadder.paddedLength(for: messageLength, blockSize: blockSize)
        let useful = PaddingScheme.lengthPrefixSize + messageLength
        return Double(useful) / Double(padded)
    }
}
