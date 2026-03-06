// VEIL — Traffic Padding
// Ticket: VEIL-602 — Traffic Padding
// Epic: 6 — Network & Transport Layer
// Spec reference: Section 2.1
//
// Pads all outgoing ciphertext to 256-byte block boundaries to prevent
// content type inference from ciphertext length. Padding is random bytes,
// stripped after decryption.
//
// Design:
//   - Block size: 256 bytes (configurable for testing)
//   - Padding format: [original_length (4 bytes LE)] [message] [random padding]
//   - Total output length is always a multiple of block size
//   - Deterministic mode: HKDF-seeded PRNG for reproducible tests
//   - Production mode: SecRandomCopyBytes for cryptographic randomness
//
// The 4-byte length prefix is included INSIDE the encrypted envelope,
// so an observer only sees the block-aligned ciphertext size.

import Foundation
import CryptoKit

// MARK: - Padding Configuration

/// Configuration for the traffic padding scheme.
public struct PaddingScheme: Sendable, Equatable {
    /// Block size in bytes. Output is always a multiple of this value.
    public let blockSize: Int
    /// Maximum allowed message size before padding (prevents OOM).
    public let maxMessageSize: Int
    /// Optional deterministic seed for reproducible padding (testing only).
    /// When nil, uses SecRandomCopyBytes (production).
    public let deterministicSeed: Data?

    /// Length prefix size: 4 bytes (UInt32 LE).
    public static let lengthPrefixSize = 4

    /// Default production scheme: 256-byte blocks, 16 MB max, random padding.
    public static let production = PaddingScheme(
        blockSize: 256,
        maxMessageSize: 16 * 1024 * 1024,
        deterministicSeed: nil
    )

    /// Testing scheme with deterministic padding.
    public static func testing(seed: Data = Data(repeating: 0xAA, count: 32)) -> PaddingScheme {
        PaddingScheme(
            blockSize: 256,
            maxMessageSize: 16 * 1024 * 1024,
            deterministicSeed: seed
        )
    }

    public init(blockSize: Int, maxMessageSize: Int = 16 * 1024 * 1024, deterministicSeed: Data? = nil) {
        self.blockSize = blockSize
        self.maxMessageSize = maxMessageSize
        self.deterministicSeed = deterministicSeed
    }
}

// MARK: - Traffic Padder

/// Core traffic padding operations.
///
/// All operations are stateless and pure-functional (no side effects
/// beyond PRNG consumption for random padding bytes).
public enum TrafficPadder {

    /// Compute the padded output length for a given message length.
    ///
    /// Output = ceil((lengthPrefix + messageLength) / blockSize) * blockSize
    ///
    /// The minimum output is one full block (even for empty messages).
    ///
    /// - Parameters:
    ///   - messageLength: Original message length in bytes.
    ///   - blockSize: Block size for alignment.
    /// - Returns: The total padded length in bytes.
    public static func paddedLength(for messageLength: Int, blockSize: Int) -> Int {
        let totalNeeded = PaddingScheme.lengthPrefixSize + messageLength
        let blocks = max(1, (totalNeeded + blockSize - 1) / blockSize)
        return blocks * blockSize
    }

    /// Pad a message to block boundaries.
    ///
    /// Format: [originalLength as UInt32 LE] [message bytes] [random padding]
    ///
    /// The total output is always a multiple of `scheme.blockSize`.
    ///
    /// - Parameters:
    ///   - message: The plaintext message bytes.
    ///   - scheme: Padding configuration (block size, max size, randomness source).
    /// - Returns: The padded message.
    /// - Throws: `NetworkTransportError` on invalid input.
    public static func pad(_ message: Data, scheme: PaddingScheme = .production) throws -> Data {
        // Validate block size
        guard scheme.blockSize > 0, scheme.blockSize & (scheme.blockSize - 1) == 0 else {
            throw NetworkTransportError.invalidBlockSize(blockSize: scheme.blockSize)
        }

        // Validate message size
        guard message.count <= scheme.maxMessageSize else {
            throw NetworkTransportError.paddingExceedsMaxSize(
                messageLength: message.count,
                maxSize: scheme.maxMessageSize
            )
        }

        let totalPaddedLength = paddedLength(for: message.count, blockSize: scheme.blockSize)
        let paddingNeeded = totalPaddedLength - PaddingScheme.lengthPrefixSize - message.count

        // Build padded output
        var output = Data(capacity: totalPaddedLength)

        // 1. Length prefix (UInt32 LE)
        var length = UInt32(message.count).littleEndian
        output.append(Data(bytes: &length, count: PaddingScheme.lengthPrefixSize))

        // 2. Original message
        output.append(message)

        // 3. Random padding bytes
        if paddingNeeded > 0 {
            let padding = try generatePaddingBytes(count: paddingNeeded, scheme: scheme)
            output.append(padding)
        }

        assert(output.count == totalPaddedLength)
        assert(output.count % scheme.blockSize == 0)

        return output
    }

    /// Strip padding and recover the original message.
    ///
    /// - Parameters:
    ///   - paddedData: The block-aligned padded data.
    ///   - scheme: Padding configuration (used for validation only).
    /// - Returns: The original message bytes.
    /// - Throws: `NetworkTransportError` on validation failure.
    public static func strip(_ paddedData: Data, scheme: PaddingScheme = .production) throws -> Data {
        // Must have at least the length prefix
        guard paddedData.count >= PaddingScheme.lengthPrefixSize else {
            throw NetworkTransportError.paddingValidationFailed(
                reason: "Padded data too short: \(paddedData.count) bytes"
            )
        }

        // Must be block-aligned
        guard paddedData.count % scheme.blockSize == 0 else {
            throw NetworkTransportError.paddingValidationFailed(
                reason: "Padded data not block-aligned: \(paddedData.count) bytes (block size: \(scheme.blockSize))"
            )
        }

        // Extract length prefix
        let lengthBytes = paddedData.prefix(PaddingScheme.lengthPrefixSize)
        let originalLength = lengthBytes.withUnsafeBytes { $0.load(as: UInt32.self).littleEndian }

        // Validate original length
        let maxOriginal = paddedData.count - PaddingScheme.lengthPrefixSize
        guard originalLength <= maxOriginal else {
            throw NetworkTransportError.paddingValidationFailed(
                reason: "Original length \(originalLength) exceeds available \(maxOriginal) bytes"
            )
        }

        // Extract original message
        let messageStart = PaddingScheme.lengthPrefixSize
        let messageEnd = messageStart + Int(originalLength)
        return paddedData[messageStart..<messageEnd]
    }

    /// Check whether two messages of the given lengths will produce the
    /// same padded output size.
    ///
    /// - Parameters:
    ///   - length1: First message length.
    ///   - length2: Second message length.
    ///   - blockSize: Block size for alignment.
    /// - Returns: `true` if both messages pad to the same total length.
    public static func sameBlockSize(length1: Int, length2: Int, blockSize: Int) -> Bool {
        paddedLength(for: length1, blockSize: blockSize) == paddedLength(for: length2, blockSize: blockSize)
    }

    // MARK: - Internal

    /// Generate padding bytes using either deterministic or random source.
    private static func generatePaddingBytes(count: Int, scheme: PaddingScheme) throws -> Data {
        if let seed = scheme.deterministicSeed {
            // Deterministic: derive padding from HKDF with the seed
            return deterministicPadding(count: count, seed: seed)
        } else {
            // Production: cryptographic random bytes
            return randomPadding(count: count)
        }
    }

    /// Generate deterministic padding bytes via HKDF-SHA256 expansion.
    /// Used only in tests for reproducibility.
    private static func deterministicPadding(count: Int, seed: Data) -> Data {
        let key = SymmetricKey(data: seed)
        // Use HKDF to expand the seed into the required number of bytes
        // We use a fixed info string for domain separation
        let info = Data("Veil:TrafficPadding:v1".utf8)
        var output = Data()
        var counter: UInt32 = 0
        while output.count < count {
            var counterData = counter.littleEndian
            let block = Data(HMAC<SHA256>.authenticationCode(
                for: info + Data(bytes: &counterData, count: 4),
                using: key
            ))
            output.append(block)
            counter += 1
        }
        return output.prefix(count)
    }

    /// Generate cryptographically random padding bytes.
    private static func randomPadding(count: Int) -> Data {
        var bytes = Data(count: count)
        bytes.withUnsafeMutableBytes { ptr in
            guard let baseAddress = ptr.baseAddress else { return }
            // SecRandomCopyBytes is available on all Apple platforms
            _ = SecRandomCopyBytes(kSecRandomDefault, count, baseAddress)
        }
        return bytes
    }
}
