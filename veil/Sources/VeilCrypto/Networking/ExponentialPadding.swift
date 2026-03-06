// VEIL — ExponentialPadding.swift
// Ticket: VEIL-901 — Security Hardening (Red Team Finding: 256-Byte Padding Leak)
// Spec reference: Section 2.1 (Traffic Analysis Resistance)
//
// CRITICAL FIX: The original 256-byte block padding allowed an observer to
// categorize messages by which bucket they fall into. Short ACKs, typical
// messages, and file transfers produce distinct padded sizes, enabling
// traffic analysis even with padding active.
//
// This module implements exponential bucket padding:
//   Buckets: 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
//   Each message is padded to the next power-of-2 bucket boundary.
//   This reduces the information leaked from O(n/256) distinct sizes to
//   only 9 distinct sizes, making traffic analysis significantly harder.
//
// Additionally adds HMAC-SHA256 authentication over the padded envelope
// to prevent an active attacker from modifying the length prefix.

import Foundation
import CryptoKit

// MARK: - Exponential Padding Scheme

/// Exponential-bucket padding scheme for traffic analysis resistance.
///
/// Pads messages to the next power-of-2 boundary from a minimum of 256 bytes.
/// Only 9 distinct output sizes are possible (256 to 65536), significantly
/// reducing the information leaked by ciphertext length.
///
/// Wire format:
/// ```
/// [HMAC-SHA256 (32 bytes)] [length (4 bytes LE)] [message] [random padding]
/// ```
///
/// The HMAC covers the entire padded envelope (length prefix + message + padding),
/// preventing an active attacker from modifying the length prefix to cause
/// incorrect padding removal.
public struct ExponentialPaddingScheme: Sendable {

    /// The exponential bucket sizes (powers of 2 from 256 to 65536).
    public static let buckets: [Int] = [
        256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
    ]

    /// Length prefix size: 4 bytes (UInt32 LE).
    public static let lengthPrefixSize = 4

    /// HMAC tag size: 32 bytes (SHA-256).
    public static let hmacSize = 32

    /// Maximum message size (largest bucket minus overhead).
    public static let maxMessageSize = 65536 - lengthPrefixSize

    /// HMAC key for authenticating padded envelopes.
    /// Derived from the session's sending chain key.
    private let hmacKey: SymmetricKey

    /// Optional deterministic seed for testing (nil = production random).
    private let deterministicSeed: Data?

    /// Production configuration.
    public init(hmacKey: SymmetricKey) {
        self.hmacKey = hmacKey
        self.deterministicSeed = nil
    }

    /// Testing configuration with deterministic padding.
    #if DEBUG
    public init(hmacKey: SymmetricKey, deterministicSeed: Data) {
        self.hmacKey = hmacKey
        self.deterministicSeed = deterministicSeed
    }
    #endif

    // MARK: - Bucket Selection

    /// Select the appropriate bucket size for a message of the given length.
    ///
    /// The message content size is: lengthPrefix (4 bytes) + message.
    /// We find the smallest bucket that can contain this.
    ///
    /// - Parameter messageSize: The raw message size in bytes.
    /// - Returns: The bucket size to pad to.
    public static func selectBucket(for messageSize: Int) -> Int {
        let totalNeeded = lengthPrefixSize + messageSize

        for bucket in buckets {
            if totalNeeded <= bucket {
                return bucket
            }
        }

        // Message too large for any bucket — use the largest
        return buckets.last!
    }

    // MARK: - Padding

    /// Pad a message to an exponential bucket boundary and authenticate.
    ///
    /// - Parameter message: The plaintext message to pad.
    /// - Returns: The padded and authenticated envelope.
    /// - Throws: If the message exceeds the maximum size.
    public func pad(message: Data) throws -> Data {
        guard message.count <= Self.maxMessageSize else {
            throw PaddingError.messageTooLarge(
                size: message.count,
                maximum: Self.maxMessageSize
            )
        }

        let bucketSize = Self.selectBucket(for: message.count)
        let paddingNeeded = bucketSize - Self.lengthPrefixSize - message.count

        // Construct the padded content: [length (4 LE)] [message] [random padding]
        var paddedContent = Data(capacity: bucketSize)

        // Length prefix (UInt32 LE)
        var messageLength = UInt32(message.count).littleEndian
        paddedContent.append(Data(bytes: &messageLength, count: 4))

        // Message
        paddedContent.append(message)

        // Random padding
        if paddingNeeded > 0 {
            let padding = generatePadding(count: paddingNeeded)
            paddedContent.append(padding)
        }

        assert(paddedContent.count == bucketSize)

        // Compute HMAC-SHA256 over the padded content
        let hmac = HMAC<SHA256>.authenticationCode(for: paddedContent, using: hmacKey)
        let hmacData = Data(hmac)

        // Final envelope: [HMAC (32)] [padded content]
        var envelope = Data(capacity: Self.hmacSize + bucketSize)
        envelope.append(hmacData)
        envelope.append(paddedContent)

        return envelope
    }

    // MARK: - Unpadding

    /// Remove padding from an authenticated envelope.
    ///
    /// - Parameter envelope: The padded and authenticated envelope.
    /// - Returns: The original message.
    /// - Throws: If HMAC verification fails or the envelope is malformed.
    public func unpad(envelope: Data) throws -> Data {
        guard envelope.count > Self.hmacSize + Self.lengthPrefixSize else {
            throw PaddingError.envelopeTooSmall
        }

        // Extract HMAC and padded content
        let receivedHMAC = envelope.prefix(Self.hmacSize)
        let paddedContent = envelope.dropFirst(Self.hmacSize)

        // Verify HMAC
        let expectedHMAC = HMAC<SHA256>.authenticationCode(
            for: paddedContent,
            using: hmacKey
        )
        guard Data(expectedHMAC) == receivedHMAC else {
            throw PaddingError.hmacVerificationFailed
        }

        // Verify bucket size
        let contentSize = paddedContent.count
        guard Self.buckets.contains(contentSize) else {
            throw PaddingError.invalidBucketSize(contentSize)
        }

        // Extract length prefix
        let lengthBytes = paddedContent.prefix(Self.lengthPrefixSize)
        let messageLength = lengthBytes.withUnsafeBytes {
            $0.load(as: UInt32.self).littleEndian
        }

        // Validate length
        guard messageLength <= contentSize - Self.lengthPrefixSize else {
            throw PaddingError.invalidLengthPrefix(
                claimed: Int(messageLength),
                available: contentSize - Self.lengthPrefixSize
            )
        }

        // Extract message
        let messageStart = paddedContent.startIndex + Self.lengthPrefixSize
        let messageEnd = messageStart + Int(messageLength)
        return Data(paddedContent[messageStart..<messageEnd])
    }

    // MARK: - Random Generation

    /// Generate random padding bytes.
    private func generatePadding(count: Int) -> Data {
        if let seed = deterministicSeed {
            // Deterministic mode (testing only)
            return generateDeterministicPadding(count: count, seed: seed)
        }

        // Production: cryptographically random
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        guard status == errSecSuccess else {
            // Fallback to less-ideal but still usable random
            for i in 0..<count {
                bytes[i] = UInt8.random(in: 0...255)
            }
            return Data(bytes)
        }
        return Data(bytes)
    }

    /// Generate deterministic padding from a seed (for testing).
    private func generateDeterministicPadding(count: Int, seed: Data) -> Data {
        var result = Data(capacity: count)
        var counter: UInt32 = 0

        while result.count < count {
            var input = seed
            var counterLE = counter.littleEndian
            input.append(Data(bytes: &counterLE, count: 4))
            let hash = Data(SHA256.hash(data: input))
            let needed = min(hash.count, count - result.count)
            result.append(hash.prefix(needed))
            counter += 1
        }

        return result.prefix(count)
    }
}

// MARK: - Padding Errors

/// Errors during padding/unpadding operations.
public enum PaddingError: Error, Sendable, Equatable {
    /// Message exceeds the maximum padded size.
    case messageTooLarge(size: Int, maximum: Int)
    /// Envelope is too small to contain a valid padded message.
    case envelopeTooSmall
    /// HMAC verification failed (tampered or corrupted envelope).
    case hmacVerificationFailed
    /// The padded content size doesn't match any valid bucket.
    case invalidBucketSize(Int)
    /// The length prefix claims more bytes than available.
    case invalidLengthPrefix(claimed: Int, available: Int)
}

// MARK: - Bucket Analysis (for testing)

/// Utility for analyzing the traffic analysis properties of the padding scheme.
public enum PaddingAnalysis: Sendable {
    /// Determine which bucket a message of a given size would fall into.
    public static func bucketFor(messageSize: Int) -> Int {
        ExponentialPaddingScheme.selectBucket(for: messageSize)
    }

    /// Count the number of distinct output sizes for a range of message sizes.
    public static func distinctSizes(messageSizeRange: Range<Int>) -> Set<Int> {
        var sizes = Set<Int>()
        for size in messageSizeRange {
            sizes.insert(bucketFor(messageSize: size))
        }
        return sizes
    }

    /// Compute the overhead (wasted bytes) for a given message size.
    public static func overhead(messageSize: Int) -> Int {
        let bucket = bucketFor(messageSize: messageSize)
        return bucket - ExponentialPaddingScheme.lengthPrefixSize - messageSize
    }
}
