// VEIL — PaddingHardeningTests.swift
// Ticket: VEIL-901 — Security Hardening Tests
// Spec reference: Section 2.1 (Traffic Analysis Resistance)
//
// Tests for exponential bucket padding:
//   - Correct bucket selection for various message sizes
//   - All 9 bucket sizes exercised
//   - HMAC authentication round-trip
//   - HMAC tampering detection
//   - Length prefix tampering detection
//   - Maximum message size handling
//   - Empty message handling
//   - Traffic analysis reduction verification

import XCTest
import CryptoKit
@testable import VeilCrypto

final class PaddingHardeningTests: XCTestCase {

    private var padding: ExponentialPaddingScheme!
    private let hmacKey = SymmetricKey(size: .bits256)

    override func setUp() {
        super.setUp()
        padding = ExponentialPaddingScheme(hmacKey: hmacKey)
    }

    // MARK: - Bucket Selection

    /// **HARDENING: Small messages pad to 256 bucket.**
    func testSmallMessage_256Bucket() {
        let bucket = ExponentialPaddingScheme.selectBucket(for: 10)
        XCTAssertEqual(bucket, 256)
    }

    /// **HARDENING: 252-byte message (+ 4 prefix = 256) fits in 256 bucket.**
    func testExact256Boundary() {
        let bucket = ExponentialPaddingScheme.selectBucket(for: 252)
        XCTAssertEqual(bucket, 256, "252 bytes + 4 prefix = 256, fits in 256 bucket")
    }

    /// **HARDENING: 253-byte message (+ 4 prefix = 257) needs 512 bucket.**
    func testJustOver256() {
        let bucket = ExponentialPaddingScheme.selectBucket(for: 253)
        XCTAssertEqual(bucket, 512, "253 + 4 = 257 > 256, needs 512 bucket")
    }

    /// **HARDENING: Messages at various sizes select correct buckets.**
    func testBucketSelection() {
        let cases: [(Int, Int)] = [
            (0, 256),       // Empty → 256
            (1, 256),       // 1 byte → 256
            (100, 256),     // 100 bytes → 256
            (252, 256),     // 252 + 4 = 256 → 256
            (253, 512),     // 253 + 4 = 257 → 512
            (508, 512),     // 508 + 4 = 512 → 512
            (509, 1024),    // 509 + 4 = 513 → 1024
            (1020, 1024),   // 1020 + 4 = 1024 → 1024
            (1021, 2048),   // 1021 + 4 = 1025 → 2048
            (4092, 4096),   // 4092 + 4 = 4096 → 4096
            (4093, 8192),   // 4093 + 4 = 4097 → 8192
            (16380, 16384), // 16380 + 4 = 16384 → 16384
            (32764, 32768), // 32764 + 4 = 32768 → 32768
            (65532, 65536), // 65532 + 4 = 65536 → 65536
        ]

        for (messageSize, expectedBucket) in cases {
            let bucket = ExponentialPaddingScheme.selectBucket(for: messageSize)
            XCTAssertEqual(
                bucket, expectedBucket,
                "Message size \(messageSize) should select bucket \(expectedBucket), got \(bucket)"
            )
        }
    }

    /// **HARDENING: All 9 bucket sizes are exercised.**
    func testBucketCoverage() {
        let expectedBuckets: Set<Int> = [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        var coveredBuckets = Set<Int>()

        // Test sizes that should hit each bucket
        let testSizes = [1, 253, 509, 1021, 2045, 4093, 8189, 16381, 32765]
        for size in testSizes {
            coveredBuckets.insert(ExponentialPaddingScheme.selectBucket(for: size))
        }

        XCTAssertEqual(coveredBuckets, expectedBuckets, "All 9 buckets should be covered")
    }

    // MARK: - HMAC Authentication

    /// **HARDENING: Pad → unpad round-trip preserves message.**
    func testHMACAuthentication_roundTrip() throws {
        let message = Data("Hello, this is a test message for padding!".utf8)

        let padded = try padding.pad(message: message)
        let unpadded = try padding.unpad(envelope: padded)

        XCTAssertEqual(unpadded, message, "Round-trip should preserve message")
    }

    /// **HARDENING: Various message sizes round-trip correctly.**
    func testRoundTrip_variousSizes() throws {
        let sizes = [0, 1, 10, 100, 252, 253, 500, 1000, 2000, 4000, 8000, 16000, 32000, 65000]

        for size in sizes {
            let message = Data((0..<size).map { _ in UInt8.random(in: 0...255) })
            let padded = try padding.pad(message: message)
            let unpadded = try padding.unpad(envelope: padded)

            XCTAssertEqual(
                unpadded, message,
                "Round-trip failed for message size \(size)"
            )
        }
    }

    /// **HARDENING: Padded envelope has correct structure.**
    func testEnvelopeStructure() throws {
        let message = Data("test".utf8)
        let envelope = try padding.pad(message: message)

        // Envelope = HMAC (32) + bucket_size
        let expectedBucket = ExponentialPaddingScheme.selectBucket(for: message.count)
        XCTAssertEqual(
            envelope.count,
            ExponentialPaddingScheme.hmacSize + expectedBucket
        )
    }

    // MARK: - Tampering Detection

    /// **HARDENING: Modified padded content detected via HMAC.**
    func testHMACTampering() throws {
        let message = Data("secret message".utf8)
        var envelope = try padding.pad(message: message)

        // Tamper with content (after HMAC)
        let tamperIndex = ExponentialPaddingScheme.hmacSize + 10
        envelope[tamperIndex] ^= 0xFF

        XCTAssertThrowsError(
            try padding.unpad(envelope: envelope),
            "Tampered envelope should fail HMAC verification"
        ) { error in
            XCTAssertEqual(error as? PaddingError, .hmacVerificationFailed)
        }
    }

    /// **HARDENING: Modified length prefix detected via HMAC.**
    func testLengthPrefixTampering() throws {
        let message = Data("test message".utf8)
        var envelope = try padding.pad(message: message)

        // Tamper with the length prefix (first 4 bytes after HMAC)
        let lengthIndex = ExponentialPaddingScheme.hmacSize
        envelope[lengthIndex] ^= 0xFF

        XCTAssertThrowsError(
            try padding.unpad(envelope: envelope),
            "Length prefix tampering should be detected"
        ) { error in
            XCTAssertEqual(error as? PaddingError, .hmacVerificationFailed)
        }
    }

    /// **HARDENING: Modified HMAC tag is rejected.**
    func testHMACTagTampering() throws {
        let message = Data("important data".utf8)
        var envelope = try padding.pad(message: message)

        // Tamper with the HMAC tag itself
        envelope[0] ^= 0x01

        XCTAssertThrowsError(
            try padding.unpad(envelope: envelope)
        ) { error in
            XCTAssertEqual(error as? PaddingError, .hmacVerificationFailed)
        }
    }

    // MARK: - Edge Cases

    /// **HARDENING: Empty message pads to 256 bucket.**
    func testEmptyMessage() throws {
        let message = Data()
        let padded = try padding.pad(message: message)

        XCTAssertEqual(
            padded.count,
            ExponentialPaddingScheme.hmacSize + 256,
            "Empty message should pad to 256 bucket"
        )

        let unpadded = try padding.unpad(envelope: padded)
        XCTAssertEqual(unpadded, message)
    }

    /// **HARDENING: Maximum size message (65532 bytes).**
    func testMaxMessageSize() throws {
        let message = Data(repeating: 0xAA, count: ExponentialPaddingScheme.maxMessageSize)
        let padded = try padding.pad(message: message)
        let unpadded = try padding.unpad(envelope: padded)

        XCTAssertEqual(unpadded, message)
    }

    /// **HARDENING: Message exceeding max size throws.**
    func testOversizedMessage() {
        let message = Data(repeating: 0xBB, count: ExponentialPaddingScheme.maxMessageSize + 1)

        XCTAssertThrowsError(
            try padding.pad(message: message)
        ) { error in
            if case PaddingError.messageTooLarge(let size, let maximum) = error {
                XCTAssertEqual(size, ExponentialPaddingScheme.maxMessageSize + 1)
                XCTAssertEqual(maximum, ExponentialPaddingScheme.maxMessageSize)
            } else {
                XCTFail("Expected messageTooLarge error")
            }
        }
    }

    /// **HARDENING: Too-small envelope rejected.**
    func testTooSmallEnvelope() {
        let smallEnvelope = Data(repeating: 0, count: 10)

        XCTAssertThrowsError(
            try padding.unpad(envelope: smallEnvelope)
        ) { error in
            XCTAssertEqual(error as? PaddingError, .envelopeTooSmall)
        }
    }

    // MARK: - Traffic Analysis Properties

    /// **HARDENING: 100 messages of varying sizes produce only 9 distinct output sizes.**
    func testTrafficAnalysis_distinctSizes() throws {
        var outputSizes = Set<Int>()

        for _ in 0..<100 {
            let size = Int.random(in: 1...65000)
            let message = Data(repeating: 0, count: size)
            let padded = try padding.pad(message: message)
            outputSizes.insert(padded.count)
        }

        // Should be at most 9 distinct sizes (one per bucket + HMAC overhead)
        XCTAssertLessThanOrEqual(
            outputSizes.count, 9,
            "At most 9 distinct padded sizes should be possible"
        )
    }

    /// **HARDENING: PaddingAnalysis utility works correctly.**
    func testPaddingAnalysis() {
        // Distinct sizes for range 1..1000
        let sizes = PaddingAnalysis.distinctSizes(messageSizeRange: 1..<1000)
        XCTAssertTrue(sizes.count <= 4, "Messages 1-999 should use at most 4 buckets")
        XCTAssertTrue(sizes.contains(256))
        XCTAssertTrue(sizes.contains(512))
        XCTAssertTrue(sizes.contains(1024))

        // Overhead calculation
        let overhead = PaddingAnalysis.overhead(messageSize: 10)
        XCTAssertEqual(overhead, 256 - 4 - 10, "Overhead for 10-byte message in 256 bucket")
    }

    /// **HARDENING: Different HMAC keys produce different envelopes.**
    func testDifferentKeys() throws {
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)
        let padding1 = ExponentialPaddingScheme(hmacKey: key1)
        let padding2 = ExponentialPaddingScheme(hmacKey: key2)

        let message = Data("same message".utf8)
        let padded1 = try padding1.pad(message: message)
        let padded2 = try padding2.pad(message: message)

        // HMAC tags should differ
        let hmac1 = padded1.prefix(ExponentialPaddingScheme.hmacSize)
        let hmac2 = padded2.prefix(ExponentialPaddingScheme.hmacSize)
        XCTAssertNotEqual(hmac1, hmac2, "Different keys should produce different HMACs")

        // Cross-key unpadding should fail
        XCTAssertThrowsError(try padding1.unpad(envelope: padded2))
        XCTAssertThrowsError(try padding2.unpad(envelope: padded1))
    }
}
