// VEIL — Traffic Padding Tests
// Ticket: VEIL-602 — Traffic Padding
// Epic: 6 — Network & Transport Layer

import XCTest
@testable import VeilCrypto

final class TrafficPaddingTests: XCTestCase {

    let scheme = PaddingScheme.testing()

    // MARK: - Padded Length Calculation

    func testPaddedLengthIsMultipleOfBlockSize() {
        for msgLen in [0, 1, 100, 251, 252, 253, 500, 1000, 2048] {
            let padded = TrafficPadder.paddedLength(for: msgLen, blockSize: 256)
            XCTAssertEqual(padded % 256, 0, "Message length \(msgLen) → padded \(padded) not aligned")
        }
    }

    func testMinimumPaddedLengthIsOneBlock() {
        let padded = TrafficPadder.paddedLength(for: 0, blockSize: 256)
        XCTAssertEqual(padded, 256)
    }

    func testPaddedLengthExactFit() {
        // 252 bytes of message + 4 bytes prefix = 256 exactly
        let padded = TrafficPadder.paddedLength(for: 252, blockSize: 256)
        XCTAssertEqual(padded, 256)
    }

    func testPaddedLengthRollsOverToNextBlock() {
        // 253 bytes of message + 4 bytes prefix = 257 → next block = 512
        let padded = TrafficPadder.paddedLength(for: 253, blockSize: 256)
        XCTAssertEqual(padded, 512)
    }

    // MARK: - Pad and Strip Round-Trip

    func testPadStripRoundTrip() throws {
        let message = Data("Hello, Veil!".utf8)
        let padded = try TrafficPadder.pad(message, scheme: scheme)
        let recovered = try TrafficPadder.strip(padded, scheme: scheme)
        XCTAssertEqual(recovered, message)
    }

    func testPadStripEmptyMessage() throws {
        let message = Data()
        let padded = try TrafficPadder.pad(message, scheme: scheme)
        XCTAssertEqual(padded.count, 256) // One full block
        let recovered = try TrafficPadder.strip(padded, scheme: scheme)
        XCTAssertEqual(recovered, message)
    }

    func testPadStripLargeMessage() throws {
        let message = Data(repeating: 0x42, count: 1000)
        let padded = try TrafficPadder.pad(message, scheme: scheme)
        XCTAssertEqual(padded.count % 256, 0)
        let recovered = try TrafficPadder.strip(padded, scheme: scheme)
        XCTAssertEqual(recovered, message)
    }

    // MARK: - Deterministic Padding

    func testDeterministicPaddingIsReproducible() throws {
        let message = Data("Deterministic test".utf8)
        let padded1 = try TrafficPadder.pad(message, scheme: scheme)
        let padded2 = try TrafficPadder.pad(message, scheme: scheme)
        XCTAssertEqual(padded1, padded2, "Same seed should produce identical padding")
    }

    func testDifferentSeedsProduceDifferentPadding() throws {
        let message = Data("Different seeds".utf8)
        let scheme1 = PaddingScheme.testing(seed: Data(repeating: 0xAA, count: 32))
        let scheme2 = PaddingScheme.testing(seed: Data(repeating: 0xBB, count: 32))
        let padded1 = try TrafficPadder.pad(message, scheme: scheme1)
        let padded2 = try TrafficPadder.pad(message, scheme: scheme2)
        // The message portion is the same but the padding bytes differ
        XCTAssertNotEqual(padded1, padded2)
    }

    // MARK: - Same-Size Property

    func testSimilarLengthMessagesSameBlockSize() {
        // Messages within the same 252-byte window should pad identically
        XCTAssertTrue(TrafficPadder.sameBlockSize(length1: 10, length2: 200, blockSize: 256))
        XCTAssertTrue(TrafficPadder.sameBlockSize(length1: 1, length2: 252, blockSize: 256))
    }

    func testDifferentBlockMessages() {
        // 252 fits in one block, 253 spills to two blocks
        XCTAssertFalse(TrafficPadder.sameBlockSize(length1: 252, length2: 253, blockSize: 256))
    }

    // MARK: - Error Cases

    func testInvalidBlockSizeThrows() {
        let badScheme = PaddingScheme(blockSize: 100) // Not power of 2
        XCTAssertThrowsError(try TrafficPadder.pad(Data("test".utf8), scheme: badScheme)) { error in
            guard let transportError = error as? NetworkTransportError else {
                XCTFail("Expected NetworkTransportError"); return
            }
            if case .invalidBlockSize(let size) = transportError {
                XCTAssertEqual(size, 100)
            } else {
                XCTFail("Expected invalidBlockSize error")
            }
        }
    }

    func testOversizedMessageThrows() {
        let smallScheme = PaddingScheme(blockSize: 256, maxMessageSize: 100)
        let bigMessage = Data(repeating: 0x42, count: 200)
        XCTAssertThrowsError(try TrafficPadder.pad(bigMessage, scheme: smallScheme)) { error in
            guard case NetworkTransportError.paddingExceedsMaxSize = error as? NetworkTransportError else {
                XCTFail("Expected paddingExceedsMaxSize error"); return
            }
        }
    }

    func testStripTooShortDataThrows() {
        let shortData = Data([0x01, 0x02])
        XCTAssertThrowsError(try TrafficPadder.strip(shortData, scheme: scheme)) { error in
            guard case NetworkTransportError.paddingValidationFailed = error as? NetworkTransportError else {
                XCTFail("Expected paddingValidationFailed error"); return
            }
        }
    }

    func testStripMisalignedDataThrows() {
        let misaligned = Data(repeating: 0x00, count: 300) // Not a multiple of 256
        XCTAssertThrowsError(try TrafficPadder.strip(misaligned, scheme: scheme)) { error in
            guard case NetworkTransportError.paddingValidationFailed = error as? NetworkTransportError else {
                XCTFail("Expected paddingValidationFailed error"); return
            }
        }
    }

    func testStripCorruptedLengthThrows() throws {
        // Create valid padded data, then corrupt the length prefix
        var padded = try TrafficPadder.pad(Data("hello".utf8), scheme: scheme)
        // Set length to something larger than available
        var badLength = UInt32(999).littleEndian
        padded.replaceSubrange(0..<4, with: Data(bytes: &badLength, count: 4))
        XCTAssertThrowsError(try TrafficPadder.strip(padded, scheme: scheme))
    }

    // MARK: - CiphertextPaddingLayer

    func testEncoderDecoderRoundTrip() throws {
        let encoder = CiphertextPaddingEncoder(scheme: scheme)
        let decoder = CiphertextPaddingDecoder(scheme: scheme)

        let ciphertext = Data(repeating: 0xEE, count: 100)
        let envelope = try encoder.encode(ciphertext)
        let recovered = try decoder.decode(envelope)
        XCTAssertEqual(recovered, ciphertext)
    }

    func testWireRoundTrip() throws {
        let encoder = CiphertextPaddingEncoder(scheme: scheme)
        let decoder = CiphertextPaddingDecoder(scheme: scheme)

        let ciphertext = Data("encrypted payload".utf8)
        let wireBytes = try encoder.encodeToWire(ciphertext)
        let recovered = try decoder.decodeFromWire(wireBytes)
        XCTAssertEqual(recovered, ciphertext)
    }

    func testPaddedEnvelopeSerialization() throws {
        let envelope = PaddedEnvelope(paddedCiphertext: Data(repeating: 0x42, count: 256))
        let serialized = envelope.serialize()
        let deserialized = try PaddedEnvelope.deserialize(from: serialized)
        XCTAssertEqual(deserialized.version, PaddedEnvelope.currentVersion)
        XCTAssertEqual(deserialized.paddedCiphertext, envelope.paddedCiphertext)
    }

    // MARK: - Padding Statistics

    func testOverheadRatioSmallMessage() {
        let overhead = PaddingStats.overheadRatio(messageLength: 10, blockSize: 256)
        // 10 bytes message + 4 bytes prefix = 14 useful; 242 wasted in 256
        XCTAssertGreaterThan(overhead, 0.9)
    }

    func testOverheadRatioNearFullBlock() {
        let overhead = PaddingStats.overheadRatio(messageLength: 252, blockSize: 256)
        // 252 + 4 = 256 exactly; 0 wasted
        XCTAssertEqual(overhead, 0.0, accuracy: 0.001)
    }

    func testBlockUtilizationExactFit() {
        let util = PaddingStats.blockUtilization(messageLength: 252, blockSize: 256)
        XCTAssertEqual(util, 1.0, accuracy: 0.001)
    }
}
