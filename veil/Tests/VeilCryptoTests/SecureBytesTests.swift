// VEIL — SecureBytesTests.swift
// Tests for VEIL-109: SecureBytes zeroizing memory type

import XCTest
@testable import VeilCrypto

final class SecureBytesTests: XCTestCase {

    // MARK: - Initialization

    func testInitWithCount_createsZeroFilledBuffer() throws {
        let sb = SecureBytes(count: 32)
        XCTAssertEqual(sb.count, 32)
        XCTAssertFalse(sb.isZeroized)

        let data = try sb.copyToData()
        XCTAssertEqual(data, Data(repeating: 0, count: 32))
    }

    func testInitWithBytes_copiesCorrectly() throws {
        let original: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF]
        let sb = SecureBytes(bytes: original)
        XCTAssertEqual(sb.count, 4)

        let data = try sb.copyToData()
        XCTAssertEqual(data, Data(original))
    }

    func testInitWithData_copiesCorrectly() throws {
        let original = Data([0x01, 0x02, 0x03])
        let sb = SecureBytes(copying: original)
        XCTAssertEqual(sb.count, 3)

        let exported = try sb.copyToData()
        XCTAssertEqual(exported, original)
    }

    // MARK: - Zeroization

    func testZeroize_marksBufferAsZeroized() {
        var sb = SecureBytes(bytes: [0xFF, 0xFF, 0xFF])
        XCTAssertFalse(sb.isZeroized)

        sb.zeroize()
        XCTAssertTrue(sb.isZeroized)
    }

    func testZeroize_isIdempotent() {
        var sb = SecureBytes(count: 16)
        sb.zeroize()
        sb.zeroize() // Should not crash
        XCTAssertTrue(sb.isZeroized)
    }

    func testAccessAfterZeroize_throws() {
        var sb = SecureBytes(bytes: [0x42])
        sb.zeroize()

        XCTAssertThrowsError(try sb.copyToData()) { error in
            XCTAssertEqual(error as? VeilError, VeilError.useAfterZeroize)
        }
    }

    func testWithUnsafeBytesAfterZeroize_throws() {
        var sb = SecureBytes(bytes: [0x42])
        sb.zeroize()

        XCTAssertThrowsError(try sb.withUnsafeBytes { _ in }) { error in
            XCTAssertEqual(error as? VeilError, VeilError.useAfterZeroize)
        }
    }

    // MARK: - Constant-Time Comparison

    func testConstantTimeEqual_identicalBuffers() {
        let a = SecureBytes(bytes: [0x01, 0x02, 0x03])
        let b = SecureBytes(bytes: [0x01, 0x02, 0x03])
        XCTAssertTrue(SecureBytes.constantTimeEqual(a, b))
    }

    func testConstantTimeEqual_differentBuffers() {
        let a = SecureBytes(bytes: [0x01, 0x02, 0x03])
        let b = SecureBytes(bytes: [0x01, 0x02, 0x04])
        XCTAssertFalse(SecureBytes.constantTimeEqual(a, b))
    }

    func testConstantTimeEqual_differentLengths() {
        let a = SecureBytes(bytes: [0x01, 0x02])
        let b = SecureBytes(bytes: [0x01, 0x02, 0x03])
        XCTAssertFalse(SecureBytes.constantTimeEqual(a, b))
    }

    func testConstantTimeEqual_zeroizedBuffer() {
        let a = SecureBytes(bytes: [0x01])
        var b = SecureBytes(bytes: [0x01])
        b.zeroize()
        XCTAssertFalse(SecureBytes.constantTimeEqual(a, b))
    }

    // MARK: - Equatable

    func testEquatable_usesConstantTimeComparison() {
        let a = SecureBytes(bytes: [0xAA, 0xBB])
        let b = SecureBytes(bytes: [0xAA, 0xBB])
        XCTAssertEqual(a, b)
    }

    // MARK: - Description Safety

    func testDescription_doesNotLeakContents() {
        let sb = SecureBytes(bytes: [0xDE, 0xAD, 0xBE, 0xEF])
        let desc = sb.description
        XCTAssertFalse(desc.contains("DE"))
        XCTAssertFalse(desc.contains("DEAD"))
        XCTAssertTrue(desc.contains("4 bytes"))
    }

    func testDebugDescription_doesNotLeakContents() {
        let sb = SecureBytes(bytes: [0xFF, 0x00])
        let desc = sb.debugDescription
        XCTAssertFalse(desc.contains("FF"))
        XCTAssertTrue(desc.contains("count: 2"))
    }
}
