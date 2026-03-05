// VEIL — SymmetricRatchetTests.swift
// Tests for VEIL-105: Symmetric Chain Ratchet

import XCTest
@testable import VeilCrypto

final class SymmetricRatchetTests: XCTestCase {

    // MARK: - Basic Advancement

    func testAdvance_producesMessageKey() throws {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(bytes: Array(repeating: 0xAA, count: 32)))
        let mk = try ratchet.advance()
        XCTAssertEqual(mk.count, 32)
        XCTAssertEqual(ratchet.index, 1)
    }

    func testAdvance_updatesChainKey() throws {
        let initialCK = SecureBytes(bytes: Array(repeating: 0xAA, count: 32))
        var ratchet = SymmetricRatchet(chainKey: initialCK)

        _ = try ratchet.advance()
        XCTAssertNotEqual(ratchet.chainKey, initialCK,
                          "Chain key must change after advancement")
    }

    func testAdvance_producesUniqueMessageKeys() throws {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(bytes: Array(repeating: 0xBB, count: 32)))
        var keys: [Data] = []

        for _ in 0..<100 {
            let mk = try ratchet.advance()
            let data = try mk.copyToData()
            XCTAssertFalse(keys.contains(data), "Message keys must be unique")
            keys.append(data)
        }
    }

    func testAdvance_indexIncrements() throws {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(count: 32))

        for i in 0..<10 {
            _ = try ratchet.advance()
            XCTAssertEqual(ratchet.index, UInt32(i + 1))
        }
    }

    // MARK: - Determinism

    func testAdvance_isDeterministic() throws {
        let ck = SecureBytes(bytes: Array(repeating: 0x42, count: 32))

        var ratchet1 = SymmetricRatchet(chainKey: ck)
        var ratchet2 = SymmetricRatchet(chainKey: SecureBytes(bytes: Array(repeating: 0x42, count: 32)))

        for _ in 0..<10 {
            let mk1 = try ratchet1.advance()
            let mk2 = try ratchet2.advance()
            XCTAssertEqual(mk1, mk2, "Same initial CK must produce same MK sequence")
        }
    }

    // MARK: - Skip Handling

    func testSkipTo_storesSkippedKeys() throws {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(count: 32))

        try ratchet.skipTo(index: 5)
        XCTAssertEqual(ratchet.skippedKeyCount, 5)
        XCTAssertEqual(ratchet.index, 5)
    }

    func testConsumeSkippedKey_returnsAndRemoves() throws {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(count: 32))

        try ratchet.skipTo(index: 3)
        XCTAssertEqual(ratchet.skippedKeyCount, 3)

        let key = ratchet.consumeSkippedKey(at: 1)
        XCTAssertNotNil(key)
        XCTAssertEqual(ratchet.skippedKeyCount, 2)

        // Consuming again returns nil
        let again = ratchet.consumeSkippedKey(at: 1)
        XCTAssertNil(again, "Consumed key must not be returned again")
    }

    func testSkipTo_exceedingMax_throws() {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(count: 32))

        XCTAssertThrowsError(
            try ratchet.skipTo(index: UInt32(VeilConstants.maxSkippedMessageKeys + 1))
        ) { error in
            guard case VeilError.tooManySkippedMessages = error else {
                XCTFail("Expected tooManySkippedMessages, got \(error)")
                return
            }
        }
    }

    // MARK: - Message Key ≠ Chain Key

    func testMessageKeyNeverEqualsChainKey() throws {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(bytes: Array(repeating: 0xFF, count: 32)))

        for _ in 0..<50 {
            let mk = try ratchet.advance()
            XCTAssertNotEqual(mk, ratchet.chainKey,
                              "Message key must never equal the chain key")
        }
    }
}
