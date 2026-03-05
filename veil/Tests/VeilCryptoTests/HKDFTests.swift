// VEIL — HKDFTests.swift
// Tests for VEIL-103: HKDF-SHA-512 with Domain Separation

import XCTest
@testable import VeilCrypto

final class HKDFTests: XCTestCase {

    // MARK: - Basic Derivation

    func testDeriveKey_produces32BytesByDefault() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0x0B, count: 32))
        let key = try VeilHKDF.deriveKey(ikm: ikm, domain: .pqxdh)
        XCTAssertEqual(key.count, 32)
        XCTAssertFalse(key.isZeroized)
    }

    func testDeriveKey_producesRequestedLength() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0x0B, count: 32))
        let key = try VeilHKDF.deriveKey(ikm: ikm, domain: .pqxdh, outputByteCount: 64)
        XCTAssertEqual(key.count, 64)
    }

    // MARK: - Domain Separation

    func testDifferentDomains_produceDifferentKeys() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0x42, count: 32))

        let key1 = try VeilHKDF.deriveKey(ikm: ikm, domain: .pqxdh)
        let key2 = try VeilHKDF.deriveKey(ikm: ikm, domain: .dhRatchet)
        let key3 = try VeilHKDF.deriveKey(ikm: ikm, domain: .spqr)

        // All three must be different — this is the core domain separation guarantee
        XCTAssertNotEqual(key1, key2)
        XCTAssertNotEqual(key1, key3)
        XCTAssertNotEqual(key2, key3)
    }

    func testAllDomains_produceUniqueKeys() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0xAA, count: 32))

        var keys: [VeilDomain: Data] = [:]
        for domain in VeilDomain.allCases {
            let key = try VeilHKDF.deriveKey(ikm: ikm, domain: domain)
            keys[domain] = try key.copyToData()
        }

        // Verify all keys are unique
        let uniqueKeys = Set(keys.values)
        XCTAssertEqual(uniqueKeys.count, VeilDomain.allCases.count,
                       "All domain separation strings must produce unique keys")
    }

    // MARK: - Determinism

    func testDeriveKey_isDeterministic() throws {
        let ikm = SecureBytes(bytes: [0x01, 0x02, 0x03, 0x04])
        let salt = SecureBytes(bytes: Array(repeating: 0x00, count: 32))

        let key1 = try VeilHKDF.deriveKey(ikm: ikm, salt: salt, domain: .chainKey)
        let key2 = try VeilHKDF.deriveKey(ikm: ikm, salt: salt, domain: .chainKey)

        XCTAssertEqual(key1, key2, "Same inputs must produce same output")
    }

    // MARK: - Salt Handling

    func testDeriveKey_nilSalt_usesZeroSalt() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0x0B, count: 32))

        // Both should produce the same result
        let key1 = try VeilHKDF.deriveKey(ikm: ikm, salt: nil, domain: .pqxdh)
        let zeroSalt = SecureBytes(count: 64) // SHA-512 hash length
        let key2 = try VeilHKDF.deriveKey(ikm: ikm, salt: zeroSalt, domain: .pqxdh)

        XCTAssertEqual(key1, key2)
    }

    func testDeriveKey_differentSalts_produceDifferentKeys() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0x42, count: 32))
        let salt1 = SecureBytes(bytes: Array(repeating: 0x01, count: 32))
        let salt2 = SecureBytes(bytes: Array(repeating: 0x02, count: 32))

        let key1 = try VeilHKDF.deriveKey(ikm: ikm, salt: salt1, domain: .dhRatchet)
        let key2 = try VeilHKDF.deriveKey(ikm: ikm, salt: salt2, domain: .dhRatchet)

        XCTAssertNotEqual(key1, key2)
    }

    // MARK: - Ratchet Key Derivation

    func testDeriveRatchetKeys_producesTwoDistinctKeys() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xAA, count: 32))
        let input = SecureBytes(bytes: Array(repeating: 0xBB, count: 32))

        let (newRootKey, chainKey) = try VeilHKDF.deriveRatchetKeys(
            rootKey: rootKey,
            input: input,
            domain: .dhRatchet
        )

        XCTAssertEqual(newRootKey.count, 32)
        XCTAssertEqual(chainKey.count, 32)
        XCTAssertNotEqual(newRootKey, chainKey, "Root key and chain key must differ")
        XCTAssertNotEqual(newRootKey, rootKey, "New root key must differ from old")
    }

    // MARK: - Session Key Derivation

    func testDeriveSessionKey_produces64Bytes() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0x42, count: 128))
        let sk = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm)
        XCTAssertEqual(sk.count, VeilConstants.sessionKeySize)
    }

    func testDeriveSessionKey_notAllZeros() throws {
        let ikm = SecureBytes(bytes: Array(repeating: 0x42, count: 128))
        let sk = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm)
        let data = try sk.copyToData()
        XCTAssertNotEqual(data, Data(repeating: 0, count: 64),
                          "Session key must not be all zeros")
    }
}
