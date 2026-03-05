// MobileCoinKeyPairTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// VEIL-401: Tests for MobileCoin key derivation from Veil identity keys.

import XCTest
@testable import VeilCrypto

final class MobileCoinKeyPairTests: XCTestCase {

    private var client: MobileCoinClient!

    override func setUp() async throws {
        client = MobileCoinClient(sdk: MockMobileCoinSDK())
    }

    // MARK: - Key Derivation

    func testDeriveProducesValidKeys() async throws {
        let identityKey = SecureBytes(bytes: Array(repeating: 0x42, count: 32))
        let keyPair = try await MobileCoinKeyPair.derive(from: identityKey, client: client)

        // Spend and view keys must be 32 bytes
        XCTAssertEqual(keyPair.spendKey.count, 32)
        XCTAssertEqual(keyPair.viewKey.count, 32)

        // Public keys must be 32 bytes
        XCTAssertEqual(keyPair.spendPublicKey.count, 32)
        XCTAssertEqual(keyPair.viewPublicKey.count, 32)
    }

    func testDeriveIsDeterministic() async throws {
        let identityKey = SecureBytes(bytes: Array(repeating: 0xAB, count: 32))

        let keyPair1 = try await MobileCoinKeyPair.derive(from: identityKey, client: client)
        let keyPair2 = try await MobileCoinKeyPair.derive(from: identityKey, client: client)

        // Same identity key must produce same MOB keys
        let spend1 = keyPair1.spendKey.withUnsafeBytes { Data($0) }
        let spend2 = keyPair2.spendKey.withUnsafeBytes { Data($0) }
        XCTAssertEqual(spend1, spend2, "Spend key derivation must be deterministic.")

        let view1 = keyPair1.viewKey.withUnsafeBytes { Data($0) }
        let view2 = keyPair2.viewKey.withUnsafeBytes { Data($0) }
        XCTAssertEqual(view1, view2, "View key derivation must be deterministic.")
    }

    func testDifferentIdentityKeysProduceDifferentMOBKeys() async throws {
        let ik1 = SecureBytes(bytes: Array(repeating: 0x01, count: 32))
        let ik2 = SecureBytes(bytes: Array(repeating: 0x02, count: 32))

        let kp1 = try await MobileCoinKeyPair.derive(from: ik1, client: client)
        let kp2 = try await MobileCoinKeyPair.derive(from: ik2, client: client)

        let spend1 = kp1.spendKey.withUnsafeBytes { Data($0) }
        let spend2 = kp2.spendKey.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(spend1, spend2, "Different IKs must produce different spend keys.")
    }

    func testSpendAndViewKeysAreDifferent() async throws {
        let identityKey = SecureBytes(bytes: Array(repeating: 0x77, count: 32))
        let keyPair = try await MobileCoinKeyPair.derive(from: identityKey, client: client)

        let spend = keyPair.spendKey.withUnsafeBytes { Data($0) }
        let view = keyPair.viewKey.withUnsafeBytes { Data($0) }
        XCTAssertNotEqual(spend, view, "Spend and view keys must differ (different domains).")
    }

    func testShortIdentityKeyThrows() async {
        let shortKey = SecureBytes(bytes: [0x01, 0x02, 0x03])

        do {
            _ = try await MobileCoinKeyPair.derive(from: shortKey, client: client)
            XCTFail("Should throw for identity key shorter than 32 bytes.")
        } catch let error as MobileCoinError {
            if case .identityKeyCorrupted = error {
                // Expected
            } else {
                XCTFail("Expected identityKeyCorrupted, got \(error)")
            }
        }
    }

    // MARK: - Mock SDK Validation

    func testMockSDKAccepts32ByteScalar() async {
        let validScalar = SecureBytes(bytes: Array(repeating: 0xFF, count: 32))
        let isValid = await client.isValidScalar(validScalar)
        XCTAssertTrue(isValid)
    }

    func testMockSDKRejectsNon32ByteScalar() async {
        let invalidScalar = SecureBytes(bytes: Array(repeating: 0xFF, count: 16))
        let isValid = await client.isValidScalar(invalidScalar)
        XCTAssertFalse(isValid)
    }
}
