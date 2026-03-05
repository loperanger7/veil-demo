// SubaddressDeriverTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// VEIL-402: Tests for recipient address derivation.

import XCTest
@testable import VeilCrypto

final class SubaddressDeriverTests: XCTestCase {

    private var client: MobileCoinClient!
    private var deriver: SubaddressDeriver!

    override func setUp() async throws {
        client = MobileCoinClient(sdk: MockMobileCoinSDK())
        deriver = SubaddressDeriver(client: client)
    }

    // MARK: - Address Derivation

    func testDeriveRecipientAddressProducesNonEmpty() async throws {
        let peerKey = Data(repeating: 0x42, count: 32)
        let address = try await deriver.deriveRecipientAddress(
            peerIdentityPublicKey: peerKey
        )

        XCTAssertFalse(address.address.isEmpty, "Derived address must not be empty.")
        XCTAssertEqual(address.subaddressIndex, 0, "Default subaddress index should be 0.")
    }

    func testDeriveIsDeterministic() async throws {
        let peerKey = Data(repeating: 0xAB, count: 32)

        let addr1 = try await deriver.deriveRecipientAddress(peerIdentityPublicKey: peerKey)
        let addr2 = try await deriver.deriveRecipientAddress(peerIdentityPublicKey: peerKey)

        XCTAssertEqual(addr1.address, addr2.address,
                        "Same peer key must produce same address.")
    }

    func testDifferentPeersProduceDifferentAddresses() async throws {
        let peer1 = Data(repeating: 0x01, count: 32)
        let peer2 = Data(repeating: 0x02, count: 32)

        let addr1 = try await deriver.deriveRecipientAddress(peerIdentityPublicKey: peer1)
        let addr2 = try await deriver.deriveRecipientAddress(peerIdentityPublicKey: peer2)

        XCTAssertNotEqual(addr1.address, addr2.address,
                          "Different peers must have different addresses.")
    }

    func testDifferentSubaddressIndicesProduceDifferentAddresses() async throws {
        let peerKey = Data(repeating: 0x55, count: 32)

        let addr0 = try await deriver.deriveRecipientAddress(
            peerIdentityPublicKey: peerKey,
            subaddressIndex: 0
        )
        let addr1 = try await deriver.deriveRecipientAddress(
            peerIdentityPublicKey: peerKey,
            subaddressIndex: 1
        )

        XCTAssertNotEqual(addr0.address, addr1.address,
                          "Different subaddress indices must yield different addresses.")
    }

    func testShortPeerKeyThrows() async {
        let shortKey = Data(repeating: 0x01, count: 16)

        do {
            _ = try await deriver.deriveRecipientAddress(peerIdentityPublicKey: shortKey)
            XCTFail("Should throw for peer key shorter than 32 bytes.")
        } catch let error as MobileCoinError {
            XCTAssertEqual(error, .invalidPeerIdentityKey)
        }
    }

    // MARK: - Self Address

    func testDeriveSelfAddress() async throws {
        let identityKey = SecureBytes(bytes: Array(repeating: 0x42, count: 32))
        let keyPair = try await MobileCoinKeyPair.derive(from: identityKey, client: client)

        let selfAddr = try await deriver.deriveSelfAddress(keyPair: keyPair)

        XCTAssertFalse(selfAddr.address.isEmpty)
        XCTAssertEqual(selfAddr.subaddressIndex, 0)
    }

    // MARK: - Verification

    func testVerifyRecipientAddressMatches() async throws {
        let peerKey = Data(repeating: 0x99, count: 32)

        let derived = try await deriver.deriveRecipientAddress(
            peerIdentityPublicKey: peerKey
        )
        let matches = try await deriver.verifyRecipientAddress(
            peerIdentityPublicKey: peerKey,
            expectedAddress: derived.address
        )

        XCTAssertTrue(matches, "Verification must pass for correctly derived address.")
    }

    func testVerifyRecipientAddressRejectsMismatch() async throws {
        let peerKey = Data(repeating: 0x99, count: 32)
        let wrongAddress = Data(repeating: 0x00, count: 32)

        let matches = try await deriver.verifyRecipientAddress(
            peerIdentityPublicKey: peerKey,
            expectedAddress: wrongAddress
        )

        XCTAssertFalse(matches, "Verification must fail for wrong address.")
    }
}
