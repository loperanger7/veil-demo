// VEIL — DHRatchetTests.swift
// Tests for VEIL-106: DH Ratchet (Classical)

import XCTest
import CryptoKit
@testable import VeilCrypto

final class DHRatchetTests: XCTestCase {

    // MARK: - Initialization

    func testInit_setsRootKeyAndEphemeral() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xAA, count: 32))
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()

        let ratchet = DHRatchet(rootKey: rootKey, ourEphemeralKey: ephemeral)

        XCTAssertEqual(ratchet.ratchetCount, 0)
        XCTAssertNil(ratchet.peerEphemeralKey)
        XCTAssertNil(ratchet.sendingChain)
        XCTAssertNil(ratchet.receivingChain)
    }

    func testInitWithPeerKey_establishesReceivingChain() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xAA, count: 32))
        let ourEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let peerEphemeral = Curve25519.KeyAgreement.PrivateKey()

        let ratchet = try DHRatchet(
            rootKey: rootKey,
            ourEphemeralKey: ourEphemeral,
            peerEphemeralKey: peerEphemeral.publicKey
        )

        XCTAssertNotNil(ratchet.receivingChain)
        XCTAssertNotNil(ratchet.peerEphemeralKey)
    }

    // MARK: - Ratchet Steps

    func testRatchetForSending_generatesNewEphemeral() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xBB, count: 32))
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let peer = Curve25519.KeyAgreement.PrivateKey()

        var ratchet = try DHRatchet(
            rootKey: rootKey,
            ourEphemeralKey: ephemeral,
            peerEphemeralKey: peer.publicKey
        )

        let originalEKPub = ratchet.ephemeralKeyPair.publicKey.rawRepresentation
        _ = try ratchet.ratchetForSending()
        let newEKPub = ratchet.ephemeralKeyPair.publicKey.rawRepresentation

        XCTAssertNotEqual(originalEKPub, newEKPub,
                          "DH ratchet step must generate a fresh ephemeral key")
    }

    func testRatchetForSending_createsSendingChain() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xCC, count: 32))
        var ratchet = DHRatchet(
            rootKey: rootKey,
            ourEphemeralKey: Curve25519.KeyAgreement.PrivateKey()
        )

        _ = try ratchet.ratchetForSending()
        XCTAssertNotNil(ratchet.sendingChain)
        XCTAssertEqual(ratchet.ratchetCount, 1)
    }

    func testRatchetForReceiving_createsReceivingChain() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xDD, count: 32))
        let peer = Curve25519.KeyAgreement.PrivateKey()

        var ratchet = DHRatchet(
            rootKey: rootKey,
            ourEphemeralKey: Curve25519.KeyAgreement.PrivateKey()
        )

        try ratchet.ratchetForReceiving(peerPublicKey: peer.publicKey.rawRepresentation)

        XCTAssertNotNil(ratchet.receivingChain)
        XCTAssertNotNil(ratchet.peerEphemeralKey)
        XCTAssertEqual(ratchet.ratchetCount, 1)
    }

    // MARK: - Root Key Evolution

    func testRatchetSteps_changeRootKey() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xEE, count: 32))
        let peer = Curve25519.KeyAgreement.PrivateKey()

        var ratchet = try DHRatchet(
            rootKey: rootKey,
            ourEphemeralKey: Curve25519.KeyAgreement.PrivateKey(),
            peerEphemeralKey: peer.publicKey
        )

        let rk1 = try ratchet.rootKey.copyToData()
        _ = try ratchet.ratchetForSending()
        let rk2 = try ratchet.rootKey.copyToData()

        XCTAssertNotEqual(rk1, rk2, "DH ratchet step must change the root key")
    }

    // MARK: - Message Key Derivation

    func testNextSendingKey_producesValidKey() throws {
        let rootKey = SecureBytes(bytes: Array(repeating: 0xFF, count: 32))
        let peer = Curve25519.KeyAgreement.PrivateKey()

        var ratchet = try DHRatchet(
            rootKey: rootKey,
            ourEphemeralKey: Curve25519.KeyAgreement.PrivateKey(),
            peerEphemeralKey: peer.publicKey
        )

        let mk = try ratchet.nextSendingKey()
        XCTAssertEqual(mk.count, 32)
    }
}
