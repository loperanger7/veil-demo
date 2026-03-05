// VEIL — PQXDHTests.swift
// Tests for VEIL-104: PQXDH Key Agreement Protocol

import XCTest
import CryptoKit
@testable import VeilCrypto

final class PQXDHTests: XCTestCase {

    // MARK: - Helpers

    /// Create a mock prekey bundle for testing.
    private func createMockBundle() throws -> (
        bundle: PrekeyBundle,
        identityKey: Curve25519.KeyAgreement.PrivateKey,
        signedPrekey: Curve25519.KeyAgreement.PrivateKey,
        pqSignedPrekey: MLKEM1024KeyPair,
        opk: Curve25519.KeyAgreement.PrivateKey?,
        pqopk: MLKEM1024KeyPair?
    ) {
        // Bob's identity
        let bobIdentity = Curve25519.Signing.PrivateKey()
        let bobIdentityKA = Curve25519.KeyAgreement.PrivateKey()

        // Bob's signed prekey
        let bobSPK = Curve25519.KeyAgreement.PrivateKey()
        let spkSig = try bobIdentity.signature(for: bobSPK.publicKey.rawRepresentation)

        // Bob's PQ signed prekey
        let bobPQSPK = try MLKEM1024KeyPair.generate()
        let pqspkSig = try bobIdentity.signature(for: bobPQSPK.publicKey)

        // Bob's one-time prekeys
        let bobOPK = Curve25519.KeyAgreement.PrivateKey()
        let bobPQOPK = try MLKEM1024KeyPair.generate()

        let bundle = PrekeyBundle(
            identityKeyEd25519: bobIdentityKA.publicKey.rawRepresentation,
            identityKeyMLDSA: Data(repeating: 0, count: VeilConstants.mldsa65PublicKeySize),
            signedPrekeyId: 1,
            signedPrekey: bobSPK.publicKey.rawRepresentation,
            signedPrekeySig: spkSig.rawRepresentation,
            pqSignedPrekey: bobPQSPK.publicKey,
            pqSignedPrekeySig: pqspkSig.rawRepresentation,
            oneTimePrekeys: [OneTimePrekey(id: 1, publicKey: bobOPK.publicKey.rawRepresentation)],
            pqOneTimePrekeys: [PQOneTimePrekey(id: 1, publicKey: bobPQOPK.publicKey)]
        )

        return (bundle, bobIdentityKA, bobSPK, bobPQSPK, bobOPK, bobPQOPK)
    }

    // MARK: - Key Agreement

    func testPQXDH_initiatorAndResponder_deriveSameSessionKey() throws {
        let (bundle, bobIdentityKA, bobSPK, bobPQSPK, bobOPK, bobPQOPK) = try createMockBundle()

        // Alice initiates
        let aliceIdentity = Curve25519.KeyAgreement.PrivateKey()
        let aliceResult = try PQXDH.initiator(
            identityKey: aliceIdentity,
            bundle: bundle,
            initialPlaintext: Data("First message!".utf8)
        )

        // Bob responds
        let bobResult = try PQXDH.responder(
            identityKey: bobIdentityKA,
            signedPrekey: bobSPK,
            pqSignedPrekey: bobPQSPK,
            oneTimePrekey: bobOPK,
            pqOneTimePrekey: bobPQOPK,
            message: aliceResult.message
        )

        // Both must derive the same session key
        XCTAssertEqual(aliceResult.sessionKey, bobResult.sessionKey,
                       "Initiator and responder must derive the same session key")
        XCTAssertEqual(aliceResult.sessionKey.count, VeilConstants.sessionKeySize)
    }

    func testPQXDH_sessionKeyIsNotAllZeros() throws {
        let (bundle, _, _, _, _, _) = try createMockBundle()

        let aliceIdentity = Curve25519.KeyAgreement.PrivateKey()
        let result = try PQXDH.initiator(
            identityKey: aliceIdentity,
            bundle: bundle,
            initialPlaintext: Data("test".utf8)
        )

        let skData = try result.sessionKey.copyToData()
        XCTAssertNotEqual(skData, Data(repeating: 0, count: VeilConstants.sessionKeySize))
    }

    // MARK: - Without One-Time Prekeys

    func testPQXDH_withoutOneTimePrekeys_stillWorks() throws {
        let bobIdentity = Curve25519.Signing.PrivateKey()
        let bobIdentityKA = Curve25519.KeyAgreement.PrivateKey()
        let bobSPK = Curve25519.KeyAgreement.PrivateKey()
        let spkSig = try bobIdentity.signature(for: bobSPK.publicKey.rawRepresentation)
        let bobPQSPK = try MLKEM1024KeyPair.generate()
        let pqspkSig = try bobIdentity.signature(for: bobPQSPK.publicKey)

        let bundle = PrekeyBundle(
            identityKeyEd25519: bobIdentityKA.publicKey.rawRepresentation,
            identityKeyMLDSA: Data(repeating: 0, count: VeilConstants.mldsa65PublicKeySize),
            signedPrekeyId: 1,
            signedPrekey: bobSPK.publicKey.rawRepresentation,
            signedPrekeySig: spkSig.rawRepresentation,
            pqSignedPrekey: bobPQSPK.publicKey,
            pqSignedPrekeySig: pqspkSig.rawRepresentation,
            oneTimePrekeys: [],  // No OTPs available
            pqOneTimePrekeys: []
        )

        let aliceIdentity = Curve25519.KeyAgreement.PrivateKey()
        let aliceResult = try PQXDH.initiator(
            identityKey: aliceIdentity,
            bundle: bundle,
            initialPlaintext: Data("test".utf8)
        )

        let bobResult = try PQXDH.responder(
            identityKey: bobIdentityKA,
            signedPrekey: bobSPK,
            pqSignedPrekey: bobPQSPK,
            oneTimePrekey: nil,
            pqOneTimePrekey: nil,
            message: aliceResult.message
        )

        XCTAssertEqual(aliceResult.sessionKey, bobResult.sessionKey)
    }

    // MARK: - Signature Verification

    func testPQXDH_invalidSignature_aborts() throws {
        let bobIdentityKA = Curve25519.KeyAgreement.PrivateKey()
        let bobSPK = Curve25519.KeyAgreement.PrivateKey()
        let bobPQSPK = try MLKEM1024KeyPair.generate()

        // Invalid signatures (random bytes)
        let bundle = PrekeyBundle(
            identityKeyEd25519: bobIdentityKA.publicKey.rawRepresentation,
            identityKeyMLDSA: Data(repeating: 0, count: VeilConstants.mldsa65PublicKeySize),
            signedPrekeyId: 1,
            signedPrekey: bobSPK.publicKey.rawRepresentation,
            signedPrekeySig: Data(repeating: 0xBA, count: 64), // Bad signature
            pqSignedPrekey: bobPQSPK.publicKey,
            pqSignedPrekeySig: Data(repeating: 0xBA, count: 64), // Bad signature
            oneTimePrekeys: [],
            pqOneTimePrekeys: []
        )

        let aliceIdentity = Curve25519.KeyAgreement.PrivateKey()

        XCTAssertThrowsError(
            try PQXDH.initiator(
                identityKey: aliceIdentity,
                bundle: bundle,
                initialPlaintext: Data("test".utf8)
            )
        ) { error in
            XCTAssertEqual(error as? VeilError, VeilError.invalidPrekeySignature)
        }
    }

    // MARK: - Initiator Message Structure

    func testInitiatorMessage_containsExpectedFields() throws {
        let (bundle, _, _, _, _, _) = try createMockBundle()

        let aliceIdentity = Curve25519.KeyAgreement.PrivateKey()
        let result = try PQXDH.initiator(
            identityKey: aliceIdentity,
            bundle: bundle,
            initialPlaintext: Data("Hello Bob".utf8)
        )

        let msg = result.message
        XCTAssertEqual(msg.identityKey.count, 32)
        XCTAssertEqual(msg.ephemeralKey.count, 32)
        XCTAssertEqual(msg.pqCiphertext.count, VeilConstants.mlkem1024CiphertextSize)
        XCTAssertNotNil(msg.pqOneTimeCiphertext)
        XCTAssertFalse(msg.initialCiphertext.isEmpty)
    }
}
