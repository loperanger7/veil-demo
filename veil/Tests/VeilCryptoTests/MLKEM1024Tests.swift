// VEIL — MLKEM1024Tests.swift
// Tests for VEIL-102: ML-KEM-1024 Integration

import XCTest
@testable import VeilCrypto

final class MLKEM1024Tests: XCTestCase {

    // MARK: - Key Generation

    func testGenerate_producesCorrectKeySizes() throws {
        let keyPair = try MLKEM1024KeyPair.generate()
        XCTAssertEqual(keyPair.publicKey.count, VeilConstants.mlkem1024PublicKeySize)
    }

    func testGenerate_producesDifferentKeysEachTime() throws {
        let kp1 = try MLKEM1024KeyPair.generate()
        let kp2 = try MLKEM1024KeyPair.generate()
        XCTAssertNotEqual(kp1.publicKey, kp2.publicKey,
                          "Two independently generated key pairs must have different public keys")
    }

    // MARK: - Encapsulate / Decapsulate Round-Trip

    func testEncapsulateDecapsulate_roundTrip() throws {
        let keyPair = try MLKEM1024KeyPair.generate()

        // Encapsulate using the public key
        let result = try MLKEM1024KeyPair.encapsulate(recipientPublicKey: keyPair.publicKey)

        XCTAssertEqual(result.sharedSecret.count, VeilConstants.mlkem1024SharedSecretSize)
        XCTAssertEqual(result.ciphertext.count, VeilConstants.mlkem1024CiphertextSize)

        // Decapsulate using the secret key
        let decapsulated = try keyPair.decapsulate(ciphertext: result.ciphertext)

        XCTAssertEqual(decapsulated.count, VeilConstants.mlkem1024SharedSecretSize)
        XCTAssertEqual(result.sharedSecret, decapsulated,
                       "Encapsulated and decapsulated shared secrets must match")
    }

    func testEncapsulateDecapsulate_multipleRoundTrips() throws {
        // Verify correctness over 10 independent encapsulations with the same key pair
        let keyPair = try MLKEM1024KeyPair.generate()

        for i in 0..<10 {
            let result = try MLKEM1024KeyPair.encapsulate(recipientPublicKey: keyPair.publicKey)
            let decapsulated = try keyPair.decapsulate(ciphertext: result.ciphertext)
            XCTAssertEqual(result.sharedSecret, decapsulated,
                           "Round trip \(i) failed")
        }
    }

    // MARK: - Shared Secret Uniqueness

    func testEncapsulate_producesDifferentSharedSecretsEachTime() throws {
        let keyPair = try MLKEM1024KeyPair.generate()

        let result1 = try MLKEM1024KeyPair.encapsulate(recipientPublicKey: keyPair.publicKey)
        let result2 = try MLKEM1024KeyPair.encapsulate(recipientPublicKey: keyPair.publicKey)

        XCTAssertNotEqual(result1.ciphertext, result2.ciphertext,
                          "Two encapsulations must produce different ciphertexts")
        XCTAssertNotEqual(result1.sharedSecret, result2.sharedSecret,
                          "Two encapsulations must produce different shared secrets")
    }

    // MARK: - Error Handling

    func testEncapsulate_invalidPublicKeySize_throws() {
        let tooShort = Data(repeating: 0x42, count: 100)
        XCTAssertThrowsError(try MLKEM1024KeyPair.encapsulate(recipientPublicKey: tooShort)) { error in
            guard case VeilError.kemEncapsulationFailed = error else {
                XCTFail("Expected kemEncapsulationFailed, got \(error)")
                return
            }
        }
    }

    func testDecapsulate_invalidCiphertextSize_throws() throws {
        let keyPair = try MLKEM1024KeyPair.generate()
        let tooShort = Data(repeating: 0x42, count: 100)

        XCTAssertThrowsError(try keyPair.decapsulate(ciphertext: tooShort)) { error in
            guard case VeilError.kemDecapsulationFailed = error else {
                XCTFail("Expected kemDecapsulationFailed, got \(error)")
                return
            }
        }
    }

    // MARK: - Cross-Key Decapsulation

    func testDecapsulate_withWrongKey_producesDifferentSecret() throws {
        // ML-KEM is IND-CCA2: decapsulating with the wrong key should produce
        // an "implicit rejection" — a pseudorandom shared secret that differs
        // from the encapsulated one.
        let correctKey = try MLKEM1024KeyPair.generate()
        let wrongKey = try MLKEM1024KeyPair.generate()

        let result = try MLKEM1024KeyPair.encapsulate(recipientPublicKey: correctKey.publicKey)
        let wrongDecaps = try wrongKey.decapsulate(ciphertext: result.ciphertext)

        // The wrong key should NOT produce the same shared secret
        XCTAssertNotEqual(result.sharedSecret, wrongDecaps,
                          "Decapsulation with wrong key must not produce correct shared secret")
    }
}
