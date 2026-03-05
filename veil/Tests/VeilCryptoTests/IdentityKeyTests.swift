// VEIL — IdentityKeyTests.swift
// Tests for VEIL-101: Hybrid Identity Key Generation

import XCTest
import CryptoKit
@testable import VeilCrypto

final class IdentityKeyTests: XCTestCase {

    // MARK: - Key Generation

    func testGenerateIdentityKey_producesValidKeys() async throws {
        let enclave = SecureEnclaveManager()
        let identity = try await IdentityKeyPair.generate(enclave: enclave)

        XCTAssertEqual(identity.ed25519PublicKey.count, VeilConstants.ed25519PublicKeySize)
        XCTAssertEqual(identity.mldsaPublicKey.count, VeilConstants.mldsa65PublicKeySize)
    }

    func testGenerateIdentityKey_producesUniqueKeys() async throws {
        let enclave1 = SecureEnclaveManager()
        let enclave2 = SecureEnclaveManager()

        let identity1 = try await IdentityKeyPair.generate(enclave: enclave1)
        let identity2 = try await IdentityKeyPair.generate(enclave: enclave2)

        XCTAssertNotEqual(identity1.ed25519PublicKey, identity2.ed25519PublicKey)
        XCTAssertNotEqual(identity1.mldsaPublicKey, identity2.mldsaPublicKey)
    }

    // MARK: - Hybrid Signing & Verification

    func testSignAndVerify_validSignature() async throws {
        let enclave = SecureEnclaveManager()
        let identity = try await IdentityKeyPair.generate(enclave: enclave)

        let message = Data("Hello, post-quantum world!".utf8)
        let signature = try await identity.sign(message)

        let isValid = IdentityKeyPair.verify(
            signature: signature,
            data: message,
            ed25519PublicKey: identity.ed25519PublicKey,
            mldsaPublicKey: identity.mldsaPublicKey
        )

        XCTAssertTrue(isValid, "Valid signature must verify")
    }

    func testVerify_tamperedMessage_fails() async throws {
        let enclave = SecureEnclaveManager()
        let identity = try await IdentityKeyPair.generate(enclave: enclave)

        let message = Data("Original message".utf8)
        let signature = try await identity.sign(message)

        let tamperedMessage = Data("Tampered message".utf8)
        let isValid = IdentityKeyPair.verify(
            signature: signature,
            data: tamperedMessage,
            ed25519PublicKey: identity.ed25519PublicKey,
            mldsaPublicKey: identity.mldsaPublicKey
        )

        XCTAssertFalse(isValid, "Tampered message must not verify")
    }

    func testVerify_wrongEd25519Key_fails() async throws {
        let enclave1 = SecureEnclaveManager()
        let enclave2 = SecureEnclaveManager()
        let identity = try await IdentityKeyPair.generate(enclave: enclave1)
        let otherIdentity = try await IdentityKeyPair.generate(enclave: enclave2)

        let message = Data("Test".utf8)
        let signature = try await identity.sign(message)

        // Use wrong Ed25519 key but correct ML-DSA key
        let isValid = IdentityKeyPair.verify(
            signature: signature,
            data: message,
            ed25519PublicKey: otherIdentity.ed25519PublicKey,
            mldsaPublicKey: identity.mldsaPublicKey
        )

        XCTAssertFalse(isValid, "Wrong Ed25519 key must fail verification")
    }

    func testVerify_wrongMLDSAKey_fails() async throws {
        let enclave1 = SecureEnclaveManager()
        let enclave2 = SecureEnclaveManager()
        let identity = try await IdentityKeyPair.generate(enclave: enclave1)
        let otherIdentity = try await IdentityKeyPair.generate(enclave: enclave2)

        let message = Data("Test".utf8)
        let signature = try await identity.sign(message)

        // Use correct Ed25519 key but wrong ML-DSA key
        let isValid = IdentityKeyPair.verify(
            signature: signature,
            data: message,
            ed25519PublicKey: identity.ed25519PublicKey,
            mldsaPublicKey: otherIdentity.mldsaPublicKey
        )

        XCTAssertFalse(isValid, "Wrong ML-DSA-65 key must fail verification — hybrid guarantee")
    }

    // MARK: - Hybrid Signature Serialization

    func testHybridSignature_roundTripSerialization() async throws {
        let enclave = SecureEnclaveManager()
        let identity = try await IdentityKeyPair.generate(enclave: enclave)

        let message = Data("Serialize me".utf8)
        let signature = try await identity.sign(message)

        let serialized = signature.serialized
        guard let deserialized = HybridSignature.deserialize(from: serialized) else {
            XCTFail("Deserialization must not return nil")
            return
        }

        XCTAssertEqual(deserialized.ed25519Signature, signature.ed25519Signature)
        XCTAssertEqual(deserialized.mldsaSignature, signature.mldsaSignature)
    }

    // MARK: - Secure Enclave Manager

    func testSecureEnclaveManager_signVerify() async throws {
        let enclave = SecureEnclaveManager()
        let key = try await enclave.generateIdentityKey()

        let data = Data("Enclave signing test".utf8)
        let signature = try await enclave.sign(data)

        let isValid = SecureEnclaveManager.verify(
            signature: signature,
            data: data,
            publicKey: key.publicKey
        )

        XCTAssertTrue(isValid)
    }

    func testSecureEnclaveManager_deriveSubkey() async throws {
        let enclave = SecureEnclaveManager()
        _ = try await enclave.generateIdentityKey()

        let spendKey = try await enclave.deriveSubkey(domain: .mobSpendKey)
        let viewKey = try await enclave.deriveSubkey(domain: .mobViewKey)

        XCTAssertEqual(spendKey.count, 32)
        XCTAssertEqual(viewKey.count, 32)
        XCTAssertNotEqual(spendKey, viewKey, "Different domains must produce different keys")
    }
}
