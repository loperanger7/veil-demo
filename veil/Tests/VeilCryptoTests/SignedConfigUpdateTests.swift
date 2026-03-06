// VEIL — Signed Configuration Update Tests
// Tickets: VEIL-601 (pin rotation), VEIL-603 (fronting config)
// Epic: 6 — Network & Transport Layer

import XCTest
import CryptoKit
@testable import VeilCrypto

final class SignedConfigUpdateTests: XCTestCase {

    // MARK: - Helpers

    private func makeSigner() -> ConfigurationUpdateSigner {
        ConfigurationUpdateSigner()
    }

    private func makeVerifier(publicKey: Data, currentVersion: UInt64 = 0) throws -> ConfigurationUpdateVerifier {
        try ConfigurationUpdateVerifier(trustedPublicKeyBytes: publicKey, currentVersion: currentVersion)
    }

    // MARK: - SignedConfigurationUpdate Codable

    func testSignedUpdateCodable() throws {
        let signer = makeSigner()
        let update = try signer.sign(version: 1, payload: Data("test".utf8))

        let data = try JSONEncoder().encode(update)
        let decoded = try JSONDecoder().decode(SignedConfigurationUpdate.self, from: data)

        XCTAssertEqual(decoded.version, update.version)
        XCTAssertEqual(decoded.payload, update.payload)
        XCTAssertEqual(decoded.signature, update.signature)
    }

    // MARK: - Signature Verification

    func testValidSignatureAccepted() throws {
        let signer = makeSigner()
        let update = try signer.sign(version: 1, payload: Data("config payload".utf8))

        var verifier = try makeVerifier(publicKey: signer.publicKey)
        let payload = try verifier.verify(update)

        XCTAssertEqual(payload, Data("config payload".utf8))
        XCTAssertEqual(verifier.appliedVersion, 1)
    }

    func testTamperedPayloadRejected() throws {
        let signer = makeSigner()
        var update = try signer.sign(version: 1, payload: Data("original".utf8))

        // Tamper with the payload
        update = SignedConfigurationUpdate(
            version: update.version,
            issuedAt: update.issuedAt,
            expiresAt: update.expiresAt,
            payload: Data("tampered".utf8),
            signature: update.signature
        )

        var verifier = try makeVerifier(publicKey: signer.publicKey)
        XCTAssertThrowsError(try verifier.verify(update)) { error in
            guard case NetworkTransportError.invalidPinRotationSignature = error as? NetworkTransportError else {
                XCTFail("Expected invalidPinRotationSignature"); return
            }
        }
    }

    func testWrongPublicKeyRejected() throws {
        let signer = makeSigner()
        let wrongSigner = makeSigner() // Different key pair
        let update = try signer.sign(version: 1, payload: Data("test".utf8))

        var verifier = try makeVerifier(publicKey: wrongSigner.publicKey)
        XCTAssertThrowsError(try verifier.verify(update)) { error in
            guard case NetworkTransportError.invalidPinRotationSignature = error as? NetworkTransportError else {
                XCTFail("Expected invalidPinRotationSignature"); return
            }
        }
    }

    // MARK: - Version Rollback Prevention

    func testVersionRollbackRejected() throws {
        let signer = makeSigner()
        let update1 = try signer.sign(version: 5, payload: Data("v5".utf8))
        let update2 = try signer.sign(version: 3, payload: Data("v3".utf8))

        var verifier = try makeVerifier(publicKey: signer.publicKey)
        _ = try verifier.verify(update1)
        XCTAssertEqual(verifier.appliedVersion, 5)

        XCTAssertThrowsError(try verifier.verify(update2)) { error in
            guard case NetworkTransportError.pinRotationVersionRollback(let current, let received) = error as? NetworkTransportError else {
                XCTFail("Expected pinRotationVersionRollback"); return
            }
            XCTAssertEqual(current, 5)
            XCTAssertEqual(received, 3)
        }
    }

    func testSameVersionRejected() throws {
        let signer = makeSigner()
        let update1 = try signer.sign(version: 1, payload: Data("first".utf8))
        let update2 = try signer.sign(version: 1, payload: Data("second".utf8))

        var verifier = try makeVerifier(publicKey: signer.publicKey)
        _ = try verifier.verify(update1)
        XCTAssertThrowsError(try verifier.verify(update2))
    }

    func testMonotonicallyIncreasingVersionsAccepted() throws {
        let signer = makeSigner()
        var verifier = try makeVerifier(publicKey: signer.publicKey)

        for version in 1...5 as ClosedRange<UInt64> {
            let update = try signer.sign(version: version, payload: Data("v\(version)".utf8))
            let payload = try verifier.verify(update)
            XCTAssertEqual(payload, Data("v\(version)".utf8))
        }
        XCTAssertEqual(verifier.appliedVersion, 5)
    }

    // MARK: - Timestamp Validation

    func testExpiredUpdateRejected() throws {
        let signer = makeSigner()
        let update = try signer.sign(
            version: 1,
            issuedAt: Date().addingTimeInterval(-86400), // Yesterday
            expiresAt: Date().addingTimeInterval(-3600),  // Expired 1 hour ago
            payload: Data("expired".utf8)
        )

        var verifier = try makeVerifier(publicKey: signer.publicKey)
        XCTAssertThrowsError(try verifier.verify(update)) { error in
            guard case NetworkTransportError.configurationUpdateExpired = error as? NetworkTransportError else {
                XCTFail("Expected configurationUpdateExpired"); return
            }
        }
    }

    func testFutureIssuedAtRejected() throws {
        let signer = makeSigner()
        let update = try signer.sign(
            version: 1,
            issuedAt: Date().addingTimeInterval(3600), // 1 hour in the future
            expiresAt: Date().addingTimeInterval(86400),
            payload: Data("future".utf8)
        )

        // With 5-minute tolerance, 1 hour in the future should fail
        var verifier = try makeVerifier(publicKey: signer.publicKey)
        XCTAssertThrowsError(try verifier.verify(update)) { error in
            guard case NetworkTransportError.configurationTimestampInvalid = error as? NetworkTransportError else {
                XCTFail("Expected configurationTimestampInvalid"); return
            }
        }
    }

    func testSlightClockSkewAccepted() throws {
        let signer = makeSigner()
        // 2 minutes in the future — within 5-minute tolerance
        let update = try signer.sign(
            version: 1,
            issuedAt: Date().addingTimeInterval(120),
            expiresAt: Date().addingTimeInterval(86400),
            payload: Data("slight skew".utf8)
        )

        var verifier = try makeVerifier(publicKey: signer.publicKey)
        let payload = try verifier.verify(update)
        XCTAssertEqual(payload, Data("slight skew".utf8))
    }

    // MARK: - PinRotationPayload

    func testPinRotationPayloadCodable() throws {
        let payload = PinRotationPayload(
            pinHashes: [
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            ],
            hostname: "relay.veil.app",
            gracePeriodSeconds: 604800
        )

        let data = try payload.encode()
        let decoded = try PinRotationPayload.decode(from: data)

        XCTAssertEqual(decoded.pinHashes.count, 2)
        XCTAssertEqual(decoded.hostname, "relay.veil.app")
        XCTAssertEqual(decoded.gracePeriodSeconds, 604800)
    }

    func testPinRotationPayloadToCertificatePins() {
        let payload = PinRotationPayload(
            pinHashes: ["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"],
            hostname: "relay.veil.app"
        )
        let pins = payload.certificatePins
        XCTAssertEqual(pins.count, 1)
        XCTAssertEqual(pins.first?.sha256Hash.count, 32)
    }

    // MARK: - Build Signed Data

    func testBuildSignedDataDeterministic() {
        let date1 = Date(timeIntervalSince1970: 1000000)
        let date2 = Date(timeIntervalSince1970: 2000000)
        let payload = Data("test".utf8)

        let data1 = ConfigurationUpdateVerifier.buildSignedData(
            version: 1, issuedAt: date1, expiresAt: date2, payload: payload
        )
        let data2 = ConfigurationUpdateVerifier.buildSignedData(
            version: 1, issuedAt: date1, expiresAt: date2, payload: payload
        )
        XCTAssertEqual(data1, data2)
    }

    func testBuildSignedDataDifferentVersionsDiffer() {
        let date1 = Date(timeIntervalSince1970: 1000000)
        let date2 = Date(timeIntervalSince1970: 2000000)
        let payload = Data("test".utf8)

        let data1 = ConfigurationUpdateVerifier.buildSignedData(
            version: 1, issuedAt: date1, expiresAt: date2, payload: payload
        )
        let data2 = ConfigurationUpdateVerifier.buildSignedData(
            version: 2, issuedAt: date1, expiresAt: date2, payload: payload
        )
        XCTAssertNotEqual(data1, data2)
    }
}
