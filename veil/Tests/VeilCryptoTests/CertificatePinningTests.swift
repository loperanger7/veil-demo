// VEIL — Certificate Pinning Tests
// Ticket: VEIL-601 — TLS 1.3 with Certificate Pinning
// Epic: 6 — Network & Transport Layer

import XCTest
@testable import VeilCrypto

final class CertificatePinningTests: XCTestCase {

    // MARK: - CertificatePin

    func testPinFromSHA256Hash() {
        let hash = Data(repeating: 0xAB, count: 32)
        let pin = CertificatePin(sha256Hash: hash)
        XCTAssertEqual(pin.sha256Hash, hash)
    }

    func testPinFromHexString() {
        let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        let pin = CertificatePin(hexString: hex)
        XCTAssertEqual(pin.sha256Hash.count, 32)
        XCTAssertEqual(pin.hexString, hex)
    }

    func testPinEquality() {
        let hash = Data(repeating: 0x42, count: 32)
        let pin1 = CertificatePin(sha256Hash: hash)
        let pin2 = CertificatePin(sha256Hash: hash)
        XCTAssertEqual(pin1, pin2)
    }

    func testPinInequality() {
        let pin1 = CertificatePin(sha256Hash: Data(repeating: 0x01, count: 32))
        let pin2 = CertificatePin(sha256Hash: Data(repeating: 0x02, count: 32))
        XCTAssertNotEqual(pin1, pin2)
    }

    func testPinHexRoundTrip() {
        let original = CertificatePin(sha256Hash: Data(repeating: 0xDE, count: 32))
        let reconstructed = CertificatePin(hexString: original.hexString)
        XCTAssertEqual(original, reconstructed)
    }

    // MARK: - PinningConfiguration

    func testDevelopmentConfigNotEnforced() {
        let config = PinningConfiguration.development(hostname: "localhost")
        XCTAssertFalse(config.enforced)
        XCTAssertTrue(config.pins.isEmpty)
        XCTAssertEqual(config.hostname, "localhost")
    }

    func testProductionConfigEnforced() {
        let pin = CertificatePin(sha256Hash: Data(repeating: 0xFF, count: 32))
        let config = PinningConfiguration(pins: [pin], hostname: "relay.veil.app")
        XCTAssertTrue(config.enforced)
        XCTAssertEqual(config.pins.count, 1)
    }

    // MARK: - PinRotationState

    func testInitialRotationStateHasNoPins() {
        let pin = CertificatePin(sha256Hash: Data(repeating: 0x01, count: 32))
        let state = PinRotationState(currentPins: [pin])
        XCTAssertEqual(state.acceptablePins, [pin])
        XCTAssertFalse(state.isInGracePeriod)
    }

    func testRotationAddsGracePeriodPins() {
        let oldPin = CertificatePin(sha256Hash: Data(repeating: 0x01, count: 32))
        let newPin = CertificatePin(sha256Hash: Data(repeating: 0x02, count: 32))

        let initial = PinRotationState(currentPins: [oldPin])
        let rotated = initial.rotate(to: [newPin])

        // Both old and new pins should be acceptable during grace period
        XCTAssertTrue(rotated.acceptablePins.contains(oldPin))
        XCTAssertTrue(rotated.acceptablePins.contains(newPin))
        XCTAssertTrue(rotated.isInGracePeriod)
    }

    func testExpiredGracePeriodOnlyAcceptsNewPins() {
        let oldPin = CertificatePin(sha256Hash: Data(repeating: 0x01, count: 32))
        let newPin = CertificatePin(sha256Hash: Data(repeating: 0x02, count: 32))

        let state = PinRotationState(
            currentPins: [newPin],
            gracePeriodPins: [oldPin],
            gracePeriodStarted: Date().addingTimeInterval(-700000), // ~8 days ago
            gracePeriodDuration: 604800 // 7 days
        )

        // Grace period expired: only new pin accepted
        XCTAssertTrue(state.acceptablePins.contains(newPin))
        XCTAssertFalse(state.acceptablePins.contains(oldPin))
        XCTAssertFalse(state.isInGracePeriod)
    }

    // MARK: - VeilTLSDelegate

    func testDelegateAppliesRotation() {
        let config = PinningConfiguration.development(hostname: "localhost")
        let delegate = VeilTLSDelegate(configuration: config)

        let newPin = CertificatePin(sha256Hash: Data(repeating: 0xAA, count: 32))
        delegate.applyRotation(newPins: [newPin])

        let state = delegate.rotationState
        XCTAssertTrue(state.acceptablePins.contains(newPin))
    }

    func testDelegateAppliesRotationFromPayload() {
        let config = PinningConfiguration.development(hostname: "localhost")
        let delegate = VeilTLSDelegate(configuration: config)

        let payload = PinRotationPayload(
            pinHashes: ["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"],
            hostname: "relay.veil.app",
            gracePeriodSeconds: 86400
        )

        delegate.applyRotation(from: payload)

        let state = delegate.rotationState
        XCTAssertEqual(state.currentPins.count, 1)
        XCTAssertTrue(state.isInGracePeriod) // Old pins in grace period
    }

    func testComputePinHash() {
        let certData = Data(repeating: 0x42, count: 256)
        let pin = VeilTLSDelegate.computePinHash(derEncodedCertificate: certData)
        XCTAssertEqual(pin.sha256Hash.count, 32)
    }

    // MARK: - Pin Validation Failure Callback

    func testPinValidationFailureCallback() {
        let pin = CertificatePin(sha256Hash: Data(repeating: 0xFF, count: 32))
        let config = PinningConfiguration(pins: [pin], hostname: "relay.veil.app")
        let delegate = VeilTLSDelegate(configuration: config)

        var callbackInvoked = false
        delegate.onPinValidationFailure = { host, hash in
            callbackInvoked = true
            XCTAssertEqual(host, "relay.veil.app")
            XCTAssertEqual(hash.count, 32)
        }

        // We can't directly trigger the callback without a real URLSession challenge,
        // but we verify the callback is assignable and the delegate initializes correctly.
        XCTAssertNotNil(delegate.onPinValidationFailure)
        // In integration tests, we'd use a mock server with the wrong cert.
    }
}
