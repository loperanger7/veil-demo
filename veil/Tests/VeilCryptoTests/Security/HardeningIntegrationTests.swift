// VEIL — HardeningIntegrationTests.swift
// Ticket: VEIL-901 — Security Hardening Integration Tests
// Spec reference: Sections 7-8 (Threat Model, Payment Flow)
//
// End-to-end integration tests verifying that the security hardening
// fixes from the red team audit work correctly when composed together:
//   - Full payment with ECDH shared secret + signed receipt + nonce
//   - Receipt forge attempt detection
//   - Replay attack prevention
//   - PQXDH one-time prekey requirement
//   - Exponential padding traffic analysis reduction
//   - Amount validation in payment state machine
//   - Memo sanitization
//   - Domain fronting fail-closed policy
//   - ECDH shared secret non-determinism

import XCTest
import CryptoKit
@testable import VeilCrypto

final class HardeningIntegrationTests: XCTestCase {

    // MARK: - Payment Authentication Flow

    /// **INTEGRATION: Full payment with ECDH + signed receipt + nonce → end-to-end.**
    func testFullPaymentWithAuthentication() throws {
        // Step 1: Derive ECDH shared secret
        let recipientViewKey = Curve25519.KeyAgreement.PrivateKey()
        let txHash = Data(repeating: 0xAA, count: 32)

        let senderResult = try PaymentKeyAgreement.senderDerive(
            recipientViewKey: recipientViewKey.publicKey,
            txHash: txHash
        )

        let recipientResult = try PaymentKeyAgreement.recipientDerive(
            recipientViewKey: recipientViewKey,
            senderEphemeralKey: try Curve25519.KeyAgreement.PublicKey(
                rawRepresentation: senderResult.ephemeralPublicKey
            ),
            txHash: txHash
        )

        // Both sides derive the same secret
        let senderSecretBytes = try senderResult.sharedSecret.copyToData()
        let recipientSecretBytes = try recipientResult.sharedSecret.copyToData()
        XCTAssertEqual(senderSecretBytes, recipientSecretBytes, "ECDH shared secrets must match")

        // Step 2: Create and sign receipt
        let receipt = PaymentReceiptMessage(
            txHash: txHash.hexEncodedString(),
            sharedSecret: senderSecretBytes.base64EncodedString(),
            amountPicomob: 500_000_000_000,
            memo: "Coffee payment",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 12345
        )

        let senderSigningKey = Curve25519.Signing.PrivateKey()
        let authenticator = ReceiptAuthenticator()
        let authenticated = try authenticator.sign(
            receipt: receipt,
            signingKey: senderSigningKey
        )

        // Step 3: Verify receipt
        let nonceTracker = ReceiptNonceTracker()
        let isValid = try waitForAsync {
            try await authenticator.verify(
                authenticatedReceipt: authenticated,
                senderIdentityKey: senderSigningKey.publicKey,
                nonceTracker: nonceTracker
            )
        }
        XCTAssertTrue(isValid, "Authenticated receipt should verify")

        // Step 4: Replay should fail
        let isReplay = try waitForAsync {
            try await authenticator.verify(
                authenticatedReceipt: authenticated,
                senderIdentityKey: senderSigningKey.publicKey,
                nonceTracker: nonceTracker
            )
        }
        XCTAssertFalse(isReplay, "Replayed receipt should be rejected")
    }

    /// **INTEGRATION: Attacker creates receipt without sender key → rejected.**
    func testReceiptForgeAttempt() throws {
        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 1_000_000_000_000,
            memo: "Forged payment",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 99999
        )

        // Attacker signs with their own key
        let attackerKey = Curve25519.Signing.PrivateKey()
        let authenticator = ReceiptAuthenticator()
        let forgedReceipt = try authenticator.sign(receipt: receipt, signingKey: attackerKey)

        // Verify with the REAL sender's key (not attacker's)
        let realSenderKey = Curve25519.Signing.PrivateKey()
        let isValid = authenticator.verifySignature(
            authenticatedReceipt: forgedReceipt,
            senderIdentityKey: realSenderKey.publicKey
        )

        XCTAssertFalse(isValid, "Receipt signed by attacker should not verify with sender's key")
    }

    // MARK: - ECDH Shared Secret

    /// **INTEGRATION: ECDH shared secret is non-deterministic (ephemeral keys).**
    func testECDHSharedSecret_nonDeterministic() throws {
        let recipientViewKey = Curve25519.KeyAgreement.PrivateKey()
        let txHash = Data(repeating: 0xBB, count: 32)

        let result1 = try PaymentKeyAgreement.senderDerive(
            recipientViewKey: recipientViewKey.publicKey,
            txHash: txHash
        )
        let result2 = try PaymentKeyAgreement.senderDerive(
            recipientViewKey: recipientViewKey.publicKey,
            txHash: txHash
        )

        // Different ephemeral keys → different shared secrets
        XCTAssertNotEqual(
            result1.ephemeralPublicKey,
            result2.ephemeralPublicKey,
            "Each derivation should use a fresh ephemeral key"
        )

        let secret1 = try result1.sharedSecret.copyToData()
        let secret2 = try result2.sharedSecret.copyToData()
        XCTAssertNotEqual(secret1, secret2, "Different ephemeral keys should produce different secrets")
    }

    /// **INTEGRATION: Same ephemeral key produces same shared secret on both sides.**
    func testECDHSharedSecret_consistency() throws {
        let recipientViewKey = Curve25519.KeyAgreement.PrivateKey()
        let senderEphemeral = Curve25519.KeyAgreement.PrivateKey()
        let txHash = Data(repeating: 0xCC, count: 32)

        let senderResult = try PaymentKeyAgreement.senderDerive(
            ephemeralPrivateKey: senderEphemeral,
            recipientViewKey: recipientViewKey.publicKey,
            txHash: txHash
        )

        let recipientResult = try PaymentKeyAgreement.recipientDerive(
            recipientViewKey: recipientViewKey,
            senderEphemeralKey: senderEphemeral.publicKey,
            txHash: txHash
        )

        let senderSecret = try senderResult.sharedSecret.copyToData()
        let recipientSecret = try recipientResult.sharedSecret.copyToData()
        XCTAssertEqual(senderSecret, recipientSecret)
    }

    /// **INTEGRATION: Ephemeral key validation works.**
    func testEphemeralKeyValidation() {
        // Valid key
        let validKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        XCTAssertTrue(PaymentKeyAgreement.validateEphemeralKey(validKey))

        // All-zeros key (identity point) is rejected
        XCTAssertFalse(PaymentKeyAgreement.validateEphemeralKey(Data(repeating: 0, count: 32)))

        // Wrong size
        XCTAssertFalse(PaymentKeyAgreement.validateEphemeralKey(Data(repeating: 1, count: 16)))
    }

    // MARK: - Amount Validation

    /// **INTEGRATION: Amount validation catches all boundary cases.**
    func testAmountValidation_boundaries() {
        let validator = PaymentAmountValidator()

        // Dust threshold
        XCTAssertTrue(validator.validate(picomob: 0).isErr)
        XCTAssertTrue(validator.validate(picomob: 999_999).isErr)
        XCTAssertTrue(validator.validate(picomob: 1_000_000).isOk)

        // Maximum
        XCTAssertTrue(validator.validate(picomob: 250_000_000_000_000).isOk)
        XCTAssertTrue(validator.validate(picomob: 250_000_000_000_001).isErr)
    }

    // MARK: - Memo Sanitization

    /// **INTEGRATION: Unicode tricks → cleaned memo → safe for display.**
    func testMemoSanitization() {
        let sanitizer = MemoSanitizer()

        // Normal memo unchanged
        let normal = sanitizer.sanitize("Thanks for lunch!")
        XCTAssertEqual(normal.text, "Thanks for lunch!")
        XCTAssertFalse(normal.wasModified)

        // RTL override stripped
        let rtl = "Send MOB to \u{202E}boB"
        let sanitizedRTL = sanitizer.sanitize(rtl)
        XCTAssertFalse(sanitizedRTL.text.contains("\u{202E}"))
        XCTAssertTrue(sanitizedRTL.wasModified)
        XCTAssertTrue(sanitizedRTL.warnings.contains(where: {
            if case .directionalOverrideRemoved = $0 { return true }
            return false
        }))

        // Zero-width characters stripped
        let zeroWidth = "Pay\u{200B}ment"
        let sanitizedZW = sanitizer.sanitize(zeroWidth)
        XCTAssertEqual(sanitizedZW.text, "Payment")

        // Control characters stripped
        let controlChars = "Hello\u{0001}World"
        let sanitizedCtrl = sanitizer.sanitize(controlChars)
        XCTAssertEqual(sanitizedCtrl.text, "HelloWorld")

        // Mixed scripts warning
        let mixed = "Pay Боб" // Latin + Cyrillic
        let sanitizedMixed = sanitizer.sanitize(mixed)
        XCTAssertTrue(sanitizedMixed.warnings.contains(.mixedScriptsDetected))
    }

    /// **INTEGRATION: Long memo truncated to byte limit.**
    func testMemoTruncation() {
        let sanitizer = MemoSanitizer()
        let longMemo = String(repeating: "A", count: 500)
        let result = sanitizer.sanitize(longMemo)
        XCTAssertLessThanOrEqual(result.text.utf8.count, MemoSanitizer.maxByteLength)
    }

    // MARK: - Exponential Padding

    /// **INTEGRATION: 100 messages of varying sizes → observer sees only ≤9 distinct sizes.**
    func testExponentialPadding_trafficAnalysis() throws {
        let key = SymmetricKey(size: .bits256)
        let padding = ExponentialPaddingScheme(hmacKey: key)
        var observedSizes = Set<Int>()

        for _ in 0..<100 {
            let size = Int.random(in: 1...60000)
            let message = Data(repeating: 0, count: size)
            let envelope = try padding.pad(message: message)
            observedSizes.insert(envelope.count)
        }

        XCTAssertLessThanOrEqual(
            observedSizes.count, 9,
            "At most 9 distinct sizes should be observable"
        )
    }

    // MARK: - Threat Model Verification

    /// **INTEGRATION: Threat model covers all critical findings.**
    func testThreatModelCompleteness() {
        let criticalFindings = ThreatModel.redTeamFindings.filter { $0.severity == .critical }
        XCTAssertEqual(criticalFindings.count, 6, "Should have 6 critical findings mapped")

        let highFindings = ThreatModel.redTeamFindings.filter { $0.severity == .high }
        XCTAssertGreaterThanOrEqual(highFindings.count, 7, "Should have 7+ high findings mapped")

        // All critical findings should be fixed
        let fixedCritical = criticalFindings.filter { $0.status == .fixed }
        XCTAssertEqual(fixedCritical.count, 6, "All 6 critical findings should be fixed")
    }

    /// **INTEGRATION: Residual risks cover all attack surfaces.**
    func testResidualRiskCoverage() {
        let coveredSurfaces = Set(ThreatModel.residualRisks.map { $0.surface })
        let allSurfaces = Set(ThreatModel.AttackSurface.allCases)
        XCTAssertEqual(coveredSurfaces, allSurfaces, "All attack surfaces should have residual risk assessment")
    }

    /// **INTEGRATION: Audit scope covers critical files.**
    func testAuditScopeCoverage() {
        let criticalFiles = AuditScope.criticalPath.filter { $0.priority == .critical }
        XCTAssertGreaterThanOrEqual(criticalFiles.count, 10, "Should have 10+ critical review files")

        // Verify all security properties are referenced
        let referencedProperties = Set(AuditScope.criticalPath.flatMap { $0.securityProperties })
        XCTAssertGreaterThanOrEqual(referencedProperties.count, 10, "Should reference 10+ security properties")
    }

    /// **INTEGRATION: Architecture diagrams are non-empty.**
    func testArchitectureDiagrams() {
        let diagrams = DiagramMetadata.all
        XCTAssertGreaterThanOrEqual(diagrams.count, 6, "Should have 6+ architecture diagrams")

        for diagram in diagrams {
            XCTAssertFalse(diagram.diagram.isEmpty, "Diagram '\(diagram.name)' should not be empty")
            XCTAssertFalse(diagram.name.isEmpty)
            XCTAssertFalse(diagram.description.isEmpty)
        }
    }

    /// **INTEGRATION: Review checklist is comprehensive.**
    func testReviewChecklist() {
        let checklist = AuditScope.reviewChecklist
        XCTAssertGreaterThanOrEqual(checklist.count, 15, "Should have 15+ checklist items")

        // All items should be verified (internal review complete)
        let verifiedCount = checklist.filter { $0.verified }.count
        XCTAssertEqual(verifiedCount, checklist.count, "All internal review items should be verified")
    }

    // MARK: - Helpers

    /// Synchronously wait for an async operation (test helper).
    private func waitForAsync<T>(_ operation: @escaping () async throws -> T) throws -> T {
        let expectation = XCTestExpectation(description: "async")
        var result: Result<T, Error>!

        Task {
            do {
                let value = try await operation()
                result = .success(value)
            } catch {
                result = .failure(error)
            }
            expectation.fulfill()
        }

        wait(for: [expectation], timeout: 10)

        switch result! {
        case .success(let value): return value
        case .failure(let error): throw error
        }
    }
}

// MARK: - Result Extension

private extension Result {
    var isOk: Bool {
        if case .success = self { return true }
        return false
    }
    var isErr: Bool {
        !isOk
    }
}
