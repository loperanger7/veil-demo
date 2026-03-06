// VEIL — ReceiptAuthenticatorTests.swift
// Ticket: VEIL-901 — Security Hardening Tests
// Spec reference: Section 8.5 (Payment Receipts)
//
// Tests for receipt authentication and replay protection:
//   - Sign and verify round-trip
//   - Forged signature detection
//   - Replay detection via nonce tracker
//   - Nonce uniqueness and bounds
//   - Backward compatibility with unsigned receipts
//   - Cross-key verification failure
//   - Field modification detection

import XCTest
import CryptoKit
@testable import VeilCrypto

final class ReceiptAuthenticatorTests: XCTestCase {

    private var authenticator: ReceiptAuthenticator!
    private var senderKey: Curve25519.Signing.PrivateKey!
    private var senderPublicKey: Curve25519.Signing.PublicKey!

    override func setUp() {
        super.setUp()
        authenticator = ReceiptAuthenticator()
        senderKey = Curve25519.Signing.PrivateKey()
        senderPublicKey = senderKey.publicKey
    }

    // MARK: - Helper

    private func makeReceipt(
        amount: UInt64 = 100_000_000_000,
        memo: String = "Test payment",
        blockIndex: UInt64 = 12345
    ) -> PaymentReceiptMessage {
        PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: amount,
            memo: memo,
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: blockIndex
        )
    }

    // MARK: - Sign and Verify

    /// **HARDENING: Sign → verify round-trip succeeds.**
    func testSignAndVerify() async throws {
        let receipt = makeReceipt()

        let authenticated = try authenticator.sign(
            receipt: receipt,
            signingKey: senderKey
        )

        let isValid = try await authenticator.verify(
            authenticatedReceipt: authenticated,
            senderIdentityKey: senderPublicKey
        )

        XCTAssertTrue(isValid, "Properly signed receipt should verify")
    }

    /// **HARDENING: Signature-only verification (no nonce tracker).**
    func testSignatureOnlyVerification() throws {
        let receipt = makeReceipt()

        let authenticated = try authenticator.sign(
            receipt: receipt,
            signingKey: senderKey
        )

        let isValid = authenticator.verifySignature(
            authenticatedReceipt: authenticated,
            senderIdentityKey: senderPublicKey
        )

        XCTAssertTrue(isValid)
    }

    /// **HARDENING: Authenticated receipt serialization round-trip.**
    func testAuthenticatedReceiptSerialization() throws {
        let receipt = makeReceipt()
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        // Encode → decode
        let encoded = try authenticated.encode()
        let decoded = try AuthenticatedReceipt.decode(from: encoded)

        XCTAssertEqual(decoded.receipt, receipt)
        XCTAssertEqual(decoded.authentication.signatureBase64, authenticated.authentication.signatureBase64)
        XCTAssertEqual(decoded.authentication.nonceBase64, authenticated.authentication.nonceBase64)
        XCTAssertEqual(decoded.authVersion, 1)
    }

    // MARK: - Forgery Detection

    /// **HARDENING: Modified receipt after signing is rejected.**
    func testForgedSignature() throws {
        let receipt = makeReceipt()
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        // Create a modified receipt with different amount
        let tamperedReceipt = PaymentReceiptMessage(
            txHash: receipt.txHash,
            sharedSecret: receipt.sharedSecret,
            amountPicomob: 999_999_999_999, // Changed!
            memo: receipt.memo,
            receiptProof: receipt.receiptProof,
            blockIndex: receipt.blockIndex
        )

        let tamperedAuth = AuthenticatedReceipt(
            receipt: tamperedReceipt,
            authentication: authenticated.authentication
        )

        let isValid = authenticator.verifySignature(
            authenticatedReceipt: tamperedAuth,
            senderIdentityKey: senderPublicKey
        )

        XCTAssertFalse(isValid, "Modified receipt should not verify")
    }

    /// **HARDENING: Amount modification detected.**
    func testAmountModification() throws {
        let receipt = makeReceipt(amount: 100_000_000_000)
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        let modifiedReceipt = PaymentReceiptMessage(
            txHash: receipt.txHash,
            sharedSecret: receipt.sharedSecret,
            amountPicomob: 200_000_000_000, // Doubled!
            memo: receipt.memo,
            receiptProof: receipt.receiptProof,
            blockIndex: receipt.blockIndex
        )

        let modifiedAuth = AuthenticatedReceipt(
            receipt: modifiedReceipt,
            authentication: authenticated.authentication
        )

        XCTAssertFalse(authenticator.verifySignature(
            authenticatedReceipt: modifiedAuth,
            senderIdentityKey: senderPublicKey
        ), "Amount modification should be detected")
    }

    /// **HARDENING: Memo modification detected.**
    func testMemoModification() throws {
        let receipt = makeReceipt(memo: "Original memo")
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        let modifiedReceipt = PaymentReceiptMessage(
            txHash: receipt.txHash,
            sharedSecret: receipt.sharedSecret,
            amountPicomob: receipt.amountPicomob,
            memo: "Send me 1000 MOB", // Changed!
            receiptProof: receipt.receiptProof,
            blockIndex: receipt.blockIndex
        )

        let modifiedAuth = AuthenticatedReceipt(
            receipt: modifiedReceipt,
            authentication: authenticated.authentication
        )

        XCTAssertFalse(authenticator.verifySignature(
            authenticatedReceipt: modifiedAuth,
            senderIdentityKey: senderPublicKey
        ), "Memo modification should be detected")
    }

    /// **HARDENING: Wrong sender key fails verification.**
    func testCrossKeyVerification() throws {
        let receipt = makeReceipt()
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        // Try verifying with a different key
        let wrongKey = Curve25519.Signing.PrivateKey()

        let isValid = authenticator.verifySignature(
            authenticatedReceipt: authenticated,
            senderIdentityKey: wrongKey.publicKey
        )

        XCTAssertFalse(isValid, "Wrong sender key should fail verification")
    }

    // MARK: - Replay Protection

    /// **HARDENING: Same nonce submitted twice is rejected.**
    func testReplayDetection() async throws {
        let receipt = makeReceipt()
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)
        let tracker = ReceiptNonceTracker()

        // First verification: should succeed
        let firstResult = try await authenticator.verify(
            authenticatedReceipt: authenticated,
            senderIdentityKey: senderPublicKey,
            nonceTracker: tracker
        )
        XCTAssertTrue(firstResult, "First submission should succeed")

        // Second verification (replay): should fail
        let replayResult = try await authenticator.verify(
            authenticatedReceipt: authenticated,
            senderIdentityKey: senderPublicKey,
            nonceTracker: tracker
        )
        XCTAssertFalse(replayResult, "Replay should be detected and rejected")
    }

    /// **HARDENING: 1000 nonces are all unique.**
    func testNonceUniqueness() throws {
        var nonces = Set<String>()

        for _ in 0..<1000 {
            let receipt = makeReceipt()
            let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)
            nonces.insert(authenticated.authentication.nonceBase64)
        }

        XCTAssertEqual(nonces.count, 1000, "All 1000 nonces should be unique")
    }

    /// **HARDENING: Nonce tracker respects capacity bound.**
    func testNonceTrackerBound() async {
        let tracker = ReceiptNonceTracker(maxNonces: 100)

        // Insert 101 nonces
        for i in 0..<101 {
            var bytes = Data(repeating: 0, count: 32)
            bytes[0] = UInt8(i & 0xFF)
            bytes[1] = UInt8((i >> 8) & 0xFF)
            let _ = await tracker.checkAndRecord(nonce: bytes)
        }

        // Should have evicted the oldest
        let count = await tracker.count
        XCTAssertEqual(count, 100, "Tracker should evict oldest to stay at capacity")

        // First nonce should have been evicted
        let firstNonce = Data(repeating: 0, count: 32)
        let firstSeen = await tracker.hasBeenSeen(nonce: firstNonce)
        XCTAssertFalse(firstSeen, "Oldest nonce should have been evicted")
    }

    /// **HARDENING: Nonce tracker reset clears all state.**
    func testNonceTrackerReset() async {
        let tracker = ReceiptNonceTracker()

        let nonce = Data(repeating: 0xAA, count: 32)
        let _ = await tracker.checkAndRecord(nonce: nonce)
        XCTAssertEqual(await tracker.count, 1)

        await tracker.reset()
        XCTAssertEqual(await tracker.count, 0)

        // Same nonce should now be accepted again
        let fresh = await tracker.checkAndRecord(nonce: nonce)
        XCTAssertTrue(fresh, "After reset, previously seen nonce should be accepted")
    }

    // MARK: - Backward Compatibility

    /// **HARDENING: Legacy receipt (no auth) handled gracefully.**
    func testBackwardCompatibility() {
        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 100_000_000_000,
            memo: "Legacy",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 100,
            version: 1
        )

        // Version 1 should not require authentication
        XCTAssertFalse(receipt.requiresAuthentication)

        // Version 2+ should require authentication
        let v2Receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 100_000_000_000,
            memo: "V2",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 200,
            version: 2
        )
        XCTAssertTrue(v2Receipt.requiresAuthentication)
    }

    // MARK: - Edge Cases

    /// **HARDENING: Empty memo signs correctly.**
    func testEmptyMemoSignature() throws {
        let receipt = makeReceipt(memo: "")
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        let isValid = authenticator.verifySignature(
            authenticatedReceipt: authenticated,
            senderIdentityKey: senderPublicKey
        )
        XCTAssertTrue(isValid)
    }

    /// **HARDENING: Maximum amount signs correctly.**
    func testMaxAmountSignature() throws {
        let receipt = makeReceipt(amount: UInt64.max - 1)
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        let isValid = authenticator.verifySignature(
            authenticatedReceipt: authenticated,
            senderIdentityKey: senderPublicKey
        )
        XCTAssertTrue(isValid)
    }

    /// **HARDENING: Authentication includes nonce field.**
    func testAuthenticationFields() throws {
        let receipt = makeReceipt()
        let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)

        // Verify nonce is 32 bytes
        let nonceData = authenticated.authentication.nonceData
        XCTAssertNotNil(nonceData)
        XCTAssertEqual(nonceData?.count, 32)

        // Verify signature is 64 bytes
        let sigData = authenticated.authentication.signatureData
        XCTAssertNotNil(sigData)
        XCTAssertEqual(sigData?.count, 64)
    }

    /// **HARDENING: Multiple receipts from same sender each have unique nonces.**
    func testMultipleReceiptsUniqueNonces() throws {
        var nonces = Set<Data>()
        for i in 0..<50 {
            let receipt = makeReceipt(blockIndex: UInt64(1000 + i))
            let authenticated = try authenticator.sign(receipt: receipt, signingKey: senderKey)
            if let nonce = authenticated.authentication.nonceData {
                nonces.insert(nonce)
            }
        }
        XCTAssertEqual(nonces.count, 50, "All 50 nonces should be unique")
    }
}
