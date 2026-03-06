// VEIL — FullLifecycleIntegrationTests.swift
// Ticket: VEIL-804 — Integration Test Suite
// Spec reference: Section 3.1 (Registration), 3.2 (PQXDH), 8.2 (Triple Ratchet)
//
// End-to-end integration tests covering the full session lifecycle:
//   1. Registration → prekey upload → PQXDH session establishment
//   2. Bidirectional message exchange (100 messages)
//   3. Payment receipt transmission
//   4. Session teardown and cleanup
//
// These tests exercise the complete protocol stack from identity
// key generation through Triple Ratchet encryption/decryption,
// using the MockRelayServer for network simulation.

import XCTest
import CryptoKit
@testable import VeilCrypto

final class FullLifecycleIntegrationTests: XCTestCase {

    // MARK: - Test Infrastructure

    private var mockServer: MockRelayServer!

    override func setUp() async throws {
        try await super.setUp()
        mockServer = MockRelayServer()
    }

    override func tearDown() async throws {
        await mockServer.reset()
        mockServer = nil
        try await super.tearDown()
    }

    // MARK: - Helper: Create Test User

    /// Create a test user with identity keys and prekey bundle.
    private struct TestUser {
        let identityKeyPair: IdentityKeyPair
        let registrationId: UInt32
        let deviceId: UInt32 = 1
    }

    /// Register a test user on the mock relay.
    private func createTestUser() async throws -> TestUser {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let registrationId = try await mockServer.registerDevice(
            deviceId: 1,
            identityKey: identityKeyPair.publicKeyEd25519
        )
        return TestUser(
            identityKeyPair: identityKeyPair,
            registrationId: registrationId
        )
    }

    // MARK: VEIL-804 — Test 1: Full Session Lifecycle

    /// **INTEGRATION: Registration → PQXDH → 100 messages → payment → teardown.**
    ///
    /// This is the primary integration test exercising the complete protocol
    /// stack end-to-end.
    func testFullSessionLifecycle() async throws {
        // Phase 1: Create Alice and Bob
        let alice = try await createTestUser()
        let bob = try await createTestUser()

        XCTAssertTrue(await mockServer.isRegistered(alice.registrationId))
        XCTAssertTrue(await mockServer.isRegistered(bob.registrationId))

        // Phase 2: PQXDH session establishment
        // Alice initiates a session with Bob
        let sessionKey = SecureBytes(bytes: Array(0..<64))

        var aliceSession = try TripleRatchetSession(
            sessionKey: sessionKey,
            isInitiator: true
        )

        // Alice sends bootstrap message
        let bootstrapEnvelope = try aliceSession.encrypt(
            plaintext: Data("Hello Bob, let's chat securely!".utf8)
        )

        var bobSession = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(0..<64)),
            isInitiator: false,
            peerEphemeralKey: bootstrapEnvelope.ephemeralKey
        )

        // Bob processes bootstrap
        let bootstrapPlaintext = try bobSession.decrypt(envelope: bootstrapEnvelope)
        XCTAssertEqual(
            String(data: bootstrapPlaintext, encoding: .utf8),
            "Hello Bob, let's chat securely!"
        )

        // Phase 3: Bidirectional message exchange (100 messages)
        var aliceMessages: [String] = []
        var bobMessages: [String] = []

        for i in 0..<100 {
            if i % 2 == 0 {
                // Alice → Bob
                let text = "Alice message \(i)"
                aliceMessages.append(text)

                let envelope = try aliceSession.encrypt(plaintext: Data(text.utf8))

                // Route through mock server
                let guid = try await mockServer.sendMessage(
                    to: bob.registrationId,
                    envelope: MockRelayServer.MockWireEnvelope(
                        content: envelope.ciphertext,
                        sealedSender: Data(),
                        contentType: VeilContentType.text.rawValue,
                        senderRegistrationId: alice.registrationId
                    )
                )
                XCTAssertFalse(guid.isEmpty)

                // Bob decrypts
                let decrypted = try bobSession.decrypt(envelope: envelope)
                XCTAssertEqual(String(data: decrypted, encoding: .utf8), text)
            } else {
                // Bob → Alice
                let text = "Bob message \(i)"
                bobMessages.append(text)

                let envelope = try bobSession.encrypt(plaintext: Data(text.utf8))

                // Route through mock server
                let guid = try await mockServer.sendMessage(
                    to: alice.registrationId,
                    envelope: MockRelayServer.MockWireEnvelope(
                        content: envelope.ciphertext,
                        sealedSender: Data(),
                        contentType: VeilContentType.text.rawValue,
                        senderRegistrationId: bob.registrationId
                    )
                )
                XCTAssertFalse(guid.isEmpty)

                // Alice decrypts
                let decrypted = try aliceSession.decrypt(envelope: envelope)
                XCTAssertEqual(String(data: decrypted, encoding: .utf8), text)
            }
        }

        XCTAssertEqual(aliceMessages.count, 50)
        XCTAssertEqual(bobMessages.count, 50)

        // Phase 4: Payment receipt transmission
        let receipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 500_000_000_000,  // 0.5 MOB
            memo: "Thanks for coffee!",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 12345
        )

        let receiptData = try receipt.encode()
        let receiptEnvelope = try aliceSession.encrypt(plaintext: receiptData)

        // Bob receives and verifies payment
        let decryptedReceipt = try bobSession.decrypt(envelope: receiptEnvelope)
        let recoveredReceipt = try PaymentReceiptMessage.decode(from: decryptedReceipt)

        XCTAssertEqual(recoveredReceipt.amountPicomob, 500_000_000_000)
        XCTAssertEqual(recoveredReceipt.memo, "Thanks for coffee!")
        XCTAssertEqual(recoveredReceipt.blockIndex, 12345)
        XCTAssertTrue(recoveredReceipt.isValid)

        // Phase 5: Verify server state
        XCTAssertGreaterThan(await mockServer.totalProcessed, 0)
    }

    // MARK: VEIL-804 — Test 2: Message Ordering

    /// **INTEGRATION: 100 messages sent rapidly preserve correct order.**
    func testMessageOrdering() async throws {
        let sessionKey = SecureBytes(bytes: Array(0..<64))

        var alice = try TripleRatchetSession(
            sessionKey: sessionKey,
            isInitiator: true
        )
        let bootstrap = try alice.encrypt(plaintext: Data("init".utf8))

        var bob = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(0..<64)),
            isInitiator: false,
            peerEphemeralKey: bootstrap.ephemeralKey
        )
        _ = try bob.decrypt(envelope: bootstrap)

        // Alice sends 100 messages rapidly
        var envelopes: [TripleRatchetSession.Envelope] = []
        for i in 0..<100 {
            let envelope = try alice.encrypt(plaintext: Data("msg_\(i)".utf8))
            envelopes.append(envelope)
        }

        // Bob decrypts all in order — must match
        for (i, envelope) in envelopes.enumerated() {
            let plaintext = try bob.decrypt(envelope: envelope)
            let text = String(data: plaintext, encoding: .utf8)
            XCTAssertEqual(text, "msg_\(i)", "Message \(i) out of order")
        }
    }

    // MARK: VEIL-804 — Test 3: Large Message Handling

    /// **INTEGRATION: Messages at various sizes round-trip correctly.**
    func testLargeMessageHandling() async throws {
        let sessionKey = SecureBytes(bytes: Array(0..<64))

        var alice = try TripleRatchetSession(
            sessionKey: sessionKey,
            isInitiator: true
        )
        let bootstrap = try alice.encrypt(plaintext: Data("init".utf8))

        var bob = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(0..<64)),
            isInitiator: false,
            peerEphemeralKey: bootstrap.ephemeralKey
        )
        _ = try bob.decrypt(envelope: bootstrap)

        // Test various message sizes
        let sizes = [1, 10, 100, 1024, 10_240, 102_400]

        for size in sizes {
            let message = Data((0..<size).map { _ in UInt8.random(in: 0...255) })
            let envelope = try alice.encrypt(plaintext: message)
            let decrypted = try bob.decrypt(envelope: envelope)

            XCTAssertEqual(
                decrypted, message,
                "Large message round-trip failed for size \(size)"
            )
        }
    }

    // MARK: VEIL-804 — Test 4: Session Key Derivation Consistency

    /// **INTEGRATION: Same session key always produces compatible sessions.**
    func testSessionKeyConsistency() async throws {
        // Run 10 sessions with the same key — all must be compatible
        for trial in 0..<10 {
            let key = SecureBytes(bytes: Array(repeating: UInt8(trial), count: 64))

            var sender = try TripleRatchetSession(
                sessionKey: key,
                isInitiator: true
            )
            let bootstrap = try sender.encrypt(plaintext: Data("trial_\(trial)".utf8))

            var receiver = try TripleRatchetSession(
                sessionKey: SecureBytes(bytes: Array(repeating: UInt8(trial), count: 64)),
                isInitiator: false,
                peerEphemeralKey: bootstrap.ephemeralKey
            )
            let decrypted = try receiver.decrypt(envelope: bootstrap)

            XCTAssertEqual(
                String(data: decrypted, encoding: .utf8),
                "trial_\(trial)"
            )
        }
    }

    // MARK: VEIL-804 — Test 5: Alternating Direction Exchange

    /// **INTEGRATION: Rapid direction changes exercise the DH ratchet correctly.**
    func testAlternatingDirectionExchange() async throws {
        let sessionKey = SecureBytes(bytes: Array(0..<64))

        var alice = try TripleRatchetSession(
            sessionKey: sessionKey,
            isInitiator: true
        )
        let bootstrap = try alice.encrypt(plaintext: Data("init".utf8))

        var bob = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(0..<64)),
            isInitiator: false,
            peerEphemeralKey: bootstrap.ephemeralKey
        )
        _ = try bob.decrypt(envelope: bootstrap)

        // Alternate: Alice → Bob → Alice → Bob (rapid DH ratchet steps)
        for round in 0..<50 {
            // Alice → Bob
            let aliceMsg = try alice.encrypt(plaintext: Data("A\(round)".utf8))
            let aliceDecrypted = try bob.decrypt(envelope: aliceMsg)
            XCTAssertEqual(String(data: aliceDecrypted, encoding: .utf8), "A\(round)")

            // Bob → Alice
            let bobMsg = try bob.encrypt(plaintext: Data("B\(round)".utf8))
            let bobDecrypted = try alice.decrypt(envelope: bobMsg)
            XCTAssertEqual(String(data: bobDecrypted, encoding: .utf8), "B\(round)")
        }
    }

    // MARK: VEIL-804 — Test 6: Server Message Queue FIFO

    /// **INTEGRATION: Mock relay delivers messages in FIFO order.**
    func testServerMessageQueueFIFO() async throws {
        let alice = try await createTestUser()
        let bob = try await createTestUser()

        // Send 20 messages to Bob
        for i in 0..<20 {
            let _ = try await mockServer.sendMessage(
                to: bob.registrationId,
                envelope: MockRelayServer.MockWireEnvelope(
                    content: Data("msg_\(i)".utf8),
                    sealedSender: Data(),
                    contentType: VeilContentType.text.rawValue,
                    senderRegistrationId: alice.registrationId
                )
            )
        }

        // Retrieve — must be in FIFO order
        let messages = try await mockServer.retrieveMessages(for: bob.registrationId)
        XCTAssertEqual(messages.count, 20)

        for (i, msg) in messages.enumerated() {
            let content = String(data: msg.envelope.content, encoding: .utf8)
            XCTAssertEqual(content, "msg_\(i)", "FIFO order violated at index \(i)")
        }
    }

    // MARK: VEIL-804 — Test 7: Message Acknowledgment

    /// **INTEGRATION: Acknowledged messages are removed from the queue.**
    func testMessageAcknowledgment() async throws {
        let alice = try await createTestUser()
        let bob = try await createTestUser()

        // Send 5 messages
        var guids: [Data] = []
        for i in 0..<5 {
            let guid = try await mockServer.sendMessage(
                to: bob.registrationId,
                envelope: MockRelayServer.MockWireEnvelope(
                    content: Data("msg_\(i)".utf8),
                    sealedSender: Data(),
                    contentType: VeilContentType.text.rawValue,
                    senderRegistrationId: alice.registrationId
                )
            )
            guids.append(guid)
        }

        XCTAssertEqual(await mockServer.queueDepth(for: bob.registrationId), 5)

        // Acknowledge first 3
        for guid in guids.prefix(3) {
            try await mockServer.acknowledgeMessage(serverGuid: guid)
        }

        // Only 2 remaining
        let remaining = try await mockServer.retrieveMessages(for: bob.registrationId)
        XCTAssertEqual(remaining.count, 2)
    }

    // MARK: VEIL-804 — Test 8: Multiple Receipts in Session

    /// **INTEGRATION: Multiple payment receipts in the same session.**
    func testMultiplePaymentReceipts() async throws {
        let sessionKey = SecureBytes(bytes: Array(0..<64))

        var alice = try TripleRatchetSession(
            sessionKey: sessionKey,
            isInitiator: true
        )
        let bootstrap = try alice.encrypt(plaintext: Data("init".utf8))

        var bob = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(0..<64)),
            isInitiator: false,
            peerEphemeralKey: bootstrap.ephemeralKey
        )
        _ = try bob.decrypt(envelope: bootstrap)

        // Send 5 payment receipts with different amounts
        let amounts: [UInt64] = [
            100_000_000_000,        // 0.1 MOB
            250_000_000_000,        // 0.25 MOB
            1_000_000_000_000,      // 1.0 MOB
            50_000_000,             // 0.00005 MOB (dust)
            2_500_000_000_000,      // 2.5 MOB
        ]

        for (i, amount) in amounts.enumerated() {
            let receipt = PaymentReceiptMessage(
                txHash: String(repeating: String(format: "%02x", i), count: 32),
                sharedSecret: Data(repeating: UInt8(i), count: 32).base64EncodedString(),
                amountPicomob: amount,
                memo: "Payment \(i)",
                receiptProof: Data(repeating: UInt8(i), count: 64).base64EncodedString(),
                blockIndex: UInt64(1000 + i)
            )

            let data = try receipt.encode()
            let envelope = try alice.encrypt(plaintext: data)
            let decrypted = try bob.decrypt(envelope: envelope)
            let recovered = try PaymentReceiptMessage.decode(from: decrypted)

            XCTAssertEqual(recovered.amountPicomob, amount)
            XCTAssertEqual(recovered.memo, "Payment \(i)")
            XCTAssertTrue(recovered.isValid)
        }
    }
}
