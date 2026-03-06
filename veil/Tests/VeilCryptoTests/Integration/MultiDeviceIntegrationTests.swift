// VEIL — MultiDeviceIntegrationTests.swift
// Ticket: VEIL-804 — Integration Test Suite
// Spec reference: Section 2.1 (Multi-Device), VEIL-509
//
// Integration tests for multi-device scenarios:
//   - User with 2 devices receives messages on both
//   - Each device maintains independent ratchet sessions
//   - Device deregistration removes one device without affecting the other
//   - Prekey pools are per-device
//   - Compromise of one device session doesn't affect others

import XCTest
import CryptoKit
@testable import VeilCrypto

final class MultiDeviceIntegrationTests: XCTestCase {

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

    // MARK: VEIL-804 — Test 1: Dual Device Receive

    /// **INTEGRATION: User with two devices receives message on both.**
    ///
    /// Bob has Device1 and Device2. Alice sends a message. Both devices
    /// must be able to decrypt independently (separate ratchet sessions).
    func testDualDeviceReceive() async throws {
        // Alice registers
        let aliceKeys = try await IdentityKeyPair.generate()
        let aliceRegId = try await mockServer.registerDevice(
            deviceId: 1,
            identityKey: aliceKeys.publicKeyEd25519
        )

        // Bob registers Device1
        let bobKeys = try await IdentityKeyPair.generate()
        let bobDevice1RegId = try await mockServer.registerDevice(
            deviceId: 1,
            identityKey: bobKeys.publicKeyEd25519
        )

        // Bob registers Device2 (same identity key, different device)
        let bobDevice2RegId = try await mockServer.registerDevice(
            deviceId: 2,
            identityKey: bobKeys.publicKeyEd25519
        )

        XCTAssertNotEqual(bobDevice1RegId, bobDevice2RegId)

        // Alice establishes separate sessions with each of Bob's devices
        let sessionKey1 = SecureBytes(bytes: Array(repeating: 0x01, count: 64))
        let sessionKey2 = SecureBytes(bytes: Array(repeating: 0x02, count: 64))

        var aliceToDevice1 = try TripleRatchetSession(
            sessionKey: sessionKey1,
            isInitiator: true
        )
        var aliceToDevice2 = try TripleRatchetSession(
            sessionKey: sessionKey2,
            isInitiator: true
        )

        // Bootstrap Device1 session
        let bootstrap1 = try aliceToDevice1.encrypt(plaintext: Data("hello_d1".utf8))
        var bobDevice1 = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(repeating: 0x01, count: 64)),
            isInitiator: false,
            peerEphemeralKey: bootstrap1.ephemeralKey
        )
        let d1Hello = try bobDevice1.decrypt(envelope: bootstrap1)
        XCTAssertEqual(String(data: d1Hello, encoding: .utf8), "hello_d1")

        // Bootstrap Device2 session
        let bootstrap2 = try aliceToDevice2.encrypt(plaintext: Data("hello_d2".utf8))
        var bobDevice2 = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(repeating: 0x02, count: 64)),
            isInitiator: false,
            peerEphemeralKey: bootstrap2.ephemeralKey
        )
        let d2Hello = try bobDevice2.decrypt(envelope: bootstrap2)
        XCTAssertEqual(String(data: d2Hello, encoding: .utf8), "hello_d2")

        // Alice sends "Important update" to both devices
        let message = "Important update from Alice"

        let env1 = try aliceToDevice1.encrypt(plaintext: Data(message.utf8))
        let env2 = try aliceToDevice2.encrypt(plaintext: Data(message.utf8))

        // Both devices decrypt independently
        let decrypted1 = try bobDevice1.decrypt(envelope: env1)
        let decrypted2 = try bobDevice2.decrypt(envelope: env2)

        XCTAssertEqual(String(data: decrypted1, encoding: .utf8), message)
        XCTAssertEqual(String(data: decrypted2, encoding: .utf8), message)

        // But the ciphertexts must be different (different ratchet states)
        XCTAssertNotEqual(env1.ciphertext, env2.ciphertext)
    }

    // MARK: VEIL-804 — Test 2: Device Replies

    /// **INTEGRATION: Each device can reply independently to Alice.**
    func testDeviceIndependentReplies() async throws {
        let sessionKey1 = SecureBytes(bytes: Array(repeating: 0x01, count: 64))
        let sessionKey2 = SecureBytes(bytes: Array(repeating: 0x02, count: 64))

        // Set up two sessions for Alice
        var aliceToD1 = try TripleRatchetSession(
            sessionKey: sessionKey1,
            isInitiator: true
        )
        var aliceToD2 = try TripleRatchetSession(
            sessionKey: sessionKey2,
            isInitiator: true
        )

        // Bootstrap
        let b1 = try aliceToD1.encrypt(plaintext: Data("init".utf8))
        let b2 = try aliceToD2.encrypt(plaintext: Data("init".utf8))

        var device1 = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(repeating: 0x01, count: 64)),
            isInitiator: false,
            peerEphemeralKey: b1.ephemeralKey
        )
        var device2 = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(repeating: 0x02, count: 64)),
            isInitiator: false,
            peerEphemeralKey: b2.ephemeralKey
        )
        _ = try device1.decrypt(envelope: b1)
        _ = try device2.decrypt(envelope: b2)

        // Device1 replies
        let reply1 = try device1.encrypt(plaintext: Data("Reply from D1".utf8))
        let d1Text = try aliceToD1.decrypt(envelope: reply1)
        XCTAssertEqual(String(data: d1Text, encoding: .utf8), "Reply from D1")

        // Device2 replies
        let reply2 = try device2.encrypt(plaintext: Data("Reply from D2".utf8))
        let d2Text = try aliceToD2.decrypt(envelope: reply2)
        XCTAssertEqual(String(data: d2Text, encoding: .utf8), "Reply from D2")
    }

    // MARK: VEIL-804 — Test 3: Device Deregistration

    /// **INTEGRATION: Deregistering a device removes it without affecting the other.**
    func testDeviceDeregistration() async throws {
        let bobKeys = try await IdentityKeyPair.generate()
        let d1RegId = try await mockServer.registerDevice(
            deviceId: 1,
            identityKey: bobKeys.publicKeyEd25519
        )
        let d2RegId = try await mockServer.registerDevice(
            deviceId: 2,
            identityKey: bobKeys.publicKeyEd25519
        )

        XCTAssertTrue(await mockServer.isRegistered(d1RegId))
        XCTAssertTrue(await mockServer.isRegistered(d2RegId))

        // Deregister Device2
        try await mockServer.deregisterDevice(d2RegId)

        XCTAssertTrue(await mockServer.isRegistered(d1RegId))
        XCTAssertFalse(await mockServer.isRegistered(d2RegId))

        // Messages to Device2 should fail
        do {
            let _ = try await mockServer.sendMessage(
                to: d2RegId,
                envelope: MockRelayServer.MockWireEnvelope(
                    content: Data("test".utf8),
                    sealedSender: Data(),
                    contentType: 1,
                    senderRegistrationId: 0
                )
            )
            XCTFail("Should throw for deregistered device")
        } catch {
            // Expected: 404 error
        }

        // Messages to Device1 still work
        let guid = try await mockServer.sendMessage(
            to: d1RegId,
            envelope: MockRelayServer.MockWireEnvelope(
                content: Data("still works".utf8),
                sealedSender: Data(),
                contentType: 1,
                senderRegistrationId: 0
            )
        )
        XCTAssertFalse(guid.isEmpty)
    }

    // MARK: VEIL-804 — Test 4: Per-Device Prekey Pools

    /// **INTEGRATION: Each device has an independent prekey pool.**
    func testPrekeyPoolPerDevice() async throws {
        let bobKeys = try await IdentityKeyPair.generate()
        let d1RegId = try await mockServer.registerDevice(
            deviceId: 1,
            identityKey: bobKeys.publicKeyEd25519
        )
        let d2RegId = try await mockServer.registerDevice(
            deviceId: 2,
            identityKey: bobKeys.publicKeyEd25519
        )

        // Upload different prekey bundles for each device
        let bundle1 = RelayPrekeyBundle(
            identityKeyEd25519: bobKeys.publicKeyEd25519,
            identityKeyMLDSA: Data(repeating: 0x01, count: 1952),
            signedPrekeyId: 1,
            signedPrekey: Data(repeating: 0xA1, count: 32),
            signedPrekeySig: Data(repeating: 0xB1, count: 64),
            pqSignedPrekey: Data(repeating: 0xC1, count: 1568),
            pqSignedPrekeySig: Data(repeating: 0xD1, count: 64),
            oneTimePrekeys: [],
            pqOneTimePrekeys: []
        )

        let bundle2 = RelayPrekeyBundle(
            identityKeyEd25519: bobKeys.publicKeyEd25519,
            identityKeyMLDSA: Data(repeating: 0x02, count: 1952),
            signedPrekeyId: 2,
            signedPrekey: Data(repeating: 0xA2, count: 32),
            signedPrekeySig: Data(repeating: 0xB2, count: 64),
            pqSignedPrekey: Data(repeating: 0xC2, count: 1568),
            pqSignedPrekeySig: Data(repeating: 0xD2, count: 64),
            oneTimePrekeys: [],
            pqOneTimePrekeys: []
        )

        try await mockServer.uploadPrekeys(registrationId: d1RegId, bundle: bundle1)
        try await mockServer.uploadPrekeys(registrationId: d2RegId, bundle: bundle2)

        // Fetch and verify they're independent
        let fetched1 = try await mockServer.fetchPrekeys(for: d1RegId)
        let fetched2 = try await mockServer.fetchPrekeys(for: d2RegId)

        XCTAssertEqual(fetched1.signedPrekeyId, 1)
        XCTAssertEqual(fetched2.signedPrekeyId, 2)
        XCTAssertNotEqual(fetched1.signedPrekey, fetched2.signedPrekey)
    }

    // MARK: VEIL-804 — Test 5: Session Independence

    /// **INTEGRATION: Compromise of Device2 session doesn't affect Device1.**
    func testSessionIndependence() async throws {
        let sessionKey1 = SecureBytes(bytes: Array(repeating: 0x01, count: 64))
        let sessionKey2 = SecureBytes(bytes: Array(repeating: 0x02, count: 64))

        // Set up two independent sessions
        var aliceToD1 = try TripleRatchetSession(
            sessionKey: sessionKey1,
            isInitiator: true
        )
        var aliceToD2 = try TripleRatchetSession(
            sessionKey: sessionKey2,
            isInitiator: true
        )

        let b1 = try aliceToD1.encrypt(plaintext: Data("init".utf8))
        let b2 = try aliceToD2.encrypt(plaintext: Data("init".utf8))

        var device1 = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(repeating: 0x01, count: 64)),
            isInitiator: false,
            peerEphemeralKey: b1.ephemeralKey
        )
        var device2 = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(repeating: 0x02, count: 64)),
            isInitiator: false,
            peerEphemeralKey: b2.ephemeralKey
        )
        _ = try device1.decrypt(envelope: b1)
        _ = try device2.decrypt(envelope: b2)

        // Exchange 10 messages on each session
        for i in 0..<10 {
            let e1 = try aliceToD1.encrypt(plaintext: Data("d1_\(i)".utf8))
            let _ = try device1.decrypt(envelope: e1)

            let e2 = try aliceToD2.encrypt(plaintext: Data("d2_\(i)".utf8))
            let _ = try device2.decrypt(envelope: e2)
        }

        // "Compromise" Device2 — try to use Device2's envelope on Device1
        let d2Envelope = try aliceToD2.encrypt(plaintext: Data("compromised".utf8))

        // Device1 should NOT be able to decrypt Device2's messages
        XCTAssertThrowsError(
            try device1.decrypt(envelope: d2Envelope),
            "Device1 should not decrypt Device2's messages"
        )

        // But Device1's session still works fine
        let d1Msg = try aliceToD1.encrypt(plaintext: Data("still_secure".utf8))
        let decrypted = try device1.decrypt(envelope: d1Msg)
        XCTAssertEqual(String(data: decrypted, encoding: .utf8), "still_secure")
    }

    // MARK: VEIL-804 — Test 6: Server Queue Isolation

    /// **INTEGRATION: Messages to different devices are queued separately.**
    func testServerQueueIsolation() async throws {
        let bobKeys = try await IdentityKeyPair.generate()
        let aliceKeys = try await IdentityKeyPair.generate()

        let aliceRegId = try await mockServer.registerDevice(
            deviceId: 1,
            identityKey: aliceKeys.publicKeyEd25519
        )
        let bobD1RegId = try await mockServer.registerDevice(
            deviceId: 1,
            identityKey: bobKeys.publicKeyEd25519
        )
        let bobD2RegId = try await mockServer.registerDevice(
            deviceId: 2,
            identityKey: bobKeys.publicKeyEd25519
        )

        // Send 5 messages to Device1, 3 to Device2
        for i in 0..<5 {
            let _ = try await mockServer.sendMessage(
                to: bobD1RegId,
                envelope: MockRelayServer.MockWireEnvelope(
                    content: Data("d1_\(i)".utf8),
                    sealedSender: Data(),
                    contentType: 1,
                    senderRegistrationId: aliceRegId
                )
            )
        }

        for i in 0..<3 {
            let _ = try await mockServer.sendMessage(
                to: bobD2RegId,
                envelope: MockRelayServer.MockWireEnvelope(
                    content: Data("d2_\(i)".utf8),
                    sealedSender: Data(),
                    contentType: 1,
                    senderRegistrationId: aliceRegId
                )
            )
        }

        let d1Messages = try await mockServer.retrieveMessages(for: bobD1RegId)
        let d2Messages = try await mockServer.retrieveMessages(for: bobD2RegId)

        XCTAssertEqual(d1Messages.count, 5)
        XCTAssertEqual(d2Messages.count, 3)

        // Verify content isolation
        for msg in d1Messages {
            let content = String(data: msg.envelope.content, encoding: .utf8)!
            XCTAssertTrue(content.hasPrefix("d1_"), "Device1 queue contains Device2 message")
        }

        for msg in d2Messages {
            let content = String(data: msg.envelope.content, encoding: .utf8)!
            XCTAssertTrue(content.hasPrefix("d2_"), "Device2 queue contains Device1 message")
        }
    }
}
