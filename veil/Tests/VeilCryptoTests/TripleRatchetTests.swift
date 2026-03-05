// VEIL — TripleRatchetTests.swift
// Tests for VEIL-108: Triple Ratchet Composition
//
// Integration tests verifying the composed encrypt/decrypt pipeline.

import XCTest
@testable import VeilCrypto

final class TripleRatchetTests: XCTestCase {

    // MARK: - Helpers

    /// Create a pair of Triple Ratchet sessions (Alice and Bob) sharing a session key.
    private func createSessionPair() throws -> (
        alice: TripleRatchetSession,
        bob: TripleRatchetSession
    ) {
        // Simulate PQXDH producing a shared session key
        let sessionKey = SecureBytes(bytes: Array(0..<64))

        var alice = try TripleRatchetSession(
            sessionKey: sessionKey,
            isInitiator: true
        )

        // Bob needs Alice's ephemeral key to set up his side
        // For testing, we do a "first message" handshake:
        let firstMessage = try alice.encrypt(plaintext: Data("init".utf8))

        var bob = try TripleRatchetSession(
            sessionKey: SecureBytes(bytes: Array(0..<64)),
            isInitiator: false,
            peerEphemeralKey: firstMessage.ephemeralKey
        )

        return (alice, bob)
    }

    // MARK: - Basic Encrypt / Decrypt

    func testEncryptDecrypt_singleMessage() throws {
        var (alice, bob) = try createSessionPair()

        let plaintext = Data("Hello Bob, this is a secret message!".utf8)
        let envelope = try alice.encrypt(plaintext: plaintext)

        let decrypted = try bob.decrypt(envelope: envelope)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptDecrypt_multipleMessages_sameDirection() throws {
        var (alice, bob) = try createSessionPair()

        for i in 0..<10 {
            let plaintext = Data("Message \(i)".utf8)
            let envelope = try alice.encrypt(plaintext: plaintext)
            let decrypted = try bob.decrypt(envelope: envelope)
            XCTAssertEqual(decrypted, plaintext, "Message \(i) failed to decrypt")
        }
    }

    func testEncryptDecrypt_alternatingDirections() throws {
        var (alice, bob) = try createSessionPair()

        // Alice sends
        let msg1 = try alice.encrypt(plaintext: Data("From Alice 1".utf8))
        XCTAssertEqual(try bob.decrypt(envelope: msg1), Data("From Alice 1".utf8))

        // Bob replies
        let msg2 = try bob.encrypt(plaintext: Data("From Bob 1".utf8))
        XCTAssertEqual(try alice.decrypt(envelope: msg2), Data("From Bob 1".utf8))

        // Alice sends again
        let msg3 = try alice.encrypt(plaintext: Data("From Alice 2".utf8))
        XCTAssertEqual(try bob.decrypt(envelope: msg3), Data("From Alice 2".utf8))

        // Bob replies again
        let msg4 = try bob.encrypt(plaintext: Data("From Bob 2".utf8))
        XCTAssertEqual(try alice.decrypt(envelope: msg4), Data("From Bob 2".utf8))
    }

    // MARK: - Padding

    func testEncrypt_paddsToCBlockBoundary() throws {
        var (alice, _) = try createSessionPair()

        // Short message
        let envelope = try alice.encrypt(plaintext: Data("Hi".utf8))

        // Ciphertext should be padded to 256-byte boundaries + AES overhead
        // The padded plaintext length should be a multiple of 256
        // Ciphertext = nonce (12) + padded_plaintext + tag (16)
        let ciphertextOverhead = VeilConstants.aesGCMNonceSize + VeilConstants.aesGCMTagSize
        let paddedPlaintextSize = envelope.ciphertext.count - ciphertextOverhead
        XCTAssertEqual(paddedPlaintextSize % VeilConstants.messagePaddingBlockSize, 0,
                       "Padded plaintext must be a multiple of block size")
    }

    // MARK: - Envelope Structure

    func testEnvelope_containsEphemeralKey() throws {
        var (alice, _) = try createSessionPair()

        let envelope = try alice.encrypt(plaintext: Data("test".utf8))
        XCTAssertEqual(envelope.ephemeralKey.count, VeilConstants.x25519KeySize)
    }

    // MARK: - Large Conversation

    func testEncryptDecrypt_100Messages_randomPattern() throws {
        var (alice, bob) = try createSessionPair()

        // Deterministic "random" pattern: Alice sends N, Bob sends M, repeat
        let patterns = [(3, 2), (1, 5), (4, 1), (2, 3), (5, 4)]

        var totalMessages = 0
        for (aliceSends, bobSends) in patterns {
            for i in 0..<aliceSends {
                let text = "Alice[\(totalMessages + i)]"
                let envelope = try alice.encrypt(plaintext: Data(text.utf8))
                let decrypted = try bob.decrypt(envelope: envelope)
                XCTAssertEqual(String(data: decrypted, encoding: .utf8), text)
            }
            totalMessages += aliceSends

            for i in 0..<bobSends {
                let text = "Bob[\(totalMessages + i)]"
                let envelope = try bob.encrypt(plaintext: Data(text.utf8))
                let decrypted = try alice.decrypt(envelope: envelope)
                XCTAssertEqual(String(data: decrypted, encoding: .utf8), text)
            }
            totalMessages += bobSends
        }
    }

    // MARK: - Empty Message

    func testEncryptDecrypt_emptyMessage() throws {
        var (alice, bob) = try createSessionPair()

        let envelope = try alice.encrypt(plaintext: Data())
        let decrypted = try bob.decrypt(envelope: envelope)
        XCTAssertEqual(decrypted, Data())
    }

    // MARK: - State

    func testSession_returnsToIdleAfterOperations() throws {
        var (alice, bob) = try createSessionPair()

        XCTAssertEqual(alice.state, .idle)
        let envelope = try alice.encrypt(plaintext: Data("test".utf8))
        XCTAssertEqual(alice.state, .idle)

        _ = try bob.decrypt(envelope: envelope)
        XCTAssertEqual(bob.state, .idle)
    }
}
