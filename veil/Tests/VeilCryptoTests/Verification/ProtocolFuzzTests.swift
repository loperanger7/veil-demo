// VEIL — ProtocolFuzzTests.swift
// Ticket: VEIL-702 — Fuzz Testing
// Spec reference: Section 9.3
//
// Structured fuzzing of protocol boundaries. Every test feeds malformed,
// random, or adversarial inputs to protocol functions and verifies:
//   - No crashes (the most important invariant)
//   - Clean error propagation (specific error types, not generic crashes)
//   - No buffer overflows, no memory corruption
//
// Uses structured random generation rather than pure random bytes for
// better coverage of interesting edge cases.

import XCTest
import CryptoKit
@testable import VeilCrypto

final class ProtocolFuzzTests: XCTestCase {

    // MARK: - Envelope Fuzzing

    /// Feed random bytes as a TripleRatchet envelope — must throw, not crash.
    func testFuzz_MalformedEnvelope_RandomBytes() throws {
        let sessionKey = SecureBytes(copying: Data(repeating: 0xAA, count: 64))
        var session = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: false)

        for size in [0, 1, 10, 31, 32, 33, 40, 100, 256, 1024] {
            var randomData = Data(count: size)
            if size > 0 {
                randomData.withUnsafeMutableBytes { ptr in
                    _ = SecRandomCopyBytes(kSecRandomDefault, size, ptr.baseAddress!)
                }
            }

            // Create a fake envelope
            let fakeEnvelope = TripleRatchetSession.Envelope(
                ephemeralKey: randomData.count >= 32 ? Data(randomData.prefix(32)) : Data(repeating: 0, count: 32),
                messageIndex: 0,
                previousChainLength: 0,
                spqrFragment: nil,
                ciphertext: randomData
            )

            // Should throw (decryption failure), not crash
            XCTAssertThrowsError(try session.decrypt(envelope: fakeEnvelope),
                                "Size \(size): Should throw on random ciphertext")
        }
    }

    /// Feed envelopes with zero-length ciphertext.
    func testFuzz_EmptyCiphertext() throws {
        let sessionKey = SecureBytes(copying: Data(repeating: 0xBB, count: 64))
        var session = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: false)

        let emptyEnvelope = TripleRatchetSession.Envelope(
            ephemeralKey: Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation,
            messageIndex: 0,
            previousChainLength: 0,
            spqrFragment: nil,
            ciphertext: Data()
        )

        XCTAssertThrowsError(try session.decrypt(envelope: emptyEnvelope),
                            "Empty ciphertext should throw")
    }

    // MARK: - Invalid Ephemeral Key Fuzzing

    /// Feed zero key, max key, and wrong-length keys as ephemeral keys.
    func testFuzz_InvalidEphemeralKeys() throws {
        let invalidKeys: [(String, Data)] = [
            ("zero key", Data(repeating: 0x00, count: 32)),
            ("max key", Data(repeating: 0xFF, count: 32)),
            ("short key", Data(repeating: 0x42, count: 16)),
            ("long key", Data(repeating: 0x42, count: 64)),
            ("empty key", Data()),
            ("one byte", Data([0x01])),
        ]

        for (name, keyData) in invalidKeys {
            // Try to create a Curve25519 public key from invalid data
            if keyData.count == 32 {
                // CryptoKit may accept any 32 bytes as an X25519 key (it's lenient)
                // But using it in a session context should still be handled gracefully
                let _ = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData)
                // No crash = pass
            } else {
                // Wrong size should throw
                XCTAssertThrowsError(
                    try Curve25519.KeyAgreement.PublicKey(rawRepresentation: keyData),
                    "\(name): Wrong-length key should throw"
                )
            }
        }
    }

    // MARK: - Corrupted Ciphertext Fuzzing

    /// Bit-flip a valid ciphertext and verify decryption fails with authentication error.
    func testFuzz_CorruptedCiphertext_BitFlip() throws {
        let sessionKey = SecureBytes(copying: Data(repeating: 0xCC, count: 64))
        var aliceSession = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: true)
        var bobSession = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: false,
                                                   peerEphemeralKey: aliceSession.dhRatchet.ephemeralKeyPair.publicKey.rawRepresentation)

        // Alice encrypts
        let envelope = try aliceSession.encrypt(plaintext: Data("secret message".utf8))

        // Flip bits at various positions in the ciphertext
        for position in stride(from: 0, to: min(envelope.ciphertext.count, 100), by: 7) {
            var corrupted = envelope.ciphertext
            corrupted[position] ^= 0xFF // Flip all bits at this byte

            let corruptedEnvelope = TripleRatchetSession.Envelope(
                ephemeralKey: envelope.ephemeralKey,
                messageIndex: envelope.messageIndex,
                previousChainLength: envelope.previousChainLength,
                spqrFragment: envelope.spqrFragment,
                ciphertext: corrupted
            )

            XCTAssertThrowsError(try bobSession.decrypt(envelope: corruptedEnvelope),
                                "Bit-flip at position \(position) should cause decryption failure")
        }
    }

    /// Truncate a valid ciphertext at various lengths.
    func testFuzz_TruncatedCiphertext() throws {
        let sessionKey = SecureBytes(copying: Data(repeating: 0xDD, count: 64))
        var aliceSession = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: true)
        var bobSession = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: false,
                                                   peerEphemeralKey: aliceSession.dhRatchet.ephemeralKeyPair.publicKey.rawRepresentation)

        let envelope = try aliceSession.encrypt(plaintext: Data("hello world test message".utf8))

        // Try decrypting with progressively shorter ciphertext
        for truncLength in [0, 1, 10, 20, envelope.ciphertext.count / 2, envelope.ciphertext.count - 1] {
            let truncated = Data(envelope.ciphertext.prefix(truncLength))
            let truncEnvelope = TripleRatchetSession.Envelope(
                ephemeralKey: envelope.ephemeralKey,
                messageIndex: envelope.messageIndex,
                previousChainLength: envelope.previousChainLength,
                spqrFragment: envelope.spqrFragment,
                ciphertext: truncated
            )

            XCTAssertThrowsError(try bobSession.decrypt(envelope: truncEnvelope),
                                "Truncated to \(truncLength) bytes should fail")
        }
    }

    // MARK: - Oversized Message Fuzzing

    /// Verify that padding handles messages near the block boundary correctly.
    func testFuzz_MessageSizesBoundaries() throws {
        let sessionKey = SecureBytes(copying: Data(repeating: 0xEE, count: 64))

        let blockSize = VeilConstants.messagePaddingBlockSize
        let testSizes = [
            0, 1,
            blockSize - 3, blockSize - 2, blockSize - 1,
            blockSize, blockSize + 1,
            blockSize * 2 - 3, blockSize * 2,
            blockSize * 10,
        ]

        for size in testSizes {
            var alice = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: true)
            var bob = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: false,
                                                peerEphemeralKey: alice.dhRatchet.ephemeralKeyPair.publicKey.rawRepresentation)

            let plaintext = Data(repeating: 0x42, count: size)
            let envelope = try alice.encrypt(plaintext: plaintext)
            let decrypted = try bob.decrypt(envelope: envelope)

            XCTAssertEqual(decrypted, plaintext,
                          "Size \(size): Round-trip should preserve plaintext")

            // Verify ciphertext is padded to block boundary
            // (ciphertext includes AES-GCM nonce + tag, so check padded portion)
            let overhead = VeilConstants.aesGCMNonceSize + VeilConstants.aesGCMTagSize
            let paddedSize = envelope.ciphertext.count - overhead
            XCTAssertEqual(paddedSize % blockSize, 0,
                          "Size \(size): Padded size should be multiple of \(blockSize)")
        }
    }

    // MARK: - Invalid Prekey Bundle Fuzzing

    /// Verify that bundles with wrong signature sizes are rejected.
    func testFuzz_InvalidSignatureSizes() throws {
        let identity = Curve25519.Signing.PrivateKey()
        let spk = Curve25519.KeyAgreement.PrivateKey()
        let pqSPK = try MLKEM1024KeyPair.generate()

        let wrongSigSizes: [Int] = [0, 1, 32, 63, 65, 128]

        for sigSize in wrongSigSizes {
            let fakeSig = Data(repeating: 0x42, count: sigSize)

            let bundle = PrekeyBundle(
                identityKeyEd25519: identity.publicKey.rawRepresentation,
                identityKeyMLDSA: Data(repeating: 0, count: VeilConstants.mldsa65PublicKeySize),
                signedPrekeyId: 1,
                signedPrekey: spk.publicKey.rawRepresentation,
                signedPrekeySig: fakeSig,
                pqSignedPrekey: pqSPK.publicKey,
                pqSignedPrekeySig: fakeSig,
                oneTimePrekeys: [],
                pqOneTimePrekeys: []
            )

            // Should either return false or the subsequent PQXDH should throw
            let valid = bundle.verifySignatures()
            if valid {
                // If somehow verified (shouldn't), PQXDH should still work
                // This path shouldn't be reached for wrong sizes
                XCTFail("Bundle with \(sigSize)-byte signature should not verify")
            }
        }
    }

    /// Verify that bundles with corrupt key material are rejected.
    func testFuzz_CorruptKeyMaterial() throws {
        let identity = Curve25519.Signing.PrivateKey()
        let spk = Curve25519.KeyAgreement.PrivateKey()
        let pqSPK = try MLKEM1024KeyPair.generate()
        let spkSig = try identity.signature(for: spk.publicKey.rawRepresentation)
        let pqSig = try identity.signature(for: pqSPK.publicKey)

        // Valid bundle but corrupt the PQ signed prekey
        var corruptPQ = pqSPK.publicKey
        if corruptPQ.count > 0 {
            corruptPQ[0] ^= 0xFF
        }

        let corruptBundle = PrekeyBundle(
            identityKeyEd25519: identity.publicKey.rawRepresentation,
            identityKeyMLDSA: Data(repeating: 0, count: VeilConstants.mldsa65PublicKeySize),
            signedPrekeyId: 1,
            signedPrekey: spk.publicKey.rawRepresentation,
            signedPrekeySig: spkSig,
            pqSignedPrekey: corruptPQ,
            pqSignedPrekeySig: pqSig,
            oneTimePrekeys: [],
            pqOneTimePrekeys: []
        )

        // Signature should fail because PQ key was modified after signing
        XCTAssertFalse(corruptBundle.verifySignatures(),
                      "Corrupt PQ key should fail signature verification")
    }

    // MARK: - HKDF Edge Cases

    /// Fuzz HKDF with various IKM sizes.
    func testFuzz_HKDF_VariousIKMSizes() throws {
        let testSizes = [1, 16, 32, 64, 128, 256, 1024]

        for size in testSizes {
            let ikm = SecureBytes(copying: Data(repeating: 0x42, count: size))
            let output = try VeilHKDF.deriveKey(ikm: ikm, domain: .pqxdh, outputByteCount: 32)
            let data = try output.copyToData()

            XCTAssertEqual(data.count, 32, "HKDF output should be 32 bytes for IKM size \(size)")
            XCTAssertNotEqual(data, Data(repeating: 0, count: 32),
                            "HKDF output should not be all zeros for IKM size \(size)")
        }
    }

    /// Verify HKDF produces different outputs for different domains with same IKM.
    func testFuzz_HKDF_DomainDifferentiation() throws {
        let ikm = SecureBytes(copying: Data(repeating: 0x55, count: 32))
        var outputs: [String: Data] = [:]

        for domain in VeilDomain.allCases {
            let output = try VeilHKDF.deriveKey(ikm: ikm, domain: domain, outputByteCount: 32)
            let data = try output.copyToData()

            // Check for uniqueness
            for (existingDomain, existingData) in outputs {
                XCTAssertNotEqual(data, existingData,
                                "\(domain.rawValue) and \(existingDomain) produce same output")
            }

            outputs[domain.rawValue] = data
        }

        XCTAssertEqual(outputs.count, VeilDomain.allCases.count,
                      "All domains should produce unique outputs")
    }

    /// Verify HKDF with salt vs without salt produces different outputs.
    func testFuzz_HKDF_SaltVariation() throws {
        let ikm = SecureBytes(copying: Data(repeating: 0x66, count: 32))

        let noSalt = try VeilHKDF.deriveKey(ikm: ikm, salt: nil, domain: .pqxdh)
        let withSalt = try VeilHKDF.deriveKey(
            ikm: ikm,
            salt: SecureBytes(copying: Data(repeating: 0x77, count: 32)),
            domain: .pqxdh
        )

        XCTAssertNotEqual(try noSalt.copyToData(), try withSalt.copyToData(),
                         "Different salts should produce different outputs")
    }

    // MARK: - Session State Fuzzing

    /// Verify that decrypting with wrong session key fails cleanly.
    func testFuzz_WrongSessionKey() throws {
        let sk1 = SecureBytes(copying: Data(repeating: 0x11, count: 64))
        let sk2 = SecureBytes(copying: Data(repeating: 0x22, count: 64))

        var alice = try TripleRatchetSession(sessionKey: sk1, isInitiator: true)
        var bob = try TripleRatchetSession(sessionKey: sk2, isInitiator: false) // Wrong key!

        let envelope = try alice.encrypt(plaintext: Data("test".utf8))

        // Bob has wrong key — decryption should fail
        XCTAssertThrowsError(try bob.decrypt(envelope: envelope),
                            "Decryption with wrong session key should fail")
    }

    /// Verify that re-encrypting with a consumed session doesn't crash.
    func testFuzz_MultipleEncryptions() throws {
        let sk = SecureBytes(copying: Data(repeating: 0x33, count: 64))
        var session = try TripleRatchetSession(sessionKey: sk, isInitiator: true)

        // Encrypt 100 messages in sequence — should not crash or leak
        for i in 0..<100 {
            let plaintext = Data("message \(i)".utf8)
            let _ = try session.encrypt(plaintext: plaintext)
        }
    }
}
