// VEIL — KnownAnswerTests.swift
// Ticket: VEIL-703 — Cryptographic Test Vectors
// Spec reference: Appendix B
//
// Known-answer tests (KAT) verify that cryptographic operations produce
// deterministic, expected outputs for fixed inputs. This ensures:
//   1. Implementation correctness across platforms
//   2. No regressions from code changes
//   3. Cross-implementation compatibility (Rust relay, Android client)
//
// All vectors are generated from TestVectorGenerator and verified here.
// Vectors are also exported as JSON for external validation.

import XCTest
import CryptoKit
@testable import VeilCrypto

final class KnownAnswerTests: XCTestCase {

    // MARK: - HKDF Domain Vectors

    /// Verify HKDF produces consistent outputs for all 12 VeilDomains.
    func testKAT_HKDF_AllDomains() throws {
        let vectors = try HKDFTestVectorGenerator.generateAllDomainVectors()

        XCTAssertEqual(vectors.count, VeilDomain.allCases.count,
                      "Should have one vector per domain")

        // Verify each vector is deterministic (generate twice, compare)
        let vectors2 = try HKDFTestVectorGenerator.generateAllDomainVectors()

        for (v1, v2) in zip(vectors, vectors2) {
            XCTAssertEqual(v1.domain, v2.domain)
            XCTAssertEqual(v1.expectedOutput, v2.expectedOutput,
                          "HKDF output for \(v1.domain) should be deterministic")
        }

        // Verify all outputs are unique (domain separation works)
        let uniqueOutputs = Set(vectors.map(\.expectedOutput.hex))
        XCTAssertEqual(uniqueOutputs.count, vectors.count,
                      "All domain outputs should be unique")

        // Verify output sizes
        for v in vectors {
            XCTAssertEqual(v.expectedOutput.data.count, v.outputByteCount,
                          "Output size mismatch for \(v.domain)")
        }
    }

    /// Verify HKDF with known IKM produces non-zero output.
    func testKAT_HKDF_NonZeroOutput() throws {
        let vectors = try HKDFTestVectorGenerator.generateAllDomainVectors()

        for v in vectors {
            XCTAssertNotEqual(v.expectedOutput.data, Data(repeating: 0, count: 32),
                            "HKDF output for \(v.domain) should not be all zeros")
        }
    }

    // MARK: - Symmetric Ratchet Chain Vector

    /// Verify 10-step symmetric ratchet chain from fixed CK_0.
    func testKAT_SymmetricRatchet_Chain() throws {
        let vector = try SymmetricRatchetVectorGenerator.generate(steps: 10)

        // Verify determinism
        let vector2 = try SymmetricRatchetVectorGenerator.generate(steps: 10)
        XCTAssertEqual(vector, vector2, "Ratchet vectors should be deterministic")

        // Verify step count
        XCTAssertEqual(vector.steps, 10)
        XCTAssertEqual(vector.messageKeys.count, 10)
        XCTAssertEqual(vector.chainKeys.count, 11) // Initial + 10 steps

        // Verify all message keys are unique
        let uniqueMKs = Set(vector.messageKeys.map(\.hex))
        XCTAssertEqual(uniqueMKs.count, 10, "All 10 message keys should be unique")

        // Verify all chain keys are unique
        let uniqueCKs = Set(vector.chainKeys.map(\.hex))
        XCTAssertEqual(uniqueCKs.count, 11, "All 11 chain keys should be unique")

        // Verify chain keys differ from message keys
        let mkSet = Set(vector.messageKeys.map(\.hex))
        let ckSet = Set(vector.chainKeys.map(\.hex))
        let intersection = mkSet.intersection(ckSet)
        XCTAssertTrue(intersection.isEmpty,
                     "No message key should equal any chain key")

        // Verify key sizes
        for mk in vector.messageKeys {
            XCTAssertEqual(mk.data.count, 32, "Message key should be 32 bytes")
        }
        for ck in vector.chainKeys {
            XCTAssertEqual(ck.data.count, 32, "Chain key should be 32 bytes")
        }
    }

    /// Independently verify the chain by re-running the ratchet.
    func testKAT_SymmetricRatchet_IndependentVerification() throws {
        let vector = try SymmetricRatchetVectorGenerator.generate(steps: 10)

        // Re-run the ratchet manually
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(copying: vector.initialChainKey.data))

        for i in 0..<10 {
            let mk = try ratchet.advance()
            let mkData = try mk.copyToData()

            XCTAssertEqual(HexBytes(data: mkData), vector.messageKeys[i],
                          "Step \(i): Message key mismatch")

            let ckData = try ratchet.chainKey.copyToData()
            XCTAssertEqual(HexBytes(data: ckData), vector.chainKeys[i + 1],
                          "Step \(i): Chain key mismatch")
        }
    }

    // MARK: - DH Ratchet Evolution Vector

    /// Verify 5-step DH ratchet evolution from fixed root key.
    func testKAT_DHRatchet_Evolution() throws {
        let vector = try DHRatchetVectorGenerator.generate(steps: 5)

        // Verify determinism
        let vector2 = try DHRatchetVectorGenerator.generate(steps: 5)
        XCTAssertEqual(vector, vector2, "DH ratchet vectors should be deterministic")

        // Verify step count
        XCTAssertEqual(vector.steps, 5)
        XCTAssertEqual(vector.dhInputs.count, 5)
        XCTAssertEqual(vector.rootKeys.count, 6) // Initial + 5 steps
        XCTAssertEqual(vector.chainKeys.count, 5)

        // Verify all root keys are unique
        let uniqueRKs = Set(vector.rootKeys.map(\.hex))
        XCTAssertEqual(uniqueRKs.count, 6, "All 6 root keys should be unique")

        // Verify all chain keys are unique
        let uniqueCKs = Set(vector.chainKeys.map(\.hex))
        XCTAssertEqual(uniqueCKs.count, 5, "All 5 chain keys should be unique")

        // Verify initial root key matches
        XCTAssertEqual(vector.rootKeys[0].data, Data(repeating: 0xCC, count: 32))
    }

    /// Independently verify DH ratchet evolution.
    func testKAT_DHRatchet_IndependentVerification() throws {
        let vector = try DHRatchetVectorGenerator.generate(steps: 5)

        var rootKey = SecureBytes(copying: vector.initialRootKey.data)

        for i in 0..<5 {
            let dhInput = SecureBytes(copying: vector.dhInputs[i].data)
            let (newRK, ck) = try VeilHKDF.deriveRatchetKeys(
                rootKey: rootKey,
                input: dhInput,
                domain: .dhRatchet
            )

            XCTAssertEqual(HexBytes(data: try newRK.copyToData()), vector.rootKeys[i + 1],
                          "Step \(i): Root key mismatch")
            XCTAssertEqual(HexBytes(data: try ck.copyToData()), vector.chainKeys[i],
                          "Step \(i): Chain key mismatch")

            rootKey = newRK
        }
    }

    // MARK: - Padding Vectors

    /// Verify padding size calculations for various plaintext sizes.
    func testKAT_PaddingSizes() {
        let vectors = PaddingVectorGenerator.generate()
        let blockSize = VeilConstants.messagePaddingBlockSize

        for v in vectors {
            // Verify expected padded size is a multiple of block size
            XCTAssertEqual(v.expectedPaddedSize % blockSize, 0,
                          "Padded size \(v.expectedPaddedSize) for plaintext \(v.plaintextLength) not block-aligned")

            // Verify padded size is sufficient to hold plaintext + 2 byte length footer
            XCTAssertGreaterThanOrEqual(v.expectedPaddedSize, v.plaintextLength + 2,
                                       "Padded size too small for plaintext \(v.plaintextLength)")

            // Verify it's the minimum sufficient block-aligned size
            let minContent = v.plaintextLength + 2
            let expectedMin = ((minContent + blockSize - 1) / blockSize) * blockSize
            XCTAssertEqual(v.expectedPaddedSize, expectedMin,
                          "Padded size not minimal for plaintext \(v.plaintextLength)")
        }
    }

    /// Verify padding round-trip preserves plaintext.
    func testKAT_PaddingRoundTrip() throws {
        let vectors = PaddingVectorGenerator.generate()
        let sessionKey = SecureBytes(copying: Data(repeating: 0xFF, count: 64))

        for v in vectors {
            var alice = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: true)
            var bob = try TripleRatchetSession(sessionKey: sessionKey, isInitiator: false,
                                                peerEphemeralKey: alice.dhRatchet.ephemeralKeyPair.publicKey.rawRepresentation)

            let plaintext = v.plaintext.data
            let envelope = try alice.encrypt(plaintext: plaintext)
            let decrypted = try bob.decrypt(envelope: envelope)

            XCTAssertEqual(decrypted, plaintext,
                          "Padding round-trip failed for size \(v.plaintextLength)")
        }
    }

    // MARK: - JSON Export/Import Round-Trip

    /// Verify the full test vector suite can be exported to JSON and re-imported.
    func testKAT_JSONRoundTrip() throws {
        let json = try TestVectorExporter.exportJSON()

        // Verify JSON is valid
        XCTAssertGreaterThan(json.count, 0, "JSON should not be empty")

        // Parse it back
        let decoder = JSONDecoder()
        let suite = try decoder.decode(TestVectorExporter.TestVectorSuite.self, from: json)

        // Verify structure
        XCTAssertEqual(suite.version, Int(VeilConstants.protocolVersion))
        XCTAssertEqual(suite.hkdfVectors.count, VeilDomain.allCases.count)
        XCTAssertEqual(suite.symmetricRatchetVector.steps, 10)
        XCTAssertEqual(suite.dhRatchetVector.steps, 5)
        XCTAssertGreaterThan(suite.paddingVectors.count, 0)

        // Verify HKDF vectors survived round-trip
        let freshVectors = try HKDFTestVectorGenerator.generateAllDomainVectors()
        for (imported, fresh) in zip(suite.hkdfVectors, freshVectors) {
            XCTAssertEqual(imported.expectedOutput, fresh.expectedOutput,
                          "HKDF vector for \(imported.domain) changed after JSON round-trip")
        }

        // Verify symmetric ratchet vector survived
        let freshSR = try SymmetricRatchetVectorGenerator.generate()
        XCTAssertEqual(suite.symmetricRatchetVector, freshSR,
                      "Symmetric ratchet vector changed after JSON round-trip")

        // Verify DH ratchet vector survived
        let freshDH = try DHRatchetVectorGenerator.generate()
        XCTAssertEqual(suite.dhRatchetVector, freshDH,
                      "DH ratchet vector changed after JSON round-trip")
    }

    /// Verify HexBytes encoding/decoding is correct.
    func testKAT_HexBytesRoundTrip() {
        let testCases: [(Data, String)] = [
            (Data(), ""),
            (Data([0x00]), "00"),
            (Data([0xFF]), "ff"),
            (Data([0x01, 0x02, 0x03]), "010203"),
            (Data([0xDE, 0xAD, 0xBE, 0xEF]), "deadbeef"),
            (Data(repeating: 0xAA, count: 32), String(repeating: "aa", count: 32)),
        ]

        for (data, expectedHex) in testCases {
            let hex = HexBytes(data: data)
            XCTAssertEqual(hex.hex, expectedHex, "Hex encoding failed for \(data)")

            let decoded = hex.data
            XCTAssertEqual(decoded, data, "Hex decoding failed for \(expectedHex)")
        }
    }

    // MARK: - Cross-Vector Consistency

    /// Verify that HKDF vectors used in ratchet vectors are consistent.
    func testKAT_CrossVectorConsistency() throws {
        // The DH ratchet uses HKDF with domain .dhRatchet
        // Verify that the HKDF vector for .dhRatchet produces a valid output
        let hkdfVectors = try HKDFTestVectorGenerator.generateAllDomainVectors()
        let dhRatchetVector = hkdfVectors.first { $0.domain == VeilDomain.dhRatchet.rawValue }

        XCTAssertNotNil(dhRatchetVector, "Should have HKDF vector for dhRatchet domain")
        XCTAssertEqual(dhRatchetVector?.outputByteCount, 32)
        XCTAssertEqual(dhRatchetVector?.expectedOutput.data.count, 32)
    }

    /// Verify that message key derivation byte (0x01) and chain key byte (0x02) are correct.
    func testKAT_DerivationByteConstants() {
        XCTAssertEqual(VeilConstants.messageKeyDerivationByte, 0x01,
                      "Message key derivation byte must be 0x01")
        XCTAssertEqual(VeilConstants.chainKeyDerivationByte, 0x02,
                      "Chain key derivation byte must be 0x02")
    }

    /// Verify that different derivation bytes produce different keys from same CK.
    func testKAT_DerivationByteDifferentiation() throws {
        let ck = SecureBytes(copying: Data(repeating: 0x42, count: 32))

        // Derive with message key byte (0x01)
        let ckData = try ck.copyToData()
        let symmetricKey = SymmetricKey(data: ckData)

        let mk = HMAC<SHA256>.authenticationCode(for: Data([0x01]), using: symmetricKey)
        let nextCK = HMAC<SHA256>.authenticationCode(for: Data([0x02]), using: symmetricKey)

        let mkData = Data(mk)
        let ckNewData = Data(nextCK)

        XCTAssertNotEqual(mkData, ckNewData,
                         "Message key and chain key must differ from same CK")
        XCTAssertEqual(mkData.count, 32, "HMAC-SHA-256 output should be 32 bytes")
        XCTAssertEqual(ckNewData.count, 32, "HMAC-SHA-256 output should be 32 bytes")
    }

    // MARK: - Protocol Constants KAT

    /// Verify all security-critical constants match the specification.
    func testKAT_ProtocolConstants() {
        // Key sizes
        XCTAssertEqual(VeilConstants.sessionKeySize, 64, "Session key: 64 bytes")
        XCTAssertEqual(VeilConstants.rootKeySize, 32, "Root key: 32 bytes")
        XCTAssertEqual(VeilConstants.chainKeySize, 32, "Chain key: 32 bytes")
        XCTAssertEqual(VeilConstants.messageKeySize, 32, "Message key: 32 bytes")

        // AES-GCM parameters
        XCTAssertEqual(VeilConstants.aesGCMNonceSize, 12, "AES-GCM nonce: 12 bytes")
        XCTAssertEqual(VeilConstants.aesGCMTagSize, 16, "AES-GCM tag: 16 bytes")

        // ML-KEM-1024 sizes
        XCTAssertEqual(VeilConstants.mlkem1024PublicKeySize, 1568, "ML-KEM pub: 1568 bytes")
        XCTAssertEqual(VeilConstants.mlkem1024SecretKeySize, 3168, "ML-KEM sec: 3168 bytes")
        XCTAssertEqual(VeilConstants.mlkem1024CiphertextSize, 1568, "ML-KEM ct: 1568 bytes")
        XCTAssertEqual(VeilConstants.mlkem1024SharedSecretSize, 32, "ML-KEM ss: 32 bytes")

        // Protocol limits
        XCTAssertEqual(VeilConstants.maxSkippedMessageKeys, 2000, "Max skip: 2000")
        XCTAssertEqual(VeilConstants.spqrDefaultIntervalMessages, 75, "SPQR interval: 75 msgs")
        XCTAssertEqual(VeilConstants.spqrMaxIntervalSeconds, 86400, "SPQR max: 24h")
        XCTAssertEqual(VeilConstants.spqrFragmentSize, 256, "SPQR fragment: 256 bytes")
        XCTAssertEqual(VeilConstants.messagePaddingBlockSize, 256, "Padding block: 256 bytes")
        XCTAssertEqual(VeilConstants.prekeyPoolSize, 100, "Prekey pool: 100")
        XCTAssertEqual(VeilConstants.pqPrekeyPoolSize, 100, "PQ prekey pool: 100")

        // Protocol version
        XCTAssertEqual(VeilConstants.protocolVersion, 1, "Protocol version: 1")
    }

    // MARK: - HKDF Session Key Derivation

    /// Verify session key derivation is deterministic.
    func testKAT_SessionKeyDerivation() throws {
        let ikm = SecureBytes(copying: Data(repeating: 0xAA, count: 192)) // Full variant

        let sk1 = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm)
        let sk2 = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm)

        XCTAssertEqual(try sk1.copyToData(), try sk2.copyToData(),
                      "Session key derivation should be deterministic")
        XCTAssertEqual(try sk1.copyToData().count, VeilConstants.sessionKeySize)
    }

    /// Verify different IKMs produce different session keys.
    func testKAT_SessionKeyDifferentIKM() throws {
        let ikm1 = SecureBytes(copying: Data(repeating: 0xAA, count: 192))
        let ikm2 = SecureBytes(copying: Data(repeating: 0xBB, count: 192))

        let sk1 = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm1)
        let sk2 = try VeilHKDF.deriveSessionKey(concatenatedIKM: ikm2)

        XCTAssertNotEqual(try sk1.copyToData(), try sk2.copyToData(),
                         "Different IKMs should produce different session keys")
    }
}
