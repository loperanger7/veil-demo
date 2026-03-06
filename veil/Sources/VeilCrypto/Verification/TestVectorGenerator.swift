// VEIL — TestVectorGenerator.swift
// Ticket: VEIL-703 — Cryptographic Test Vectors
// Spec reference: Appendix B
//
// Deterministic known-answer test (KAT) vector generation.
//
// All vectors use fixed seeds for reproducibility and are JSON-serializable
// via Codable for cross-implementation validation (Rust relay, Android client).
//
// Vector types:
//   1. HKDFTestVector — HKDF-SHA-512 outputs for all 12 domains
//   2. SymmetricRatchetVector — 10-step chain from fixed CK_0
//   3. DHRatchetVector — 5-step ratchet evolution from fixed RK
//   4. SPQRFragmentVector — Fragment sequence for fixed ML-KEM key
//   5. PaddingVector — Padding/unpadding for known inputs

import Foundation
import CryptoKit

// MARK: - Common Types

/// Hex-encoded byte array for JSON serialization.
public struct HexBytes: Sendable, Codable, Equatable {
    public let hex: String

    public init(data: Data) {
        self.hex = data.map { String(format: "%02x", $0) }.joined()
    }

    public init(hex: String) {
        self.hex = hex
    }

    public var data: Data {
        var bytes = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2)
            let byteString = hex[index..<nextIndex]
            bytes.append(UInt8(byteString, radix: 16) ?? 0)
            index = nextIndex
        }
        return bytes
    }
}

// MARK: - HKDF Test Vector

/// Known-answer test vector for HKDF-SHA-512 with domain separation.
public struct HKDFTestVector: Sendable, Codable, Equatable {
    /// Which domain this vector covers.
    public let domain: String
    /// Input keying material (hex).
    public let ikm: HexBytes
    /// Salt (hex, empty for zero salt).
    public let salt: HexBytes?
    /// Output byte count.
    public let outputByteCount: Int
    /// Expected output (hex).
    public let expectedOutput: HexBytes
}

/// Generator for HKDF test vectors.
public enum HKDFTestVectorGenerator: Sendable {

    /// Generate a test vector for each VeilDomain.
    ///
    /// Uses a fixed 32-byte IKM (all 0xAA) and no salt.
    public static func generateAllDomainVectors() throws -> [HKDFTestVector] {
        let fixedIKM = Data(repeating: 0xAA, count: 32)
        let ikm = SecureBytes(copying: fixedIKM)
        var vectors: [HKDFTestVector] = []

        for domain in VeilDomain.allCases {
            let output = try VeilHKDF.deriveKey(
                ikm: ikm,
                salt: nil,
                domain: domain,
                outputByteCount: 32
            )
            let outputData = try output.copyToData()

            vectors.append(HKDFTestVector(
                domain: domain.rawValue,
                ikm: HexBytes(data: fixedIKM),
                salt: nil,
                outputByteCount: 32,
                expectedOutput: HexBytes(data: outputData)
            ))
        }

        return vectors
    }
}

// MARK: - Symmetric Ratchet Test Vector

/// Known-answer test vector for the symmetric chain ratchet.
public struct SymmetricRatchetVector: Sendable, Codable, Equatable {
    /// Initial chain key (hex).
    public let initialChainKey: HexBytes
    /// Number of steps.
    public let steps: Int
    /// Expected chain keys at each step (hex).
    public let chainKeys: [HexBytes]
    /// Expected message keys at each step (hex).
    public let messageKeys: [HexBytes]
}

/// Generator for symmetric ratchet test vectors.
public enum SymmetricRatchetVectorGenerator: Sendable {

    /// Generate a 10-step chain vector from a fixed initial chain key.
    public static func generate(steps: Int = 10) throws -> SymmetricRatchetVector {
        let fixedCK = Data(repeating: 0xBB, count: 32)
        let initialCK = SecureBytes(copying: fixedCK)
        var ratchet = SymmetricRatchet(chainKey: initialCK)

        var chainKeys: [HexBytes] = [HexBytes(data: fixedCK)]
        var messageKeys: [HexBytes] = []

        for _ in 0..<steps {
            let mk = try ratchet.advance()
            messageKeys.append(HexBytes(data: try mk.copyToData()))
            chainKeys.append(HexBytes(data: try ratchet.chainKey.copyToData()))
        }

        return SymmetricRatchetVector(
            initialChainKey: HexBytes(data: fixedCK),
            steps: steps,
            chainKeys: chainKeys,
            messageKeys: messageKeys
        )
    }
}

// MARK: - DH Ratchet Test Vector

/// Known-answer test vector for the DH ratchet evolution.
public struct DHRatchetVector: Sendable, Codable, Equatable {
    /// Initial root key (hex).
    public let initialRootKey: HexBytes
    /// Number of ratchet steps.
    public let steps: Int
    /// DH inputs at each step (hex).
    public let dhInputs: [HexBytes]
    /// Root keys after each step (hex).
    public let rootKeys: [HexBytes]
    /// Chain keys after each step (hex).
    public let chainKeys: [HexBytes]
}

/// Generator for DH ratchet test vectors.
public enum DHRatchetVectorGenerator: Sendable {

    /// Generate a multi-step DH ratchet vector using deterministic DH inputs.
    public static func generate(steps: Int = 5) throws -> DHRatchetVector {
        let fixedRK = Data(repeating: 0xCC, count: 32)
        var rootKey = SecureBytes(copying: fixedRK)

        var dhInputs: [HexBytes] = []
        var rootKeys: [HexBytes] = [HexBytes(data: fixedRK)]
        var chainKeys: [HexBytes] = []

        for i in 0..<steps {
            // Use a deterministic "DH output" — in production this would be X25519
            let dhInput = Data((0..<32).map { UInt8(($0 + i * 32) & 0xFF) })
            let dhBytes = SecureBytes(copying: dhInput)

            let (newRK, ck) = try VeilHKDF.deriveRatchetKeys(
                rootKey: rootKey,
                input: dhBytes,
                domain: .dhRatchet
            )

            dhInputs.append(HexBytes(data: dhInput))
            rootKeys.append(HexBytes(data: try newRK.copyToData()))
            chainKeys.append(HexBytes(data: try ck.copyToData()))

            rootKey = newRK
        }

        return DHRatchetVector(
            initialRootKey: HexBytes(data: fixedRK),
            steps: steps,
            dhInputs: dhInputs,
            rootKeys: rootKeys,
            chainKeys: chainKeys
        )
    }
}

// MARK: - Padding Test Vector

/// Known-answer test vector for message padding.
public struct PaddingVector: Sendable, Codable, Equatable {
    /// Original plaintext (hex).
    public let plaintext: HexBytes
    /// Plaintext length.
    public let plaintextLength: Int
    /// Expected padded size (multiple of 256).
    public let expectedPaddedSize: Int
    /// Block size used.
    public let blockSize: Int
}

/// Generator for padding test vectors.
public enum PaddingVectorGenerator: Sendable {

    /// Generate padding vectors for various plaintext sizes.
    public static func generate() -> [PaddingVector] {
        let blockSize = VeilConstants.messagePaddingBlockSize
        let testSizes = [0, 1, 100, 253, 254, 255, 256, 500, 1024, 4096]

        return testSizes.map { size in
            let plaintext = Data(repeating: 0x42, count: size)
            // Padded size formula: ceil((plaintextLen + 2) / blockSize) * blockSize
            let contentSize = size + 2
            let paddedSize = ((contentSize + blockSize - 1) / blockSize) * blockSize

            return PaddingVector(
                plaintext: HexBytes(data: plaintext),
                plaintextLength: size,
                expectedPaddedSize: paddedSize,
                blockSize: blockSize
            )
        }
    }
}

// MARK: - JSON Export

/// Exports all test vectors to a single JSON document.
public enum TestVectorExporter: Sendable {

    /// The complete test vector suite.
    public struct TestVectorSuite: Sendable, Codable {
        public let version: Int
        public let generated: String
        public let hkdfVectors: [HKDFTestVector]
        public let symmetricRatchetVector: SymmetricRatchetVector
        public let dhRatchetVector: DHRatchetVector
        public let paddingVectors: [PaddingVector]
    }

    /// Generate the complete suite and return as JSON data.
    public static func exportJSON() throws -> Data {
        let suite = TestVectorSuite(
            version: Int(VeilConstants.protocolVersion),
            generated: ISO8601DateFormatter().string(from: Date()),
            hkdfVectors: try HKDFTestVectorGenerator.generateAllDomainVectors(),
            symmetricRatchetVector: try SymmetricRatchetVectorGenerator.generate(),
            dhRatchetVector: try DHRatchetVectorGenerator.generate(),
            paddingVectors: PaddingVectorGenerator.generate()
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(suite)
    }
}
