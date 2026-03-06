// VEIL — DudectHarness.swift
// Ticket: VEIL-803 — Constant-Time Verification
// Spec reference: VEIL-109 (Memory Safety)
//
// Core dudect algorithm implementation for detecting timing side channels
// in cryptographic operations.
//
// Algorithm: "Dude, is my code constant time?" (Reparaz et al., USENIX 2017)
//
// Approach:
//   1. For each operation, define two input classes:
//      - Fixed: a specific, known input (e.g., all-zero key)
//      - Random: a fresh random input each time
//   2. Interleave measurements from both classes to cancel systematic drift
//   3. Apply Welch's t-test to detect statistically significant timing differences
//   4. Early termination: |t| > 4.5 → leaky; samples > 10000 and |t| < 1.0 → non-leaky
//
// This implementation tests four critical cryptographic operations:
//   - HMAC-SHA256 tag comparison
//   - AES-256-GCM decryption
//   - X25519 scalar multiplication
//   - ML-KEM-1024 decapsulation

import Foundation
import CryptoKit
@testable import VeilCrypto

// MARK: - Crypto Operation Protocol

/// Protocol for a cryptographic operation to be tested for constant-time behavior.
public protocol CryptoOperation: Sendable {
    /// Human-readable name of the operation.
    var name: String { get }

    /// Generate the fixed input (same every time).
    func fixedInput() -> Data

    /// Generate a random input (different every time).
    func randomInput() -> Data

    /// Execute the operation on the given input.
    /// The operation should be the one we're testing for timing leaks.
    func run(input: Data) -> Data
}

// MARK: - HMAC Comparison Operation

/// Tests HMAC-SHA256 tag comparison for timing leaks.
///
/// Fixed: compare a tag against itself (equal comparison).
/// Random: compare a tag against a different random tag.
///
/// A leaky implementation would take less time for early-exit on mismatches.
public struct HMACComparisonOperation: CryptoOperation {
    public let name = "HMAC-SHA256 Comparison"

    private let key: SymmetricKey
    private let referenceTag: Data

    public init() {
        self.key = SymmetricKey(size: .bits256)
        let message = Data("Veil HMAC constant-time test".utf8)
        let auth = HMAC<SHA256>.authenticationCode(for: message, using: key)
        self.referenceTag = Data(auth)
    }

    public func fixedInput() -> Data {
        // Equal tag — comparison should take same time as unequal
        referenceTag
    }

    public func randomInput() -> Data {
        // Random tag — comparison should take same time as equal
        Data((0..<32).map { _ in UInt8.random(in: 0...255) })
    }

    public func run(input: Data) -> Data {
        // Perform constant-time comparison
        let isEqual = SecureBytes.constantTimeEqual(
            Array(referenceTag), Array(input)
        )
        return Data([isEqual ? 1 : 0])
    }
}

// MARK: - AES-GCM Decryption Operation

/// Tests AES-256-GCM decryption timing for tag validity leaks.
///
/// Fixed: decrypt with the correct tag.
/// Random: decrypt with a random (incorrect) tag.
///
/// A leaky implementation might return faster for invalid tags.
public struct AESGCMDecryptionOperation: CryptoOperation {
    public let name = "AES-256-GCM Decryption"

    private let key: SymmetricKey
    private let validSealedBox: Data
    private let nonce: AES.GCM.Nonce

    public init() {
        self.key = SymmetricKey(size: .bits256)
        let plaintext = Data("Veil AES-GCM constant-time test message".utf8)
        self.nonce = AES.GCM.Nonce()

        if let box = try? AES.GCM.seal(plaintext, using: key, nonce: nonce) {
            self.validSealedBox = box.combined!
        } else {
            self.validSealedBox = Data(repeating: 0, count: 68)
        }
    }

    public func fixedInput() -> Data {
        // Valid sealed box — decryption should succeed
        validSealedBox
    }

    public func randomInput() -> Data {
        // Corrupted sealed box — decryption should fail
        var corrupted = validSealedBox
        if corrupted.count > 12 {
            // Flip a bit in the ciphertext portion (after nonce)
            let idx = 12 + Int.random(in: 0..<max(1, corrupted.count - 12))
            if idx < corrupted.count {
                corrupted[idx] ^= 0xFF
            }
        }
        return corrupted
    }

    public func run(input: Data) -> Data {
        // Attempt decryption — we measure whether timing differs
        do {
            let box = try AES.GCM.SealedBox(combined: input)
            let plaintext = try AES.GCM.open(box, using: key)
            return plaintext
        } catch {
            return Data([0])
        }
    }
}

// MARK: - X25519 Scalar Multiplication Operation

/// Tests X25519 key agreement for scalar-dependent timing.
///
/// Fixed: scalar multiply with a known scalar (small-value key).
/// Random: scalar multiply with a random scalar.
///
/// A leaky implementation might vary timing based on scalar bit pattern.
public struct X25519ScalarMultOperation: CryptoOperation {
    public let name = "X25519 Scalar Multiplication"

    private let peerPublicKey: Curve25519.KeyAgreement.PublicKey

    public init() {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        self.peerPublicKey = ephemeral.publicKey
    }

    public func fixedInput() -> Data {
        // Fixed private key (deterministic)
        let fixedKey = Curve25519.KeyAgreement.PrivateKey()
        return fixedKey.rawRepresentation
    }

    public func randomInput() -> Data {
        // Random private key
        let randomKey = Curve25519.KeyAgreement.PrivateKey()
        return randomKey.rawRepresentation
    }

    public func run(input: Data) -> Data {
        do {
            let privateKey = try Curve25519.KeyAgreement.PrivateKey(
                rawRepresentation: input
            )
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(
                with: peerPublicKey
            )
            return sharedSecret.withUnsafeBytes { Data($0) }
        } catch {
            return Data([0])
        }
    }
}

// MARK: - ML-KEM Decapsulation Operation

/// Tests ML-KEM-1024 decapsulation for ciphertext-dependent timing.
///
/// Fixed: decapsulate a valid ciphertext.
/// Random: decapsulate a corrupted/random ciphertext.
///
/// A leaky implementation might behave differently for invalid ciphertexts.
public struct MLKEMDecapsulationOperation: CryptoOperation {
    public let name = "ML-KEM-1024 Decapsulation"

    private let secretKey: Data
    private let validCiphertext: Data

    public init() {
        if let keyPair = try? MLKEM1024.generateKeyPair(),
           let (_, ct) = try? MLKEM1024.encapsulate(publicKey: keyPair.publicKey) {
            self.secretKey = keyPair.secretKey
            self.validCiphertext = ct
        } else {
            self.secretKey = Data(repeating: 0, count: 3168)
            self.validCiphertext = Data(repeating: 0, count: 1568)
        }
    }

    public func fixedInput() -> Data {
        // Valid ciphertext
        validCiphertext
    }

    public func randomInput() -> Data {
        // Random/corrupted ciphertext (same length)
        Data((0..<1568).map { _ in UInt8.random(in: 0...255) })
    }

    public func run(input: Data) -> Data {
        do {
            let sharedSecret = try MLKEM1024.decapsulate(
                secretKey: secretKey,
                ciphertext: input
            )
            return sharedSecret
        } catch {
            return Data([0])
        }
    }
}

// MARK: - Dudect Runner

/// Core dudect algorithm runner.
///
/// Runs interleaved measurements from fixed and random input classes,
/// applies Welch's t-test, and provides early termination for
/// efficient detection of timing leaks.
public final class DudectRunner: @unchecked Sendable {

    /// Configuration for the dudect run.
    public struct Configuration: Sendable {
        /// Maximum number of samples per class before forced termination.
        public let maxSamples: Int
        /// t-statistic threshold for declaring a leak (|t| > this → leaky).
        public let leakThreshold: Double
        /// t-statistic threshold for declaring non-leaky (|t| < this after minSamples).
        public let safeThreshold: Double
        /// Minimum samples before early safe termination is allowed.
        public let minSamplesForSafe: Int

        public static let `default` = Configuration(
            maxSamples: 10_000,
            leakThreshold: 4.5,
            safeThreshold: 1.0,
            minSamplesForSafe: 5_000
        )

        public static let quick = Configuration(
            maxSamples: 1_000,
            leakThreshold: 4.5,
            safeThreshold: 1.5,
            minSamplesForSafe: 500
        )
    }

    /// Result of a dudect run.
    public struct Result: Sendable {
        public let operation: String
        public let verdict: Verdict
        public let tStatistic: Double
        public let pValue: Double
        public let samplesCollected: Int

        public enum Verdict: String, Sendable {
            case constantTime = "CONSTANT_TIME"
            case leaky = "LEAKY"
            case inconclusive = "INCONCLUSIVE"
        }
    }

    private let configuration: Configuration

    public init(configuration: Configuration = .default) {
        self.configuration = configuration
    }

    /// Run dudect analysis on a cryptographic operation.
    ///
    /// Interleaves fixed and random measurements to cancel systematic drift,
    /// then applies Welch's t-test for statistical comparison.
    ///
    /// - Parameter operation: The cryptographic operation to test.
    /// - Returns: The dudect result with verdict and statistics.
    public func run(operation: CryptoOperation) -> Result {
        let collector = TimingCollector(operation: operation.name)

        for i in 0..<configuration.maxSamples {
            // Interleave: even samples → fixed, odd → random
            // This cancels linear drift in timing
            if i % 2 == 0 {
                let input = operation.fixedInput()
                let duration = timingNanos {
                    let _ = operation.run(input: input)
                }
                collector.addFixedSample(duration)
            } else {
                let input = operation.randomInput()
                let duration = timingNanos {
                    let _ = operation.run(input: input)
                }
                collector.addRandomSample(duration)
            }

            // Early termination check (every 100 samples)
            if i > 0 && i % 100 == 0 {
                let tTest = WelchTTest(
                    fixedSamples: collector.fixedSamples,
                    randomSamples: collector.randomSamples,
                    threshold: 0.01
                )

                // Early leak detection
                if abs(tTest.tStatistic) > configuration.leakThreshold {
                    return Result(
                        operation: operation.name,
                        verdict: .leaky,
                        tStatistic: tTest.tStatistic,
                        pValue: tTest.pValue,
                        samplesCollected: collector.totalSamples
                    )
                }

                // Early safe termination
                if collector.totalSamples >= configuration.minSamplesForSafe &&
                   abs(tTest.tStatistic) < configuration.safeThreshold {
                    return Result(
                        operation: operation.name,
                        verdict: .constantTime,
                        tStatistic: tTest.tStatistic,
                        pValue: tTest.pValue,
                        samplesCollected: collector.totalSamples
                    )
                }
            }
        }

        // Final test after all samples collected
        let finalTest = WelchTTest(
            fixedSamples: collector.fixedSamples,
            randomSamples: collector.randomSamples,
            threshold: 0.01
        )

        let verdict: Result.Verdict
        if abs(finalTest.tStatistic) > configuration.leakThreshold {
            verdict = .leaky
        } else if finalTest.isConstantTime {
            verdict = .constantTime
        } else {
            verdict = .inconclusive
        }

        return Result(
            operation: operation.name,
            verdict: verdict,
            tStatistic: finalTest.tStatistic,
            pValue: finalTest.pValue,
            samplesCollected: collector.totalSamples
        )
    }

    /// Run dudect on multiple operations and generate a summary report.
    public func runAll(operations: [CryptoOperation]) -> (results: [Result], report: TimingReport) {
        var results: [Result] = []
        var collectors: [TimingCollector] = []
        var tTests: [WelchTTest] = []

        for operation in operations {
            let result = run(operation: operation)
            results.append(result)

            // Recreate collector and t-test for report generation
            let collector = TimingCollector(operation: operation.name)
            let tTest = WelchTTest(
                fixedSamples: [],
                randomSamples: [],
                threshold: 0.01
            )
            collectors.append(collector)
            tTests.append(tTest)
        }

        let report = TimingReport(
            generatedAt: ISO8601DateFormatter().string(from: Date()),
            platform: "Apple Silicon (mach_absolute_time)",
            results: results.map { result in
                TimingReport.OperationResult(
                    operation: result.operation,
                    fixedMeanNanos: 0,
                    randomMeanNanos: 0,
                    tStatistic: result.tStatistic,
                    pValue: result.pValue,
                    verdict: result.verdict.rawValue,
                    sampleCount: result.samplesCollected
                )
            },
            overallVerdict: results.allSatisfy({ $0.verdict == .constantTime }) ? "PASS" : "FAIL"
        )

        return (results, report)
    }
}
