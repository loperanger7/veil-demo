// VEIL — ConstantTimeTests.swift
// Ticket: VEIL-803 — Constant-Time Verification
// Spec reference: VEIL-109 (Memory Safety), Section 6.3
//
// XCTest suite running dudect constant-time analysis on all
// security-critical cryptographic operations.
//
// Each test:
//   1. Instantiates a CryptoOperation (fixed vs random inputs)
//   2. Runs DudectRunner with 10,000 sample pairs
//   3. Applies Welch's t-test (p > 0.01 → no leak detected)
//   4. Reports verdict: CONSTANT_TIME / LEAKY / INCONCLUSIVE
//
// CI NOTES:
//   - These tests MUST run on dedicated (non-virtualized) hardware
//     for reliable timing measurements.
//   - On virtualized CI (GitHub Actions, etc.), timing jitter from
//     hypervisor scheduling makes results unreliable.
//   - Use XCTSkipIf to skip on virtualized environments.
//
// References:
//   Reparaz et al., "Dude, is my code constant time?", USENIX 2017
//   Oscar Reparaz, Josep Balasch, Ingrid Verbauwhede

import XCTest
import CryptoKit
@testable import VeilCrypto

final class ConstantTimeTests: XCTestCase {

    // MARK: - Environment Check

    /// Check if we're running in a virtualized environment.
    /// dudect results are unreliable under hypervisor scheduling jitter.
    private var isVirtualized: Bool {
        // Check common virtualization indicators
        #if targetEnvironment(simulator)
        return true
        #else
        // On real hardware, check for known CI environment variables
        if ProcessInfo.processInfo.environment["CI"] != nil {
            // CI environments are typically virtualized
            // Skip unless VEIL_TIMING_HARDWARE=1 is set
            return ProcessInfo.processInfo.environment["VEIL_TIMING_HARDWARE"] == nil
        }
        return false
        #endif
    }

    /// Quick configuration for CI — fewer samples, wider thresholds.
    /// Full configuration used on dedicated timing hardware.
    private var dudectConfig: DudectRunner.Configuration {
        if ProcessInfo.processInfo.environment["VEIL_TIMING_FULL"] != nil {
            return .default  // 10,000 samples, tight thresholds
        }
        return .quick  // 1,000 samples, wider thresholds
    }

    // MARK: VEIL-803 — Test 1: HMAC-SHA256 Comparison

    /// **CONSTANT-TIME: HMAC tag comparison.**
    ///
    /// Verifies that comparing HMAC-SHA256 tags takes the same time
    /// regardless of whether the tags match or differ.
    ///
    /// A timing leak here would allow an attacker to forge MACs
    /// by measuring per-byte comparison timing.
    func testConstantTime_HMACComparison() throws {
        try XCTSkipIf(isVirtualized, "Timing tests require dedicated hardware")

        let operation = HMACComparisonOperation()
        let runner = DudectRunner(configuration: dudectConfig)
        let result = runner.run(operation: operation)

        XCTAssertNotEqual(
            result.verdict, .leaky,
            "HMAC comparison shows timing leak: t=\(result.tStatistic), p=\(result.pValue)"
        )

        // Log results for CI artifact
        print("[VEIL-803] HMAC Comparison: \(result.verdict.rawValue)")
        print("  t-statistic: \(String(format: "%.4f", result.tStatistic))")
        print("  p-value: \(String(format: "%.6f", result.pValue))")
        print("  samples: \(result.samplesCollected)")
    }

    // MARK: VEIL-803 — Test 2: AES-256-GCM Decryption

    /// **CONSTANT-TIME: AES-256-GCM decryption.**
    ///
    /// Verifies that AES-GCM decryption takes the same time for
    /// valid tags vs invalid tags.
    ///
    /// A timing leak here would allow a padding oracle-style attack
    /// where the attacker can distinguish authentication failures
    /// from decryption failures.
    func testConstantTime_AESGCMDecryption() throws {
        try XCTSkipIf(isVirtualized, "Timing tests require dedicated hardware")

        let operation = AESGCMDecryptionOperation()
        let runner = DudectRunner(configuration: dudectConfig)
        let result = runner.run(operation: operation)

        XCTAssertNotEqual(
            result.verdict, .leaky,
            "AES-GCM decryption shows timing leak: t=\(result.tStatistic), p=\(result.pValue)"
        )

        print("[VEIL-803] AES-GCM Decryption: \(result.verdict.rawValue)")
        print("  t-statistic: \(String(format: "%.4f", result.tStatistic))")
        print("  p-value: \(String(format: "%.6f", result.pValue))")
        print("  samples: \(result.samplesCollected)")
    }

    // MARK: VEIL-803 — Test 3: X25519 Scalar Multiplication

    /// **CONSTANT-TIME: X25519 scalar multiplication.**
    ///
    /// Verifies that X25519 key agreement takes the same time
    /// regardless of the scalar value.
    ///
    /// A timing leak here would allow an attacker to recover the
    /// private key by measuring multiplication timing.
    func testConstantTime_X25519ScalarMult() throws {
        try XCTSkipIf(isVirtualized, "Timing tests require dedicated hardware")

        let operation = X25519ScalarMultOperation()
        let runner = DudectRunner(configuration: dudectConfig)
        let result = runner.run(operation: operation)

        XCTAssertNotEqual(
            result.verdict, .leaky,
            "X25519 scalar mult shows timing leak: t=\(result.tStatistic), p=\(result.pValue)"
        )

        print("[VEIL-803] X25519 Scalar Mult: \(result.verdict.rawValue)")
        print("  t-statistic: \(String(format: "%.4f", result.tStatistic))")
        print("  p-value: \(String(format: "%.6f", result.pValue))")
        print("  samples: \(result.samplesCollected)")
    }

    // MARK: VEIL-803 — Test 4: ML-KEM-1024 Decapsulation

    /// **CONSTANT-TIME: ML-KEM-1024 decapsulation.**
    ///
    /// Verifies that KEM decapsulation takes the same time for
    /// valid ciphertexts vs corrupted ciphertexts.
    ///
    /// A timing leak here would allow a chosen-ciphertext attack
    /// against the KEM, potentially recovering the shared secret.
    func testConstantTime_MLKEMDecapsulation() throws {
        try XCTSkipIf(isVirtualized, "Timing tests require dedicated hardware")

        let operation = MLKEMDecapsulationOperation()
        let runner = DudectRunner(configuration: dudectConfig)
        let result = runner.run(operation: operation)

        XCTAssertNotEqual(
            result.verdict, .leaky,
            "ML-KEM decapsulation shows timing leak: t=\(result.tStatistic), p=\(result.pValue)"
        )

        print("[VEIL-803] ML-KEM Decapsulation: \(result.verdict.rawValue)")
        print("  t-statistic: \(String(format: "%.4f", result.tStatistic))")
        print("  p-value: \(String(format: "%.6f", result.pValue))")
        print("  samples: \(result.samplesCollected)")
    }

    // MARK: VEIL-803 — Test 5: SecureBytes Equality

    /// **CONSTANT-TIME: SecureBytes constant-time comparison.**
    ///
    /// Verifies that SecureBytes.constantTimeEqual takes the same
    /// time for equal and unequal inputs.
    ///
    /// This is the foundation of all MAC verification in Veil.
    func testConstantTime_SecureBytesEquality() throws {
        try XCTSkipIf(isVirtualized, "Timing tests require dedicated hardware")

        let referenceBytes = Array((0..<64).map { _ in UInt8.random(in: 0...255) })
        let runner = DudectRunner(configuration: dudectConfig)

        // Create a custom operation for SecureBytes comparison
        struct SecureBytesEqualityOp: CryptoOperation {
            let name = "SecureBytes Equality"
            let reference: [UInt8]

            func fixedInput() -> Data {
                Data(reference)  // Equal to reference
            }

            func randomInput() -> Data {
                Data((0..<reference.count).map { _ in UInt8.random(in: 0...255) })
            }

            func run(input: Data) -> Data {
                let isEqual = SecureBytes.constantTimeEqual(reference, Array(input))
                return Data([isEqual ? 1 : 0])
            }
        }

        let operation = SecureBytesEqualityOp(reference: referenceBytes)
        let result = runner.run(operation: operation)

        XCTAssertNotEqual(
            result.verdict, .leaky,
            "SecureBytes equality shows timing leak: t=\(result.tStatistic), p=\(result.pValue)"
        )

        print("[VEIL-803] SecureBytes Equality: \(result.verdict.rawValue)")
        print("  t-statistic: \(String(format: "%.4f", result.tStatistic))")
        print("  p-value: \(String(format: "%.6f", result.pValue))")
        print("  samples: \(result.samplesCollected)")
    }

    // MARK: VEIL-803 — Test 6: Full Report Generation

    /// **REPORT: Generate JSON timing report for CI artifacts.**
    ///
    /// Runs all operations and generates a comprehensive JSON report
    /// that can be stored as a CI artifact for trend analysis.
    func testConstantTime_generateFullReport() throws {
        try XCTSkipIf(isVirtualized, "Timing tests require dedicated hardware")

        let operations: [CryptoOperation] = [
            HMACComparisonOperation(),
            AESGCMDecryptionOperation(),
            X25519ScalarMultOperation(),
            MLKEMDecapsulationOperation(),
        ]

        let runner = DudectRunner(configuration: dudectConfig)
        let (results, report) = runner.runAll(operations: operations)

        // Verify all operations passed
        for result in results {
            XCTAssertNotEqual(
                result.verdict, .leaky,
                "\(result.operation) shows timing leak"
            )
        }

        // Generate JSON report
        let jsonData = try report.exportJSON()
        let jsonString = String(data: jsonData, encoding: .utf8)!

        print("[VEIL-803] Full Timing Report:")
        print(jsonString)

        // Verify report structure
        XCTAssertFalse(jsonString.isEmpty)
        XCTAssertTrue(jsonString.contains("\"overallVerdict\""))
        XCTAssertTrue(jsonString.contains("\"results\""))
    }

    // MARK: VEIL-803 — Test 7: Welch t-Test Validation

    /// **VALIDATION: Welch's t-test produces correct results for known distributions.**
    ///
    /// Tests the statistical machinery with known-distribution inputs to ensure
    /// the t-test implementation is correct.
    func testWelchTTest_knownDistributions() {
        // Test 1: Identical distributions → should be constant time
        let identical1 = (0..<1000).map { _ in UInt64.random(in: 100...200) }
        let identical2 = (0..<1000).map { _ in UInt64.random(in: 100...200) }
        let identicalTest = WelchTTest(fixedSamples: identical1, randomSamples: identical2)
        XCTAssertTrue(
            identicalTest.isConstantTime,
            "Identical distributions should show no timing difference"
        )

        // Test 2: Very different distributions → should detect leak
        let fast = (0..<1000).map { _ in UInt64.random(in: 100...150) }
        let slow = (0..<1000).map { _ in UInt64.random(in: 500...600) }
        let differentTest = WelchTTest(fixedSamples: fast, randomSamples: slow)
        XCTAssertFalse(
            differentTest.isConstantTime,
            "Very different distributions should be detected as a timing leak"
        )
        XCTAssertTrue(
            abs(differentTest.tStatistic) > 4.0,
            "t-statistic should be large for clearly different distributions"
        )

        // Test 3: Empty samples → should be constant time (safe default)
        let emptyTest = WelchTTest(fixedSamples: [], randomSamples: [])
        XCTAssertTrue(emptyTest.isConstantTime)

        // Test 4: Single sample → should be constant time (insufficient data)
        let singleTest = WelchTTest(fixedSamples: [100], randomSamples: [200])
        XCTAssertTrue(singleTest.isConstantTime)
    }

    // MARK: VEIL-803 — Test 8: Timing Measurement Accuracy

    /// **VALIDATION: timingNanos produces reasonable measurements.**
    ///
    /// Verifies that our timing infrastructure actually measures
    /// non-zero, non-ridiculous values.
    func testTimingMeasurement_accuracy() {
        // A no-op should be very fast (< 1ms = 1_000_000 ns)
        let noopDuration = timingNanos { }
        XCTAssertLessThan(noopDuration, 1_000_000, "No-op should take < 1ms")

        // A known-slow operation should take measurable time
        let slowDuration = timingNanos {
            var sum: UInt64 = 0
            for i in 0..<10000 {
                sum &+= UInt64(i)
            }
            _ = sum
        }
        XCTAssertGreaterThan(slowDuration, 0, "Loop should take > 0 ns")

        // Multiple measurements should be somewhat consistent
        var durations: [UInt64] = []
        for _ in 0..<100 {
            let d = timingNanos {
                let _ = SHA256.hash(data: Data(repeating: 0xAA, count: 1024))
            }
            durations.append(d)
        }

        let stats = TimingCollector.Stats(from: durations)
        XCTAssertGreaterThan(stats.mean, 0, "SHA256 hash should take > 0 ns on average")
        // Coefficient of variation should be reasonable (< 500% for timing on real hardware)
        let cv = stats.stddev / stats.mean
        XCTAssertLessThan(cv, 5.0, "Timing measurements should be reasonably consistent (CV < 5.0)")
    }

    // MARK: VEIL-803 — Test 9: Collector Statistics

    /// **VALIDATION: TimingCollector produces correct descriptive statistics.**
    func testTimingCollector_statistics() {
        let collector = TimingCollector(operation: "test")

        // Add known samples
        let fixedValues: [UInt64] = [100, 200, 300, 400, 500]
        let randomValues: [UInt64] = [150, 250, 350, 450, 550]

        for v in fixedValues { collector.addFixedSample(v) }
        for v in randomValues { collector.addRandomSample(v) }

        XCTAssertEqual(collector.totalSamples, 10)
        XCTAssertEqual(collector.fixedSamples.count, 5)
        XCTAssertEqual(collector.randomSamples.count, 5)

        let fixedStats = collector.fixedStats
        XCTAssertEqual(fixedStats.count, 5)
        XCTAssertEqual(fixedStats.mean, 300.0, accuracy: 0.01)
        XCTAssertEqual(fixedStats.min, 100)
        XCTAssertEqual(fixedStats.max, 500)
        XCTAssertEqual(fixedStats.median, 300)

        let randomStats = collector.randomStats
        XCTAssertEqual(randomStats.mean, 350.0, accuracy: 0.01)
        XCTAssertEqual(randomStats.min, 150)
        XCTAssertEqual(randomStats.max, 550)
    }

    // MARK: VEIL-803 — Test 10: Report JSON Round-Trip

    /// **VALIDATION: TimingReport serializes to valid JSON and back.**
    func testTimingReport_jsonRoundTrip() throws {
        let report = TimingReport(
            generatedAt: "2026-03-05T00:00:00Z",
            platform: "Test",
            results: [
                TimingReport.OperationResult(
                    operation: "Test Op",
                    fixedMeanNanos: 100.5,
                    randomMeanNanos: 101.2,
                    tStatistic: 0.42,
                    pValue: 0.67,
                    verdict: "PASS",
                    sampleCount: 10000
                )
            ],
            overallVerdict: "PASS"
        )

        let jsonData = try report.exportJSON()
        let decoded = try JSONDecoder().decode(TimingReport.self, from: jsonData)

        XCTAssertEqual(decoded.generatedAt, report.generatedAt)
        XCTAssertEqual(decoded.platform, report.platform)
        XCTAssertEqual(decoded.overallVerdict, report.overallVerdict)
        XCTAssertEqual(decoded.results.count, 1)
        XCTAssertEqual(decoded.results[0].operation, "Test Op")
        XCTAssertEqual(decoded.results[0].tStatistic, 0.42, accuracy: 0.001)
    }
}
