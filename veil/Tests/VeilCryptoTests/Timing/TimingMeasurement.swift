// VEIL — TimingMeasurement.swift
// Ticket: VEIL-803 — Constant-Time Verification
// Spec reference: VEIL-109 (Memory Safety), Section 6.3
//
// Statistical timing measurement infrastructure for dudect-based
// constant-time verification.
//
// Components:
//   - TimingSample: Individual measurement record
//   - TimingCollector: Batched collection with descriptive statistics
//   - WelchTTest: Two-sample t-test for timing class comparison
//   - TimingReport: JSON-serializable summary for CI artifacts
//
// Timing precision:
//   Uses mach_absolute_time() with mach_timebase_info conversion
//   for nanosecond-resolution measurements on Apple silicon.
//
// References:
//   Reparaz et al., "Dude, is my code constant time?", USENIX 2017

import Foundation
#if canImport(Darwin)
import Darwin
#endif

// MARK: - Timing Sample

/// A single timing measurement for a cryptographic operation.
public struct TimingSample: Sendable, Codable {
    /// The operation being measured.
    public let operation: String
    /// Input class: "fixed" (known input) or "random" (varying input).
    public let inputClass: String
    /// Duration in nanoseconds.
    public let durationNanos: UInt64
    /// Sample index within the batch.
    public let sampleIndex: Int

    public init(operation: String, inputClass: String, durationNanos: UInt64, sampleIndex: Int) {
        self.operation = operation
        self.inputClass = inputClass
        self.durationNanos = durationNanos
        self.sampleIndex = sampleIndex
    }
}

// MARK: - Timing Collector

/// Collects timing samples for two input classes and computes
/// descriptive statistics for comparison.
public final class TimingCollector: @unchecked Sendable {

    /// Collected samples for the "fixed" input class.
    public private(set) var fixedSamples: [UInt64] = []

    /// Collected samples for the "random" input class.
    public private(set) var randomSamples: [UInt64] = []

    /// The operation name.
    public let operation: String

    public init(operation: String) {
        self.operation = operation
    }

    /// Add a sample for the fixed input class.
    public func addFixedSample(_ durationNanos: UInt64) {
        fixedSamples.append(durationNanos)
    }

    /// Add a sample for the random input class.
    public func addRandomSample(_ durationNanos: UInt64) {
        randomSamples.append(durationNanos)
    }

    /// Number of total samples collected.
    public var totalSamples: Int {
        fixedSamples.count + randomSamples.count
    }

    /// Descriptive statistics for a sample array.
    public struct Stats: Sendable, Codable {
        public let count: Int
        public let mean: Double
        public let stddev: Double
        public let min: UInt64
        public let max: UInt64
        public let median: UInt64

        public init(from samples: [UInt64]) {
            self.count = samples.count
            guard !samples.isEmpty else {
                self.mean = 0
                self.stddev = 0
                self.min = 0
                self.max = 0
                self.median = 0
                return
            }

            let sorted = samples.sorted()
            let sum = samples.reduce(0.0) { $0 + Double($1) }
            self.mean = sum / Double(samples.count)
            self.min = sorted.first!
            self.max = sorted.last!
            self.median = sorted[sorted.count / 2]

            let variance = samples.reduce(0.0) { acc, val in
                let diff = Double(val) - self.mean
                return acc + diff * diff
            } / Double(max(samples.count - 1, 1))
            self.stddev = sqrt(variance)
        }
    }

    /// Compute descriptive statistics for fixed samples.
    public var fixedStats: Stats { Stats(from: fixedSamples) }

    /// Compute descriptive statistics for random samples.
    public var randomStats: Stats { Stats(from: randomSamples) }
}

// MARK: - Welch's t-Test

/// Two-sample t-test with Welch's correction for unequal variances.
///
/// Used to determine if there is a statistically significant difference
/// in timing between fixed and random input classes.
public struct WelchTTest: Sendable, Codable {

    /// t-statistic value.
    public let tStatistic: Double

    /// Approximate p-value (two-tailed).
    public let pValue: Double

    /// Degrees of freedom (Welch-Satterthwaite approximation).
    public let degreesOfFreedom: Double

    /// Whether the null hypothesis (no timing difference) holds.
    /// A p-value > threshold means no detectable leakage.
    public let isConstantTime: Bool

    /// The significance threshold used.
    public let threshold: Double

    /// Perform Welch's t-test on two sample sets.
    ///
    /// - Parameters:
    ///   - fixedSamples: Timing samples for the fixed input class.
    ///   - randomSamples: Timing samples for the random input class.
    ///   - threshold: p-value threshold (default 0.01; higher = more conservative).
    public init(fixedSamples: [UInt64], randomSamples: [UInt64], threshold: Double = 0.01) {
        self.threshold = threshold

        let n1 = Double(fixedSamples.count)
        let n2 = Double(randomSamples.count)

        guard n1 > 1, n2 > 1 else {
            self.tStatistic = 0
            self.pValue = 1.0
            self.degreesOfFreedom = 0
            self.isConstantTime = true
            return
        }

        let mean1 = fixedSamples.reduce(0.0) { $0 + Double($1) } / n1
        let mean2 = randomSamples.reduce(0.0) { $0 + Double($1) } / n2

        let var1 = fixedSamples.reduce(0.0) { acc, val in
            let diff = Double(val) - mean1
            return acc + diff * diff
        } / (n1 - 1)

        let var2 = randomSamples.reduce(0.0) { acc, val in
            let diff = Double(val) - mean2
            return acc + diff * diff
        } / (n2 - 1)

        let se = sqrt(var1 / n1 + var2 / n2)

        guard se > 0 else {
            self.tStatistic = 0
            self.pValue = 1.0
            self.degreesOfFreedom = n1 + n2 - 2
            self.isConstantTime = true
            return
        }

        self.tStatistic = (mean1 - mean2) / se

        // Welch-Satterthwaite degrees of freedom
        let num = pow(var1 / n1 + var2 / n2, 2)
        let denom = pow(var1 / n1, 2) / (n1 - 1) + pow(var2 / n2, 2) / (n2 - 1)
        self.degreesOfFreedom = denom > 0 ? num / denom : n1 + n2 - 2

        // Approximate p-value using the t-distribution
        // For large df, we use the normal approximation
        self.pValue = WelchTTest.approximatePValue(
            tStatistic: tStatistic,
            df: degreesOfFreedom
        )

        self.isConstantTime = pValue > threshold
    }

    /// Approximate two-tailed p-value from t-statistic.
    ///
    /// Uses the normal approximation for large degrees of freedom,
    /// and a simple series expansion for smaller values.
    private static func approximatePValue(tStatistic: Double, df: Double) -> Double {
        let absT = abs(tStatistic)

        // For large df (> 30), use normal approximation
        if df > 30 {
            // Standard normal CDF approximation (Abramowitz and Stegun)
            let z = absT
            let p = 0.5 * erfc(z / sqrt(2.0))
            return 2.0 * p  // Two-tailed
        }

        // For smaller df, use a conservative estimate
        // Based on t-distribution quantiles
        if absT < 1.0 { return 0.5 }        // Very weak evidence
        if absT < 2.0 { return 0.1 }        // Weak evidence
        if absT < 2.5 { return 0.05 }       // Moderate evidence
        if absT < 3.0 { return 0.01 }       // Strong evidence
        if absT < 3.5 { return 0.005 }      // Very strong evidence
        return 0.001                          // Extremely strong evidence
    }
}

// MARK: - Timing Report

/// JSON-serializable timing report for CI artifact generation.
public struct TimingReport: Sendable, Codable {

    /// Individual operation results.
    public struct OperationResult: Sendable, Codable {
        public let operation: String
        public let fixedMeanNanos: Double
        public let randomMeanNanos: Double
        public let tStatistic: Double
        public let pValue: Double
        public let verdict: String
        public let sampleCount: Int
    }

    /// Timestamp of the report.
    public let generatedAt: String

    /// Platform information.
    public let platform: String

    /// Results for each tested operation.
    public let results: [OperationResult]

    /// Overall verdict: all operations must pass.
    public let overallVerdict: String

    /// Generate a report from collectors and t-test results.
    public static func generate(
        from collectors: [TimingCollector],
        tTests: [WelchTTest]
    ) -> TimingReport {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]

        var results: [OperationResult] = []
        for (collector, test) in zip(collectors, tTests) {
            results.append(OperationResult(
                operation: collector.operation,
                fixedMeanNanos: collector.fixedStats.mean,
                randomMeanNanos: collector.randomStats.mean,
                tStatistic: test.tStatistic,
                pValue: test.pValue,
                verdict: test.isConstantTime ? "PASS" : "FAIL",
                sampleCount: collector.totalSamples
            ))
        }

        let allPassed = tTests.allSatisfy { $0.isConstantTime }

        return TimingReport(
            generatedAt: formatter.string(from: Date()),
            platform: "Apple Silicon (mach_absolute_time)",
            results: results,
            overallVerdict: allPassed ? "PASS" : "FAIL"
        )
    }

    /// Export as pretty-printed JSON data.
    public func exportJSON() throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(self)
    }
}

// MARK: - High-Resolution Timer

/// Nanosecond-precision timing using mach_absolute_time.
///
/// Converts Mach absolute time units to nanoseconds using
/// mach_timebase_info for accurate cross-architecture timing.
public func timingNanos(_ block: () -> Void) -> UInt64 {
    var info = mach_timebase_info_data_t()
    mach_timebase_info(&info)

    let start = mach_absolute_time()
    block()
    let end = mach_absolute_time()

    let elapsed = end - start
    return elapsed * UInt64(info.numer) / UInt64(info.denom)
}

/// Async variant of nanosecond timing.
public func timingNanosAsync(_ block: () async throws -> Void) async rethrows -> UInt64 {
    var info = mach_timebase_info_data_t()
    mach_timebase_info(&info)

    let start = mach_absolute_time()
    try await block()
    let end = mach_absolute_time()

    let elapsed = end - start
    return elapsed * UInt64(info.numer) / UInt64(info.denom)
}
