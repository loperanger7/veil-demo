// VEIL — Censorship Detector Tests
// Ticket: VEIL-603 — Domain Fronting / Censorship Resistance
// Epic: 6 — Network & Transport Layer

import XCTest
@testable import VeilCrypto

final class CensorshipDetectorTests: XCTestCase {

    // MARK: - CensorshipProbeResult

    func testProbeResultEquality() {
        XCTAssertEqual(CensorshipProbeResult.reachable, CensorshipProbeResult.reachable)
        XCTAssertEqual(
            CensorshipProbeResult.censored(reason: .timeout),
            CensorshipProbeResult.censored(reason: .timeout)
        )
        XCTAssertNotEqual(CensorshipProbeResult.reachable, CensorshipProbeResult.censored(reason: .timeout))
        XCTAssertNotEqual(
            CensorshipProbeResult.censored(reason: .timeout),
            CensorshipProbeResult.censored(reason: .forbidden)
        )
    }

    // MARK: - CensorshipReason

    func testCensorshipReasonCodable() throws {
        let reason = CensorshipReason.timeout
        let data = try JSONEncoder().encode(reason)
        let decoded = try JSONDecoder().decode(CensorshipReason.self, from: data)
        XCTAssertEqual(decoded, reason)
    }

    func testAllCensorshipReasons() {
        let reasons: [CensorshipReason] = [.timeout, .forbidden, .legalBlock, .connectionReset, .dnsPoisoning]
        XCTAssertEqual(reasons.count, 5)
        // Each has a unique raw value
        let rawValues = Set(reasons.map { $0.rawValue })
        XCTAssertEqual(rawValues.count, 5)
    }

    // MARK: - CensorshipDetectorConfiguration

    func testDefaultConfiguration() {
        let config = CensorshipDetectorConfiguration.veilDefault(
            relayBaseURL: URL(string: "https://relay.veil.app")!
        )
        XCTAssertEqual(config.probeURL.absoluteString, "https://relay.veil.app/v1/health")
        XCTAssertEqual(config.probeTimeout, 10)
        XCTAssertEqual(config.cacheTTL, 300)
        XCTAssertTrue(config.censorshipStatusCodes.contains(403))
        XCTAssertTrue(config.censorshipStatusCodes.contains(451))
    }

    func testCustomConfiguration() {
        let config = CensorshipDetectorConfiguration(
            probeURL: URL(string: "https://custom.relay.app/health")!,
            probeTimeout: 5,
            cacheTTL: 60,
            censorshipStatusCodes: [403, 451, 503]
        )
        XCTAssertEqual(config.probeTimeout, 5)
        XCTAssertEqual(config.cacheTTL, 60)
        XCTAssertTrue(config.censorshipStatusCodes.contains(503))
    }

    // MARK: - NetworkCensorshipDetector

    func testDetectorInitialization() async {
        let config = CensorshipDetectorConfiguration(
            probeURL: URL(string: "https://relay.veil.app/v1/health")!,
            probeTimeout: 1,
            cacheTTL: 60
        )
        let detector = NetworkCensorshipDetector(configuration: config)

        // Initial state: no cached result, probe will be attempted
        // We can't test the actual probe without a real server,
        // but we can verify the actor is created successfully
        await detector.clearCache()
    }

    func testDetectorCacheClearing() async {
        let config = CensorshipDetectorConfiguration(
            probeURL: URL(string: "https://relay.veil.app/v1/health")!,
            probeTimeout: 1,
            cacheTTL: 60
        )
        let detector = NetworkCensorshipDetector(configuration: config)

        // Clear cache should not crash
        await detector.clearCache()
    }

    func testShouldActivateFrontingRequiresProbe() async {
        let config = CensorshipDetectorConfiguration(
            probeURL: URL(string: "https://localhost:1/nonexistent")!, // Will fail
            probeTimeout: 1,
            cacheTTL: 5
        )
        let detector = NetworkCensorshipDetector(configuration: config)

        // This will attempt a probe to an unreachable address
        // Should return true or inconclusive (not reachable)
        let result = await detector.detectCensorship()
        // The exact result depends on network, but it should not crash
        switch result {
        case .reachable:
            break // Unlikely but possible on some networks
        case .censored, .inconclusive:
            break // Expected for unreachable target
        }
    }

    // MARK: - FallbackPolicy

    func testFallbackPolicyCodable() throws {
        let policies: [FrontingFallbackPolicy] = [
            .directOnFailure,
            .failCompletely,
            .tryAlternateProfiles,
        ]
        for policy in policies {
            let data = try JSONEncoder().encode(policy)
            let decoded = try JSONDecoder().decode(FrontingFallbackPolicy.self, from: data)
            XCTAssertEqual(decoded, policy)
        }
    }
}
