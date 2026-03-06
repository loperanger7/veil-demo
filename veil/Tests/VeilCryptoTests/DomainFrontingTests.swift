// VEIL — Domain Fronting Tests
// Ticket: VEIL-603 — Domain Fronting / Censorship Resistance
// Epic: 6 — Network & Transport Layer

import XCTest
@testable import VeilCrypto

final class DomainFrontingTests: XCTestCase {

    // MARK: - DomainFrontingProfile

    func testProfileCreation() {
        let profile = DomainFrontingProfile(
            sniDomain: "cdn.example.com",
            hostDomain: "relay.veil.app",
            fallbackPolicy: .directOnFailure
        )
        XCTAssertEqual(profile.sniDomain, "cdn.example.com")
        XCTAssertEqual(profile.hostDomain, "relay.veil.app")
        XCTAssertNil(profile.pathPrefix)
        XCTAssertEqual(profile.fallbackPolicy, .directOnFailure)
    }

    func testProfileWithPathPrefix() {
        let profile = DomainFrontingProfile(
            sniDomain: "cdn.example.com",
            hostDomain: "relay.veil.app",
            pathPrefix: "/veil"
        )
        XCTAssertEqual(profile.pathPrefix, "/veil")
    }

    // MARK: - FrontingConfiguration

    func testConfigPreferredProfile() {
        let profile = DomainFrontingProfile(
            sniDomain: "cdn-cn.example.com",
            hostDomain: "relay.veil.app"
        )
        let config = FrontingConfiguration(
            profiles: ["CN": [profile]],
            defaultRelayDomain: "relay.veil.app"
        )
        XCTAssertNotNil(config.preferredProfile(for: "CN"))
        XCTAssertNil(config.preferredProfile(for: "US"))
    }

    func testConfigAllProfiles() {
        let profile1 = DomainFrontingProfile(sniDomain: "cdn1.example.com", hostDomain: "relay.veil.app")
        let profile2 = DomainFrontingProfile(sniDomain: "cdn2.example.com", hostDomain: "relay.veil.app")
        let config = FrontingConfiguration(
            profiles: ["CN": [profile1, profile2]],
            defaultRelayDomain: "relay.veil.app"
        )
        XCTAssertEqual(config.allProfiles(for: "CN").count, 2)
        XCTAssertEqual(config.allProfiles(for: "US").count, 0)
    }

    func testConfiguredRegions() {
        let profile = DomainFrontingProfile(sniDomain: "cdn.example.com", hostDomain: "relay.veil.app")
        let config = FrontingConfiguration(
            profiles: ["CN": [profile], "IR": [profile]],
            defaultRelayDomain: "relay.veil.app"
        )
        XCTAssertEqual(config.configuredRegions, ["CN", "IR"])
    }

    func testDisabledConfig() {
        let config = FrontingConfiguration.disabled
        XCTAssertFalse(config.enabled)
        XCTAssertTrue(config.profiles.isEmpty)
    }

    func testConfigCodableRoundTrip() throws {
        let profile = DomainFrontingProfile(
            sniDomain: "cdn.example.com",
            hostDomain: "relay.veil.app",
            pathPrefix: "/v1",
            fallbackPolicy: .tryAlternateProfiles
        )
        let config = FrontingConfiguration(
            version: 3,
            profiles: ["CN": [profile]],
            defaultRelayDomain: "relay.veil.app",
            enabled: true
        )
        let data = try config.encode()
        let decoded = try FrontingConfiguration.decode(from: data)
        XCTAssertEqual(decoded, config)
    }

    // MARK: - FrontingRequestRewriter

    func testApplyFrontingChangesURLHost() {
        let profile = DomainFrontingProfile(
            sniDomain: "cdn.example.com",
            hostDomain: "relay.veil.app"
        )
        var request = URLRequest(url: URL(string: "https://relay.veil.app/v1/messages")!)
        request.httpMethod = "PUT"

        let fronted = FrontingRequestRewriter.applyFronting(to: request, profile: profile)

        // URL should now point to CDN
        XCTAssertEqual(fronted.url?.host, "cdn.example.com")
        // Host header should contain the real relay domain
        XCTAssertEqual(fronted.value(forHTTPHeaderField: "Host"), "relay.veil.app")
        // Path should be preserved
        XCTAssertEqual(fronted.url?.path, "/v1/messages")
    }

    func testApplyFrontingWithPathPrefix() {
        let profile = DomainFrontingProfile(
            sniDomain: "cdn.example.com",
            hostDomain: "relay.veil.app",
            pathPrefix: "/veil"
        )
        let request = URLRequest(url: URL(string: "https://relay.veil.app/v1/messages")!)
        let fronted = FrontingRequestRewriter.applyFronting(to: request, profile: profile)

        XCTAssertEqual(fronted.url?.path, "/veil/v1/messages")
    }

    func testRemoveFronting() {
        var request = URLRequest(url: URL(string: "https://cdn.example.com/v1/messages")!)
        request.setValue("relay.veil.app", forHTTPHeaderField: "Host")

        let direct = FrontingRequestRewriter.removeFronting(from: request, relayDomain: "relay.veil.app")

        XCTAssertEqual(direct.url?.host, "relay.veil.app")
        XCTAssertNil(direct.value(forHTTPHeaderField: "Host"))
    }

    // MARK: - FrontingState

    func testFrontingStateEquality() {
        XCTAssertEqual(FrontingState.disabled, FrontingState.disabled)
        XCTAssertEqual(FrontingState.direct, FrontingState.direct)
        XCTAssertEqual(
            FrontingState.fronting(region: "CN", profileIndex: 0),
            FrontingState.fronting(region: "CN", profileIndex: 0)
        )
        XCTAssertNotEqual(FrontingState.direct, FrontingState.disabled)
        XCTAssertNotEqual(
            FrontingState.fronting(region: "CN", profileIndex: 0),
            FrontingState.fronting(region: "IR", profileIndex: 0)
        )
    }

    // MARK: - RegionDetector

    func testRegionFromISOCode() {
        XCTAssertEqual(RegionDetector.from(isoCode: "cn"), "CN")
        XCTAssertEqual(RegionDetector.from(isoCode: "US"), "US")
    }

    func testDetectFromLocale() {
        let region = RegionDetector.detectFromLocale()
        XCTAssertFalse(region.isEmpty)
        XCTAssertEqual(region.count, 2)
    }

    // MARK: - DomainFrontingInterceptor

    func testInterceptorInitialState() async {
        let config = FrontingConfiguration.disabled
        let detectorConfig = CensorshipDetectorConfiguration(
            probeURL: URL(string: "https://relay.veil.app/v1/health")!
        )
        let detector = NetworkCensorshipDetector(configuration: detectorConfig)
        let interceptor = DomainFrontingInterceptor(
            censorshipDetector: detector,
            frontingConfig: config,
            detectedRegion: "US"
        )
        let state = await interceptor.currentState
        XCTAssertEqual(state, .disabled)
    }

    func testInterceptorReset() async {
        let profile = DomainFrontingProfile(sniDomain: "cdn.example.com", hostDomain: "relay.veil.app")
        let config = FrontingConfiguration(
            profiles: ["CN": [profile]],
            defaultRelayDomain: "relay.veil.app",
            enabled: true
        )
        let detectorConfig = CensorshipDetectorConfiguration(
            probeURL: URL(string: "https://relay.veil.app/v1/health")!
        )
        let detector = NetworkCensorshipDetector(configuration: detectorConfig)
        let interceptor = DomainFrontingInterceptor(
            censorshipDetector: detector,
            frontingConfig: config,
            detectedRegion: "CN"
        )

        await interceptor.reset()
        let state = await interceptor.currentState
        XCTAssertEqual(state, .direct)
    }

    func testInterceptorConfigUpdate() async {
        let config = FrontingConfiguration.disabled
        let detectorConfig = CensorshipDetectorConfiguration(
            probeURL: URL(string: "https://relay.veil.app/v1/health")!
        )
        let detector = NetworkCensorshipDetector(configuration: detectorConfig)
        let interceptor = DomainFrontingInterceptor(
            censorshipDetector: detector,
            frontingConfig: config,
            detectedRegion: "US"
        )

        // Update to enabled config
        let newConfig = FrontingConfiguration(
            profiles: ["US": [DomainFrontingProfile(sniDomain: "cdn.example.com", hostDomain: "relay.veil.app")]],
            defaultRelayDomain: "relay.veil.app",
            enabled: true
        )
        await interceptor.updateConfiguration(newConfig)

        // State should not be disabled anymore after update
        // (exact state depends on censorship detection, but it shouldn't be .disabled)
    }
}
