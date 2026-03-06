// VEIL — Domain Fronting Configuration
// Ticket: VEIL-603 — Domain Fronting / Censorship Resistance
// Epic: 6 — Network & Transport Layer
// Spec reference: Section 2.1
//
// Per-region domain fronting configuration that routes Veil relay
// traffic through CDN infrastructure to bypass network censorship.
//
// Mechanism:
//   - TLS SNI (Server Name Indication): Set to the CDN domain
//   - HTTP Host header: Set to the actual relay domain
//   - The CDN terminates TLS and forwards to the relay based on Host
//   - An observer sees traffic to a legitimate CDN, not the relay
//
// Configuration is delivered via signed updates (reuses
// SignedConfigurationUpdate from VEIL-601) to prevent injection.

import Foundation

// MARK: - Region Code

/// ISO 3166-1 alpha-2 region code (e.g., "CN", "IR", "RU").
public typealias RegionCode = String

// MARK: - Fronting Profile

/// Domain fronting profile for a specific region.
///
/// Defines the CDN domain to use for TLS SNI and the actual relay
/// domain to use in the HTTP Host header.
public struct DomainFrontingProfile: Sendable, Codable, Equatable {
    /// The CDN domain to use in the TLS SNI extension.
    /// This is what network observers and censors see.
    public let sniDomain: String

    /// The actual relay domain to use in the HTTP Host header.
    /// The CDN routes traffic to this domain internally.
    public let hostDomain: String

    /// CDN path prefix (if the CDN requires a specific path).
    public let pathPrefix: String?

    /// Fallback policy when fronting fails.
    public let fallbackPolicy: FrontingFallbackPolicy

    public init(
        sniDomain: String,
        hostDomain: String,
        pathPrefix: String? = nil,
        fallbackPolicy: FrontingFallbackPolicy = .directOnFailure
    ) {
        self.sniDomain = sniDomain
        self.hostDomain = hostDomain
        self.pathPrefix = pathPrefix
        self.fallbackPolicy = fallbackPolicy
    }
}

// MARK: - Fallback Policy

/// What to do when domain fronting fails.
public enum FrontingFallbackPolicy: String, Sendable, Codable, Equatable {
    /// Fall back to direct connection if fronting fails.
    case directOnFailure
    /// Fail completely — do not attempt direct connection.
    case failCompletely
    /// Try alternate fronting profiles before failing.
    case tryAlternateProfiles
}

// MARK: - Fronting Configuration

/// Top-level domain fronting configuration mapping regions to profiles.
///
/// Delivered via signed configuration update and stored locally.
/// Each region can have one or more fronting profiles.
public struct FrontingConfiguration: Sendable, Codable, Equatable {
    /// Version number for this configuration.
    public let version: UInt64

    /// Mapping from region code to fronting profile(s).
    /// Ordered by preference (first profile is preferred).
    public let profiles: [RegionCode: [DomainFrontingProfile]]

    /// The default relay domain for direct connections.
    public let defaultRelayDomain: String

    /// Whether fronting is globally enabled.
    public let enabled: Bool

    public init(
        version: UInt64 = 1,
        profiles: [RegionCode: [DomainFrontingProfile]],
        defaultRelayDomain: String,
        enabled: Bool = true
    ) {
        self.version = version
        self.profiles = profiles
        self.defaultRelayDomain = defaultRelayDomain
        self.enabled = enabled
    }

    /// Look up the preferred fronting profile for a region.
    ///
    /// - Parameter region: ISO 3166-1 alpha-2 region code.
    /// - Returns: The preferred fronting profile, or nil if no fronting
    ///   is configured for this region.
    public func preferredProfile(for region: RegionCode) -> DomainFrontingProfile? {
        profiles[region]?.first
    }

    /// All fronting profiles for a region, ordered by preference.
    public func allProfiles(for region: RegionCode) -> [DomainFrontingProfile] {
        profiles[region] ?? []
    }

    /// Regions that have fronting profiles configured.
    public var configuredRegions: Set<RegionCode> {
        Set(profiles.keys)
    }

    /// Decode from a signed configuration update payload.
    public static func decode(from data: Data) throws -> FrontingConfiguration {
        try JSONDecoder().decode(FrontingConfiguration.self, from: data)
    }

    /// Encode to a configuration update payload.
    public func encode() throws -> Data {
        try JSONEncoder().encode(self)
    }

    /// Empty configuration (no fronting profiles).
    public static let disabled = FrontingConfiguration(
        profiles: [:],
        defaultRelayDomain: "relay.veil.app",
        enabled: false
    )
}

// MARK: - Fronting Request Rewriter

/// Rewrites URLRequest objects to apply domain fronting.
///
/// Modifies the request URL to use the CDN domain while setting
/// the original relay domain in the Host header.
public enum FrontingRequestRewriter {
    /// Rewrite a request to apply domain fronting.
    ///
    /// - Parameters:
    ///   - request: The original request targeting the relay domain.
    ///   - profile: The fronting profile to apply.
    /// - Returns: A modified request with CDN domain in URL and relay domain in Host.
    public static func applyFronting(
        to request: URLRequest,
        profile: DomainFrontingProfile
    ) -> URLRequest {
        guard let originalURL = request.url,
              var components = URLComponents(url: originalURL, resolvingAgainstBaseURL: false) else {
            return request
        }

        // Preserve the original host for the Host header
        let originalHost = components.host ?? profile.hostDomain

        // Replace the URL host with the CDN domain (this sets TLS SNI)
        components.host = profile.sniDomain

        // Apply path prefix if configured
        if let prefix = profile.pathPrefix {
            components.path = prefix + components.path
        }

        var frontedRequest = request
        frontedRequest.url = components.url

        // Set Host header to the actual relay domain
        frontedRequest.setValue(originalHost, forHTTPHeaderField: "Host")

        return frontedRequest
    }

    /// Remove fronting from a request (restore direct connection).
    ///
    /// - Parameters:
    ///   - request: The fronted request.
    ///   - relayDomain: The actual relay domain to restore.
    /// - Returns: A request targeting the relay domain directly.
    public static func removeFronting(
        from request: URLRequest,
        relayDomain: String
    ) -> URLRequest {
        guard let originalURL = request.url,
              var components = URLComponents(url: originalURL, resolvingAgainstBaseURL: false) else {
            return request
        }

        components.host = relayDomain

        var directRequest = request
        directRequest.url = components.url
        directRequest.setValue(nil, forHTTPHeaderField: "Host")

        return directRequest
    }
}
