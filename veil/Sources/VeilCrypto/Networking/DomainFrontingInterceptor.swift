// VEIL — Domain Fronting Interceptor
// Ticket: VEIL-603 — Domain Fronting / Censorship Resistance
// Epic: 6 — Network & Transport Layer
//
// Orchestrates domain fronting for the relay client by:
//   1. Detecting censorship via NetworkCensorshipDetector
//   2. Selecting the appropriate fronting profile for the user's region
//   3. Rewriting HTTP requests to use CDN domains
//   4. Implementing fallback logic when fronting fails
//
// This actor is composed into RelayClient to transparently apply
// domain fronting when needed.

import Foundation

// MARK: - Fronting State

/// Current state of the domain fronting system.
public enum FrontingState: Sendable, Equatable {
    /// Fronting is disabled or not configured.
    case disabled
    /// Direct connection is working; fronting not needed.
    case direct
    /// Fronting is active for the given region.
    case fronting(region: RegionCode, profileIndex: Int)
    /// All fronting strategies failed.
    case failed
}

// MARK: - Domain Fronting Interceptor

/// Orchestrates domain fronting for relay communication.
///
/// Manages the lifecycle of censorship detection, profile selection,
/// request rewriting, and fallback logic.
public actor DomainFrontingInterceptor {
    private let censorshipDetector: NetworkCensorshipDetector
    private var frontingConfig: FrontingConfiguration
    private let detectedRegion: RegionCode

    /// Current fronting state.
    private var state: FrontingState = .disabled

    /// Number of consecutive fronting failures (for fallback logic).
    private var consecutiveFailures: Int = 0
    /// Maximum failures before trying the next profile.
    private let maxFailuresBeforeFallback: Int = 3

    public init(
        censorshipDetector: NetworkCensorshipDetector,
        frontingConfig: FrontingConfiguration,
        detectedRegion: RegionCode
    ) {
        self.censorshipDetector = censorshipDetector
        self.frontingConfig = frontingConfig
        self.detectedRegion = detectedRegion

        // Initialize state based on configuration
        if !frontingConfig.enabled {
            self.state = .disabled
        }
    }

    /// The current fronting state.
    public var currentState: FrontingState { state }

    // MARK: - Request Processing

    /// Process an outgoing request, applying fronting if needed.
    ///
    /// Checks censorship status and rewrites the request if fronting
    /// is required.
    ///
    /// - Parameter request: The original request to the relay server.
    /// - Returns: The (possibly rewritten) request.
    public func processOutgoingRequest(_ request: URLRequest) async -> URLRequest {
        // Determine if we need fronting
        await updateFrontingState()

        switch state {
        case .disabled, .direct:
            return request
        case .fronting(let region, let profileIndex):
            let profiles = frontingConfig.allProfiles(for: region)
            guard profileIndex < profiles.count else {
                return request // Fallback to direct
            }
            return FrontingRequestRewriter.applyFronting(to: request, profile: profiles[profileIndex])
        case .failed:
            // All strategies exhausted — try direct as last resort
            return request
        }
    }

    /// Report a request failure to trigger fallback logic.
    ///
    /// Call this when a fronted request fails. After enough consecutive
    /// failures, the interceptor will try the next fronting profile
    /// or fall back to direct connection.
    ///
    /// - Parameter error: The error that occurred.
    public func reportFailure(_ error: Error) {
        consecutiveFailures += 1

        guard case .fronting(let region, let profileIndex) = state else {
            return
        }

        let profiles = frontingConfig.allProfiles(for: region)

        if consecutiveFailures >= maxFailuresBeforeFallback {
            consecutiveFailures = 0

            // Try the next profile
            let nextIndex = profileIndex + 1
            if nextIndex < profiles.count {
                // Check the fallback policy
                let currentProfile = profiles[profileIndex]
                switch currentProfile.fallbackPolicy {
                case .tryAlternateProfiles:
                    state = .fronting(region: region, profileIndex: nextIndex)
                case .directOnFailure:
                    state = .direct
                case .failCompletely:
                    state = .failed
                }
            } else {
                // No more profiles — check last profile's fallback policy
                let lastProfile = profiles[profileIndex]
                switch lastProfile.fallbackPolicy {
                case .directOnFailure, .tryAlternateProfiles:
                    state = .direct
                case .failCompletely:
                    state = .failed
                }
            }
        }
    }

    /// Report a successful request to reset the failure counter.
    public func reportSuccess() {
        consecutiveFailures = 0
    }

    // MARK: - Configuration Updates

    /// Apply a new fronting configuration from a signed update.
    ///
    /// - Parameter newConfig: The new fronting configuration.
    public func updateConfiguration(_ newConfig: FrontingConfiguration) {
        frontingConfig = newConfig
        if !newConfig.enabled {
            state = .disabled
        }
        // Reset failure state on config change
        consecutiveFailures = 0
    }

    // MARK: - Internal

    /// Update the fronting state based on censorship detection.
    private func updateFrontingState() async {
        guard frontingConfig.enabled else {
            state = .disabled
            return
        }

        // Don't re-probe if already in a stable state
        switch state {
        case .fronting:
            return // Already fronting, don't change unless failure reported
        case .failed:
            return // Already failed, caller must reset
        case .disabled, .direct:
            break // Re-evaluate
        }

        let shouldFront = await censorshipDetector.shouldActivateFronting()

        if shouldFront {
            let profiles = frontingConfig.allProfiles(for: detectedRegion)
            if !profiles.isEmpty {
                state = .fronting(region: detectedRegion, profileIndex: 0)
            } else {
                // Censorship detected but no fronting profile for this region
                state = .direct // Best effort: try direct anyway
            }
        } else {
            state = .direct
        }
    }

    /// Force re-evaluation of censorship status.
    public func reevaluate() async {
        await censorshipDetector.clearCache()
        consecutiveFailures = 0
        state = .direct
        await updateFrontingState()
    }

    /// Reset to initial state (useful for testing or reconnection).
    public func reset() {
        state = frontingConfig.enabled ? .direct : .disabled
        consecutiveFailures = 0
    }
}

// MARK: - Region Detection

/// Utility for detecting the user's region.
public enum RegionDetector {
    /// Detect the user's region from the device locale.
    ///
    /// Returns the ISO 3166-1 alpha-2 region code from the device's
    /// current locale. Falls back to "US" if undetermined.
    public static func detectFromLocale() -> RegionCode {
        if #available(iOS 16, macOS 13, *) {
            return Locale.current.region?.identifier ?? "US"
        } else {
            return Locale.current.regionCode ?? "US"
        }
    }

    /// Detect region from a provided ISO country code.
    public static func from(isoCode: String) -> RegionCode {
        isoCode.uppercased()
    }
}
