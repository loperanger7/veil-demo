// VEIL — Network Censorship Detector
// Ticket: VEIL-603 — Domain Fronting / Censorship Resistance
// Epic: 6 — Network & Transport Layer
//
// Probes network connectivity to determine if the Veil relay server
// is reachable directly or if domain fronting is required.
//
// Detection strategy:
//   1. On app launch, send a lightweight HTTP probe to the relay
//   2. If the probe times out, returns 403, or returns 451:
//      → Censorship likely; activate domain fronting
//   3. If the probe succeeds (200):
//      → Direct connection works; no fronting needed
//   4. Cache the result with a TTL to avoid repeated slow probes
//
// The detector is an actor for thread-safe concurrent access with
// cached probe results.

import Foundation

// MARK: - Censorship Probe Result

/// Result of a censorship detection probe.
public enum CensorshipProbeResult: Sendable, Equatable {
    /// Direct connection succeeded — no fronting needed.
    case reachable
    /// Connection appears censored (timeout, 403, or 451).
    case censored(reason: CensorshipReason)
    /// Probe failed for non-censorship reasons (e.g., server down).
    case inconclusive(error: String)
}

/// Reason censorship was detected.
public enum CensorshipReason: String, Sendable, Codable, Equatable {
    /// Connection timed out.
    case timeout
    /// HTTP 403 Forbidden (often used by DPI firewalls).
    case forbidden
    /// HTTP 451 Unavailable For Legal Reasons.
    case legalBlock
    /// TCP connection reset by intermediate device.
    case connectionReset
    /// DNS resolution was poisoned or failed.
    case dnsPoisoning
}

// MARK: - Detector Configuration

/// Configuration for the censorship detector.
public struct CensorshipDetectorConfiguration: Sendable {
    /// URL to probe for direct connectivity (lightweight health endpoint).
    public let probeURL: URL
    /// Probe timeout in seconds.
    public let probeTimeout: TimeInterval
    /// How long to cache a probe result before re-probing.
    public let cacheTTL: TimeInterval
    /// HTTP status codes that indicate censorship.
    public let censorshipStatusCodes: Set<Int>

    public init(
        probeURL: URL,
        probeTimeout: TimeInterval = 10,
        cacheTTL: TimeInterval = 300, // 5 minutes
        censorshipStatusCodes: Set<Int> = [403, 451]
    ) {
        self.probeURL = probeURL
        self.probeTimeout = probeTimeout
        self.cacheTTL = cacheTTL
        self.censorshipStatusCodes = censorshipStatusCodes
    }

    /// Default configuration for the Veil relay.
    public static func veilDefault(relayBaseURL: URL) -> CensorshipDetectorConfiguration {
        CensorshipDetectorConfiguration(
            probeURL: relayBaseURL.appendingPathComponent("/v1/health"),
            probeTimeout: 10,
            cacheTTL: 300
        )
    }
}

// MARK: - Censorship Detector

/// Detects network censorship by probing relay server connectivity.
///
/// Thread-safe actor with cached probe results to minimize latency
/// on repeated checks.
public actor NetworkCensorshipDetector {
    private let configuration: CensorshipDetectorConfiguration
    private let urlSession: URLSession

    /// Cached probe result and timestamp.
    private var cachedResult: CensorshipProbeResult?
    private var cachedAt: Date?

    /// Whether a probe is currently in flight (prevents concurrent probes).
    private var probeInFlight: Bool = false

    public init(configuration: CensorshipDetectorConfiguration) {
        self.configuration = configuration

        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.timeoutIntervalForRequest = configuration.probeTimeout
        sessionConfig.timeoutIntervalForResource = configuration.probeTimeout
        sessionConfig.waitsForConnectivity = false

        self.urlSession = URLSession(configuration: sessionConfig)
    }

    /// Check if the relay appears to be censored.
    ///
    /// Returns a cached result if within the TTL window. Otherwise,
    /// performs a fresh probe.
    ///
    /// - Returns: The probe result.
    public func detectCensorship() async -> CensorshipProbeResult {
        // Return cached result if still valid
        if let cached = cachedResult,
           let cachedTime = cachedAt,
           Date().timeIntervalSince(cachedTime) < configuration.cacheTTL {
            return cached
        }

        // Perform fresh probe
        return await probe()
    }

    /// Force a fresh probe, ignoring any cached result.
    ///
    /// - Returns: The fresh probe result.
    public func forceProbe() async -> CensorshipProbeResult {
        await probe()
    }

    /// Clear the cached probe result.
    public func clearCache() {
        cachedResult = nil
        cachedAt = nil
    }

    /// Whether fronting should be activated based on the latest probe.
    public func shouldActivateFronting() async -> Bool {
        let result = await detectCensorship()
        switch result {
        case .censored:
            return true
        case .reachable, .inconclusive:
            return false
        }
    }

    // MARK: - Internal Probing

    /// Execute a connectivity probe.
    private func probe() async -> CensorshipProbeResult {
        // Prevent concurrent probes
        guard !probeInFlight else {
            return cachedResult ?? .inconclusive(error: "Probe already in flight")
        }
        probeInFlight = true
        defer { probeInFlight = false }

        var request = URLRequest(url: configuration.probeURL)
        request.httpMethod = "HEAD"
        request.timeoutInterval = configuration.probeTimeout

        let result: CensorshipProbeResult

        do {
            let (_, response) = try await urlSession.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                result = .inconclusive(error: "Non-HTTP response")
                cacheResult(result)
                return result
            }

            if httpResponse.statusCode == 200 || httpResponse.statusCode == 204 {
                result = .reachable
            } else if configuration.censorshipStatusCodes.contains(httpResponse.statusCode) {
                let reason: CensorshipReason = httpResponse.statusCode == 451 ? .legalBlock : .forbidden
                result = .censored(reason: reason)
            } else {
                result = .inconclusive(error: "HTTP \(httpResponse.statusCode)")
            }
        } catch let error as URLError {
            switch error.code {
            case .timedOut:
                result = .censored(reason: .timeout)
            case .networkConnectionLost, .notConnectedToInternet:
                result = .inconclusive(error: "No network connectivity")
            case .dnsLookupFailed:
                result = .censored(reason: .dnsPoisoning)
            case .secureConnectionFailed:
                result = .censored(reason: .connectionReset)
            default:
                result = .inconclusive(error: error.localizedDescription)
            }
        } catch {
            result = .inconclusive(error: error.localizedDescription)
        }

        cacheResult(result)
        return result
    }

    /// Cache a probe result with the current timestamp.
    private func cacheResult(_ result: CensorshipProbeResult) {
        cachedResult = result
        cachedAt = Date()
    }
}
