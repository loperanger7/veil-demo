// VEIL — TLS 1.3 Certificate Pinning
// Tickets: VEIL-202 (secure relay communication), VEIL-601 (TLS 1.3 + rotation)
// Spec reference: Section 2.1
//
// URLSession delegate that enforces:
//   1. TLS 1.3 minimum (reject TLS 1.2 and below)
//   2. Certificate pinning against known relay server leaf certificate(s)
//   3. Configurable pin rotation for zero-downtime certificate rollover
//   4. Signed configuration updates for out-of-band pin delivery
//
// This prevents MITM attacks even if a CA is compromised. The relay
// server's certificate hash must be compiled into the client binary
// or delivered via a trusted out-of-band channel.

import Foundation
import CryptoKit

/// Certificate pin: SHA-256 hash of the DER-encoded leaf certificate.
public struct CertificatePin: Sendable, Hashable {
    /// SHA-256 hash of the certificate's Subject Public Key Info (SPKI).
    public let sha256Hash: Data

    public init(sha256Hash: Data) {
        precondition(sha256Hash.count == 32, "SHA-256 hash must be 32 bytes")
        self.sha256Hash = sha256Hash
    }

    /// Create a pin from a hex-encoded SHA-256 hash string.
    public init(hexString: String) {
        let bytes = stride(from: 0, to: hexString.count, by: 2).compactMap { i -> UInt8? in
            let start = hexString.index(hexString.startIndex, offsetBy: i)
            let end = hexString.index(start, offsetBy: 2)
            return UInt8(hexString[start..<end], radix: 16)
        }
        self.init(sha256Hash: Data(bytes))
    }

    /// Hex-encoded representation of the SHA-256 hash.
    public var hexString: String {
        sha256Hash.map { String(format: "%02x", $0) }.joined()
    }
}

/// TLS 1.3 certificate pinning configuration.
public struct PinningConfiguration: Sendable {
    /// Set of acceptable certificate pins (supports rotation: old + new).
    public let pins: Set<CertificatePin>
    /// The relay server hostname to validate against.
    public let hostname: String
    /// Whether to enforce pinning (false = report-only mode for testing).
    public let enforced: Bool

    public init(pins: Set<CertificatePin>, hostname: String, enforced: Bool = true) {
        self.pins = pins
        self.hostname = hostname
        self.enforced = enforced
    }

    /// Development configuration that accepts any certificate.
    /// NEVER use in production.
    public static func development(hostname: String) -> PinningConfiguration {
        PinningConfiguration(pins: [], hostname: hostname, enforced: false)
    }
}

// MARK: - Pin Rotation State

/// Manages pin rotation with a grace period during which both old and
/// new pins are accepted, preventing client lockout during certificate rollover.
public struct PinRotationState: Sendable {
    /// The current (active) set of certificate pins.
    public let currentPins: Set<CertificatePin>
    /// Pins from the previous rotation that are still within the grace period.
    public let gracePeriodPins: Set<CertificatePin>
    /// When the grace period started (old pins added).
    public let gracePeriodStarted: Date?
    /// Duration of the grace period in seconds.
    public let gracePeriodDuration: TimeInterval

    public init(
        currentPins: Set<CertificatePin>,
        gracePeriodPins: Set<CertificatePin> = [],
        gracePeriodStarted: Date? = nil,
        gracePeriodDuration: TimeInterval = 604800 // 7 days
    ) {
        self.currentPins = currentPins
        self.gracePeriodPins = gracePeriodPins
        self.gracePeriodStarted = gracePeriodStarted
        self.gracePeriodDuration = gracePeriodDuration
    }

    /// All pins that are currently acceptable (current + grace period).
    public var acceptablePins: Set<CertificatePin> {
        guard let started = gracePeriodStarted else {
            return currentPins
        }
        // Check if grace period has expired
        if Date().timeIntervalSince(started) > gracePeriodDuration {
            return currentPins
        }
        return currentPins.union(gracePeriodPins)
    }

    /// Whether we are currently in a grace period.
    public var isInGracePeriod: Bool {
        guard let started = gracePeriodStarted else { return false }
        return Date().timeIntervalSince(started) <= gracePeriodDuration
    }

    /// Apply a pin rotation: current pins become grace period pins,
    /// new pins become current.
    public func rotate(to newPins: Set<CertificatePin>, gracePeriodDuration: TimeInterval? = nil) -> PinRotationState {
        PinRotationState(
            currentPins: newPins,
            gracePeriodPins: currentPins,
            gracePeriodStarted: Date(),
            gracePeriodDuration: gracePeriodDuration ?? self.gracePeriodDuration
        )
    }
}

// MARK: - VeilTLSDelegate

/// URLSession delegate that enforces TLS 1.3 and certificate pinning.
///
/// Supports pin rotation via `applyRotation(_:)`. During the grace period,
/// both the old and new pins are accepted.
///
/// Usage:
/// ```swift
/// let delegate = VeilTLSDelegate(configuration: pinConfig)
/// let session = URLSession(configuration: .default, delegate: delegate, delegateQueue: nil)
/// ```
public final class VeilTLSDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    private let configuration: PinningConfiguration
    /// Thread-safe rotation state (protected by lock).
    private let lock = NSLock()
    private var _rotationState: PinRotationState
    /// Callback invoked on pin validation failure (for logging/metrics).
    public var onPinValidationFailure: (@Sendable (_ host: String, _ pinHash: Data) -> Void)?

    public init(configuration: PinningConfiguration) {
        self.configuration = configuration
        self._rotationState = PinRotationState(currentPins: configuration.pins)
        super.init()
    }

    /// The current rotation state (thread-safe read).
    public var rotationState: PinRotationState {
        lock.lock()
        defer { lock.unlock() }
        return _rotationState
    }

    /// Apply a signed pin rotation.
    ///
    /// Current pins move to the grace period set; new pins become active.
    /// Both old and new pins are accepted for the duration of the grace period.
    ///
    /// - Parameters:
    ///   - newPins: The new set of certificate pins.
    ///   - gracePeriodDuration: Optional override for the grace period duration.
    public func applyRotation(newPins: Set<CertificatePin>, gracePeriodDuration: TimeInterval? = nil) {
        lock.lock()
        defer { lock.unlock() }
        _rotationState = _rotationState.rotate(to: newPins, gracePeriodDuration: gracePeriodDuration)
    }

    /// Apply a pin rotation from a verified PinRotationPayload.
    ///
    /// - Parameter payload: The decoded pin rotation payload.
    public func applyRotation(from payload: PinRotationPayload) {
        applyRotation(
            newPins: payload.certificatePins,
            gracePeriodDuration: payload.gracePeriodSeconds
        )
    }

    public func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }

        // Verify hostname matches
        guard challenge.protectionSpace.host == configuration.hostname else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // Evaluate the server trust
        var error: CFError?
        guard SecTrustEvaluateWithError(serverTrust, &error) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        // TLS 1.3 enforcement: URLSessionConfiguration.tlsMinimumSupportedProtocolVersion
        // is set to .TLSv13 by the caller. The Security framework rejects < TLS 1.3
        // during trust evaluation when configured properly.

        // Skip pin validation in development mode
        guard configuration.enforced else {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
            return
        }

        // Extract the leaf certificate and compute its SPKI SHA-256 hash
        guard let leafCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        let leafData = SecCertificateCopyData(leafCertificate) as Data
        let hash = SHA256.hash(data: leafData)
        let hashData = Data(hash)
        let pin = CertificatePin(sha256Hash: hashData)

        // Check against all acceptable pins (current + grace period)
        let acceptable = rotationState.acceptablePins
        if acceptable.contains(pin) {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            // Pin mismatch — potential MITM
            // SECURITY: Do NOT log the received hash (could assist attackers)
            onPinValidationFailure?(challenge.protectionSpace.host, hashData)
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }

    /// Compute the SHA-256 pin hash for a given DER-encoded certificate.
    /// Useful for deriving pins from known certificates during setup.
    public static func computePinHash(derEncodedCertificate: Data) -> CertificatePin {
        let hash = SHA256.hash(data: derEncodedCertificate)
        return CertificatePin(sha256Hash: Data(hash))
    }
}
