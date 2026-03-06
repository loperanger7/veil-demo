// VEIL — Network Transport Error
// Epic: 6 — Network & Transport Layer
// Tickets: VEIL-601, VEIL-602, VEIL-603
//
// Unified error enum for the hardened network transport layer:
//   - TLS 1.3 certificate pinning failures
//   - Traffic padding validation errors
//   - Domain fronting configuration and fallback errors
//   - Censorship detection errors
//   - Signed configuration update verification failures
//
// Follows the categorical error pattern from VeilError and MobileCoinError.

import Foundation

// MARK: - Network Transport Error

/// Errors for the hardened network transport layer (TLS, padding, fronting).
public enum NetworkTransportError: Error, Equatable, Sendable {

    // MARK: - Certificate Pinning (VEIL-601)

    /// Certificate pin validation failed for the given host.
    case pinValidationFailed(host: String)

    /// No certificate pins configured for the given host.
    case noPinsConfigured(host: String)

    /// TLS version below minimum (requires TLS 1.3).
    case tlsVersionTooLow(negotiated: String)

    /// Certificate pin rotation update has an invalid signature.
    case invalidPinRotationSignature

    /// Pin rotation update version is stale (rollback attempt).
    case pinRotationVersionRollback(currentVersion: UInt64, receivedVersion: UInt64)

    /// Pin rotation signing key does not match trusted issuer.
    case pinRotationKeyMismatch

    /// Pin rotation grace period has expired; old pins are no longer accepted.
    case pinRotationGracePeriodExpired

    // MARK: - Traffic Padding (VEIL-602)

    /// Padding validation failed during strip operation.
    case paddingValidationFailed(reason: String)

    /// Padded message exceeds the maximum allowed size.
    case paddingExceedsMaxSize(messageLength: Int, maxSize: Int)

    /// Block size must be a positive power of two.
    case invalidBlockSize(blockSize: Int)

    /// Message data is empty; cannot pad or strip.
    case emptyMessage

    // MARK: - Domain Fronting (VEIL-603)

    /// No fronting profile configured for the detected region.
    case frontingProfileNotAvailable(region: String)

    /// All fronting fallback strategies exhausted.
    case frontingFallbackExhausted

    /// Fronting configuration update has an invalid signature.
    case invalidFrontingConfigSignature

    /// Fronting configuration version is stale (rollback attempt).
    case frontingConfigVersionRollback(currentVersion: UInt64, receivedVersion: UInt64)

    // MARK: - Censorship Detection

    /// Censorship detection probe timed out.
    case censorshipDetectionTimeout(host: String)

    /// Network probe returned a censorship indicator status code.
    case censorshipDetected(host: String, statusCode: Int)

    // MARK: - Configuration Updates

    /// Signed configuration update payload is malformed.
    case malformedConfigurationUpdate(reason: String)

    /// Configuration update timestamp is in the future (clock skew or replay).
    case configurationTimestampInvalid(timestamp: Date)

    /// Configuration update has expired.
    case configurationUpdateExpired(expiresAt: Date)
}

// MARK: - LocalizedError

extension NetworkTransportError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .pinValidationFailed(let host):
            return "Certificate pin validation failed for \(host)"
        case .noPinsConfigured(let host):
            return "No certificate pins configured for \(host)"
        case .tlsVersionTooLow(let negotiated):
            return "TLS version too low: \(negotiated); minimum is TLS 1.3"
        case .invalidPinRotationSignature:
            return "Pin rotation update signature is invalid"
        case .pinRotationVersionRollback(let current, let received):
            return "Pin rotation version rollback: current \(current), received \(received)"
        case .pinRotationKeyMismatch:
            return "Pin rotation signing key does not match trusted issuer"
        case .pinRotationGracePeriodExpired:
            return "Pin rotation grace period has expired"
        case .paddingValidationFailed(let reason):
            return "Padding validation failed: \(reason)"
        case .paddingExceedsMaxSize(let length, let max):
            return "Padded message (\(length) bytes) exceeds maximum (\(max) bytes)"
        case .invalidBlockSize(let size):
            return "Invalid block size: \(size); must be a positive power of two"
        case .emptyMessage:
            return "Cannot pad or strip an empty message"
        case .frontingProfileNotAvailable(let region):
            return "No domain fronting profile for region \(region)"
        case .frontingFallbackExhausted:
            return "All domain fronting fallback strategies exhausted"
        case .invalidFrontingConfigSignature:
            return "Fronting configuration signature is invalid"
        case .frontingConfigVersionRollback(let current, let received):
            return "Fronting config version rollback: current \(current), received \(received)"
        case .censorshipDetectionTimeout(let host):
            return "Censorship detection probe timed out for \(host)"
        case .censorshipDetected(let host, let code):
            return "Censorship detected for \(host) (HTTP \(code))"
        case .malformedConfigurationUpdate(let reason):
            return "Malformed configuration update: \(reason)"
        case .configurationTimestampInvalid(let ts):
            return "Configuration timestamp invalid: \(ts)"
        case .configurationUpdateExpired(let exp):
            return "Configuration update expired at \(exp)"
        }
    }
}
