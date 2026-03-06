// VEIL — Signed Configuration Update
// Epic: 6 — Network & Transport Layer
// Tickets: VEIL-601 (pin rotation), VEIL-603 (fronting config)
//
// Out-of-band configuration delivery with Ed25519 signature verification.
// Configuration updates are signed by a trusted issuer (hardcoded public key)
// to prevent MITM injection of malicious configurations.
//
// Used by both certificate pin rotation (VEIL-601) and domain fronting
// configuration delivery (VEIL-603).

import Foundation
import CryptoKit

// MARK: - Configuration Update Types

/// A versioned, signed configuration payload delivered out-of-band.
///
/// The update is signed with Ed25519 to prevent tampering. The version
/// number prevents rollback attacks. The expiration prevents replay
/// of stale configurations.
public struct SignedConfigurationUpdate: Sendable, Codable, Equatable {
    /// Monotonically increasing version number (prevents rollback).
    public let version: UInt64
    /// Unix timestamp when this update was issued.
    public let issuedAt: Date
    /// Unix timestamp after which this update is no longer valid.
    public let expiresAt: Date
    /// The configuration payload (opaque bytes; consumer interprets).
    public let payload: Data
    /// Ed25519 signature over (version || issuedAt || expiresAt || payload).
    public let signature: Data

    public init(
        version: UInt64,
        issuedAt: Date,
        expiresAt: Date,
        payload: Data,
        signature: Data
    ) {
        self.version = version
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.payload = payload
        self.signature = signature
    }
}

// MARK: - Configuration Update Verifier

/// Verifies and applies signed configuration updates.
///
/// Verification checks:
///   1. Ed25519 signature is valid against the trusted issuer public key
///   2. Version is strictly greater than the currently applied version
///   3. `issuedAt` is not in the future (with clock skew tolerance)
///   4. `expiresAt` has not passed
public struct ConfigurationUpdateVerifier: Sendable {
    /// Ed25519 public key of the trusted configuration issuer.
    private let trustedPublicKey: Curve25519.Signing.PublicKey
    /// Maximum allowed clock skew (default: 5 minutes).
    private let clockSkewTolerance: TimeInterval
    /// Current applied version (updates must be strictly greater).
    private var currentVersion: UInt64

    public init(
        trustedPublicKeyBytes: Data,
        currentVersion: UInt64 = 0,
        clockSkewTolerance: TimeInterval = 300
    ) throws {
        self.trustedPublicKey = try Curve25519.Signing.PublicKey(rawRepresentation: trustedPublicKeyBytes)
        self.currentVersion = currentVersion
        self.clockSkewTolerance = clockSkewTolerance
    }

    /// Verify a signed configuration update.
    ///
    /// - Parameter update: The signed update to verify.
    /// - Returns: The verified payload bytes.
    /// - Throws: `NetworkTransportError` if verification fails.
    public mutating func verify(_ update: SignedConfigurationUpdate) throws -> Data {
        // 1. Check version monotonicity (prevent rollback)
        guard update.version > currentVersion else {
            throw NetworkTransportError.pinRotationVersionRollback(
                currentVersion: currentVersion,
                receivedVersion: update.version
            )
        }

        // 2. Check timestamp validity
        let now = Date()
        let futureThreshold = now.addingTimeInterval(clockSkewTolerance)

        guard update.issuedAt <= futureThreshold else {
            throw NetworkTransportError.configurationTimestampInvalid(timestamp: update.issuedAt)
        }

        guard update.expiresAt > now else {
            throw NetworkTransportError.configurationUpdateExpired(expiresAt: update.expiresAt)
        }

        // 3. Reconstruct the signed message
        let signedData = Self.buildSignedData(
            version: update.version,
            issuedAt: update.issuedAt,
            expiresAt: update.expiresAt,
            payload: update.payload
        )

        // 4. Verify Ed25519 signature
        guard trustedPublicKey.isValidSignature(update.signature, for: signedData) else {
            throw NetworkTransportError.invalidPinRotationSignature
        }

        // 5. Accept update — advance version
        currentVersion = update.version

        return update.payload
    }

    /// Build the canonical byte sequence that is signed.
    ///
    /// Format: version (8 bytes LE) || issuedAt (8 bytes LE) || expiresAt (8 bytes LE) || payload
    public static func buildSignedData(
        version: UInt64,
        issuedAt: Date,
        expiresAt: Date,
        payload: Data
    ) -> Data {
        var data = Data()
        // Version (little-endian UInt64)
        var v = version.littleEndian
        data.append(Data(bytes: &v, count: 8))
        // IssuedAt (Unix timestamp as little-endian Int64)
        var issued = Int64(issuedAt.timeIntervalSince1970).littleEndian
        data.append(Data(bytes: &issued, count: 8))
        // ExpiresAt (Unix timestamp as little-endian Int64)
        var expires = Int64(expiresAt.timeIntervalSince1970).littleEndian
        data.append(Data(bytes: &expires, count: 8))
        // Payload
        data.append(payload)
        return data
    }

    /// The currently applied configuration version.
    public var appliedVersion: UInt64 { currentVersion }
}

// MARK: - Signing Utility (for testing and server-side)

/// Signs a configuration update payload. Used by the configuration
/// server (or test harness) to produce signed updates.
public struct ConfigurationUpdateSigner: Sendable {
    private let privateKey: Curve25519.Signing.PrivateKey

    public init(privateKey: Curve25519.Signing.PrivateKey) {
        self.privateKey = privateKey
    }

    /// Generate a fresh Ed25519 signing key pair for testing.
    public init() {
        self.privateKey = Curve25519.Signing.PrivateKey()
    }

    /// The public key corresponding to this signer.
    public var publicKey: Data {
        privateKey.publicKey.rawRepresentation
    }

    /// Sign a configuration update.
    ///
    /// - Parameters:
    ///   - version: Monotonically increasing version number.
    ///   - issuedAt: Timestamp of issuance.
    ///   - expiresAt: Expiration timestamp.
    ///   - payload: The configuration payload bytes.
    /// - Returns: A signed configuration update.
    public func sign(
        version: UInt64,
        issuedAt: Date = Date(),
        expiresAt: Date = Date().addingTimeInterval(86400 * 30), // 30 days
        payload: Data
    ) throws -> SignedConfigurationUpdate {
        let signedData = ConfigurationUpdateVerifier.buildSignedData(
            version: version,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            payload: payload
        )

        let signature = try privateKey.signature(for: signedData)

        return SignedConfigurationUpdate(
            version: version,
            issuedAt: issuedAt,
            expiresAt: expiresAt,
            payload: payload,
            signature: signature
        )
    }
}

// MARK: - Pin Rotation Configuration

/// A pin rotation payload carried inside a SignedConfigurationUpdate.
///
/// Contains the new set of certificate pins, the grace period during
/// which both old and new pins are accepted, and the target hostname.
public struct PinRotationPayload: Sendable, Codable, Equatable {
    /// The new certificate pins (SHA-256 hashes as hex strings).
    public let pinHashes: [String]
    /// The hostname these pins apply to.
    public let hostname: String
    /// Grace period in seconds during which old pins are still accepted.
    public let gracePeriodSeconds: TimeInterval

    public init(pinHashes: [String], hostname: String, gracePeriodSeconds: TimeInterval = 604800) {
        self.pinHashes = pinHashes
        self.hostname = hostname
        self.gracePeriodSeconds = gracePeriodSeconds
    }

    /// Decode from a raw payload (JSON).
    public static func decode(from data: Data) throws -> PinRotationPayload {
        try JSONDecoder().decode(PinRotationPayload.self, from: data)
    }

    /// Encode to raw payload (JSON).
    public func encode() throws -> Data {
        try JSONEncoder().encode(self)
    }

    /// Convert pin hashes to CertificatePin set.
    public var certificatePins: Set<CertificatePin> {
        Set(pinHashes.map { CertificatePin(hexString: $0) })
    }
}
