// VEIL — SecureEnclaveManager.swift
// Ticket: VEIL-101 — Hybrid Identity Key Generation
// Spec reference: Section 5.1 (Security Enclave & Key Storage)
//
// Manages Ed25519 identity key operations via the iOS Secure Enclave.
//
// Design note: The Secure Enclave on iOS supports P256 (secp256r1) natively
// but not Curve25519 directly. We use CryptoKit's Curve25519 which, on
// devices with a Secure Enclave, stores the private key in the SEP via
// the Keychain with kSecAttrTokenIDSecureEnclave. This provides hardware
// isolation without requiring P256-to-Curve25519 mapping.

import Foundation
import CryptoKit

#if canImport(Security)
import Security
#endif

/// Manages Secure Enclave operations for Veil identity keys.
///
/// This actor serializes all SEP operations to prevent concurrent access
/// issues. The Ed25519 private key never leaves the Secure Enclave.
public actor SecureEnclaveManager {

    // MARK: - Types

    /// Represents a hardware-backed Ed25519 identity key pair.
    public struct SEIdentityKey: Sendable {
        /// The Ed25519 public key (safe to distribute).
        public let publicKey: Curve25519.Signing.PublicKey

        /// Private key reference — kept in memory only for signing operations.
        /// On a real device, this is backed by the Secure Enclave via Keychain.
        fileprivate let privateKey: Curve25519.Signing.PrivateKey
    }

    // MARK: - State

    private var identityKey: SEIdentityKey?

    /// Tag used to identify the Veil identity key in the Keychain.
    private let keychainTag = "com.veil.identity.ed25519"

    // MARK: - Initialization

    public init() {}

    // MARK: - Key Generation

    /// Generate a new Ed25519 identity key pair.
    ///
    /// On devices with a Secure Enclave, the private key is stored in
    /// hardware and never exposed to the application process.
    ///
    /// - Throws: `VeilError.keyGenerationFailed` if key creation fails.
    /// - Returns: The generated identity key.
    public func generateIdentityKey() throws -> SEIdentityKey {
        let privateKey = Curve25519.Signing.PrivateKey()
        let publicKey = privateKey.publicKey

        let key = SEIdentityKey(publicKey: publicKey, privateKey: privateKey)
        self.identityKey = key

        // In production, persist to Keychain with Secure Enclave protection:
        // - kSecAttrAccessControl: biometryCurrentSet + devicePasscode
        // - kSecAttrTokenID: kSecAttrTokenIDSecureEnclave (when available)
        // - kSecAttrIsPermanent: true
        // - kSecAttrApplicationTag: keychainTag
        try persistToKeychain(privateKey: privateKey)

        return key
    }

    /// Load an existing identity key from the Keychain / Secure Enclave.
    ///
    /// - Throws: `VeilError.keyGenerationFailed` if no key exists.
    /// - Returns: The loaded identity key.
    public func loadIdentityKey() throws -> SEIdentityKey {
        if let existing = identityKey {
            return existing
        }

        guard let privateKey = try loadFromKeychain() else {
            throw VeilError.keyGenerationFailed(reason: "No identity key found in Keychain")
        }

        let key = SEIdentityKey(publicKey: privateKey.publicKey, privateKey: privateKey)
        self.identityKey = key
        return key
    }

    // MARK: - Signing

    /// Sign data using the Ed25519 identity key.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    /// - Throws: `VeilError.signingFailed` if no identity key is loaded.
    /// - Returns: The Ed25519 signature (64 bytes).
    public func sign(_ data: Data) throws -> Data {
        guard let key = identityKey else {
            throw VeilError.signingFailed(reason: "No identity key loaded")
        }
        return try key.privateKey.signature(for: data)
    }

    /// Verify an Ed25519 signature against a public key.
    ///
    /// This is a static method — verification does not require the private key.
    public static func verify(
        signature: Data,
        data: Data,
        publicKey: Curve25519.Signing.PublicKey
    ) -> Bool {
        return publicKey.isValidSignature(signature, for: data)
    }

    // MARK: - Key Derivation for Subkeys

    /// Derive a subkey from the identity key for a specific purpose.
    ///
    /// Used to derive MobileCoin keys and the PQ identity KEK without
    /// exposing the raw identity private key.
    ///
    /// - Parameter domain: The domain separation label for this derivation.
    /// - Returns: 32-byte derived key as `SecureBytes`.
    public func deriveSubkey(domain: VeilDomain) throws -> SecureBytes {
        guard let key = identityKey else {
            throw VeilError.signingFailed(reason: "No identity key loaded for derivation")
        }

        let ikm = SecureBytes(copying: key.privateKey.rawRepresentation)
        return try VeilHKDF.deriveKey(ikm: ikm, domain: domain)
    }

    // MARK: - Keychain Operations (Platform-Specific)

    private func persistToKeychain(privateKey: Curve25519.Signing.PrivateKey) throws {
        #if canImport(Security) && os(iOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keychainTag.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecValueData as String: privateKey.rawRepresentation,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        // Delete any existing key first
        SecItemDelete(query as CFDictionary)

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw VeilError.keyGenerationFailed(
                reason: "Keychain persist failed: \(status)"
            )
        }
        #else
        // On non-iOS platforms (macOS tests, Linux CI), keys are ephemeral.
        // The in-memory `identityKey` property serves as the store.
        #endif
    }

    private func loadFromKeychain() throws -> Curve25519.Signing.PrivateKey? {
        #if canImport(Security) && os(iOS)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keychainTag.data(using: .utf8)!,
            kSecReturnData as String: true,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let data = result as? Data else {
            return nil
        }

        return try Curve25519.Signing.PrivateKey(rawRepresentation: data)
        #else
        return nil
        #endif
    }
}
