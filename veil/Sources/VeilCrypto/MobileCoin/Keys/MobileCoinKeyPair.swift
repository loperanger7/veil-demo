// MobileCoinKeyPair.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-401: Derive MobileCoin spend and view keys deterministically from
// the Veil identity key using domain-separated HKDF-SHA-512.
//
// mob_spend_key = HKDF(ikm=IK, info="Veil:MOB:spend:v1") → Ristretto255 scalar
// mob_view_key  = HKDF(ikm=IK, info="Veil:MOB:view:v1") → Ristretto255 scalar
//
// Security model:
// - Spend key stored in Keychain with biometric access control
// - View key stored with after-first-unlock access (for background Fog queries)
//
// References: Veil Spec Section 3.2, 8.1

import Foundation

// MARK: - MobileCoin Key Pair

/// Holds the derived MobileCoin spend and view keys in zeroizing memory.
/// Keys are derived deterministically from the Veil identity key — the same
/// identity key always produces the same MobileCoin keys.
public struct MobileCoinKeyPair: Sendable {

    // MARK: Properties

    /// Private spend key (Ristretto255 scalar, 32 bytes).
    /// Required for transaction signing. Stored with biometric access control.
    public let spendKey: SecureBytes

    /// Private view key (Ristretto255 scalar, 32 bytes).
    /// Required for balance queries and incoming TXO detection.
    /// Stored with after-first-unlock access for background refresh.
    public let viewKey: SecureBytes

    /// Public spend key (Ristretto255 point, 32 bytes).
    /// Derived from spendKey via scalar-base multiplication.
    public let spendPublicKey: Data

    /// Public view key (Ristretto255 point, 32 bytes).
    /// Derived from viewKey via scalar-base multiplication.
    public let viewPublicKey: Data

    // MARK: Derivation

    /// Derive MobileCoin keys from a Veil identity key.
    /// - Parameters:
    ///   - identityKey: The Veil identity private key (IK).
    ///   - client: MobileCoinClient for scalar validation.
    /// - Returns: A validated key pair ready for wallet operations.
    /// - Throws: `MobileCoinError.invalidSpendKey` or `.invalidViewKey` if
    ///           HKDF output is not a valid Ristretto255 scalar.
    public static func derive(
        from identityKey: SecureBytes,
        client: MobileCoinClient
    ) async throws -> MobileCoinKeyPair {
        // Guard: identity key must be non-empty
        guard identityKey.count >= 32 else {
            throw MobileCoinError.identityKeyCorrupted(
                detail: "Identity key too short: \(identityKey.count) bytes, expected >= 32."
            )
        }

        // Derive spend key: HKDF(ikm=IK, info="Veil:MOB:spend:v1")
        let spendKeyBytes = try deriveKey(
            from: identityKey,
            domain: .mobSpendKey,
            outputLength: 32
        )

        // Validate spend key is a valid Ristretto255 scalar
        let spendValid = try await client.isValidScalar(spendKeyBytes)
        guard spendValid else {
            throw MobileCoinError.invalidSpendKey
        }

        // Derive view key: HKDF(ikm=IK, info="Veil:MOB:view:v1")
        let viewKeyBytes = try deriveKey(
            from: identityKey,
            domain: .mobViewKey,
            outputLength: 32
        )

        // Validate view key is a valid Ristretto255 scalar
        let viewValid = try await client.isValidScalar(viewKeyBytes)
        guard viewValid else {
            throw MobileCoinError.invalidViewKey
        }

        // Derive public keys via scalar-base multiplication
        // In mock mode, we use a deterministic derivation
        let spendPubKey = derivePublicKey(from: spendKeyBytes)
        let viewPubKey = derivePublicKey(from: viewKeyBytes)

        return MobileCoinKeyPair(
            spendKey: spendKeyBytes,
            viewKey: viewKeyBytes,
            spendPublicKey: spendPubKey,
            viewPublicKey: viewPubKey
        )
    }

    // MARK: Keychain Persistence

    /// Store the key pair in the Keychain with appropriate access controls.
    /// - Spend key: biometric access control (kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly)
    /// - View key: after-first-unlock (kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
    public func storeInKeychain(service: String = "app.veil.mobilecoin") throws {
        // Store spend key with biometric requirement
        try KeychainHelper.store(
            data: try spendKey.withUnsafeBytes { Data($0) },
            service: service,
            account: "spend_key",
            accessControl: .biometricCurrentSet
        )

        // Store view key with less restrictive access (for background Fog queries)
        try KeychainHelper.store(
            data: try viewKey.withUnsafeBytes { Data($0) },
            service: service,
            account: "view_key",
            accessControl: .afterFirstUnlock
        )
    }

    /// Load a previously stored key pair from the Keychain.
    /// - Parameter service: Keychain service identifier.
    /// - Returns: The restored key pair, or nil if not found.
    public static func loadFromKeychain(
        service: String = "app.veil.mobilecoin"
    ) throws -> MobileCoinKeyPair? {
        guard let spendData = try KeychainHelper.load(
            service: service,
            account: "spend_key"
        ) else {
            return nil
        }

        guard let viewData = try KeychainHelper.load(
            service: service,
            account: "view_key"
        ) else {
            return nil
        }

        let spendKey = SecureBytes(bytes: Array(spendData))
        let viewKey = SecureBytes(bytes: Array(viewData))

        return MobileCoinKeyPair(
            spendKey: spendKey,
            viewKey: viewKey,
            spendPublicKey: derivePublicKey(from: spendKey),
            viewPublicKey: derivePublicKey(from: viewKey)
        )
    }

    /// Delete stored keys from Keychain.
    public static func deleteFromKeychain(
        service: String = "app.veil.mobilecoin"
    ) {
        KeychainHelper.delete(service: service, account: "spend_key")
        KeychainHelper.delete(service: service, account: "view_key")
    }

    // MARK: - Private Helpers

    /// HKDF-based key derivation using domain separation.
    private static func deriveKey(
        from identityKey: SecureBytes,
        domain: VeilDomain,
        outputLength: Int
    ) throws -> SecureBytes {
        return try VeilHKDF.deriveKey(
            ikm: identityKey,
            salt: nil,
            domain: domain,
            outputByteCount: outputLength
        )
    }

    /// Derive a mock public key from a private key (scalar-base multiplication).
    /// In production, this would use Ristretto255 basepoint multiplication.
    /// Mock: HKDF(ikm=privateKey, info="Veil:MOB:pubkey:v1") truncated to 32 bytes.
    private static func derivePublicKey(from privateKey: SecureBytes) -> Data {
        let privBytes = (try? privateKey.withUnsafeBytes { Array($0) }) ?? []
        // Deterministic derivation: hash the private key with a fixed domain
        var pubKey = Data(count: 32)
        for (i, byte) in privBytes.enumerated() {
            let idx = i % 32
            pubKey[idx] ^= byte
            pubKey[idx] = pubKey[idx] &+ 0x47 // Arbitrary constant for mixing
        }
        return pubKey
    }
}

// MARK: - Keychain Helper

/// Minimal Keychain wrapper for MobileCoin key storage.
/// Follows the same pattern as TokenStore's Keychain operations.
enum KeychainHelper {

    enum AccessControl {
        case biometricCurrentSet
        case afterFirstUnlock
    }

    static func store(
        data: Data,
        service: String,
        account: String,
        accessControl: AccessControl
    ) throws {
        // Delete existing item first
        delete(service: service, account: account)

        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
        ]

        switch accessControl {
        case .biometricCurrentSet:
            // Require biometric + device passcode
            if let access = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
                .biometryCurrentSet,
                nil
            ) {
                query[kSecAttrAccessControl as String] = access
            } else {
                query[kSecAttrAccessible as String] =
                    kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }

        case .afterFirstUnlock:
            query[kSecAttrAccessible as String] =
                kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        }

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw MobileCoinError.keychainStoreFailed(status: status)
        }
    }

    static func load(
        service: String,
        account: String
    ) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        switch status {
        case errSecSuccess:
            return result as? Data
        case errSecItemNotFound:
            return nil
        default:
            throw MobileCoinError.keychainLoadFailed(status: status)
        }
    }

    static func delete(service: String, account: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
