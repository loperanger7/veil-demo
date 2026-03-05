// VEIL — HKDF.swift
// Ticket: VEIL-103 — HKDF-SHA-512 with Domain Separation
// Spec reference: Section 3.4
//
// All key derivation in Veil passes through this module.
// The API enforces domain separation at the type level: you cannot call
// `deriveKey` without providing a `VeilDomain` value.

import Foundation
import CryptoKit

/// HKDF-SHA-512 key derivation with mandatory domain separation.
///
/// This is the sole KDF used throughout Veil. It wraps CryptoKit's HKDF
/// with two invariants:
///
/// 1. The `info` parameter is always a `VeilDomain` enum case (not a raw string).
/// 2. Outputs are returned as `SecureBytes`, ensuring automatic zeroization.
///
/// Spec: "All key derivation in Veil uses HKDF-SHA-512 with explicit domain
/// separation strings to prevent cross-protocol attacks."
public enum VeilHKDF: Sendable {

    // MARK: - Primary API

    /// Derive a key of the given length from input keying material.
    ///
    /// - Parameters:
    ///   - ikm: Input keying material (e.g., DH shared secrets, KEM outputs).
    ///   - salt: Optional salt. Use `nil` for a zero-filled salt (per RFC 5869).
    ///   - domain: The domain separation label identifying this derivation context.
    ///   - outputByteCount: Number of bytes to produce (max 255 * 64 = 16,320).
    /// - Returns: Derived key material as `SecureBytes`.
    public static func deriveKey(
        ikm: SecureBytes,
        salt: SecureBytes? = nil,
        domain: VeilDomain,
        outputByteCount: Int = 32
    ) throws -> SecureBytes {
        let ikmData = try ikm.copyToData()
        defer { /* ikmData will be released by ARC — short-lived */ }

        let saltKey: SymmetricKey
        if let salt = salt {
            let saltData = try salt.copyToData()
            saltKey = SymmetricKey(data: saltData)
        } else {
            // RFC 5869: if salt is not provided, use a zero-filled string
            // of HashLen bytes
            saltKey = SymmetricKey(data: Data(repeating: 0, count: 64))
        }

        let infoData = domain.utf8Data
        let inputKey = SymmetricKey(data: ikmData)

        let derivedKey = HKDF<SHA512>.deriveKey(
            inputKeyMaterial: inputKey,
            salt: saltKey.withUnsafeBytes { Data($0) },
            info: infoData,
            outputByteCount: outputByteCount
        )

        // Convert CryptoKit SymmetricKey to SecureBytes
        return derivedKey.withUnsafeBytes { buffer in
            SecureBytes(bytes: Array(buffer))
        }
    }

    /// Derive two keys from a single root key and DH/KEM output.
    ///
    /// This is the standard ratchet KDF pattern:
    ///   `(RK_new, CK) = HKDF(salt=RK, ikm=dh_output, info=domain)`
    ///
    /// The first 32 bytes become the new root key; the second 32 bytes
    /// become the new chain key.
    ///
    /// - Parameters:
    ///   - rootKey: Current root key (used as HKDF salt).
    ///   - input: DH shared secret or KEM shared secret.
    ///   - domain: Domain separation label.
    /// - Returns: Tuple of `(newRootKey, chainKey)` as `SecureBytes`.
    public static func deriveRatchetKeys(
        rootKey: SecureBytes,
        input: SecureBytes,
        domain: VeilDomain
    ) throws -> (rootKey: SecureBytes, chainKey: SecureBytes) {
        let combined = try deriveKey(
            ikm: input,
            salt: rootKey,
            domain: domain,
            outputByteCount: VeilConstants.rootKeySize + VeilConstants.chainKeySize
        )

        // Split the 64-byte output into two 32-byte keys
        let combinedData = try combined.copyToData()
        let newRootKey = SecureBytes(copying: combinedData.prefix(VeilConstants.rootKeySize))
        let chainKey = SecureBytes(copying: combinedData.suffix(VeilConstants.chainKeySize))

        return (rootKey: newRootKey, chainKey: chainKey)
    }

    /// Derive the session key from PQXDH concatenated input keying material.
    ///
    /// Spec Section 3.2:
    ///   `SK = HKDF-SHA-512(salt=0, ikm=DH1||DH2||DH3||DH4||ss||ss2, info="VeilPQXDH")`
    ///
    /// - Parameter concatenatedIKM: The concatenation of all DH outputs and KEM shared secrets.
    /// - Returns: 64-byte session key.
    public static func deriveSessionKey(
        concatenatedIKM: SecureBytes
    ) throws -> SecureBytes {
        try deriveKey(
            ikm: concatenatedIKM,
            salt: nil,
            domain: .pqxdh,
            outputByteCount: VeilConstants.sessionKeySize
        )
    }
}
