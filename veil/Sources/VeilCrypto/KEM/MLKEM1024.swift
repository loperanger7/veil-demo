// VEIL — MLKEM1024.swift
// Ticket: VEIL-102 — ML-KEM-1024 Integration
// Spec reference: Section 3.1
//
// Swift wrapper over liboqs ML-KEM-1024 (NIST FIPS 203, Security Level 5).
//
// ML-KEM-1024 provides IND-CCA2 security under the Module Learning with
// Errors assumption (MLWE) with parameters n=4, q=3329, eta_1=2, eta_2=2.
//
// Key sizes:
//   Public key:     1568 bytes
//   Secret key:     3168 bytes
//   Ciphertext:     1568 bytes
//   Shared secret:  32 bytes

import Foundation
import CLibOQS

/// ML-KEM-1024 Key Encapsulation Mechanism via liboqs.
///
/// Usage:
/// ```swift
/// let keyPair = try MLKEM1024KeyPair.generate()
///
/// // Encapsulation (sender side)
/// let result = try MLKEM1024KeyPair.encapsulate(recipientPublicKey: keyPair.publicKey)
/// // result.sharedSecret is the agreed 32-byte secret
/// // result.ciphertext is sent to the recipient
///
/// // Decapsulation (recipient side)
/// let sharedSecret = try keyPair.decapsulate(ciphertext: result.ciphertext)
/// // sharedSecret == result.sharedSecret
/// ```
public struct MLKEM1024KeyPair: KEMKeyPairProtocol {

    /// ML-KEM-1024 public key (1568 bytes).
    public let publicKey: Data

    /// ML-KEM-1024 secret key (3168 bytes), stored as SecureBytes for zeroization.
    private let secretKey: SecureBytes

    // MARK: - Key Generation

    /// Generate a fresh ML-KEM-1024 key pair.
    ///
    /// The secret key is returned inside a `SecureBytes` wrapper that
    /// guarantees zeroization on deallocation.
    ///
    /// - Throws: `VeilError.liboqsError` if liboqs initialization fails.
    /// - Returns: A new key pair.
    public static func generate() throws -> MLKEM1024KeyPair {
        guard let kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024) else {
            throw VeilError.liboqsError(reason: "Failed to initialize ML-KEM-1024")
        }
        defer { OQS_KEM_free(kem) }

        let pkSize = Int(kem.pointee.length_public_key)
        let skSize = Int(kem.pointee.length_secret_key)

        var publicKey = Data(count: pkSize)
        var secretKeyBytes = [UInt8](repeating: 0, count: skSize)
        defer {
            // Zeroize temporary array
            secretKeyBytes.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                    memset(base, 0, ptr.count)
                }
            }
        }

        let result = publicKey.withUnsafeMutableBytes { pkPtr in
            secretKeyBytes.withUnsafeMutableBytes { skPtr in
                OQS_KEM_keypair(
                    kem,
                    pkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    skPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }

        guard result == OQS_SUCCESS else {
            throw VeilError.keyGenerationFailed(reason: "ML-KEM-1024 keypair generation failed")
        }

        return MLKEM1024KeyPair(
            publicKey: publicKey,
            secretKey: SecureBytes(bytes: secretKeyBytes)
        )
    }

    // MARK: - Encapsulation

    /// Encapsulate a shared secret using the recipient's public key.
    ///
    /// This is the sender-side operation. The shared secret is returned
    /// as `SecureBytes`; the ciphertext must be transmitted to the recipient.
    ///
    /// - Parameter recipientPublicKey: The recipient's ML-KEM-1024 public key (1568 bytes).
    /// - Throws: `VeilError.kemEncapsulationFailed` on failure.
    /// - Returns: The shared secret and ciphertext.
    public static func encapsulate(recipientPublicKey: Data) throws -> KEMEncapsulationResult {
        guard recipientPublicKey.count == VeilConstants.mlkem1024PublicKeySize else {
            throw VeilError.kemEncapsulationFailed(
                reason: "Invalid public key size: \(recipientPublicKey.count), expected \(VeilConstants.mlkem1024PublicKeySize)"
            )
        }

        guard let kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024) else {
            throw VeilError.liboqsError(reason: "Failed to initialize ML-KEM-1024")
        }
        defer { OQS_KEM_free(kem) }

        let ctSize = Int(kem.pointee.length_ciphertext)
        let ssSize = Int(kem.pointee.length_shared_secret)

        var ciphertext = Data(count: ctSize)
        var sharedSecretBytes = [UInt8](repeating: 0, count: ssSize)
        defer {
            sharedSecretBytes.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                    memset(base, 0, ptr.count)
                }
            }
        }

        let result = ciphertext.withUnsafeMutableBytes { ctPtr in
            sharedSecretBytes.withUnsafeMutableBytes { ssPtr in
                recipientPublicKey.withUnsafeBytes { pkPtr in
                    OQS_KEM_encaps(
                        kem,
                        ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        ssPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        pkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        guard result == OQS_SUCCESS else {
            throw VeilError.kemEncapsulationFailed(reason: "ML-KEM-1024 encapsulation failed")
        }

        return KEMEncapsulationResult(
            sharedSecret: SecureBytes(bytes: sharedSecretBytes),
            ciphertext: ciphertext
        )
    }

    // MARK: - Decapsulation

    /// Decapsulate a shared secret from a ciphertext using this key pair's secret key.
    ///
    /// This is the recipient-side operation. The ciphertext was produced by
    /// `encapsulate(recipientPublicKey:)` using this key pair's public key.
    ///
    /// - Parameter ciphertext: The ciphertext from the sender (1568 bytes).
    /// - Throws: `VeilError.kemDecapsulationFailed` on failure.
    /// - Returns: The shared secret (32 bytes).
    public func decapsulate(ciphertext: Data) throws -> SecureBytes {
        guard ciphertext.count == VeilConstants.mlkem1024CiphertextSize else {
            throw VeilError.kemDecapsulationFailed(
                reason: "Invalid ciphertext size: \(ciphertext.count), expected \(VeilConstants.mlkem1024CiphertextSize)"
            )
        }

        guard let kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024) else {
            throw VeilError.liboqsError(reason: "Failed to initialize ML-KEM-1024")
        }
        defer { OQS_KEM_free(kem) }

        let ssSize = Int(kem.pointee.length_shared_secret)
        var sharedSecretBytes = [UInt8](repeating: 0, count: ssSize)
        defer {
            sharedSecretBytes.withUnsafeMutableBytes { ptr in
                if let base = ptr.baseAddress {
                    memset(base, 0, ptr.count)
                }
            }
        }

        let skData = try secretKey.copyToData()

        let result = sharedSecretBytes.withUnsafeMutableBytes { ssPtr in
            ciphertext.withUnsafeBytes { ctPtr in
                skData.withUnsafeBytes { skPtr in
                    OQS_KEM_decaps(
                        kem,
                        ssPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        ctPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        skPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        guard result == OQS_SUCCESS else {
            throw VeilError.kemDecapsulationFailed(reason: "ML-KEM-1024 decapsulation failed")
        }

        return SecureBytes(bytes: sharedSecretBytes)
    }
}
