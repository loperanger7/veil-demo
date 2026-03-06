// VEIL — IdentityKeyPair.swift
// Ticket: VEIL-101 — Hybrid Identity Key Generation
// Spec reference: Section 3.2 (PQXDH Prekey Bundle), Section 5.1
//
// A Veil identity is a hybrid key pair: Ed25519 (classical, SEP-backed)
// paired with ML-DSA-65 (post-quantum, encrypted at rest by SEP-derived KEK).
//
// The hybrid construction ensures that an adversary must break BOTH
// Ed25519 AND ML-DSA-65 to forge an identity — neither alone suffices.

import Foundation
import CryptoKit
import CLibOQS

/// A hybrid identity key pair combining classical and post-quantum signatures.
///
/// - Ed25519: Hardware-backed via Secure Enclave. Used for prekey signatures
///   and short-term authentication.
/// - ML-DSA-65: Software-based via liboqs. Provides post-quantum signature
///   capability for long-term identity binding.
///
/// The public components of both keys are distributed together in the
/// prekey bundle. Verifiers check BOTH signatures.
public struct IdentityKeyPair: Sendable {

    // MARK: - Public Keys

    /// Ed25519 public key (32 bytes).
    public let ed25519PublicKey: Data

    /// Alias for Ed25519 public key (used by MessagePipeline sealed sender).
    public var publicKeyEd25519: Data { ed25519PublicKey }

    /// ML-DSA-65 public key (1952 bytes).
    public let mldsaPublicKey: Data

    // MARK: - Private Keys (wrapped)

    /// Ed25519 private key — managed by SecureEnclaveManager.
    /// This reference is used only for delegation; the raw bytes
    /// never leave the Secure Enclave on supported hardware.
    internal let enclaveManager: SecureEnclaveManager

    /// X25519 agreement private key for sealed sender ECDH.
    /// Generated alongside the Ed25519 signing key during identity creation.
    internal let _agreementKey: Curve25519.KeyAgreement.PrivateKey

    /// X25519 agreement private key (used by MessagePipeline for sealed sender).
    public var agreementPrivateKey: Curve25519.KeyAgreement.PrivateKey { _agreementKey }

    /// ML-DSA-65 secret key (4032 bytes), encrypted at rest.
    /// Decrypted into `SecureBytes` only for signing operations.
    internal let mldsaSecretKey: SecureBytes

    // MARK: - Initialization

    /// Generate a new hybrid identity key pair.
    ///
    /// 1. Ed25519 key is generated inside the Secure Enclave.
    /// 2. ML-DSA-65 key is generated via liboqs and encrypted with a
    ///    KEK derived from the Secure Enclave.
    ///
    /// - Parameter enclave: The Secure Enclave manager to use.
    /// - Throws: On key generation or liboqs failure.
    public static func generate(enclave: SecureEnclaveManager) async throws -> IdentityKeyPair {
        // Step 1: Generate Ed25519 identity key in Secure Enclave
        let seKey = try await enclave.generateIdentityKey()
        let ed25519Pub = seKey.publicKey.rawRepresentation

        // Step 2: Generate X25519 agreement key for sealed sender ECDH
        let agreementKey = Curve25519.KeyAgreement.PrivateKey()

        // Step 3: Generate ML-DSA-65 key pair via liboqs
        let (mldsaPub, mldsaSec) = try generateMLDSA65KeyPair()

        return IdentityKeyPair(
            ed25519PublicKey: ed25519Pub,
            mldsaPublicKey: mldsaPub,
            enclaveManager: enclave,
            _agreementKey: agreementKey,
            mldsaSecretKey: mldsaSec
        )
    }

    // MARK: - Signing

    /// Produce a hybrid signature over the given data.
    ///
    /// The signature is the concatenation of:
    ///   `Ed25519_sig(data) || ML-DSA-65_sig(data)`
    ///
    /// Verifiers must check BOTH signatures.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: Concatenated hybrid signature.
    public func sign(_ data: Data) async throws -> HybridSignature {
        // Ed25519 signature via Secure Enclave
        let ed25519Sig = try await enclaveManager.sign(data)

        // ML-DSA-65 signature via liboqs
        let mldsaSig = try signMLDSA65(data: data, secretKey: mldsaSecretKey)

        return HybridSignature(
            ed25519Signature: ed25519Sig,
            mldsaSignature: mldsaSig
        )
    }

    /// Verify a hybrid signature against this identity's public keys.
    ///
    /// BOTH signatures must be valid. If either fails, the entire
    /// verification fails — this is the hybrid security guarantee.
    public static func verify(
        signature: HybridSignature,
        data: Data,
        ed25519PublicKey: Data,
        mldsaPublicKey: Data
    ) -> Bool {
        // Verify Ed25519
        guard let ed25519Key = try? Curve25519.Signing.PublicKey(
            rawRepresentation: ed25519PublicKey
        ) else { return false }

        guard ed25519Key.isValidSignature(signature.ed25519Signature, for: data) else {
            return false
        }

        // Verify ML-DSA-65
        guard verifyMLDSA65(
            signature: signature.mldsaSignature,
            data: data,
            publicKey: mldsaPublicKey
        ) else {
            return false
        }

        return true
    }

    // MARK: - ML-DSA-65 Operations (liboqs)

    /// Generate an ML-DSA-65 key pair using liboqs.
    private static func generateMLDSA65KeyPair() throws -> (publicKey: Data, secretKey: SecureBytes) {
        guard let sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65) else {
            throw VeilError.liboqsError(reason: "Failed to initialize ML-DSA-65")
        }
        defer { OQS_SIG_free(sig) }

        var publicKey = Data(count: Int(sig.pointee.length_public_key))
        var secretKey = [UInt8](repeating: 0, count: Int(sig.pointee.length_secret_key))
        defer {
            // Zeroize the temporary secret key array
            secretKey.withUnsafeMutableBytes { ptr in
                memset(ptr.baseAddress!, 0, ptr.count)
            }
        }

        let result = publicKey.withUnsafeMutableBytes { pubPtr in
            secretKey.withUnsafeMutableBytes { secPtr in
                OQS_SIG_keypair(
                    sig,
                    pubPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                    secPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }

        guard result == OQS_SUCCESS else {
            throw VeilError.keyGenerationFailed(reason: "ML-DSA-65 keypair generation failed")
        }

        return (publicKey: publicKey, secretKey: SecureBytes(bytes: secretKey))
    }

    /// Sign data with ML-DSA-65.
    private func signMLDSA65(data: Data, secretKey: SecureBytes) throws -> Data {
        guard let sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65) else {
            throw VeilError.liboqsError(reason: "Failed to initialize ML-DSA-65 for signing")
        }
        defer { OQS_SIG_free(sig) }

        var signature = Data(count: Int(sig.pointee.length_signature))
        var sigLen: Int = 0

        let skData = try secretKey.copyToData()

        let result = signature.withUnsafeMutableBytes { sigPtr in
            data.withUnsafeBytes { msgPtr in
                skData.withUnsafeBytes { skPtr in
                    OQS_SIG_sign(
                        sig,
                        sigPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        &sigLen,
                        msgPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        data.count,
                        skPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        guard result == OQS_SUCCESS else {
            throw VeilError.signingFailed(reason: "ML-DSA-65 signing failed")
        }

        return signature.prefix(sigLen)
    }

    /// Verify an ML-DSA-65 signature.
    private static func verifyMLDSA65(
        signature: Data,
        data: Data,
        publicKey: Data
    ) -> Bool {
        guard let sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65) else {
            return false
        }
        defer { OQS_SIG_free(sig) }

        let result = signature.withUnsafeBytes { sigPtr in
            data.withUnsafeBytes { msgPtr in
                publicKey.withUnsafeBytes { pkPtr in
                    OQS_SIG_verify(
                        sig,
                        msgPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        data.count,
                        sigPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                        signature.count,
                        pkPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                    )
                }
            }
        }

        return result == OQS_SUCCESS
    }
}

// MARK: - Hybrid Signature

/// A hybrid signature containing both classical and post-quantum components.
///
/// Both signatures must verify for the overall verification to succeed.
/// This structure is serialized into prekey bundles and key exchange messages.
public struct HybridSignature: Sendable, Equatable {
    /// Ed25519 signature (64 bytes).
    public let ed25519Signature: Data

    /// ML-DSA-65 signature (up to 3309 bytes).
    public let mldsaSignature: Data

    /// Serialized form: length-prefixed concatenation.
    public var serialized: Data {
        var result = Data()
        // 2-byte length prefix for Ed25519 signature
        var ed25519Len = UInt16(ed25519Signature.count).bigEndian
        result.append(Data(bytes: &ed25519Len, count: 2))
        result.append(ed25519Signature)
        // Remainder is ML-DSA-65 signature
        result.append(mldsaSignature)
        return result
    }

    /// Deserialize from the length-prefixed concatenation format.
    public static func deserialize(from data: Data) -> HybridSignature? {
        guard data.count > 2 else { return nil }
        let ed25519Len = Int(UInt16(bigEndian: data.prefix(2).withUnsafeBytes { $0.load(as: UInt16.self) }))
        guard data.count >= 2 + ed25519Len else { return nil }

        let ed25519Sig = data[2..<(2 + ed25519Len)]
        let mldsaSig = data[(2 + ed25519Len)...]

        return HybridSignature(
            ed25519Signature: Data(ed25519Sig),
            mldsaSignature: Data(mldsaSig)
        )
    }
}
