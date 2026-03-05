// VEIL — Constants.swift
// Global constants for the Veil cryptographic library.
// Spec reference: Section 3.1 (Cryptographic Primitives), Appendix A

import Foundation

/// Protocol-wide constants.
///
/// These values are fixed by the specification and must not be changed
/// without a protocol version bump.
public enum VeilConstants: Sendable {

    /// Current protocol version.
    public static let protocolVersion: UInt32 = 1

    // MARK: - Key Sizes (bytes)

    /// X25519 public or private key: 32 bytes.
    public static let x25519KeySize = 32

    /// Ed25519 public key: 32 bytes.
    public static let ed25519PublicKeySize = 32

    /// Ed25519 signature: 64 bytes.
    public static let ed25519SignatureSize = 64

    /// ML-KEM-1024 public key: 1568 bytes.
    public static let mlkem1024PublicKeySize = 1568

    /// ML-KEM-1024 secret key: 3168 bytes.
    public static let mlkem1024SecretKeySize = 3168

    /// ML-KEM-1024 ciphertext: 1568 bytes.
    public static let mlkem1024CiphertextSize = 1568

    /// ML-KEM-1024 shared secret: 32 bytes.
    public static let mlkem1024SharedSecretSize = 32

    /// ML-DSA-65 public key: 1952 bytes.
    public static let mldsa65PublicKeySize = 1952

    /// ML-DSA-65 secret key: 4032 bytes.
    public static let mldsa65SecretKeySize = 4032

    /// ML-DSA-65 signature: 3309 bytes (max).
    public static let mldsa65SignatureMaxSize = 3309

    // MARK: - Derived Key Sizes

    /// Session key output from PQXDH: 64 bytes (512 bits).
    public static let sessionKeySize = 64

    /// Root key size: 32 bytes.
    public static let rootKeySize = 32

    /// Chain key size: 32 bytes.
    public static let chainKeySize = 32

    /// Message key size: 32 bytes (used as AES-256-GCM key).
    public static let messageKeySize = 32

    /// AES-256-GCM nonce size: 12 bytes (96 bits).
    public static let aesGCMNonceSize = 12

    /// AES-256-GCM tag size: 16 bytes.
    public static let aesGCMTagSize = 16

    // MARK: - HMAC Constants for Chain Ratchet

    /// Input byte for deriving the next chain key: 0x02.
    public static let chainKeyDerivationByte: UInt8 = 0x02

    /// Input byte for deriving a message key: 0x01.
    public static let messageKeyDerivationByte: UInt8 = 0x01

    // MARK: - Protocol Limits

    /// Maximum number of skipped message keys to store per session.
    /// Prevents memory exhaustion from malicious skip counts.
    public static let maxSkippedMessageKeys = 2000

    /// Default SPQR ratchet interval in messages.
    public static let spqrDefaultIntervalMessages = 75

    /// Maximum SPQR ratchet interval before forced step (seconds).
    public static let spqrMaxIntervalSeconds: TimeInterval = 86400 // 24 hours

    /// Default fragment size for SPQR key/ciphertext distribution (bytes).
    public static let spqrFragmentSize = 256

    /// Number of classical one-time prekeys to maintain in the pool.
    public static let prekeyPoolSize = 100

    /// Number of PQ one-time prekeys to maintain in the pool.
    public static let pqPrekeyPoolSize = 100

    /// Prekey replenishment threshold (fraction of pool).
    public static let prekeyReplenishThreshold = 0.20

    /// Message padding block size (bytes) for traffic analysis resistance.
    public static let messagePaddingBlockSize = 256
}
