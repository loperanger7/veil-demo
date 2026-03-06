// VEIL — Errors.swift
// Unified error types for the Veil cryptographic library.
//
// Design note: Errors are categorized by subsystem to enable precise
// handling without leaking implementation details across module boundaries.

import Foundation

/// Top-level error namespace for all Veil cryptographic operations.
public enum VeilError: Error, Equatable, Sendable {

    // MARK: - Key Management Errors

    /// Secure Enclave is unavailable on this device.
    case secureEnclaveUnavailable

    /// Key generation failed in the Secure Enclave.
    case keyGenerationFailed(reason: String)

    /// A signing operation failed.
    case signingFailed(reason: String)

    /// Signature verification failed — the data or key is invalid.
    case signatureVerificationFailed

    // MARK: - KEM Errors

    /// ML-KEM encapsulation failed.
    case kemEncapsulationFailed(reason: String)

    /// ML-KEM decapsulation failed — ciphertext may be malformed.
    case kemDecapsulationFailed(reason: String)

    /// liboqs initialization or operation failed.
    case liboqsError(reason: String)

    // MARK: - Key Derivation Errors

    /// HKDF derivation produced an unexpected output length.
    case kdfOutputLengthMismatch(expected: Int, got: Int)

    // MARK: - Protocol Errors

    /// Prekey bundle signature is invalid — abort session establishment.
    case invalidPrekeySignature

    /// No one-time prekeys available on the server.
    case noOneTimePrekeysAvailable

    /// Session is in an invalid state for the requested operation.
    case invalidSessionState(current: String, expected: String)

    /// A received message could not be decrypted — ratchet state mismatch.
    case decryptionFailed(reason: String)

    /// Message authentication code verification failed.
    case authenticationFailed

    /// Too many skipped messages — potential denial-of-service.
    case tooManySkippedMessages(count: Int, max: Int)

    // MARK: - SPQR Errors

    /// PQ key fragment is out of order or duplicated.
    case invalidFragment(reason: String)

    /// Fragment accumulation timed out before completion.
    case fragmentAssemblyTimeout

    // MARK: - Memory Safety

    /// Attempted to use a SecureBytes buffer after it was zeroized.
    case useAfterZeroize

    /// Cryptographic random number generation failed.
    case randomGenerationFailed
}
