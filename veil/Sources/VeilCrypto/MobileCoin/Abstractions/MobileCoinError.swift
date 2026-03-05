// MobileCoinError.swift
// VEIL — MobileCoin Payment Integration
//
// Unified error taxonomy for all MobileCoin operations.
// References: Veil Protocol Specification v1.0, Section 8

import Foundation

// MARK: - MobileCoin Error Domain

/// Comprehensive error enum covering key derivation, transaction construction,
/// network submission, Fog queries, receipt handling, and state machine violations.
public enum MobileCoinError: Error, Sendable, Equatable {

    // MARK: Key Derivation (VEIL-401)

    /// HKDF output is not a valid Ristretto255 scalar (rejected by curve reduction).
    case invalidSpendKey

    /// HKDF output for view key failed scalar validation.
    case invalidViewKey

    /// Identity key material too short or corrupted for derivation.
    case identityKeyCorrupted(detail: String)

    /// Keychain write failed during key storage.
    case keychainStoreFailed(status: Int32)

    /// Keychain read failed (item not found or access denied).
    case keychainLoadFailed(status: Int32)

    /// Biometric authentication required but unavailable or denied.
    case biometricAuthFailed(reason: String)

    // MARK: Address Resolution (VEIL-402)

    /// Peer identity key cannot be parsed as a valid public key.
    case invalidPeerIdentityKey

    /// Subaddress derivation produced an invalid public address.
    case subaddressDerivationFailed

    /// Address mismatch: recipient computes a different address than sender derived.
    case addressMismatch

    // MARK: Transaction Construction (VEIL-403)

    /// Available TXOs insufficient to cover amount + fee.
    case insufficientBalance(available: UInt64, required: UInt64)

    /// No unspent TXOs available in wallet.
    case noUnspentTXOs

    /// Ring signature generation failed (mixin selection or signing error).
    case ringSignatureFailed(detail: String)

    /// Bulletproofs+ range proof generation failed.
    case rangeProofFailed(detail: String)

    /// Transaction serialization to wire format failed.
    case transactionSerializationFailed

    /// Transaction exceeds maximum allowed size.
    case transactionTooLarge(bytes: Int)

    /// TXO selection algorithm encountered an internal inconsistency.
    case txoSelectionFailed(reason: String)

    // MARK: Submission & Confirmation (VEIL-404)

    /// Full-Service Node rejected the transaction.
    case submissionRejected(reason: String)

    /// Full-Service Node returned an unexpected HTTP status.
    case submissionHTTPError(statusCode: Int)

    /// Transaction not confirmed within the timeout window.
    case confirmationTimeout(timeoutSeconds: TimeInterval)

    /// Transient network failure during submission (eligible for retry).
    case transientNetworkError(underlying: String)

    /// All retry attempts exhausted.
    case retriesExhausted(attempts: Int)

    /// TLS handshake or certificate pinning failure to Full-Service Node.
    case tlsPinningFailed(host: String)

    // MARK: Fog Integration (VEIL-406)

    /// Fog service is unreachable; cached balance may be stale.
    case fogServiceUnavailable

    /// SGX attestation verification failed — enclave may be compromised.
    case sgxAttestationFailed(detail: String)

    /// Fog returned an invalid or unparseable balance response.
    case invalidBalanceResponse

    /// View key registration with Fog failed.
    case fogRegistrationFailed(reason: String)

    // MARK: Receipts (VEIL-405)

    /// Receipt decryption failed (session key mismatch or corruption).
    case receiptDecryptionFailed

    /// Receipt contains invalid or inconsistent fields.
    case invalidReceipt(detail: String)

    /// Cannot locate incoming TXO using the shared secret.
    case txoNotFound

    /// Shared secret does not match any known incoming output.
    case sharedSecretMismatch

    // MARK: State Machine (VEIL-407)

    /// Attempted an invalid state transition.
    case invalidStateTransition(from: String, to: String)

    /// State machine encountered an unrecoverable internal error.
    case stateMachineCorrupted

    /// Persisted state could not be decoded on recovery.
    case stateDecodingFailed(detail: String)

    // MARK: SDK

    /// MobileCoin SDK is not available (running with mock).
    case sdkUnavailable

    /// SDK returned an unexpected error.
    case sdkError(detail: String)
}

// MARK: - LocalizedError

extension MobileCoinError: LocalizedError {

    public var errorDescription: String? {
        switch self {
        case .invalidSpendKey:
            return "Derived spend key is not a valid Ristretto255 scalar."
        case .invalidViewKey:
            return "Derived view key is not a valid Ristretto255 scalar."
        case .identityKeyCorrupted(let detail):
            return "Identity key corrupted: \(detail)"
        case .keychainStoreFailed(let status):
            return "Keychain store failed with OSStatus \(status)."
        case .keychainLoadFailed(let status):
            return "Keychain load failed with OSStatus \(status)."
        case .biometricAuthFailed(let reason):
            return "Biometric authentication failed: \(reason)"
        case .invalidPeerIdentityKey:
            return "Peer identity key is invalid or unparseable."
        case .subaddressDerivationFailed:
            return "Failed to derive MobileCoin subaddress."
        case .addressMismatch:
            return "Derived address does not match recipient's computed address."
        case .insufficientBalance(let available, let required):
            return "Insufficient balance: \(available) picoMOB available, \(required) required."
        case .noUnspentTXOs:
            return "No unspent transaction outputs available."
        case .ringSignatureFailed(let detail):
            return "Ring signature generation failed: \(detail)"
        case .rangeProofFailed(let detail):
            return "Bulletproofs+ range proof failed: \(detail)"
        case .transactionSerializationFailed:
            return "Transaction serialization to wire format failed."
        case .transactionTooLarge(let bytes):
            return "Transaction exceeds maximum size: \(bytes) bytes."
        case .txoSelectionFailed(let reason):
            return "TXO selection failed: \(reason)"
        case .submissionRejected(let reason):
            return "Transaction rejected by Full-Service Node: \(reason)"
        case .submissionHTTPError(let code):
            return "Full-Service Node returned HTTP \(code)."
        case .confirmationTimeout(let timeout):
            return "Transaction not confirmed within \(timeout)s."
        case .transientNetworkError(let underlying):
            return "Transient network error: \(underlying)"
        case .retriesExhausted(let attempts):
            return "All \(attempts) retry attempts exhausted."
        case .tlsPinningFailed(let host):
            return "TLS certificate pinning failed for \(host)."
        case .fogServiceUnavailable:
            return "MobileCoin Fog service is unavailable."
        case .sgxAttestationFailed(let detail):
            return "SGX attestation verification failed: \(detail)"
        case .invalidBalanceResponse:
            return "Fog returned an invalid balance response."
        case .fogRegistrationFailed(let reason):
            return "Fog view key registration failed: \(reason)"
        case .receiptDecryptionFailed:
            return "Payment receipt decryption failed."
        case .invalidReceipt(let detail):
            return "Invalid payment receipt: \(detail)"
        case .txoNotFound:
            return "Cannot locate incoming TXO from shared secret."
        case .sharedSecretMismatch:
            return "Shared secret does not match any known output."
        case .invalidStateTransition(let from, let to):
            return "Invalid payment state transition: \(from) → \(to)"
        case .stateMachineCorrupted:
            return "Payment state machine is in an unrecoverable state."
        case .stateDecodingFailed(let detail):
            return "Failed to decode persisted payment state: \(detail)"
        case .sdkUnavailable:
            return "MobileCoin SDK is not available."
        case .sdkError(let detail):
            return "MobileCoin SDK error: \(detail)"
        }
    }
}
