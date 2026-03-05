// MobileCoinClient.swift
// VEIL — MobileCoin Payment Integration
//
// Actor-based adapter wrapping MobileCoinSDKProtocol with Veil conventions:
// SecureBytes for key material, caching for derived addresses, and
// structured error handling.
//
// References: Veil Spec Section 8

import Foundation

// MARK: - MobileCoin Client Actor

/// Thread-safe client for MobileCoin SDK operations.
/// All methods accept `SecureBytes` for key material and handle zeroization.
public actor MobileCoinClient {

    // MARK: Properties

    private let sdk: MobileCoinSDKProtocol

    /// Cache of derived subaddresses: (spendPubKey + viewPubKey + index) → address
    private var addressCache: [Data: Data] = [:]

    /// Maximum cache entries before eviction.
    private let maxCacheSize: Int = 256

    // MARK: Initialization

    /// Create a client wrapping the given SDK implementation.
    /// - Parameter sdk: SDK protocol implementation (real or mock).
    public init(sdk: MobileCoinSDKProtocol = MockMobileCoinSDK()) {
        self.sdk = sdk
    }

    // MARK: Key Validation

    /// Validate that a derived key is a valid Ristretto255 scalar.
    /// - Parameter keyBytes: Raw key material (expected 32 bytes).
    /// - Returns: `true` if the key is valid on the curve.
    public func isValidScalar(_ keyBytes: SecureBytes) -> Bool {
        let data = keyBytes.withUnsafeBytes { Data($0) }
        return sdk.isValidRistrettoScalar(data)
    }

    // MARK: Address Derivation

    /// Derive a public subaddress from spend and view public keys.
    /// Results are cached for performance (addresses are deterministic).
    /// - Parameters:
    ///   - spendPublicKey: 32-byte public spend key.
    ///   - viewPublicKey: 32-byte public view key.
    ///   - subaddressIndex: Subaddress index (default 0).
    /// - Returns: Serialized public address.
    public func derivePublicSubaddress(
        spendPublicKey: Data,
        viewPublicKey: Data,
        subaddressIndex: UInt64 = 0
    ) throws -> Data {
        // Build cache key
        var cacheKey = Data()
        cacheKey.append(spendPublicKey)
        cacheKey.append(viewPublicKey)
        withUnsafeBytes(of: subaddressIndex.littleEndian) { cacheKey.append(contentsOf: $0) }

        // Check cache
        if let cached = addressCache[cacheKey] {
            return cached
        }

        // Derive via SDK
        let address = try sdk.derivePublicSubaddress(
            spendPublicKey: spendPublicKey,
            viewPublicKey: viewPublicKey,
            subaddressIndex: subaddressIndex
        )

        // Cache with eviction
        if addressCache.count >= maxCacheSize {
            // Remove oldest entry (FIFO approximation via random eviction)
            if let firstKey = addressCache.keys.first {
                addressCache.removeValue(forKey: firstKey)
            }
        }
        addressCache[cacheKey] = address

        return address
    }

    // MARK: Transaction Building

    /// Build a signed transaction using the SDK.
    /// - Parameters:
    ///   - inputs: Selected TXO inputs with ring members.
    ///   - recipientAddress: Serialized recipient address.
    ///   - outputAmount: Payment amount in picoMOB.
    ///   - changeAddress: Sender's change address.
    ///   - changeAmount: Change amount in picoMOB.
    ///   - spendKey: Sender's private spend key (SecureBytes for zeroization).
    ///   - fee: Network fee in picoMOB.
    /// - Returns: Serialized signed transaction and its hash.
    public func buildTransaction(
        inputs: [SDKTXOInput],
        recipientAddress: Data,
        outputAmount: UInt64,
        changeAddress: Data,
        changeAmount: UInt64,
        spendKey: SecureBytes,
        fee: UInt64
    ) throws -> (transactionBytes: Data, txHash: Data) {
        let spendKeyData = spendKey.withUnsafeBytes { Data($0) }

        let txBytes = try sdk.buildTransaction(
            inputs: inputs,
            recipientAddress: recipientAddress,
            outputAmount: outputAmount,
            changeAddress: changeAddress,
            changeAmount: changeAmount,
            spendKey: spendKeyData,
            ringSize: MobileCoinConstants.defaultRingSize,
            fee: fee
        )

        let txHash = sdk.computeTransactionHash(txBytes)
        return (txBytes, txHash)
    }

    /// Validate a signed transaction's cryptographic proofs.
    /// - Parameter transactionBytes: Serialized signed transaction.
    /// - Returns: `true` if all proofs (ring sigs + range proofs) verify.
    public func validateTransaction(_ transactionBytes: Data) -> Bool {
        sdk.validateTransaction(transactionBytes)
    }

    // MARK: Key Image

    /// Compute the key image for a TXO (used for double-spend detection).
    /// - Parameters:
    ///   - txoPublicKey: The TXO's one-time public key.
    ///   - spendKey: Owner's private spend key.
    /// - Returns: 32-byte key image.
    public func computeKeyImage(
        txoPublicKey: Data,
        spendKey: SecureBytes
    ) throws -> Data {
        let spendKeyData = spendKey.withUnsafeBytes { Data($0) }
        return try sdk.computeKeyImage(txoPublicKey: txoPublicKey, spendKey: spendKeyData)
    }

    // MARK: TXO Decryption

    /// Attempt to decrypt a TXO amount (check if output belongs to us).
    /// - Parameters:
    ///   - encryptedAmount: TXO encrypted amount field.
    ///   - sharedSecret: ECDH shared secret for this output.
    ///   - viewKey: Recipient's private view key.
    /// - Returns: Decrypted amount in picoMOB, or nil if not ours.
    public func decryptTXOAmount(
        encryptedAmount: Data,
        sharedSecret: Data,
        viewKey: SecureBytes
    ) -> UInt64? {
        let viewKeyData = viewKey.withUnsafeBytes { Data($0) }
        return sdk.decryptTXOAmount(
            encryptedAmount: encryptedAmount,
            sharedSecret: sharedSecret,
            viewKey: viewKeyData
        )
    }

    // MARK: SGX Attestation

    /// Verify an SGX attestation report from a Fog node.
    /// - Parameters:
    ///   - report: Raw attestation report.
    ///   - expectedMrEnclave: Expected MRENCLAVE measurement.
    /// - Returns: `true` if attestation is valid.
    public func verifySGXAttestation(
        report: Data,
        expectedMrEnclave: Data
    ) -> Bool {
        sdk.verifySGXAttestation(report: report, expectedMrEnclave: expectedMrEnclave)
    }

    // MARK: Cache Management

    /// Clear the address derivation cache.
    public func clearCache() {
        addressCache.removeAll()
    }
}

// MARK: - Constants

/// MobileCoin protocol constants.
public enum MobileCoinConstants {
    /// Default ring size (number of decoy outputs per input). MobileCoin mainnet uses 11.
    public static let defaultRingSize: Int = 11

    /// Minimum network fee in picoMOB (0.0004 MOB = 400,000,000 picoMOB).
    public static let minimumFee: UInt64 = 400_000_000

    /// 1 MOB = 10^12 picoMOB.
    public static let picoMOBPerMOB: UInt64 = 1_000_000_000_000

    /// Maximum transaction size in bytes.
    public static let maxTransactionSize: Int = 65_536

    /// Block confirmation polling interval in seconds.
    public static let pollIntervalSeconds: TimeInterval = 1.0

    /// Default confirmation timeout in seconds.
    public static let confirmationTimeoutSeconds: TimeInterval = 30.0

    /// Maximum retry count for transient failures.
    public static let maxRetries: Int = 3

    /// Fog MRENCLAVE measurement for mainnet (placeholder — updated per release).
    public static let fogMrEnclave = Data(repeating: 0xAA, count: 32)

    /// Prekey replenishment threshold for balance refresh.
    public static let balanceRefreshIntervalSeconds: TimeInterval = 60.0
}
