// VEIL — SymmetricRatchet.swift
// Ticket: VEIL-105 — Symmetric Chain Ratchet
// Spec reference: Section 3.3.1
//
// The symmetric ratchet derives per-message keys from a chain key using
// HMAC-SHA-256. Each advancement is irreversible, providing forward secrecy
// at the granularity of individual messages.
//
// CK_{n+1} = HMAC-SHA-256(CK_n, 0x02)
// MK_n     = HMAC-SHA-256(CK_n, 0x01)
//
// After deriving MK_n, both MK_n and CK_n are zeroized. An adversary who
// compromises the device after message n learns nothing about messages 0..n-1.

import Foundation
import CryptoKit

/// A symmetric chain ratchet that derives per-message encryption keys.
///
/// Each chain ratchet instance represents one direction of communication
/// (sending or receiving). The chain key advances with every message,
/// and spent keys are immediately erased.
public struct SymmetricRatchet: Sendable {

    // MARK: - State

    /// Current chain key (32 bytes). Advances with each message.
    private(set) var chainKey: SecureBytes

    /// Current message index in this chain.
    private(set) var index: UInt32 = 0

    /// Skipped message keys, indexed by message number.
    /// These are stored for out-of-order message decryption.
    /// Bounded by `VeilConstants.maxSkippedMessageKeys` to prevent DoS.
    private(set) var skippedKeys: [UInt32: SecureBytes] = [:]

    // MARK: - Initialization

    /// Create a new chain ratchet with the given initial chain key.
    ///
    /// - Parameter chainKey: The initial chain key from the root KDF.
    public init(chainKey: SecureBytes) {
        self.chainKey = chainKey
    }

    // MARK: - Ratchet Operations

    /// Advance the chain and derive the next message key.
    ///
    /// After calling this method:
    ///   - `chainKey` has been updated to CK_{n+1}
    ///   - The returned message key MK_n is valid for exactly one encryption
    ///   - The previous chain key CK_n has been zeroized
    ///
    /// - Returns: The message key for encryption/decryption of message `index`.
    public mutating func advance() throws -> SecureBytes {
        let currentCK = chainKey

        // MK_n = HMAC-SHA-256(CK_n, 0x01)
        let messageKey = try deriveKey(
            from: currentCK,
            byte: VeilConstants.messageKeyDerivationByte
        )

        // CK_{n+1} = HMAC-SHA-256(CK_n, 0x02)
        let nextChainKey = try deriveKey(
            from: currentCK,
            byte: VeilConstants.chainKeyDerivationByte
        )

        // Update state (old chainKey is zeroized via SecureBytes deinit)
        chainKey = nextChainKey
        index += 1

        return messageKey
    }

    /// Skip ahead to a given message index, storing intermediate keys.
    ///
    /// When we receive a message with index > our current index, we need
    /// to advance the chain and store the skipped message keys for
    /// potential future out-of-order delivery.
    ///
    /// - Parameter targetIndex: The message index to advance to.
    /// - Throws: `VeilError.tooManySkippedMessages` if the skip count
    ///   exceeds `maxSkippedMessageKeys`.
    public mutating func skipTo(index targetIndex: UInt32) throws {
        let skipCount = Int(targetIndex) - Int(index)
        guard skipCount >= 0 else { return }

        guard skippedKeys.count + skipCount <= VeilConstants.maxSkippedMessageKeys else {
            throw VeilError.tooManySkippedMessages(
                count: skippedKeys.count + skipCount,
                max: VeilConstants.maxSkippedMessageKeys
            )
        }

        for _ in 0..<skipCount {
            let mk = try advance()
            skippedKeys[index - 1] = mk  // Store with the message index it corresponds to
        }
    }

    /// Retrieve and consume a previously skipped message key.
    ///
    /// If a key exists for the given index, it is removed from storage
    /// and returned. Each skipped key can only be consumed once.
    ///
    /// - Parameter messageIndex: The index of the skipped message.
    /// - Returns: The message key, or `nil` if no skipped key exists.
    public mutating func consumeSkippedKey(at messageIndex: UInt32) -> SecureBytes? {
        skippedKeys.removeValue(forKey: messageIndex)
    }

    // MARK: - Key Derivation

    /// Derive a key from a chain key using HMAC-SHA-256.
    ///
    /// This is the core primitive of the symmetric ratchet:
    ///   `output = HMAC-SHA-256(chainKey, singleByte)`
    private func deriveKey(from ck: SecureBytes, byte: UInt8) throws -> SecureBytes {
        let ckData = try ck.copyToData()
        let symmetricKey = SymmetricKey(data: ckData)
        let input = Data([byte])

        let mac = HMAC<SHA256>.authenticationCode(for: input, using: symmetricKey)
        let macData = Data(mac)

        return SecureBytes(copying: macData)
    }

    // MARK: - Inspection (for testing)

    /// The number of skipped message keys currently stored.
    public var skippedKeyCount: Int { skippedKeys.count }
}
