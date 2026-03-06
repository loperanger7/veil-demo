// VEIL — PaymentIntegrityProperty.swift
// Ticket: VEIL-801 — Property-Based Test Suite
// Spec reference: Section 6.3
//
// Property-based tests for MobileCoin payment receipt integrity.
//
// Invariants tested:
//   1. Receipt serialization round-trip preserves all fields exactly
//   2. All well-formed receipts pass validation
//   3. Corrupted receipts fail validation deterministically
//   4. MOB ↔ picoMOB conversion is exact
//   5. Receipt encryption/decryption via TripleRatchet preserves receipt
//
// "A property-based test is worth a thousand unit tests."

import XCTest
import SwiftCheck
@testable import VeilCrypto

// MARK: - SwiftCheck Generators

/// Generate a valid 64-character hex string (32-byte txHash).
private let hexStringGen: Gen<String> = Gen<[UInt8]>.compose { c in
    (0..<32).map { _ in c.generate(using: UInt8.arbitrary) }
}.map { bytes in
    bytes.map { String(format: "%02x", $0) }.joined()
}

/// Generate a valid base64-encoded string (32-byte shared secret).
private let base64StringGen: Gen<String> = Gen<[UInt8]>.compose { c in
    (0..<32).map { _ in c.generate(using: UInt8.arbitrary) }
}.map { bytes in
    Data(bytes).base64EncodedString()
}

/// Generate a valid receipt proof (64-byte base64-encoded prefix).
private let receiptProofGen: Gen<String> = Gen<[UInt8]>.compose { c in
    (0..<64).map { _ in c.generate(using: UInt8.arbitrary) }
}.map { bytes in
    Data(bytes).base64EncodedString()
}

/// Generate a valid memo string (0–256 characters).
private let memoGen: Gen<String> = Gen<Int>.fromElements(in: 0...256).flatMap { length in
    Gen<String>.compose { c in
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .,!?"
        return String((0..<length).map { _ in
            chars.randomElement()!
        })
    }
}

/// Generate a realistic payment amount in picoMOB.
/// Range: 100 picoMOB (dust) to 2.5 MOB (2,500,000,000,000 picoMOB).
private let amountGen: Gen<UInt64> = Gen<UInt64>.fromElements(
    in: 100...2_500_000_000_000
)

/// Generate a valid block index (realistic range).
private let blockIndexGen: Gen<UInt64> = Gen<UInt64>.fromElements(
    in: 1...10_000_000
)

// MARK: - PaymentReceiptMessage Generator

extension PaymentReceiptMessage: Arbitrary {
    public static var arbitrary: Gen<PaymentReceiptMessage> {
        Gen<PaymentReceiptMessage>.compose { c in
            PaymentReceiptMessage(
                txHash: c.generate(using: hexStringGen),
                sharedSecret: c.generate(using: base64StringGen),
                amountPicomob: c.generate(using: amountGen),
                memo: c.generate(using: memoGen),
                receiptProof: c.generate(using: receiptProofGen),
                blockIndex: c.generate(using: blockIndexGen)
            )
        }
    }
}

// MARK: - Property Tests

final class PaymentIntegrityPropertyTests: XCTestCase {

    // MARK: VEIL-801 — Property 1: Serialization Round-Trip

    /// **INVARIANT: Receipt Serialization Round-Trip**
    ///
    /// For all well-formed payment receipts, encoding to JSON and decoding
    /// back produces a receipt that is Equatable-identical to the original.
    func testProperty_receiptSerializationRoundTrip() {
        property("encode() → decode() preserves all receipt fields") <- forAll { (receipt: PaymentReceiptMessage) in
            do {
                let encoded = try receipt.encode()
                let decoded = try PaymentReceiptMessage.decode(from: encoded)

                // Every field must match exactly
                guard decoded.txHash == receipt.txHash else { return false }
                guard decoded.sharedSecret == receipt.sharedSecret else { return false }
                guard decoded.amountPicomob == receipt.amountPicomob else { return false }
                guard decoded.memo == receipt.memo else { return false }
                guard decoded.receiptProof == receipt.receiptProof else { return false }
                guard decoded.blockIndex == receipt.blockIndex else { return false }
                guard decoded.version == receipt.version else { return false }
                guard decoded.timestamp == receipt.timestamp else { return false }

                return decoded == receipt
            } catch {
                return false
            }
        }
    }

    // MARK: VEIL-801 — Property 2: Validation Completeness

    /// **INVARIANT: All well-formed receipts are valid.**
    ///
    /// Any receipt produced by our generators (which enforce correct formats)
    /// must pass the `isValid` validation check.
    func testProperty_wellFormedReceiptsAreValid() {
        property("All generated receipts pass isValid") <- forAll { (receipt: PaymentReceiptMessage) in
            receipt.isValid
        }
    }

    // MARK: VEIL-801 — Property 3: Corrupted TxHash

    /// **INVARIANT: Corrupted txHash fails validation.**
    ///
    /// If we replace the txHash with a string of wrong length (not 64 hex chars),
    /// isValid must return false.
    func testProperty_corruptedTxHashFailsValidation() {
        let corruptedLengthGen = Gen<Int>.fromElements(in: 0...128)
            .suchThat { $0 != 64 }

        property("Non-64-char txHash fails validation") <- forAll(corruptedLengthGen) { length in
            let badHash = String(repeating: "a", count: length)
            let receipt = PaymentReceiptMessage(
                txHash: badHash,
                sharedSecret: Data(repeating: 0xAA, count: 32).base64EncodedString(),
                amountPicomob: 1_000_000,
                memo: "",
                receiptProof: Data(repeating: 0xBB, count: 64).base64EncodedString(),
                blockIndex: 100
            )
            return !receipt.isValid
        }
    }

    // MARK: VEIL-801 — Property 4: Zero Amount

    /// **INVARIANT: Zero-amount receipts are invalid.**
    ///
    /// A payment receipt with amountPicomob == 0 must fail validation,
    /// as it represents a nonsensical payment.
    func testProperty_zeroAmountIsInvalid() {
        property("amountPicomob == 0 fails validation") <- forAll(hexStringGen, base64StringGen, receiptProofGen, blockIndexGen) { (txHash: String, secret: String, proof: String, block: UInt64) in
            let receipt = PaymentReceiptMessage(
                txHash: txHash,
                sharedSecret: secret,
                amountPicomob: 0,
                memo: "",
                receiptProof: proof,
                blockIndex: block
            )
            return !receipt.isValid
        }
    }

    // MARK: VEIL-801 — Property 5: Zero Block Index

    /// **INVARIANT: Zero block index receipts are invalid.**
    ///
    /// blockIndex must be positive (confirmed on ledger means block >= 1).
    func testProperty_zeroBlockIndexIsInvalid() {
        property("blockIndex == 0 fails validation") <- forAll(hexStringGen, base64StringGen, receiptProofGen, amountGen) { (txHash: String, secret: String, proof: String, amount: UInt64) in
            let receipt = PaymentReceiptMessage(
                txHash: txHash,
                sharedSecret: secret,
                amountPicomob: amount,
                memo: "",
                receiptProof: proof,
                blockIndex: 0
            )
            return !receipt.isValid
        }
    }

    // MARK: VEIL-801 — Property 6: MOB Conversion Exactness

    /// **INVARIANT: picoMOB → MOB conversion is exact.**
    ///
    /// amountInMOB must equal Double(amountPicomob) / 1_000_000_000_000
    /// for all generated amounts.
    func testProperty_picomobToMOBConversion() {
        property("amountInMOB == Double(amountPicomob) / picoMOBPerMOB") <- forAll { (receipt: PaymentReceiptMessage) in
            let expected = Double(receipt.amountPicomob) / 1_000_000_000_000.0
            return receipt.amountInMOB == expected
        }
    }

    // MARK: VEIL-801 — Property 7: Non-Hex TxHash

    /// **INVARIANT: Non-hex characters in txHash fail validation.**
    ///
    /// Even a 64-character string fails if it contains non-hex characters.
    func testProperty_nonHexTxHashFailsValidation() {
        let nonHexCharGen = Gen<Character>.fromElements(of: Array("ghijklmnopqrstuvwxyzGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()"))

        property("Non-hex txHash fails validation") <- forAll(nonHexCharGen) { badChar in
            // Create a 64-char string with one non-hex character
            var hash = String(repeating: "a", count: 63)
            hash.append(badChar)
            let receipt = PaymentReceiptMessage(
                txHash: hash,
                sharedSecret: Data(repeating: 0xAA, count: 32).base64EncodedString(),
                amountPicomob: 1_000_000,
                memo: "",
                receiptProof: Data(repeating: 0xBB, count: 64).base64EncodedString(),
                blockIndex: 100
            )
            return !receipt.isValid
        }
    }

    // MARK: VEIL-801 — Property 8: Invalid Base64 SharedSecret

    /// **INVARIANT: Invalid base64 shared secret fails validation.**
    func testProperty_invalidBase64SharedSecretFails() {
        property("Non-base64 sharedSecret fails validation") <- forAll(hexStringGen, amountGen, blockIndexGen) { (txHash: String, amount: UInt64, block: UInt64) in
            let receipt = PaymentReceiptMessage(
                txHash: txHash,
                sharedSecret: "not!valid!base64!@#$%",
                amountPicomob: amount,
                memo: "",
                receiptProof: Data(repeating: 0xBB, count: 64).base64EncodedString(),
                blockIndex: block
            )
            return !receipt.isValid
        }
    }

    // MARK: VEIL-801 — Property 9: Memo Truncation

    /// **INVARIANT: Memo is truncated to 256 characters.**
    ///
    /// If we construct a receipt with a memo longer than 256 characters,
    /// the initializer should truncate it to exactly 256.
    func testProperty_memoTruncation() {
        let longMemoGen = Gen<Int>.fromElements(in: 257...1000).map { length in
            String(repeating: "A", count: length)
        }

        property("Memo > 256 chars is truncated to 256") <- forAll(longMemoGen) { longMemo in
            let receipt = PaymentReceiptMessage(
                txHash: String(repeating: "a", count: 64),
                sharedSecret: Data(repeating: 0xAA, count: 32).base64EncodedString(),
                amountPicomob: 1_000_000,
                memo: longMemo,
                receiptProof: Data(repeating: 0xBB, count: 64).base64EncodedString(),
                blockIndex: 100
            )
            return receipt.memo.count == 256
        }
    }

    // MARK: VEIL-801 — Property 10: JSON Determinism

    /// **INVARIANT: JSON encoding is deterministic.**
    ///
    /// Encoding the same receipt twice produces identical byte sequences
    /// (because we use .sortedKeys).
    func testProperty_jsonEncodingDeterminism() {
        property("Encoding same receipt twice produces identical JSON") <- forAll { (receipt: PaymentReceiptMessage) in
            do {
                let encoded1 = try receipt.encode()
                let encoded2 = try receipt.encode()
                return encoded1 == encoded2
            } catch {
                return false
            }
        }
    }

    // MARK: VEIL-801 — Property 11: Receipt Encryption Round-Trip

    /// **INVARIANT: Receipt survives Triple Ratchet encryption/decryption.**
    ///
    /// For any receipt, serializing → encrypting → decrypting → deserializing
    /// produces the original receipt.
    func testProperty_receiptEncryptionRoundTrip() {
        // Use a limited count since TripleRatchet is heavier
        property("Receipt survives ratchet encryption round-trip").forAll(
            PaymentReceiptMessage.arbitrary
        ) { receipt in
            do {
                let sessionKey = SecureBytes(bytes: Array(0..<64))

                var alice = try TripleRatchetSession(
                    sessionKey: sessionKey,
                    isInitiator: true
                )

                let bootstrap = try alice.encrypt(plaintext: Data("bootstrap".utf8))

                var bob = try TripleRatchetSession(
                    sessionKey: SecureBytes(bytes: Array(0..<64)),
                    isInitiator: false,
                    peerEphemeralKey: bootstrap.ephemeralKey
                )
                _ = try bob.decrypt(envelope: bootstrap)

                // Serialize receipt, encrypt, decrypt, deserialize
                let receiptData = try receipt.encode()
                let envelope = try alice.encrypt(plaintext: receiptData)
                let decryptedData = try bob.decrypt(envelope: envelope)
                let recoveredReceipt = try PaymentReceiptMessage.decode(from: decryptedData)

                return recoveredReceipt == receipt
            } catch {
                return false
            }
        }
    }
}
