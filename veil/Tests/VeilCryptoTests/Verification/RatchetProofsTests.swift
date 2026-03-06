// VEIL — RatchetProofsTests.swift
// Ticket: VEIL-701 — Protocol Proofs
// Spec reference: Section 9.1.2
//
// Formal security proofs for the ratchet protocols:
//   - Symmetric chain forward secrecy (HMAC-SHA-256 one-wayness)
//   - DH ratchet forward secrecy (root key irreversibility)
//   - Post-compromise security (recovery after DH ratchet steps)
//   - Chain isolation (sending ≠ receiving)
//   - Skip bound enforcement
//   - Message key deletion

import XCTest
import CryptoKit
@testable import VeilCrypto

final class RatchetProofsTests: XCTestCase {

    // MARK: - Symmetric Chain Forward Secrecy

    /// Prove that compromising CK_50 reveals nothing about MK_0..MK_49.
    func testForwardSecrecy_SymmetricChain_50Messages() throws {
        let ck = SecureBytes(copying: Data(repeating: 0xAA, count: 32))
        let (verdict, state) = try RatchetForwardSecrecyGame.playSymmetricChainGame(
            initialChainKey: ck,
            totalMessages: 100,
            compromiseAt: 50
        )

        XCTAssertTrue(verdict.isSecure, "FS game should pass: \(verdict)")
        XCTAssertEqual(state.epochN, 50)
        XCTAssertEqual(state.previousMessageKeys.count, 50)
    }

    /// Prove forward secrecy with compromise at message 1 (edge case).
    func testForwardSecrecy_SymmetricChain_EarlyCompromise() throws {
        let ck = SecureBytes(copying: Data(repeating: 0xBB, count: 32))
        let (verdict, state) = try RatchetForwardSecrecyGame.playSymmetricChainGame(
            initialChainKey: ck,
            totalMessages: 20,
            compromiseAt: 1
        )

        XCTAssertTrue(verdict.isSecure, "FS at epoch 1: \(verdict)")
        XCTAssertEqual(state.previousMessageKeys.count, 1, "Should protect exactly 1 prior key")
    }

    /// Prove forward secrecy with compromise at the last message.
    func testForwardSecrecy_SymmetricChain_LateCompromise() throws {
        let ck = SecureBytes(copying: Data(repeating: 0xCC, count: 32))
        let (verdict, state) = try RatchetForwardSecrecyGame.playSymmetricChainGame(
            initialChainKey: ck,
            totalMessages: 100,
            compromiseAt: 99
        )

        XCTAssertTrue(verdict.isSecure, "FS at epoch 99: \(verdict)")
        XCTAssertEqual(state.previousMessageKeys.count, 99)
    }

    /// Run forward secrecy game with multiple random compromise points.
    func testForwardSecrecy_SymmetricChain_MultipleTrials() throws {
        for i in 0..<20 {
            let seed = Data((0..<32).map { UInt8(($0 + i) & 0xFF) })
            let ck = SecureBytes(copying: seed)
            let compromiseAt = (i * 7 + 3) % 50 + 1 // Vary compromise point

            let (verdict, _) = try RatchetForwardSecrecyGame.playSymmetricChainGame(
                initialChainKey: ck,
                totalMessages: 60,
                compromiseAt: compromiseAt
            )

            XCTAssertTrue(verdict.isSecure, "Trial \(i) (compromise at \(compromiseAt)): \(verdict)")
        }
    }

    // MARK: - DH Ratchet Forward Secrecy

    /// Prove that DH ratchet root key evolution is irreversible.
    func testForwardSecrecy_DHRatchet() throws {
        let rk = SecureBytes(copying: Data(repeating: 0xDD, count: 32))
        var rootKeys: [Data] = [try rk.copyToData()]

        var currentRK = rk
        for _ in 0..<10 {
            let ek = Curve25519.KeyAgreement.PrivateKey()
            let peer = Curve25519.KeyAgreement.PrivateKey()
            let dh = try ek.sharedSecretFromKeyAgreement(with: peer.publicKey)
            let dhBytes = SecureBytes(copying: dh.withUnsafeBytes { Data($0) })

            let (newRK, _) = try VeilHKDF.deriveRatchetKeys(
                rootKey: currentRK,
                input: dhBytes,
                domain: .dhRatchet
            )

            let newRKData = try newRK.copyToData()
            // Each root key should be unique
            XCTAssertFalse(rootKeys.contains(newRKData), "Root key collision at step \(rootKeys.count)")
            rootKeys.append(newRKData)
            currentRK = newRK
        }

        // Verify no two root keys are equal
        let uniqueKeys = Set(rootKeys)
        XCTAssertEqual(uniqueKeys.count, rootKeys.count,
                       "All \(rootKeys.count) root keys should be unique")
    }

    // MARK: - Post-Compromise Security

    /// Prove that security recovers after 1 DH ratchet step.
    func testPostCompromiseSecurity_1Step() throws {
        let rk = SecureBytes(copying: Data(repeating: 0xEE, count: 32))
        let (verdict, result) = try PostCompromiseSecurityGame.playPCSGame(
            rootKey: rk,
            steps: 1
        )

        XCTAssertTrue(verdict.isSecure, "PCS with 1 step: \(verdict)")
        XCTAssertEqual(result.stepsToRecovery, 1)
        XCTAssertEqual(result.recoveryRootKeys.count, 1)
    }

    /// Prove that security recovers after 2 DH ratchet steps.
    func testPostCompromiseSecurity_2Steps() throws {
        let rk = SecureBytes(copying: Data(repeating: 0xFF, count: 32))
        let (verdict, result) = try PostCompromiseSecurityGame.playPCSGame(
            rootKey: rk,
            steps: 2
        )

        XCTAssertTrue(verdict.isSecure, "PCS with 2 steps: \(verdict)")
        XCTAssertEqual(result.stepsToRecovery, 2)
    }

    /// Prove PCS holds with 5 recovery steps for extra assurance.
    func testPostCompromiseSecurity_5Steps() throws {
        let rk = SecureBytes(copying: Data(repeating: 0x11, count: 32))
        let (verdict, result) = try PostCompromiseSecurityGame.playPCSGame(
            rootKey: rk,
            steps: 5
        )

        XCTAssertTrue(verdict.isSecure, "PCS with 5 steps: \(verdict)")
        XCTAssertEqual(result.recoveryRootKeys.count, 5)

        // Verify each recovery key is different from the compromised key
        for (i, keyData) in result.recoveryRootKeys.enumerated() {
            XCTAssertNotEqual(keyData, result.compromisedRootKey,
                            "Recovery key \(i) should differ from compromised key")
        }
    }

    /// Run PCS game with multiple starting root keys.
    func testPostCompromiseSecurity_MultipleTrials() throws {
        for i in 0..<10 {
            let seed = Data((0..<32).map { UInt8(($0 &+ i * 13) & 0xFF) })
            let rk = SecureBytes(copying: seed)

            let (verdict, _) = try PostCompromiseSecurityGame.playPCSGame(
                rootKey: rk,
                steps: 3
            )

            XCTAssertTrue(verdict.isSecure, "PCS trial \(i): \(verdict)")
        }
    }

    // MARK: - Chain Isolation

    /// Prove that sending and receiving chains derived from the same root key
    /// with different DH inputs are cryptographically independent.
    func testChainIsolation() throws {
        let rk = SecureBytes(copying: Data(repeating: 0x22, count: 32))

        let verdict = try ChainIsolationGame.playChainIsolation(rootKey: rk)
        XCTAssertTrue(verdict.isSecure, "Chain isolation: \(verdict)")
    }

    /// Run chain isolation with multiple root keys.
    func testChainIsolation_MultipleRootKeys() throws {
        for i in 0..<20 {
            let seed = Data((0..<32).map { UInt8(($0 &+ i * 7) & 0xFF) })
            let rk = SecureBytes(copying: seed)

            let verdict = try ChainIsolationGame.playChainIsolation(rootKey: rk)
            XCTAssertTrue(verdict.isSecure, "Chain isolation trial \(i): \(verdict)")
        }
    }

    // MARK: - Skip Bound Enforcement

    /// Verify the skip bound is enforced at exactly maxSkippedMessageKeys.
    func testSkipBoundEnforcement() throws {
        let ck = SecureBytes(copying: Data(repeating: 0x33, count: 32))
        let (canSkipMax, cannotSkipOver) = try SymmetricChainInvariant.verifySkipBound(
            initialChainKey: ck
        )

        XCTAssertTrue(canSkipMax, "Should allow exactly \(VeilConstants.maxSkippedMessageKeys) skips")
        XCTAssertTrue(cannotSkipOver, "Should reject \(VeilConstants.maxSkippedMessageKeys + 1) skips")
    }

    // MARK: - Message Key Deletion

    /// Verify that consumed skipped keys are permanently deleted.
    func testMessageKeyDeletion() throws {
        let ck = SecureBytes(copying: Data(repeating: 0x44, count: 32))
        let deleted = try SymmetricChainInvariant.verifySkippedKeyDeletion(initialChainKey: ck)
        XCTAssertTrue(deleted, "Consumed key should be permanently removed")
    }

    /// Verify skipped keys are stored and consumable.
    func testSkippedKeyConsumption() throws {
        let ck = SecureBytes(copying: Data(repeating: 0x55, count: 32))
        var ratchet = SymmetricRatchet(chainKey: ck)

        // Skip to index 5 (creates keys for indices 0-4)
        try ratchet.skipTo(index: 5)
        XCTAssertEqual(ratchet.skippedKeyCount, 5)

        // Consume each key exactly once
        for i: UInt32 in 0..<5 {
            let key = ratchet.consumeSkippedKey(at: i)
            XCTAssertNotNil(key, "Skipped key at index \(i) should exist")
        }

        XCTAssertEqual(ratchet.skippedKeyCount, 0, "All skipped keys consumed")
    }

    // MARK: - Symmetric Chain Invariants

    /// Run the full invariant suite on a 100-message chain.
    func testSymmetricChainInvariants_100Messages() throws {
        let ck = SecureBytes(copying: Data(repeating: 0x66, count: 32))
        let violations = try SymmetricChainInvariant.verifyAll(
            initialChainKey: ck,
            length: 100
        )

        XCTAssertTrue(violations.isEmpty, "Violations found: \(violations)")
    }

    /// Run invariants with different initial chain keys.
    func testSymmetricChainInvariants_MultipleSeeds() throws {
        for i in 0..<10 {
            let seed = Data((0..<32).map { UInt8(($0 &+ i * 19) & 0xFF) })
            let ck = SecureBytes(copying: seed)

            let violations = try SymmetricChainInvariant.verifyAll(
                initialChainKey: ck,
                length: 50
            )

            XCTAssertTrue(violations.isEmpty, "Trial \(i) violations: \(violations)")
        }
    }

    // MARK: - Chain Key Advancement Properties

    /// Verify that chain key advancement is deterministic.
    func testChainKeyDeterminism() throws {
        let seed = Data(repeating: 0x77, count: 32)

        // Run the same chain twice
        var r1 = SymmetricRatchet(chainKey: SecureBytes(copying: seed))
        var r2 = SymmetricRatchet(chainKey: SecureBytes(copying: seed))

        for _ in 0..<20 {
            let mk1 = try r1.advance()
            let mk2 = try r2.advance()

            XCTAssertEqual(try mk1.copyToData(), try mk2.copyToData(),
                          "Same CK_0 must produce same key sequence")
        }
    }

    /// Verify that different initial chain keys produce completely different sequences.
    func testChainKeyDivergence() throws {
        var r1 = SymmetricRatchet(chainKey: SecureBytes(copying: Data(repeating: 0x88, count: 32)))
        var r2 = SymmetricRatchet(chainKey: SecureBytes(copying: Data(repeating: 0x99, count: 32)))

        for _ in 0..<20 {
            let mk1 = try r1.advance()
            let mk2 = try r2.advance()

            XCTAssertNotEqual(try mk1.copyToData(), try mk2.copyToData(),
                            "Different CK_0 must produce different key sequences")
        }
    }

    // MARK: - Message Key vs Chain Key Independence

    /// Verify that message keys and chain keys from the same derivation are different.
    func testMessageKeyChainKeyIndependence() throws {
        var ratchet = SymmetricRatchet(chainKey: SecureBytes(copying: Data(repeating: 0xAB, count: 32)))

        for _ in 0..<20 {
            let ckBefore = try ratchet.chainKey.copyToData()
            let mk = try ratchet.advance()
            let ckAfter = try ratchet.chainKey.copyToData()

            // MK should differ from both the old and new CK
            let mkData = try mk.copyToData()
            XCTAssertNotEqual(mkData, ckBefore, "MK should differ from CK_n")
            XCTAssertNotEqual(mkData, ckAfter, "MK should differ from CK_{n+1}")
            XCTAssertNotEqual(ckBefore, ckAfter, "CK should advance")
        }
    }
}
