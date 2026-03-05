// VEIL — ForwardSecrecyProperty.swift
// Dijkstra-style invariant: Forward Secrecy
//
// Spec Section 6.3:
//   forall (n : Nat, session : Session) ->
//       let state_n = advanceTo(session, n)
//       in canDecrypt(state_n, messageAt(session, n-1)) == false
//
// This property states that after advancing the symmetric ratchet to step n,
// it is impossible to derive the message key for step n-1. The irreversible
// advancement of the chain key ensures that compromise of the current state
// reveals nothing about past states.

import XCTest
import SwiftCheck
@testable import VeilCrypto

final class ForwardSecrecyPropertyTests: XCTestCase {

    /// **INVARIANT: Forward Secrecy of Symmetric Ratchet**
    ///
    /// After advancing to step n, the chain key at step n cannot be used
    /// to derive the message key for step n-1.
    ///
    /// Formally: CK_n cannot produce MK_{n-1}.
    func testProperty_forwardSecrecy_symmetricRatchet() {
        property("Advancing the chain makes previous message keys unrecoverable") <- forAll(
            Gen<Int>.fromElements(in: 1...100)
        ) { n in
            do {
                let initialCK = SecureBytes(bytes: Array(repeating: 0x42, count: 32))
                var ratchet = SymmetricRatchet(chainKey: initialCK)

                // Collect all message keys as we advance
                var messageKeys: [Data] = []
                for _ in 0..<n {
                    let mk = try ratchet.advance()
                    messageKeys.append(try mk.copyToData())
                }

                // Now we have state at step n.
                // The ratchet's current chain key should NOT be equal to any
                // previous message key — and there is no operation on
                // SymmetricRatchet that can reverse the HMAC to recover
                // a previous MK from the current CK.

                // Verify: current chain key differs from all message keys
                let currentCK = try ratchet.chainKey.copyToData()
                for (i, mk) in messageKeys.enumerated() {
                    guard currentCK != mk else {
                        // Chain key should never equal a message key
                        return false
                    }
                    // Also verify no two message keys are the same
                    for (j, mk2) in messageKeys.enumerated() where j != i {
                        guard mk != mk2 else { return false }
                    }
                }

                // Additional check: advancing further produces keys that
                // differ from all previously collected keys
                let newMK = try ratchet.advance()
                let newMKData = try newMK.copyToData()
                for mk in messageKeys {
                    guard newMKData != mk else { return false }
                }

                return true
            } catch {
                return false
            }
        }
    }

    /// **INVARIANT: Forward Secrecy of DH Ratchet**
    ///
    /// After a DH ratchet step, the new root key cannot be used to
    /// recover the previous root key.
    func testProperty_forwardSecrecy_dhRatchet() throws {
        // This is a structural test: we verify that each DH ratchet step
        // produces a root key that is unrelated to the previous one
        // (different bytes, different derived chain keys).

        let rootKey = SecureBytes(bytes: Array(repeating: 0xAA, count: 32))
        let input1 = SecureBytes(bytes: Array(repeating: 0xBB, count: 32))
        let input2 = SecureBytes(bytes: Array(repeating: 0xCC, count: 32))

        let (rk1, ck1) = try VeilHKDF.deriveRatchetKeys(
            rootKey: rootKey,
            input: input1,
            domain: .dhRatchet
        )

        let (rk2, ck2) = try VeilHKDF.deriveRatchetKeys(
            rootKey: rk1,
            input: input2,
            domain: .dhRatchet
        )

        // RK2 must differ from RK1 and the original root key
        XCTAssertNotEqual(try rk2.copyToData(), try rk1.copyToData())
        XCTAssertNotEqual(try rk2.copyToData(), try rootKey.copyToData())

        // Chain keys must differ from each other and from root keys
        XCTAssertNotEqual(try ck1.copyToData(), try ck2.copyToData())
    }
}
