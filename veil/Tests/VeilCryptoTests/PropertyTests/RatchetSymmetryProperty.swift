// VEIL — RatchetSymmetryProperty.swift
// Dijkstra-style invariant: Ratchet Symmetry
//
// Spec Section 6.3:
//   forall (msgs : [Message]) ->
//       let (stateA, stateB) = simulateSession(msgs)
//       in allDecrypted(stateA, stateB, msgs) == true
//
// "Testing can reveal the presence of bugs, but never their absence."
// — E.W. Dijkstra
//
// This property states that for ANY sequence of messages exchanged between
// Alice and Bob, every message encrypted by one party can be decrypted by
// the other, and the decrypted plaintext matches the original.

import XCTest
import SwiftCheck
@testable import VeilCrypto

final class RatchetSymmetryPropertyTests: XCTestCase {

    /// Generate an arbitrary message exchange pattern.
    ///
    /// The pattern is a sequence of (sender: Bool, plaintext: Data) pairs
    /// where `true` means Alice sends and `false` means Bob sends.
    struct MessageExchange: Arbitrary {
        let steps: [(senderIsAlice: Bool, plaintext: Data)]

        static var arbitrary: Gen<MessageExchange> {
            let stepGen = Gen<(Bool, Data)>.zip(
                Bool.arbitrary,
                Gen<[UInt8]>.compose { c in
                    let len = c.generate(using: Gen<Int>.fromElements(in: 1...200))
                    return (0..<len).map { _ in c.generate(using: UInt8.arbitrary) }
                }.map { Data($0) }
            )

            return Gen<Int>.fromElements(in: 1...50).flatMap { count in
                Gen<[(Bool, Data)]>.compose { c in
                    (0..<count).map { _ in c.generate(using: stepGen) }
                }
            }.map { steps in
                MessageExchange(steps: steps.map { ($0.0, $0.1) })
            }
        }
    }

    /// **INVARIANT: Ratchet Symmetry**
    ///
    /// For all message exchange patterns, every message encrypted by
    /// Alice can be decrypted by Bob, and vice versa, with the plaintext
    /// preserved exactly.
    func testProperty_ratchetSymmetry() {
        property("Every encrypted message decrypts to the original plaintext") <- forAll { (exchange: MessageExchange) in
            do {
                let sessionKey = SecureBytes(bytes: Array(0..<64))

                var alice = try TripleRatchetSession(
                    sessionKey: sessionKey,
                    isInitiator: true
                )

                // Bootstrap: Alice sends first message so Bob gets her ephemeral key
                let bootstrap = try alice.encrypt(plaintext: Data("bootstrap".utf8))

                var bob = try TripleRatchetSession(
                    sessionKey: SecureBytes(bytes: Array(0..<64)),
                    isInitiator: false,
                    peerEphemeralKey: bootstrap.ephemeralKey
                )

                // Process bootstrap
                _ = try bob.decrypt(envelope: bootstrap)

                // Execute the random exchange pattern
                for (senderIsAlice, plaintext) in exchange.steps {
                    if senderIsAlice {
                        let envelope = try alice.encrypt(plaintext: plaintext)
                        let decrypted = try bob.decrypt(envelope: envelope)
                        guard decrypted == plaintext else { return false }
                    } else {
                        let envelope = try bob.encrypt(plaintext: plaintext)
                        let decrypted = try alice.decrypt(envelope: envelope)
                        guard decrypted == plaintext else { return false }
                    }
                }

                return true
            } catch {
                return false
            }
        }
    }
}
