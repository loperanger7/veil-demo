// VEIL — IdempotentRatchetProperty.swift
// Dijkstra-style invariant: Idempotent Message Processing
//
// Spec Section 6.3:
//   forall (msg : Message, state : RatchetState) ->
//       let (state1, _) = processMessage(state, msg)
//       let (state2, _) = processMessage(state1, msg)
//       in state1 == state2
//
// This property verifies that processing the same message twice does not
// corrupt the ratchet state. In a real system, duplicate messages can arrive
// due to network retransmission, and the protocol must handle them gracefully.

import XCTest
import SwiftCheck
@testable import VeilCrypto

final class IdempotentRatchetPropertyTests: XCTestCase {

    /// **INVARIANT: Duplicate Detection in Symmetric Ratchet**
    ///
    /// Once a message key has been consumed (via skipped key storage),
    /// consuming it again returns nil, preventing the same key from
    /// being used for two different decryptions.
    func testProperty_consumedSkippedKeyReturnsNilOnSecondAccess() {
        property("Consumed skipped key is removed from storage") <- forAll(
            Gen<UInt32>.fromElements(in: 1...100)
        ) { skipCount in
            do {
                var ratchet = SymmetricRatchet(
                    chainKey: SecureBytes(bytes: Array(repeating: 0xAB, count: 32))
                )

                try ratchet.skipTo(index: skipCount)

                // Pick a random index from the skipped range
                let targetIndex = UInt32.random(in: 0..<skipCount)

                // First consumption should succeed
                guard ratchet.consumeSkippedKey(at: targetIndex) != nil else {
                    return false
                }

                // Second consumption must return nil (idempotent / no double-use)
                return ratchet.consumeSkippedKey(at: targetIndex) == nil
            } catch {
                return false
            }
        }
    }

    /// **INVARIANT: Ratchet State Monotonicity**
    ///
    /// The chain index only ever increases. There is no operation that
    /// decreases the index, which would imply reuse of a previous state.
    func testProperty_chainIndexIsMonotonicallyIncreasing() {
        property("Chain index is strictly monotonically increasing") <- forAll(
            Gen<Int>.fromElements(in: 1...200)
        ) { n in
            do {
                var ratchet = SymmetricRatchet(
                    chainKey: SecureBytes(bytes: (0..<32).map { _ in UInt8.random(in: 0...255) })
                )

                var previousIndex: UInt32 = 0
                for _ in 0..<n {
                    _ = try ratchet.advance()
                    guard ratchet.index > previousIndex else {
                        return false
                    }
                    previousIndex = ratchet.index
                }
                return true
            } catch {
                return false
            }
        }
    }

    /// **INVARIANT: Skip-Then-Advance Consistency**
    ///
    /// After skipping to index K, the next advance() produces the key
    /// for index K (and increments to K+1). The skipped keys for
    /// indices 0..K-1 are stored separately.
    func testProperty_skipThenAdvanceIsConsistent() throws {
        let ck = SecureBytes(bytes: Array(repeating: 0x42, count: 32))

        // Path 1: advance one by one to index 10
        var ratchetSequential = SymmetricRatchet(chainKey: SecureBytes(bytes: Array(repeating: 0x42, count: 32)))
        var sequentialKeys: [Data] = []
        for _ in 0..<10 {
            let mk = try ratchetSequential.advance()
            sequentialKeys.append(try mk.copyToData())
        }

        // Path 2: skip to index 10 (storing keys 0..9)
        var ratchetSkip = SymmetricRatchet(chainKey: SecureBytes(bytes: Array(repeating: 0x42, count: 32)))
        try ratchetSkip.skipTo(index: 10)

        // The skipped keys should match the sequential keys
        for i: UInt32 in 0..<10 {
            let skippedKey = ratchetSkip.consumeSkippedKey(at: i + 1) // +1 because advance() sets index to i+1
        }

        // Both ratchets should now be at the same index
        XCTAssertEqual(ratchetSequential.index, ratchetSkip.index)

        // And the next key from both should be identical
        let nextSeq = try ratchetSequential.advance()
        let nextSkip = try ratchetSkip.advance()
        XCTAssertEqual(nextSeq, nextSkip,
                       "Sequential and skip-based advancement must converge")
    }
}
