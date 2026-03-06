// VEIL — SPQRFuzzTests.swift
// Ticket: VEIL-702 — Fuzz Testing
// Spec reference: Section 9.3.2
//
// Focused fuzzing of the SPQR (Sparse Post-Quantum Ratchet) protocol:
//   - Duplicate fragment handling
//   - Out-of-range fragment indices
//   - Empty and oversized fragments
//   - Interleaved epoch fragments
//   - Rapid phase transitions
//   - Malformed ML-KEM public keys

import XCTest
@testable import VeilCrypto

final class SPQRFuzzTests: XCTestCase {

    // MARK: - Helpers

    /// Create a SPQR ratchet that immediately triggers.
    private func makeImmediate() -> SPQRRatchet {
        SPQRRatchet(fragmentSize: 256, intervalMessages: 0, maxIntervalSeconds: 0)
    }

    /// Run Alice through key distribution and collect all fragments.
    private func distributeKey(_ alice: inout SPQRRatchet) throws -> [SPQRFragment] {
        alice.recordMessage()
        try alice.initiateKeyDistribution()
        var fragments: [SPQRFragment] = []
        while let f = alice.nextOutgoingFragment() {
            fragments.append(f)
        }
        return fragments
    }

    // MARK: - Duplicate Fragment Handling

    /// Send the same fragment twice — should be handled gracefully.
    func testFuzz_DuplicateFragments() throws {
        var alice = makeImmediate()
        var bob = makeImmediate()

        let fragments = try distributeKey(&alice)
        guard let firstFragment = fragments.first else {
            XCTFail("No fragments generated")
            return
        }

        // Send the first fragment twice
        _ = try bob.processIncomingFragment(firstFragment)
        _ = try bob.processIncomingFragment(firstFragment) // Duplicate: should overwrite, not crash

        // Send remaining fragments
        for fragment in fragments.dropFirst() {
            _ = try bob.processIncomingFragment(fragment)
        }

        // Bob should have assembled the full key
        let ctFragment = bob.nextOutgoingFragment()
        XCTAssertNotNil(ctFragment, "Duplicate fragment should not prevent assembly")
    }

    /// Send all fragments twice (full replay).
    func testFuzz_FullReplay() throws {
        var alice = makeImmediate()
        var bob = makeImmediate()

        let fragments = try distributeKey(&alice)

        // First pass: normal delivery
        for fragment in fragments {
            _ = try bob.processIncomingFragment(fragment)
        }

        // Bob assembled key, started CT distribution
        let ctFragment = bob.nextOutgoingFragment()
        XCTAssertNotNil(ctFragment, "First pass should complete")

        // Second pass: replay all fragments — Bob is now in a different phase
        // These should be handled gracefully (ignored or processed as new context)
        for fragment in fragments {
            // May throw or be ignored — the key is NO CRASH
            _ = try? bob.processIncomingFragment(fragment)
        }
    }

    // MARK: - Out-of-Range Fragment Index

    /// Fragment with index >= totalFragments.
    func testFuzz_OutOfRangeIndex() throws {
        var bob = makeImmediate()

        let badFragment = SPQRFragment(
            type: .publicKey,
            index: 100,           // Way beyond total
            totalFragments: 7,
            data: Data(repeating: 0xAB, count: 256)
        )

        // Should not crash. May store the fragment (no bounds check in current impl)
        // or may throw. Either way, should not crash.
        _ = try? bob.processIncomingFragment(badFragment)
    }

    /// Fragment with negative-equivalent index (UInt16 overflow).
    func testFuzz_MaxIndex() throws {
        var bob = makeImmediate()

        let maxFragment = SPQRFragment(
            type: .publicKey,
            index: Int(UInt16.max),
            totalFragments: Int(UInt16.max),
            data: Data(repeating: 0xCD, count: 256)
        )

        _ = try? bob.processIncomingFragment(maxFragment)
        // No crash = pass
    }

    // MARK: - Empty Fragment Data

    /// Fragment with zero-length data.
    func testFuzz_EmptyFragmentData() throws {
        var bob = makeImmediate()

        let emptyFragment = SPQRFragment(
            type: .publicKey,
            index: 0,
            totalFragments: 1,
            data: Data()  // Empty!
        )

        // Processing an empty fragment for a 1-fragment key will try to
        // encapsulate with an empty public key — should fail gracefully
        do {
            _ = try bob.processIncomingFragment(emptyFragment)
            // If we get here, the fragment was accepted (empty key would fail at encapsulation)
        } catch {
            // Expected — empty public key can't be encapsulated
        }
    }

    /// Fragment with oversized data.
    func testFuzz_OversizedFragmentData() throws {
        var bob = makeImmediate()

        let bigFragment = SPQRFragment(
            type: .publicKey,
            index: 0,
            totalFragments: 1,
            data: Data(repeating: 0xFF, count: 10_000)  // Much larger than expected
        )

        // Should handle oversized data without crash
        // The assembled "key" will be wrong size → encapsulation will fail
        do {
            _ = try bob.processIncomingFragment(bigFragment)
        } catch {
            // Expected — invalid key size
        }
    }

    // MARK: - Interleaved Epoch Fragments

    /// Start two SPQR exchanges and interleave their fragments.
    func testFuzz_InterleavedEpochs() throws {
        var alice1 = makeImmediate()
        var alice2 = makeImmediate()
        var bob = makeImmediate()

        // Get fragments from two different SPQR initiations
        let frags1 = try distributeKey(&alice1)
        let frags2 = try distributeKey(&alice2)

        // Interleave fragments from both exchanges
        let maxLen = max(frags1.count, frags2.count)
        for i in 0..<maxLen {
            if i < frags1.count {
                _ = try? bob.processIncomingFragment(frags1[i])
            }
            if i < frags2.count {
                _ = try? bob.processIncomingFragment(frags2[i])
            }
        }

        // Bob should have assembled SOME key (possibly confused, but no crash)
        // The important thing is no crash or memory corruption
    }

    // MARK: - Rapid Phase Transitions

    /// Initiate key distribution multiple times without completing.
    func testFuzz_RapidReInitiation() throws {
        var ratchet = makeImmediate()

        for _ in 0..<10 {
            ratchet.recordMessage()
            if ratchet.shouldInitiateStep {
                try ratchet.initiateKeyDistribution()
            }

            // Get one fragment then re-initiate (simulating timeout/restart)
            let _ = ratchet.nextOutgoingFragment()

            // Force back to idle-like state by consuming (will return nil since not complete)
            _ = ratchet.consumeCompletedSecret()
        }

        // Should not crash after rapid re-initiations
    }

    /// Force initiation during fragment distribution.
    func testFuzz_InitiationDuringDistribution() throws {
        var ratchet = makeImmediate()
        ratchet.recordMessage()

        try ratchet.initiateKeyDistribution()

        // Get first fragment but don't send it
        let _ = ratchet.nextOutgoingFragment()

        // Try to initiate again (should not since not idle)
        XCTAssertFalse(ratchet.shouldInitiateStep,
                      "Should not suggest step while distributing")
    }

    // MARK: - Malformed ML-KEM Public Key

    /// Assemble fragments that form an invalid ML-KEM public key.
    func testFuzz_MalformedAssembledKey() throws {
        var bob = makeImmediate()

        // Create fragments that assemble to garbage data (not a valid ML-KEM key)
        let fakeKeySize = VeilConstants.mlkem1024PublicKeySize
        let fragmentSize = 256
        let totalFragments = (fakeKeySize + fragmentSize - 1) / fragmentSize

        for i in 0..<totalFragments {
            let start = i * fragmentSize
            let end = min(start + fragmentSize, fakeKeySize)
            let fragData = Data(repeating: UInt8(i & 0xFF), count: end - start)

            let fragment = SPQRFragment(
                type: .publicKey,
                index: i,
                totalFragments: totalFragments,
                data: fragData
            )

            do {
                _ = try bob.processIncomingFragment(fragment)
            } catch {
                // Expected: when all fragments assembled, encapsulation with garbage key will fail
                // This is the correct behavior
                return
            }
        }

        // If we got here, encapsulation succeeded with garbage key (unlikely but possible
        // since ML-KEM may not validate key structure in all implementations)
    }

    /// Feed the correct number of ciphertext fragments but with garbage data.
    func testFuzz_MalformedCiphertextFragments() throws {
        var alice = makeImmediate()
        var bob = makeImmediate()

        // Alice distributes real key
        let keyFrags = try distributeKey(&alice)
        for f in keyFrags {
            _ = try bob.processIncomingFragment(f)
        }

        // Bob now has Alice's key and is distributing real CT
        // Instead, feed Alice garbage CT fragments
        let ctSize = VeilConstants.mlkem1024CiphertextSize
        let fragmentSize = 256
        let totalCTFragments = (ctSize + fragmentSize - 1) / fragmentSize

        for i in 0..<totalCTFragments {
            let start = i * fragmentSize
            let end = min(start + fragmentSize, ctSize)
            let garbageFrag = SPQRFragment(
                type: .ciphertext,
                index: i,
                totalFragments: totalCTFragments,
                data: Data(repeating: 0xDE, count: end - start)
            )

            do {
                _ = try alice.processIncomingFragment(garbageFrag)
            } catch {
                // Expected: garbage CT → decapsulation failure
                return
            }
        }
        // If we got here, decapsulation with garbage CT produced a "secret"
        // (ML-KEM IND-CCA2 should prevent this, but implementation may vary)
    }

    // MARK: - Fragment Serialization Fuzzing

    /// Attempt to deserialize random bytes as SPQR fragments.
    func testFuzz_FragmentDeserializationRandomBytes() {
        for _ in 0..<100 {
            let size = Int.random(in: 0...50)
            var randomData = Data(count: size)
            if size > 0 {
                randomData.withUnsafeMutableBytes { ptr in
                    _ = SecRandomCopyBytes(kSecRandomDefault, size, ptr.baseAddress!)
                }
            }

            // Should return nil for invalid data, not crash
            let fragment = SPQRFragment.deserialize(from: randomData)

            if size < 7 {
                XCTAssertNil(fragment, "Data shorter than 7 bytes should not deserialize")
            }
            // For larger data, may or may not deserialize depending on content
        }
    }

    /// Deserialize with various invalid type bytes.
    func testFuzz_FragmentInvalidType() {
        // Valid types are 0x01 (publicKey) and 0x02 (ciphertext)
        let invalidTypes: [UInt8] = [0x00, 0x03, 0x04, 0xFF, 0x80]

        for invalidType in invalidTypes {
            var data = Data()
            data.append(invalidType)            // Invalid type
            data.append(contentsOf: [0, 0])     // Index
            data.append(contentsOf: [0, 1])     // Total fragments
            data.append(contentsOf: [0, 4])     // Length = 4
            data.append(contentsOf: [1, 2, 3, 4]) // Payload

            let fragment = SPQRFragment.deserialize(from: data)
            XCTAssertNil(fragment, "Type \(invalidType) should not deserialize")
        }
    }

    // MARK: - Scheduling Edge Cases

    /// Verify behavior with zero interval (immediate trigger).
    func testFuzz_ZeroInterval() {
        var ratchet = SPQRRatchet(fragmentSize: 256, intervalMessages: 0, maxIntervalSeconds: 0)
        ratchet.recordMessage()
        XCTAssertTrue(ratchet.shouldInitiateStep, "Zero interval should trigger immediately")
    }

    /// Verify behavior with very large interval.
    func testFuzz_LargeInterval() {
        var ratchet = SPQRRatchet(
            fragmentSize: 256,
            intervalMessages: Int.max / 2,
            maxIntervalSeconds: .infinity
        )

        for _ in 0..<1000 {
            ratchet.recordMessage()
        }

        XCTAssertFalse(ratchet.shouldInitiateStep, "Large interval should not trigger in 1000 messages")
    }

    /// Verify behavior with fragment size of 1 byte (extreme fragmentation).
    func testFuzz_TinyFragmentSize() throws {
        var alice = SPQRRatchet(fragmentSize: 1, intervalMessages: 0, maxIntervalSeconds: 0)
        alice.recordMessage()

        try alice.initiateKeyDistribution()

        var fragmentCount = 0
        while let _ = alice.nextOutgoingFragment() {
            fragmentCount += 1
            if fragmentCount > 2000 {
                break // Safety valve
            }
        }

        // 1568 byte key / 1 byte per fragment = 1568 fragments
        XCTAssertEqual(fragmentCount, VeilConstants.mlkem1024PublicKeySize,
                      "Should produce exactly \(VeilConstants.mlkem1024PublicKeySize) fragments")
    }
}
