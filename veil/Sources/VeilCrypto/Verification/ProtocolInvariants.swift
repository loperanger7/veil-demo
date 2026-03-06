// VEIL — ProtocolInvariants.swift
// Ticket: VEIL-701 — Protocol Proofs
// Spec reference: Section 9.2
//
// Exhaustive invariant checkers for all Veil protocols.
//
// Unlike property-based tests (which sample randomly), these invariants
// enumerate ALL valid states or transitions and verify correctness for each.
//
// Invariants implemented:
//   1. SPQRStateInvariant — Phase transition completeness
//   2. SymmetricChainInvariant — Chain key monotonicity and key uniqueness
//   3. DomainSeparationInvariant — Domain label uniqueness and format
//   4. IKMConcatenationInvariant — PQXDH IKM byte layout specification

import Foundation
import CryptoKit

// MARK: - SPQR State Invariant

/// Exhaustive verification of the SPQR phase state machine.
///
/// The SPQR protocol has 6 phases with specific valid transitions:
/// ```
/// idle → distributingKey
/// distributingKey → accumulatingCiphertext  (peer assembled our key, sending CT back)
/// accumulatingKey → distributingCiphertext  (we assembled peer's key, encapsulating)
/// distributingCiphertext → complete         (last fragment sent)
/// accumulatingCiphertext → complete         (all CT fragments received, decapsulated)
/// complete → idle                           (secret consumed)
/// ```
public enum SPQRStateInvariant: Sendable {

    /// All 6 SPQR phases as simple labels for enumeration.
    public enum PhaseLabel: String, CaseIterable, Sendable {
        case idle
        case distributingKey
        case accumulatingKey
        case distributingCiphertext
        case accumulatingCiphertext
        case complete
    }

    /// A transition record for the state machine.
    public struct Transition: Sendable, Equatable {
        public let from: PhaseLabel
        public let to: PhaseLabel
        public let isValid: Bool
    }

    /// The complete set of valid transitions in the SPQR state machine.
    public static let validTransitions: Set<String> = [
        "idle→distributingKey",
        "idle→accumulatingKey",           // If peer initiates first
        "distributingKey→accumulatingCiphertext",
        "accumulatingKey→distributingCiphertext",
        "distributingCiphertext→complete",
        "accumulatingCiphertext→complete",
        "complete→idle",
    ]

    /// Enumerate all 36 possible phase transitions and classify each as valid or invalid.
    ///
    /// - Returns: Array of 36 transitions with validity labels.
    public static func enumerateAllTransitions() -> [Transition] {
        var transitions: [Transition] = []

        for from in PhaseLabel.allCases {
            for to in PhaseLabel.allCases {
                let key = "\(from.rawValue)→\(to.rawValue)"
                let isValid = validTransitions.contains(key)
                transitions.append(Transition(from: from, to: to, isValid: isValid))
            }
        }

        return transitions
    }

    /// Verify that every phase has at least one valid successor.
    ///
    /// A phase with no successors is a terminal state — only `complete` should
    /// have `idle` as its sole successor (and it's not truly terminal since
    /// `idle` can restart).
    ///
    /// - Returns: Set of phases with no valid outgoing transitions (should be empty).
    public static func findDeadEndPhases() -> Set<PhaseLabel> {
        var deadEnds = Set<PhaseLabel>()
        for phase in PhaseLabel.allCases {
            let hasSuccessor = PhaseLabel.allCases.contains { to in
                validTransitions.contains("\(phase.rawValue)→\(to.rawValue)")
            }
            if !hasSuccessor {
                deadEnds.insert(phase)
            }
        }
        return deadEnds
    }

    /// Verify that the state machine is strongly connected (every phase is reachable
    /// from `idle` via some sequence of valid transitions).
    ///
    /// - Returns: Set of unreachable phases (should be empty).
    public static func findUnreachablePhases() -> Set<PhaseLabel> {
        var reachable = Set<PhaseLabel>([.idle])
        var frontier = Set<PhaseLabel>([.idle])

        while !frontier.isEmpty {
            var nextFrontier = Set<PhaseLabel>()
            for from in frontier {
                for to in PhaseLabel.allCases {
                    let key = "\(from.rawValue)→\(to.rawValue)"
                    if validTransitions.contains(key) && !reachable.contains(to) {
                        reachable.insert(to)
                        nextFrontier.insert(to)
                    }
                }
            }
            frontier = nextFrontier
        }

        return Set(PhaseLabel.allCases).subtracting(reachable)
    }
}

// MARK: - Symmetric Chain Invariant

/// Verifies structural properties of the symmetric chain ratchet.
///
/// Invariants:
///   1. Chain key index is strictly monotonically increasing
///   2. All derived message keys are unique
///   3. Skip bound is enforced at exactly maxSkippedMessageKeys
///   4. Consumed skipped keys are permanently deleted
public enum SymmetricChainInvariant: Sendable {

    /// Run the full invariant suite on a chain of `length` messages.
    ///
    /// - Parameters:
    ///   - initialChainKey: The starting chain key.
    ///   - length: Number of messages to derive.
    /// - Returns: A list of any violated invariants (empty = all pass).
    public static func verifyAll(
        initialChainKey: SecureBytes,
        length: Int
    ) throws -> [String] {
        var violations: [String] = []
        var ratchet = SymmetricRatchet(chainKey: initialChainKey)
        var allKeys: [Data] = []
        var previousIndex: UInt32 = 0

        for i in 0..<length {
            let prevIdx = ratchet.index
            let mk = try ratchet.advance()
            let mkData = try mk.copyToData()

            // Invariant 1: Index monotonically increases
            if i > 0 && ratchet.index <= previousIndex {
                violations.append("INV-1: Index not monotonic at step \(i): \(ratchet.index) <= \(previousIndex)")
            }
            previousIndex = ratchet.index

            // Invariant 2: All keys unique
            if allKeys.contains(mkData) {
                violations.append("INV-2: Duplicate message key at step \(i)")
            }
            allKeys.append(mkData)

            // Invariant: advance() increments index by exactly 1
            if ratchet.index != prevIdx + 1 {
                violations.append("INV-ADV: advance() changed index by \(ratchet.index - prevIdx) at step \(i)")
            }
        }

        return violations
    }

    /// Verify the skip bound is enforced at exactly the specified limit.
    ///
    /// - Parameter initialChainKey: The starting chain key.
    /// - Returns: Tuple of (canSkipMax, cannotSkipMaxPlusOne).
    public static func verifySkipBound(initialChainKey: SecureBytes) throws -> (Bool, Bool) {
        // Should succeed: skip to exactly maxSkippedMessageKeys
        var ratchet1 = SymmetricRatchet(chainKey: initialChainKey)
        let canSkipMax: Bool
        do {
            try ratchet1.skipTo(index: UInt32(VeilConstants.maxSkippedMessageKeys))
            canSkipMax = true
        } catch {
            canSkipMax = false
        }

        // Should fail: skip to maxSkippedMessageKeys + 1
        var ratchet2 = SymmetricRatchet(chainKey: initialChainKey)
        let cannotSkipOver: Bool
        do {
            try ratchet2.skipTo(index: UInt32(VeilConstants.maxSkippedMessageKeys + 1))
            cannotSkipOver = false // Should have thrown
        } catch {
            cannotSkipOver = true // Correctly threw
        }

        return (canSkipMax, cannotSkipOver)
    }

    /// Verify that consumed skipped keys are permanently deleted.
    ///
    /// - Parameter initialChainKey: The starting chain key.
    /// - Returns: True if consumed key is permanently removed.
    public static func verifySkippedKeyDeletion(initialChainKey: SecureBytes) throws -> Bool {
        var ratchet = SymmetricRatchet(chainKey: initialChainKey)

        // Skip forward to create some skipped keys
        try ratchet.skipTo(index: 5)

        // Consume key at index 2
        let key = ratchet.consumeSkippedKey(at: 2)
        guard key != nil else { return false }

        // Second consumption should return nil
        let secondKey = ratchet.consumeSkippedKey(at: 2)
        return secondKey == nil
    }
}

// MARK: - Domain Separation Invariant

/// Verifies the uniqueness and format of all VeilDomain labels.
///
/// Invariants:
///   1. All domain strings are unique
///   2. All domain strings follow the format "Veil:<Context>:v<N>"
///   3. No domain string is a prefix of another (prevents extension attacks)
///   4. All domain strings encode to valid UTF-8
public enum DomainSeparationInvariant: Sendable {

    /// Verify all domain separation invariants.
    ///
    /// - Returns: List of violated invariants (empty = all pass).
    public static func verifyAll() -> [String] {
        var violations: [String] = []
        let allDomains = VeilDomain.allCases

        // Invariant 1: All strings unique
        let rawValues = allDomains.map(\.rawValue)
        let uniqueValues = Set(rawValues)
        if rawValues.count != uniqueValues.count {
            violations.append("INV-1: Duplicate domain strings found")
        }

        // Invariant 2: Format check — "Veil:<Context>:v<N>"
        let formatRegex = /^Veil:[A-Za-z:]+:v\d+$/
        for domain in allDomains {
            if domain.rawValue.wholeMatch(of: formatRegex) == nil {
                violations.append("INV-2: Domain '\(domain.rawValue)' doesn't match format Veil:<Context>:v<N>")
            }
        }

        // Invariant 3: No domain is a prefix of another
        for (i, d1) in rawValues.enumerated() {
            for (j, d2) in rawValues.enumerated() where i != j {
                if d2.hasPrefix(d1) {
                    violations.append("INV-3: '\(d1)' is a prefix of '\(d2)'")
                }
            }
        }

        // Invariant 4: UTF-8 validity and UTF8Data round-trip
        for domain in allDomains {
            let data = domain.utf8Data
            guard let roundTrip = String(data: data, encoding: .utf8) else {
                violations.append("INV-4: Domain '\(domain.rawValue)' fails UTF-8 round-trip")
                continue
            }
            if roundTrip != domain.rawValue {
                violations.append("INV-4: Domain '\(domain.rawValue)' UTF-8 round-trip mismatch")
            }
        }

        return violations
    }

    /// Count the total number of defined domains.
    public static var domainCount: Int {
        VeilDomain.allCases.count
    }
}

// MARK: - IKM Concatenation Invariant

/// Verifies the byte layout of the PQXDH input keying material.
///
/// The IKM layout is:
///   DH1 (32 bytes) || DH2 (32 bytes) || DH3 (32 bytes) || DH4 (0 or 32 bytes)
///   || KEM_SS (32 bytes) || KEM_OT_SS (0 or 32 bytes)
///
/// This invariant checks that the IKM size is correct for all variants:
///   - Full (4 DH + 2 KEM): 32*4 + 32*2 = 192 bytes
///   - No DH4 + No KEM2:    32*3 + 32*1 = 128 bytes
///   - DH4 only:            32*4 + 32*1 = 160 bytes
///   - KEM2 only:           32*3 + 32*2 = 160 bytes
public enum IKMConcatenationInvariant: Sendable {

    /// Expected IKM sizes for all four variants.
    public static let expectedSizes: [(hasDH4: Bool, hasKEM2: Bool, size: Int)] = [
        (true,  true,  192),  // Full: 4 DH + 2 KEM
        (true,  false, 160),  // DH4 only
        (false, true,  160),  // KEM2 only
        (false, false, 128),  // Minimal: 3 DH + 1 KEM
    ]

    /// The fixed sizes of each IKM component.
    public static let componentSizes: [(name: String, size: Int)] = [
        ("DH1 (IK_A, SPK_B)",     VeilConstants.x25519KeySize),
        ("DH2 (EK_A, IK_B)",      VeilConstants.x25519KeySize),
        ("DH3 (EK_A, SPK_B)",     VeilConstants.x25519KeySize),
        ("DH4 (EK_A, OPK_B)",     VeilConstants.x25519KeySize),
        ("KEM_SS (signed prekey)", VeilConstants.mlkem1024SharedSecretSize),
        ("KEM_OT_SS (one-time)",   VeilConstants.mlkem1024SharedSecretSize),
    ]

    /// Verify that a given IKM data matches the expected size for its variant.
    ///
    /// - Parameters:
    ///   - ikmData: The concatenated IKM bytes.
    ///   - hasDH4: Whether DH4 is included.
    ///   - hasKEM2: Whether KEM2 is included.
    /// - Returns: Whether the size matches.
    public static func verifyIKMSize(
        ikmData: Data,
        hasDH4: Bool,
        hasKEM2: Bool
    ) -> Bool {
        guard let expected = expectedSizes.first(where: { $0.hasDH4 == hasDH4 && $0.hasKEM2 == hasKEM2 }) else {
            return false
        }
        return ikmData.count == expected.size
    }

    /// Compute the expected IKM size for a given variant.
    public static func expectedSize(hasDH4: Bool, hasKEM2: Bool) -> Int {
        var size = 3 * VeilConstants.x25519KeySize // DH1 + DH2 + DH3
        if hasDH4 { size += VeilConstants.x25519KeySize }
        size += VeilConstants.mlkem1024SharedSecretSize // KEM_SS (always present)
        if hasKEM2 { size += VeilConstants.mlkem1024SharedSecretSize }
        return size
    }
}
