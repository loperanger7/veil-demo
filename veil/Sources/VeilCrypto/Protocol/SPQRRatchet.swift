// VEIL — SPQRRatchet.swift
// Ticket: VEIL-107 — Sparse Post-Quantum Ratchet (SPQR)
// Spec reference: Section 3.3.3
//
// The SPQR runs in parallel with the DH ratchet to provide post-compromise
// security against quantum adversaries. It uses ML-KEM-1024 encapsulations
// exchanged over multiple messages (to amortize the larger key sizes).
//
// The "sparse" nature means PQ ratchet steps occur less frequently than
// DH steps — roughly every N messages or 24 hours, whichever comes first.
//
// When a SPQR step completes, the PQ shared secret is mixed into the root
// key: RK_new = HKDF(RK, ss_pq, "Veil:SPQR:v1")

import Foundation

/// The Sparse Post-Quantum Ratchet for quantum-resistant post-compromise security.
///
/// SPQR operates by fragmenting ML-KEM-1024 public keys and ciphertexts
/// across multiple messages, since ML-KEM keys (1568 bytes) are much larger
/// than the typical message header budget.
///
/// The protocol alternates between two phases:
/// 1. **Key Distribution:** One party sends fragments of a fresh ML-KEM public key.
/// 2. **Encapsulation:** The other party assembles the key, encapsulates,
///    and sends ciphertext fragments back.
///
/// When both sides have the shared secret, it is mixed into the root key.
public struct SPQRRatchet: Sendable {

    // MARK: - Types

    /// The current phase of the SPQR protocol.
    public enum Phase: Sendable {
        /// Idle — no SPQR step in progress.
        case idle

        /// We are distributing our ML-KEM public key to the peer.
        case distributingKey(keyPair: SPQRKeyState, fragmentsSent: Int, totalFragments: Int)

        /// We are accumulating the peer's ML-KEM public key fragments.
        case accumulatingKey(fragments: [Int: Data], totalFragments: Int)

        /// We have the peer's full key and are distributing our ciphertext.
        case distributingCiphertext(ciphertext: Data, sharedSecret: SecureBytes, fragmentsSent: Int, totalFragments: Int)

        /// We are accumulating the peer's ciphertext fragments.
        case accumulatingCiphertext(fragments: [Int: Data], totalFragments: Int, keyPair: SPQRKeyState)

        /// SPQR step complete — shared secret ready to mix into root key.
        case complete(sharedSecret: SecureBytes)
    }

    /// Holds the ML-KEM key pair state during an SPQR epoch.
    public struct SPQRKeyState: Sendable {
        let publicKey: Data
        let keyPair: MLKEM1024KeyPair
    }

    // MARK: - State

    /// Current SPQR phase.
    private(set) var phase: Phase = .idle

    /// Number of messages since last SPQR step.
    private(set) var messagesSinceLastStep: UInt32 = 0

    /// Timestamp of last SPQR step completion.
    private(set) var lastStepTimestamp: Date = Date()

    /// Fragment size in bytes.
    private let fragmentSize: Int

    /// Message interval between SPQR steps.
    private let intervalMessages: Int

    /// Maximum time between SPQR steps.
    private let maxIntervalSeconds: TimeInterval

    // MARK: - Initialization

    public init(
        fragmentSize: Int = VeilConstants.spqrFragmentSize,
        intervalMessages: Int = VeilConstants.spqrDefaultIntervalMessages,
        maxIntervalSeconds: TimeInterval = VeilConstants.spqrMaxIntervalSeconds
    ) {
        self.fragmentSize = fragmentSize
        self.intervalMessages = intervalMessages
        self.maxIntervalSeconds = maxIntervalSeconds
    }

    // MARK: - Scheduling

    /// Whether it's time to initiate a new SPQR step.
    public var shouldInitiateStep: Bool {
        if case .idle = phase {
            let messageThreshold = messagesSinceLastStep >= UInt32(intervalMessages)
            let timeThreshold = Date().timeIntervalSince(lastStepTimestamp) >= maxIntervalSeconds
            return messageThreshold || timeThreshold
        }
        return false
    }

    /// Record that a message was sent/received (for scheduling).
    public mutating func recordMessage() {
        messagesSinceLastStep += 1
    }

    // MARK: - Key Distribution (Initiator)

    /// Begin a new SPQR step by generating an ML-KEM key pair
    /// and preparing to distribute the public key in fragments.
    public mutating func initiateKeyDistribution() throws {
        let keyPair = try MLKEM1024KeyPair.generate()
        let publicKeyData = keyPair.publicKey
        let totalFragments = (publicKeyData.count + fragmentSize - 1) / fragmentSize

        phase = .distributingKey(
            keyPair: SPQRKeyState(publicKey: publicKeyData, keyPair: keyPair),
            fragmentsSent: 0,
            totalFragments: totalFragments
        )
    }

    /// Get the next fragment to attach to an outgoing message.
    ///
    /// - Returns: A `SPQRFragment` to include in the message header, or `nil` if
    ///   no fragment needs to be sent in this message.
    public mutating func nextOutgoingFragment() -> SPQRFragment? {
        switch phase {
        case .distributingKey(let keyState, let sent, let total):
            guard sent < total else { return nil }
            let start = sent * fragmentSize
            let end = min(start + fragmentSize, keyState.publicKey.count)
            let fragmentData = keyState.publicKey[start..<end]

            phase = .distributingKey(
                keyPair: keyState,
                fragmentsSent: sent + 1,
                totalFragments: total
            )

            return SPQRFragment(
                type: .publicKey,
                index: sent,
                totalFragments: total,
                data: Data(fragmentData)
            )

        case .distributingCiphertext(let ct, let ss, let sent, let total):
            guard sent < total else { return nil }
            let start = sent * fragmentSize
            let end = min(start + fragmentSize, ct.count)
            let fragmentData = ct[start..<end]

            phase = .distributingCiphertext(
                ciphertext: ct,
                sharedSecret: ss,
                fragmentsSent: sent + 1,
                totalFragments: total
            )

            // If this was the last fragment, transition to complete
            if sent + 1 == total {
                phase = .complete(sharedSecret: ss)
            }

            return SPQRFragment(
                type: .ciphertext,
                index: sent,
                totalFragments: total,
                data: Data(fragmentData)
            )

        default:
            return nil
        }
    }

    // MARK: - Fragment Processing (Responder)

    /// Process an incoming SPQR fragment from the peer.
    ///
    /// - Parameter fragment: The fragment received in a message header.
    /// - Returns: The PQ shared secret if the SPQR step is now complete.
    public mutating func processIncomingFragment(_ fragment: SPQRFragment) throws -> SecureBytes? {
        switch fragment.type {
        case .publicKey:
            return try processPublicKeyFragment(fragment)
        case .ciphertext:
            return try processCiphertextFragment(fragment)
        }
    }

    /// Process a public key fragment from the peer.
    private mutating func processPublicKeyFragment(_ fragment: SPQRFragment) throws -> SecureBytes? {
        var fragments: [Int: Data]
        let total: Int

        if case .accumulatingKey(let existing, let t) = phase {
            fragments = existing
            total = t
        } else {
            fragments = [:]
            total = fragment.totalFragments
        }

        fragments[fragment.index] = fragment.data
        phase = .accumulatingKey(fragments: fragments, totalFragments: total)

        // Check if we have all fragments
        if fragments.count == total {
            // Assemble the full public key
            var publicKey = Data()
            for i in 0..<total {
                guard let frag = fragments[i] else {
                    throw VeilError.invalidFragment(reason: "Missing fragment \(i)")
                }
                publicKey.append(frag)
            }

            // Encapsulate using the assembled key
            let result = try MLKEM1024KeyPair.encapsulate(recipientPublicKey: publicKey)

            // Prepare to distribute ciphertext back
            let ctTotal = (result.ciphertext.count + fragmentSize - 1) / fragmentSize
            phase = .distributingCiphertext(
                ciphertext: result.ciphertext,
                sharedSecret: result.sharedSecret,
                fragmentsSent: 0,
                totalFragments: ctTotal
            )

            // Don't return the shared secret yet — we return it after
            // finishing ciphertext distribution (in nextOutgoingFragment)
        }

        return nil
    }

    /// Process a ciphertext fragment from the peer.
    private mutating func processCiphertextFragment(_ fragment: SPQRFragment) throws -> SecureBytes? {
        var fragments: [Int: Data]
        let total: Int
        let keyState: SPQRKeyState

        if case .accumulatingCiphertext(let existing, let t, let ks) = phase {
            fragments = existing
            total = t
            keyState = ks
        } else if case .distributingKey(let ks, _, _) = phase {
            // We were distributing our key; peer has assembled it and is sending CT back
            fragments = [:]
            total = fragment.totalFragments
            keyState = ks
        } else {
            throw VeilError.invalidFragment(reason: "Unexpected ciphertext fragment in phase")
        }

        fragments[fragment.index] = fragment.data
        phase = .accumulatingCiphertext(fragments: fragments, totalFragments: total, keyPair: keyState)

        // Check if we have all fragments
        if fragments.count == total {
            // Assemble the full ciphertext
            var ciphertext = Data()
            for i in 0..<total {
                guard let frag = fragments[i] else {
                    throw VeilError.invalidFragment(reason: "Missing ciphertext fragment \(i)")
                }
                ciphertext.append(frag)
            }

            // Decapsulate
            let sharedSecret = try keyState.keyPair.decapsulate(ciphertext: ciphertext)

            phase = .complete(sharedSecret: sharedSecret)
            messagesSinceLastStep = 0
            lastStepTimestamp = Date()

            return sharedSecret
        }

        return nil
    }

    // MARK: - Completion

    /// Consume the completed SPQR shared secret and reset to idle.
    ///
    /// - Returns: The PQ shared secret to mix into the root key.
    public mutating func consumeCompletedSecret() -> SecureBytes? {
        if case .complete(let ss) = phase {
            phase = .idle
            messagesSinceLastStep = 0
            return ss
        }
        return nil
    }
}

// MARK: - Fragment Type

/// A single fragment of an SPQR key or ciphertext exchange.
public struct SPQRFragment: Sendable, Codable {

    /// Whether this fragment contains public key or ciphertext data.
    public enum FragmentType: UInt8, Sendable, Codable {
        case publicKey = 0x01
        case ciphertext = 0x02
    }

    /// Fragment type.
    public let type: FragmentType

    /// Fragment index (0-based).
    public let index: Int

    /// Total number of fragments in this key/ciphertext.
    public let totalFragments: Int

    /// The fragment payload.
    public let data: Data

    public init(type: FragmentType, index: Int, totalFragments: Int, data: Data) {
        self.type = type
        self.index = index
        self.totalFragments = totalFragments
        self.data = data
    }

    /// Serialize this fragment for inclusion in a message header.
    public var serialized: Data {
        var result = Data()
        result.append(type.rawValue)
        var idx = UInt16(index).bigEndian
        result.append(Data(bytes: &idx, count: 2))
        var total = UInt16(totalFragments).bigEndian
        result.append(Data(bytes: &total, count: 2))
        var len = UInt16(data.count).bigEndian
        result.append(Data(bytes: &len, count: 2))
        result.append(data)
        return result
    }

    /// Deserialize a fragment from a message header.
    public static func deserialize(from data: Data) -> SPQRFragment? {
        guard data.count >= 7 else { return nil }
        guard let type = FragmentType(rawValue: data[0]) else { return nil }
        let index = Int(UInt16(bigEndian: data[1...2].withUnsafeBytes { $0.load(as: UInt16.self) }))
        let total = Int(UInt16(bigEndian: data[3...4].withUnsafeBytes { $0.load(as: UInt16.self) }))
        let len = Int(UInt16(bigEndian: data[5...6].withUnsafeBytes { $0.load(as: UInt16.self) }))
        guard data.count >= 7 + len else { return nil }
        let payload = Data(data[7..<(7 + len)])
        return SPQRFragment(type: type, index: index, totalFragments: total, data: payload)
    }
}
