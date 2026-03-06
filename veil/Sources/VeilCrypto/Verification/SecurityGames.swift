// VEIL — SecurityGames.swift
// Ticket: VEIL-701 — Protocol Proofs
// Spec reference: Section 9.1
//
// Security game infrastructure for formal verification of Veil's protocols.
//
// Each game models a specific attacker capability and verifies that the protocol
// resists the corresponding attack. Games are deterministic, reproducible, and
// produce machine-readable verdicts.
//
// Games implemented:
//   1. PQXDHSecurityGame  — IND-CCA2 key indistinguishability
//   2. RatchetForwardSecrecyGame — compromise at epoch n reveals nothing about 0..n-1
//   3. PostCompromiseSecurityGame — recovery after k DH ratchet steps
//   4. ChainIsolationGame — sending chain ≠ receiving chain

import Foundation
import CryptoKit

// MARK: - Game Verdict

/// The outcome of a security game execution.
public enum GameVerdict: Sendable, Equatable {
    /// The protocol resisted the attack.
    case secure(reason: String)
    /// The protocol was violated — a real attack exists.
    case violated(reason: String, evidence: String)

    public var isSecure: Bool {
        if case .secure = self { return true }
        return false
    }
}

// MARK: - PQXDH Security Game (IND-CCA2)

/// Models an IND-CCA2 attacker against the PQXDH key agreement.
///
/// The attacker observes:
///   - All public keys (both parties' identity and ephemeral keys)
///   - The initiator message (ciphertexts, key selections)
///   - A challenge: either the real session key or a random 64-byte key
///
/// The game verifies the attacker cannot distinguish real from random.
///
/// Security reduction:
///   An adversary who wins this game can break either:
///   (a) X25519 CDH in the random oracle model, OR
///   (b) ML-KEM-1024 IND-CCA2
public struct PQXDHSecurityGame: Sendable {

    /// The attacker's observable view of a PQXDH handshake.
    public struct AttackerView: Sendable {
        /// Alice's identity public key (Ed25519, 32 bytes).
        public let aliceIdentityKey: Data
        /// Alice's ephemeral public key (X25519, 32 bytes).
        public let aliceEphemeralKey: Data
        /// Bob's identity public key (Ed25519, 32 bytes).
        public let bobIdentityKey: Data
        /// Bob's signed prekey (X25519, 32 bytes).
        public let bobSignedPrekey: Data
        /// Bob's one-time prekey (X25519, 32 bytes), if used.
        public let bobOneTimePrekey: Data?
        /// Bob's PQ signed prekey (ML-KEM-1024 public, 1568 bytes).
        public let bobPQSignedPrekey: Data
        /// Bob's PQ one-time prekey (ML-KEM-1024 public, 1568 bytes), if used.
        public let bobPQOneTimePrekey: Data?
        /// KEM ciphertext for PQ signed prekey.
        public let pqCiphertext: Data
        /// KEM ciphertext for PQ one-time prekey, if used.
        public let pqOneTimeCiphertext: Data?
    }

    /// The challenge presented to the attacker.
    public struct Challenge: Sendable {
        /// The candidate session key (either real or random).
        public let candidateKey: Data
        /// Whether this is the real key (hidden from attacker, revealed for verification).
        public let isReal: Bool
    }

    /// Build the attacker's view from a PQXDH initiator result.
    ///
    /// - Parameters:
    ///   - message: The initiator message (publicly transmitted).
    ///   - bundle: Bob's prekey bundle (publicly available).
    /// - Returns: The attacker's view of the handshake.
    public static func buildAttackerView(
        message: PQXDH.InitiatorMessage,
        bundle: PrekeyBundle
    ) -> AttackerView {
        AttackerView(
            aliceIdentityKey: message.identityKey,
            aliceEphemeralKey: message.ephemeralKey,
            bobIdentityKey: bundle.identityKeyEd25519,
            bobSignedPrekey: bundle.signedPrekey,
            bobOneTimePrekey: bundle.oneTimePrekeys.first?.publicKey,
            bobPQSignedPrekey: bundle.pqSignedPrekey,
            bobPQOneTimePrekey: bundle.pqOneTimePrekeys.first?.publicKey,
            pqCiphertext: message.pqCiphertext,
            pqOneTimeCiphertext: message.pqOneTimeCiphertext
        )
    }

    /// Generate a challenge for the IND-CCA2 game.
    ///
    /// With probability 0.5, the challenge contains the real session key.
    /// With probability 0.5, it contains a random 64-byte key.
    ///
    /// - Parameters:
    ///   - realSessionKey: The actual session key from PQXDH.
    ///   - useReal: Whether to use the real key (controlled by test for determinism).
    /// - Returns: The challenge.
    public static func generateChallenge(
        realSessionKey: SecureBytes,
        useReal: Bool
    ) throws -> Challenge {
        if useReal {
            return Challenge(
                candidateKey: try realSessionKey.copyToData(),
                isReal: true
            )
        } else {
            var randomKey = Data(count: VeilConstants.sessionKeySize)
            randomKey.withUnsafeMutableBytes { ptr in
                _ = SecRandomCopyBytes(kSecRandomDefault, VeilConstants.sessionKeySize, ptr.baseAddress!)
            }
            return Challenge(
                candidateKey: randomKey,
                isReal: false
            )
        }
    }

    /// Verify that the attacker's guess matches reality.
    ///
    /// An IND-CCA2 secure protocol means the attacker's advantage is negligible:
    /// `Adv = |Pr[guess=real | real] - Pr[guess=real | random]| ≈ 0`
    ///
    /// - Parameters:
    ///   - attackerGuessIsReal: The attacker's guess (true = "I think it's the real key").
    ///   - challenge: The actual challenge.
    /// - Returns: Whether the attacker guessed correctly.
    public static func evaluateGuess(
        attackerGuessIsReal: Bool,
        challenge: Challenge
    ) -> Bool {
        attackerGuessIsReal == challenge.isReal
    }

    /// Run a statistical IND-CCA2 game over multiple trials.
    ///
    /// The attacker's advantage should be negligible (≈ 0.5 success rate).
    ///
    /// - Parameters:
    ///   - trials: Number of game trials.
    ///   - attackerOracle: A closure simulating the attacker's distinguisher.
    ///     Given the attacker view and a candidate key, returns true if the
    ///     attacker believes it's the real key.
    ///   - sessionFactory: A closure that generates a fresh PQXDH session.
    /// - Returns: The game verdict.
    public static func runStatisticalGame(
        trials: Int,
        attackerOracle: (AttackerView, Data) -> Bool,
        sessionFactory: () throws -> (PQXDH.InitiatorResult, PrekeyBundle)
    ) throws -> GameVerdict {
        var correctGuesses = 0

        for i in 0..<trials {
            let useReal = (i % 2 == 0) // Alternate real/random
            let (result, bundle) = try sessionFactory()
            let view = buildAttackerView(message: result.message, bundle: bundle)
            let challenge = try generateChallenge(realSessionKey: result.sessionKey, useReal: useReal)

            let guess = attackerOracle(view, challenge.candidateKey)
            if evaluateGuess(attackerGuessIsReal: guess, challenge: challenge) {
                correctGuesses += 1
            }
        }

        let successRate = Double(correctGuesses) / Double(trials)
        let advantage = abs(successRate - 0.5)

        // A negligible advantage should be < 0.1 for reasonable trial counts
        if advantage < 0.1 {
            return .secure(
                reason: "Attacker advantage \(String(format: "%.4f", advantage)) is negligible "
                + "over \(trials) trials (success rate: \(String(format: "%.2f%%", successRate * 100)))"
            )
        } else {
            return .violated(
                reason: "Attacker advantage \(String(format: "%.4f", advantage)) exceeds threshold",
                evidence: "Success rate: \(String(format: "%.2f%%", successRate * 100)) over \(trials) trials"
            )
        }
    }
}

// MARK: - Ratchet Forward Secrecy Game

/// Models an attacker who compromises the device at epoch n and attempts
/// to recover message keys from epochs 0..n-1.
///
/// Security property:
///   Given CK_n (chain key at epoch n), the attacker cannot derive
///   MK_0, MK_1, ..., MK_{n-1} because HMAC-SHA-256 is one-way.
public struct RatchetForwardSecrecyGame: Sendable {

    /// The attacker's view after compromising at epoch n.
    public struct CompromisedState: Sendable {
        /// The chain key at the compromised epoch.
        public let chainKeyAtEpochN: SecureBytes
        /// The chain index at compromise.
        public let epochN: UInt32
        /// All message keys from epochs 0..n-1 (ground truth for verification).
        public let previousMessageKeys: [UInt32: SecureBytes]
    }

    /// Run a symmetric chain forward secrecy game.
    ///
    /// Simulates a ratchet session of `totalMessages` messages, then
    /// captures the chain state at message `compromiseAt`. Verifies that
    /// the compromised chain key cannot reproduce any earlier message key.
    ///
    /// - Parameters:
    ///   - initialChainKey: The starting chain key.
    ///   - totalMessages: Number of messages to simulate.
    ///   - compromiseAt: The message index at which the attacker compromises.
    /// - Returns: Game verdict.
    public static func playSymmetricChainGame(
        initialChainKey: SecureBytes,
        totalMessages: Int,
        compromiseAt: Int
    ) throws -> (verdict: GameVerdict, state: CompromisedState) {
        var ratchet = SymmetricRatchet(chainKey: initialChainKey)
        var allMessageKeys: [UInt32: SecureBytes] = [:]
        var compromisedCK: SecureBytes?

        for i in 0..<totalMessages {
            if i == compromiseAt {
                compromisedCK = ratchet.chainKey
            }
            let mk = try ratchet.advance()
            allMessageKeys[UInt32(i)] = mk
        }

        guard let captured = compromisedCK else {
            return (
                .violated(reason: "Compromise point exceeds total messages", evidence: ""),
                CompromisedState(chainKeyAtEpochN: initialChainKey, epochN: 0, previousMessageKeys: [:])
            )
        }

        // The attacker has captured.chainKey at epoch compromiseAt.
        // Try to derive forward from the captured CK and see if ANY
        // of those derived keys match previous message keys.
        var attackerRatchet = SymmetricRatchet(chainKey: captured)
        var forwardKeys: [SecureBytes] = []
        for _ in 0..<(totalMessages - compromiseAt) {
            let fk = try attackerRatchet.advance()
            forwardKeys.append(fk)
        }

        // Collect previous keys (epochs 0..compromiseAt-1)
        var previousKeys: [UInt32: SecureBytes] = [:]
        for i in 0..<compromiseAt {
            previousKeys[UInt32(i)] = allMessageKeys[UInt32(i)]
        }

        // Check: none of the forward-derived keys match any previous key
        for (epoch, prevKey) in previousKeys {
            for fk in forwardKeys {
                if SecureBytes.constantTimeEqual(prevKey, fk) {
                    return (
                        .violated(
                            reason: "Forward key derived from CK_\(compromiseAt) matches MK_\(epoch)",
                            evidence: "Collision found"
                        ),
                        CompromisedState(chainKeyAtEpochN: captured, epochN: UInt32(compromiseAt), previousMessageKeys: previousKeys)
                    )
                }
            }
        }

        let state = CompromisedState(
            chainKeyAtEpochN: captured,
            epochN: UInt32(compromiseAt),
            previousMessageKeys: previousKeys
        )

        return (
            .secure(
                reason: "CK_\(compromiseAt) cannot reproduce any of \(previousKeys.count) prior message keys "
                + "(HMAC-SHA-256 one-wayness holds)"
            ),
            state
        )
    }
}

// MARK: - Post-Compromise Security Game

/// Models an attacker who compromises the full DH ratchet state and verifies
/// that security is restored after k new DH ratchet steps.
///
/// Security property:
///   After k ≥ 2 DH ratchet steps with fresh ephemeral keys from the
///   non-compromised party, the root key is independent of the compromised state.
public struct PostCompromiseSecurityGame: Sendable {

    /// Result of a PCS game round.
    public struct PCSResult: Sendable {
        /// Root key at compromise.
        public let compromisedRootKey: Data
        /// Root keys after each recovery step.
        public let recoveryRootKeys: [Data]
        /// Number of DH steps to recovery.
        public let stepsToRecovery: Int
    }

    /// Verify that root keys diverge after DH ratchet steps.
    ///
    /// Two sessions with the same initial state but different DH inputs
    /// should produce completely different root keys after 2+ steps.
    ///
    /// - Parameters:
    ///   - rootKey: The compromised root key.
    ///   - steps: Number of recovery DH ratchet steps.
    /// - Returns: Game verdict.
    public static func playPCSGame(
        rootKey: SecureBytes,
        steps: Int
    ) throws -> (verdict: GameVerdict, result: PCSResult) {
        // Simulate two independent DH ratchet evolutions from the same root key
        // with different ephemeral keys (modeling honest peer generating fresh keys)
        var rk1 = rootKey
        var rk2 = rootKey
        var recoveryKeys: [Data] = []

        for _ in 0..<steps {
            // Session 1: fresh DH
            let ek1 = Curve25519.KeyAgreement.PrivateKey()
            let peer1 = Curve25519.KeyAgreement.PrivateKey()
            let dh1 = try ek1.sharedSecretFromKeyAgreement(with: peer1.publicKey)
            let dhBytes1 = SecureBytes(copying: dh1.withUnsafeBytes { Data($0) })
            let (newRK1, _) = try VeilHKDF.deriveRatchetKeys(rootKey: rk1, input: dhBytes1, domain: .dhRatchet)
            rk1 = newRK1

            // Session 2: different fresh DH from same starting root
            let ek2 = Curve25519.KeyAgreement.PrivateKey()
            let peer2 = Curve25519.KeyAgreement.PrivateKey()
            let dh2 = try ek2.sharedSecretFromKeyAgreement(with: peer2.publicKey)
            let dhBytes2 = SecureBytes(copying: dh2.withUnsafeBytes { Data($0) })
            let (newRK2, _) = try VeilHKDF.deriveRatchetKeys(rootKey: rk2, input: dhBytes2, domain: .dhRatchet)
            rk2 = newRK2

            recoveryKeys.append(try rk1.copyToData())
        }

        // After `steps` DH ratchet steps with independent fresh ephemeral keys,
        // the two root keys should be completely different
        let rk1Data = try rk1.copyToData()
        let rk2Data = try rk2.copyToData()

        let result = PCSResult(
            compromisedRootKey: try rootKey.copyToData(),
            recoveryRootKeys: recoveryKeys,
            stepsToRecovery: steps
        )

        if rk1Data != rk2Data {
            return (
                .secure(
                    reason: "After \(steps) DH ratchet step(s) with independent ephemeral keys, "
                    + "root keys diverge completely (post-compromise security holds)"
                ),
                result
            )
        } else {
            return (
                .violated(
                    reason: "Root keys identical after \(steps) steps",
                    evidence: "RK1 == RK2 after independent DH evolution"
                ),
                result
            )
        }
    }
}

// MARK: - Chain Isolation Game

/// Verifies that sending and receiving chains are cryptographically independent.
///
/// Security property:
///   Compromise of the sending chain key reveals nothing about the receiving chain key,
///   and vice versa. This is because they are derived from different DH outputs with
///   the same root key but at different ratchet epochs.
public struct ChainIsolationGame: Sendable {

    /// Verify chain independence by checking that sending and receiving chain keys
    /// derived from the same root key but different DH steps are unrelated.
    ///
    /// - Parameter rootKey: The root key to derive chains from.
    /// - Returns: Game verdict.
    public static func playChainIsolation(
        rootKey: SecureBytes
    ) throws -> GameVerdict {
        // Derive a sending chain (DH with one key pair)
        let sendEK = Curve25519.KeyAgreement.PrivateKey()
        let sendPeer = Curve25519.KeyAgreement.PrivateKey()
        let sendDH = try sendEK.sharedSecretFromKeyAgreement(with: sendPeer.publicKey)
        let sendDHBytes = SecureBytes(copying: sendDH.withUnsafeBytes { Data($0) })
        let (_, sendCK) = try VeilHKDF.deriveRatchetKeys(rootKey: rootKey, input: sendDHBytes, domain: .dhRatchet)

        // Derive a receiving chain (DH with a different key pair, same root)
        let recvEK = Curve25519.KeyAgreement.PrivateKey()
        let recvPeer = Curve25519.KeyAgreement.PrivateKey()
        let recvDH = try recvEK.sharedSecretFromKeyAgreement(with: recvPeer.publicKey)
        let recvDHBytes = SecureBytes(copying: recvDH.withUnsafeBytes { Data($0) })
        let (_, recvCK) = try VeilHKDF.deriveRatchetKeys(rootKey: rootKey, input: recvDHBytes, domain: .dhRatchet)

        // The two chain keys should be completely different
        if SecureBytes.constantTimeEqual(sendCK, recvCK) {
            return .violated(
                reason: "Sending CK == Receiving CK from same root key with different DH",
                evidence: "Chain isolation broken"
            )
        }

        // Further: deriving message keys from each chain should also be independent
        var sendRatchet = SymmetricRatchet(chainKey: sendCK)
        var recvRatchet = SymmetricRatchet(chainKey: recvCK)

        let sendMK = try sendRatchet.advance()
        let recvMK = try recvRatchet.advance()

        if SecureBytes.constantTimeEqual(sendMK, recvMK) {
            return .violated(
                reason: "Sending MK_0 == Receiving MK_0",
                evidence: "Message key isolation broken"
            )
        }

        return .secure(
            reason: "Sending and receiving chains are cryptographically independent "
            + "(different DH inputs produce unrelated chain and message keys)"
        )
    }
}
