// VEIL — DomainSeparation.swift
// Ticket: VEIL-103 — HKDF-SHA-512 with Domain Separation
// Spec reference: Section 3.4
//
// Domain separation strings are defined as an enum with no raw initializer,
// making it impossible to accidentally pass an arbitrary string to HKDF.
// Every KDF call in Veil must use one of these constants.

import Foundation

/// Domain separation labels for all HKDF derivations in Veil.
///
/// Each label is a unique, human-readable UTF-8 string that prevents
/// cross-protocol key confusion. Adding a new derivation context requires
/// adding a case here — the compiler enforces exhaustiveness.
public enum VeilDomain: String, Sendable, CaseIterable {

    // MARK: - Key Agreement (PQXDH)

    /// Initial session key derivation from PQXDH handshake.
    case pqxdh = "Veil:PQXDH:v1"

    // MARK: - Ratchet Protocols

    /// Classical Diffie-Hellman ratchet step.
    case dhRatchet = "Veil:DHRatchet:v1"

    /// Sparse Post-Quantum Ratchet (SPQR) step.
    case spqr = "Veil:SPQR:v1"

    /// Symmetric chain key advancement.
    case chainKey = "Veil:ChainKey:v1"

    /// Per-message key derivation from chain key.
    case messageKey = "Veil:MessageKey:v1"

    // MARK: - Application Layer

    /// Sealed sender envelope encryption.
    case sealedSender = "Veil:SealedSender:v1"

    /// Payment notification encryption within ratchet session.
    case payment = "Veil:Payment:v1"

    // MARK: - Key Encryption

    /// Key-encrypting key for the PQ identity key at rest.
    case pqIdentityKEK = "Veil:KEK:PQIK:v1"

    // MARK: - MobileCoin Derivation

    /// MobileCoin spend key derivation from Veil identity key.
    case mobSpendKey = "Veil:MOB:spend:v1"

    /// MobileCoin view key derivation from Veil identity key.
    case mobViewKey = "Veil:MOB:view:v1"

    // MARK: - Network Transport (Epic 6)

    /// Traffic padding PRNG seeding for deterministic test padding.
    case trafficPadding = "Veil:TrafficPadding:v1"

    /// Configuration update signature domain.
    case configUpdate = "Veil:ConfigUpdate:v1"

    // MARK: - Access

    /// The raw UTF-8 bytes of this domain separation string.
    public var utf8Data: Data {
        Data(rawValue.utf8)
    }
}
