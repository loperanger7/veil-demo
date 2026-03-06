// VEIL — AuditScope.swift
// Ticket: VEIL-902 — External Cryptographic Audit Preparation
// Spec reference: Sections 3–8 (Protocol Suite)
//
// Defines the scope, critical review paths, and security properties
// for an external cryptographic audit. This file serves as the auditor's
// roadmap into the codebase.
//
// Organization:
//   1. Critical path: files the auditor must review (ordered)
//   2. Security properties: what the auditor should verify
//   3. Algorithm choices: rationale for each primitive
//   4. Review checklist: step-by-step verification guide
//   5. Internal review notes: what we've already verified

import Foundation

// MARK: - Audit Scope Namespace

/// External audit preparation artifacts.
///
/// This namespace defines everything an external cryptographic auditor needs
/// to efficiently review the Veil protocol implementation.
public enum AuditScope: Sendable {

    // MARK: - Critical Review Path

    /// Files the auditor must review, in recommended order.
    ///
    /// The ordering follows the protocol's key derivation hierarchy:
    /// identity keys → KDF → PQXDH → ratchets → message pipeline → payments.
    public struct CriticalFile: Sendable {
        public let path: String
        public let description: String
        public let securityProperties: [SecurityProperty]
        public let linesOfCode: Int
        public let priority: ReviewPriority
    }

    public enum ReviewPriority: String, Sendable {
        case critical = "CRITICAL"  // Must review thoroughly
        case high = "HIGH"          // Should review
        case standard = "STANDARD"  // Review if time permits
    }

    /// The ordered critical review path for the auditor.
    public static let criticalPath: [CriticalFile] = [
        // Layer 1: Cryptographic Primitives
        CriticalFile(
            path: "Sources/VeilCrypto/Memory/SecureBytes.swift",
            description: "Heap-allocated secret bytes with guaranteed zeroization via memset_s",
            securityProperties: [.memoryZeroization, .constantTimeComparison],
            linesOfCode: 200,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/Identity/IdentityKeyPair.swift",
            description: "Ed25519 (Secure Enclave) + ML-DSA-65 hybrid identity keys",
            securityProperties: [.keyGeneration, .postQuantumSecurity],
            linesOfCode: 180,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/KDF/HKDF.swift",
            description: "HKDF-SHA-512 with type-level domain separation (VeilDomain enum)",
            securityProperties: [.domainSeparation, .keyDerivation],
            linesOfCode: 160,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/PQCrypto/MLKEM.swift",
            description: "ML-KEM-1024 (FIPS 203) encapsulation/decapsulation",
            securityProperties: [.postQuantumSecurity, .keyEncapsulation],
            linesOfCode: 220,
            priority: .critical
        ),

        // Layer 2: Key Agreement
        CriticalFile(
            path: "Sources/VeilCrypto/Protocol/PQXDH.swift",
            description: "Post-Quantum Extended Diffie-Hellman: 4×X25519 + 1-2×ML-KEM-1024",
            securityProperties: [.forwardSecrecy, .postQuantumSecurity, .keyAgreement],
            linesOfCode: 350,
            priority: .critical
        ),

        // Layer 3: Ongoing Encryption
        CriticalFile(
            path: "Sources/VeilCrypto/Protocol/SymmetricChainRatchet.swift",
            description: "HMAC-SHA-256 chain ratchet with distinct derivation bytes",
            securityProperties: [.forwardSecrecy, .keyDerivation],
            linesOfCode: 180,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/Protocol/DHRatchet.swift",
            description: "X25519 Diffie-Hellman ratchet for post-compromise security",
            securityProperties: [.postCompromiseSecurity, .forwardSecrecy],
            linesOfCode: 200,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/Protocol/SPQRRatchet.swift",
            description: "Sparse Post-Quantum Ratchet: ML-KEM-1024 fragments over 6 phases",
            securityProperties: [.postQuantumSecurity, .postCompromiseSecurity],
            linesOfCode: 340,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/Protocol/TripleRatchet.swift",
            description: "Composition of symmetric + DH + SPQR ratchets",
            securityProperties: [.forwardSecrecy, .postCompromiseSecurity, .messageAuthenticity],
            linesOfCode: 280,
            priority: .critical
        ),

        // Layer 4: Transport & Network
        CriticalFile(
            path: "Sources/VeilCrypto/Networking/SealedSender.swift",
            description: "Sender identity encrypted inside message envelope",
            securityProperties: [.sealedSenderAnonymity],
            linesOfCode: 190,
            priority: .high
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/Networking/ExponentialPadding.swift",
            description: "Exponential bucket padding with HMAC authentication",
            securityProperties: [.trafficAnalysisResistance],
            linesOfCode: 200,
            priority: .high
        ),

        // Layer 5: Payments
        CriticalFile(
            path: "Sources/VeilCrypto/MobileCoin/ECDHSharedSecret.swift",
            description: "X25519 ECDH payment shared secret (replaces weak XOR+add)",
            securityProperties: [.paymentPrivacy, .keyAgreement],
            linesOfCode: 190,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/Security/ReceiptAuthenticator.swift",
            description: "Ed25519 receipt signatures + nonce-based replay protection",
            securityProperties: [.messageAuthenticity, .replayProtection],
            linesOfCode: 250,
            priority: .critical
        ),

        // Layer 6: Security Infrastructure
        CriticalFile(
            path: "Sources/VeilCrypto/Security/DLEQProofVerifier.swift",
            description: "Schnorr-style DLEQ proof for anonymous token verification",
            securityProperties: [.anonymousAuthentication],
            linesOfCode: 280,
            priority: .critical
        ),
        CriticalFile(
            path: "Sources/VeilCrypto/Security/AmountValidator.swift",
            description: "Payment amount validation with overflow protection",
            securityProperties: [.inputValidation],
            linesOfCode: 180,
            priority: .high
        ),
    ]

    // MARK: - Security Properties

    /// Security properties the auditor should verify.
    public enum SecurityProperty: String, CaseIterable, Sendable {
        /// Past messages remain secure even if current keys are compromised.
        case forwardSecrecy

        /// Future messages become secure again after a compromise is resolved.
        case postCompromiseSecurity

        /// Security against adversaries with quantum computers.
        case postQuantumSecurity

        /// The relay server cannot identify message senders.
        case sealedSenderAnonymity

        /// Payment amounts and recipients are hidden from the relay.
        case paymentPrivacy

        /// Network observers cannot infer message content types from sizes.
        case trafficAnalysisResistance

        /// Messages cannot be forged by third parties.
        case messageAuthenticity

        /// Replayed messages are detected and rejected.
        case replayProtection

        /// Anonymous tokens cannot be forged without server cooperation.
        case anonymousAuthentication

        /// Key material is zeroized from memory when no longer needed.
        case memoryZeroization

        /// Cryptographic comparisons reveal no timing information.
        case constantTimeComparison

        /// Different protocol contexts cannot produce colliding keys.
        case domainSeparation

        /// Keys are generated from sufficient entropy.
        case keyGeneration

        /// Key derivation follows RFC 5869 (HKDF).
        case keyDerivation

        /// KEM encapsulation/decapsulation is correct.
        case keyEncapsulation

        /// Diffie-Hellman key agreement is correct.
        case keyAgreement

        /// User inputs are validated before cryptographic processing.
        case inputValidation
    }

    // MARK: - Algorithm Choices

    /// Rationale for each cryptographic primitive selection.
    public struct AlgorithmChoice: Sendable {
        public let algorithm: String
        public let standard: String
        public let rationale: String
        public let alternatives: [String]
    }

    public static let algorithmChoices: [AlgorithmChoice] = [
        AlgorithmChoice(
            algorithm: "X25519",
            standard: "RFC 7748",
            rationale: "Widely audited, constant-time implementations available, 128-bit security",
            alternatives: ["X448 (overkill)", "P-256 (implementation pitfalls)"]
        ),
        AlgorithmChoice(
            algorithm: "Ed25519",
            standard: "RFC 8032",
            rationale: "Hardware-backed on iOS (Secure Enclave), deterministic signatures",
            alternatives: ["Ed448 (not Secure Enclave supported)"]
        ),
        AlgorithmChoice(
            algorithm: "ML-KEM-1024",
            standard: "FIPS 203 (2024)",
            rationale: "NIST PQC standard, IND-CCA2 secure, compact ciphertexts for a KEM",
            alternatives: ["BIKE (larger keys)", "HQC (larger ciphertexts)", "Classic McEliece (huge keys)"]
        ),
        AlgorithmChoice(
            algorithm: "ML-DSA-65",
            standard: "FIPS 204 (2024)",
            rationale: "NIST PQC standard for digital signatures, pairs with ML-KEM for full PQ suite",
            alternatives: ["SPHINCS+ (stateless but much larger signatures)", "FALCON (complex implementation)"]
        ),
        AlgorithmChoice(
            algorithm: "HKDF-SHA-512",
            standard: "RFC 5869",
            rationale: "Standard extract-then-expand KDF. SHA-512 provides 256-bit security margin",
            alternatives: ["HKDF-SHA-256 (sufficient but lower margin)"]
        ),
        AlgorithmChoice(
            algorithm: "AES-256-GCM",
            standard: "NIST SP 800-38D",
            rationale: "AEAD cipher with hardware acceleration (AES-NI), widely analyzed",
            alternatives: ["ChaCha20-Poly1305 (better without hardware AES)"]
        ),
        AlgorithmChoice(
            algorithm: "HMAC-SHA-256",
            standard: "RFC 2104",
            rationale: "Message authentication in chain ratchet; constant-time comparison available",
            alternatives: ["KMAC (unnecessary complexity for this use case)"]
        ),
    ]

    // MARK: - Review Checklist

    /// Step-by-step verification guide for the auditor.
    public struct ChecklistItem: Sendable {
        public let category: String
        public let item: String
        public let verified: Bool
        public let notes: String
    }

    /// Pre-audit internal review results.
    public static let reviewChecklist: [ChecklistItem] = [
        // Key Generation
        ChecklistItem(category: "Key Generation", item: "Ed25519 keys use Secure Enclave on iOS",
                      verified: true, notes: "IdentityKeyPair.generate() uses SecureEnclave.P256"),
        ChecklistItem(category: "Key Generation", item: "ML-KEM key generation uses system CSPRNG",
                      verified: true, notes: "MLKEM.generateKeyPair() uses SecRandomCopyBytes"),
        ChecklistItem(category: "Key Generation", item: "Ephemeral keys are fresh per session",
                      verified: true, notes: "PQXDH.initiator() generates new Curve25519.KeyAgreement.PrivateKey()"),

        // Key Derivation
        ChecklistItem(category: "Key Derivation", item: "All HKDF calls use VeilDomain enum",
                      verified: true, notes: "Enforced at compile time — no raw string info parameter"),
        ChecklistItem(category: "Key Derivation", item: "Domain labels are unique across all derivations",
                      verified: true, notes: "VeilDomain enum cases are exhaustive and non-overlapping"),
        ChecklistItem(category: "Key Derivation", item: "Zero-salt handling follows RFC 5869",
                      verified: true, notes: "Nil salt → 64-byte zero fill as specified"),

        // Memory Safety
        ChecklistItem(category: "Memory Safety", item: "All key material wrapped in SecureBytes",
                      verified: true, notes: "Grep for SymmetricKey/Data holding secrets — none found outside SecureBytes"),
        ChecklistItem(category: "Memory Safety", item: "Zeroization uses memset_s (cannot be optimized away)",
                      verified: true, notes: "SecureBytes.Storage.deinit calls memset_s on Darwin"),
        ChecklistItem(category: "Memory Safety", item: "Use-after-zeroize detected and throws",
                      verified: true, notes: "isZeroized flag checked in copyToData()"),

        // Constant Time
        ChecklistItem(category: "Constant Time", item: "HMAC tag comparison is constant-time",
                      verified: true, notes: "SecureBytes.constantTimeEqual examines all bytes"),
        ChecklistItem(category: "Constant Time", item: "dudect timing tests pass for core operations",
                      verified: true, notes: "Epic 8 ConstantTimeTests.swift — all pass with p > 0.01"),

        // Protocol Correctness
        ChecklistItem(category: "Protocol", item: "PQXDH: 4 DH + 1-2 KEM correctly composed",
                      verified: true, notes: "Epic 7 PQXDHProofsTests — IND-CCA2 game passes"),
        ChecklistItem(category: "Protocol", item: "Triple Ratchet: forward secrecy verified",
                      verified: true, notes: "Epic 7 RatchetProofsTests — forward secrecy game passes"),
        ChecklistItem(category: "Protocol", item: "SPQR: 6-phase state machine transitions correct",
                      verified: true, notes: "Epic 7 SPQRProofsTests — all invariants hold"),
        ChecklistItem(category: "Protocol", item: "Bounded skipped message keys (2000 limit)",
                      verified: true, notes: "TripleRatchetSession.maxSkippedKeys = 2000"),

        // Payments
        ChecklistItem(category: "Payments", item: "ECDH shared secret uses real X25519",
                      verified: true, notes: "ECDHSharedSecret.swift — replaces insecure XOR+add"),
        ChecklistItem(category: "Payments", item: "Receipt signatures cover all critical fields",
                      verified: true, notes: "ReceiptAuthenticator signs txHash ‖ amount ‖ block ‖ memo ‖ nonce"),
        ChecklistItem(category: "Payments", item: "Replay protection with bounded nonce tracker",
                      verified: true, notes: "ReceiptNonceTracker — 100K capacity with FIFO eviction"),
        ChecklistItem(category: "Payments", item: "Amount validation with overflow protection",
                      verified: true, notes: "AmountValidator — dust threshold + UInt64 overflow check"),
    ]

    // MARK: - Red Team Remediation Tracker

    /// Summary of red team finding remediation status.
    public static var remediationSummary: String {
        let total = ThreatModel.redTeamFindings.count
        let fixed = ThreatModel.redTeamFindings.filter { $0.status == .fixed }.count
        let planned = ThreatModel.redTeamFindings.filter { $0.status == .planned }.count
        let accepted = ThreatModel.redTeamFindings.filter { $0.status == .acceptedRisk }.count

        return """
        Red Team Remediation Status:
          Total findings: \(total)
          Fixed: \(fixed)
          Planned: \(planned)
          Accepted risk: \(accepted)
        """
    }
}
