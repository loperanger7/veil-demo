// VEIL — ThreatModel.swift
// Ticket: VEIL-901 — Threat Model Documentation
// Spec reference: Section 7 (Threat Model & Security Analysis)
//
// Standalone security document for external auditors, implemented as
// compilable Swift code so it stays in sync with the codebase.
//
// This module defines the complete threat model from the Veil Protocol
// Specification, including adversary capabilities, attack surfaces,
// known limitations, and residual risk assessments. Each red team finding
// is mapped to its corresponding threat category.

import Foundation

// MARK: - Threat Model Namespace

/// The Veil threat model, structured for auditor consumption.
///
/// This namespace contains all threat modeling artifacts as Swift types,
/// ensuring they compile alongside the protocol implementation and
/// remain synchronized with code changes.
public enum ThreatModel: Sendable {

    // MARK: - Adversary Types

    /// Categories of adversaries considered in the threat model.
    ///
    /// From spec Section 7.1: "Veil considers six categories of adversary,
    /// ranging from passive observers to quantum-capable state actors."
    public enum Adversary: String, CaseIterable, Sendable {
        /// Observes encrypted traffic but cannot modify it.
        /// Capabilities: packet timing, sizes, endpoints, frequency analysis.
        /// Mitigations: traffic padding (ExponentialPaddingScheme), sealed sender.
        case passiveNetworkObserver

        /// Can intercept and modify traffic (MITM position).
        /// Capabilities: inject/drop/modify packets, DNS poisoning, TLS downgrade.
        /// Mitigations: TLS 1.3 with certificate pinning, domain fronting.
        case activeNetworkAttacker

        /// Controls the relay server infrastructure.
        /// Capabilities: read all metadata, drop/delay messages, log connections.
        /// Mitigations: sealed sender (server can't identify senders), E2E encryption.
        case compromisedRelay

        /// A peer in a conversation who turns adversarial.
        /// Capabilities: knows session keys, can forge messages within session.
        /// Mitigations: forward secrecy (compromised keys don't decrypt past messages).
        case maliciousContact

        /// Physical access to a user's device.
        /// Capabilities: read Keychain, extract keys from Secure Enclave via jailbreak.
        /// Mitigations: Secure Enclave for Ed25519, SecureBytes zeroization.
        case stolenDevice

        /// Adversary with access to a large-scale quantum computer.
        /// Capabilities: break X25519/ECDH (Shor's algorithm).
        /// Mitigations: ML-KEM-1024 in PQXDH, SPQR post-quantum ratchet.
        case quantumAdversary
    }

    // MARK: - Adversary Capabilities

    /// Detailed capability matrix per adversary type.
    public struct AdversaryCapability: Sendable {
        public let adversary: Adversary
        public let description: String
        public let canReadContent: Bool
        public let canReadMetadata: Bool
        public let canModifyTraffic: Bool
        public let canCorrelateMessages: Bool
        public let canBreakForwardSecrecy: Bool
        public let canForgeMessages: Bool
    }

    /// The full adversary capability matrix.
    public static let capabilities: [AdversaryCapability] = [
        AdversaryCapability(
            adversary: .passiveNetworkObserver,
            description: "ISP or network tap observing encrypted traffic",
            canReadContent: false,
            canReadMetadata: true,  // IP addresses, connection timing
            canModifyTraffic: false,
            canCorrelateMessages: true, // Timing correlation possible
            canBreakForwardSecrecy: false,
            canForgeMessages: false
        ),
        AdversaryCapability(
            adversary: .activeNetworkAttacker,
            description: "MITM capable of injecting/modifying packets",
            canReadContent: false, // TLS 1.3 prevents
            canReadMetadata: true,
            canModifyTraffic: true,
            canCorrelateMessages: true,
            canBreakForwardSecrecy: false,
            canForgeMessages: false // E2E encryption prevents
        ),
        AdversaryCapability(
            adversary: .compromisedRelay,
            description: "Adversary controlling the relay server",
            canReadContent: false, // E2E encryption
            canReadMetadata: true, // Registration IDs, device IDs, timing
            canModifyTraffic: true, // Can drop/delay messages
            canCorrelateMessages: true, // Can correlate sender IP with recipient
            canBreakForwardSecrecy: false,
            canForgeMessages: false
        ),
        AdversaryCapability(
            adversary: .maliciousContact,
            description: "A conversation participant who turns adversarial",
            canReadContent: true, // Within the session
            canReadMetadata: true,
            canModifyTraffic: false,
            canCorrelateMessages: false,
            canBreakForwardSecrecy: false, // Only future messages in current session
            canForgeMessages: true // Can create messages that look like they're from the session
        ),
        AdversaryCapability(
            adversary: .stolenDevice,
            description: "Physical access to an unlocked device",
            canReadContent: true, // If device is unlocked
            canReadMetadata: true,
            canModifyTraffic: false,
            canCorrelateMessages: false,
            canBreakForwardSecrecy: true, // Can extract current session keys
            canForgeMessages: true
        ),
        AdversaryCapability(
            adversary: .quantumAdversary,
            description: "Adversary with large-scale quantum computer",
            canReadContent: false, // ML-KEM-1024 protects
            canReadMetadata: true,
            canModifyTraffic: false,
            canCorrelateMessages: true,
            canBreakForwardSecrecy: false, // SPQR PQ ratchet
            canForgeMessages: false
        ),
    ]

    // MARK: - Attack Surfaces

    /// Components of the system exposed to attack.
    public enum AttackSurface: String, CaseIterable, Sendable {
        /// The PQXDH initial key agreement handshake.
        /// Threats: bundle tampering, prekey exhaustion, downgrade to fewer DH exchanges.
        /// Red team finding: HIGH — Optional DH4/KEM2 weakens key agreement.
        case pqxdhHandshake

        /// The Triple Ratchet ongoing encryption.
        /// Threats: message reordering, replay, ratchet desync.
        /// Red team finding: INFORMATIONAL — Correct implementation.
        case tripleRatchet

        /// The SPQR post-quantum ratchet.
        /// Threats: fragment manipulation, epoch confusion.
        /// Red team finding: MEDIUM — Fragment ordering not enforced.
        case spqrRatchet

        /// Sealed sender envelope handling.
        /// Threats: sender deanonymization, envelope format exploitation.
        /// Red team finding: INFORMATIONAL — Correct design.
        case sealedSender

        /// The relay server API.
        /// Threats: auth bypass, rate limiting, metadata logging.
        /// Red team findings: CRITICAL — Token auth bypass, no rate limiting.
        case relayAPI

        /// Payment receipt messages.
        /// Threats: forgery, replay, amount manipulation.
        /// Red team findings: CRITICAL — Weak shared secret, no receipt auth, no replay.
        case paymentReceipts

        /// Ciphertext length / traffic pattern analysis.
        /// Threats: message type inference, user activity profiling.
        /// Red team finding: CRITICAL — 256-byte block padding leaks categories.
        case trafficAnalysis

        /// On-device key storage and data at rest.
        /// Threats: key extraction, plaintext message caching.
        /// Red team findings: HIGH — Unencrypted payment state, no key backup.
        case deviceStorage
    }

    // MARK: - Red Team Finding Mapping

    /// Maps each red team finding to its threat model components.
    public struct FindingMapping: Sendable {
        public let findingId: String
        public let severity: Severity
        public let title: String
        public let attackSurface: AttackSurface
        public let adversaryTypes: [Adversary]
        public let remediation: String
        public let status: RemediationStatus
    }

    public enum Severity: String, Sendable, CaseIterable {
        case critical = "CRITICAL"
        case high = "HIGH"
        case medium = "MEDIUM"
        case low = "LOW"
        case informational = "INFORMATIONAL"
    }

    public enum RemediationStatus: String, Sendable {
        case fixed = "FIXED"
        case inProgress = "IN_PROGRESS"
        case planned = "PLANNED"
        case acceptedRisk = "ACCEPTED_RISK"
    }

    /// All red team findings with their remediation status.
    public static let redTeamFindings: [FindingMapping] = [
        // CRITICAL
        FindingMapping(
            findingId: "RT-001", severity: .critical,
            title: "Anonymous Token Verification Bypass",
            attackSurface: .relayAPI,
            adversaryTypes: [.activeNetworkAttacker, .compromisedRelay],
            remediation: "DLEQProofVerifier.swift — Schnorr-style DLEQ proof verification",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-002", severity: .critical,
            title: "No Per-Sender Rate Limiting",
            attackSurface: .relayAPI,
            adversaryTypes: [.activeNetworkAttacker],
            remediation: "RateLimiter actor — Per-IP and per-registration rate limiting",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-003", severity: .critical,
            title: "256-Byte Block Padding Leaks Message Categories",
            attackSurface: .trafficAnalysis,
            adversaryTypes: [.passiveNetworkObserver, .activeNetworkAttacker],
            remediation: "ExponentialPaddingScheme — 9 power-of-2 buckets with HMAC",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-004", severity: .critical,
            title: "Weak Shared Secret Generation",
            attackSurface: .paymentReceipts,
            adversaryTypes: [.passiveNetworkObserver, .compromisedRelay],
            remediation: "PaymentKeyAgreement — Real X25519 ECDH with HKDF expansion",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-005", severity: .critical,
            title: "No Authentication on Payment Receipts",
            attackSurface: .paymentReceipts,
            adversaryTypes: [.maliciousContact, .compromisedRelay],
            remediation: "ReceiptAuthenticator — Ed25519 signature over receipt fields",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-006", severity: .critical,
            title: "Missing Replay Protection on Receipts",
            attackSurface: .paymentReceipts,
            adversaryTypes: [.maliciousContact],
            remediation: "ReceiptNonceTracker — Per-receipt nonce with bounded dedup",
            status: .fixed
        ),

        // HIGH
        FindingMapping(
            findingId: "RT-007", severity: .high,
            title: "Optional DH4/KEM2 Weakens Key Agreement",
            attackSurface: .pqxdhHandshake,
            adversaryTypes: [.compromisedRelay],
            remediation: "PQXDH.swift — guard !bundle.oneTimePrekeys.isEmpty",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-008", severity: .high,
            title: "Fronting Fallback Reveals Relay",
            attackSurface: .trafficAnalysis,
            adversaryTypes: [.activeNetworkAttacker],
            remediation: "FrontingFallbackPolicy — Configurable fail-closed policy",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-009", severity: .high,
            title: "Probe Results Can Be Poisoned",
            attackSurface: .trafficAnalysis,
            adversaryTypes: [.activeNetworkAttacker],
            remediation: "Signed probe responses with Ed25519 verification",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-010", severity: .high,
            title: "Messages Stored in Plaintext on Relay",
            attackSurface: .relayAPI,
            adversaryTypes: [.compromisedRelay],
            remediation: "Server-side encryption at rest with master key",
            status: .planned
        ),
        FindingMapping(
            findingId: "RT-011", severity: .high,
            title: "Insufficient Amount Validation",
            attackSurface: .paymentReceipts,
            adversaryTypes: [.maliciousContact],
            remediation: "PaymentAmountValidator — Dust threshold + overflow protection",
            status: .fixed
        ),
        FindingMapping(
            findingId: "RT-012", severity: .high,
            title: "Payment Confirmation Race Condition",
            attackSurface: .paymentReceipts,
            adversaryTypes: [.stolenDevice],
            remediation: "UI: Disable Cancel during biometric auth",
            status: .planned
        ),
        FindingMapping(
            findingId: "RT-013", severity: .high,
            title: "Unencrypted Payment State in Keychain",
            attackSurface: .deviceStorage,
            adversaryTypes: [.stolenDevice],
            remediation: "Encrypt PaymentContext with device-specific key",
            status: .planned
        ),
        FindingMapping(
            findingId: "RT-014", severity: .high,
            title: "No Key Backup/Recovery",
            attackSurface: .deviceStorage,
            adversaryTypes: [.stolenDevice],
            remediation: "Documented as intentional design boundary",
            status: .acceptedRisk
        ),
    ]

    // MARK: - Known Limitations

    /// Documented limitations from spec Section 7.2.
    ///
    /// These are threats that Veil explicitly does NOT attempt to mitigate,
    /// either because they are out of scope or require tradeoffs inconsistent
    /// with the design philosophy.
    public enum KnownLimitation: String, CaseIterable, Sendable {
        /// The relay server can observe connection metadata (IP, timing, registration ID).
        /// Sealed sender prevents content inspection but not metadata collection.
        case metadataAtRelay

        /// A compromised device exposes all current session keys and message history.
        /// Forward secrecy protects past messages but not current state.
        case deviceCompromise

        /// Veil does not provide cryptographic deniability.
        /// Recipients can prove to third parties that a message was sent.
        case noDeniability

        /// Veil does not protect against a global passive adversary
        /// who can observe all network traffic simultaneously.
        case globalPassiveAdversary

        /// Side-channel attacks on the device (power analysis, electromagnetic
        /// emanation) are not mitigated.
        case physicalSideChannels

        /// Key recovery is impossible by design. Lost device = lost identity.
        case noKeyRecovery
    }

    // MARK: - Residual Risk Assessment

    /// Risk assessment per attack surface after all mitigations.
    public struct ResidualRisk: Sendable {
        public let surface: AttackSurface
        public let riskLevel: RiskLevel
        public let description: String
        public let mitigations: [String]
    }

    public enum RiskLevel: String, Sendable, Comparable {
        case low = "LOW"
        case medium = "MEDIUM"
        case high = "HIGH"
        case critical = "CRITICAL"

        public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
            let order: [RiskLevel] = [.low, .medium, .high, .critical]
            return (order.firstIndex(of: lhs) ?? 0) < (order.firstIndex(of: rhs) ?? 0)
        }
    }

    /// Residual risk assessment after Epic 9 hardening.
    public static let residualRisks: [ResidualRisk] = [
        ResidualRisk(
            surface: .pqxdhHandshake,
            riskLevel: .low,
            description: "PQXDH now requires one-time prekeys. Fixed-length encoding prevents boundary confusion.",
            mitigations: ["One-time prekey requirement", "Fixed-length DH4/KEM2 encoding"]
        ),
        ResidualRisk(
            surface: .tripleRatchet,
            riskLevel: .low,
            description: "No vulnerabilities found. Bounded skipped keys, correct DH ratchet.",
            mitigations: ["2000-key skip limit", "Constant-time HMAC comparison"]
        ),
        ResidualRisk(
            surface: .spqrRatchet,
            riskLevel: .low,
            description: "Fragment ordering is bounded by epoch. Duplicate assembly prevented.",
            mitigations: ["Epoch-bounded fragments", "Duplicate detection"]
        ),
        ResidualRisk(
            surface: .sealedSender,
            riskLevel: .low,
            description: "Correct design. Server cannot identify senders.",
            mitigations: ["E2E encrypted sender identity"]
        ),
        ResidualRisk(
            surface: .relayAPI,
            riskLevel: .medium,
            description: "Token auth fixed. Rate limiting added. Plaintext storage on server remains planned.",
            mitigations: ["DLEQ proof verification", "Rate limiting", "Server-side encryption (planned)"]
        ),
        ResidualRisk(
            surface: .paymentReceipts,
            riskLevel: .low,
            description: "All critical receipt vulnerabilities fixed: ECDH shared secret, Ed25519 signatures, replay nonces.",
            mitigations: ["X25519 ECDH", "Ed25519 receipt signatures", "Nonce-based replay protection", "Amount validation"]
        ),
        ResidualRisk(
            surface: .trafficAnalysis,
            riskLevel: .medium,
            description: "Exponential padding reduces distinct sizes to 9. Timing correlation remains possible.",
            mitigations: ["Exponential bucket padding", "HMAC-authenticated envelopes", "Fail-closed fronting"]
        ),
        ResidualRisk(
            surface: .deviceStorage,
            riskLevel: .medium,
            description: "Payment state encryption planned. Key backup intentionally omitted.",
            mitigations: ["Secure Enclave for Ed25519", "SecureBytes zeroization", "Payment state encryption (planned)"]
        ),
    ]

    // MARK: - Summary

    /// Total finding counts by severity.
    public static var findingSummary: [Severity: Int] {
        var counts: [Severity: Int] = [:]
        for finding in redTeamFindings {
            counts[finding.severity, default: 0] += 1
        }
        return counts
    }

    /// Findings that are still unresolved (not fixed).
    public static var unresolvedFindings: [FindingMapping] {
        redTeamFindings.filter { $0.status != .fixed }
    }
}
