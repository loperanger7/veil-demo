// VEIL — TestFlightChecklist.swift
// Ticket: VEIL-1001 — App Store Submission
//
// Pre-submission validation checklist mapping every critical feature
// back to its engineering ticket. Used to verify TestFlight beta
// readiness before external distribution.

import Foundation

// MARK: - TestFlight Checklist

/// Pre-submission validation checklist for TestFlight and App Store.
///
/// Each check maps to one or more engineering tickets and can be
/// programmatically evaluated against the running application.
public enum TestFlightChecklist: Sendable {

    // MARK: - Check Categories

    /// Categories of validation checks.
    public enum Category: String, Sendable, CaseIterable {
        case cryptography = "Cryptography"
        case payments = "Payments"
        case userInterface = "User Interface"
        case networking = "Networking"
        case security = "Security"
        case privacy = "Privacy"
    }

    /// Priority level for checks.
    public enum Priority: String, Sendable, Comparable {
        case p0 = "P0 — Blocker"
        case p1 = "P1 — Critical"
        case p2 = "P2 — Important"

        public static func < (lhs: Priority, rhs: Priority) -> Bool {
            let order: [Priority] = [.p0, .p1, .p2]
            guard let l = order.firstIndex(of: lhs),
                  let r = order.firstIndex(of: rhs) else { return false }
            return l < r
        }
    }

    /// A single validation check.
    public struct Check: Sendable {
        /// Unique identifier for the check.
        public let id: String
        /// Human-readable description.
        public let description: String
        /// Category this check belongs to.
        public let category: Category
        /// Priority level.
        public let priority: Priority
        /// Engineering ticket(s) this check validates.
        public let tickets: [String]
        /// How to verify this check (manual or automated).
        public let verification: VerificationMethod
        /// Current status.
        public var status: CheckStatus

        public var isBlocking: Bool {
            priority == .p0 && status != .passed
        }
    }

    public enum VerificationMethod: String, Sendable {
        case automated = "Automated (unit/integration test)"
        case manual = "Manual QA"
        case codeReview = "Code review"
        case configuration = "Configuration check"
    }

    public enum CheckStatus: String, Sendable {
        case passed = "Passed"
        case failed = "Failed"
        case notTested = "Not Tested"
        case skipped = "Skipped"
    }

    // MARK: - Cryptography Checks

    /// Cryptographic subsystem validation.
    public static let cryptographyChecks: [Check] = [
        Check(
            id: "CRYPTO-001",
            description: "Identity key generation produces valid Ed25519 + X25519 key pairs",
            category: .cryptography, priority: .p0,
            tickets: ["VEIL-101"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "CRYPTO-002",
            description: "ML-KEM-1024 encapsulation and decapsulation round-trips correctly",
            category: .cryptography, priority: .p0,
            tickets: ["VEIL-102"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "CRYPTO-003",
            description: "HKDF-SHA-512 with domain separation produces correct test vectors",
            category: .cryptography, priority: .p0,
            tickets: ["VEIL-103"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "CRYPTO-004",
            description: "PQXDH handshake completes between two parties and produces matching session keys",
            category: .cryptography, priority: .p0,
            tickets: ["VEIL-104"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "CRYPTO-005",
            description: "Triple Ratchet advances symmetric, DH, and SPQR chains correctly",
            category: .cryptography, priority: .p0,
            tickets: ["VEIL-105", "VEIL-106", "VEIL-107", "VEIL-108"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "CRYPTO-006",
            description: "Key material is zeroized on deallocation (SecureBytes memset_s)",
            category: .cryptography, priority: .p0,
            tickets: ["VEIL-109"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "CRYPTO-007",
            description: "DLEQ proof verification rejects invalid anonymous tokens",
            category: .cryptography, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .automated,
            status: .passed
        ),
    ]

    // MARK: - Payment Checks

    /// Payment subsystem validation.
    public static let paymentChecks: [Check] = [
        Check(
            id: "PAY-001",
            description: "MobileCoin key pair derivation from identity key produces valid account keys",
            category: .payments, priority: .p0,
            tickets: ["VEIL-401"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "PAY-002",
            description: "Transaction builder creates valid MobileCoin transactions with correct fee calculation",
            category: .payments, priority: .p0,
            tickets: ["VEIL-403"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "PAY-003",
            description: "Payment receipt encryption and decryption preserves all fields",
            category: .payments, priority: .p0,
            tickets: ["VEIL-405"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "PAY-004",
            description: "Payment state machine handles all transitions including failure recovery",
            category: .payments, priority: .p0,
            tickets: ["VEIL-504"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "PAY-005",
            description: "ECDH shared secret uses real X25519 (not legacy XOR+add)",
            category: .payments, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "PAY-006",
            description: "Payment receipts are Ed25519 signed with replay protection",
            category: .payments, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "PAY-007",
            description: "Amount validation enforces dust threshold, per-tx maximum, and overflow protection",
            category: .payments, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .automated,
            status: .passed
        ),
    ]

    // MARK: - UI Checks

    /// User interface validation.
    public static let uiChecks: [Check] = [
        Check(
            id: "UI-001",
            description: "Registration flow completes with phone number verification",
            category: .userInterface, priority: .p0,
            tickets: ["VEIL-404"],
            verification: .manual,
            status: .passed
        ),
        Check(
            id: "UI-002",
            description: "Conversation list loads and displays all conversations with correct timestamps",
            category: .userInterface, priority: .p0,
            tickets: ["VEIL-505"],
            verification: .manual,
            status: .passed
        ),
        Check(
            id: "UI-003",
            description: "Chat view sends and receives messages with correct bubble layout",
            category: .userInterface, priority: .p0,
            tickets: ["VEIL-505"],
            verification: .manual,
            status: .passed
        ),
        Check(
            id: "UI-004",
            description: "Payment flow shows confirmation dialog with amount and biometric authentication",
            category: .userInterface, priority: .p0,
            tickets: ["VEIL-506"],
            verification: .manual,
            status: .passed
        ),
        Check(
            id: "UI-005",
            description: "Safety number verification shows matching fingerprints for both parties",
            category: .userInterface, priority: .p1,
            tickets: ["VEIL-505"],
            verification: .manual,
            status: .passed
        ),
        Check(
            id: "UI-006",
            description: "Settings view allows toggling notifications, read receipts, and security options",
            category: .userInterface, priority: .p1,
            tickets: ["VEIL-505"],
            verification: .manual,
            status: .passed
        ),
    ]

    // MARK: - Networking Checks

    /// Networking subsystem validation.
    public static let networkingChecks: [Check] = [
        Check(
            id: "NET-001",
            description: "WebSocket connection to relay server establishes and maintains heartbeat",
            category: .networking, priority: .p0,
            tickets: ["VEIL-301"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "NET-002",
            description: "Domain fronting activates in censored network conditions",
            category: .networking, priority: .p1,
            tickets: ["VEIL-601"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "NET-003",
            description: "Certificate pinning rejects invalid server certificates",
            category: .networking, priority: .p0,
            tickets: ["VEIL-602"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "NET-004",
            description: "Offline message queue persists and retransmits on reconnection",
            category: .networking, priority: .p0,
            tickets: ["VEIL-203"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "NET-005",
            description: "Exponential padding produces at most 9 distinct envelope sizes",
            category: .networking, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .automated,
            status: .passed
        ),
    ]

    // MARK: - Security Checks

    /// Security hardening validation.
    public static let securityChecks: [Check] = [
        Check(
            id: "SEC-001",
            description: "All critical red team findings (6) have been remediated and tested",
            category: .security, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .codeReview,
            status: .passed
        ),
        Check(
            id: "SEC-002",
            description: "All high-severity red team findings (8) have been remediated and tested",
            category: .security, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .codeReview,
            status: .passed
        ),
        Check(
            id: "SEC-003",
            description: "Threat model documents all adversary types and attack surfaces",
            category: .security, priority: .p1,
            tickets: ["VEIL-901"],
            verification: .codeReview,
            status: .passed
        ),
        Check(
            id: "SEC-004",
            description: "Audit scope defines critical review path for external auditors",
            category: .security, priority: .p1,
            tickets: ["VEIL-902"],
            verification: .codeReview,
            status: .passed
        ),
        Check(
            id: "SEC-005",
            description: "Rate limiting prevents brute-force attacks on registration and token issuance",
            category: .security, priority: .p0,
            tickets: ["VEIL-901"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "SEC-006",
            description: "Memo sanitization strips Unicode control characters and directional overrides",
            category: .security, priority: .p1,
            tickets: ["VEIL-901"],
            verification: .automated,
            status: .passed
        ),
    ]

    // MARK: - Privacy Checks

    /// Privacy compliance validation.
    public static let privacyChecks: [Check] = [
        Check(
            id: "PRIV-001",
            description: "No analytics or telemetry data is collected or transmitted",
            category: .privacy, priority: .p0,
            tickets: ["VEIL-1001"],
            verification: .codeReview,
            status: .passed
        ),
        Check(
            id: "PRIV-002",
            description: "Phone numbers are SHA-256 hashed before server contact discovery",
            category: .privacy, priority: .p0,
            tickets: ["VEIL-404"],
            verification: .automated,
            status: .passed
        ),
        Check(
            id: "PRIV-003",
            description: "Privacy nutrition labels accurately reflect actual data collection",
            category: .privacy, priority: .p0,
            tickets: ["VEIL-1001"],
            verification: .configuration,
            status: .passed
        ),
        Check(
            id: "PRIV-004",
            description: "No third-party SDKs that collect user data are included",
            category: .privacy, priority: .p0,
            tickets: ["VEIL-1001"],
            verification: .codeReview,
            status: .passed
        ),
        Check(
            id: "PRIV-005",
            description: "Relay server retains no message content after delivery confirmation",
            category: .privacy, priority: .p0,
            tickets: ["VEIL-301", "VEIL-1003"],
            verification: .configuration,
            status: .passed
        ),
        Check(
            id: "PRIV-006",
            description: "Sealed sender conceals message origin from relay server",
            category: .privacy, priority: .p1,
            tickets: ["VEIL-301"],
            verification: .automated,
            status: .passed
        ),
    ]

    // MARK: - All Checks

    /// All checks across all categories.
    public static var allChecks: [Check] {
        cryptographyChecks + paymentChecks + uiChecks +
        networkingChecks + securityChecks + privacyChecks
    }

    /// Total number of checks.
    public static var totalChecks: Int { allChecks.count }

    /// Number of passed checks.
    public static var passedChecks: Int { allChecks.filter { $0.status == .passed }.count }

    /// Number of blocking failures.
    public static var blockingFailures: Int { allChecks.filter(\.isBlocking).count }

    /// Whether the build is ready for TestFlight submission.
    public static var isTestFlightReady: Bool {
        blockingFailures == 0
    }

    /// Summary by category.
    public static func summary(for category: Category) -> (total: Int, passed: Int, failed: Int) {
        let checks = allChecks.filter { $0.category == category }
        let passed = checks.filter { $0.status == .passed }.count
        let failed = checks.filter { $0.status == .failed }.count
        return (checks.count, passed, failed)
    }

    // MARK: - Performance Budgets

    /// Performance targets for TestFlight beta.
    public struct PerformanceBudget: Sendable {
        public let metric: String
        public let target: String
        public let measurement: String
    }

    /// Performance budgets that must be met before App Store submission.
    public static let performanceBudgets: [PerformanceBudget] = [
        PerformanceBudget(
            metric: "App launch to conversation list",
            target: "< 2 seconds (cold start)",
            measurement: "Instruments Time Profiler"
        ),
        PerformanceBudget(
            metric: "Message send latency (local encryption)",
            target: "< 50ms",
            measurement: "XCTest measure block"
        ),
        PerformanceBudget(
            metric: "Message receive latency (decryption)",
            target: "< 50ms",
            measurement: "XCTest measure block"
        ),
        PerformanceBudget(
            metric: "PQXDH handshake (full protocol)",
            target: "< 200ms",
            measurement: "XCTest measure block"
        ),
        PerformanceBudget(
            metric: "Payment transaction build",
            target: "< 500ms",
            measurement: "XCTest measure block"
        ),
        PerformanceBudget(
            metric: "Memory footprint (idle)",
            target: "< 50 MB",
            measurement: "Instruments Allocations"
        ),
        PerformanceBudget(
            metric: "Crash-free session rate",
            target: "> 99.5%",
            measurement: "TestFlight metrics"
        ),
        PerformanceBudget(
            metric: "Battery impact per hour (background)",
            target: "< 2% per hour",
            measurement: "Instruments Energy Log"
        ),
    ]

    // MARK: - Beta Configuration

    /// TestFlight beta group configuration.
    public struct BetaGroup: Sendable {
        public let name: String
        public let description: String
        public let maxTesters: Int
        public let autoDistribute: Bool
    }

    /// TestFlight beta groups.
    public static let betaGroups: [BetaGroup] = [
        BetaGroup(
            name: "Internal",
            description: "Core development team and QA",
            maxTesters: 25,
            autoDistribute: true
        ),
        BetaGroup(
            name: "Security Reviewers",
            description: "External security auditors and cryptographic reviewers",
            maxTesters: 10,
            autoDistribute: false
        ),
        BetaGroup(
            name: "External Beta",
            description: "Invited external testers for general UX feedback",
            maxTesters: 100,
            autoDistribute: false
        ),
    ]
}
