// VEIL — SecurityPolicy.swift
// Ticket: VEIL-1002 — Open Source Preparation
//
// Structured security policy for the VeilProtocol open-source release.
// Defines bug bounty scope, vulnerability classification, and the
// security.txt well-known URI content.

import Foundation

// MARK: - Security Policy

/// Security policy for the VeilProtocol project.
///
/// This generates the content for SECURITY.md and the
/// .well-known/security.txt file per RFC 9116.
public enum SecurityPolicy: Sendable {

    // MARK: - Bug Bounty

    /// Bug bounty program definition.
    public struct BugBountyProgram: Sendable {
        public let enabled: Bool
        public let currency: String
        public let rewards: [BountyReward]
        public let rules: [String]
    }

    public struct BountyReward: Sendable {
        public let severity: String
        public let minimumReward: Int
        public let maximumReward: Int
        public let currency: String

        public var rangeDescription: String {
            if minimumReward == maximumReward {
                return "\(currency)\(minimumReward)"
            }
            return "\(currency)\(minimumReward) – \(currency)\(maximumReward)"
        }
    }

    /// Bug bounty program details.
    public static let bugBounty = BugBountyProgram(
        enabled: true,
        currency: "USD",
        rewards: [
            BountyReward(severity: "Critical", minimumReward: 5000, maximumReward: 25000, currency: "$"),
            BountyReward(severity: "High", minimumReward: 2000, maximumReward: 10000, currency: "$"),
            BountyReward(severity: "Medium", minimumReward: 500, maximumReward: 2000, currency: "$"),
            BountyReward(severity: "Low", minimumReward: 100, maximumReward: 500, currency: "$"),
        ],
        rules: [
            "Only vulnerabilities in the VeilProtocol cryptographic library are eligible",
            "Vulnerabilities must be previously unreported",
            "Reporter must not exploit the vulnerability beyond proof-of-concept",
            "Reporter must not access other users' data",
            "Duplicate reports receive no reward (first reporter wins)",
            "Veil team members and their immediate family are ineligible",
            "Rewards are paid in MobileCoin (MOB) or USD at reporter's preference",
            "Reports must include a clear proof-of-concept or detailed description",
        ]
    )

    // MARK: - Security Hardening History

    /// Record of security audits and hardening efforts.
    public struct SecurityAudit: Sendable {
        public let date: String
        public let type: AuditType
        public let scope: String
        public let findings: AuditFindings
        public let auditor: String
        public let status: AuditStatus
    }

    public enum AuditType: String, Sendable {
        case internalRedTeam = "Internal Red Team"
        case externalAudit = "External Cryptographic Audit"
        case penetrationTest = "Penetration Test"
        case formalVerification = "Formal Verification"
    }

    public struct AuditFindings: Sendable {
        public let critical: Int
        public let high: Int
        public let medium: Int
        public let low: Int
        public let informational: Int

        public var total: Int { critical + high + medium + low + informational }
    }

    public enum AuditStatus: String, Sendable {
        case completed = "Completed"
        case inProgress = "In Progress"
        case planned = "Planned"
        case remediated = "Fully Remediated"
    }

    /// History of security audits.
    public static let auditHistory: [SecurityAudit] = [
        SecurityAudit(
            date: "2025-Q4",
            type: .internalRedTeam,
            scope: "Full protocol stack: PQXDH, Triple Ratchet, SPQR, payments, networking",
            findings: AuditFindings(critical: 6, high: 8, medium: 14, low: 0, informational: 0),
            auditor: "Internal security team",
            status: .remediated
        ),
        SecurityAudit(
            date: "2025-Q4",
            type: .formalVerification,
            scope: "ProVerif models for PQXDH, Triple Ratchet, SPQR ratchet",
            findings: AuditFindings(critical: 0, high: 0, medium: 0, low: 0, informational: 3),
            auditor: "Internal — formal methods",
            status: .completed
        ),
        SecurityAudit(
            date: "2026-Q1",
            type: .externalAudit,
            scope: "VeilCrypto protocol library — full cryptographic review",
            findings: AuditFindings(critical: 0, high: 0, medium: 0, low: 0, informational: 0),
            auditor: "TBD — external firm",
            status: .planned
        ),
        SecurityAudit(
            date: "2026-Q1",
            type: .penetrationTest,
            scope: "Relay server API, WebSocket endpoints, domain fronting",
            findings: AuditFindings(critical: 0, high: 0, medium: 0, low: 0, informational: 0),
            auditor: "TBD — external firm",
            status: .planned
        ),
    ]

    // MARK: - Cryptographic Agility

    /// Cryptographic algorithm deprecation policy.
    public struct DeprecationPolicy: Sendable {
        public let algorithm: String
        public let currentStatus: AlgorithmStatus
        public let migrationPath: String?
        public let deprecationTrigger: String
    }

    public enum AlgorithmStatus: String, Sendable {
        case active = "Active"
        case monitoring = "Monitoring"
        case deprecated = "Deprecated"
        case removed = "Removed"
    }

    /// Algorithm lifecycle management.
    public static let algorithmPolicies: [DeprecationPolicy] = [
        DeprecationPolicy(
            algorithm: "X25519",
            currentStatus: .active,
            migrationPath: "X448 or post-quantum KEM (already covered by ML-KEM-1024)",
            deprecationTrigger: "NIST recommendation or demonstrated attack below 2^100"
        ),
        DeprecationPolicy(
            algorithm: "Ed25519",
            currentStatus: .active,
            migrationPath: "Ed448 or ML-DSA-65",
            deprecationTrigger: "NIST recommendation or demonstrated attack below 2^100"
        ),
        DeprecationPolicy(
            algorithm: "AES-256-GCM",
            currentStatus: .active,
            migrationPath: "AES-256-GCM-SIV or ChaCha20-Poly1305",
            deprecationTrigger: "Practical nonce-reuse attack or NIST deprecation"
        ),
        DeprecationPolicy(
            algorithm: "ML-KEM-1024",
            currentStatus: .active,
            migrationPath: "Updated NIST PQC standard",
            deprecationTrigger: "NIST revises FIPS 203 or practical lattice attack"
        ),
        DeprecationPolicy(
            algorithm: "HKDF-SHA-512",
            currentStatus: .active,
            migrationPath: "HKDF-SHA-3-512",
            deprecationTrigger: "SHA-2 collision attack below birthday bound"
        ),
    ]

    // MARK: - Security.txt (RFC 9116)

    /// Generates RFC 9116 compliant security.txt content.
    ///
    /// This file should be served at:
    /// - https://veil.app/.well-known/security.txt
    /// - https://veil.app/security.txt (redirect to above)
    public static func generateSecurityTxt() -> String {
        """
        # Veil Security Policy
        # https://veil.app/.well-known/security.txt
        # This file conforms to RFC 9116

        Contact: mailto:\(SecurityDisclosurePolicy.contact.email)
        Encryption: https://veil.app/.well-known/pgp-key.txt
        Preferred-Languages: en
        Canonical: https://veil.app/.well-known/security.txt
        Policy: https://github.com/loperanger7/veil-protocol/blob/main/SECURITY.md
        Hiring: https://veil.app/careers
        Expires: 2027-01-01T00:00:00.000Z
        """
    }

    // MARK: - SECURITY.md Generator

    /// Generates SECURITY.md content for the repository.
    public static func generateSecurityMD() -> String {
        """
        # Security Policy

        ## Reporting a Vulnerability

        **DO NOT** open a public GitHub issue for security vulnerabilities.

        Email: \(SecurityDisclosurePolicy.contact.email)

        Encrypt your report using our PGP key:
        \(SecurityDisclosurePolicy.contact.pgpKeyFingerprint)

        We will respond within \(SecurityDisclosurePolicy.contact.responseSLA).

        ## Disclosure Timeline

        We follow a \(SecurityDisclosurePolicy.disclosureWindowDays)-day responsible disclosure policy.

        ## Scope

        In scope:
        \(SecurityDisclosurePolicy.inScope.map { "- \($0)" }.joined(separator: "\n"))

        Out of scope:
        \(SecurityDisclosurePolicy.outOfScope.map { "- \($0)" }.joined(separator: "\n"))

        ## Bug Bounty

        We offer rewards for qualifying vulnerabilities:
        \(bugBounty.rewards.map { "- \($0.severity): \($0.rangeDescription)" }.joined(separator: "\n"))

        ## Audit History

        \(auditHistory.map { "- \($0.date): \($0.type.rawValue) (\($0.status.rawValue))" }.joined(separator: "\n"))
        """
    }

    // MARK: - Supply Chain Security

    /// Measures to protect against supply chain attacks.
    public struct SupplyChainMeasure: Sendable {
        public let category: String
        public let measure: String
        public let implementation: String
    }

    /// Supply chain security measures.
    public static let supplyChainMeasures: [SupplyChainMeasure] = [
        SupplyChainMeasure(
            category: "Dependencies",
            measure: "Minimal dependency tree",
            implementation: "Only 2 external dependencies: liboqs (system library) and SwiftCheck (test only)"
        ),
        SupplyChainMeasure(
            category: "Dependencies",
            measure: "Pinned dependency versions",
            implementation: "Package.swift specifies exact version constraints"
        ),
        SupplyChainMeasure(
            category: "Build",
            measure: "Reproducible builds",
            implementation: "Swift Package Manager with locked dependency resolution (Package.resolved)"
        ),
        SupplyChainMeasure(
            category: "Build",
            measure: "CI/CD pipeline security",
            implementation: "GitHub Actions with pinned action versions, no third-party actions in crypto path"
        ),
        SupplyChainMeasure(
            category: "Release",
            measure: "Signed releases",
            implementation: "Git tags signed with maintainer GPG key"
        ),
        SupplyChainMeasure(
            category: "Release",
            measure: "SBOM generation",
            implementation: "Software Bill of Materials generated for each release"
        ),
        SupplyChainMeasure(
            category: "Code",
            measure: "Branch protection",
            implementation: "main branch requires 2 approvals, status checks, signed commits"
        ),
        SupplyChainMeasure(
            category: "Code",
            measure: "No binary artifacts",
            implementation: "All code compiled from source; no pre-built binaries in the repository"
        ),
    ]
}
