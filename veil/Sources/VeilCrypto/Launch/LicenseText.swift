// VEIL — LicenseText.swift
// Ticket: VEIL-1002 — Open Source Preparation
//
// License, contributing guidelines, and security disclosure policy
// for the open-source VeilProtocol package release.

import Foundation

// MARK: - License

/// License and legal information for the VeilProtocol open-source release.
public enum LicenseInfo: Sendable {

    /// SPDX license identifier.
    public static let spdxIdentifier = "AGPL-3.0-only"

    /// License short name.
    public static let shortName = "GNU Affero General Public License v3.0"

    /// Copyright holder.
    public static let copyrightHolder = "Veil Contributors"

    /// Copyright year.
    public static let copyrightYear = "2025"

    /// License header for source files.
    public static let sourceFileHeader = """
        // Copyright (c) \(copyrightYear) \(copyrightHolder)
        // SPDX-License-Identifier: \(spdxIdentifier)
        //
        // This file is part of VeilProtocol.
        // See LICENSE for the full license text.
        """

    /// Why AGPL-3.0 was chosen over other licenses.
    ///
    /// AGPL-3.0 ensures that modifications to the cryptographic protocol
    /// library must be shared when used in networked services. This prevents
    /// silent modifications that could weaken security guarantees while
    /// still allowing the protocol to be used freely.
    public static let licenseRationale = """
        The AGPL-3.0 license was selected for VeilProtocol because:

        1. Transparency: Any server-side modifications to the protocol must
           be published, preventing hidden weakening of cryptographic guarantees.

        2. Copyleft: Derivative works must remain open source under the same
           license, ensuring the protocol stays publicly auditable.

        3. Network clause: The "network use is distribution" provision (Section 13)
           ensures that relay operators using a modified VeilProtocol must share
           their modifications, even if they only provide the software as a service.

        4. Compatibility: AGPL-3.0 is compatible with GPL-3.0, allowing integration
           with other copyleft projects.

        The iOS application layer (VeilUI) is NOT covered by this license and
        remains proprietary.
        """
}

// MARK: - Contributing Guidelines

/// Contributing guidelines for the VeilProtocol open-source project.
public enum ContributingGuidelines: Sendable {

    /// Code of conduct reference.
    public static let codeOfConduct = "Contributor Covenant v2.1"

    /// How to submit contributions.
    public struct ContributionProcess: Sendable {
        public let step: Int
        public let action: String
        public let details: String
    }

    /// Steps to contribute to VeilProtocol.
    public static let process: [ContributionProcess] = [
        ContributionProcess(
            step: 1,
            action: "Open an issue",
            details: "Describe the bug, feature request, or security concern before starting work."
        ),
        ContributionProcess(
            step: 2,
            action: "Fork and branch",
            details: "Create a feature branch from main. Use the naming convention: feature/description or fix/description."
        ),
        ContributionProcess(
            step: 3,
            action: "Write code + tests",
            details: "All cryptographic changes MUST include corresponding test coverage. Property-based tests preferred for protocol invariants."
        ),
        ContributionProcess(
            step: 4,
            action: "Run the full test suite",
            details: "swift test must pass with zero failures. Performance tests must not regress."
        ),
        ContributionProcess(
            step: 5,
            action: "Submit pull request",
            details: "Reference the issue number. Include a description of what changed and why. Cryptographic changes require two reviewers."
        ),
        ContributionProcess(
            step: 6,
            action: "Code review",
            details: "All PRs require at least one approval. Cryptographic PRs require review from a maintainer with cryptographic expertise."
        ),
    ]

    /// Requirements for cryptographic contributions.
    public static let cryptoContributionRequirements: [String] = [
        "All new cryptographic operations must use SecureBytes for key material",
        "All new key derivations must use VeilHKDF with a registered VeilDomain",
        "All new protocol messages must have a formal security argument",
        "No floating-point arithmetic in any cryptographic code path",
        "No branching on secret data (constant-time operations only)",
        "All random number generation must use SystemRandomNumberGenerator or CryptoKit",
        "New algorithms must reference a published standard (NIST, IETF RFC, or peer-reviewed paper)",
    ]

    /// Development environment setup.
    public static let devEnvironment = """
        Requirements:
        - macOS 14+ with Xcode 15.2+
        - Swift 5.9+
        - liboqs (brew install liboqs)
        - SwiftLint (optional, brew install swiftlint)

        Setup:
        $ git clone https://github.com/loperanger7/veil-protocol.git
        $ cd veil-protocol
        $ swift build
        $ swift test
        """
}

// MARK: - Security Disclosure Policy

/// Security vulnerability disclosure policy.
public enum SecurityDisclosurePolicy: Sendable {

    /// Disclosure timeline.
    public static let disclosureWindowDays = 90

    /// Contact information for reporting vulnerabilities.
    public struct ContactInfo: Sendable {
        public let email: String
        public let pgpKeyFingerprint: String
        public let responseSLA: String
    }

    /// Security contact details.
    public static let contact = ContactInfo(
        email: "security@veil.app",
        pgpKeyFingerprint: "TBD — PGP key will be published at veil.app/.well-known/security.txt",
        responseSLA: "Initial response within 48 hours"
    )

    /// Scope of the security disclosure program.
    public static let inScope: [String] = [
        "Cryptographic protocol weaknesses (PQXDH, Triple Ratchet, SPQR)",
        "Key material exposure or insufficient zeroization",
        "Authentication bypass on anonymous tokens or payment receipts",
        "Side-channel attacks (timing, cache, power analysis)",
        "Replay attacks on any protocol message",
        "Traffic analysis attacks that defeat padding",
        "Relay server vulnerabilities that expose metadata",
        "Memory safety issues in cryptographic code paths",
    ]

    /// Explicitly out of scope.
    public static let outOfScope: [String] = [
        "Social engineering attacks",
        "Physical device attacks (stolen unlocked device)",
        "Denial of service attacks against the relay server",
        "UI/UX bugs that don't affect security",
        "Third-party dependency vulnerabilities (report upstream)",
    ]

    /// Severity classification for vulnerabilities.
    public struct SeverityLevel: Sendable {
        public let level: String
        public let description: String
        public let responseTarget: String
        public let exampleImpact: String
    }

    /// Vulnerability severity levels.
    public static let severityLevels: [SeverityLevel] = [
        SeverityLevel(
            level: "Critical",
            description: "Allows reading plaintext messages or recovering key material",
            responseTarget: "Fix within 7 days, coordinate disclosure",
            exampleImpact: "Break E2E encryption for all users"
        ),
        SeverityLevel(
            level: "High",
            description: "Weakens cryptographic guarantees or exposes metadata",
            responseTarget: "Fix within 14 days",
            exampleImpact: "Defeat forward secrecy for specific sessions"
        ),
        SeverityLevel(
            level: "Medium",
            description: "Reduces security margin or enables limited information leakage",
            responseTarget: "Fix within 30 days",
            exampleImpact: "Traffic analysis reveals message frequency"
        ),
        SeverityLevel(
            level: "Low",
            description: "Minor issue with limited security impact",
            responseTarget: "Fix within 90 days",
            exampleImpact: "Cosmetic issue in security UI"
        ),
    ]

    /// The responsible disclosure process.
    public static let disclosureProcess = """
        1. Reporter sends encrypted email to \(contact.email) with vulnerability details.
        2. Veil team acknowledges receipt within 48 hours.
        3. Veil team triages and assigns severity within 5 business days.
        4. Veil team develops and tests a fix within the severity-based timeline.
        5. Fix is released and reporter is credited (unless they prefer anonymity).
        6. Public disclosure occurs \(disclosureWindowDays) days after the initial report,
           or when the fix is released, whichever comes first.
        7. If Veil team is unresponsive for 14 days, reporter may disclose at their discretion.
        """
}
