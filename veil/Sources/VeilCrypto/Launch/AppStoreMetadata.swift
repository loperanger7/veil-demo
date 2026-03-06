// VEIL — AppStoreMetadata.swift
// Ticket: VEIL-1001 — App Store Submission
//
// Structured App Store listing metadata, privacy nutrition labels,
// export compliance classification, and App Review compliance checks.
//
// All metadata is expressed as compilable Swift types for traceability
// and automated validation against App Store Connect requirements.

import Foundation

// MARK: - App Store Metadata

/// Centralized App Store listing metadata for Veil.
///
/// All field lengths are validated against App Store Connect constraints.
/// Content is structured to enable automated submission via the
/// App Store Connect API (Transporter / `altool`).
public enum AppStoreMetadata: Sendable {

    // MARK: - App Identity

    /// The app's display name on the App Store (max 30 characters).
    public static let appName = "Veil"

    /// The app's subtitle (max 30 characters).
    public static let subtitle = "Private Chat & Payments"

    /// Bundle identifier.
    public static let bundleIdentifier = "com.veil.messenger"

    /// Primary App Store category.
    public static let primaryCategory: AppCategory = .socialNetworking

    /// Secondary App Store category.
    public static let secondaryCategory: AppCategory = .finance

    /// App Store categories relevant to Veil.
    public enum AppCategory: String, Sendable, CaseIterable {
        case socialNetworking = "Social Networking"
        case finance = "Finance"
        case utilities = "Utilities"
    }

    // MARK: - Description

    /// Promotional text (max 170 characters, can be updated without new binary).
    public static let promotionalText = """
        Post-quantum encrypted messaging with built-in MobileCoin payments. \
        Your conversations are safe today and tomorrow.
        """

    /// Short description for search results (first ~165 characters matter most).
    public static let descriptionShort = """
        Veil is a private messenger that protects your conversations with \
        post-quantum encryption. Send messages and MobileCoin payments \
        knowing that no one — not even future quantum computers — can read them.
        """

    /// Full App Store description (max 4000 characters).
    public static let descriptionFull = """
        Veil is a next-generation private messenger built from the ground up \
        with post-quantum cryptography. Every message is protected by a hybrid \
        encryption protocol combining classical elliptic curve cryptography \
        with lattice-based post-quantum algorithms, ensuring your conversations \
        remain private against both current and future threats.

        PRIVATE MESSAGING
        • End-to-end encrypted messages using the PQXDH key agreement protocol
        • Forward secrecy and post-compromise security via Triple Ratchet
        • Sealed sender anonymity — the relay server never sees who messages whom
        • No message history stored on servers — messages are deleted after delivery

        BUILT-IN PAYMENTS
        • Send and receive MobileCoin (MOB) directly in conversations
        • Payment receipts are cryptographically signed and verified
        • Transaction details are end-to-end encrypted between sender and recipient
        • No payment metadata is visible to the relay server

        POST-QUANTUM SECURITY
        • ML-KEM-1024 (CRYSTALS-Kyber) key encapsulation for quantum resistance
        • Sparse Post-Quantum Ratchet (SPQR) for ongoing quantum protection
        • Hybrid design: security requires breaking BOTH classical AND quantum primitives
        • All cryptographic code is open source for independent verification

        TRUST THROUGH TRANSPARENCY
        • Cryptographic protocol library is open source (AGPL-3.0)
        • ProVerif formal verification models available for public review
        • Independent security audit in progress
        • No ads, no tracking, no data mining

        Veil requires an iOS device running iOS 17 or later. Registration uses \
        your phone number for contact discovery only — no other personal data \
        is collected or stored.
        """

    // MARK: - Keywords

    /// App Store keywords (max 100 characters total, comma-separated).
    public static let keywords = "encrypted,messenger,quantum,private,secure,chat,payments,mobilecoin,crypto,privacy"

    /// Keyword character count validation.
    public static var keywordsCharacterCount: Int {
        keywords.count
    }

    // MARK: - Screenshots

    /// Required screenshot specifications per device class.
    public struct ScreenshotSpec: Sendable {
        public let deviceClass: String
        public let resolution: (width: Int, height: Int)
        public let required: Bool

        public var aspectRatio: String {
            "\(resolution.width)x\(resolution.height)"
        }
    }

    /// Screenshot specifications for all required device classes.
    public static let screenshotSpecs: [ScreenshotSpec] = [
        ScreenshotSpec(deviceClass: "iPhone 6.7\"", resolution: (1290, 2796), required: true),
        ScreenshotSpec(deviceClass: "iPhone 6.5\"", resolution: (1284, 2778), required: true),
        ScreenshotSpec(deviceClass: "iPhone 5.5\"", resolution: (1242, 2208), required: true),
        ScreenshotSpec(deviceClass: "iPad Pro 12.9\"", resolution: (2048, 2732), required: false),
    ]

    /// Recommended screenshot scenes for the listing.
    public static let screenshotScenes: [String] = [
        "Conversation list with unread badges",
        "Chat view showing encrypted message bubbles",
        "Payment flow — sending MOB in conversation",
        "Safety number verification screen",
        "Settings — privacy and security options",
    ]

    // MARK: - Age Rating

    /// Content rating questionnaire responses.
    public struct AgeRatingResponse: Sendable {
        public let question: String
        public let answer: AgeRatingAnswer
    }

    public enum AgeRatingAnswer: String, Sendable {
        case none = "None"
        case inffrequentMild = "Infrequent/Mild"
        case frequentIntense = "Frequent/Intense"
    }

    /// Age rating questionnaire (all "None" — Veil has no objectionable content).
    public static let ageRatingResponses: [AgeRatingResponse] = [
        AgeRatingResponse(question: "Cartoon or Fantasy Violence", answer: .none),
        AgeRatingResponse(question: "Realistic Violence", answer: .none),
        AgeRatingResponse(question: "Prolonged Graphic or Sadistic Violence", answer: .none),
        AgeRatingResponse(question: "Profanity or Crude Humor", answer: .none),
        AgeRatingResponse(question: "Mature/Suggestive Themes", answer: .none),
        AgeRatingResponse(question: "Horror/Fear Themes", answer: .none),
        AgeRatingResponse(question: "Medical/Treatment Information", answer: .none),
        AgeRatingResponse(question: "Alcohol, Tobacco, or Drug Use", answer: .none),
        AgeRatingResponse(question: "Gambling or Contests", answer: .none),
        AgeRatingResponse(question: "Simulated Gambling", answer: .none),
        AgeRatingResponse(question: "Sexual Content or Nudity", answer: .none),
        AgeRatingResponse(question: "Graphic Sexual Content", answer: .none),
        AgeRatingResponse(question: "Unrestricted Web Access", answer: .none),
    ]

    /// Expected age rating based on responses.
    public static let expectedAgeRating = "4+"
}

// MARK: - Privacy Nutrition Labels

/// App Store privacy nutrition label declarations.
///
/// Veil collects minimal data: phone number for registration/contact discovery only.
/// No data is linked to identity, no data is used for tracking.
public enum PrivacyNutritionLabel: Sendable {

    /// Categories of data that can be declared.
    public enum DataCategory: String, Sendable, CaseIterable {
        case contactInfo = "Contact Info"
        case healthFitness = "Health & Fitness"
        case financialInfo = "Financial Info"
        case location = "Location"
        case sensitiveInfo = "Sensitive Info"
        case contacts = "Contacts"
        case userContent = "User Content"
        case browsingHistory = "Browsing History"
        case searchHistory = "Search History"
        case identifiers = "Identifiers"
        case usageData = "Usage Data"
        case diagnostics = "Diagnostics"
        case other = "Other Data"
    }

    /// Data collection purposes.
    public enum Purpose: String, Sendable, CaseIterable {
        case thirdPartyAdvertising = "Third-Party Advertising"
        case developerAdvertising = "Developer's Advertising or Marketing"
        case analytics = "Analytics"
        case productPersonalization = "Product Personalization"
        case appFunctionality = "App Functionality"
        case otherPurposes = "Other Purposes"
    }

    /// A single privacy declaration entry.
    public struct Declaration: Sendable {
        public let dataType: String
        public let category: DataCategory
        public let purpose: Purpose
        public let linkedToIdentity: Bool
        public let usedForTracking: Bool

        public var summaryString: String {
            let linked = linkedToIdentity ? "linked" : "not linked"
            let tracking = usedForTracking ? "tracking" : "not tracking"
            return "\(dataType) (\(category.rawValue)) — \(purpose.rawValue), \(linked), \(tracking)"
        }
    }

    /// All data collected by Veil.
    ///
    /// Only phone number is collected, solely for registration and contact discovery.
    /// It is NOT linked to identity and NOT used for tracking.
    public static let declarations: [Declaration] = [
        Declaration(
            dataType: "Phone Number",
            category: .contactInfo,
            purpose: .appFunctionality,
            linkedToIdentity: false,
            usedForTracking: false
        ),
    ]

    /// Data NOT collected by Veil (explicit declarations for App Review).
    public static let notCollected: [DataCategory] = DataCategory.allCases.filter { category in
        !declarations.contains { $0.category == category }
    }

    /// Whether Veil links any collected data to user identity.
    public static var linksDataToIdentity: Bool {
        declarations.contains { $0.linkedToIdentity }
    }

    /// Whether Veil uses any data for tracking across apps.
    public static var usesDataForTracking: Bool {
        declarations.contains { $0.usedForTracking }
    }

    /// Human-readable privacy summary for App Review notes.
    public static var reviewNotes: String {
        """
        Veil collects phone numbers solely for registration and contact \
        discovery. Phone numbers are hashed (SHA-256) before being sent to \
        the relay server for contact matching. No phone numbers are stored \
        in plaintext on the server. No data is linked to user identity. \
        No data is shared with third parties. No data is used for tracking. \
        All message content is end-to-end encrypted and never accessible \
        to the server.
        """
    }
}

// MARK: - Export Compliance

/// Encryption export compliance documentation.
///
/// Veil uses encryption and must declare this for App Store submission.
/// Under U.S. Bureau of Industry and Security (BIS) regulations, apps using
/// standard encryption algorithms may qualify for the EAR 5A992.c exemption.
public enum ExportCompliance: Sendable {

    /// Whether the app uses encryption.
    public static let usesEncryption = true

    /// Whether the app qualifies for an encryption exemption.
    ///
    /// Veil uses only standard, published encryption algorithms (AES-256-GCM,
    /// X25519, Ed25519, HKDF-SHA-512, ML-KEM-1024) for protecting user data.
    /// The primary function of the app is communication, not encryption technology.
    public static let qualifiesForExemption = true

    /// Export control classification.
    public enum Classification: String, Sendable {
        /// Mass-market encryption software (exempt from CCATS filing).
        case ear5A992c = "EAR 5A992.c"
        /// Requires CCATS filing with BIS.
        case ear5A002 = "EAR 5A002"
    }

    /// Veil's export classification.
    ///
    /// EAR 5A992.c: mass-market encryption software. Exempt from individual
    /// export licenses to most destinations. Requires annual self-classification
    /// report to BIS (by February 1 each year).
    public static let classification: Classification = .ear5A992c

    /// Encryption algorithms used and their purpose.
    public struct AlgorithmDeclaration: Sendable {
        public let algorithm: String
        public let keySize: String
        public let purpose: String
        public let standard: String
    }

    /// All cryptographic algorithms used by Veil.
    public static let algorithms: [AlgorithmDeclaration] = [
        AlgorithmDeclaration(
            algorithm: "AES-256-GCM",
            keySize: "256-bit",
            purpose: "Message encryption",
            standard: "NIST SP 800-38D"
        ),
        AlgorithmDeclaration(
            algorithm: "X25519",
            keySize: "256-bit",
            purpose: "Key agreement (Diffie-Hellman)",
            standard: "RFC 7748"
        ),
        AlgorithmDeclaration(
            algorithm: "Ed25519",
            keySize: "256-bit",
            purpose: "Digital signatures",
            standard: "RFC 8032"
        ),
        AlgorithmDeclaration(
            algorithm: "HKDF-SHA-512",
            keySize: "512-bit hash",
            purpose: "Key derivation",
            standard: "RFC 5869"
        ),
        AlgorithmDeclaration(
            algorithm: "ML-KEM-1024",
            keySize: "1024-dimensional lattice",
            purpose: "Post-quantum key encapsulation",
            standard: "NIST FIPS 203"
        ),
        AlgorithmDeclaration(
            algorithm: "ML-DSA-65",
            keySize: "65-dimensional lattice",
            purpose: "Post-quantum digital signatures",
            standard: "NIST FIPS 204"
        ),
        AlgorithmDeclaration(
            algorithm: "HMAC-SHA-256",
            keySize: "256-bit",
            purpose: "Message authentication",
            standard: "RFC 2104"
        ),
    ]

    /// BIS annual self-classification report requirements.
    public struct AnnualReportRequirements: Sendable {
        public let dueDate: String
        public let filingEmail: String
        public let requiredFields: [String]
    }

    public static let annualReport = AnnualReportRequirements(
        dueDate: "February 1 (annually)",
        filingEmail: "crypt-supp8@bis.doc.gov",
        requiredFields: [
            "Product name and version",
            "Manufacturer name and address",
            "Encryption algorithms and key lengths",
            "ECCN classification (5A992.c)",
            "Countries of distribution (worldwide via App Store)",
        ]
    )
}

// MARK: - App Review Compliance

/// App Review guidelines compliance verification.
///
/// Maps Veil's features against relevant App Store Review Guidelines
/// sections to ensure compliance before submission.
public enum AppReviewCompliance: Sendable {

    /// A compliance check against a specific guideline.
    public struct GuidelineCheck: Sendable {
        public let section: String
        public let title: String
        public let requirement: String
        public let veilCompliance: String
        public let status: ComplianceStatus
    }

    public enum ComplianceStatus: String, Sendable {
        case compliant = "Compliant"
        case needsReview = "Needs Review"
        case notApplicable = "N/A"
    }

    /// All relevant App Review guideline checks.
    public static let checks: [GuidelineCheck] = [
        // Safety
        GuidelineCheck(
            section: "1.1",
            title: "Objectionable Content",
            requirement: "No objectionable content in user-generated messages",
            veilCompliance: "Messages are E2E encrypted; Veil cannot moderate content. Report abuse mechanism available.",
            status: .compliant
        ),
        GuidelineCheck(
            section: "1.2",
            title: "User Generated Content",
            requirement: "Must have mechanism to report offensive content and block abusive users",
            veilCompliance: "Block user feature in conversation settings. Report mechanism forwards encrypted metadata to support.",
            status: .compliant
        ),

        // Payments
        GuidelineCheck(
            section: "3.1.1",
            title: "In-App Purchase",
            requirement: "Digital goods must use IAP",
            veilCompliance: "MobileCoin is a cryptocurrency transfer (person-to-person), not a digital good purchase. Exempt per guideline 3.1.5(b).",
            status: .compliant
        ),
        GuidelineCheck(
            section: "3.1.5(b)",
            title: "Cryptocurrency",
            requirement: "Cryptocurrency apps may facilitate approved virtual currency transactions",
            veilCompliance: "Veil facilitates person-to-person MobileCoin transfers within messaging. No exchange functionality.",
            status: .compliant
        ),

        // Privacy
        GuidelineCheck(
            section: "5.1.1",
            title: "Data Collection and Storage",
            requirement: "Must clearly describe data collection in privacy policy",
            veilCompliance: "Privacy policy documents minimal data collection (phone number only). Nutrition labels accurate.",
            status: .compliant
        ),
        GuidelineCheck(
            section: "5.1.2",
            title: "Data Use and Sharing",
            requirement: "Must not share data with third parties without consent",
            veilCompliance: "No data shared with third parties. All messages E2E encrypted. Relay sees only encrypted blobs.",
            status: .compliant
        ),

        // Encryption
        GuidelineCheck(
            section: "5.2",
            title: "Intellectual Property / Encryption",
            requirement: "Must comply with export regulations",
            veilCompliance: "EAR 5A992.c classification. Annual self-classification report filed. Standard published algorithms only.",
            status: .compliant
        ),

        // Legal
        GuidelineCheck(
            section: "5.3",
            title: "Gaming, Gambling, and Lotteries",
            requirement: "No gambling features without appropriate licenses",
            veilCompliance: "Not applicable. Veil is a messaging and payment app with no gambling features.",
            status: .notApplicable
        ),

        // Design
        GuidelineCheck(
            section: "4.0",
            title: "Design",
            requirement: "Must function as described, no hidden features",
            veilCompliance: "All features (messaging, payments, encryption) function as described in listing.",
            status: .compliant
        ),
        GuidelineCheck(
            section: "4.2",
            title: "Minimum Functionality",
            requirement: "Must provide sufficient value and functionality",
            veilCompliance: "Full messaging + payment functionality. Not a thin wrapper or marketing app.",
            status: .compliant
        ),
    ]

    /// Number of checks in each status.
    public static var complianceSummary: (compliant: Int, needsReview: Int, notApplicable: Int) {
        let c = checks.filter { $0.status == .compliant }.count
        let r = checks.filter { $0.status == .needsReview }.count
        let n = checks.filter { $0.status == .notApplicable }.count
        return (c, r, n)
    }

    /// Whether all applicable checks are compliant.
    public static var allCompliant: Bool {
        checks.allSatisfy { $0.status == .compliant || $0.status == .notApplicable }
    }
}

// MARK: - Field Length Validation

extension AppStoreMetadata {

    /// Validates all metadata field lengths against App Store Connect constraints.
    public struct FieldValidation: Sendable {
        public let field: String
        public let value: String
        public let maxLength: Int
        public let actualLength: Int
        public let isValid: Bool
    }

    /// Validate all constrained fields.
    public static func validateAllFields() -> [FieldValidation] {
        [
            FieldValidation(
                field: "App Name",
                value: appName,
                maxLength: 30,
                actualLength: appName.count,
                isValid: appName.count <= 30
            ),
            FieldValidation(
                field: "Subtitle",
                value: subtitle,
                maxLength: 30,
                actualLength: subtitle.count,
                isValid: subtitle.count <= 30
            ),
            FieldValidation(
                field: "Keywords",
                value: keywords,
                maxLength: 100,
                actualLength: keywords.count,
                isValid: keywords.count <= 100
            ),
            FieldValidation(
                field: "Promotional Text",
                value: promotionalText,
                maxLength: 170,
                actualLength: promotionalText.count,
                isValid: promotionalText.count <= 170
            ),
            FieldValidation(
                field: "Description",
                value: descriptionFull,
                maxLength: 4000,
                actualLength: descriptionFull.count,
                isValid: descriptionFull.count <= 4000
            ),
        ]
    }

    /// Whether all field lengths are within constraints.
    public static var allFieldsValid: Bool {
        validateAllFields().allSatisfy(\.isValid)
    }
}
