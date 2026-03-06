// VEIL — PackageExport.swift
// Ticket: VEIL-1002 — Open Source Preparation
//
// Defines the standalone VeilProtocol Swift package for open-source release.
// Maps which source files belong in the public protocol library vs. the
// proprietary iOS application layer.

import Foundation

// MARK: - Package Export

/// Configuration for extracting the VeilProtocol open-source Swift package.
///
/// The protocol library contains all cryptographic primitives, protocol
/// implementations, and verification infrastructure. The iOS application
/// layer (VeilUI, MobileCoin SDK integrations) remains proprietary.
public enum PackageExport: Sendable {

    // MARK: - Package Identity

    /// The open-source package name.
    public static let packageName = "VeilProtocol"

    /// Swift tools version required.
    public static let swiftToolsVersion = "5.9"

    /// Minimum platform versions.
    public static let platforms: [PlatformRequirement] = [
        PlatformRequirement(platform: "iOS", minimumVersion: "17.0"),
        PlatformRequirement(platform: "macOS", minimumVersion: "14.0"),
    ]

    /// Package repository URL.
    public static let repositoryURL = "https://github.com/loperanger7/veil-protocol"

    /// License identifier.
    public static let license = "AGPL-3.0"

    public struct PlatformRequirement: Sendable {
        public let platform: String
        public let minimumVersion: String
    }

    // MARK: - Module Map

    /// Modules exported by the open-source package.
    public enum ExportModule: String, Sendable, CaseIterable {
        /// Core cryptographic primitives and protocols.
        case veilCrypto = "VeilCrypto"
        /// ProVerif formal verification models (documentation only).
        case veilVerification = "VeilVerification"
    }

    /// Source file classification: open-source vs. proprietary.
    public struct FileClassification: Sendable {
        public let relativePath: String
        public let module: ExportModule?
        public let isOpenSource: Bool
        public let description: String
    }

    /// Complete file classification for the VeilCrypto source tree.
    ///
    /// Files with `isOpenSource: true` are included in the standalone package.
    /// Files with `isOpenSource: false` remain in the proprietary iOS app.
    public static let fileClassifications: [FileClassification] = [
        // === Core Primitives (OPEN SOURCE) ===
        FileClassification(
            relativePath: "Sources/VeilCrypto/KDF/HKDF.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "HKDF-SHA-512 key derivation with domain separation"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/KDF/DomainSeparation.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Type-safe domain separation for KDF"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Memory/SecureBytes.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Heap-allocated zeroizing byte buffer"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Identity/IdentityKeyPair.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Ed25519 + X25519 identity key generation"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/KEM/MLKEM1024.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "ML-KEM-1024 key encapsulation mechanism"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/KEM/KEMKeyPair.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "KEM key pair management"
        ),

        // === Protocol Layer (OPEN SOURCE) ===
        FileClassification(
            relativePath: "Sources/VeilCrypto/Protocol/PQXDH.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Post-Quantum Extended Diffie-Hellman key agreement"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Protocol/SymmetricRatchet.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Symmetric chain ratchet"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Protocol/DHRatchet.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Diffie-Hellman ratchet (classical)"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Protocol/SPQRRatchet.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Sparse Post-Quantum Ratchet"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Protocol/TripleRatchet.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Triple Ratchet composition"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Protocol/PrekeyBundle.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Prekey bundle for asynchronous key agreement"
        ),

        // === Security Hardening (OPEN SOURCE) ===
        FileClassification(
            relativePath: "Sources/VeilCrypto/Security/DLEQProofVerifier.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "DLEQ proof verification for anonymous tokens"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Security/ReceiptAuthenticator.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Ed25519 receipt signatures with replay protection"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Security/AmountValidator.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Payment amount validation and overflow protection"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Security/MemoSanitizer.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Unicode memo sanitization"
        ),

        // === Networking (OPEN SOURCE — protocol level) ===
        FileClassification(
            relativePath: "Sources/VeilCrypto/Networking/ExponentialPadding.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Exponential bucket traffic padding with HMAC"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Networking/TrafficPadding.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Base traffic padding scheme"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Networking/CiphertextPaddingLayer.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Ciphertext padding layer"
        ),

        // === Documentation (OPEN SOURCE) ===
        FileClassification(
            relativePath: "Sources/VeilCrypto/Docs/ThreatModel.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Threat model documentation"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Docs/AuditScope.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "External audit scope and review checklist"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Docs/ArchitectureDiagrams.swift",
            module: .veilCrypto, isOpenSource: true,
            description: "Mermaid protocol architecture diagrams"
        ),

        // === Verification (OPEN SOURCE) ===
        FileClassification(
            relativePath: "Sources/VeilCrypto/Verification/SecurityGames.swift",
            module: .veilVerification, isOpenSource: true,
            description: "Cryptographic security game definitions"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Verification/TestVectorGenerator.swift",
            module: .veilVerification, isOpenSource: true,
            description: "Known-answer test vector generator"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/Verification/ProtocolInvariants.swift",
            module: .veilVerification, isOpenSource: true,
            description: "Protocol invariant assertions"
        ),

        // === MobileCoin Integration (PROPRIETARY) ===
        FileClassification(
            relativePath: "Sources/VeilCrypto/MobileCoin/ECDHSharedSecret.swift",
            module: nil, isOpenSource: false,
            description: "MobileCoin-specific ECDH shared secret derivation"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/MobileCoin/MobileCoinWallet.swift",
            module: nil, isOpenSource: false,
            description: "MobileCoin wallet management"
        ),
        FileClassification(
            relativePath: "Sources/VeilCrypto/MobileCoin/Receipts/PaymentReceiptMessage.swift",
            module: nil, isOpenSource: false,
            description: "Payment receipt message format"
        ),

        // === iOS Application Layer (PROPRIETARY) ===
        FileClassification(
            relativePath: "Sources/VeilUI/",
            module: nil, isOpenSource: false,
            description: "Entire SwiftUI interface layer (proprietary)"
        ),
    ]

    /// Files included in the open-source package.
    public static var openSourceFiles: [FileClassification] {
        fileClassifications.filter(\.isOpenSource)
    }

    /// Files excluded from the open-source package.
    public static var proprietaryFiles: [FileClassification] {
        fileClassifications.filter { !$0.isOpenSource }
    }

    // MARK: - Public API Surface

    /// Public types exported by the VeilProtocol package.
    public struct PublicAPIEntry: Sendable {
        public let typeName: String
        public let kind: TypeKind
        public let module: ExportModule
        public let description: String
    }

    public enum TypeKind: String, Sendable {
        case `struct` = "struct"
        case `enum` = "enum"
        case `protocol` = "protocol"
        case `actor` = "actor"
        case function = "function"
    }

    /// Enumeration of all public API surface.
    public static let publicAPI: [PublicAPIEntry] = [
        // Primitives
        PublicAPIEntry(typeName: "SecureBytes", kind: .struct, module: .veilCrypto,
                       description: "Heap-allocated zeroizing byte buffer"),
        PublicAPIEntry(typeName: "VeilHKDF", kind: .enum, module: .veilCrypto,
                       description: "HKDF-SHA-512 key derivation"),
        PublicAPIEntry(typeName: "VeilDomain", kind: .enum, module: .veilCrypto,
                       description: "Type-safe KDF domain separation"),
        PublicAPIEntry(typeName: "IdentityKeyPair", kind: .struct, module: .veilCrypto,
                       description: "Ed25519 + X25519 identity keys"),
        PublicAPIEntry(typeName: "MLKEM1024", kind: .enum, module: .veilCrypto,
                       description: "ML-KEM-1024 key encapsulation"),
        PublicAPIEntry(typeName: "KEMKeyPair", kind: .struct, module: .veilCrypto,
                       description: "KEM key pair"),

        // Protocols
        PublicAPIEntry(typeName: "PQXDH", kind: .enum, module: .veilCrypto,
                       description: "Post-Quantum Extended Diffie-Hellman"),
        PublicAPIEntry(typeName: "SymmetricRatchet", kind: .struct, module: .veilCrypto,
                       description: "Symmetric chain ratchet"),
        PublicAPIEntry(typeName: "DHRatchet", kind: .struct, module: .veilCrypto,
                       description: "DH ratchet"),
        PublicAPIEntry(typeName: "SPQRRatchet", kind: .struct, module: .veilCrypto,
                       description: "Sparse Post-Quantum Ratchet"),
        PublicAPIEntry(typeName: "TripleRatchet", kind: .struct, module: .veilCrypto,
                       description: "Triple Ratchet composition"),

        // Security
        PublicAPIEntry(typeName: "DLEQProofVerifier", kind: .struct, module: .veilCrypto,
                       description: "DLEQ proof verification"),
        PublicAPIEntry(typeName: "ReceiptAuthenticator", kind: .enum, module: .veilCrypto,
                       description: "Receipt signing and verification"),
        PublicAPIEntry(typeName: "AmountValidator", kind: .enum, module: .veilCrypto,
                       description: "Payment amount validation"),
        PublicAPIEntry(typeName: "MemoSanitizer", kind: .enum, module: .veilCrypto,
                       description: "Unicode memo sanitization"),
        PublicAPIEntry(typeName: "ExponentialPaddingScheme", kind: .struct, module: .veilCrypto,
                       description: "Exponential bucket traffic padding"),
    ]

    // MARK: - Build Verification

    /// Steps to verify the standalone package builds on a clean environment.
    public struct BuildStep: Sendable {
        public let order: Int
        public let command: String
        public let description: String
        public let expectedOutput: String
    }

    /// Build verification steps for clean macOS environment.
    public static let buildVerificationSteps: [BuildStep] = [
        BuildStep(
            order: 1,
            command: "xcode-select --install",
            description: "Ensure Xcode command line tools are installed",
            expectedOutput: "Already installed or fresh installation completes"
        ),
        BuildStep(
            order: 2,
            command: "brew install liboqs",
            description: "Install liboqs for ML-KEM-1024 and ML-DSA-65",
            expectedOutput: "liboqs installed successfully"
        ),
        BuildStep(
            order: 3,
            command: "git clone https://github.com/loperanger7/veil-protocol.git && cd veil-protocol",
            description: "Clone the repository",
            expectedOutput: "Repository cloned"
        ),
        BuildStep(
            order: 4,
            command: "swift build",
            description: "Build all targets",
            expectedOutput: "Build complete! (no errors or warnings)"
        ),
        BuildStep(
            order: 5,
            command: "swift test",
            description: "Run all tests",
            expectedOutput: "All tests passed"
        ),
        BuildStep(
            order: 6,
            command: "swift package generate-xcodeproj",
            description: "Generate Xcode project for IDE users",
            expectedOutput: "Generated VeilProtocol.xcodeproj"
        ),
    ]

    // MARK: - Generated Package.swift

    /// Generates the Package.swift content for the standalone open-source package.
    public static func generatePackageManifest() -> String {
        """
        // swift-tools-version: \(swiftToolsVersion)
        // VeilProtocol — Post-Quantum Encrypted Messaging Protocol
        // License: AGPL-3.0
        // https://github.com/loperanger7/veil-protocol

        import PackageDescription

        let package = Package(
            name: "\(packageName)",
            platforms: [
                .iOS(.v17),
                .macOS(.v14),
            ],
            products: [
                .library(
                    name: "VeilProtocol",
                    targets: ["VeilCrypto"]
                ),
            ],
            dependencies: [
                .package(url: "https://github.com/typelift/SwiftCheck.git", from: "0.12.0"),
            ],
            targets: [
                .systemLibrary(
                    name: "CLibOQS",
                    path: "Sources/CLibOQS",
                    pkgConfig: "liboqs",
                    providers: [
                        .brew(["liboqs"]),
                        .apt(["liboqs-dev"]),
                    ]
                ),
                .target(
                    name: "VeilCrypto",
                    dependencies: ["CLibOQS"],
                    path: "Sources/VeilCrypto",
                    swiftSettings: [
                        .enableExperimentalFeature("StrictConcurrency"),
                    ]
                ),
                .testTarget(
                    name: "VeilProtocolTests",
                    dependencies: [
                        "VeilCrypto",
                        "SwiftCheck",
                    ],
                    path: "Tests/VeilProtocolTests"
                ),
            ]
        )
        """
    }
}
