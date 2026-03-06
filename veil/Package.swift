// swift-tools-version: 5.9
// VEIL — Post-Quantum Encrypted Chat & Payments
// Cryptographic Core + iOS UI
//
// References: Veil Protocol Specification v1.0, Sections 3–6

import PackageDescription

let package = Package(
    name: "Veil",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "VeilCrypto",
            targets: ["VeilCrypto"]
        ),
        .library(
            name: "VeilUI",
            targets: ["VeilUI"]
        ),
    ],
    dependencies: [
        // SwiftCheck for property-based testing (Dijkstra-style invariants)
        .package(url: "https://github.com/typelift/SwiftCheck.git", from: "0.12.0"),
    ],
    targets: [
        // C bridging module for liboqs (ML-KEM-1024, ML-DSA-65)
        // Uses stub implementations for iOS simulator; real liboqs for macOS CLI.
        .target(
            name: "CLibOQS",
            path: "Sources/CLibOQS",
            publicHeadersPath: "."
        ),

        // Core cryptographic library
        .target(
            name: "VeilCrypto",
            dependencies: ["CLibOQS"],
            path: "Sources/VeilCrypto",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),

        // SwiftUI interface layer
        .target(
            name: "VeilUI",
            dependencies: ["VeilCrypto"],
            path: "Sources/VeilUI",
            swiftSettings: [
                .enableExperimentalFeature("StrictConcurrency"),
            ]
        ),

        // Test suite: unit tests + property-based tests
        .testTarget(
            name: "VeilCryptoTests",
            dependencies: [
                "VeilCrypto",
                "SwiftCheck",
            ],
            path: "Tests/VeilCryptoTests"
        ),
    ]
)
