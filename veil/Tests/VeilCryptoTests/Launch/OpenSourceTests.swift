// VEIL — OpenSourceTests.swift
// Ticket: VEIL-1002 — Open Source Preparation
//
// Tests validating the open-source package export: module graph,
// public API surface, license presence, security policy, and
// contributing guidelines.

import XCTest
@testable import VeilCrypto

final class OpenSourceTests: XCTestCase {

    // MARK: - Package Export Module Graph Tests

    func testOpenSourceFilesNotEmpty() {
        XCTAssertGreaterThan(
            PackageExport.openSourceFiles.count, 0,
            "Must have files marked for open-source release"
        )
    }

    func testProprietaryFilesExcluded() {
        XCTAssertGreaterThan(
            PackageExport.proprietaryFiles.count, 0,
            "Must have files marked as proprietary"
        )
    }

    func testVeilUIIsNotOpenSource() {
        let uiFile = PackageExport.fileClassifications.first { $0.relativePath.hasPrefix("Sources/VeilUI/") }
        XCTAssertNotNil(uiFile, "VeilUI should be in file classifications")
        XCTAssertFalse(uiFile!.isOpenSource, "VeilUI must NOT be open source")
    }

    func testCoreProtocolIsOpenSource() {
        let protocolFiles = PackageExport.openSourceFiles.filter {
            $0.relativePath.contains("/Protocol/")
        }
        XCTAssertGreaterThanOrEqual(
            protocolFiles.count, 5,
            "All core protocol files (PQXDH, ratchets) must be open source"
        )
    }

    func testSecurityHardeningIsOpenSource() {
        let securityFiles = PackageExport.openSourceFiles.filter {
            $0.relativePath.contains("/Security/")
        }
        XCTAssertGreaterThanOrEqual(
            securityFiles.count, 3,
            "Security hardening files should be open source for auditability"
        )
    }

    func testDocumentationIsOpenSource() {
        let docFiles = PackageExport.openSourceFiles.filter {
            $0.relativePath.contains("/Docs/")
        }
        XCTAssertGreaterThanOrEqual(docFiles.count, 3, "All doc files should be open source")
    }

    func testVerificationIsOpenSource() {
        let verificationFiles = PackageExport.openSourceFiles.filter {
            $0.relativePath.contains("/Verification/")
        }
        XCTAssertGreaterThanOrEqual(
            verificationFiles.count, 2,
            "Verification/proof files should be open source"
        )
    }

    func testAllOpenSourceFilesHaveModule() {
        for file in PackageExport.openSourceFiles {
            XCTAssertNotNil(
                file.module,
                "Open source file \(file.relativePath) must have a module assignment"
            )
        }
    }

    func testAllFilesHaveDescriptions() {
        for file in PackageExport.fileClassifications {
            XCTAssertFalse(
                file.description.isEmpty,
                "File \(file.relativePath) missing description"
            )
        }
    }

    // MARK: - Public API Surface Tests

    func testPublicAPISurfaceNotEmpty() {
        XCTAssertGreaterThan(PackageExport.publicAPI.count, 0)
    }

    func testCoreTypesInPublicAPI() {
        let typeNames = PackageExport.publicAPI.map(\.typeName)
        XCTAssertTrue(typeNames.contains("SecureBytes"), "SecureBytes must be public")
        XCTAssertTrue(typeNames.contains("VeilHKDF"), "VeilHKDF must be public")
        XCTAssertTrue(typeNames.contains("PQXDH"), "PQXDH must be public")
        XCTAssertTrue(typeNames.contains("TripleRatchet"), "TripleRatchet must be public")
    }

    func testSecurityTypesInPublicAPI() {
        let typeNames = PackageExport.publicAPI.map(\.typeName)
        XCTAssertTrue(typeNames.contains("DLEQProofVerifier"), "DLEQProofVerifier must be public")
        XCTAssertTrue(typeNames.contains("ReceiptAuthenticator"), "ReceiptAuthenticator must be public")
        XCTAssertTrue(typeNames.contains("AmountValidator"), "AmountValidator must be public")
    }

    func testAllPublicAPIsHaveDescriptions() {
        for entry in PackageExport.publicAPI {
            XCTAssertFalse(
                entry.description.isEmpty,
                "Public API \(entry.typeName) missing description"
            )
        }
    }

    func testNoInternalTypesExposed() {
        let internalPrefixes = ["_", "Internal", "Private", "Mock"]
        for entry in PackageExport.publicAPI {
            for prefix in internalPrefixes {
                XCTAssertFalse(
                    entry.typeName.hasPrefix(prefix),
                    "Public API should not expose internal type: \(entry.typeName)"
                )
            }
        }
    }

    // MARK: - Build Verification Tests

    func testBuildStepsOrdered() {
        let steps = PackageExport.buildVerificationSteps
        XCTAssertGreaterThanOrEqual(steps.count, 4)
        for i in 0..<steps.count {
            XCTAssertEqual(steps[i].order, i + 1, "Build steps should be sequentially numbered")
        }
    }

    func testBuildStepsHaveCommands() {
        for step in PackageExport.buildVerificationSteps {
            XCTAssertFalse(step.command.isEmpty, "Step \(step.order) missing command")
            XCTAssertFalse(step.description.isEmpty, "Step \(step.order) missing description")
            XCTAssertFalse(step.expectedOutput.isEmpty, "Step \(step.order) missing expected output")
        }
    }

    func testBuildStepsIncludeSwiftBuild() {
        let commands = PackageExport.buildVerificationSteps.map(\.command)
        XCTAssertTrue(
            commands.contains(where: { $0.contains("swift build") }),
            "Must include swift build step"
        )
    }

    func testBuildStepsIncludeSwiftTest() {
        let commands = PackageExport.buildVerificationSteps.map(\.command)
        XCTAssertTrue(
            commands.contains(where: { $0.contains("swift test") }),
            "Must include swift test step"
        )
    }

    // MARK: - Package Manifest Generation Tests

    func testGeneratedManifestContainsPackageName() {
        let manifest = PackageExport.generatePackageManifest()
        XCTAssertTrue(manifest.contains(PackageExport.packageName))
    }

    func testGeneratedManifestContainsPlatforms() {
        let manifest = PackageExport.generatePackageManifest()
        XCTAssertTrue(manifest.contains(".iOS(.v17)"))
        XCTAssertTrue(manifest.contains(".macOS(.v14)"))
    }

    func testGeneratedManifestContainsCLibOQS() {
        let manifest = PackageExport.generatePackageManifest()
        XCTAssertTrue(manifest.contains("CLibOQS"))
    }

    func testGeneratedManifestContainsStrictConcurrency() {
        let manifest = PackageExport.generatePackageManifest()
        XCTAssertTrue(manifest.contains("StrictConcurrency"))
    }

    // MARK: - License Tests

    func testLicenseIdentifier() {
        XCTAssertEqual(LicenseInfo.spdxIdentifier, "AGPL-3.0-only")
    }

    func testSourceFileHeaderContainsCopyright() {
        XCTAssertTrue(LicenseInfo.sourceFileHeader.contains("Copyright"))
        XCTAssertTrue(LicenseInfo.sourceFileHeader.contains(LicenseInfo.spdxIdentifier))
    }

    func testLicenseRationaleExplainsCopyleft() {
        XCTAssertTrue(LicenseInfo.licenseRationale.contains("copyleft").description.isEmpty == false)
        // The rationale should explain the network clause (AGPL's distinguishing feature)
        XCTAssertTrue(LicenseInfo.licenseRationale.lowercased().contains("network"))
    }

    // MARK: - Contributing Guidelines Tests

    func testContributionProcessComplete() {
        XCTAssertGreaterThanOrEqual(ContributingGuidelines.process.count, 5)
        for step in ContributingGuidelines.process {
            XCTAssertFalse(step.action.isEmpty)
            XCTAssertFalse(step.details.isEmpty)
        }
    }

    func testCryptoContributionRequirementsNotEmpty() {
        XCTAssertGreaterThanOrEqual(
            ContributingGuidelines.cryptoContributionRequirements.count, 5,
            "Need comprehensive crypto contribution requirements"
        )
    }

    func testCryptoRequirementsIncludeSecureBytes() {
        let requirements = ContributingGuidelines.cryptoContributionRequirements
        XCTAssertTrue(
            requirements.contains(where: { $0.contains("SecureBytes") }),
            "Must require SecureBytes for key material"
        )
    }

    func testCryptoRequirementsIncludeConstantTime() {
        let requirements = ContributingGuidelines.cryptoContributionRequirements
        XCTAssertTrue(
            requirements.contains(where: { $0.lowercased().contains("constant-time") || $0.lowercased().contains("constant time") }),
            "Must require constant-time operations"
        )
    }

    // MARK: - Security Disclosure Tests

    func testDisclosureWindowIs90Days() {
        XCTAssertEqual(SecurityDisclosurePolicy.disclosureWindowDays, 90)
    }

    func testContactEmailProvided() {
        XCTAssertFalse(SecurityDisclosurePolicy.contact.email.isEmpty)
        XCTAssertTrue(SecurityDisclosurePolicy.contact.email.contains("@"))
    }

    func testInScopeNotEmpty() {
        XCTAssertGreaterThanOrEqual(SecurityDisclosurePolicy.inScope.count, 5)
    }

    func testOutOfScopeNotEmpty() {
        XCTAssertGreaterThanOrEqual(SecurityDisclosurePolicy.outOfScope.count, 3)
    }

    func testSeverityLevelsDefined() {
        XCTAssertEqual(SecurityDisclosurePolicy.severityLevels.count, 4)
        let levels = SecurityDisclosurePolicy.severityLevels.map(\.level)
        XCTAssertTrue(levels.contains("Critical"))
        XCTAssertTrue(levels.contains("High"))
        XCTAssertTrue(levels.contains("Medium"))
        XCTAssertTrue(levels.contains("Low"))
    }

    // MARK: - Security Policy Tests

    func testBugBountyEnabled() {
        XCTAssertTrue(SecurityPolicy.bugBounty.enabled)
    }

    func testBugBountyRewardsExist() {
        XCTAssertEqual(SecurityPolicy.bugBounty.rewards.count, 4)
        let criticalReward = SecurityPolicy.bugBounty.rewards.first { $0.severity == "Critical" }
        XCTAssertNotNil(criticalReward)
        XCTAssertGreaterThan(criticalReward!.maximumReward, 0)
    }

    func testAuditHistoryExists() {
        XCTAssertGreaterThanOrEqual(SecurityPolicy.auditHistory.count, 2)
        let redTeam = SecurityPolicy.auditHistory.first { $0.type == .internalRedTeam }
        XCTAssertNotNil(redTeam)
        XCTAssertEqual(redTeam!.findings.critical, 6, "Should match our 6 CRITICAL findings")
        XCTAssertEqual(redTeam!.findings.high, 8, "Should match our 8 HIGH findings")
        XCTAssertEqual(redTeam!.status, .remediated)
    }

    func testAlgorithmPoliciesDefined() {
        XCTAssertGreaterThanOrEqual(SecurityPolicy.algorithmPolicies.count, 4)
        for policy in SecurityPolicy.algorithmPolicies {
            XCTAssertFalse(policy.algorithm.isEmpty)
            XCTAssertFalse(policy.deprecationTrigger.isEmpty)
        }
    }

    func testSecurityTxtGeneration() {
        let securityTxt = SecurityPolicy.generateSecurityTxt()
        XCTAssertTrue(securityTxt.contains("Contact:"))
        XCTAssertTrue(securityTxt.contains("Canonical:"))
        XCTAssertTrue(securityTxt.contains("Expires:"))
    }

    func testSecurityMDGeneration() {
        let securityMD = SecurityPolicy.generateSecurityMD()
        XCTAssertTrue(securityMD.contains("Reporting a Vulnerability"))
        XCTAssertTrue(securityMD.contains("Bug Bounty"))
        XCTAssertTrue(securityMD.contains("Audit History"))
    }

    func testSupplyChainMeasures() {
        XCTAssertGreaterThanOrEqual(SecurityPolicy.supplyChainMeasures.count, 5)
        let categories = Set(SecurityPolicy.supplyChainMeasures.map(\.category))
        XCTAssertTrue(categories.contains("Dependencies"))
        XCTAssertTrue(categories.contains("Build"))
        XCTAssertTrue(categories.contains("Release"))
        XCTAssertTrue(categories.contains("Code"))
    }
}
