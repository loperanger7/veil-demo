// VEIL — AppStoreComplianceTests.swift
// Ticket: VEIL-1001 — App Store Submission
//
// Tests validating App Store metadata, privacy nutrition labels,
// export compliance, and App Review guideline compliance.

import XCTest
@testable import VeilCrypto

final class AppStoreComplianceTests: XCTestCase {

    // MARK: - Metadata Field Length Tests

    func testAppNameWithinLimit() {
        XCTAssertLessThanOrEqual(
            AppStoreMetadata.appName.count, 30,
            "App name must be ≤ 30 characters"
        )
        XCTAssertFalse(AppStoreMetadata.appName.isEmpty)
    }

    func testSubtitleWithinLimit() {
        XCTAssertLessThanOrEqual(
            AppStoreMetadata.subtitle.count, 30,
            "Subtitle must be ≤ 30 characters"
        )
    }

    func testKeywordsWithinLimit() {
        XCTAssertLessThanOrEqual(
            AppStoreMetadata.keywords.count, 100,
            "Keywords must be ≤ 100 characters"
        )
    }

    func testKeywordsAreCommaSeparated() {
        let keywords = AppStoreMetadata.keywords.split(separator: ",")
        XCTAssertGreaterThan(keywords.count, 1, "Should have multiple keywords")
        for keyword in keywords {
            let trimmed = keyword.trimmingCharacters(in: .whitespaces)
            XCTAssertFalse(trimmed.isEmpty, "No empty keywords allowed")
            XCTAssertFalse(trimmed.contains(" "), "Individual keywords should not contain spaces")
        }
    }

    func testPromotionalTextWithinLimit() {
        XCTAssertLessThanOrEqual(
            AppStoreMetadata.promotionalText.count, 170,
            "Promotional text must be ≤ 170 characters"
        )
    }

    func testDescriptionWithinLimit() {
        XCTAssertLessThanOrEqual(
            AppStoreMetadata.descriptionFull.count, 4000,
            "Full description must be ≤ 4000 characters"
        )
    }

    func testAllFieldsValidation() {
        let validations = AppStoreMetadata.validateAllFields()
        XCTAssertFalse(validations.isEmpty)
        for validation in validations {
            XCTAssertTrue(
                validation.isValid,
                "\(validation.field) exceeds max length: \(validation.actualLength)/\(validation.maxLength)"
            )
        }
        XCTAssertTrue(AppStoreMetadata.allFieldsValid)
    }

    // MARK: - Privacy Nutrition Label Tests

    func testMinimalDataCollection() {
        // Veil should collect only phone number
        XCTAssertEqual(PrivacyNutritionLabel.declarations.count, 1)
        XCTAssertEqual(PrivacyNutritionLabel.declarations[0].dataType, "Phone Number")
    }

    func testNoDataLinkedToIdentity() {
        XCTAssertFalse(
            PrivacyNutritionLabel.linksDataToIdentity,
            "Veil must not link any data to user identity"
        )
    }

    func testNoDataUsedForTracking() {
        XCTAssertFalse(
            PrivacyNutritionLabel.usesDataForTracking,
            "Veil must not use any data for tracking"
        )
    }

    func testPhoneNumberPurpose() {
        guard let phoneDeclaration = PrivacyNutritionLabel.declarations.first else {
            XCTFail("Expected phone number declaration")
            return
        }
        XCTAssertEqual(phoneDeclaration.purpose, .appFunctionality)
        XCTAssertEqual(phoneDeclaration.category, .contactInfo)
        XCTAssertFalse(phoneDeclaration.linkedToIdentity)
        XCTAssertFalse(phoneDeclaration.usedForTracking)
    }

    func testNotCollectedCategories() {
        let notCollected = PrivacyNutritionLabel.notCollected
        // Should not collect most data categories
        XCTAssertTrue(notCollected.contains(.financialInfo))
        XCTAssertTrue(notCollected.contains(.location))
        XCTAssertTrue(notCollected.contains(.browsingHistory))
        XCTAssertTrue(notCollected.contains(.identifiers))
        XCTAssertTrue(notCollected.contains(.usageData))
        XCTAssertTrue(notCollected.contains(.diagnostics))
    }

    func testReviewNotesNotEmpty() {
        XCTAssertFalse(PrivacyNutritionLabel.reviewNotes.isEmpty)
        XCTAssertTrue(PrivacyNutritionLabel.reviewNotes.contains("phone number"))
        XCTAssertTrue(PrivacyNutritionLabel.reviewNotes.contains("end-to-end encrypted"))
    }

    // MARK: - Export Compliance Tests

    func testUsesEncryption() {
        XCTAssertTrue(ExportCompliance.usesEncryption)
    }

    func testQualifiesForExemption() {
        XCTAssertTrue(ExportCompliance.qualifiesForExemption)
    }

    func testClassification() {
        XCTAssertEqual(ExportCompliance.classification, .ear5A992c)
    }

    func testAllAlgorithmsHaveStandards() {
        for algorithm in ExportCompliance.algorithms {
            XCTAssertFalse(algorithm.algorithm.isEmpty)
            XCTAssertFalse(algorithm.keySize.isEmpty)
            XCTAssertFalse(algorithm.purpose.isEmpty)
            XCTAssertFalse(algorithm.standard.isEmpty, "\(algorithm.algorithm) missing standard reference")
        }
    }

    func testRequiredAlgorithmsPresent() {
        let algorithmNames = ExportCompliance.algorithms.map(\.algorithm)
        XCTAssertTrue(algorithmNames.contains("AES-256-GCM"), "Must declare AES")
        XCTAssertTrue(algorithmNames.contains("X25519"), "Must declare X25519")
        XCTAssertTrue(algorithmNames.contains("Ed25519"), "Must declare Ed25519")
        XCTAssertTrue(algorithmNames.contains("ML-KEM-1024"), "Must declare ML-KEM")
        XCTAssertTrue(algorithmNames.contains("HKDF-SHA-512"), "Must declare HKDF")
    }

    func testAnnualReportRequirements() {
        XCTAssertFalse(ExportCompliance.annualReport.dueDate.isEmpty)
        XCTAssertFalse(ExportCompliance.annualReport.filingEmail.isEmpty)
        XCTAssertGreaterThan(ExportCompliance.annualReport.requiredFields.count, 0)
    }

    // MARK: - App Review Compliance Tests

    func testAllGuidelinesCompliant() {
        XCTAssertTrue(
            AppReviewCompliance.allCompliant,
            "All applicable App Review guidelines must be compliant"
        )
    }

    func testNoNeedsReviewItems() {
        let summary = AppReviewCompliance.complianceSummary
        XCTAssertEqual(summary.needsReview, 0, "No checks should be in 'needs review' state")
    }

    func testCriticalGuidelinesPresent() {
        let sections = AppReviewCompliance.checks.map(\.section)
        // Privacy
        XCTAssertTrue(sections.contains("5.1.1"), "Must address data collection guideline")
        XCTAssertTrue(sections.contains("5.1.2"), "Must address data sharing guideline")
        // Encryption
        XCTAssertTrue(sections.contains("5.2"), "Must address encryption export guideline")
        // Payments
        XCTAssertTrue(sections.contains("3.1.5(b)"), "Must address cryptocurrency guideline")
    }

    func testCryptocurrencyComplianceExplicit() {
        guard let cryptoCheck = AppReviewCompliance.checks.first(where: { $0.section == "3.1.5(b)" }) else {
            XCTFail("Missing cryptocurrency compliance check")
            return
        }
        XCTAssertEqual(cryptoCheck.status, .compliant)
        XCTAssertTrue(cryptoCheck.veilCompliance.contains("person-to-person"))
    }

    // MARK: - Screenshot Specifications

    func testScreenshotSpecsNotEmpty() {
        XCTAssertFalse(AppStoreMetadata.screenshotSpecs.isEmpty)
    }

    func testRequiredDeviceClassesPresent() {
        let required = AppStoreMetadata.screenshotSpecs.filter(\.required)
        XCTAssertGreaterThanOrEqual(required.count, 2, "Need at least 2 required device classes")
    }

    func testScreenshotScenesNotEmpty() {
        XCTAssertGreaterThanOrEqual(
            AppStoreMetadata.screenshotScenes.count, 3,
            "Need at least 3 screenshot scenes"
        )
    }

    // MARK: - Age Rating Tests

    func testAgeRatingAllNone() {
        for response in AppStoreMetadata.ageRatingResponses {
            XCTAssertEqual(
                response.answer, .none,
                "Age rating for '\(response.question)' should be 'None'"
            )
        }
    }

    func testExpectedAgeRating4Plus() {
        XCTAssertEqual(AppStoreMetadata.expectedAgeRating, "4+")
    }

    // MARK: - TestFlight Checklist Tests

    func testChecklistCoversAllCategories() {
        let coveredCategories = Set(TestFlightChecklist.allChecks.map(\.category))
        for category in TestFlightChecklist.Category.allCases {
            XCTAssertTrue(
                coveredCategories.contains(category),
                "Category \(category.rawValue) has no checks"
            )
        }
    }

    func testAllChecksHaveTickets() {
        for check in TestFlightChecklist.allChecks {
            XCTAssertFalse(
                check.tickets.isEmpty,
                "Check \(check.id) has no associated engineering tickets"
            )
        }
    }

    func testAllChecksPassed() {
        for check in TestFlightChecklist.allChecks {
            XCTAssertEqual(
                check.status, .passed,
                "Check \(check.id) (\(check.description)) is not passed"
            )
        }
    }

    func testNoBlockingFailures() {
        XCTAssertEqual(TestFlightChecklist.blockingFailures, 0)
    }

    func testTestFlightReady() {
        XCTAssertTrue(TestFlightChecklist.isTestFlightReady)
    }

    func testMinimumCheckCount() {
        XCTAssertGreaterThanOrEqual(
            TestFlightChecklist.totalChecks, 30,
            "Should have at least 30 validation checks"
        )
    }

    func testPerformanceBudgetsDefined() {
        XCTAssertGreaterThanOrEqual(
            TestFlightChecklist.performanceBudgets.count, 5,
            "Need at least 5 performance budgets"
        )
    }

    func testBetaGroupsDefined() {
        XCTAssertGreaterThanOrEqual(TestFlightChecklist.betaGroups.count, 2)
        let names = TestFlightChecklist.betaGroups.map(\.name)
        XCTAssertTrue(names.contains("Internal"))
        XCTAssertTrue(names.contains("Security Reviewers"))
    }

    // MARK: - Cross-Validation

    func testPrivacyLabelMatchesChecklist() {
        // The privacy checklist says no analytics, and the nutrition label should confirm
        XCTAssertFalse(PrivacyNutritionLabel.usesDataForTracking)
        let analyticsCheck = TestFlightChecklist.privacyChecks.first { $0.id == "PRIV-001" }
        XCTAssertNotNil(analyticsCheck)
        XCTAssertEqual(analyticsCheck?.status, .passed)
    }

    func testExportComplianceMatchesChecklist() {
        let encryptionCheck = TestFlightChecklist.securityChecks.first { check in
            check.tickets.contains("VEIL-901")
        }
        XCTAssertNotNil(encryptionCheck)
    }
}
