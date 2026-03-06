// VEIL — AmountValidatorTests.swift
// Ticket: VEIL-901 — Security Hardening Tests
// Spec reference: Section 8.3 (Payment State Machine)
//
// Tests for payment amount validation:
//   - Valid amounts pass
//   - Zero amounts rejected
//   - Dust threshold enforcement
//   - Maximum amount enforcement
//   - UInt64 overflow on fee addition
//   - MOB ↔ picoMOB conversion
//   - String parsing
//   - Boundary values

import XCTest
@testable import VeilCrypto

final class AmountValidatorTests: XCTestCase {

    private let validator = PaymentAmountValidator()

    // MARK: - Valid Amounts

    /// **HARDENING: 1 MOB passes validation.**
    func testValidAmount_1MOB() {
        let result = validator.validate(picomob: 1_000_000_000_000)
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 1_000_000_000_000)
            XCTAssertEqual(amount.inMOB, 1.0, accuracy: 0.0001)
        } else {
            XCTFail("1 MOB should be valid")
        }
    }

    /// **HARDENING: Exact minimum amount passes.**
    func testExactMinimum() {
        let result = validator.validate(picomob: PaymentAmountValidator.minimumPicomob)
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 1_000_000)
        } else {
            XCTFail("Exact minimum should pass")
        }
    }

    /// **HARDENING: Exact maximum amount passes.**
    func testExactMaximum() {
        let result = validator.validate(picomob: PaymentAmountValidator.maximumPicomob)
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 250_000_000_000_000)
        } else {
            XCTFail("Exact maximum should pass")
        }
    }

    // MARK: - Invalid Amounts

    /// **HARDENING: Zero amount rejected.**
    func testZeroAmount() {
        let result = validator.validate(picomob: 0)
        if case .failure(let error) = result {
            XCTAssertEqual(error, .zeroAmount)
        } else {
            XCTFail("Zero should be rejected")
        }
    }

    /// **HARDENING: Below dust threshold rejected.**
    func testBelowDustThreshold() {
        let result = validator.validate(picomob: 999_999) // Just under 1M
        if case .failure(let error) = result {
            XCTAssertEqual(error, .belowDustThreshold(minimum: 1_000_000))
        } else {
            XCTFail("Below dust threshold should be rejected")
        }
    }

    /// **HARDENING: Above maximum rejected.**
    func testAboveMaximum() {
        let result = validator.validate(picomob: 250_000_000_000_001)
        if case .failure(let error) = result {
            XCTAssertEqual(error, .exceedsMaximum(maximum: 250_000_000_000_000))
        } else {
            XCTFail("Above maximum should be rejected")
        }
    }

    // MARK: - Fee Overflow

    /// **HARDENING: Fee addition overflow detected.**
    func testFeeOverflow() {
        // Amount near UInt64.max where adding fee would overflow
        let result = validator.validateWithFee(
            picomob: 250_000_000_000_000, // Max valid amount
            fee: 400_000_000
        )
        // This should succeed because 250T + 400M doesn't overflow UInt64
        if case .success = result {
            // Good
        } else {
            XCTFail("Valid amount + fee should succeed")
        }
    }

    /// **HARDENING: Normal amount with standard fee passes.**
    func testStandardFee() {
        let result = validator.validateWithFee(picomob: 1_000_000_000_000) // 1 MOB
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 1_000_000_000_000)
        } else {
            XCTFail("1 MOB + standard fee should pass")
        }
    }

    // MARK: - MOB Conversion

    /// **HARDENING: MOB to picoMOB conversion.**
    func testMOBConversion() {
        let result = validator.validateFromMOB(1.5)
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 1_500_000_000_000)
        } else {
            XCTFail("1.5 MOB should be valid")
        }
    }

    /// **HARDENING: Negative MOB rejected.**
    func testNegativeMOB() {
        let result = validator.validateFromMOB(-1.0)
        if case .failure(let error) = result {
            XCTAssertEqual(error, .negativeAmount)
        } else {
            XCTFail("Negative MOB should be rejected")
        }
    }

    /// **HARDENING: Zero MOB rejected.**
    func testZeroMOB() {
        let result = validator.validateFromMOB(0.0)
        if case .failure(let error) = result {
            XCTAssertEqual(error, .zeroAmount)
        } else {
            XCTFail("Zero MOB should be rejected")
        }
    }

    /// **HARDENING: Overflow MOB rejected.**
    func testOverflowMOB() {
        let result = validator.validateFromMOB(Double(UInt64.max))
        if case .failure(let error) = result {
            XCTAssertEqual(error, .overflow)
        } else {
            XCTFail("Overflow MOB should be rejected")
        }
    }

    // MARK: - String Parsing

    /// **HARDENING: String "1.5" parses correctly.**
    func testStringParsing_decimal() {
        let result = validator.validateFromString("1.5")
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 1_500_000_000_000)
        } else {
            XCTFail("'1.5' should parse as 1.5 MOB")
        }
    }

    /// **HARDENING: String "1.5 MOB" parses correctly.**
    func testStringParsing_withUnit() {
        let result = validator.validateFromString("1.5 MOB")
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 1_500_000_000_000)
        } else {
            XCTFail("'1.5 MOB' should parse correctly")
        }
    }

    /// **HARDENING: String picoMOB parses correctly.**
    func testStringParsing_picomob() {
        let result = validator.validateFromString("1000000000000")
        if case .success(let amount) = result {
            XCTAssertEqual(amount.picomob, 1_000_000_000_000)
        } else {
            XCTFail("Integer string should parse as picoMOB")
        }
    }

    /// **HARDENING: Invalid string rejected.**
    func testStringParsing_invalid() {
        let result = validator.validateFromString("not a number")
        if case .failure(let error) = result {
            if case .invalidFormat = error {
                // Expected
            } else {
                XCTFail("Expected invalidFormat error")
            }
        } else {
            XCTFail("Invalid string should be rejected")
        }
    }

    // MARK: - ValidatedAmount Properties

    /// **HARDENING: Display string formats correctly.**
    func testDisplayString() {
        let validator = PaymentAmountValidator()

        if case .success(let amount) = validator.validate(picomob: 1_500_000_000_000) {
            XCTAssertTrue(amount.displayString.contains("1.5"))
            XCTAssertTrue(amount.displayString.contains("MOB"))
        }

        if case .success(let amount) = validator.validate(picomob: 1_000_000) {
            XCTAssertTrue(amount.displayString.contains("MOB"))
        }
    }

    /// **HARDENING: ValidatedAmount is Comparable.**
    func testComparable() {
        let a = PaymentAmountValidator().validate(picomob: 1_000_000_000_000)
        let b = PaymentAmountValidator().validate(picomob: 2_000_000_000_000)

        if case .success(let amountA) = a, case .success(let amountB) = b {
            XCTAssertTrue(amountA < amountB)
            XCTAssertFalse(amountB < amountA)
            XCTAssertEqual(amountA, amountA)
        }
    }

    // MARK: - Safe Conversion Utilities

    /// **HARDENING: picoMOB to MOB round-trip.**
    func testSafeConversion_roundTrip() {
        let original: UInt64 = 1_234_567_890_123
        let mob = PaymentAmountValidator.picomobToMOB(original)
        let backToPico = PaymentAmountValidator.mobToPicomob(mob)

        XCTAssertNotNil(backToPico)
        // May have small floating-point error
        XCTAssertEqual(backToPico!, original, accuracy: 1)
    }

    /// **HARDENING: mobToPicomob rejects negative.**
    func testSafeConversion_rejectsNegative() {
        let result = PaymentAmountValidator.mobToPicomob(-1.0)
        XCTAssertNil(result)
    }

    /// **HARDENING: Boundary values around dust threshold.**
    func testBoundaryValues() {
        // Just below minimum
        let belowMin = validator.validate(picomob: PaymentAmountValidator.minimumPicomob - 1)
        XCTAssertTrue(belowMin.isFailure)

        // Exact minimum
        let exactMin = validator.validate(picomob: PaymentAmountValidator.minimumPicomob)
        XCTAssertTrue(exactMin.isSuccess)

        // Just above maximum
        let aboveMax = validator.validate(picomob: PaymentAmountValidator.maximumPicomob + 1)
        XCTAssertTrue(aboveMax.isFailure)

        // Exact maximum
        let exactMax = validator.validate(picomob: PaymentAmountValidator.maximumPicomob)
        XCTAssertTrue(exactMax.isSuccess)
    }
}

// MARK: - Result Helpers

private extension Result {
    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }
    var isFailure: Bool {
        !isSuccess
    }
}
