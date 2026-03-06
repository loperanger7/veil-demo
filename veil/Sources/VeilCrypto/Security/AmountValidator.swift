// VEIL — AmountValidator.swift
// Ticket: VEIL-901 — Security Hardening (Red Team Finding: Insufficient Amount Validation)
// Spec reference: Section 8.3 (Payment State Machine)
//
// HIGH FIX: The UI previously allowed sending 0.0 MOB, had no minimum amount
// check, no UInt64 overflow protection, and string-to-picoMOB conversion was
// unsafe. This module adds comprehensive amount validation with:
//   - Dust threshold (minimum 0.000001 MOB = 1,000,000 picoMOB)
//   - Per-transaction maximum (250 MOB)
//   - UInt64 overflow protection on fee addition
//   - Safe MOB ↔ picoMOB conversion
//   - Newtype wrapper for validated amounts

import Foundation

// MARK: - Validated Amount

/// A payment amount that has passed all validation checks.
///
/// This newtype wrapper ensures that only validated amounts can be passed
/// to the payment state machine. It cannot be constructed directly —
/// only through `PaymentAmountValidator.validate()`.
public struct ValidatedAmount: Sendable, Equatable, Comparable {
    /// The validated amount in picoMOB.
    public let picomob: UInt64

    /// Internal initializer — only callable from AmountValidator.
    fileprivate init(picomob: UInt64) {
        self.picomob = picomob
    }

    /// Amount in MOB (for display purposes).
    public var inMOB: Double {
        Double(picomob) / Double(MobileCoinConstants.picoMOBPerMOB)
    }

    /// Formatted display string.
    public var displayString: String {
        let mob = inMOB
        if mob >= 1.0 {
            return String(format: "%.4f MOB", mob)
        } else if mob >= 0.001 {
            return String(format: "%.6f MOB", mob)
        } else {
            return String(format: "%.12f MOB", mob)
        }
    }

    public static func < (lhs: ValidatedAmount, rhs: ValidatedAmount) -> Bool {
        lhs.picomob < rhs.picomob
    }
}

// MARK: - Amount Errors

/// Errors that can occur during payment amount validation.
public enum AmountError: Error, Sendable, Equatable {
    /// Amount is zero.
    case zeroAmount
    /// Amount is below the dust threshold.
    case belowDustThreshold(minimum: UInt64)
    /// Amount exceeds the per-transaction maximum.
    case exceedsMaximum(maximum: UInt64)
    /// Adding the fee would overflow UInt64.
    case feeOverflow(amount: UInt64, fee: UInt64)
    /// The amount overflows UInt64 (e.g., from string conversion).
    case overflow
    /// Invalid string format for MOB amount.
    case invalidFormat(String)
    /// Negative amount (from floating-point conversion).
    case negativeAmount
}

// MARK: - Amount Validator

/// Validates payment amounts with comprehensive bounds checking.
///
/// Enforces:
///   - Minimum: 1,000,000 picoMOB (0.000001 MOB, dust threshold)
///   - Maximum: 250,000,000,000,000 picoMOB (250 MOB, per-tx limit)
///   - Fee overflow: amount + fee must not exceed UInt64.max
///   - Safe conversions from MOB (Double) and string representations
public struct PaymentAmountValidator: Sendable {

    /// Minimum amount in picoMOB (0.000001 MOB = dust threshold).
    public static let minimumPicomob: UInt64 = 1_000_000

    /// Maximum amount in picoMOB (250 MOB per transaction).
    public static let maximumPicomob: UInt64 = 250_000_000_000_000

    /// Standard network fee in picoMOB (0.0004 MOB).
    public static let standardFee: UInt64 = 400_000_000

    public init() {}

    // MARK: - Validation

    /// Validate a payment amount in picoMOB.
    ///
    /// - Parameter picomob: The amount to validate.
    /// - Returns: A `ValidatedAmount` if valid, or an error.
    public func validate(picomob: UInt64) -> Result<ValidatedAmount, AmountError> {
        // Zero check
        guard picomob > 0 else {
            return .failure(.zeroAmount)
        }

        // Dust threshold
        guard picomob >= Self.minimumPicomob else {
            return .failure(.belowDustThreshold(minimum: Self.minimumPicomob))
        }

        // Maximum check
        guard picomob <= Self.maximumPicomob else {
            return .failure(.exceedsMaximum(maximum: Self.maximumPicomob))
        }

        return .success(ValidatedAmount(picomob: picomob))
    }

    /// Validate a payment amount and check that adding the fee doesn't overflow.
    ///
    /// - Parameters:
    ///   - picomob: The payment amount.
    ///   - fee: The transaction fee (defaults to standard fee).
    /// - Returns: A `ValidatedAmount` if valid, or an error.
    public func validateWithFee(
        picomob: UInt64,
        fee: UInt64 = standardFee
    ) -> Result<ValidatedAmount, AmountError> {
        // First validate the amount itself
        let result = validate(picomob: picomob)
        guard case .success(let validated) = result else {
            return result
        }

        // Check for overflow when adding fee
        let (total, overflow) = validated.picomob.addingReportingOverflow(fee)
        guard !overflow else {
            return .failure(.feeOverflow(amount: picomob, fee: fee))
        }

        // Also check total doesn't exceed maximum (amount + fee should be payable)
        guard total <= UInt64.max else {
            return .failure(.feeOverflow(amount: picomob, fee: fee))
        }

        return .success(validated)
    }

    /// Validate a payment amount from a MOB decimal value.
    ///
    /// - Parameter mob: The amount in MOB (e.g., 1.5 for 1.5 MOB).
    /// - Returns: A `ValidatedAmount` if valid, or an error.
    public func validateFromMOB(_ mob: Double) -> Result<ValidatedAmount, AmountError> {
        // Check for negative
        guard mob >= 0 else {
            return .failure(.negativeAmount)
        }

        // Check for zero (before conversion to avoid floating-point issues)
        guard mob > 0 else {
            return .failure(.zeroAmount)
        }

        // Convert to picoMOB with overflow protection
        let picomobDouble = mob * Double(MobileCoinConstants.picoMOBPerMOB)

        // Check for overflow
        guard picomobDouble < Double(UInt64.max) else {
            return .failure(.overflow)
        }

        let picomob = UInt64(picomobDouble)
        return validate(picomob: picomob)
    }

    /// Validate a payment amount from a string representation.
    ///
    /// Accepts formats: "1.5", "1.5 MOB", "1500000000000" (picoMOB)
    ///
    /// - Parameter string: The amount string.
    /// - Returns: A `ValidatedAmount` if valid, or an error.
    public func validateFromString(_ string: String) -> Result<ValidatedAmount, AmountError> {
        let trimmed = string.trimmingCharacters(in: .whitespaces)
            .replacingOccurrences(of: " MOB", with: "")
            .replacingOccurrences(of: " mob", with: "")
            .replacingOccurrences(of: ",", with: "")

        // Try as integer (picoMOB) first
        if let picomob = UInt64(trimmed) {
            return validate(picomob: picomob)
        }

        // Try as decimal (MOB)
        if let mob = Double(trimmed) {
            return validateFromMOB(mob)
        }

        return .failure(.invalidFormat(string))
    }

    // MARK: - Safe Conversion

    /// Safely convert picoMOB to MOB with precision preservation.
    public static func picomobToMOB(_ picomob: UInt64) -> Double {
        Double(picomob) / Double(MobileCoinConstants.picoMOBPerMOB)
    }

    /// Safely convert MOB to picoMOB with overflow checking.
    public static func mobToPicomob(_ mob: Double) -> UInt64? {
        guard mob >= 0 else { return nil }
        let result = mob * Double(MobileCoinConstants.picoMOBPerMOB)
        guard result < Double(UInt64.max) else { return nil }
        return UInt64(result)
    }
}
