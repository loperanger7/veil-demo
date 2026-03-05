// TXOSelector.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-403 (partial): Coin selection algorithm for MobileCoin transactions.
// Selects unspent TXOs sufficient to cover the payment amount plus network fee.
//
// Strategy: Greedy selection (largest-first) to minimize the number of inputs,
// which reduces transaction size, ring signature computation, and fees.
//
// Invariant: sum(selected) >= targetAmount + fee
//
// References: Veil Spec Section 8.3

import Foundation

// MARK: - TXO Selector

/// Selects unspent TXOs for transaction construction.
///
/// The selector uses a greedy largest-first strategy:
/// 1. Sort available TXOs by amount descending
/// 2. Accumulate until total >= target + fee
/// 3. Compute change (total - target - fee)
///
/// This minimizes input count, which directly impacts:
/// - Ring signature computation time
/// - Transaction size (bytes)
/// - Network fee (proportional to inputs)
public struct TXOSelector: Sendable {

    // MARK: Properties

    /// Fee calculator — can be overridden for testing.
    private let feeCalculator: FeeCalculator

    // MARK: Initialization

    /// Create a selector with a custom fee calculator.
    /// - Parameter feeCalculator: Fee calculation strategy (default: fixed minimum fee).
    public init(feeCalculator: FeeCalculator = FixedFeeCalculator()) {
        self.feeCalculator = feeCalculator
    }

    // MARK: Selection

    /// Select TXOs sufficient to cover the payment amount plus fee.
    ///
    /// - Parameters:
    ///   - targetAmount: The amount to send in picoMOB (excluding fee).
    ///   - availableTXOs: All unspent TXOs in the wallet.
    /// - Returns: A `SelectionResult` containing selected TXOs, fee, and change.
    /// - Throws: `MobileCoinError.insufficientBalance` or `.noUnspentTXOs`.
    public func select(
        targetAmount: UInt64,
        from availableTXOs: [UnspentTXO]
    ) throws -> SelectionResult {
        // Filter out spent TXOs
        let unspent = availableTXOs.filter { !$0.isSpent }

        guard !unspent.isEmpty else {
            throw MobileCoinError.noUnspentTXOs
        }

        // Calculate total available balance
        let totalAvailable = unspent.reduce(UInt64(0)) { $0 + $1.amount }

        // Estimate fee for single-input case (will adjust if more inputs needed)
        var estimatedFee = feeCalculator.calculateFee(inputCount: 1, outputCount: 2)

        // Check if total balance is sufficient
        guard totalAvailable >= targetAmount + estimatedFee else {
            throw MobileCoinError.insufficientBalance(
                available: totalAvailable,
                required: targetAmount + estimatedFee
            )
        }

        // Sort by amount descending (greedy: pick largest first)
        let sorted = unspent.sorted { $0.amount > $1.amount }

        // Greedy accumulation
        var selected: [UnspentTXO] = []
        var accumulated: UInt64 = 0

        for txo in sorted {
            selected.append(txo)
            accumulated += txo.amount

            // Recalculate fee based on actual input count
            // MobileCoin: 2 outputs (recipient + change)
            estimatedFee = feeCalculator.calculateFee(
                inputCount: selected.count,
                outputCount: 2
            )

            if accumulated >= targetAmount + estimatedFee {
                break
            }
        }

        // Final check (should always pass due to guard above)
        guard accumulated >= targetAmount + estimatedFee else {
            throw MobileCoinError.insufficientBalance(
                available: totalAvailable,
                required: targetAmount + estimatedFee
            )
        }

        // Compute change
        let change = accumulated - targetAmount - estimatedFee

        return SelectionResult(
            selectedTXOs: selected,
            targetAmount: targetAmount,
            fee: estimatedFee,
            change: change,
            totalInputAmount: accumulated
        )
    }

    /// Check if a payment of the given amount is possible.
    /// - Parameters:
    ///   - amount: Target payment amount in picoMOB.
    ///   - availableTXOs: All unspent TXOs.
    /// - Returns: `true` if sufficient funds are available.
    public func canAfford(
        amount: UInt64,
        from availableTXOs: [UnspentTXO]
    ) -> Bool {
        let unspent = availableTXOs.filter { !$0.isSpent }
        let total = unspent.reduce(UInt64(0)) { $0 + $1.amount }
        let fee = feeCalculator.calculateFee(inputCount: 1, outputCount: 2)
        return total >= amount + fee
    }
}

// MARK: - Selection Result

/// The result of TXO selection.
public struct SelectionResult: Sendable, Equatable {

    /// TXOs selected for spending.
    public let selectedTXOs: [UnspentTXO]

    /// Target payment amount in picoMOB.
    public let targetAmount: UInt64

    /// Network fee in picoMOB.
    public let fee: UInt64

    /// Change amount returned to sender in picoMOB.
    public let change: UInt64

    /// Total input amount (sum of all selected TXOs).
    public let totalInputAmount: UInt64

    /// Number of inputs.
    public var inputCount: Int { selectedTXOs.count }

    /// Verify the selection invariant: totalInput == target + fee + change.
    public var isBalanced: Bool {
        totalInputAmount == targetAmount + fee + change
    }
}

// MARK: - Fee Calculator Protocol

/// Abstraction for fee calculation strategies.
public protocol FeeCalculator: Sendable {
    /// Calculate the network fee for a transaction.
    /// - Parameters:
    ///   - inputCount: Number of transaction inputs.
    ///   - outputCount: Number of transaction outputs.
    /// - Returns: Fee in picoMOB.
    func calculateFee(inputCount: Int, outputCount: Int) -> UInt64
}

// MARK: - Fixed Fee Calculator

/// Uses the MobileCoin minimum fee regardless of transaction shape.
/// This is the current mainnet behavior (fee is fixed per transaction).
public struct FixedFeeCalculator: FeeCalculator {

    private let fixedFee: UInt64

    /// Create a calculator with a fixed fee.
    /// - Parameter fee: Fee in picoMOB (default: MobileCoin minimum).
    public init(fee: UInt64 = MobileCoinConstants.minimumFee) {
        self.fixedFee = fee
    }

    public func calculateFee(inputCount: Int, outputCount: Int) -> UInt64 {
        fixedFee
    }
}

// MARK: - Proportional Fee Calculator

/// Fee scales linearly with input count (for future MobileCoin fee models).
public struct ProportionalFeeCalculator: FeeCalculator {

    private let baseFee: UInt64
    private let perInputFee: UInt64

    public init(
        baseFee: UInt64 = MobileCoinConstants.minimumFee,
        perInputFee: UInt64 = 100_000_000 // 0.0001 MOB per additional input
    ) {
        self.baseFee = baseFee
        self.perInputFee = perInputFee
    }

    public func calculateFee(inputCount: Int, outputCount: Int) -> UInt64 {
        baseFee + UInt64(max(0, inputCount - 1)) * perInputFee
    }
}
