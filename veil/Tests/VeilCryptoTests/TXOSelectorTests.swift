// TXOSelectorTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// VEIL-403 (partial): Tests for TXO coin selection algorithm.

import XCTest
@testable import VeilCrypto

final class TXOSelectorTests: XCTestCase {

    private var selector: TXOSelector!

    override func setUp() {
        // Use a small fixed fee for predictable tests
        selector = TXOSelector(feeCalculator: FixedFeeCalculator(fee: 1000))
    }

    // MARK: - Helpers

    private func makeTXO(amount: UInt64, index: Int = 0) -> UnspentTXO {
        UnspentTXO(
            txoPublicKey: Data(repeating: UInt8(index & 0xFF), count: 32),
            amount: amount,
            blockIndex: 100
        )
    }

    // MARK: - Basic Selection

    func testSelectSingleTXOExactAmount() throws {
        let txos = [makeTXO(amount: 5000, index: 0)]
        let result = try selector.select(targetAmount: 4000, from: txos)

        XCTAssertEqual(result.selectedTXOs.count, 1)
        XCTAssertEqual(result.targetAmount, 4000)
        XCTAssertEqual(result.fee, 1000)
        XCTAssertEqual(result.change, 0) // 5000 - 4000 - 1000 = 0
        XCTAssertTrue(result.isBalanced)
    }

    func testSelectWithChange() throws {
        let txos = [makeTXO(amount: 10000, index: 0)]
        let result = try selector.select(targetAmount: 3000, from: txos)

        XCTAssertEqual(result.change, 6000) // 10000 - 3000 - 1000 = 6000
        XCTAssertTrue(result.isBalanced)
    }

    func testSelectMultipleTXOs() throws {
        let txos = [
            makeTXO(amount: 3000, index: 0),
            makeTXO(amount: 2000, index: 1),
            makeTXO(amount: 4000, index: 2),
        ]
        let result = try selector.select(targetAmount: 5000, from: txos)

        // Greedy: picks 4000 first, then 3000 = 7000 >= 5000 + 1000
        XCTAssertEqual(result.selectedTXOs.count, 2)
        XCTAssertEqual(result.totalInputAmount, 7000)
        XCTAssertEqual(result.change, 1000) // 7000 - 5000 - 1000
        XCTAssertTrue(result.isBalanced)
    }

    // MARK: - Greedy Ordering

    func testGreedySelectsLargestFirst() throws {
        let txos = [
            makeTXO(amount: 1000, index: 0),
            makeTXO(amount: 5000, index: 1),
            makeTXO(amount: 2000, index: 2),
        ]
        let result = try selector.select(targetAmount: 4000, from: txos)

        // Should pick 5000 (largest) first — sufficient alone
        XCTAssertEqual(result.selectedTXOs.count, 1)
        XCTAssertEqual(result.selectedTXOs[0].amount, 5000)
    }

    // MARK: - Edge Cases

    func testInsufficientBalanceThrows() {
        let txos = [makeTXO(amount: 500, index: 0)]

        XCTAssertThrowsError(try selector.select(targetAmount: 1000, from: txos)) { error in
            guard case MobileCoinError.insufficientBalance(let avail, let req) = error as? MobileCoinError else {
                XCTFail("Expected insufficientBalance error"); return
            }
            XCTAssertEqual(avail, 500)
            XCTAssertEqual(req, 2000) // 1000 + 1000 fee
        }
    }

    func testNoUnspentTXOsThrows() {
        XCTAssertThrowsError(try selector.select(targetAmount: 100, from: [])) { error in
            XCTAssertEqual(error as? MobileCoinError, .noUnspentTXOs)
        }
    }

    func testSpentTXOsAreFiltered() throws {
        let unspent = makeTXO(amount: 5000, index: 0)
        let spent = UnspentTXO(
            txoPublicKey: Data(repeating: 0x01, count: 32),
            amount: 10000,
            blockIndex: 100,
            isSpent: true
        )

        let result = try selector.select(targetAmount: 2000, from: [unspent, spent])

        // Only the unspent TXO should be selected
        XCTAssertEqual(result.selectedTXOs.count, 1)
        XCTAssertEqual(result.selectedTXOs[0].amount, 5000)
    }

    // MARK: - Balance Invariant

    func testSelectionInvariantHolds() throws {
        // Property: totalInput == target + fee + change
        for target in stride(from: UInt64(100), to: 9000, by: 500) {
            let txos = [
                makeTXO(amount: 3000, index: 0),
                makeTXO(amount: 4000, index: 1),
                makeTXO(amount: 5000, index: 2),
            ]

            let result = try selector.select(targetAmount: target, from: txos)
            XCTAssertTrue(result.isBalanced,
                          "Invariant violated for target \(target): \(result.totalInputAmount) != \(target) + \(result.fee) + \(result.change)")
        }
    }

    // MARK: - Can Afford

    func testCanAffordReturnsTrue() {
        let txos = [makeTXO(amount: 5000)]
        XCTAssertTrue(selector.canAfford(amount: 3000, from: txos))
    }

    func testCanAffordReturnsFalse() {
        let txos = [makeTXO(amount: 500)]
        XCTAssertFalse(selector.canAfford(amount: 3000, from: txos))
    }

    // MARK: - Proportional Fee Calculator

    func testProportionalFeeIncreasesWithInputs() {
        let calc = ProportionalFeeCalculator(
            baseFee: 1000,
            perInputFee: 500
        )

        XCTAssertEqual(calc.calculateFee(inputCount: 1, outputCount: 2), 1000)
        XCTAssertEqual(calc.calculateFee(inputCount: 2, outputCount: 2), 1500)
        XCTAssertEqual(calc.calculateFee(inputCount: 3, outputCount: 2), 2000)
    }
}
