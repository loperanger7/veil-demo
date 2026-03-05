// PaymentStateMachineTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// VEIL-407: Tests for the payment state machine. Every state transition
// is exercised, invalid transitions are rejected, and serialization
// round-trips are verified.

import XCTest
@testable import VeilCrypto

final class PaymentStateMachineTests: XCTestCase {

    private func makeContext() -> PaymentContext {
        PaymentContext(
            recipientId: "bob-001",
            amountPicomob: 1_000_000_000_000,
            memo: "Test payment"
        )
    }

    private func makeEnvelope() -> TransactionEnvelope {
        TransactionEnvelope(
            serializedTransaction: Data(repeating: 0x02, count: 100),
            txHash: Data(repeating: 0xAB, count: 32),
            outputs: [],
            fee: 400_000_000,
            totalInputAmount: 1_400_000_000
        )
    }

    private func makeConfirmed() -> ConfirmedTransaction {
        ConfirmedTransaction(
            txHash: Data(repeating: 0xAB, count: 32),
            blockIndex: 12345,
            amount: 1_000_000_000_000,
            fee: 400_000_000
        )
    }

    // MARK: - Happy Path

    func testFullLifecycleHappyPath() async throws {
        let machine = PaymentStateMachine()
        let context = makeContext()
        let envelope = makeEnvelope()
        let confirmed = makeConfirmed()

        // Idle → ConstructingTx
        try await machine.beginConstruction(context: context)
        let state1 = await machine.currentState
        if case .constructingTx = state1 {} else {
            XCTFail("Expected constructingTx, got \(state1)")
        }

        // ConstructingTx → SubmittingTx
        try await machine.transactionBuilt(envelope: envelope)
        let state2 = await machine.currentState
        if case .submittingTx = state2 {} else {
            XCTFail("Expected submittingTx, got \(state2)")
        }

        // SubmittingTx → AwaitingConfirmation
        try await machine.transactionSubmitted()
        let state3 = await machine.currentState
        if case .awaitingConfirmation = state3 {} else {
            XCTFail("Expected awaitingConfirmation, got \(state3)")
        }

        // AwaitingConfirmation → SendingReceipt
        try await machine.transactionConfirmed(confirmed)
        let state4 = await machine.currentState
        if case .sendingReceipt = state4 {} else {
            XCTFail("Expected sendingReceipt, got \(state4)")
        }

        // SendingReceipt → Complete
        try await machine.receiptSent()
        let state5 = await machine.currentState
        if case .complete = state5 {} else {
            XCTFail("Expected complete, got \(state5)")
        }

        // Verify transitions logged
        let transitions = await machine.transitions
        XCTAssertEqual(transitions.count, 5, "Should have 5 transitions.")
        XCTAssertEqual(transitions[0].from, "idle")
        XCTAssertEqual(transitions[0].to, "constructingTx")
        XCTAssertEqual(transitions[4].from, "sendingReceipt")
        XCTAssertEqual(transitions[4].to, "complete")
    }

    // MARK: - Failure Transitions

    func testFailFromConstructingTx() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())
        try await machine.fail(reason: "Insufficient balance")

        let state = await machine.currentState
        if case .failed(_, let reason) = state {
            XCTAssertEqual(reason, "Insufficient balance")
        } else {
            XCTFail("Expected failed state.")
        }
    }

    func testFailFromSubmittingTx() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())
        try await machine.transactionBuilt(envelope: makeEnvelope())
        try await machine.fail(reason: "Network error")

        let state = await machine.currentState
        if case .failed = state {} else {
            XCTFail("Expected failed state.")
        }
    }

    func testFailFromAwaitingConfirmation() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())
        try await machine.transactionBuilt(envelope: makeEnvelope())
        try await machine.transactionSubmitted()
        try await machine.fail(reason: "Confirmation timeout")

        let state = await machine.currentState
        if case .failed(_, let reason) = state {
            XCTAssertEqual(reason, "Confirmation timeout")
        } else {
            XCTFail("Expected failed state.")
        }
    }

    // MARK: - Invalid Transitions

    func testCannotBuildFromIdle() async throws {
        let machine = PaymentStateMachine()

        do {
            try await machine.transactionBuilt(envelope: makeEnvelope())
            XCTFail("Should throw for idle → submittingTx.")
        } catch let error as MobileCoinError {
            if case .invalidStateTransition(let from, let to) = error {
                XCTAssertEqual(from, "idle")
                XCTAssertEqual(to, "submittingTx")
            } else {
                XCTFail("Expected invalidStateTransition.")
            }
        }
    }

    func testCannotSubmitFromIdle() async {
        let machine = PaymentStateMachine()

        do {
            try await machine.transactionSubmitted()
            XCTFail("Should throw for idle → awaitingConfirmation.")
        } catch {
            // Expected
        }
    }

    func testCannotConfirmFromIdle() async {
        let machine = PaymentStateMachine()

        do {
            try await machine.transactionConfirmed(makeConfirmed())
            XCTFail("Should throw.")
        } catch {
            // Expected
        }
    }

    func testCannotSendReceiptFromIdle() async {
        let machine = PaymentStateMachine()

        do {
            try await machine.receiptSent()
            XCTFail("Should throw.")
        } catch {
            // Expected
        }
    }

    func testCannotFailFromComplete() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())
        try await machine.transactionBuilt(envelope: makeEnvelope())
        try await machine.transactionSubmitted()
        try await machine.transactionConfirmed(makeConfirmed())
        try await machine.receiptSent()

        do {
            try await machine.fail(reason: "Should not work")
            XCTFail("Should not be able to fail from complete.")
        } catch let error as MobileCoinError {
            if case .invalidStateTransition = error {} else {
                XCTFail("Expected invalidStateTransition.")
            }
        }
    }

    func testCannotFailFromFailed() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())
        try await machine.fail(reason: "First failure")

        do {
            try await machine.fail(reason: "Second failure")
            XCTFail("Should not be able to fail from failed.")
        } catch {
            // Expected
        }
    }

    // MARK: - Reset

    func testResetFromComplete() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())
        try await machine.transactionBuilt(envelope: makeEnvelope())
        try await machine.transactionSubmitted()
        try await machine.transactionConfirmed(makeConfirmed())
        try await machine.receiptSent()

        try await machine.reset()

        let state = await machine.currentState
        if case .idle = state {} else {
            XCTFail("Should be idle after reset.")
        }

        let transitions = await machine.transitions
        XCTAssertTrue(transitions.isEmpty, "Transitions should be cleared on reset.")
    }

    func testResetFromFailed() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())
        try await machine.fail(reason: "Test failure")

        try await machine.reset()

        let state = await machine.currentState
        if case .idle = state {} else {
            XCTFail("Should be idle after reset.")
        }
    }

    func testCannotResetFromNonTerminal() async throws {
        let machine = PaymentStateMachine()
        try await machine.beginConstruction(context: makeContext())

        do {
            try await machine.reset()
            XCTFail("Should not reset from non-terminal state.")
        } catch {
            // Expected
        }
    }

    // MARK: - Terminal State Detection

    func testIsTerminal() {
        let context = makeContext()

        XCTAssertFalse(PaymentState.idle.isTerminal)
        XCTAssertFalse(PaymentState.constructingTx(context: context).isTerminal)
        XCTAssertTrue(PaymentState.failed(context: context, reason: "x").isTerminal)

        let confRef = ConfirmationRef(txHash: Data(), blockIndex: 1)
        XCTAssertTrue(PaymentState.complete(context: context, confirmation: confRef).isTerminal)
    }

    // MARK: - Display Status

    func testDisplayStatus() {
        XCTAssertEqual(PaymentState.idle.displayStatus, "Ready")
        XCTAssertTrue(
            PaymentState.failed(context: nil, reason: "timeout").displayStatus.contains("timeout")
        )
    }

    // MARK: - Codable Round-Trip

    func testPaymentStateCodableRoundTrip() throws {
        let context = makeContext()
        let states: [PaymentState] = [
            .idle,
            .constructingTx(context: context),
            .failed(context: context, reason: "test error"),
        ]

        for state in states {
            let data = try JSONEncoder().encode(state)
            let decoded = try JSONDecoder().decode(PaymentState.self, from: data)
            XCTAssertEqual(decoded, state, "Codable round-trip failed for \(state.displayStatus)")
        }
    }

    func testPaymentContextCodableRoundTrip() throws {
        let context = makeContext()
        let data = try JSONEncoder().encode(context)
        let decoded = try JSONDecoder().decode(PaymentContext.self, from: data)

        XCTAssertEqual(decoded.recipientId, context.recipientId)
        XCTAssertEqual(decoded.amountPicomob, context.amountPicomob)
        XCTAssertEqual(decoded.memo, context.memo)
    }

    func testPersistedPaymentStateCodable() throws {
        let persisted = PersistedPaymentState(
            state: .idle,
            transitions: [
                PaymentTransition(from: "idle", to: "constructingTx")
            ]
        )

        let data = try JSONEncoder().encode(persisted)
        let decoded = try JSONDecoder().decode(PersistedPaymentState.self, from: data)

        XCTAssertEqual(decoded.state, .idle)
        XCTAssertEqual(decoded.transitions.count, 1)
    }
}
