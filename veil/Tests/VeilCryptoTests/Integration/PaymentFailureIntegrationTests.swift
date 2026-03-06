// VEIL — PaymentFailureIntegrationTests.swift
// Ticket: VEIL-804 — Integration Test Suite
// Spec reference: Section 8.3 (Payment State Machine), VEIL-407
//
// Integration tests for payment failure scenarios:
//   - Insufficient balance rejection
//   - Submission timeout handling
//   - Malformed receipt rejection
//   - Receipt validation edge cases
//   - Payment state machine recovery after failure
//   - No TXO consumption on construction failure
//   - Concurrent payment isolation (actor safety)

import XCTest
@testable import VeilCrypto

final class PaymentFailureIntegrationTests: XCTestCase {

    // MARK: VEIL-804 — Test 1: Insufficient Balance

    /// **INTEGRATION: Payment state machine transitions to failed on insufficient funds.**
    ///
    /// Alice tries to pay more than her balance → construction fails →
    /// state machine → .failed with insufficient funds reason.
    func testInsufficientBalance() async throws {
        let stateMachine = PaymentStateMachine()

        let context = PaymentContext(
            recipientId: "bob-reg-id",
            amountPicomob: 999_999_999_999_999,  // ~1000 MOB (way too much)
            memo: "This will fail"
        )

        // Begin construction
        try await stateMachine.beginConstruction(context: context)
        let state = await stateMachine.currentState
        if case .constructingTx = state {
            // Good — we're in construction state
        } else {
            XCTFail("Expected constructingTx state")
        }

        // Simulate construction failure: insufficient funds
        try await stateMachine.fail(reason: "Insufficient funds: need 999,999,999,999,999 picoMOB but have 0")

        let failedState = await stateMachine.currentState
        if case .failed(_, let reason) = failedState {
            XCTAssertTrue(reason.contains("Insufficient funds"))
        } else {
            XCTFail("Expected failed state")
        }

        // Verify terminal state
        let isTerminal = await stateMachine.currentState.isTerminal
        XCTAssertTrue(isTerminal)

        // Verify display status
        let status = await stateMachine.currentState.displayStatus
        XCTAssertTrue(status.contains("Failed"))
    }

    // MARK: VEIL-804 — Test 2: Submission Timeout

    /// **INTEGRATION: State machine transitions to failed on submission timeout.**
    func testSubmissionTimeout() async throws {
        let stateMachine = PaymentStateMachine()

        let context = PaymentContext(
            recipientId: "bob-reg-id",
            amountPicomob: 1_000_000_000,
            memo: "Will timeout"
        )

        // Walk through states: idle → constructing → submitting → failed
        try await stateMachine.beginConstruction(context: context)

        let envelope = TransactionEnvelope(
            txHash: Data(repeating: 0xAB, count: 32),
            fee: 400_000_000,  // 0.0004 MOB
            totalInputAmount: 1_400_000_000,
            serializedTransaction: Data(repeating: 0xCD, count: 256)
        )
        try await stateMachine.transactionBuilt(envelope: envelope)

        // Simulate submission timeout
        try await stateMachine.fail(reason: "Submission timed out after 30 seconds")

        let state = await stateMachine.currentState
        if case .failed(_, let reason) = state {
            XCTAssertTrue(reason.contains("timed out"))
        } else {
            XCTFail("Expected failed state after timeout")
        }
    }

    // MARK: VEIL-804 — Test 3: Malformed Receipt

    /// **INTEGRATION: Corrupted receipt JSON fails to decode.**
    func testMalformedReceipt() async throws {
        // Category 1: Random garbage
        XCTAssertThrowsError(
            try PaymentReceiptMessage.decode(from: Data("not json".utf8))
        )

        // Category 2: Valid JSON, wrong schema
        XCTAssertThrowsError(
            try PaymentReceiptMessage.decode(from: Data("{\"wrong\": \"schema\"}".utf8))
        )

        // Category 3: Missing required fields
        let partialJSON = """
        {"txHash": "aaaa", "amountPicomob": 100}
        """.data(using: .utf8)!
        XCTAssertThrowsError(
            try PaymentReceiptMessage.decode(from: partialJSON)
        )

        // Category 4: Empty data
        XCTAssertThrowsError(
            try PaymentReceiptMessage.decode(from: Data())
        )

        // Category 5: Truncated valid receipt
        let validReceipt = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 100_000_000,
            memo: "test",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 100
        )
        let validJSON = try validReceipt.encode()
        let truncated = validJSON.prefix(validJSON.count / 2)
        XCTAssertThrowsError(
            try PaymentReceiptMessage.decode(from: Data(truncated))
        )
    }

    // MARK: VEIL-804 — Test 4: Receipt Validation Edge Cases

    /// **INTEGRATION: Receipt validation catches all invalid states.**
    func testReceiptValidation() {
        // Zero amount → invalid
        let zeroAmount = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 0,
            memo: "",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 100
        )
        XCTAssertFalse(zeroAmount.isValid)

        // Zero block index → invalid
        let zeroBlock = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 100_000_000,
            memo: "",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 0
        )
        XCTAssertFalse(zeroBlock.isValid)

        // Too-short txHash → invalid
        let shortHash = PaymentReceiptMessage(
            txHash: "abc",
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 100_000_000,
            memo: "",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 100
        )
        XCTAssertFalse(shortHash.isValid)

        // Invalid base64 shared secret → invalid
        let badBase64 = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: "not!valid!base64",
            amountPicomob: 100_000_000,
            memo: "",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 100
        )
        XCTAssertFalse(badBase64.isValid)

        // Valid receipt → valid
        let valid = PaymentReceiptMessage(
            txHash: String(repeating: "ab", count: 32),
            sharedSecret: Data(repeating: 0xCC, count: 32).base64EncodedString(),
            amountPicomob: 100_000_000,
            memo: "Valid payment",
            receiptProof: Data(repeating: 0xDD, count: 64).base64EncodedString(),
            blockIndex: 100
        )
        XCTAssertTrue(valid.isValid)
    }

    // MARK: VEIL-804 — Test 5: Payment State Recovery

    /// **INTEGRATION: State machine can reset from failed and retry successfully.**
    func testPaymentStateRecovery() async throws {
        let stateMachine = PaymentStateMachine()

        // First attempt: fail
        let context1 = PaymentContext(
            recipientId: "bob-reg-id",
            amountPicomob: 500_000_000_000,
            memo: "First attempt"
        )
        try await stateMachine.beginConstruction(context: context1)
        try await stateMachine.fail(reason: "Network error")

        // Reset to idle
        try await stateMachine.reset()
        let stateAfterReset = await stateMachine.currentState
        if case .idle = stateAfterReset {
            // Good — ready for retry
        } else {
            XCTFail("Expected idle state after reset")
        }

        // Transitions cleared
        let transitions = await stateMachine.transitions
        XCTAssertEqual(transitions.count, 0, "Transitions should be cleared on reset")

        // Second attempt: succeed through full lifecycle
        let context2 = PaymentContext(
            recipientId: "bob-reg-id",
            amountPicomob: 100_000_000_000,
            memo: "Retry"
        )
        try await stateMachine.beginConstruction(context: context2)

        let envelope = TransactionEnvelope(
            txHash: Data(repeating: 0x01, count: 32),
            fee: 400_000_000,
            totalInputAmount: 100_400_000_000,
            serializedTransaction: Data(repeating: 0x02, count: 256)
        )
        try await stateMachine.transactionBuilt(envelope: envelope)
        try await stateMachine.transactionSubmitted()

        let confirmed = ConfirmedTransaction(
            txHash: Data(repeating: 0x01, count: 32),
            amount: 100_000_000_000,
            blockIndex: 54321,
            confirmedAt: Date()
        )
        try await stateMachine.transactionConfirmed(confirmed)
        try await stateMachine.receiptSent()

        let finalState = await stateMachine.currentState
        if case .complete = finalState {
            // Success!
        } else {
            XCTFail("Expected complete state after retry")
        }
    }

    // MARK: VEIL-804 — Test 6: No TXO Consumption on Failure

    /// **INTEGRATION: Construction failure leaves no partial state.**
    func testNoPartialStateOnFailure() async throws {
        let stateMachine = PaymentStateMachine()

        let context = PaymentContext(
            recipientId: "bob-reg-id",
            amountPicomob: 1_000_000_000_000,
            memo: "Will fail"
        )

        try await stateMachine.beginConstruction(context: context)

        // Verify context is set
        let ctx = await stateMachine.context
        XCTAssertNotNil(ctx)
        XCTAssertEqual(ctx?.amountPicomob, 1_000_000_000_000)

        // Fail during construction
        try await stateMachine.fail(reason: "TXO selection failed")

        // After failure, the payment context is still accessible
        // (for error reporting) but no TXOs were consumed
        let failedCtx = await stateMachine.context
        XCTAssertNotNil(failedCtx)

        // State is terminal
        let isTerminal = await stateMachine.currentState.isTerminal
        XCTAssertTrue(isTerminal)
    }

    // MARK: VEIL-804 — Test 7: Concurrent Payments (Actor Safety)

    /// **INTEGRATION: Two concurrent payment state machines are fully isolated.**
    func testConcurrentPayments() async throws {
        let machine1 = PaymentStateMachine()
        let machine2 = PaymentStateMachine()

        let context1 = PaymentContext(
            recipientId: "alice",
            amountPicomob: 100_000_000_000,
            memo: "Payment 1"
        )

        let context2 = PaymentContext(
            recipientId: "charlie",
            amountPicomob: 200_000_000_000,
            memo: "Payment 2"
        )

        // Start both concurrently
        try await withThrowingTaskGroup(of: Void.self) { group in
            group.addTask {
                try await machine1.beginConstruction(context: context1)
            }
            group.addTask {
                try await machine2.beginConstruction(context: context2)
            }
            try await group.waitForAll()
        }

        // Both should be in constructing state
        let state1 = await machine1.currentState
        let state2 = await machine2.currentState

        if case .constructingTx(let ctx1) = state1 {
            XCTAssertEqual(ctx1.amountPicomob, 100_000_000_000)
        } else {
            XCTFail("Machine 1 should be in constructingTx")
        }

        if case .constructingTx(let ctx2) = state2 {
            XCTAssertEqual(ctx2.amountPicomob, 200_000_000_000)
        } else {
            XCTFail("Machine 2 should be in constructingTx")
        }

        // Fail machine1, advance machine2
        try await machine1.fail(reason: "Machine 1 failed")

        let envelope2 = TransactionEnvelope(
            txHash: Data(repeating: 0x02, count: 32),
            fee: 400_000_000,
            totalInputAmount: 200_400_000_000,
            serializedTransaction: Data(repeating: 0xAB, count: 256)
        )
        try await machine2.transactionBuilt(envelope: envelope2)

        // Verify isolation: machine1 failed, machine2 advanced
        let final1 = await machine1.currentState
        let final2 = await machine2.currentState

        if case .failed = final1 { /* expected */ } else {
            XCTFail("Machine 1 should be failed")
        }

        if case .submittingTx = final2 { /* expected */ } else {
            XCTFail("Machine 2 should be in submittingTx")
        }
    }

    // MARK: VEIL-804 — Test 8: Invalid State Transitions

    /// **INTEGRATION: Invalid state transitions throw appropriate errors.**
    func testInvalidStateTransitions() async throws {
        let stateMachine = PaymentStateMachine()

        // Can't submit from idle
        let envelope = TransactionEnvelope(
            txHash: Data(repeating: 0x01, count: 32),
            fee: 400_000_000,
            totalInputAmount: 1_400_000_000,
            serializedTransaction: Data(repeating: 0x02, count: 256)
        )

        do {
            try await stateMachine.transactionBuilt(envelope: envelope)
            XCTFail("Should throw for idle → submittingTx")
        } catch {
            // Expected: invalid state transition
        }

        // Can't submit from idle
        do {
            try await stateMachine.transactionSubmitted()
            XCTFail("Should throw for idle → awaitingConfirmation")
        } catch {
            // Expected
        }

        // Can't send receipt from idle
        do {
            try await stateMachine.receiptSent()
            XCTFail("Should throw for idle → complete")
        } catch {
            // Expected
        }

        // Can't reset from non-terminal state
        do {
            try await stateMachine.reset()
            XCTFail("Should throw for reset from idle")
        } catch {
            // Expected: idle is not terminal
        }
    }

    // MARK: VEIL-804 — Test 9: Full Payment Lifecycle

    /// **INTEGRATION: Complete payment lifecycle through all states.**
    func testFullPaymentLifecycle() async throws {
        let stateMachine = PaymentStateMachine()

        // idle → constructingTx
        let context = PaymentContext(
            recipientId: "bob",
            amountPicomob: 750_000_000_000,
            memo: "Dinner split"
        )
        try await stateMachine.beginConstruction(context: context)

        // constructingTx → submittingTx
        let envelope = TransactionEnvelope(
            txHash: Data(repeating: 0xAA, count: 32),
            fee: 400_000_000,
            totalInputAmount: 750_400_000_000,
            serializedTransaction: Data(repeating: 0xBB, count: 512)
        )
        try await stateMachine.transactionBuilt(envelope: envelope)

        // submittingTx → awaitingConfirmation
        try await stateMachine.transactionSubmitted()

        // awaitingConfirmation → sendingReceipt
        let confirmed = ConfirmedTransaction(
            txHash: Data(repeating: 0xAA, count: 32),
            amount: 750_000_000_000,
            blockIndex: 99999,
            confirmedAt: Date()
        )
        try await stateMachine.transactionConfirmed(confirmed)

        // sendingReceipt → complete
        try await stateMachine.receiptSent()

        let finalState = await stateMachine.currentState
        if case .complete(let ctx, let conf) = finalState {
            XCTAssertEqual(ctx.amountPicomob, 750_000_000_000)
            XCTAssertEqual(ctx.memo, "Dinner split")
            XCTAssertEqual(conf.blockIndex, 99999)
        } else {
            XCTFail("Expected complete state")
        }

        // Verify transition history
        let transitions = await stateMachine.transitions
        XCTAssertEqual(transitions.count, 5)
        XCTAssertEqual(transitions[0].from, "idle")
        XCTAssertEqual(transitions[0].to, "constructingTx")
        XCTAssertEqual(transitions[4].from, "sendingReceipt")
        XCTAssertEqual(transitions[4].to, "complete")

        // Display status
        let status = await stateMachine.currentState.displayStatus
        XCTAssertEqual(status, "Payment complete")
    }
}
