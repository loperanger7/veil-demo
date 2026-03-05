// BlockPoller.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-404 (continued): Poll the Full-Service Node for transaction
// confirmation (block inclusion). Uses configurable timeout (default 30s)
// and exponential backoff for transient failures.
//
// References: Veil Spec Section 8.4

import Foundation

// MARK: - Block Poller

/// Polls the Full-Service Node for transaction block inclusion.
///
/// After a transaction is submitted, the poller periodically checks its status
/// until one of three outcomes:
/// 1. Confirmed: Transaction included in a block → return `ConfirmedTransaction`
/// 2. Failed: Transaction rejected by consensus → throw error
/// 3. Timeout: No confirmation within deadline → throw `confirmationTimeout`
public struct BlockPoller: Sendable {

    // MARK: Properties

    private let fsnClient: FullServiceNodeClient

    /// Polling interval between status checks.
    private let pollInterval: TimeInterval

    /// Maximum time to wait for confirmation.
    private let timeout: TimeInterval

    // MARK: Initialization

    /// Create a poller with configurable timing.
    /// - Parameters:
    ///   - fsnClient: Full-Service Node client for status queries.
    ///   - pollInterval: Seconds between polls (default 1.0).
    ///   - timeout: Maximum wait time in seconds (default 30.0).
    public init(
        fsnClient: FullServiceNodeClient,
        pollInterval: TimeInterval = MobileCoinConstants.pollIntervalSeconds,
        timeout: TimeInterval = MobileCoinConstants.confirmationTimeoutSeconds
    ) {
        self.fsnClient = fsnClient
        self.pollInterval = pollInterval
        self.timeout = timeout
    }

    // MARK: Polling

    /// Poll for transaction confirmation.
    ///
    /// - Parameters:
    ///   - txHash: The transaction hash to monitor.
    ///   - amount: Payment amount in picoMOB (for the returned confirmation).
    ///   - fee: Fee in picoMOB.
    /// - Returns: A `ConfirmedTransaction` once the transaction is included in a block.
    /// - Throws: `MobileCoinError.confirmationTimeout` or `.submissionRejected`.
    public func pollForConfirmation(
        txHash: Data,
        amount: UInt64,
        fee: UInt64
    ) async throws -> ConfirmedTransaction {
        let deadline = Date().addingTimeInterval(timeout)
        var pollCount: Int = 0

        while Date() < deadline {
            // Check for task cancellation
            try Task.checkCancellation()

            pollCount += 1

            do {
                let status = try await fsnClient.getTransactionStatus(txHash: txHash)

                switch status.status {
                case "confirmed":
                    guard let blockIndex = status.blockIndex else {
                        throw MobileCoinError.invalidReceipt(
                            detail: "Confirmed status but missing block index."
                        )
                    }
                    return ConfirmedTransaction(
                        txHash: txHash,
                        blockIndex: blockIndex,
                        confirmations: status.confirmations ?? 1,
                        amount: amount,
                        fee: fee
                    )

                case "failed":
                    throw MobileCoinError.submissionRejected(
                        reason: status.failureReason ?? "Transaction failed during consensus."
                    )

                case "pending":
                    // Continue polling
                    break

                default:
                    // Unknown status — treat as pending
                    break
                }

            } catch let error as MobileCoinError {
                // Re-throw non-transient errors
                switch error {
                case .submissionRejected, .invalidReceipt:
                    throw error
                default:
                    // Transient — continue polling
                    break
                }
            }

            // Wait before next poll (with jitter to avoid thundering herd)
            let jitter = Double.random(in: 0...0.2)
            let sleepDuration = pollInterval + jitter
            try await Task.sleep(
                nanoseconds: UInt64(sleepDuration * 1_000_000_000)
            )
        }

        // Deadline exceeded
        throw MobileCoinError.confirmationTimeout(timeoutSeconds: timeout)
    }

    /// Poll with a callback for progress updates.
    /// - Parameters:
    ///   - txHash: Transaction hash to monitor.
    ///   - amount: Payment amount.
    ///   - fee: Fee amount.
    ///   - onPollUpdate: Called after each poll with elapsed time and poll count.
    /// - Returns: Confirmed transaction.
    public func pollForConfirmation(
        txHash: Data,
        amount: UInt64,
        fee: UInt64,
        onPollUpdate: @Sendable (TimeInterval, Int) async -> Void
    ) async throws -> ConfirmedTransaction {
        let startTime = Date()
        let deadline = startTime.addingTimeInterval(timeout)
        var pollCount: Int = 0

        while Date() < deadline {
            try Task.checkCancellation()
            pollCount += 1

            let elapsed = Date().timeIntervalSince(startTime)
            await onPollUpdate(elapsed, pollCount)

            do {
                let status = try await fsnClient.getTransactionStatus(txHash: txHash)

                switch status.status {
                case "confirmed":
                    guard let blockIndex = status.blockIndex else {
                        throw MobileCoinError.invalidReceipt(
                            detail: "Confirmed but missing block index."
                        )
                    }
                    return ConfirmedTransaction(
                        txHash: txHash,
                        blockIndex: blockIndex,
                        confirmations: status.confirmations ?? 1,
                        amount: amount,
                        fee: fee
                    )

                case "failed":
                    throw MobileCoinError.submissionRejected(
                        reason: status.failureReason ?? "Consensus failure."
                    )

                default:
                    break
                }
            } catch let error as MobileCoinError {
                switch error {
                case .submissionRejected, .invalidReceipt:
                    throw error
                default:
                    break
                }
            }

            let jitter = Double.random(in: 0...0.2)
            try await Task.sleep(
                nanoseconds: UInt64((pollInterval + jitter) * 1_000_000_000)
            )
        }

        throw MobileCoinError.confirmationTimeout(timeoutSeconds: timeout)
    }
}

// MARK: - Submission Strategy

/// Orchestrates the full submit → poll → confirm cycle with retry logic.
public struct SubmissionStrategy: Sendable {

    private let fsnClient: FullServiceNodeClient
    private let poller: BlockPoller
    private let maxSubmissionRetries: Int

    /// Create a submission strategy.
    /// - Parameters:
    ///   - fsnClient: Full-Service Node client.
    ///   - poller: Block poller for confirmation.
    ///   - maxSubmissionRetries: Maximum submission attempts (default 3).
    public init(
        fsnClient: FullServiceNodeClient,
        poller: BlockPoller,
        maxSubmissionRetries: Int = MobileCoinConstants.maxRetries
    ) {
        self.fsnClient = fsnClient
        self.poller = poller
        self.maxSubmissionRetries = maxSubmissionRetries
    }

    /// Submit a transaction and wait for confirmation.
    /// Retries submission on transient failures; polls for block inclusion.
    ///
    /// - Parameter envelope: The signed transaction to submit.
    /// - Returns: A confirmed transaction with block index.
    /// - Throws: `MobileCoinError` on final failure.
    public func submitAndConfirm(
        _ envelope: TransactionEnvelope
    ) async throws -> ConfirmedTransaction {
        var lastError: MobileCoinError?

        for attempt in 0..<maxSubmissionRetries {
            do {
                // Submit
                _ = try await fsnClient.submitTransaction(envelope)

                // Poll for confirmation
                let confirmed = try await poller.pollForConfirmation(
                    txHash: envelope.txHash,
                    amount: envelope.paymentAmount,
                    fee: envelope.fee
                )

                return confirmed

            } catch let error as MobileCoinError {
                lastError = error

                // Only retry on transient/timeout errors
                switch error {
                case .transientNetworkError, .retriesExhausted, .confirmationTimeout:
                    if attempt < maxSubmissionRetries - 1 {
                        // Backoff before retry
                        let delay = pow(2.0, Double(attempt)) * 1.0
                        try await Task.sleep(
                            nanoseconds: UInt64(delay * 1_000_000_000)
                        )
                        continue
                    }
                default:
                    // Non-retryable error — fail immediately
                    throw error
                }
            }
        }

        throw lastError ?? MobileCoinError.retriesExhausted(
            attempts: maxSubmissionRetries
        )
    }
}
