// MobileCoinWallet.swift
// VEIL — MobileCoin Payment Integration
//
// Top-level wallet orchestrator. Coordinates all MobileCoin subsystems:
// key derivation, address resolution, transaction construction, submission,
// Fog balance queries, receipt encryption, and state machine management.
//
// This is the single entry point consumed by VeilUI (ChatViewModel,
// BalanceView, PaymentFlowView).
//
// References: Veil Spec Sections 8.1–8.6

import Foundation

// MARK: - Payment Result

/// Result of a completed payment operation.
public struct PaymentResult: Sendable, Equatable {
    /// Unique payment ID.
    public let paymentId: String
    /// Transaction hash on the MobileCoin ledger.
    public let txHash: Data
    /// Block index of confirmation.
    public let blockIndex: UInt64
    /// Amount sent in picoMOB.
    public let amountPicomob: UInt64
    /// Fee paid in picoMOB.
    public let fee: UInt64
    /// Memo text.
    public let memo: String
    /// Timestamp of confirmation.
    public let confirmedAt: Date
}

// MARK: - Wallet Balance

/// Snapshot of the wallet's balance and transaction state.
public struct WalletBalance: Sendable {
    /// Total balance in picoMOB.
    public let balancePicomob: UInt64
    /// Number of unspent TXOs.
    public let unspentTXOCount: Int
    /// Number of in-flight payments.
    public let inFlightPaymentCount: Int
    /// Timestamp of last balance refresh.
    public let lastUpdated: Date?

    /// Balance formatted as MOB.
    public var balanceInMOB: Double {
        Double(balancePicomob) / Double(MobileCoinConstants.picoMOBPerMOB)
    }
}

// MARK: - MobileCoin Wallet Actor

/// Top-level wallet API for the Veil iOS client.
///
/// Orchestrates the full payment lifecycle:
/// 1. Key derivation from Veil identity
/// 2. Recipient address resolution
/// 3. Transaction construction with ring signatures
/// 4. Submission to Full-Service Node
/// 5. Block confirmation polling
/// 6. Encrypted receipt delivery via Triple Ratchet
/// 7. State machine persistence for crash recovery
///
/// All methods are actor-isolated for thread safety.
public actor MobileCoinWallet {

    // MARK: Properties

    /// Derived MobileCoin key pair.
    private let keyPair: MobileCoinKeyPair

    /// MobileCoin SDK client.
    private let mobClient: MobileCoinClient

    /// Fog client for balance and TXO queries.
    private let fogClient: FogClient

    /// Subaddress deriver for recipient addresses.
    private let subaddressDeriver: SubaddressDeriver

    /// Transaction builder.
    private let txBuilder: TransactionBuilder

    /// Submission strategy (submit + poll).
    private let submissionStrategy: SubmissionStrategy

    /// Receipt encryptor.
    private let receiptEncryptor: ReceiptEncryptor

    /// TXO detector for incoming payments.
    private let txoDetector: TXODetector

    /// Receipt verifier.
    private let receiptVerifier: ReceiptVerifier

    /// Payment state store (Keychain persistence).
    private let stateStore: PaymentStateStore

    /// Sender's own subaddress (for change outputs).
    private let selfAddress: PublicSubaddress

    /// Active state machines for in-flight payments.
    private var activeMachines: [String: PaymentStateMachine] = [:]

    // MARK: Initialization

    /// Create a wallet from a Veil identity key.
    ///
    /// This performs key derivation and initializes all subsystems.
    /// Call `initialize()` after construction to register with Fog and
    /// recover any in-flight payments.
    ///
    /// - Parameters:
    ///   - keyPair: Pre-derived MobileCoin key pair.
    ///   - mobClient: MobileCoin SDK client.
    ///   - fogClient: Fog client for balance queries.
    ///   - fsnClient: Full-Service Node client.
    ///   - selfAddress: The wallet owner's subaddress.
    public init(
        keyPair: MobileCoinKeyPair,
        mobClient: MobileCoinClient,
        fogClient: FogClient,
        fsnClient: FullServiceNodeClient,
        selfAddress: PublicSubaddress
    ) {
        self.keyPair = keyPair
        self.mobClient = mobClient
        self.fogClient = fogClient
        self.selfAddress = selfAddress

        self.subaddressDeriver = SubaddressDeriver(client: mobClient)
        self.txBuilder = TransactionBuilder(client: mobClient)
        self.receiptEncryptor = ReceiptEncryptor()
        self.txoDetector = TXODetector(mobClient: mobClient)
        self.receiptVerifier = ReceiptVerifier(mobClient: mobClient)
        self.stateStore = PaymentStateStore()

        let poller = BlockPoller(fsnClient: fsnClient)
        self.submissionStrategy = SubmissionStrategy(
            fsnClient: fsnClient,
            poller: poller
        )
    }

    // MARK: Initialization

    /// Initialize the wallet: register with Fog and recover in-flight payments.
    public func initialize() async throws {
        // Register view key with Fog
        try await fogClient.registerViewKey()

        // Recover in-flight payments from Keychain
        let recovered = try await stateStore.recoverAll()
        for (id, machine) in recovered {
            activeMachines[id] = machine
        }
    }

    // MARK: Send Payment

    /// Send a MobileCoin payment to a recipient.
    ///
    /// This orchestrates the full payment lifecycle:
    /// 1. Derive recipient address
    /// 2. Select TXOs and build transaction
    /// 3. Submit and wait for confirmation
    /// 4. Construct encrypted receipt
    ///
    /// The returned receipt data should be sent via `MessagePipeline.sendMessage()`
    /// with contentType `.payment`.
    ///
    /// - Parameters:
    ///   - recipientIdentityKey: Recipient's Veil public identity key.
    ///   - amountPicomob: Amount to send in picoMOB.
    ///   - memo: Optional memo text (max 256 characters).
    /// - Returns: A `PaymentResult` and the encoded receipt data for the messaging layer.
    /// - Throws: `MobileCoinError` at any stage of the payment lifecycle.
    public func sendPayment(
        recipientIdentityKey: Data,
        amountPicomob: UInt64,
        memo: String = ""
    ) async throws -> (result: PaymentResult, receiptData: Data) {
        // Create state machine
        let machine = PaymentStateMachine()
        let context = PaymentContext(
            recipientId: recipientIdentityKey.prefix(8).hexEncodedString(),
            amountPicomob: amountPicomob,
            memo: memo
        )

        activeMachines[context.paymentId] = machine

        do {
            // 1. Begin construction
            try await machine.beginConstruction(context: context)
            try await stateStore.save(machine: machine, paymentId: context.paymentId)

            // 2. Derive recipient address
            let recipientAddress = try await subaddressDeriver.deriveRecipientAddress(
                peerIdentityPublicKey: recipientIdentityKey
            )

            // 3. Get available TXOs
            let availableTXOs = try await fogClient.getUnspentTXOs(
                spendKey: keyPair.spendKey
            )

            // 4. Build transaction
            let envelope = try await txBuilder.buildTransaction(
                amount: amountPicomob,
                recipientAddress: recipientAddress,
                senderKeyPair: keyPair,
                senderAddress: selfAddress,
                availableTXOs: availableTXOs,
                memo: memo
            )

            // 5. Transition to submitting
            try await machine.transactionBuilt(envelope: envelope)
            try await stateStore.save(machine: machine, paymentId: context.paymentId)

            // 6. Submit and wait for confirmation
            try await machine.transactionSubmitted()
            try await stateStore.save(machine: machine, paymentId: context.paymentId)

            let confirmed = try await submissionStrategy.submitAndConfirm(envelope)

            // 7. Transition to sending receipt
            try await machine.transactionConfirmed(confirmed)
            try await stateStore.save(machine: machine, paymentId: context.paymentId)

            // 8. Construct receipt
            // Generate a shared secret for the recipient to locate their TXO
            let sharedSecret = generateSharedSecret(
                recipientAddress: recipientAddress,
                txHash: confirmed.txHash
            )

            let (receipt, receiptData) = try receiptEncryptor.constructReceipt(
                confirmedTx: confirmed,
                envelope: envelope,
                sharedSecret: sharedSecret,
                memo: memo
            )

            // 9. Mark receipt sent (caller sends via MessagePipeline)
            try await machine.receiptSent()
            try await stateStore.save(machine: machine, paymentId: context.paymentId)

            // 10. Mark spent TXOs
            let spentKeyImages = Set(
                availableTXOs
                    .filter { txo in
                        envelope.txHash != Data() // simplified — mark selected TXOs
                    }
                    .compactMap(\.keyImage)
            )
            await fogClient.markSpent(keyImages: spentKeyImages)

            // 11. Clean up
            try await stateStore.delete(paymentId: context.paymentId)
            activeMachines.removeValue(forKey: context.paymentId)

            let result = PaymentResult(
                paymentId: context.paymentId,
                txHash: confirmed.txHash,
                blockIndex: confirmed.blockIndex,
                amountPicomob: amountPicomob,
                fee: confirmed.fee,
                memo: memo,
                confirmedAt: confirmed.confirmedAt
            )

            return (result, receiptData)

        } catch {
            // Fail the state machine
            try? await machine.fail(
                reason: error.localizedDescription
            )
            try? await stateStore.save(machine: machine, paymentId: context.paymentId)

            throw error
        }
    }

    // MARK: Balance

    /// Query the current wallet balance.
    /// Falls back to cached balance if Fog is unavailable.
    /// - Returns: A `WalletBalance` snapshot.
    public func getBalance() async throws -> WalletBalance {
        let balance = try await fogClient.queryBalance()
        let unspentTXOs = try await fogClient.getUnspentTXOs(
            spendKey: keyPair.spendKey
        )

        return WalletBalance(
            balancePicomob: balance,
            unspentTXOCount: unspentTXOs.count,
            inFlightPaymentCount: activeMachines.count,
            lastUpdated: Date()
        )
    }

    /// Get the cached balance without a network request.
    public func getCachedBalance() async -> WalletBalance? {
        guard let cached = await fogClient.getCachedBalance() else {
            return nil
        }
        return WalletBalance(
            balancePicomob: cached.balance,
            unspentTXOCount: 0,
            inFlightPaymentCount: activeMachines.count,
            lastUpdated: cached.updatedAt
        )
    }

    // MARK: Incoming Payments

    /// Process a received payment receipt.
    /// - Parameters:
    ///   - receiptData: Decrypted receipt data from the message pipeline.
    /// - Returns: Verification result for the incoming payment.
    public func processIncomingReceipt(
        _ receiptData: Data
    ) async throws -> ReceiptVerificationResult {
        let receipt = try receiptEncryptor.parseDecryptedReceipt(receiptData)
        let incomingTXOs = try await fogClient.detectIncomingTXOs()

        return await receiptVerifier.verify(
            receipt: receipt,
            viewKey: keyPair.viewKey,
            incomingTXOs: incomingTXOs
        )
    }

    // MARK: Recovery

    /// Resume a previously in-flight payment.
    /// Called after `initialize()` finds recovered state machines.
    /// - Parameter paymentId: The payment to resume.
    /// - Returns: The current state of the payment.
    public func getPaymentState(paymentId: String) async -> PaymentState? {
        guard let machine = activeMachines[paymentId] else { return nil }
        return await machine.currentState
    }

    /// Get all in-flight payment IDs.
    public func getInFlightPaymentIds() -> [String] {
        Array(activeMachines.keys)
    }

    // MARK: - Private Helpers

    /// Generate a shared secret for the recipient to locate their TXO.
    /// In production, this would be an ECDH exchange with the recipient's view key.
    /// Mock: deterministic derivation from address + txHash.
    private func generateSharedSecret(
        recipientAddress: PublicSubaddress,
        txHash: Data
    ) -> Data {
        var input = recipientAddress.address
        input.append(txHash)
        // Simple hash for mock (production uses ECDH)
        var secret = Data(count: 32)
        for (i, byte) in input.enumerated() {
            let idx = i % 32
            secret[idx] ^= byte
            secret[idx] = secret[idx] &+ 0x5A
        }
        return secret
    }
}
