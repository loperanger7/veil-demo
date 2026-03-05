// PaymentStateStore.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-407 (continued): Persist payment state machines to Keychain so
// in-flight payments survive app crashes and restarts.
//
// Each payment is stored under its paymentId. On app launch, all in-flight
// payments are recovered and can be resumed from their last state.
//
// References: Veil Spec Section 8.3

import Foundation

// MARK: - Persisted Payment State

/// Codable wrapper for persisting a PaymentStateMachine.
/// Actors cannot directly conform to Codable, so this struct captures
/// the machine's state snapshot for serialization.
public struct PersistedPaymentState: Sendable, Codable, Equatable {
    /// The payment state.
    public let state: PaymentState
    /// Transition history.
    public let transitions: [PaymentTransition]
    /// When this snapshot was taken.
    public let persistedAt: Date

    public init(
        state: PaymentState,
        transitions: [PaymentTransition],
        persistedAt: Date = Date()
    ) {
        self.state = state
        self.transitions = transitions
        self.persistedAt = persistedAt
    }
}

// MARK: - Payment State Store

/// Actor-based persistent storage for in-flight payment state machines.
///
/// Uses Keychain for storage with `afterFirstUnlockThisDeviceOnly` access,
/// matching the pattern established by `TokenStore`.
///
/// Each payment is stored under key: `{service}.{paymentId}`.
/// A manifest key tracks all active payment IDs for bulk recovery.
public actor PaymentStateStore {

    // MARK: Properties

    private let keychainService: String
    private let manifestAccount = "payment_manifest"
    private var activePaymentIds: Set<String> = []

    // MARK: Initialization

    /// Create a payment state store.
    /// - Parameter service: Keychain service identifier.
    public init(service: String = "app.veil.payments.state") {
        self.keychainService = service
    }

    // MARK: Save / Load

    /// Persist a payment state machine snapshot.
    /// Called after every state transition to ensure crash recovery.
    ///
    /// - Parameters:
    ///   - machine: The payment state machine to persist.
    ///   - paymentId: Unique payment identifier.
    public func save(machine: PaymentStateMachine, paymentId: String) async throws {
        let state = await machine.currentState
        let transitions = await machine.transitions

        let persisted = PersistedPaymentState(
            state: state,
            transitions: transitions
        )

        let data = try JSONEncoder().encode(persisted)

        // Store the state
        try KeychainHelper.store(
            data: data,
            service: keychainService,
            account: paymentId,
            accessControl: .afterFirstUnlock
        )

        // Update manifest
        activePaymentIds.insert(paymentId)
        try persistManifest()
    }

    /// Load a specific payment state.
    /// - Parameter paymentId: The payment to load.
    /// - Returns: The persisted state, or nil if not found.
    public func load(paymentId: String) throws -> PersistedPaymentState? {
        guard let data = try KeychainHelper.load(
            service: keychainService,
            account: paymentId
        ) else {
            return nil
        }

        return try JSONDecoder().decode(PersistedPaymentState.self, from: data)
    }

    /// Delete a payment's persisted state (called on completion or failure cleanup).
    /// - Parameter paymentId: The payment to remove.
    public func delete(paymentId: String) throws {
        KeychainHelper.delete(service: keychainService, account: paymentId)
        activePaymentIds.remove(paymentId)
        try persistManifest()
    }

    // MARK: Recovery

    /// Recover all in-flight payments from Keychain.
    /// Called on app launch to resume pending payments.
    ///
    /// - Returns: Dictionary of paymentId → restored PaymentStateMachine.
    public func recoverAll() throws -> [String: PaymentStateMachine] {
        // Load manifest
        loadManifest()

        var recovered: [String: PaymentStateMachine] = [:]

        for paymentId in activePaymentIds {
            if let persisted = try load(paymentId: paymentId) {
                // Skip terminal states (cleanup)
                if persisted.state.isTerminal {
                    try? delete(paymentId: paymentId)
                    continue
                }

                let machine = PaymentStateMachine(
                    restoredState: persisted.state,
                    transitions: persisted.transitions
                )
                recovered[paymentId] = machine
            } else {
                // Orphaned manifest entry — clean up
                activePaymentIds.remove(paymentId)
            }
        }

        // Re-persist cleaned manifest
        try persistManifest()

        return recovered
    }

    /// Get all active (non-terminal) payment IDs.
    public func getActivePaymentIds() -> Set<String> {
        activePaymentIds
    }

    /// Check if a specific payment is in-flight.
    public func isInFlight(paymentId: String) -> Bool {
        activePaymentIds.contains(paymentId)
    }

    // MARK: - Manifest Management

    /// Persist the set of active payment IDs.
    private func persistManifest() throws {
        let manifest = PaymentManifest(paymentIds: Array(activePaymentIds))
        let data = try JSONEncoder().encode(manifest)
        try KeychainHelper.store(
            data: data,
            service: keychainService,
            account: manifestAccount,
            accessControl: .afterFirstUnlock
        )
    }

    /// Load the manifest of active payment IDs.
    private func loadManifest() {
        guard let data = try? KeychainHelper.load(
            service: keychainService,
            account: manifestAccount
        ) else {
            return
        }

        if let manifest = try? JSONDecoder().decode(PaymentManifest.self, from: data) {
            activePaymentIds = Set(manifest.paymentIds)
        }
    }

    /// Clear all stored payment state (for testing or account deletion).
    public func clearAll() throws {
        for paymentId in activePaymentIds {
            KeychainHelper.delete(service: keychainService, account: paymentId)
        }
        activePaymentIds.removeAll()
        KeychainHelper.delete(service: keychainService, account: manifestAccount)
    }
}

// MARK: - Manifest

struct PaymentManifest: Codable {
    let paymentIds: [String]
}
