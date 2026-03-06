// VEIL — MockRelayServer.swift
// Ticket: VEIL-804 — Integration Test Suite
// Spec reference: Section 2.1 (Relay Service)
//
// In-memory relay server mock for integration testing.
//
// Provides the same logical interface as the Veil Relay Service
// without network I/O. Used by all VEIL-804 integration tests
// to simulate device registration, prekey storage, message delivery,
// and acknowledgment.
//
// Features:
//   - Per-device FIFO message queues
//   - Prekey bundle storage and retrieval
//   - Message acknowledgment (deletion after delivery)
//   - Network failure simulation (offline/online toggle)
//   - Token validation (accepts any non-empty token)
//   - Server GUID generation for message tracking

import Foundation
@testable import VeilCrypto

// MARK: - Mock Relay Server

/// In-memory relay server actor for integration testing.
///
/// Simulates the Veil Relay Service's core operations:
///   - Device registration and identity management
///   - Prekey bundle storage and fetch
///   - Message queueing and delivery (FIFO per device)
///   - Message acknowledgment (server-side deletion)
///   - Network failure simulation
public actor MockRelayServer {

    // MARK: - Types

    /// A queued message envelope.
    public struct QueuedEnvelope: Sendable {
        public let serverGuid: Data
        public let envelope: MockWireEnvelope
        public let serverTimestamp: UInt64
        public let acknowledged: Bool

        public init(envelope: MockWireEnvelope) {
            self.serverGuid = Self.generateGuid()
            self.envelope = envelope
            self.serverTimestamp = UInt64(Date().timeIntervalSince1970 * 1000)
            self.acknowledged = false
        }

        private static func generateGuid() -> Data {
            Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        }
    }

    /// A simplified wire envelope for testing.
    public struct MockWireEnvelope: Sendable {
        public let content: Data
        public let sealedSender: Data
        public let contentType: UInt32
        public let senderRegistrationId: UInt32
    }

    /// Registered device record.
    public struct DeviceRecord: Sendable {
        public let registrationId: UInt32
        public let deviceId: UInt32
        public let identityKey: Data
        public let registeredAt: Date
    }

    // MARK: - State

    /// Registered devices indexed by registration ID.
    private var devices: [UInt32: DeviceRecord] = [:]

    /// Prekey bundles indexed by registration ID.
    private var prekeyBundles: [UInt32: RelayPrekeyBundle] = [:]

    /// Message queues indexed by registration ID.
    private var messageQueues: [UInt32: [QueuedEnvelope]] = [:]

    /// Next available registration ID.
    private var nextRegistrationId: UInt32 = 1000

    /// Whether the server is "online" (simulated network state).
    private var isOnline: Bool = true

    /// Total messages processed (for statistics).
    private var totalMessagesProcessed: UInt64 = 0

    /// Acknowledged message GUIDs (for deduplication).
    private var acknowledgedGuids: Set<Data> = []

    // MARK: - Initialization

    public init() {}

    // MARK: - Network Simulation

    /// Simulate server going offline (all operations throw).
    public func simulateOffline() {
        isOnline = false
    }

    /// Simulate server coming back online.
    public func simulateOnline() {
        isOnline = true
    }

    /// Current network state.
    public var networkState: Bool { isOnline }

    /// Check network state and throw if offline.
    private func checkOnline() throws {
        guard isOnline else {
            throw RelayError.networkUnavailable
        }
    }

    // MARK: - Device Registration

    /// Register a new device and return a registration ID.
    ///
    /// - Parameters:
    ///   - deviceId: The device's local ID (1 for primary).
    ///   - identityKey: The device's identity public key.
    /// - Returns: Server-assigned registration ID.
    public func registerDevice(
        deviceId: UInt32,
        identityKey: Data
    ) throws -> UInt32 {
        try checkOnline()

        let registrationId = nextRegistrationId
        nextRegistrationId += 1

        let record = DeviceRecord(
            registrationId: registrationId,
            deviceId: deviceId,
            identityKey: identityKey,
            registeredAt: Date()
        )

        devices[registrationId] = record
        messageQueues[registrationId] = []

        return registrationId
    }

    /// Check if a device is registered.
    public func isRegistered(_ registrationId: UInt32) -> Bool {
        devices[registrationId] != nil
    }

    /// Deregister a device (remove all data).
    public func deregisterDevice(_ registrationId: UInt32) throws {
        try checkOnline()
        devices.removeValue(forKey: registrationId)
        prekeyBundles.removeValue(forKey: registrationId)
        messageQueues.removeValue(forKey: registrationId)
    }

    // MARK: - Prekey Management

    /// Upload a prekey bundle for a registered device.
    public func uploadPrekeys(
        registrationId: UInt32,
        bundle: RelayPrekeyBundle
    ) throws {
        try checkOnline()
        guard devices[registrationId] != nil else {
            throw RelayError.httpError(statusCode: 404, body: nil)
        }
        prekeyBundles[registrationId] = bundle
    }

    /// Fetch a device's prekey bundle.
    public func fetchPrekeys(
        for registrationId: UInt32
    ) throws -> RelayPrekeyBundle {
        try checkOnline()
        guard let bundle = prekeyBundles[registrationId] else {
            throw RelayError.httpError(statusCode: 404, body: nil)
        }
        return bundle
    }

    // MARK: - Message Delivery

    /// Queue a message for delivery to a recipient.
    ///
    /// - Parameters:
    ///   - recipientRegistrationId: The recipient's registration ID.
    ///   - envelope: The sealed-sender message envelope.
    /// - Returns: The server-assigned GUID for acknowledgment.
    public func sendMessage(
        to recipientRegistrationId: UInt32,
        envelope: MockWireEnvelope
    ) throws -> Data {
        try checkOnline()
        guard devices[recipientRegistrationId] != nil else {
            throw RelayError.httpError(statusCode: 404, body: nil)
        }

        let queued = QueuedEnvelope(envelope: envelope)
        messageQueues[recipientRegistrationId, default: []].append(queued)
        totalMessagesProcessed += 1

        return queued.serverGuid
    }

    /// Retrieve all pending messages for a device.
    ///
    /// Messages are returned but NOT removed. They persist until
    /// explicitly acknowledged via `acknowledgeMessage()`.
    ///
    /// - Parameter registrationId: The device's registration ID.
    /// - Returns: Array of pending envelopes.
    public func retrieveMessages(
        for registrationId: UInt32
    ) throws -> [QueuedEnvelope] {
        try checkOnline()
        guard let queue = messageQueues[registrationId] else {
            throw RelayError.httpError(statusCode: 404, body: nil)
        }
        return queue.filter { !acknowledgedGuids.contains($0.serverGuid) }
    }

    /// Acknowledge receipt of a message (triggers server-side deletion).
    ///
    /// - Parameter serverGuid: The server GUID of the message to acknowledge.
    public func acknowledgeMessage(serverGuid: Data) throws {
        try checkOnline()
        acknowledgedGuids.insert(serverGuid)

        // Remove from all queues
        for (regId, queue) in messageQueues {
            messageQueues[regId] = queue.filter { !acknowledgedGuids.contains($0.serverGuid) }
        }
    }

    // MARK: - Statistics

    /// Number of messages currently queued across all devices.
    public var totalQueuedMessages: Int {
        messageQueues.values.reduce(0) { $0 + $1.count }
    }

    /// Total messages processed since server creation.
    public var totalProcessed: UInt64 { totalMessagesProcessed }

    /// Number of registered devices.
    public var registeredDeviceCount: Int { devices.count }

    /// Queue depth for a specific device.
    public func queueDepth(for registrationId: UInt32) -> Int {
        messageQueues[registrationId]?.count ?? 0
    }

    /// Reset all state (for test isolation).
    public func reset() {
        devices = [:]
        prekeyBundles = [:]
        messageQueues = [:]
        nextRegistrationId = 1000
        isOnline = true
        totalMessagesProcessed = 0
        acknowledgedGuids = []
    }
}
