// VEIL — Device Registration
// Tickets: VEIL-201, VEIL-202, VEIL-303
// Spec reference: Section 2.1, 3.2
//
// First-launch registration flow:
//   1. Generate hybrid identity keys (Ed25519 + ML-DSA-65)
//   2. Generate initial prekey bundle (SPK, PQSPK, 100 OTPs, 100 PQ OTPs)
//   3. Generate blinded tokens for anonymous credential supply
//   4. Register with relay server (POST /v1/registration)
//   5. Unblind returned tokens and store in TokenStore
//   6. Upload prekey bundle (PUT /v1/keys)
//   7. Register APNs push token (PUT /v1/push/token)
//
// This flow runs exactly once per device. The resulting identity and
// registration data are persisted to the Keychain for subsequent launches.

import Foundation

// MARK: - Registration State

/// State of the device registration process.
public enum RegistrationState: Sendable {
    case unregistered
    case generatingKeys
    case registeringWithServer
    case uploadingPrekeys
    case registeringPushToken
    case complete(registrationId: UInt32, deviceId: UInt32)
    case failed(Error)
}

/// Persisted registration data (stored in Keychain after successful registration).
public struct RegistrationData: Codable, Sendable {
    public let registrationId: UInt32
    public let deviceId: UInt32
    public let registeredAt: Date
    public let serverPublicKey: Data
}

// MARK: - Device Registration

/// Orchestrates the first-launch device registration flow.
///
/// This is a one-shot operation: once complete, the device is registered
/// and can participate in the Veil protocol. All generated keys and
/// credentials are persisted to the Keychain.
public actor DeviceRegistration {
    private let relayClient: RelayClient
    private let tokenStore: TokenStore
    private let tokenClient: AnonymousTokenClient
    private let config: PrekeyManagerConfig

    /// Current registration state.
    public private(set) var state: RegistrationState = .unregistered

    /// Initial token count to request during registration.
    private let initialTokenCount: Int

    /// Keychain service for registration data.
    private let keychainService = "app.veil.registration"

    public init(
        relayClient: RelayClient,
        tokenStore: TokenStore,
        tokenClient: AnonymousTokenClient = AnonymousTokenClient(),
        config: PrekeyManagerConfig = .default,
        initialTokenCount: Int = 100
    ) {
        self.relayClient = relayClient
        self.tokenStore = tokenStore
        self.tokenClient = tokenClient
        self.config = config
        self.initialTokenCount = initialTokenCount
    }

    // MARK: - Registration Flow

    /// Execute the full registration flow.
    ///
    /// Returns the complete registration context needed to initialize
    /// all other managers (SessionManager, PrekeyManager, MessagePipeline).
    ///
    /// - Parameter apnsToken: Optional APNs device token for push notifications.
    /// - Returns: Registration context with all initialized components.
    public func register(
        apnsToken: String? = nil
    ) async throws -> RegistrationContext {
        do {
            // Phase 1: Generate identity keys
            state = .generatingKeys

            let identityKeyPair = try await IdentityKeyPair.generate()

            // Phase 2: Generate blinded tokens for anonymous credentials
            let (wireTokens, blindingContexts) = try tokenClient.prepareTokenRequest(
                count: initialTokenCount
            )

            // Phase 3: Register with relay server
            state = .registeringWithServer

            let regResponse = try await relayClient.registerDevice(
                deviceId: 1,  // Primary device
                identityKey: identityKeyPair.publicKeyEd25519,
                blindedTokens: wireTokens
            )

            let registrationId = regResponse.registrationId
            let deviceId: UInt32 = 1

            // Phase 4: Unblind returned tokens
            let spentTokens = try tokenClient.unblindTokens(
                signedBlindedTokens: regResponse.signedTokens,
                contexts: blindingContexts
            )
            await tokenStore.addTokens(spentTokens)

            // Phase 5: Set device identity on relay client
            await relayClient.setDeviceIdentity(
                registrationId: registrationId,
                deviceId: deviceId
            )

            // Phase 6: Generate and upload prekey bundle
            state = .uploadingPrekeys

            let prekeyManager = PrekeyManager(
                identityKeyPair: identityKeyPair,
                relayClient: relayClient,
                tokenStore: tokenStore,
                config: config
            )

            let bundle = try await prekeyManager.generateFullBundle()
            try await prekeyManager.uploadBundle(bundle)

            // Phase 7: Register push token (if available)
            if let apnsToken = apnsToken {
                state = .registeringPushToken

                if let pushToken = await tokenStore.consumeToken() {
                    try await relayClient.registerPushToken(
                        apnsToken: apnsToken,
                        token: pushToken
                    )
                }
            }

            // Phase 8: Persist registration data
            let regData = RegistrationData(
                registrationId: registrationId,
                deviceId: deviceId,
                registeredAt: Date(),
                serverPublicKey: regResponse.serverPublicKey
            )
            persistRegistrationData(regData)

            state = .complete(registrationId: registrationId, deviceId: deviceId)

            // Build and return the full registration context
            let sessionManager = SessionManager(
                identityKeyPair: identityKeyPair,
                relayClient: relayClient,
                prekeyManager: prekeyManager
            )

            let messagePipeline = MessagePipeline(
                sessionManager: sessionManager,
                relayClient: relayClient,
                tokenStore: tokenStore,
                identityKeyPair: identityKeyPair,
                registrationId: registrationId,
                deviceId: deviceId
            )

            return RegistrationContext(
                registrationId: registrationId,
                deviceId: deviceId,
                identityKeyPair: identityKeyPair,
                relayClient: relayClient,
                tokenStore: tokenStore,
                prekeyManager: prekeyManager,
                sessionManager: sessionManager,
                messagePipeline: messagePipeline
            )

        } catch {
            state = .failed(error)
            throw error
        }
    }

    // MARK: - Restoration

    /// Check if this device has already been registered.
    public func loadExistingRegistration() -> RegistrationData? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: "registration_data",
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let regData = try? JSONDecoder().decode(RegistrationData.self, from: data)
        else {
            return nil
        }

        state = .complete(registrationId: regData.registrationId, deviceId: regData.deviceId)
        return regData
    }

    // MARK: - Persistence

    /// Persist registration data to Keychain.
    private func persistRegistrationData(_ data: RegistrationData) {
        guard let encoded = try? JSONEncoder().encode(data) else { return }

        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: "registration_data",
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: "registration_data",
            kSecValueData as String: encoded,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    /// Delete all registration data (sign-out / account deletion).
    public func deleteRegistration() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
        ]
        SecItemDelete(query as CFDictionary)
        state = .unregistered
    }
}

// MARK: - Registration Context

/// The complete set of initialized managers after successful registration.
///
/// This is the entry point for all Veil protocol operations:
/// messaging, session management, prekey lifecycle, and token management.
public struct RegistrationContext: Sendable {
    public let registrationId: UInt32
    public let deviceId: UInt32
    public let identityKeyPair: IdentityKeyPair
    public let relayClient: RelayClient
    public let tokenStore: TokenStore
    public let prekeyManager: PrekeyManager
    public let sessionManager: SessionManager
    public let messagePipeline: MessagePipeline
}
