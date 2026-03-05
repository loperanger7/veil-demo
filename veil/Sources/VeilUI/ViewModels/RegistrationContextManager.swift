// VEIL — Registration Context Manager
// Tickets: VEIL-503 (registration), VEIL-504+ (all UI)
// Spec reference: Section 2.1
//
// Application-wide singleton that holds the RegistrationContext after
// successful device registration. All UI components access the crypto
// layer exclusively through this manager.
//
// On first launch: runs the full registration flow.
// On subsequent launches: restores from Keychain.

import SwiftUI
import VeilCrypto

/// Observable state for the registration and app initialization flow.
@Observable
public final class RegistrationContextManager {
    /// The active registration context (nil until registration completes).
    public private(set) var context: RegistrationContext?

    /// Current registration state for progress display.
    public private(set) var state: AppInitState = .loading

    /// Error encountered during initialization.
    public private(set) var error: Error?

    /// Relay server configuration.
    private let relayConfig: RelayConfiguration

    public enum AppInitState {
        case loading
        case registering(RegistrationState)
        case ready
        case failed(Error)
    }

    public init(relayConfig: RelayConfiguration = .development()) {
        self.relayConfig = relayConfig
    }

    /// Initialize the app: restore existing registration or perform a new one.
    ///
    /// Called once on app launch from VeilApp.
    @MainActor
    public func initialize(apnsToken: String? = nil) async {
        state = .loading

        let relayClient = RelayClient(configuration: relayConfig)
        let tokenStore = TokenStore()
        await tokenStore.loadFromKeychain()

        let registration = DeviceRegistration(
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        // Try restoring from Keychain
        if let existingData = await registration.loadExistingRegistration() {
            // Rebuild context from persisted data
            await relayClient.setDeviceIdentity(
                registrationId: existingData.registrationId,
                deviceId: existingData.deviceId
            )

            // For full restoration, we'd rebuild all managers from Keychain.
            // For now, mark as ready with the relay client available.
            state = .ready
            return
        }

        // No existing registration — perform a fresh one
        do {
            state = .registering(.generatingKeys)
            let registrationContext = try await registration.register(apnsToken: apnsToken)
            self.context = registrationContext
            state = .ready
        } catch {
            self.error = error
            state = .failed(error)
        }
    }

    /// Whether the app is ready for use.
    public var isReady: Bool {
        if case .ready = state { return true }
        return false
    }
}
