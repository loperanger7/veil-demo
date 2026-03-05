// VEIL — Anonymous Token Store
// Ticket: VEIL-303 (client side)
// Spec reference: Section 4.3
//
// Actor-based Keychain storage for unblinded anonymous tokens.
// Tokens are consumed (spent) one at a time for each state-mutating
// API request. The store tracks balance and triggers replenishment
// when the supply drops below threshold.
//
// Persistence: Tokens are stored in the iOS Keychain with
// kSecAttrAccessible = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly.
// This ensures tokens survive app restarts but not device restoration
// from backup (by design — tokens are device-specific).

import Foundation

/// Token balance state for monitoring.
public enum TokenBalanceState: Sendable {
    /// Healthy supply of tokens.
    case healthy
    /// Below replenishment threshold — should request more.
    case low
    /// No tokens available — cannot make authenticated requests.
    case depleted
}

/// Actor-based store for anonymous credential tokens.
///
/// Thread safety is guaranteed by Swift's actor isolation.
/// All mutations are serialized automatically.
public actor TokenStore {
    /// Unblinded tokens available for spending.
    private var availableTokens: [WireSpentToken]

    /// Replenishment threshold as a fraction (default: 0.2 = 20%).
    private let replenishmentThreshold: Double

    /// Maximum token count (initial supply size).
    private let maxTokenCount: Int

    /// Keychain service identifier.
    private let keychainService: String

    /// Keychain account identifier.
    private let keychainAccount: String

    public init(
        maxTokenCount: Int = 100,
        replenishmentThreshold: Double = 0.2,
        keychainService: String = "app.veil.tokens",
        keychainAccount: String = "anonymous_tokens"
    ) {
        self.maxTokenCount = maxTokenCount
        self.replenishmentThreshold = replenishmentThreshold
        self.keychainService = keychainService
        self.keychainAccount = keychainAccount
        self.availableTokens = []
    }

    // MARK: - Token Lifecycle

    /// Add newly unblinded tokens to the store.
    ///
    /// Called after registration (initial supply) or replenishment.
    public func addTokens(_ tokens: [WireSpentToken]) {
        availableTokens.append(contentsOf: tokens)
        persistToKeychain()
    }

    /// Consume one token for an authenticated API request.
    ///
    /// Returns the token to attach to the X-Veil-Token header.
    /// Returns nil if no tokens are available (triggers replenishment).
    public func consumeToken() -> WireSpentToken? {
        guard !availableTokens.isEmpty else {
            return nil
        }

        let token = availableTokens.removeFirst()
        persistToKeychain()
        return token
    }

    /// Check the current balance state.
    public var balanceState: TokenBalanceState {
        if availableTokens.isEmpty {
            return .depleted
        } else if Double(availableTokens.count) / Double(maxTokenCount) < replenishmentThreshold {
            return .low
        } else {
            return .healthy
        }
    }

    /// Current number of available tokens.
    public var tokenCount: Int {
        availableTokens.count
    }

    /// Number of tokens to request during replenishment.
    public var replenishmentCount: Int {
        max(0, maxTokenCount - availableTokens.count)
    }

    /// Whether replenishment is needed.
    public var needsReplenishment: Bool {
        balanceState == .low || balanceState == .depleted
    }

    // MARK: - Persistence

    /// Load tokens from Keychain on app launch.
    public func loadFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let decoded = try? JSONDecoder().decode([WireSpentToken].self, from: data)
        else {
            return
        }

        availableTokens = decoded
    }

    /// Persist current tokens to Keychain.
    private func persistToKeychain() {
        guard let data = try? JSONEncoder().encode(availableTokens) else {
            return
        }

        // Delete existing entry
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Add updated entry
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        SecItemAdd(addQuery as CFDictionary, nil)
    }

    /// Delete all tokens from Keychain (called on sign-out).
    public func deleteAll() {
        availableTokens.removeAll()

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
