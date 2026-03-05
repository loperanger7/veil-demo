// VEIL — Conversation List ViewModel
// Ticket: VEIL-504
// Spec reference: Section 5.2
//
// Manages the conversation list state:
//   - Polls for new messages via MessagePipeline
//   - Aggregates conversations sorted by most recent activity
//   - Tracks unread counts per conversation
//   - Supports search/filter
//   - Handles delete/archive

import SwiftUI
import VeilCrypto

/// Summary of a conversation for list display.
public struct ConversationItem: Identifiable, Sendable {
    public var id: UInt32 { registrationId }
    public let registrationId: UInt32
    public let displayName: String
    public let lastMessage: String
    public let lastMessageTimestamp: Date
    public var unreadCount: Int
    public let contentType: UInt32
}

@Observable
public final class ConversationListViewModel {
    /// All conversations sorted by most recent activity.
    public private(set) var conversations: [ConversationItem] = []

    /// Search text for filtering.
    public var searchText: String = ""

    /// Whether a message poll is in progress.
    public private(set) var isLoading: Bool = false

    /// Filtered conversations based on search text.
    public var filteredConversations: [ConversationItem] {
        if searchText.isEmpty {
            return conversations
        }
        return conversations.filter { item in
            item.displayName.localizedCaseInsensitiveContains(searchText) ||
            item.lastMessage.localizedCaseInsensitiveContains(searchText)
        }
    }

    private let context: RegistrationContext
    private var pollingTask: Task<Void, Never>?

    public init(context: RegistrationContext) {
        self.context = context
    }

    /// Start periodic message polling.
    ///
    /// Polls every 3 seconds for new messages.
    /// In production, this would be triggered by silent push notifications.
    public func startPolling() {
        pollingTask?.cancel()
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollForMessages()
                try? await Task.sleep(nanoseconds: 3_000_000_000) // 3 seconds
            }
        }
    }

    /// Stop polling (e.g., when view disappears).
    public func stopPolling() {
        pollingTask?.cancel()
        pollingTask = nil
    }

    /// Manually refresh the conversation list.
    public func refresh() async {
        await pollForMessages()
    }

    /// Poll MessagePipeline for new messages and update conversations.
    private func pollForMessages() async {
        guard !isLoading else { return }
        isLoading = true
        defer { isLoading = false }

        do {
            let messages = try await context.messagePipeline.retrieveAndProcessMessages()

            for message in messages {
                updateConversation(with: message)
            }

            // Sort by most recent
            conversations.sort { $0.lastMessageTimestamp > $1.lastMessageTimestamp }
        } catch {
            // Silent failure — will retry on next poll
        }
    }

    /// Update or create a conversation entry from a received message.
    private func updateConversation(with message: DecryptedMessage) {
        let plaintext = String(data: message.plaintext, encoding: .utf8) ?? ""
        let timestamp = Date(timeIntervalSince1970: TimeInterval(message.serverTimestamp) / 1000)

        if let index = conversations.firstIndex(where: { $0.registrationId == message.senderRegistrationId }) {
            // Update existing conversation
            var updated = conversations[index]
            updated = ConversationItem(
                registrationId: updated.registrationId,
                displayName: updated.displayName,
                lastMessage: plaintext,
                lastMessageTimestamp: timestamp,
                unreadCount: updated.unreadCount + 1,
                contentType: message.contentType.rawValue
            )
            conversations[index] = updated
        } else {
            // New conversation
            conversations.append(ConversationItem(
                registrationId: message.senderRegistrationId,
                displayName: "Contact \(message.senderRegistrationId)",
                lastMessage: plaintext,
                lastMessageTimestamp: timestamp,
                unreadCount: 1,
                contentType: message.contentType.rawValue
            ))
        }
    }

    /// Delete a conversation and its session.
    public func deleteConversation(_ item: ConversationItem) async {
        conversations.removeAll { $0.registrationId == item.registrationId }
        await context.sessionManager.removeSession(for: item.registrationId)
    }

    /// Mark all messages in a conversation as read.
    public func markAsRead(_ registrationId: UInt32) {
        if let index = conversations.firstIndex(where: { $0.registrationId == registrationId }) {
            conversations[index] = ConversationItem(
                registrationId: conversations[index].registrationId,
                displayName: conversations[index].displayName,
                lastMessage: conversations[index].lastMessage,
                lastMessageTimestamp: conversations[index].lastMessageTimestamp,
                unreadCount: 0,
                contentType: conversations[index].contentType
            )
        }
    }
}
