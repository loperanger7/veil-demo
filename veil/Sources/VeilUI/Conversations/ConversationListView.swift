// VEIL — Conversation List View
// Ticket: VEIL-504
// Spec reference: Section 5.2
//
// List of conversations sorted by most recent activity.
// Clean, minimal styling. San Francisco typeface.
//
// Features:
//   - Swipe to delete
//   - Pull to refresh
//   - Search bar
//   - Unread count badges
//   - New conversation button

import SwiftUI
import VeilCrypto

public struct ConversationListView: View {
    let context: RegistrationContext

    @State private var viewModel: ConversationListViewModel
    @State private var showNewConversation = false

    public init(context: RegistrationContext) {
        self.context = context
        self._viewModel = State(initialValue: ConversationListViewModel(context: context))
    }

    public var body: some View {
        List {
            if viewModel.filteredConversations.isEmpty && !viewModel.searchText.isEmpty {
                ContentUnavailableView.search(text: viewModel.searchText)
            } else if viewModel.filteredConversations.isEmpty {
                ContentUnavailableView(
                    "No conversations",
                    systemImage: "bubble.left.and.bubble.right",
                    description: Text("Tap the compose button to start a conversation.")
                )
            } else {
                ForEach(viewModel.filteredConversations) { item in
                    NavigationLink(value: item.registrationId) {
                        ConversationRow(item: item)
                    }
                    .swipeActions(edge: .trailing, allowsFullSwipe: true) {
                        Button(role: .destructive) {
                            Task { await viewModel.deleteConversation(item) }
                        } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
        }
        .listStyle(.plain)
        .searchable(text: $viewModel.searchText, prompt: "Search")
        .refreshable {
            await viewModel.refresh()
        }
        .navigationTitle("Messages")
        .navigationBarTitleDisplayMode(.large)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showNewConversation = true
                } label: {
                    Image(systemName: "square.and.pencil")
                }
            }
        }
        .navigationDestination(for: UInt32.self) { registrationId in
            ChatView(
                peerRegistrationId: registrationId,
                context: context
            )
        }
        .sheet(isPresented: $showNewConversation) {
            NewConversationView()
        }
        .onAppear { viewModel.startPolling() }
        .onDisappear { viewModel.stopPolling() }
    }
}

// MARK: - Conversation Row

/// Single row in the conversation list.
struct ConversationRow: View {
    let item: ConversationItem

    var body: some View {
        HStack(spacing: VeilSpacing.md) {
            // Avatar circle
            Circle()
                .fill(Color(.systemGray4))
                .frame(width: 48, height: 48)
                .overlay(
                    Text(String(item.displayName.prefix(1)).uppercased())
                        .font(.title3.weight(.medium))
                        .foregroundColor(.white)
                )

            // Name + preview
            VStack(alignment: .leading, spacing: VeilSpacing.xxs) {
                HStack {
                    Text(item.displayName)
                        .font(VeilTypography.contactName)
                        .lineLimit(1)

                    Spacer()

                    Text(TimestampFormatter.conversationList(item.lastMessageTimestamp))
                        .font(VeilTypography.timestamp)
                        .foregroundColor(VeilColors.secondaryText)
                }

                HStack {
                    if item.contentType == 3 { // Payment
                        Image(systemName: "creditcard")
                            .font(.caption)
                            .foregroundColor(VeilColors.secondaryText)
                    }

                    Text(item.lastMessage)
                        .font(VeilTypography.messagePreview)
                        .foregroundColor(VeilColors.secondaryText)
                        .lineLimit(2)

                    Spacer()

                    if item.unreadCount > 0 {
                        UnreadBadge(count: item.unreadCount)
                    }
                }
            }
        }
        .padding(.vertical, VeilSpacing.xs)
    }
}

// MARK: - New Conversation Placeholder

/// Placeholder for the new conversation flow.
struct NewConversationView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            VStack(spacing: VeilSpacing.xl) {
                Image(systemName: "person.crop.circle.badge.plus")
                    .font(.system(size: 64, weight: .thin))
                    .foregroundColor(VeilColors.secondaryText)

                Text("Enter a phone number or choose a contact to start a conversation.")
                    .font(.subheadline)
                    .foregroundColor(VeilColors.secondaryText)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, VeilSpacing.xxl)
            }
            .navigationTitle("New Message")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
        }
    }
}
