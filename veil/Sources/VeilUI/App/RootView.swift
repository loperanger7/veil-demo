// VEIL — Root View
// Spec reference: Section 5.2
//
// Navigation coordinator. A single NavigationStack owns the entire
// app's navigation hierarchy:
//   Conversations → Chat → (Safety Numbers | Payment)
//   Conversations → Settings
//   Conversations → Balance

import SwiftUI
import VeilCrypto

/// Root navigation view for the authenticated app.
struct RootView: View {
    let contextManager: RegistrationContextManager

    @State private var selectedTab: Tab = .conversations

    enum Tab {
        case conversations
        case balance
        case settings
    }

    var body: some View {
        TabView(selection: $selectedTab) {
            // Conversations tab
            NavigationStack {
                if let context = contextManager.context {
                    ConversationListView(context: context)
                } else {
                    VeilEmptyStateView(
                        title: "No conversations yet",
                        systemImage: "bubble.left.and.bubble.right",
                        description: "Start a new conversation to get going."
                    )
                }
            }
            .tabItem {
                Label("Messages", systemImage: "bubble.left.and.bubble.right")
            }
            .tag(Tab.conversations)

            // Balance tab
            NavigationStack {
                BalanceView()
            }
            .tabItem {
                Label("Balance", systemImage: "creditcard")
            }
            .tag(Tab.balance)

            // Settings tab
            NavigationStack {
                if let context = contextManager.context {
                    SettingsView(context: context)
                } else {
                    SettingsView(context: nil)
                }
            }
            .tabItem {
                Label("Settings", systemImage: "gear")
            }
            .tag(Tab.settings)
        }
        .tint(VeilColors.accent)
    }
}
