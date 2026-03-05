// VEIL — App Entry Point
// Spec reference: Section 5.2
//
// "The best design is the least design."
//
// The app launches into the conversation list after registration.
// First launch triggers the registration flow automatically.
// No onboarding screens, no feature tours, no permission dialogs
// beyond what iOS requires. The app should feel like it was always there.

import SwiftUI

@main
struct VeilApp: App {
    @State private var contextManager = RegistrationContextManager()

    var body: some Scene {
        WindowGroup {
            Group {
                switch contextManager.state {
                case .loading:
                    LaunchScreen()

                case .registering(let regState):
                    RegistrationProgressView(state: regState)

                case .ready:
                    RootView(contextManager: contextManager)

                case .failed(let error):
                    ErrorView(error: error) {
                        Task {
                            await contextManager.initialize()
                        }
                    }
                }
            }
            .task {
                await contextManager.initialize()
            }
        }
    }
}

// MARK: - Launch Screen

/// Minimal launch screen — just the app name, centered.
private struct LaunchScreen: View {
    var body: some View {
        VStack {
            Spacer()
            Text("Veil")
                .font(.system(size: 36, weight: .ultraLight))
                .foregroundColor(.primary)
            Spacer()
        }
    }
}

// MARK: - Registration Progress

/// Progress view during first-launch registration.
private struct RegistrationProgressView: View {
    let state: RegistrationState

    var body: some View {
        VStack(spacing: VeilSpacing.xl) {
            ProgressView()
                .controlSize(.large)

            Text(statusText)
                .font(.subheadline)
                .foregroundColor(VeilColors.secondaryText)
        }
    }

    private var statusText: String {
        switch state {
        case .unregistered: return "Preparing..."
        case .generatingKeys: return "Generating keys..."
        case .registeringWithServer: return "Connecting..."
        case .uploadingPrekeys: return "Setting up encryption..."
        case .registeringPushToken: return "Almost ready..."
        case .complete: return "Ready"
        case .failed: return "Something went wrong"
        }
    }
}

// MARK: - Error View

/// Error state with retry.
private struct ErrorView: View {
    let error: Error
    let onRetry: () -> Void

    var body: some View {
        VStack(spacing: VeilSpacing.xl) {
            Image(systemName: "exclamationmark.triangle")
                .font(.system(size: 48, weight: .thin))
                .foregroundColor(VeilColors.secondaryText)

            Text("Unable to connect")
                .font(.headline)

            Text("Please check your network connection and try again.")
                .font(.subheadline)
                .foregroundColor(VeilColors.secondaryText)
                .multilineTextAlignment(.center)
                .padding(.horizontal, VeilSpacing.xxl)

            Button("Try Again") {
                onRetry()
            }
            .buttonStyle(.borderedProminent)
        }
    }
}
