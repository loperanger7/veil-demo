// VEIL — Payment Confirmation
// Ticket: VEIL-506
// Spec reference: Section 5.2, 8.3
//
// Final confirmation screen before sending a payment.
// Shows amount, recipient, and memo. Requires biometric
// authentication (Face ID / Touch ID) before proceeding.
//
// "Biometric authentication required per transaction."
//   — Spec Section 8.1

import SwiftUI
import LocalAuthentication

struct PaymentConfirmationView: View {
    let amount: String
    let currency: String
    let memo: String
    let peerRegistrationId: UInt32
    let onConfirm: () -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var isAuthenticating = false
    @State private var authError: String?
    @State private var isConfirmed = false

    var body: some View {
        NavigationStack {
            VStack(spacing: VeilSpacing.xxl) {
                Spacer()

                // Amount
                VStack(spacing: VeilSpacing.sm) {
                    Text("Send")
                        .font(.subheadline)
                        .foregroundColor(VeilColors.secondaryText)

                    Text(displayAmount)
                        .font(.system(size: 48, weight: .thin))

                    Text("to Contact \(peerRegistrationId)")
                        .font(.subheadline)
                        .foregroundColor(VeilColors.secondaryText)
                }

                // Memo
                if !memo.isEmpty {
                    Text("\"\(memo)\"")
                        .font(.body)
                        .foregroundColor(VeilColors.secondaryText)
                        .italic()
                        .padding(.horizontal, VeilSpacing.xxl)
                }

                Spacer()

                // Confirmation state
                if isConfirmed {
                    VStack(spacing: VeilSpacing.md) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 64))
                            .foregroundColor(.green)
                            .transition(.scale.combined(with: .opacity))

                        Text("Payment Sent")
                            .font(.headline)
                    }
                    .animation(VeilAnimation.paymentConfirm, value: isConfirmed)
                } else {
                    // Confirm button
                    VStack(spacing: VeilSpacing.md) {
                        Button {
                            authenticate()
                        } label: {
                            HStack {
                                Image(systemName: "faceid")
                                Text("Confirm with Face ID")
                            }
                            .font(.headline)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, VeilSpacing.md)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(isAuthenticating)

                        if let authError {
                            Text(authError)
                                .font(.caption)
                                .foregroundColor(.red)
                        }
                    }
                }

                Spacer()
                    .frame(height: VeilSpacing.xxl)
            }
            .padding(.horizontal, VeilSpacing.xl)
            .navigationTitle("Confirm Payment")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                        .disabled(isConfirmed)
                }
            }
        }
    }

    private var displayAmount: String {
        let prefix = currency == "USD" ? "$" : ""
        return "\(prefix)\(amount) \(currency)"
    }

    /// Authenticate with biometrics before sending payment.
    private func authenticate() {
        isAuthenticating = true
        authError = nil

        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            authError = "Biometric authentication unavailable"
            isAuthenticating = false
            return
        }

        context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: "Authenticate to send \(displayAmount)"
        ) { success, authenticationError in
            DispatchQueue.main.async {
                isAuthenticating = false

                if success {
                    withAnimation(VeilAnimation.paymentConfirm) {
                        isConfirmed = true
                    }

                    // Brief delay to show confirmation, then dismiss
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.2) {
                        onConfirm()
                        dismiss()
                    }
                } else {
                    authError = authenticationError?.localizedDescription ?? "Authentication failed"
                }
            }
        }
    }
}
