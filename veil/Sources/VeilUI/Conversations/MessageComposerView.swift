// VEIL — Message Composer
// Ticket: VEIL-505, VEIL-506
// Spec reference: Section 5.2
//
// Text input with send button and payment icon.
// Clean, minimal. The payment icon sits adjacent to the composer
// as described in the spec — a single tap opens the payment flow.

import SwiftUI

struct MessageComposerView: View {
    @Binding var text: String
    let isSending: Bool
    let onSend: () -> Void
    let onPayment: () -> Void

    @FocusState private var isFocused: Bool

    var body: some View {
        HStack(alignment: .bottom, spacing: VeilSpacing.sm) {
            // Payment button
            Button(action: onPayment) {
                Image(systemName: "dollarsign.circle")
                    .font(.title2)
                    .foregroundColor(VeilColors.accent)
            }
            .padding(.bottom, 6)

            // Text input
            TextField("Message", text: $text, axis: .vertical)
                .lineLimit(1...5)
                .padding(.horizontal, VeilSpacing.md)
                .padding(.vertical, VeilSpacing.sm)
                .background(VeilColors.composerBackground)
                .clipShape(RoundedRectangle(cornerRadius: 20))
                .focused($isFocused)

            // Send button
            Button(action: onSend) {
                Image(systemName: "arrow.up.circle.fill")
                    .font(.title2)
                    .foregroundColor(canSend ? VeilColors.accent : Color.gray.opacity(0.5))
            }
            .disabled(!canSend)
            .padding(.bottom, 6)
        }
        .padding(.horizontal, VeilSpacing.md)
        .padding(.vertical, VeilSpacing.sm)
        .background(.bar)
    }

    private var canSend: Bool {
        !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isSending
    }
}
