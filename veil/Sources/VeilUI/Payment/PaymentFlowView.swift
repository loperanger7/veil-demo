// VEIL — Payment Flow
// Ticket: VEIL-506
// Spec reference: Section 5.2, 8.3
//
// The payment flow should complete in under 4 seconds (excluding biometric):
//   1. Tap payment icon → this view appears
//   2. Enter amount via custom numeric keypad
//   3. Toggle between local currency and MOB
//   4. Optional memo (max 256 chars)
//   5. Tap "Send" → PaymentConfirmationView
//   6. Biometric → done
//
// Custom keypad instead of system keyboard for speed and polish.

import SwiftUI

/// Currency selection.
enum PaymentCurrency: String, CaseIterable {
    case usd = "USD"
    case mob = "MOB"
}

struct PaymentFlowView: View {
    let peerRegistrationId: UInt32
    let onConfirm: (String, String, String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var amount: String = ""
    @State private var currency: PaymentCurrency = .usd
    @State private var memo: String = ""
    @State private var showConfirmation = false

    var body: some View {
        NavigationStack {
            VStack(spacing: 0) {
                Spacer()

                // Amount display
                VStack(spacing: VeilSpacing.sm) {
                    Text(displayAmount)
                        .font(VeilTypography.amountDisplay)
                        .foregroundColor(amount.isEmpty ? Color.gray.opacity(0.5) : .primary)
                        .contentTransition(.numericText())
                        .animation(.snappy(duration: 0.15), value: amount)

                    // Currency toggle
                    Picker("Currency", selection: $currency) {
                        ForEach(PaymentCurrency.allCases, id: \.self) { curr in
                            Text(curr.rawValue).tag(curr)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 160)
                }
                .padding(.bottom, VeilSpacing.xl)

                // Memo field
                TextField("Add a note", text: $memo)
                    .textFieldStyle(.plain)
                    .multilineTextAlignment(.center)
                    .font(.subheadline)
                    .foregroundColor(VeilColors.secondaryText)
                    .padding(.horizontal, VeilSpacing.xxl)
                    .padding(.bottom, VeilSpacing.xl)

                Spacer()

                // Numeric keypad
                NumericKeypad(value: $amount)
                    .padding(.horizontal, VeilSpacing.xl)

                // Send button
                Button {
                    showConfirmation = true
                } label: {
                    Text("Send Payment")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, VeilSpacing.md)
                }
                .buttonStyle(.borderedProminent)
                .disabled(amount.isEmpty || amount == "0")
                .padding(.horizontal, VeilSpacing.xl)
                .padding(.vertical, VeilSpacing.lg)
            }
            .navigationTitle("Send Payment")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .sheet(isPresented: $showConfirmation) {
                PaymentConfirmationView(
                    amount: amount,
                    currency: currency.rawValue,
                    memo: memo,
                    peerRegistrationId: peerRegistrationId,
                    onConfirm: {
                        onConfirm(amount, currency.rawValue, memo)
                        dismiss()
                    }
                )
            }
        }
    }

    private var displayAmount: String {
        if amount.isEmpty {
            return currency == .usd ? "$0.00" : "0.000"
        }
        let prefix = currency == .usd ? "$" : ""
        return "\(prefix)\(amount)"
    }
}

// MARK: - Numeric Keypad

/// Custom numeric keypad for fast amount entry.
struct NumericKeypad: View {
    @Binding var value: String

    private let keys: [[String]] = [
        ["1", "2", "3"],
        ["4", "5", "6"],
        ["7", "8", "9"],
        [".", "0", "delete"],
    ]

    var body: some View {
        VStack(spacing: VeilSpacing.sm) {
            ForEach(keys, id: \.self) { row in
                HStack(spacing: VeilSpacing.sm) {
                    ForEach(row, id: \.self) { key in
                        keyButton(key)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func keyButton(_ key: String) -> some View {
        Button {
            handleKeyPress(key)
        } label: {
            Group {
                if key == "delete" {
                    Image(systemName: "delete.left")
                        .font(.title3)
                } else {
                    Text(key)
                        .font(VeilTypography.keypadDigit)
                }
            }
            .frame(maxWidth: .infinity)
            .frame(height: 52)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundColor(.primary)
    }

    private func handleKeyPress(_ key: String) {
        switch key {
        case "delete":
            if !value.isEmpty {
                value.removeLast()
            }
        case ".":
            if !value.contains(".") {
                value += value.isEmpty ? "0." : "."
            }
        default:
            // Limit decimal places
            if let dotIndex = value.firstIndex(of: ".") {
                let decimals = value[value.index(after: dotIndex)...]
                if decimals.count >= 6 { return } // Max 6 decimal places for MOB
            }
            // Limit total length
            if value.count < 12 {
                value += key
            }
        }
    }
}
