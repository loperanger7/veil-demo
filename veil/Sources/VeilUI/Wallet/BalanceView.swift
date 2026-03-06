// VEIL — Balance View
// Ticket: VEIL-507
// Spec reference: Section 5.2
//
// Balance display in MOB and local currency equivalent.
// Transaction history with pull-to-refresh.
// Clean, minimal — no charts, no graphs, just numbers and a list.

import SwiftUI

/// A single transaction for display.
struct TransactionItem: Identifiable {
    let id = UUID()
    let isSent: Bool
    let amount: String
    let currency: String
    let peerName: String
    let memo: String?
    let timestamp: Date
}

public struct BalanceView: View {
    @State private var balanceMOB: String = "0.000000"
    @State private var balanceUSD: String = "0.00"
    @State private var transactions: [TransactionItem] = []
    @State private var isLoading: Bool = false

    public init() {}

    public var body: some View {
        VStack(spacing: 0) {
            // Balance header
            VStack(spacing: VeilSpacing.sm) {
                Text("Balance")
                    .font(VeilTypography.sectionHeader)
                    .foregroundColor(VeilColors.secondaryText)
                    .textCase(.uppercase)

                Text("\(balanceMOB) MOB")
                    .font(VeilTypography.balanceAmount)

                Text("~ $\(balanceUSD)")
                    .font(.subheadline)
                    .foregroundColor(VeilColors.secondaryText)
            }
            .padding(.vertical, VeilSpacing.xxl)
            .frame(maxWidth: .infinity)

            Divider()

            // Transaction history
            if transactions.isEmpty {
                Spacer()
                VeilEmptyStateView(
                    title: "No transactions",
                    systemImage: "arrow.left.arrow.right",
                    description: "Send or receive a payment to see it here."
                )
                Spacer()
            } else {
                List {
                    ForEach(groupedByDate, id: \.0) { date, items in
                        Section {
                            ForEach(items) { transaction in
                                TransactionRow(item: transaction)
                            }
                        } header: {
                            Text(TimestampFormatter.conversationList(date))
                        }
                    }
                }
                .listStyle(.plain)
            }
        }
        .navigationTitle("Wallet")
        .refreshable {
            await refreshBalance()
        }
    }

    /// Group transactions by day for section headers.
    private var groupedByDate: [(Date, [TransactionItem])] {
        let calendar = Calendar.current
        let grouped = Dictionary(grouping: transactions) { item in
            calendar.startOfDay(for: item.timestamp)
        }
        return grouped.sorted { $0.key > $1.key }
    }

    /// Refresh balance from MobileCoin Fog service.
    private func refreshBalance() async {
        isLoading = true
        defer { isLoading = false }

        // In production, this would query MobileCoin Fog via the payment layer.
        // For now, this is a placeholder.
        try? await Task.sleep(nanoseconds: 500_000_000)
    }
}

// MARK: - Transaction Row

struct TransactionRow: View {
    let item: TransactionItem

    var body: some View {
        HStack(spacing: VeilSpacing.md) {
            // Direction indicator
            Image(systemName: item.isSent ? "arrow.up.circle.fill" : "arrow.down.circle.fill")
                .font(.title3)
                .foregroundColor(item.isSent ? .orange : .green)

            // Details
            VStack(alignment: .leading, spacing: VeilSpacing.xxs) {
                Text(item.peerName)
                    .font(VeilTypography.contactName)

                if let memo = item.memo, !memo.isEmpty {
                    Text(memo)
                        .font(.caption)
                        .foregroundColor(VeilColors.secondaryText)
                        .lineLimit(1)
                }
            }

            Spacer()

            // Amount
            VStack(alignment: .trailing, spacing: VeilSpacing.xxs) {
                Text("\(item.isSent ? "-" : "+")\(item.amount)")
                    .font(.body.weight(.medium))
                    .foregroundColor(item.isSent ? .primary : .green)

                Text(item.currency)
                    .font(.caption)
                    .foregroundColor(VeilColors.secondaryText)
            }
        }
        .padding(.vertical, VeilSpacing.xs)
    }
}
