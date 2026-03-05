// VEIL — Message Bubble Views
// Ticket: VEIL-505
// Spec reference: Section 5.2
//
// Message bubble styling:
//   - Outgoing: subtle tinted background, trailing alignment
//   - Incoming: white background with whisper border, leading alignment
//   - Payment: subtle gradient border, special layout with amount + memo
//
// No encryption indicators. No lock icons. No "sent securely" text.
// The entire app is encrypted — it would be redundant to show it.

import SwiftUI

// MARK: - Message Display Item

/// UI-friendly representation of a message.
public struct MessageDisplayItem: Identifiable, Sendable {
    public let id: UUID
    public let senderRegistrationId: UInt32
    public let isOutgoing: Bool
    public let text: String
    public let contentType: UInt32
    public let timestamp: Date
    public let isRead: Bool
    public let serverGuid: Data?

    /// Payment-specific fields (populated when contentType == .payment)
    public let paymentAmount: String?
    public let paymentCurrency: String?
    public let paymentMemo: String?

    public init(
        id: UUID = UUID(),
        senderRegistrationId: UInt32,
        isOutgoing: Bool,
        text: String,
        contentType: UInt32 = 1,
        timestamp: Date = Date(),
        isRead: Bool = false,
        serverGuid: Data? = nil,
        paymentAmount: String? = nil,
        paymentCurrency: String? = nil,
        paymentMemo: String? = nil
    ) {
        self.id = id
        self.senderRegistrationId = senderRegistrationId
        self.isOutgoing = isOutgoing
        self.text = text
        self.contentType = contentType
        self.timestamp = timestamp
        self.isRead = isRead
        self.serverGuid = serverGuid
        self.paymentAmount = paymentAmount
        self.paymentCurrency = paymentCurrency
        self.paymentMemo = paymentMemo
    }
}

// MARK: - Outgoing Message Bubble

/// Outgoing message: subtle tinted background, right-aligned.
public struct OutgoingBubble: View {
    let item: MessageDisplayItem

    public init(item: MessageDisplayItem) {
        self.item = item
    }

    public var body: some View {
        VStack(alignment: .trailing, spacing: VeilSpacing.xxs) {
            Text(item.text)
                .font(VeilTypography.messageBody)
                .foregroundColor(.primary)
                .padding(.horizontal, VeilSpacing.bubblePaddingH)
                .padding(.vertical, VeilSpacing.bubblePaddingV)
                .background(VeilColors.outgoingBubble)
                .clipShape(BubbleShape(isOutgoing: true))

            if item.isRead {
                Text("Read")
                    .font(.caption2)
                    .foregroundColor(VeilColors.secondaryText)
                    .padding(.trailing, VeilSpacing.xs)
            }
        }
    }
}

// MARK: - Incoming Message Bubble

/// Incoming message: white background with subtle border, left-aligned.
public struct IncomingBubble: View {
    let item: MessageDisplayItem

    public init(item: MessageDisplayItem) {
        self.item = item
    }

    public var body: some View {
        Text(item.text)
            .font(VeilTypography.messageBody)
            .foregroundColor(.primary)
            .padding(.horizontal, VeilSpacing.bubblePaddingH)
            .padding(.vertical, VeilSpacing.bubblePaddingV)
            .background(VeilColors.incomingBubble)
            .clipShape(BubbleShape(isOutgoing: false))
            .overlay(
                BubbleShape(isOutgoing: false)
                    .stroke(VeilColors.incomingBubbleBorder, lineWidth: 0.5)
            )
    }
}

// MARK: - Payment Bubble

/// Payment message: gradient border, amount display, optional memo.
public struct PaymentBubble: View {
    let item: MessageDisplayItem

    public init(item: MessageDisplayItem) {
        self.item = item
    }

    public var body: some View {
        VStack(alignment: item.isOutgoing ? .trailing : .leading, spacing: VeilSpacing.sm) {
            // Amount
            HStack(spacing: VeilSpacing.sm) {
                Image(systemName: item.isOutgoing ? "arrow.up.circle.fill" : "arrow.down.circle.fill")
                    .foregroundColor(item.isOutgoing ? .orange : .green)
                    .font(.title3)

                VStack(alignment: .leading, spacing: 2) {
                    Text(item.paymentAmount ?? "0.00")
                        .font(VeilTypography.paymentAmount)

                    if let currency = item.paymentCurrency {
                        Text(currency)
                            .font(.caption)
                            .foregroundColor(VeilColors.secondaryText)
                    }
                }
            }

            // Memo (if present)
            if let memo = item.paymentMemo, !memo.isEmpty {
                Text(memo)
                    .font(VeilTypography.paymentMemo)
                    .foregroundColor(VeilColors.secondaryText)
            }
        }
        .padding(.horizontal, VeilSpacing.bubblePaddingH + 2)
        .padding(.vertical, VeilSpacing.bubblePaddingV + 4)
        .background(
            item.isOutgoing
                ? AnyShapeStyle(VeilColors.outgoingBubble)
                : AnyShapeStyle(VeilColors.incomingBubble)
        )
        .clipShape(BubbleShape(isOutgoing: item.isOutgoing))
        .overlay(
            BubbleShape(isOutgoing: item.isOutgoing)
                .stroke(
                    LinearGradient(
                        colors: [VeilColors.paymentGradientStart, VeilColors.paymentGradientEnd],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    ),
                    lineWidth: 1.5
                )
        )
    }
}

// MARK: - Typing Indicator

/// Animated typing indicator (three dots).
public struct TypingIndicatorBubble: View {
    @State private var animating = false

    public init() {}

    public var body: some View {
        HStack(spacing: 4) {
            ForEach(0..<3) { index in
                Circle()
                    .fill(Color(.tertiaryLabel))
                    .frame(width: 7, height: 7)
                    .scaleEffect(animating ? 1.0 : 0.5)
                    .animation(
                        .easeInOut(duration: 0.6)
                            .repeatForever()
                            .delay(Double(index) * 0.2),
                        value: animating
                    )
            }
        }
        .padding(.horizontal, VeilSpacing.bubblePaddingH)
        .padding(.vertical, VeilSpacing.bubblePaddingV)
        .background(VeilColors.incomingBubble)
        .clipShape(BubbleShape(isOutgoing: false))
        .overlay(
            BubbleShape(isOutgoing: false)
                .stroke(VeilColors.incomingBubbleBorder, lineWidth: 0.5)
        )
        .onAppear { animating = true }
    }
}

// MARK: - Timestamp Separator

/// Contextual timestamp displayed between message groups.
public struct TimestampSeparator: View {
    let date: Date

    public init(date: Date) {
        self.date = date
    }

    public var body: some View {
        Text(TimestampFormatter.messageGroup(date))
            .font(VeilTypography.contextualTimestamp)
            .foregroundColor(VeilColors.secondaryText)
            .padding(.vertical, VeilSpacing.sm)
    }
}

// MARK: - Bubble Shape

/// Custom bubble shape with a subtle tail.
struct BubbleShape: Shape {
    let isOutgoing: Bool

    func path(in rect: CGRect) -> Path {
        let radius = VeilSpacing.bubbleCornerRadius

        var path = Path()

        if isOutgoing {
            // Rounded rect with slightly flattened bottom-right corner
            path.addRoundedRect(
                in: rect,
                cornerRadii: RectangleCornerRadii(
                    topLeading: radius,
                    bottomLeading: radius,
                    bottomTrailing: radius * 0.3,
                    topTrailing: radius
                )
            )
        } else {
            // Rounded rect with slightly flattened bottom-left corner
            path.addRoundedRect(
                in: rect,
                cornerRadii: RectangleCornerRadii(
                    topLeading: radius,
                    bottomLeading: radius * 0.3,
                    bottomTrailing: radius,
                    topTrailing: radius
                )
            )
        }

        return path
    }
}

// MARK: - Unread Badge

/// Small circular badge showing unread message count.
public struct UnreadBadge: View {
    let count: Int

    public init(count: Int) {
        self.count = count
    }

    public var body: some View {
        if count > 0 {
            Text(count > 99 ? "99+" : "\(count)")
                .font(.caption2.weight(.bold))
                .foregroundColor(.white)
                .padding(.horizontal, 6)
                .padding(.vertical, 2)
                .background(VeilColors.unreadBadge)
                .clipShape(Capsule())
        }
    }
}
