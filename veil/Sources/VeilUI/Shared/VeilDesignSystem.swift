// VEIL — Design System
// Spec reference: Section 5.2
//
// "The best design is the least design."
//
// Visual language drawn from Dieter Rams and the original iOS Human
// Interface Guidelines. No unnecessary elements, no gratuitous
// decoration, no features for their own sake.
//
// Encryption is not a feature; it is a precondition. There are no
// lock icons, no "encrypted" badges, no security theater UI.

import SwiftUI

// MARK: - Colors

/// Veil's color palette — deliberately minimal.
public enum VeilColors {
    /// Primary accent color used for outgoing message bubbles and interactive elements.
    public static let accent = Color.blue

    /// Outgoing message bubble background — subtle tint.
    public static let outgoingBubble = Color.blue.opacity(0.12)

    /// Incoming message bubble background — clean white.
    public static let incomingBubble = Color(.systemBackground)

    /// Incoming message bubble border — whisper-thin separator.
    public static let incomingBubbleBorder = Color(.separator).opacity(0.3)

    /// Payment bubble gradient — start color.
    public static let paymentGradientStart = Color.blue.opacity(0.6)

    /// Payment bubble gradient — end color.
    public static let paymentGradientEnd = Color.purple.opacity(0.4)

    /// Unread badge background.
    public static let unreadBadge = Color.blue

    /// Timestamp and secondary text.
    public static let secondaryText = Color(.secondaryLabel)

    /// Composer background.
    public static let composerBackground = Color(.systemGray6)

    /// Subtle divider.
    public static let divider = Color(.separator).opacity(0.5)
}

// MARK: - Typography

/// San Francisco typeface at sizes optimized for readability.
/// No custom fonts — the system font is the right choice.
public enum VeilTypography {
    /// Large title for balance display.
    public static let balanceAmount = Font.system(size: 48, weight: .thin, design: .default)

    /// Section headers.
    public static let sectionHeader = Font.caption.weight(.semibold)

    /// Conversation list — contact name.
    public static let contactName = Font.body.weight(.medium)

    /// Conversation list — message preview.
    public static let messagePreview = Font.subheadline

    /// Conversation list — timestamp.
    public static let timestamp = Font.caption

    /// Chat — message body.
    public static let messageBody = Font.body

    /// Chat — contextual timestamp between messages.
    public static let contextualTimestamp = Font.caption2.weight(.medium)

    /// Payment amount in bubble.
    public static let paymentAmount = Font.title2.weight(.semibold)

    /// Payment memo.
    public static let paymentMemo = Font.subheadline

    /// Safety number — monospaced digits.
    public static let safetyNumber = Font.system(.body, design: .monospaced)

    /// Numeric keypad digits.
    public static let keypadDigit = Font.system(size: 28, weight: .light)

    /// Amount entry display.
    public static let amountDisplay = Font.system(size: 56, weight: .ultraLight)
}

// MARK: - Spacing

/// Consistent spacing scale.
public enum VeilSpacing {
    public static let xxs: CGFloat = 2
    public static let xs: CGFloat = 4
    public static let sm: CGFloat = 8
    public static let md: CGFloat = 12
    public static let lg: CGFloat = 16
    public static let xl: CGFloat = 24
    public static let xxl: CGFloat = 32
    public static let xxxl: CGFloat = 48

    /// Horizontal padding for message bubbles.
    public static let bubblePaddingH: CGFloat = 14
    /// Vertical padding for message bubbles.
    public static let bubblePaddingV: CGFloat = 10
    /// Corner radius for message bubbles.
    public static let bubbleCornerRadius: CGFloat = 18
    /// Maximum bubble width as fraction of screen width.
    public static let maxBubbleWidthFraction: CGFloat = 0.75
}

// MARK: - Animations

/// Veil uses subtle, non-distracting animations.
public enum VeilAnimation {
    /// Default animation for UI transitions.
    public static let standard = Animation.easeInOut(duration: 0.2)
    /// Scroll-to-bottom animation.
    public static let scroll = Animation.easeOut(duration: 0.3)
    /// Payment confirmation appearance.
    public static let paymentConfirm = Animation.spring(response: 0.4, dampingFraction: 0.8)
}
