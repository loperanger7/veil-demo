// VEIL — Timestamp Formatter
// Spec reference: Section 5.2
//
// Contextual timestamps that reduce visual noise.
// Instead of showing "March 4, 2026 at 2:34 PM" on every message,
// timestamps appear between message groups and use natural language:
//   - "Just now" (< 1 minute)
//   - "2:34 PM" (today)
//   - "Yesterday"
//   - "Monday" (within the last week)
//   - "Mar 4" (this year)
//   - "Mar 4, 2025" (previous years)

import Foundation

public enum TimestampFormatter {

    /// Format a timestamp for display in the conversation list.
    /// Shows the most compact useful representation.
    public static func conversationList(_ date: Date) -> String {
        let now = Date()
        let calendar = Calendar.current

        if calendar.isDateInToday(date) {
            return timeOnly(date)
        } else if calendar.isDateInYesterday(date) {
            return "Yesterday"
        } else if isWithinLastWeek(date, from: now, calendar: calendar) {
            return dayOfWeek(date)
        } else if calendar.component(.year, from: date) == calendar.component(.year, from: now) {
            return shortDate(date)
        } else {
            return fullDate(date)
        }
    }

    /// Format a timestamp for contextual display between message groups.
    /// Only shown when there's a significant time gap between messages.
    public static func messageGroup(_ date: Date) -> String {
        let now = Date()
        let calendar = Calendar.current

        if calendar.isDateInToday(date) {
            return "Today \(timeOnly(date))"
        } else if calendar.isDateInYesterday(date) {
            return "Yesterday \(timeOnly(date))"
        } else if isWithinLastWeek(date, from: now, calendar: calendar) {
            return "\(dayOfWeek(date)) \(timeOnly(date))"
        } else {
            return "\(shortDate(date)) \(timeOnly(date))"
        }
    }

    /// Format a timestamp for individual message display (when tapped).
    public static func messageDetail(_ date: Date) -> String {
        let now = Date()
        let interval = now.timeIntervalSince(date)

        if interval < 60 {
            return "Just now"
        } else {
            return timeOnly(date)
        }
    }

    /// Determine if a timestamp separator should be shown between two messages.
    /// Shows a separator when there's more than 15 minutes between messages.
    public static func shouldShowSeparator(
        previous: Date?,
        current: Date
    ) -> Bool {
        guard let previous = previous else {
            return true // Always show for first message
        }
        return current.timeIntervalSince(previous) > 15 * 60
    }

    // MARK: - Private Helpers

    private static func timeOnly(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .none
        formatter.timeStyle = .short
        return formatter.string(from: date)
    }

    private static func dayOfWeek(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "EEEE"
        return formatter.string(from: date)
    }

    private static func shortDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d"
        return formatter.string(from: date)
    }

    private static func fullDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "MMM d, yyyy"
        return formatter.string(from: date)
    }

    private static func isWithinLastWeek(
        _ date: Date,
        from now: Date,
        calendar: Calendar
    ) -> Bool {
        guard let weekAgo = calendar.date(byAdding: .day, value: -7, to: now) else {
            return false
        }
        return date >= weekAgo
    }
}
