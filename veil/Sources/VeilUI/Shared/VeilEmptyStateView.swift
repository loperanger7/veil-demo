// VEIL — Empty State View
// Reusable empty state placeholder, replacing ContentUnavailableView
// for broader iOS version compatibility.

import SwiftUI

/// A simple empty-state view with an icon, title, and description.
/// Drop-in replacement for ContentUnavailableView.
public struct VeilEmptyStateView: View {
    let title: String
    let systemImage: String
    let description: String

    public init(title: String, systemImage: String, description: String) {
        self.title = title
        self.systemImage = systemImage
        self.description = description
    }

    public var body: some View {
        VStack(spacing: VeilSpacing.lg) {
            Image(systemName: systemImage)
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text(title)
                .font(.headline)
            Text(description)
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
    }
}
