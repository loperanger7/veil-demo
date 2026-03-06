// VEIL — Settings View
// Ticket: VEIL-509
// Spec reference: Section 5.2
//
// Deliberately minimal settings surface.
// "No encryption settings — there are no choices to make."
//
// Sections:
//   - Profile (name, phone, registration ID)
//   - Linked Devices
//   - Notifications (on/off, preview always off by default)
//   - About (version, open-source licenses)

import SwiftUI
import VeilCrypto

public struct SettingsView: View {
    let context: RegistrationContext?

    @State private var notificationsEnabled: Bool = true
    @State private var showLinkedDevices: Bool = false

    public init(context: RegistrationContext?) {
        self.context = context
    }

    public var body: some View {
        Form {
            // Profile
            Section {
                HStack(spacing: VeilSpacing.md) {
                    Circle()
                        .fill(Color.gray.opacity(0.4))
                        .frame(width: 56, height: 56)
                        .overlay(
                            Image(systemName: "person.fill")
                                .font(.title2)
                                .foregroundColor(.white)
                        )

                    VStack(alignment: .leading, spacing: VeilSpacing.xxs) {
                        Text("Veil User")
                            .font(.headline)

                        if let context = context {
                            Text("ID: \(context.registrationId)")
                                .font(.caption)
                                .foregroundColor(VeilColors.secondaryText)
                        }
                    }
                }
                .padding(.vertical, VeilSpacing.xs)
            }

            // Linked Devices
            Section(header: Text("Linked Devices")) {
                NavigationLink {
                    LinkedDevicesPlaceholder()
                } label: {
                    Label("Manage Devices", systemImage: "laptopcomputer.and.iphone")
                }
            }

            // Notifications
            Section(header: Text("Notifications"), footer: Text("Message previews are always disabled for privacy.")) {
                Toggle("Enable Notifications", isOn: $notificationsEnabled)

                HStack {
                    Text("Message Preview")
                    Spacer()
                    Text("Off")
                        .foregroundColor(VeilColors.secondaryText)
                }
            }

            // About
            Section(header: Text("About")) {
                HStack {
                    Text("Version")
                    Spacer()
                    Text("1.0.0")
                        .foregroundColor(VeilColors.secondaryText)
                }

                NavigationLink {
                    LicensesPlaceholder()
                } label: {
                    Text("Open Source Licenses")
                }
            }
        }
        .navigationTitle("Settings")
    }
}

// MARK: - Placeholder Views

struct LinkedDevicesPlaceholder: View {
    var body: some View {
        VStack(spacing: VeilSpacing.lg) {
            Image(systemName: "link.circle")
                .font(.system(size: 48))
                .foregroundColor(.secondary)
            Text("No Linked Devices")
                .font(.headline)
            Text("Scan a QR code from another device to link it.")
                .font(.subheadline)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .padding()
        .navigationTitle("Linked Devices")
    }
}

struct LicensesPlaceholder: View {
    var body: some View {
        List {
            ForEach(licenses, id: \.name) { license in
                VStack(alignment: .leading, spacing: VeilSpacing.sm) {
                    Text(license.name)
                        .font(.headline)
                    Text(license.license)
                        .font(.caption)
                        .foregroundColor(VeilColors.secondaryText)
                }
                .padding(.vertical, VeilSpacing.xs)
            }
        }
        .navigationTitle("Licenses")
    }

    private var licenses: [(name: String, license: String)] {
        [
            ("liboqs", "MIT License"),
            ("CryptoKit", "Apple License"),
            ("curve25519-dalek", "BSD-3-Clause"),
            ("MobileCoin", "Apache 2.0"),
            ("SwiftCheck", "MIT License"),
        ]
    }
}
