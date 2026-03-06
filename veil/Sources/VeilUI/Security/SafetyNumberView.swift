// VEIL — Safety Number Verification
// Ticket: VEIL-508
// Spec reference: Section 5.2
//
// Safety numbers allow users to verify they're communicating with
// the right person. Computed from both parties' identity keys,
// displayed as a 60-digit numeric code and a scannable QR code.
//
// If a contact re-registers with a new identity key, the safety
// number changes and the user is warned.

import SwiftUI
import CoreImage.CIFilterBuiltins
import VeilCrypto

struct SafetyNumberView: View {
    let peerRegistrationId: UInt32
    let context: RegistrationContext

    @Environment(\.dismiss) private var dismiss
    @State private var safetyNumber: String = ""
    @State private var isLoading: Bool = true
    @State private var showScanner: Bool = false
    @State private var scanResult: ScanResult?

    enum ScanResult {
        case match
        case mismatch
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: VeilSpacing.xxl) {
                    if isLoading {
                        ProgressView()
                            .padding(.top, VeilSpacing.xxxl)
                    } else {
                        // Safety number display
                        VStack(spacing: VeilSpacing.lg) {
                            Text("Safety Number")
                                .font(.headline)

                            Text("Compare this number with your contact. If they match, your conversation is secure.")
                                .font(.subheadline)
                                .foregroundColor(VeilColors.secondaryText)
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, VeilSpacing.xl)
                        }

                        // 60-digit code in groups of 5
                        VStack(spacing: VeilSpacing.sm) {
                            ForEach(formattedRows, id: \.self) { row in
                                Text(row)
                                    .font(VeilTypography.safetyNumber)
                                    .tracking(2)
                            }
                        }
                        .padding(VeilSpacing.lg)
                        .background(Color(.sRGB, white: 0.95, opacity: 1.0))
                        .cornerRadius(12)
                        .padding(.horizontal, VeilSpacing.xl)

                        // QR Code
                        if let qrImage = generateQRCode(from: safetyNumber) {
                            Image(uiImage: qrImage)
                                .interpolation(.none)
                                .resizable()
                                .scaledToFit()
                                .frame(width: 200, height: 200)
                                .padding(VeilSpacing.lg)
                                .background(Color.white)
                                .cornerRadius(12)
                        }

                        // Scan button
                        Button {
                            showScanner = true
                        } label: {
                            Label("Scan Their Code", systemImage: "camera")
                                .font(.headline)
                                .frame(maxWidth: .infinity)
                                .padding(.vertical, VeilSpacing.md)
                        }
                        .buttonStyle(.borderedProminent)
                        .padding(.horizontal, VeilSpacing.xl)

                        // Scan result
                        if let result = scanResult {
                            scanResultView(result)
                        }
                    }
                }
                .padding(.vertical, VeilSpacing.xl)
            }
            .navigationTitle("Verify Contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                }
            }
            .task {
                await loadSafetyNumber()
            }
        }
    }

    // MARK: - Safety Number Computation

    private func loadSafetyNumber() async {
        isLoading = true
        defer { isLoading = false }

        if let data = await context.sessionManager.computeSafetyNumber(for: peerRegistrationId) {
            // Convert hash to 60-digit numeric code
            safetyNumber = data.prefix(30)
                .map { String(format: "%02d", $0 % 100) }
                .joined()
        } else {
            safetyNumber = String(repeating: "0", count: 60)
        }
    }

    /// Format the 60-digit code into rows of 5-digit groups.
    private var formattedRows: [String] {
        let digits = Array(safetyNumber)
        var rows: [String] = []

        // 4 rows of 15 digits each (3 groups of 5)
        for rowStart in stride(from: 0, to: min(digits.count, 60), by: 15) {
            let rowEnd = min(rowStart + 15, digits.count)
            let rowDigits = Array(digits[rowStart..<rowEnd])

            let groups = stride(from: 0, to: rowDigits.count, by: 5).map { start in
                let end = min(start + 5, rowDigits.count)
                return String(rowDigits[start..<end])
            }

            rows.append(groups.joined(separator: " "))
        }

        return rows
    }

    // MARK: - QR Code Generation

    private func generateQRCode(from string: String) -> UIImage? {
        let context = CIContext()
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"

        guard let outputImage = filter.outputImage else { return nil }

        let scale = 200.0 / outputImage.extent.width
        let scaledImage = outputImage.transformed(by: CGAffineTransform(scaleX: scale, y: scale))

        guard let cgImage = context.createCGImage(scaledImage, from: scaledImage.extent) else {
            return nil
        }

        return UIImage(cgImage: cgImage)
    }

    // MARK: - Scan Result

    @ViewBuilder
    private func scanResultView(_ result: ScanResult) -> some View {
        HStack(spacing: VeilSpacing.md) {
            Image(systemName: result == .match ? "checkmark.circle.fill" : "xmark.circle.fill")
                .font(.title2)
                .foregroundColor(result == .match ? .green : .red)

            VStack(alignment: .leading) {
                Text(result == .match ? "Numbers Match" : "Numbers Don't Match")
                    .font(.headline)

                Text(result == .match
                     ? "Your conversation with this contact is verified."
                     : "This may indicate a security issue. Verify in person.")
                    .font(.caption)
                    .foregroundColor(VeilColors.secondaryText)
            }
        }
        .padding(VeilSpacing.lg)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(result == .match ? Color.green.opacity(0.1) : Color.red.opacity(0.1))
        )
        .padding(.horizontal, VeilSpacing.xl)
    }
}
