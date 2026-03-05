// VEIL — Chat ViewModel
// Ticket: VEIL-505
// Spec reference: Section 5.2
//
// Manages the state for a single chat conversation:
//   - Message history (in-memory)
//   - Send outbound messages via MessagePipeline
//   - Poll for inbound messages
//   - Typing indicators
//   - Read receipts
//
// All encryption/decryption happens transparently through
// the MessagePipeline — the ViewModel never sees keys or ciphertext.

import SwiftUI
import VeilCrypto

/// Typing indicator state.
public enum TypingState: Sendable {
    case idle
    case typing
}

@Observable
public final class ChatViewModel {
    /// Peer's registration ID.
    public let peerRegistrationId: UInt32

    /// Message history for this conversation.
    public private(set) var messages: [MessageDisplayItem] = []

    /// Draft text in the composer.
    public var draftText: String = ""

    /// Whether a send or receive operation is in progress.
    public private(set) var isSending: Bool = false

    /// Peer's typing state.
    public private(set) var peerTyping: TypingState = .idle

    /// Error from the last operation (cleared on next success).
    public private(set) var lastError: Error?

    /// Our registration ID (for determining outgoing messages).
    private let ourRegistrationId: UInt32

    private let context: RegistrationContext
    private var pollingTask: Task<Void, Never>?

    public init(peerRegistrationId: UInt32, context: RegistrationContext) {
        self.peerRegistrationId = peerRegistrationId
        self.context = context
        self.ourRegistrationId = context.registrationId
    }

    // MARK: - Send

    /// Send a text message.
    public func sendTextMessage() async {
        let text = draftText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }

        isSending = true
        lastError = nil

        // Optimistically add to local history
        let optimisticItem = MessageDisplayItem(
            senderRegistrationId: ourRegistrationId,
            isOutgoing: true,
            text: text,
            contentType: 1, // .text
            timestamp: Date()
        )
        messages.append(optimisticItem)
        draftText = ""

        do {
            try await context.messagePipeline.sendMessage(
                plaintext: Data(text.utf8),
                to: peerRegistrationId,
                contentType: .text
            )
        } catch {
            // Remove optimistic message on failure
            messages.removeAll { $0.id == optimisticItem.id }
            draftText = text // Restore draft
            lastError = error
        }

        isSending = false
    }

    /// Send a payment message.
    public func sendPaymentMessage(
        amount: String,
        currency: String,
        memo: String
    ) async {
        isSending = true
        lastError = nil

        // Build payment payload
        let paymentData = """
        {"amount":"\(amount)","currency":"\(currency)","memo":"\(memo)"}
        """.data(using: .utf8) ?? Data()

        // Optimistically add payment bubble
        let optimisticItem = MessageDisplayItem(
            senderRegistrationId: ourRegistrationId,
            isOutgoing: true,
            text: "Payment: \(amount) \(currency)",
            contentType: 3, // .payment
            timestamp: Date(),
            paymentAmount: amount,
            paymentCurrency: currency,
            paymentMemo: memo.isEmpty ? nil : memo
        )
        messages.append(optimisticItem)

        do {
            try await context.messagePipeline.sendMessage(
                plaintext: paymentData,
                to: peerRegistrationId,
                contentType: .payment
            )
        } catch {
            messages.removeAll { $0.id == optimisticItem.id }
            lastError = error
        }

        isSending = false
    }

    // MARK: - Receive

    /// Start polling for inbound messages.
    public func startReceiving() {
        pollingTask?.cancel()
        pollingTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollMessages()
                try? await Task.sleep(nanoseconds: 2_000_000_000) // 2 seconds
            }
        }
    }

    /// Stop polling.
    public func stopReceiving() {
        pollingTask?.cancel()
        pollingTask = nil
    }

    /// Poll for new messages from this peer.
    private func pollMessages() async {
        do {
            let incoming = try await context.messagePipeline.retrieveAndProcessMessages()

            for message in incoming where message.senderRegistrationId == peerRegistrationId {
                let displayItem = convertToDisplayItem(message)
                // Avoid duplicates
                if !messages.contains(where: { $0.serverGuid == displayItem.serverGuid && displayItem.serverGuid != nil }) {
                    messages.append(displayItem)
                }
            }
        } catch {
            // Silent — will retry
        }
    }

    /// Convert a DecryptedMessage to a MessageDisplayItem.
    private func convertToDisplayItem(_ message: DecryptedMessage) -> MessageDisplayItem {
        let text = String(data: message.plaintext, encoding: .utf8) ?? ""
        let isPayment = message.contentType == .payment

        var paymentAmount: String?
        var paymentCurrency: String?
        var paymentMemo: String?

        if isPayment, let json = try? JSONSerialization.jsonObject(with: message.plaintext) as? [String: String] {
            paymentAmount = json["amount"]
            paymentCurrency = json["currency"]
            paymentMemo = json["memo"]
        }

        return MessageDisplayItem(
            senderRegistrationId: message.senderRegistrationId,
            isOutgoing: false,
            text: isPayment ? "Payment: \(paymentAmount ?? "?") \(paymentCurrency ?? "")" : text,
            contentType: message.contentType.rawValue,
            timestamp: Date(timeIntervalSince1970: TimeInterval(message.serverTimestamp) / 1000),
            serverGuid: message.serverGuid,
            paymentAmount: paymentAmount,
            paymentCurrency: paymentCurrency,
            paymentMemo: paymentMemo
        )
    }

    // MARK: - Safety Number

    /// Compute the safety number for this peer.
    public func computeSafetyNumber() async -> String? {
        guard let data = await context.sessionManager.computeSafetyNumber(for: peerRegistrationId) else {
            return nil
        }

        // Convert to 60-digit numeric code
        return data.map { String(format: "%03d", $0 % 100) }
            .prefix(20)
            .joined(separator: " ")
    }
}
