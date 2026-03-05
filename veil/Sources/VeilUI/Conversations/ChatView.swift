// VEIL — Chat View
// Ticket: VEIL-505
// Spec reference: Section 5.2
//
// The conversation view. Message bubbles, typing indicators,
// contextual timestamps, and the message composer.
//
// Design principles:
//   - Outgoing messages: subtle blue tint, right-aligned
//   - Incoming messages: white, left-aligned
//   - Payment messages: gradient border
//   - No encryption indicators anywhere
//   - Timestamps between groups, not on every message

import SwiftUI
import VeilCrypto

public struct ChatView: View {
    let peerRegistrationId: UInt32
    let context: RegistrationContext

    @State private var viewModel: ChatViewModel
    @State private var showSafetyNumber = false
    @State private var showPaymentFlow = false

    public init(peerRegistrationId: UInt32, context: RegistrationContext) {
        self.peerRegistrationId = peerRegistrationId
        self.context = context
        self._viewModel = State(
            initialValue: ChatViewModel(peerRegistrationId: peerRegistrationId, context: context)
        )
    }

    public var body: some View {
        VStack(spacing: 0) {
            // Message list
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: VeilSpacing.xs) {
                        ForEach(Array(viewModel.messages.enumerated()), id: \.element.id) { index, message in
                            // Contextual timestamp separator
                            let previous = index > 0 ? viewModel.messages[index - 1].timestamp : nil
                            if TimestampFormatter.shouldShowSeparator(previous: previous, current: message.timestamp) {
                                TimestampSeparator(date: message.timestamp)
                            }

                            // Message bubble
                            messageBubble(for: message)
                                .id(message.id)
                        }

                        // Typing indicator
                        if viewModel.peerTyping == .typing {
                            TypingIndicatorBubble()
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.horizontal, VeilSpacing.lg)
                        }
                    }
                    .padding(.horizontal, VeilSpacing.lg)
                    .padding(.vertical, VeilSpacing.sm)
                }
                .onChange(of: viewModel.messages.count) { _, _ in
                    withAnimation(VeilAnimation.scroll) {
                        if let lastId = viewModel.messages.last?.id {
                            proxy.scrollTo(lastId, anchor: .bottom)
                        }
                    }
                }
            }

            Divider()

            // Composer
            MessageComposerView(
                text: $viewModel.draftText,
                isSending: viewModel.isSending,
                onSend: {
                    Task { await viewModel.sendTextMessage() }
                },
                onPayment: {
                    showPaymentFlow = true
                }
            )
        }
        .navigationTitle("Contact \(peerRegistrationId)")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button {
                        showSafetyNumber = true
                    } label: {
                        Label("Verify Safety Number", systemImage: "number")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .sheet(isPresented: $showSafetyNumber) {
            SafetyNumberView(
                peerRegistrationId: peerRegistrationId,
                context: context
            )
        }
        .sheet(isPresented: $showPaymentFlow) {
            PaymentFlowView(
                peerRegistrationId: peerRegistrationId,
                onConfirm: { amount, currency, memo in
                    Task {
                        await viewModel.sendPaymentMessage(
                            amount: amount,
                            currency: currency,
                            memo: memo
                        )
                    }
                }
            )
        }
        .onAppear { viewModel.startReceiving() }
        .onDisappear { viewModel.stopReceiving() }
    }

    // MARK: - Bubble Selection

    @ViewBuilder
    private func messageBubble(for message: MessageDisplayItem) -> some View {
        let isPayment = message.contentType == 3

        if isPayment {
            PaymentBubble(item: message)
                .frame(
                    maxWidth: UIScreen.main.bounds.width * VeilSpacing.maxBubbleWidthFraction,
                    alignment: message.isOutgoing ? .trailing : .leading
                )
                .frame(maxWidth: .infinity, alignment: message.isOutgoing ? .trailing : .leading)
        } else if message.isOutgoing {
            OutgoingBubble(item: message)
                .frame(
                    maxWidth: UIScreen.main.bounds.width * VeilSpacing.maxBubbleWidthFraction,
                    alignment: .trailing
                )
                .frame(maxWidth: .infinity, alignment: .trailing)
        } else {
            IncomingBubble(item: message)
                .frame(
                    maxWidth: UIScreen.main.bounds.width * VeilSpacing.maxBubbleWidthFraction,
                    alignment: .leading
                )
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}
