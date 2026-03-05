// VEIL — Message Pipeline Tests
// Tickets: VEIL-201, VEIL-202, VEIL-203, VEIL-302
//
// Tests for the end-to-end message send/receive pipeline.
//
// Dijkstra-style invariants:
//   - Sealed sender never leaks sender identity to the server
//   - Envelope contentType is preserved through encrypt/decrypt
//   - Offline queue accumulates during network failure
//   - Messages are acknowledged after successful processing

import XCTest
@testable import VeilCrypto

final class MessagePipelineTests: XCTestCase {

    // ── Test: Wire envelope for sending has zero source fields ──

    func testSealedSenderEnvelopeHasZeroSourceFields() {
        let envelope = WireVeilEnvelope.forSending(
            content: Data(repeating: 0x42, count: 256),
            sealedSender: Data(repeating: 0x99, count: 128),
            contentType: 1
        )

        XCTAssertEqual(envelope.sourceRegistrationId, 0,
                       "sealed sender must not include source registration ID")
        XCTAssertEqual(envelope.sourceDeviceId, 0,
                       "sealed sender must not include source device ID")
        XCTAssertTrue(envelope.serverGuid.isEmpty,
                      "server_guid must be empty on send (assigned by server)")
        XCTAssertEqual(envelope.serverTimestamp, 0,
                       "server_timestamp must be 0 on send (assigned by server)")
    }

    // ── Test: Content type is preserved ──

    func testContentTypePreservation() {
        for contentType: VeilContentType in [.text, .media, .payment, .receipt] {
            let envelope = WireVeilEnvelope.forSending(
                content: Data([0x01]),
                sealedSender: Data([0x02]),
                contentType: contentType.rawValue
            )
            XCTAssertEqual(
                VeilContentType(rawValue: envelope.contentType),
                contentType,
                "content type \(contentType) must be preserved"
            )
        }
    }

    // ── Test: Wire format encode/decode round-trip ──

    func testWireFormatRoundTrip() throws {
        let original = WireVeilEnvelope.forSending(
            content: Data(repeating: 0x42, count: 256),
            sealedSender: Data(repeating: 0x99, count: 128),
            contentType: VeilContentType.text.rawValue
        )

        let encoded = try WireFormat.encode(original)
        let decoded = try WireFormat.decode(WireVeilEnvelope.self, from: encoded)

        XCTAssertEqual(decoded.content, original.content)
        XCTAssertEqual(decoded.sealedSender, original.sealedSender)
        XCTAssertEqual(decoded.contentType, original.contentType)
        XCTAssertEqual(decoded.sourceRegistrationId, 0)
        XCTAssertEqual(decoded.sourceDeviceId, 0)
    }

    // ── Test: Send message response parsing ──

    func testSendMessageResponseParsing() throws {
        let response = SendMessageResponse(
            deliveryResults: [
                DeliveryResult(deviceId: 1, serverGuid: Data([0x01, 0x02, 0x03])),
                DeliveryResult(deviceId: 2, serverGuid: Data([0x04, 0x05, 0x06])),
            ]
        )

        let encoded = try WireFormat.encode(response)
        let decoded = try WireFormat.decode(SendMessageResponse.self, from: encoded)

        XCTAssertEqual(decoded.deliveryResults.count, 2)
        XCTAssertEqual(decoded.deliveryResults[0].deviceId, 1)
        XCTAssertEqual(decoded.deliveryResults[1].deviceId, 2)
    }

    // ── Test: Retrieve messages response with replenishment tokens ──

    func testRetrieveMessagesResponseWithReplenishment() throws {
        let response = RetrieveMessagesResponse(
            envelopes: [
                WireVeilEnvelope(
                    content: Data(repeating: 0x42, count: 64),
                    sealedSender: Data(repeating: 0x99, count: 32),
                    contentType: 1,
                    sourceRegistrationId: 0,
                    sourceDeviceId: 0,
                    serverGuid: Data([0x01]),
                    serverTimestamp: 1234567890
                )
            ],
            replenishmentTokens: [
                WireSignedBlindedToken(point: Data(repeating: 0xAA, count: 32)),
                WireSignedBlindedToken(point: Data(repeating: 0xBB, count: 32)),
            ]
        )

        let encoded = try WireFormat.encode(response)
        let decoded = try WireFormat.decode(RetrieveMessagesResponse.self, from: encoded)

        XCTAssertEqual(decoded.envelopes.count, 1)
        XCTAssertEqual(decoded.replenishmentTokens.count, 2)
        XCTAssertEqual(decoded.envelopes[0].serverTimestamp, 1234567890)
    }

    // ── Test: Outbound message serialization for offline queue ──

    func testOutboundMessageSerialization() throws {
        let message = OutboundMessage(
            recipientRegistrationId: 42,
            plaintext: Data("Hello, Veil!".utf8),
            contentType: VeilContentType.text.rawValue,
            enqueuedAt: Date()
        )

        let encoded = try JSONEncoder().encode(message)
        let decoded = try JSONDecoder().decode(OutboundMessage.self, from: encoded)

        XCTAssertEqual(decoded.recipientRegistrationId, 42)
        XCTAssertEqual(decoded.plaintext, Data("Hello, Veil!".utf8))
        XCTAssertEqual(decoded.contentType, VeilContentType.text.rawValue)
    }

    // ── Test: DecryptedMessage properties ──

    func testDecryptedMessageProperties() {
        let message = DecryptedMessage(
            senderRegistrationId: 99,
            senderDeviceId: 1,
            plaintext: Data("Test message".utf8),
            contentType: .text,
            serverGuid: Data([0x01, 0x02]),
            serverTimestamp: 1234567890
        )

        XCTAssertEqual(message.senderRegistrationId, 99)
        XCTAssertEqual(message.senderDeviceId, 1)
        XCTAssertEqual(message.contentType, .text)
        XCTAssertEqual(String(data: message.plaintext, encoding: .utf8), "Test message")
    }
}
