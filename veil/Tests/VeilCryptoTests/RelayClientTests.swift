// VEIL — Relay Client Tests
// Tickets: VEIL-201, VEIL-202, VEIL-203
//
// Mock-based tests for the HTTP/2 relay client.
// Uses a custom URLProtocol to intercept requests without network I/O.

import XCTest
@testable import VeilCrypto

// MARK: - Mock URL Protocol

/// URLProtocol subclass that intercepts HTTP requests for testing.
final class MockURLProtocol: URLProtocol {
    /// Handler closure set by each test.
    static var requestHandler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.requestHandler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

// MARK: - Tests

final class RelayClientTests: XCTestCase {

    // ── Test: Registration sends correct request ──

    func testRegistrationSendsCorrectEndpoint() async throws {
        var capturedRequest: URLRequest?

        MockURLProtocol.requestHandler = { request in
            capturedRequest = request

            let response = RegistrationResponse(
                registrationId: 42,
                serverPublicKey: Data(repeating: 0xAA, count: 32),
                signedTokens: []
            )
            let body = try WireFormat.encode(response)

            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 201,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                body
            )
        }

        let config = RelayConfiguration.development()
        let client = RelayClient(configuration: config)

        let response = try await client.registerDevice(
            deviceId: 1,
            identityKey: Data(repeating: 0xBB, count: 32),
            blindedTokens: []
        )

        XCTAssertEqual(response.registrationId, 42)
        XCTAssertNotNil(capturedRequest)
        XCTAssertEqual(capturedRequest?.httpMethod, "POST")
        XCTAssertTrue(capturedRequest?.url?.path.contains("/v1/registration") ?? false)
    }

    // ── Test: Prekey upload includes token header ──

    func testPrekeyUploadIncludesTokenHeader() async throws {
        var capturedRequest: URLRequest?

        MockURLProtocol.requestHandler = { request in
            capturedRequest = request
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 204,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                Data()
            )
        }

        let config = RelayConfiguration.development()
        let client = RelayClient(configuration: config)
        await client.setDeviceIdentity(registrationId: 42, deviceId: 1)

        let bundle = RelayPrekeyBundle(
            identityKeyEd25519: Data(repeating: 0xAA, count: 32),
            identityKeyMLDSA: Data(repeating: 0xBB, count: 1952),
            signedPrekeyId: 1,
            signedPrekey: Data(repeating: 0xCC, count: 32),
            signedPrekeySig: Data(repeating: 0xDD, count: 64),
            pqSignedPrekey: Data(repeating: 0xEE, count: 1568),
            pqSignedPrekeySig: Data(repeating: 0xFF, count: 64),
            oneTimePrekeys: [],
            pqOneTimePrekeys: []
        )

        let token = WireSpentToken(point: Data(repeating: 0x42, count: 32))

        try await client.uploadPrekeys(bundle: bundle, token: token)

        XCTAssertNotNil(capturedRequest)
        XCTAssertEqual(capturedRequest?.httpMethod, "PUT")
        XCTAssertNotNil(capturedRequest?.value(forHTTPHeaderField: "X-Veil-Token"))
    }

    // ── Test: Prekey fetch is unauthenticated ──

    func testPrekeyFetchIsUnauthenticated() async throws {
        var capturedRequest: URLRequest?

        MockURLProtocol.requestHandler = { request in
            capturedRequest = request

            let response = PrekeyFetchResponse(
                registrationId: 99,
                bundle: RelayPrekeyBundle(
                    identityKeyEd25519: Data(repeating: 0xAA, count: 32),
                    identityKeyMLDSA: Data(repeating: 0xBB, count: 1952),
                    signedPrekeyId: 1,
                    signedPrekey: Data(repeating: 0xCC, count: 32),
                    signedPrekeySig: Data(repeating: 0xDD, count: 64),
                    pqSignedPrekey: Data(repeating: 0xEE, count: 1568),
                    pqSignedPrekeySig: Data(repeating: 0xFF, count: 64),
                    oneTimePrekeys: [],
                    pqOneTimePrekeys: []
                )
            )
            let body = try WireFormat.encode(response)

            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                body
            )
        }

        let config = RelayConfiguration.development()
        let client = RelayClient(configuration: config)

        let response = try await client.fetchPrekeys(recipientRegistrationId: 99)

        XCTAssertEqual(response.registrationId, 99)
        XCTAssertNil(capturedRequest?.value(forHTTPHeaderField: "X-Veil-Token"),
                     "prekey fetch must NOT include auth token")
    }

    // ── Test: HTTP 404 returns appropriate error ──

    func testHTTP404ReturnsError() async throws {
        MockURLProtocol.requestHandler = { request in
            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 404,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                Data()
            )
        }

        let config = RelayConfiguration.development()
        let client = RelayClient(configuration: config)

        do {
            let _ = try await client.fetchPrekeys(recipientRegistrationId: 999)
            XCTFail("should have thrown")
        } catch let error as RelayError {
            if case .httpError(let statusCode, _) = error {
                XCTAssertEqual(statusCode, 404)
            } else {
                XCTFail("wrong error type: \(error)")
            }
        }
    }

    // ── Test: Message send includes sealed sender envelope ──

    func testMessageSendIncludesEnvelope() async throws {
        var capturedBody: Data?

        MockURLProtocol.requestHandler = { request in
            capturedBody = request.httpBody

            let response = SendMessageResponse(
                deliveryResults: [DeliveryResult(deviceId: 1, serverGuid: Data([0x01, 0x02]))]
            )
            let body = try WireFormat.encode(response)

            return (
                HTTPURLResponse(
                    url: request.url!,
                    statusCode: 200,
                    httpVersion: nil,
                    headerFields: nil
                )!,
                body
            )
        }

        let config = RelayConfiguration.development()
        let client = RelayClient(configuration: config)

        let envelope = WireVeilEnvelope.forSending(
            content: Data(repeating: 0x42, count: 256),
            sealedSender: Data(repeating: 0x99, count: 128),
            contentType: 1
        )

        let token = WireSpentToken(point: Data(repeating: 0xAA, count: 32))
        let response = try await client.sendMessage(to: 99, envelope: envelope, token: token)

        XCTAssertEqual(response.deliveryResults.count, 1)
        XCTAssertNotNil(capturedBody)
        XCTAssert(capturedBody!.count > 0)
    }
}
