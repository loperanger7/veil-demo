// VEIL — Relay Client
// Tickets: VEIL-201, VEIL-202, VEIL-203, VEIL-301, VEIL-601, VEIL-602, VEIL-603
// Spec reference: Section 2.1
//
// Async HTTP/2 client for the Veil Relay Service.
// Built on URLSession (iOS 17+ HTTP/2 support) with:
//   - Protobuf binary content type
//   - Anonymous token authentication via X-Veil-Token header
//   - Exponential backoff with jitter on transient failures
//   - TLS 1.3 + certificate pinning via VeilTLSDelegate (VEIL-601)
//   - Traffic padding on message payloads (VEIL-602)
//   - Domain fronting for censorship resistance (VEIL-603)
//   - Zero-knowledge logging (never logs message content or sender)

import Foundation

// MARK: - Relay Client Configuration

/// Configuration for connecting to a Veil Relay server.
public struct RelayConfiguration: Sendable {
    /// Base URL of the relay server (e.g., "https://relay.veil.app").
    public let baseURL: URL
    /// TLS certificate pinning configuration.
    public let pinning: PinningConfiguration
    /// Maximum retry attempts for transient failures.
    public let maxRetries: Int
    /// Base delay for exponential backoff (seconds).
    public let baseRetryDelay: TimeInterval
    /// Traffic padding scheme (nil = no padding). Default: .production (VEIL-602).
    public let paddingScheme: PaddingScheme?
    /// Domain fronting configuration (nil = no fronting). (VEIL-603).
    public let frontingConfig: FrontingConfiguration?
    /// User's detected region for fronting profile selection.
    public let regionCode: RegionCode?

    public init(
        baseURL: URL,
        pinning: PinningConfiguration,
        maxRetries: Int = 3,
        baseRetryDelay: TimeInterval = 1.0,
        paddingScheme: PaddingScheme? = .production,
        frontingConfig: FrontingConfiguration? = nil,
        regionCode: RegionCode? = nil
    ) {
        self.baseURL = baseURL
        self.pinning = pinning
        self.maxRetries = maxRetries
        self.baseRetryDelay = baseRetryDelay
        self.paddingScheme = paddingScheme
        self.frontingConfig = frontingConfig
        self.regionCode = regionCode
    }

    /// Development configuration for local testing (no padding, no fronting).
    public static func development(port: Int = 8443) -> RelayConfiguration {
        RelayConfiguration(
            baseURL: URL(string: "https://localhost:\(port)")!,
            pinning: .development(hostname: "localhost"),
            maxRetries: 1,
            baseRetryDelay: 0.1,
            paddingScheme: nil,
            frontingConfig: nil
        )
    }
}

// MARK: - Relay Client Errors

/// Errors specific to relay communication.
public enum RelayError: Error, Sendable {
    case invalidResponse
    case httpError(statusCode: Int, body: Data?)
    case networkUnavailable
    case certificatePinningFailed
    case serializationFailed(String)
    case maxRetriesExceeded
    case serverUnavailable
}

// MARK: - Relay Client

/// Async HTTP/2 client for the Veil Relay Service.
///
/// All methods are async and throw `RelayError` on failure.
/// State-mutating requests automatically attach the anonymous token.
///
/// Thread safety: This actor is safe for concurrent use from multiple tasks.
public actor RelayClient {
    private let configuration: RelayConfiguration
    private let session: URLSession
    private let tlsDelegate: VeilTLSDelegate

    /// Traffic padding encoder/decoder (VEIL-602).
    private let paddingEncoder: CiphertextPaddingEncoder?
    private let paddingDecoder: CiphertextPaddingDecoder?

    /// Domain fronting interceptor (VEIL-603).
    private let frontingInterceptor: DomainFrontingInterceptor?

    /// Device identity after registration.
    private var registrationId: UInt32?
    private var deviceId: UInt32?

    public init(configuration: RelayConfiguration) {
        self.configuration = configuration
        self.tlsDelegate = VeilTLSDelegate(configuration: configuration.pinning)

        // Initialize traffic padding (VEIL-602)
        if let scheme = configuration.paddingScheme {
            self.paddingEncoder = CiphertextPaddingEncoder(scheme: scheme)
            self.paddingDecoder = CiphertextPaddingDecoder(scheme: scheme)
        } else {
            self.paddingEncoder = nil
            self.paddingDecoder = nil
        }

        // Initialize domain fronting (VEIL-603)
        if let frontingConfig = configuration.frontingConfig, frontingConfig.enabled {
            let region = configuration.regionCode ?? RegionDetector.detectFromLocale()
            let detectorConfig = CensorshipDetectorConfiguration.veilDefault(
                relayBaseURL: configuration.baseURL
            )
            let detector = NetworkCensorshipDetector(configuration: detectorConfig)
            self.frontingInterceptor = DomainFrontingInterceptor(
                censorshipDetector: detector,
                frontingConfig: frontingConfig,
                detectedRegion: region
            )
        } else {
            self.frontingInterceptor = nil
        }

        let sessionConfig = URLSessionConfiguration.default
        sessionConfig.httpAdditionalHeaders = [
            "Content-Type": "application/x-protobuf",
            "Accept": "application/x-protobuf",
        ]
        sessionConfig.timeoutIntervalForRequest = 30
        sessionConfig.timeoutIntervalForResource = 60
        // Enforce TLS 1.3 minimum (VEIL-601)
        sessionConfig.tlsMinimumSupportedProtocolVersion = .TLSv13

        self.session = URLSession(
            configuration: sessionConfig,
            delegate: tlsDelegate,
            delegateQueue: nil
        )
    }

    /// Access the TLS delegate (for pin rotation updates).
    public nonisolated var tls: VeilTLSDelegate { tlsDelegate }

    /// Access the fronting interceptor (for configuration updates).
    public var fronting: DomainFrontingInterceptor? { frontingInterceptor }

    /// Set device identity (called after registration or restoration from Keychain).
    public func setDeviceIdentity(registrationId: UInt32, deviceId: UInt32) {
        self.registrationId = registrationId
        self.deviceId = deviceId
    }

    // MARK: - Padding Helpers (VEIL-602)

    /// Pad a message body before transmission.
    /// Returns the original body if padding is not configured.
    public func padBody(_ body: Data) throws -> Data {
        guard let encoder = paddingEncoder else { return body }
        return try encoder.encodeToWire(body)
    }

    /// Strip padding from a received response body.
    /// Returns the original body if padding is not configured.
    public func unpadBody(_ body: Data) throws -> Data {
        guard let decoder = paddingDecoder else { return body }
        return try decoder.decodeFromWire(body)
    }

    // MARK: - Registration

    /// Register a new device with the relay server.
    ///
    /// POST /v1/registration
    ///
    /// - Parameters:
    ///   - deviceId: Local device ID (1 for primary device).
    ///   - identityKey: Serialized hybrid identity public key.
    ///   - blindedTokens: Blinded tokens for initial anonymous credential supply.
    /// - Returns: Registration response with server-assigned ID and signed tokens.
    public func registerDevice(
        deviceId: UInt32,
        identityKey: Data,
        blindedTokens: [WireBlindedToken]
    ) async throws -> RegistrationResponse {
        let request = RegistrationRequest(
            deviceId: deviceId,
            identityKey: identityKey,
            blindedTokens: blindedTokens
        )

        let body = try WireFormat.encode(request)
        let url = configuration.baseURL.appendingPathComponent("/v1/registration")

        let responseData = try await performRequest(
            url: url,
            method: "POST",
            body: body,
            token: nil  // Registration is unauthenticated
        )

        let response = try WireFormat.decode(RegistrationResponse.self, from: responseData)

        // Cache device identity
        self.registrationId = response.registrationId
        self.deviceId = deviceId

        return response
    }

    // MARK: - Prekey Management

    /// Upload a prekey bundle to the relay server.
    ///
    /// PUT /v1/keys
    ///
    /// - Parameters:
    ///   - bundle: The prekey bundle to upload.
    ///   - token: Anonymous token for authentication.
    public func uploadPrekeys(
        bundle: RelayPrekeyBundle,
        token: WireSpentToken
    ) async throws {
        guard let regId = registrationId else {
            throw RelayError.invalidResponse
        }

        let request = PrekeyUploadRequest(
            registrationId: regId,
            bundle: bundle
        )

        let body = try WireFormat.encode(request)
        let url = configuration.baseURL.appendingPathComponent("/v1/keys")

        let _ = try await performRequest(
            url: url,
            method: "PUT",
            body: body,
            token: token
        )
    }

    /// Fetch a recipient's prekey bundle.
    ///
    /// GET /v1/keys/{registration_id}
    ///
    /// No authentication required — anyone needs to fetch prekeys to
    /// initiate a conversation.
    ///
    /// - Parameter recipientRegistrationId: The recipient's registration ID.
    /// - Returns: The recipient's prekey bundle.
    public func fetchPrekeys(
        recipientRegistrationId: UInt32
    ) async throws -> PrekeyFetchResponse {
        let url = configuration.baseURL
            .appendingPathComponent("/v1/keys/\(recipientRegistrationId)")

        let responseData = try await performRequest(
            url: url,
            method: "GET",
            body: nil,
            token: nil  // Public endpoint
        )

        return try WireFormat.decode(PrekeyFetchResponse.self, from: responseData)
    }

    // MARK: - Message Delivery

    /// Send a sealed-sender message to a recipient.
    ///
    /// PUT /v1/messages/{registration_id}
    ///
    /// - Parameters:
    ///   - recipientRegistrationId: The recipient's registration ID.
    ///   - envelope: The sealed-sender envelope.
    ///   - token: Anonymous token for authentication.
    /// - Returns: Delivery results (server GUIDs per device).
    public func sendMessage(
        to recipientRegistrationId: UInt32,
        envelope: WireVeilEnvelope,
        token: WireSpentToken
    ) async throws -> SendMessageResponse {
        let request = SendMessageRequest(envelope: envelope)
        let body = try WireFormat.encode(request)
        let url = configuration.baseURL
            .appendingPathComponent("/v1/messages/\(recipientRegistrationId)")

        let responseData = try await performRequest(
            url: url,
            method: "PUT",
            body: body,
            token: token
        )

        return try WireFormat.decode(SendMessageResponse.self, from: responseData)
    }

    /// Retrieve pending messages for this device.
    ///
    /// GET /v1/messages?registration_id=X&device_id=Y
    ///
    /// - Parameter token: Anonymous token for authentication.
    /// - Returns: Pending envelopes and optional replenishment tokens.
    public func retrieveMessages(
        token: WireSpentToken
    ) async throws -> RetrieveMessagesResponse {
        guard let regId = registrationId, let devId = deviceId else {
            throw RelayError.invalidResponse
        }

        var components = URLComponents(
            url: configuration.baseURL.appendingPathComponent("/v1/messages"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(name: "registration_id", value: "\(regId)"),
            URLQueryItem(name: "device_id", value: "\(devId)"),
        ]

        let responseData = try await performRequest(
            url: components.url!,
            method: "GET",
            body: nil,
            token: token
        )

        return try WireFormat.decode(RetrieveMessagesResponse.self, from: responseData)
    }

    /// Acknowledge message receipt (triggers permanent deletion on server).
    ///
    /// DELETE /v1/messages/{server_guid}
    ///
    /// - Parameters:
    ///   - serverGuid: The server-assigned GUID of the message to acknowledge.
    ///   - token: Anonymous token for authentication.
    public func acknowledgeMessage(
        serverGuid: Data,
        token: WireSpentToken
    ) async throws {
        guard let regId = registrationId, let devId = deviceId else {
            throw RelayError.invalidResponse
        }

        let guidHex = serverGuid.map { String(format: "%02x", $0) }.joined()

        var components = URLComponents(
            url: configuration.baseURL.appendingPathComponent("/v1/messages/\(guidHex)"),
            resolvingAgainstBaseURL: false
        )!
        components.queryItems = [
            URLQueryItem(name: "registration_id", value: "\(regId)"),
            URLQueryItem(name: "device_id", value: "\(devId)"),
        ]

        let _ = try await performRequest(
            url: components.url!,
            method: "DELETE",
            body: nil,
            token: token
        )
    }

    // MARK: - Push Token

    /// Register an APNs push token for silent push notifications.
    ///
    /// PUT /v1/push/token
    ///
    /// - Parameters:
    ///   - apnsToken: The hex-encoded APNs device token.
    ///   - token: Anonymous token for authentication.
    public func registerPushToken(
        apnsToken: String,
        token: WireSpentToken
    ) async throws {
        guard let regId = registrationId, let devId = deviceId else {
            throw RelayError.invalidResponse
        }

        let request = PushTokenRequest(
            registrationId: regId,
            deviceId: devId,
            apnsToken: apnsToken
        )

        let body = try WireFormat.encode(request)
        let url = configuration.baseURL.appendingPathComponent("/v1/push/token")

        let _ = try await performRequest(
            url: url,
            method: "PUT",
            body: body,
            token: token
        )
    }

    // MARK: - Internal HTTP Layer

    /// Execute an HTTP request with retry logic, token attachment,
    /// and domain fronting (VEIL-603).
    private func performRequest(
        url: URL,
        method: String,
        body: Data?,
        token: WireSpentToken?
    ) async throws -> Data {
        var lastError: Error = RelayError.maxRetriesExceeded

        for attempt in 0...configuration.maxRetries {
            if attempt > 0 {
                // Exponential backoff with jitter
                let delay = configuration.baseRetryDelay * pow(2.0, Double(attempt - 1))
                let jitter = Double.random(in: 0...0.5)
                try await Task.sleep(nanoseconds: UInt64((delay + jitter) * 1_000_000_000))
            }

            do {
                var request = URLRequest(url: url)
                request.httpMethod = method
                request.httpBody = body

                // Attach anonymous token for authenticated requests
                if let token = token {
                    request.setValue(token.hexEncoded, forHTTPHeaderField: "X-Veil-Token")
                }

                // Apply domain fronting if active (VEIL-603)
                if let interceptor = frontingInterceptor {
                    request = await interceptor.processOutgoingRequest(request)
                }

                let (data, response) = try await session.data(for: request)

                guard let httpResponse = response as? HTTPURLResponse else {
                    throw RelayError.invalidResponse
                }

                switch httpResponse.statusCode {
                case 200...204:
                    // Report success to fronting interceptor
                    await frontingInterceptor?.reportSuccess()
                    return data
                case 401:
                    throw RelayError.httpError(statusCode: 401, body: data)
                case 404:
                    throw RelayError.httpError(statusCode: 404, body: data)
                case 429:
                    // Rate limited — retry after backoff
                    lastError = RelayError.httpError(statusCode: 429, body: data)
                    continue
                case 500...599:
                    // Server error — retry
                    lastError = RelayError.httpError(statusCode: httpResponse.statusCode, body: data)
                    continue
                default:
                    throw RelayError.httpError(statusCode: httpResponse.statusCode, body: data)
                }
            } catch let error as RelayError {
                throw error  // Don't retry client errors
            } catch is URLError {
                // Report failure to fronting interceptor for fallback logic
                await frontingInterceptor?.reportFailure(RelayError.networkUnavailable)
                lastError = RelayError.networkUnavailable
                continue  // Retry network errors
            } catch {
                await frontingInterceptor?.reportFailure(error)
                lastError = error
                continue
            }
        }

        throw lastError
    }
}
