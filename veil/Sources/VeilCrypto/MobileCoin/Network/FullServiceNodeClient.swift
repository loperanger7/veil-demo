// FullServiceNodeClient.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-404: Secure connection to the MobileCoin Full-Service Node for
// transaction submission. Uses TLS 1.3 with certificate pinning (reusing
// VeilTLSDelegate from the relay client).
//
// References: Veil Spec Section 8.4, MobileCoin Full-Service Node API

import Foundation

// MARK: - Full-Service Node Client

/// Actor-based client for MobileCoin Full-Service Node communication.
/// All requests use TLS 1.3 with SPKI certificate pinning.
public actor FullServiceNodeClient {

    // MARK: Properties

    /// Base URL of the Full-Service Node API.
    private let baseURL: URL

    /// URL session configured with certificate pinning.
    private let urlSession: URLSession

    /// TLS delegate enforcing certificate pins.
    private let tlsDelegate: VeilTLSDelegate

    /// JSON encoder for requests.
    private let encoder = JSONEncoder()

    /// JSON decoder for responses.
    private let decoder = JSONDecoder()

    // MARK: Initialization

    /// Create a Full-Service Node client with certificate pinning.
    /// - Parameters:
    ///   - hostname: Full-Service Node hostname (e.g., "fsn.veil.app").
    ///   - port: Port number (default 8443).
    ///   - pins: Set of SPKI SHA-256 certificate pins.
    public init(
        hostname: String,
        port: Int = 8443,
        pins: Set<CertificatePin>
    ) {
        self.baseURL = URL(string: "https://\(hostname):\(port)")!

        let pinConfig = PinningConfiguration(
            pins: pins,
            hostname: hostname,
            enforced: true
        )
        self.tlsDelegate = VeilTLSDelegate(configuration: pinConfig)

        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.tlsMinimumSupportedProtocolVersion = .TLSv13
        sessionConfig.timeoutIntervalForRequest = 30
        sessionConfig.timeoutIntervalForResource = 60

        self.urlSession = URLSession(
            configuration: sessionConfig,
            delegate: tlsDelegate,
            delegateQueue: nil
        )
    }

    // MARK: Transaction Submission

    /// Submit a signed transaction to the Full-Service Node.
    /// - Parameter envelope: The signed transaction envelope.
    /// - Returns: A submission receipt with the assigned block height hint.
    /// - Throws: `MobileCoinError.submissionRejected` or `.submissionHTTPError`.
    public func submitTransaction(
        _ envelope: TransactionEnvelope
    ) async throws -> SubmissionReceipt {
        let requestBody = SubmitTransactionRequest(
            transactionData: envelope.serializedTransaction.base64EncodedString(),
            txHash: envelope.txHash.base64EncodedString()
        )

        let data = try encoder.encode(requestBody)
        let url = baseURL.appendingPathComponent("/v1/transactions/submit")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = data

        let (responseData, response) = try await performRequest(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw MobileCoinError.submissionRejected(reason: "Invalid response type.")
        }

        switch httpResponse.statusCode {
        case 200...299:
            let receipt = try decoder.decode(SubmissionReceipt.self, from: responseData)
            return receipt

        case 400:
            let error = try? decoder.decode(FSNErrorResponse.self, from: responseData)
            throw MobileCoinError.submissionRejected(
                reason: error?.message ?? "Bad request"
            )

        case 409:
            throw MobileCoinError.submissionRejected(
                reason: "Transaction conflicts with an existing transaction (double-spend)."
            )

        default:
            throw MobileCoinError.submissionHTTPError(statusCode: httpResponse.statusCode)
        }
    }

    // MARK: Transaction Status

    /// Check the status of a previously submitted transaction.
    /// - Parameter txHash: The transaction hash to query.
    /// - Returns: The current transaction status.
    public func getTransactionStatus(
        txHash: Data
    ) async throws -> TransactionStatusResponse {
        let hashString = txHash.base64EncodedString()
        let url = baseURL.appendingPathComponent("/v1/transactions/status/\(hashString)")

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (responseData, response) = try await performRequest(request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw MobileCoinError.transientNetworkError(underlying: "Invalid response.")
        }

        guard httpResponse.statusCode == 200 else {
            throw MobileCoinError.submissionHTTPError(statusCode: httpResponse.statusCode)
        }

        return try decoder.decode(TransactionStatusResponse.self, from: responseData)
    }

    // MARK: Ring Members

    /// Fetch ring members from the ledger for transaction construction.
    /// - Parameters:
    ///   - txoPublicKeys: Public keys of TXOs needing ring members.
    ///   - ringSize: Desired ring size.
    /// - Returns: Ring members grouped by input TXO public key.
    public func fetchRingMembers(
        for txoPublicKeys: [Data],
        ringSize: Int
    ) async throws -> [Data: [RingMember]] {
        let requestBody = RingMemberRequest(
            txoPublicKeys: txoPublicKeys.map { $0.base64EncodedString() },
            ringSize: ringSize
        )

        let data = try encoder.encode(requestBody)
        let url = baseURL.appendingPathComponent("/v1/ledger/ring-members")

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = data

        let (responseData, response) = try await performRequest(request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw MobileCoinError.transientNetworkError(
                underlying: "Failed to fetch ring members."
            )
        }

        let ringResponse = try decoder.decode(RingMemberResponse.self, from: responseData)
        return ringResponse.toRingMembers()
    }

    // MARK: - Private Helpers

    /// Perform an HTTP request with retry on transient failures.
    private func performRequest(
        _ request: URLRequest,
        retryCount: Int = 0
    ) async throws -> (Data, URLResponse) {
        do {
            return try await urlSession.data(for: request)
        } catch let error as URLError where isTransient(error) {
            guard retryCount < MobileCoinConstants.maxRetries else {
                throw MobileCoinError.retriesExhausted(
                    attempts: MobileCoinConstants.maxRetries
                )
            }
            // Exponential backoff: 1s, 2s, 4s
            let delay = pow(2.0, Double(retryCount))
            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            return try await performRequest(request, retryCount: retryCount + 1)
        } catch let error as URLError where error.code == .serverCertificateUntrusted {
            throw MobileCoinError.tlsPinningFailed(
                host: request.url?.host ?? "unknown"
            )
        } catch {
            throw MobileCoinError.transientNetworkError(
                underlying: error.localizedDescription
            )
        }
    }

    /// Check if a URLError represents a transient (retryable) failure.
    private func isTransient(_ error: URLError) -> Bool {
        switch error.code {
        case .timedOut, .networkConnectionLost, .notConnectedToInternet,
             .cannotConnectToHost, .cannotFindHost:
            return true
        default:
            return false
        }
    }
}

// MARK: - Request/Response Types

struct SubmitTransactionRequest: Codable {
    let transactionData: String // base64
    let txHash: String // base64
}

/// Receipt returned after successful transaction submission.
public struct SubmissionReceipt: Sendable, Codable, Equatable {
    /// Server-assigned submission ID.
    public let submissionId: String
    /// Estimated block height for inclusion.
    public let estimatedBlockHeight: UInt64
    /// Server timestamp of receipt.
    public let submittedAt: String
}

/// Response when querying transaction status.
public struct TransactionStatusResponse: Sendable, Codable, Equatable {
    /// Current status: "pending", "confirmed", "failed".
    public let status: String
    /// Block index (present if confirmed).
    public let blockIndex: UInt64?
    /// Number of confirmations (present if confirmed).
    public let confirmations: UInt32?
    /// Failure reason (present if failed).
    public let failureReason: String?
}

struct FSNErrorResponse: Codable {
    let message: String
    let code: String?
}

struct RingMemberRequest: Codable {
    let txoPublicKeys: [String] // base64
    let ringSize: Int
}

struct RingMemberResponse: Codable {
    let rings: [RingData]

    struct RingData: Codable {
        let txoPublicKey: String
        let members: [MemberData]
    }

    struct MemberData: Codable {
        let publicKey: String
        let membershipProof: String
        let blockIndex: UInt64
    }

    func toRingMembers() -> [Data: [RingMember]] {
        var result: [Data: [RingMember]] = [:]
        for ring in rings {
            guard let keyData = Data(base64Encoded: ring.txoPublicKey) else { continue }
            let members = ring.members.compactMap { member -> RingMember? in
                guard let pk = Data(base64Encoded: member.publicKey),
                      let proof = Data(base64Encoded: member.membershipProof) else {
                    return nil
                }
                return RingMember(
                    publicKey: pk,
                    membershipProof: proof,
                    blockIndex: member.blockIndex
                )
            }
            result[keyData] = members
        }
        return result
    }
}
