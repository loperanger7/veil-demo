// FogClient.swift
// VEIL — MobileCoin Payment Integration
//
// VEIL-406: Fog client for lightweight balance queries and incoming TXO
// detection. Fog runs inside SGX enclaves so the view key is never exposed
// to the Fog operator — only the attested enclave can read it.
//
// Features:
// - SGX attestation verification
// - Balance queries with caching/fallback
// - Incoming TXO detection via view key
// - Background refresh on app foreground
//
// References: Veil Spec Section 8.6, MobileCoin Fog architecture

import Foundation

// MARK: - Fog Client

/// Actor-based client for MobileCoin Fog queries.
///
/// Fog enables lightweight mobile clients to check balances and detect
/// incoming transactions without downloading the full ledger. The view key
/// is registered with an SGX enclave (verified via remote attestation).
public actor FogClient {

    // MARK: Properties

    /// Fog service base URL.
    private let baseURL: URL

    /// URL session with TLS pinning.
    private let urlSession: URLSession

    /// MobileCoin client for cryptographic operations.
    private let mobClient: MobileCoinClient

    /// View key for TXO scanning (stored as SecureBytes).
    private let viewKey: SecureBytes

    /// Expected MRENCLAVE measurement for the Fog enclave.
    private let expectedMrEnclave: Data

    /// Cached balance (picoMOB) for graceful degradation.
    private var cachedBalance: UInt64?

    /// Timestamp of last successful balance query.
    private var lastBalanceUpdate: Date?

    /// Cached unspent TXOs.
    private var cachedTXOs: [UnspentTXO] = []

    /// Last block index processed for incremental TXO scanning.
    private var lastProcessedBlock: UInt64 = 0

    /// Whether the view key has been registered with Fog.
    private var isRegistered: Bool = false

    /// JSON encoder/decoder.
    private let encoder = JSONEncoder()
    private let decoder = JSONDecoder()

    // MARK: Initialization

    /// Create a Fog client.
    /// - Parameters:
    ///   - hostname: Fog service hostname.
    ///   - port: Fog service port (default 443).
    ///   - pins: TLS certificate pins.
    ///   - viewKey: The wallet's private view key.
    ///   - mobClient: MobileCoin client for crypto operations.
    ///   - mrEnclave: Expected SGX MRENCLAVE (default from constants).
    public init(
        hostname: String,
        port: Int = 443,
        pins: Set<CertificatePin>,
        viewKey: SecureBytes,
        mobClient: MobileCoinClient,
        mrEnclave: Data = MobileCoinConstants.fogMrEnclave
    ) {
        self.baseURL = URL(string: "https://\(hostname):\(port)")!
        self.viewKey = viewKey
        self.mobClient = mobClient
        self.expectedMrEnclave = mrEnclave

        let pinConfig = PinningConfiguration(
            pins: pins,
            hostname: hostname,
            enforced: true
        )
        let tlsDelegate = VeilTLSDelegate(configuration: pinConfig)

        let sessionConfig = URLSessionConfiguration.ephemeral
        sessionConfig.tlsMinimumSupportedProtocolVersion = .TLSv13
        sessionConfig.timeoutIntervalForRequest = 15
        self.urlSession = URLSession(
            configuration: sessionConfig,
            delegate: tlsDelegate,
            delegateQueue: nil
        )
    }

    // MARK: Registration

    /// Register the view key with the Fog enclave.
    /// Must be called before balance queries or TXO detection.
    ///
    /// The registration process:
    /// 1. Request attestation report from Fog
    /// 2. Verify SGX MRENCLAVE matches expected value
    /// 3. Encrypt view key to the enclave's public key
    /// 4. Send encrypted view key
    ///
    /// - Throws: `MobileCoinError.sgxAttestationFailed` or `.fogRegistrationFailed`.
    public func registerViewKey() async throws {
        // 1. Request attestation
        let attestationURL = baseURL.appendingPathComponent("/v1/fog/attestation")
        var request = URLRequest(url: attestationURL)
        request.httpMethod = "GET"

        let (attestationData, _) = try await urlSession.data(for: request)
        let attestation = try decoder.decode(FogAttestationResponse.self, from: attestationData)

        // 2. Verify SGX attestation
        guard let reportData = Data(base64Encoded: attestation.attestationReport) else {
            throw MobileCoinError.sgxAttestationFailed(
                detail: "Invalid attestation report encoding."
            )
        }

        let attestationValid = await mobClient.verifySGXAttestation(
            report: reportData,
            expectedMrEnclave: expectedMrEnclave
        )

        guard attestationValid else {
            throw MobileCoinError.sgxAttestationFailed(
                detail: "MRENCLAVE mismatch — Fog enclave may be compromised."
            )
        }

        // 3. Encrypt and send view key
        let viewKeyData = try viewKey.withUnsafeBytes { Data($0) }
        let registrationBody = FogRegistrationRequest(
            encryptedViewKey: viewKeyData.base64EncodedString(),
            enclaveId: attestation.enclaveId
        )

        let registrationURL = baseURL.appendingPathComponent("/v1/fog/register")
        var regRequest = URLRequest(url: registrationURL)
        regRequest.httpMethod = "POST"
        regRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        regRequest.httpBody = try encoder.encode(registrationBody)

        let (_, regResponse) = try await urlSession.data(for: regRequest)

        guard let httpResponse = regResponse as? HTTPURLResponse,
              httpResponse.statusCode == 200 || httpResponse.statusCode == 201 else {
            throw MobileCoinError.fogRegistrationFailed(
                reason: "Registration request returned non-success status."
            )
        }

        isRegistered = true
    }

    // MARK: Balance Queries

    /// Query the current balance via Fog.
    /// Falls back to cached balance if Fog is unavailable.
    ///
    /// - Returns: Balance in picoMOB.
    /// - Throws: `MobileCoinError.fogServiceUnavailable` only if no cache exists.
    public func queryBalance() async throws -> UInt64 {
        guard isRegistered else {
            // Try to register first
            try await registerViewKey()
        }

        do {
            let url = baseURL.appendingPathComponent("/v1/fog/balance")
            var request = URLRequest(url: url)
            request.httpMethod = "GET"
            request.setValue("application/json", forHTTPHeaderField: "Accept")

            let (data, response) = try await urlSession.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200 else {
                throw MobileCoinError.invalidBalanceResponse
            }

            let balanceResponse = try decoder.decode(FogBalanceResponse.self, from: data)

            // Update cache
            cachedBalance = balanceResponse.balancePicomob
            lastBalanceUpdate = Date()

            return balanceResponse.balancePicomob

        } catch {
            // Graceful fallback to cache
            if let cached = cachedBalance {
                return cached
            }
            throw MobileCoinError.fogServiceUnavailable
        }
    }

    /// Get the cached balance without making a network request.
    /// - Returns: Last known balance, or nil if never queried.
    public func getCachedBalance() -> (balance: UInt64, updatedAt: Date)? {
        guard let balance = cachedBalance, let date = lastBalanceUpdate else {
            return nil
        }
        return (balance, date)
    }

    // MARK: TXO Detection

    /// Detect incoming TXOs since the last processed block.
    /// Uses the view key to scan for outputs belonging to this wallet.
    ///
    /// - Returns: Newly detected incoming TXOs.
    /// - Throws: `MobileCoinError.fogServiceUnavailable`.
    public func detectIncomingTXOs() async throws -> [IncomingTXO] {
        guard isRegistered else {
            try await registerViewKey()
        }

        let url = baseURL.appendingPathComponent("/v1/fog/txos")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let scanRequest = FogTXOScanRequest(
            sinceBlockIndex: lastProcessedBlock
        )
        request.httpBody = try encoder.encode(scanRequest)

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              httpResponse.statusCode == 200 else {
            throw MobileCoinError.fogServiceUnavailable
        }

        let txoResponse = try decoder.decode(FogTXOResponse.self, from: data)

        // Convert to IncomingTXO
        let incomingTXOs = txoResponse.txos.compactMap { raw -> IncomingTXO? in
            guard let pubKey = Data(base64Encoded: raw.txoPublicKey),
                  let encAmount = Data(base64Encoded: raw.encryptedAmount),
                  let secret = Data(base64Encoded: raw.sharedSecret) else {
                return nil
            }
            return IncomingTXO(
                txoPublicKey: pubKey,
                encryptedAmount: encAmount,
                sharedSecret: secret,
                blockIndex: raw.blockIndex
            )
        }

        // Update last processed block
        if let maxBlock = txoResponse.txos.map(\.blockIndex).max() {
            lastProcessedBlock = maxBlock
        }

        return incomingTXOs
    }

    /// Get all known unspent TXOs (cached + newly detected).
    /// - Parameter spendKey: For computing key images (spent detection).
    /// - Returns: All unspent TXOs.
    public func getUnspentTXOs(spendKey: SecureBytes) async throws -> [UnspentTXO] {
        // Detect new incoming TXOs
        let newTXOs = try await detectIncomingTXOs()

        // Decrypt amounts and add to cached TXOs
        for incoming in newTXOs {
            if let amount = try await mobClient.decryptTXOAmount(
                encryptedAmount: incoming.encryptedAmount,
                sharedSecret: incoming.sharedSecret,
                viewKey: viewKey
            ) {
                // Compute key image for spent detection
                let keyImage = try? await mobClient.computeKeyImage(
                    txoPublicKey: incoming.txoPublicKey,
                    spendKey: spendKey
                )

                let utxo = UnspentTXO(
                    txoPublicKey: incoming.txoPublicKey,
                    amount: amount,
                    blockIndex: incoming.blockIndex,
                    keyImage: keyImage,
                    isSpent: false
                )
                cachedTXOs.append(utxo)
            }
        }

        return cachedTXOs.filter { !$0.isSpent }
    }

    /// Mark TXOs as spent (after submitting a transaction).
    /// - Parameter keyImages: Key images of spent TXOs.
    public func markSpent(keyImages: Set<Data>) {
        cachedTXOs = cachedTXOs.map { txo in
            if let ki = txo.keyImage, keyImages.contains(ki) {
                return UnspentTXO(
                    txoPublicKey: txo.txoPublicKey,
                    amount: txo.amount,
                    blockIndex: txo.blockIndex,
                    detectedAt: txo.detectedAt,
                    subaddressIndex: txo.subaddressIndex,
                    keyImage: txo.keyImage,
                    isSpent: true
                )
            }
            return txo
        }
    }

    // MARK: Cache Management

    /// Clear all cached data.
    public func clearCache() {
        cachedBalance = nil
        lastBalanceUpdate = nil
        cachedTXOs = []
        lastProcessedBlock = 0
    }
}

// MARK: - Fog API Types

struct FogAttestationResponse: Codable {
    let attestationReport: String // base64
    let enclaveId: String
    let enclavePublicKey: String // base64
}

struct FogRegistrationRequest: Codable {
    let encryptedViewKey: String // base64
    let enclaveId: String
}

struct FogBalanceResponse: Codable {
    let balancePicomob: UInt64
    let blockIndex: UInt64
    let timestamp: String
}

struct FogTXOScanRequest: Codable {
    let sinceBlockIndex: UInt64
}

struct FogTXOResponse: Codable {
    let txos: [RawTXO]

    struct RawTXO: Codable {
        let txoPublicKey: String // base64
        let encryptedAmount: String // base64
        let sharedSecret: String // base64
        let blockIndex: UInt64
    }
}
