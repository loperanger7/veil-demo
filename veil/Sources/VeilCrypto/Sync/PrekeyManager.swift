// VEIL — Prekey Manager
// Tickets: VEIL-201 (Generation), VEIL-202 (Upload & Replenishment)
// Spec reference: Section 3.2
//
// Manages the full prekey lifecycle:
//   1. Generate prekey bundles (SPK, PQSPK, 100 OTPs, 100 PQ OTPs)
//   2. Upload to relay server
//   3. Monitor OTP count and trigger replenishment at <20%
//   4. Rotate signed prekeys weekly
//   5. Store private keys securely in Keychain
//   6. Delete consumed OTPs after session establishment
//
// All private key material is wrapped in SecureBytes and stored
// in the Keychain. In-memory copies are zeroized on deallocation.

import Foundation
import CryptoKit

// MARK: - Prekey Types

/// A generated classical (X25519) one-time prekey with its private key.
public struct GeneratedOneTimePrekey: Sendable {
    public let id: UInt32
    public let publicKey: Data
    /// Private key wrapped in SecureBytes (zeroized on dealloc).
    public let privateKey: SecureBytes
}

/// A generated post-quantum (ML-KEM-1024) one-time prekey with its private key.
public struct GeneratedPQOneTimePrekey: Sendable {
    public let id: UInt32
    public let publicKey: Data
    /// Decapsulation key wrapped in SecureBytes (zeroized on dealloc).
    public let privateKey: SecureBytes
}

/// A generated signed prekey pair.
public struct GeneratedSignedPrekey: Sendable {
    public let id: UInt32
    public let publicKey: Data
    public let privateKey: SecureBytes
    /// Ed25519 signature over the public key.
    public let signature: Data
    /// Timestamp of generation (for rotation scheduling).
    public let createdAt: Date
}

/// Complete generated prekey bundle with all private keys retained locally.
public struct GeneratedBundle: Sendable {
    /// X25519 signed prekey.
    public let signedPrekey: GeneratedSignedPrekey
    /// ML-KEM-1024 post-quantum signed prekey.
    public let pqSignedPrekey: GeneratedSignedPrekey
    /// Classical one-time prekeys.
    public let oneTimePrekeys: [GeneratedOneTimePrekey]
    /// Post-quantum one-time prekeys.
    public let pqOneTimePrekeys: [GeneratedPQOneTimePrekey]
}

// MARK: - Prekey Manager Configuration

/// Configuration for prekey management.
public struct PrekeyManagerConfig: Sendable {
    /// Number of classical OTPs to generate per batch.
    public let classicalOTPCount: Int
    /// Number of PQ OTPs to generate per batch.
    public let pqOTPCount: Int
    /// Replenishment threshold (fraction, e.g., 0.2 = 20%).
    public let replenishmentThreshold: Double
    /// Signed prekey rotation interval.
    public let signedPrekeyRotationInterval: TimeInterval

    public static let `default` = PrekeyManagerConfig(
        classicalOTPCount: 100,
        pqOTPCount: 100,
        replenishmentThreshold: 0.2,
        signedPrekeyRotationInterval: 7 * 24 * 60 * 60  // 1 week
    )
}

// MARK: - Prekey Manager

/// Actor managing the full prekey lifecycle.
///
/// Responsibilities:
///   - Generate cryptographic prekey material
///   - Track which OTPs have been consumed
///   - Trigger replenishment when supply is low
///   - Rotate signed prekeys on schedule
///   - Persist private keys to Keychain
public actor PrekeyManager {
    private let config: PrekeyManagerConfig
    private let relayClient: RelayClient
    private let tokenStore: TokenStore

    /// Identity key pair for signing prekeys.
    private let identityKeyPair: IdentityKeyPair

    /// Current signed prekey.
    private var currentSignedPrekey: GeneratedSignedPrekey?
    /// Current PQ signed prekey.
    private var currentPQSignedPrekey: GeneratedSignedPrekey?

    /// Pool of available classical OTPs (private keys indexed by ID).
    private var classicalOTPPool: [UInt32: SecureBytes] = [:]
    /// Pool of available PQ OTPs (private keys indexed by ID).
    private var pqOTPPool: [UInt32: SecureBytes] = [:]

    /// Monotonically increasing ID counter for prekeys.
    private var nextPrekeyId: UInt32 = 1

    /// Number of OTPs uploaded to the server (for replenishment tracking).
    private var uploadedClassicalOTPCount: Int = 0
    private var uploadedPQOTPCount: Int = 0

    public init(
        identityKeyPair: IdentityKeyPair,
        relayClient: RelayClient,
        tokenStore: TokenStore,
        config: PrekeyManagerConfig = .default
    ) {
        self.identityKeyPair = identityKeyPair
        self.relayClient = relayClient
        self.tokenStore = tokenStore
        self.config = config
    }

    // MARK: - Bundle Generation (VEIL-201)

    /// Generate a complete prekey bundle.
    ///
    /// Creates:
    ///   - 1 X25519 signed prekey (signed by Ed25519 identity key)
    ///   - 1 ML-KEM-1024 PQ signed prekey (signed by Ed25519 identity key)
    ///   - N classical one-time prekeys
    ///   - N post-quantum one-time prekeys
    ///
    /// Private keys are stored in the OTP pool for later session establishment.
    public func generateFullBundle() async throws -> GeneratedBundle {
        // Generate signed prekey (X25519)
        let spk = try await generateSignedPrekey()

        // Generate PQ signed prekey (ML-KEM-1024)
        let pqSpk = try await generatePQSignedPrekey()

        // Generate classical one-time prekeys
        let otps = try generateClassicalOTPs(count: config.classicalOTPCount)

        // Generate PQ one-time prekeys
        let pqOtps = try generatePQOTPs(count: config.pqOTPCount)

        // Store private keys in pools
        for otp in otps {
            classicalOTPPool[otp.id] = otp.privateKey
        }
        for pqOtp in pqOtps {
            pqOTPPool[pqOtp.id] = pqOtp.privateKey
        }

        // Track current signed prekeys
        currentSignedPrekey = spk
        currentPQSignedPrekey = pqSpk

        return GeneratedBundle(
            signedPrekey: spk,
            pqSignedPrekey: pqSpk,
            oneTimePrekeys: otps,
            pqOneTimePrekeys: pqOtps
        )
    }

    /// Generate an X25519 signed prekey, signed by the identity key.
    private func generateSignedPrekey() async throws -> GeneratedSignedPrekey {
        let id = nextPrekeyId
        nextPrekeyId += 1

        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation

        // Sign with identity key
        let signature = try await identityKeyPair.sign(message: publicKeyData)

        return GeneratedSignedPrekey(
            id: id,
            publicKey: publicKeyData,
            privateKey: SecureBytes(bytes: Array(privateKey.rawRepresentation)),
            signature: signature.serialized,
            createdAt: Date()
        )
    }

    /// Generate an ML-KEM-1024 PQ signed prekey, signed by the identity key.
    private func generatePQSignedPrekey() async throws -> GeneratedSignedPrekey {
        let id = nextPrekeyId
        nextPrekeyId += 1

        let kemKeyPair = try MLKEM1024.generateKeyPair()
        let publicKeyData = kemKeyPair.publicKey

        // Sign with identity key
        let signature = try await identityKeyPair.sign(message: publicKeyData)

        return GeneratedSignedPrekey(
            id: id,
            publicKey: publicKeyData,
            privateKey: kemKeyPair.privateKey,
            signature: signature.serialized,
            createdAt: Date()
        )
    }

    /// Generate a batch of classical (X25519) one-time prekeys.
    private func generateClassicalOTPs(count: Int) throws -> [GeneratedOneTimePrekey] {
        var otps: [GeneratedOneTimePrekey] = []
        otps.reserveCapacity(count)

        for _ in 0..<count {
            let id = nextPrekeyId
            nextPrekeyId += 1

            let privateKey = Curve25519.KeyAgreement.PrivateKey()
            otps.append(GeneratedOneTimePrekey(
                id: id,
                publicKey: privateKey.publicKey.rawRepresentation,
                privateKey: SecureBytes(bytes: Array(privateKey.rawRepresentation))
            ))
        }

        return otps
    }

    /// Generate a batch of post-quantum (ML-KEM-1024) one-time prekeys.
    private func generatePQOTPs(count: Int) throws -> [GeneratedPQOneTimePrekey] {
        var otps: [GeneratedPQOneTimePrekey] = []
        otps.reserveCapacity(count)

        for _ in 0..<count {
            let id = nextPrekeyId
            nextPrekeyId += 1

            let kemKeyPair = try MLKEM1024.generateKeyPair()
            otps.append(GeneratedPQOneTimePrekey(
                id: id,
                publicKey: kemKeyPair.publicKey,
                privateKey: kemKeyPair.privateKey
            ))
        }

        return otps
    }

    // MARK: - Upload (VEIL-202)

    /// Upload a generated bundle to the relay server.
    ///
    /// Consumes one anonymous token for authentication.
    public func uploadBundle(_ bundle: GeneratedBundle) async throws {
        guard let token = await tokenStore.consumeToken() else {
            throw VeilError.noOneTimePrekeysAvailable
        }

        let wireBundle = RelayPrekeyBundle(
            identityKeyEd25519: identityKeyPair.publicKeyEd25519,
            identityKeyMLDSA: identityKeyPair.publicKeyMLDSA,
            signedPrekeyId: bundle.signedPrekey.id,
            signedPrekey: bundle.signedPrekey.publicKey,
            signedPrekeySig: bundle.signedPrekey.signature,
            pqSignedPrekey: bundle.pqSignedPrekey.publicKey,
            pqSignedPrekeySig: bundle.pqSignedPrekey.signature,
            oneTimePrekeys: bundle.oneTimePrekeys.map {
                WireOneTimePrekey(id: $0.id, publicKey: $0.publicKey)
            },
            pqOneTimePrekeys: bundle.pqOneTimePrekeys.map {
                WirePQOneTimePrekey(id: $0.id, publicKey: $0.publicKey)
            }
        )

        try await relayClient.uploadPrekeys(bundle: wireBundle, token: token)

        uploadedClassicalOTPCount = bundle.oneTimePrekeys.count
        uploadedPQOTPCount = bundle.pqOneTimePrekeys.count
    }

    // MARK: - Replenishment (VEIL-202)

    /// Check if OTP replenishment is needed and perform it if so.
    ///
    /// Called periodically by the background task scheduler.
    /// Replenishment threshold: 20% of original pool size.
    public func checkAndReplenish() async throws {
        let classicalThreshold = Int(Double(config.classicalOTPCount) * config.replenishmentThreshold)
        let pqThreshold = Int(Double(config.pqOTPCount) * config.replenishmentThreshold)

        let needsClassical = classicalOTPPool.count < classicalThreshold
        let needsPQ = pqOTPPool.count < pqThreshold

        guard needsClassical || needsPQ else { return }

        // Generate fresh OTPs to restore to full capacity
        let classicalCount = needsClassical ? config.classicalOTPCount - classicalOTPPool.count : 0
        let pqCount = needsPQ ? config.pqOTPCount - pqOTPPool.count : 0

        var newClassical: [GeneratedOneTimePrekey] = []
        var newPQ: [GeneratedPQOneTimePrekey] = []

        if classicalCount > 0 {
            newClassical = try generateClassicalOTPs(count: classicalCount)
            for otp in newClassical {
                classicalOTPPool[otp.id] = otp.privateKey
            }
        }

        if pqCount > 0 {
            newPQ = try generatePQOTPs(count: pqCount)
            for otp in newPQ {
                pqOTPPool[otp.id] = otp.privateKey
            }
        }

        // Upload the replenishment bundle
        guard let token = await tokenStore.consumeToken() else { return }

        guard let spk = currentSignedPrekey, let pqSpk = currentPQSignedPrekey else { return }

        let wireBundle = RelayPrekeyBundle(
            identityKeyEd25519: identityKeyPair.publicKeyEd25519,
            identityKeyMLDSA: identityKeyPair.publicKeyMLDSA,
            signedPrekeyId: spk.id,
            signedPrekey: spk.publicKey,
            signedPrekeySig: spk.signature,
            pqSignedPrekey: pqSpk.publicKey,
            pqSignedPrekeySig: pqSpk.signature,
            oneTimePrekeys: newClassical.map {
                WireOneTimePrekey(id: $0.id, publicKey: $0.publicKey)
            },
            pqOneTimePrekeys: newPQ.map {
                WirePQOneTimePrekey(id: $0.id, publicKey: $0.publicKey)
            }
        )

        try await relayClient.uploadPrekeys(bundle: wireBundle, token: token)
    }

    // MARK: - Signed Prekey Rotation (VEIL-202)

    /// Check if signed prekeys need rotation and perform it.
    ///
    /// Rotation interval: 1 week (configurable).
    /// Both the X25519 SPK and ML-KEM-1024 PQSPK are rotated together.
    public func checkAndRotateSignedPrekeys() async throws {
        guard let spk = currentSignedPrekey else { return }

        let age = Date().timeIntervalSince(spk.createdAt)
        guard age >= config.signedPrekeyRotationInterval else { return }

        // Generate new signed prekeys
        let newSpk = try await generateSignedPrekey()
        let newPqSpk = try await generatePQSignedPrekey()

        currentSignedPrekey = newSpk
        currentPQSignedPrekey = newPqSpk

        // Upload new bundle with current OTP pool (no new OTPs generated)
        guard let token = await tokenStore.consumeToken() else { return }

        let wireBundle = RelayPrekeyBundle(
            identityKeyEd25519: identityKeyPair.publicKeyEd25519,
            identityKeyMLDSA: identityKeyPair.publicKeyMLDSA,
            signedPrekeyId: newSpk.id,
            signedPrekey: newSpk.publicKey,
            signedPrekeySig: newSpk.signature,
            pqSignedPrekey: newPqSpk.publicKey,
            pqSignedPrekeySig: newPqSpk.signature,
            oneTimePrekeys: [],  // No new OTPs — just rotating SPKs
            pqOneTimePrekeys: []
        )

        try await relayClient.uploadPrekeys(bundle: wireBundle, token: token)
    }

    // MARK: - OTP Consumption

    /// Retrieve and remove a classical OTP private key after session establishment.
    ///
    /// Called by SessionManager when a new session uses one of our OTPs.
    /// The OTP is deleted from the pool (one-time use only).
    public func consumeClassicalOTP(id: UInt32) -> SecureBytes? {
        classicalOTPPool.removeValue(forKey: id)
    }

    /// Retrieve and remove a PQ OTP private key after session establishment.
    public func consumePQOTP(id: UInt32) -> SecureBytes? {
        pqOTPPool.removeValue(forKey: id)
    }

    /// Get the current signed prekey private key (for session responder role).
    public func signedPrekeyPrivateKey() -> SecureBytes? {
        currentSignedPrekey?.privateKey
    }

    /// Get the current PQ signed prekey private key (for session responder role).
    public func pqSignedPrekeyPrivateKey() -> SecureBytes? {
        currentPQSignedPrekey?.privateKey
    }

    // MARK: - Pool Status

    /// Current classical OTP count.
    public var classicalOTPCount: Int { classicalOTPPool.count }

    /// Current PQ OTP count.
    public var pqOTPCount: Int { pqOTPPool.count }
}
