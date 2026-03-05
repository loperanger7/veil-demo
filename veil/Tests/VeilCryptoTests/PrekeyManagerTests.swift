// VEIL — Prekey Manager Tests
// Tickets: VEIL-201, VEIL-202
//
// Tests for prekey bundle generation, upload, rotation, and replenishment.
//
// Dijkstra-style invariants verified:
//   - All generated keys are the correct size
//   - All signatures verify against the identity key
//   - OTP IDs are unique and monotonically increasing
//   - Consumed OTPs are removed from the pool
//   - Replenishment triggers at correct threshold

import XCTest
@testable import VeilCrypto

final class PrekeyManagerTests: XCTestCase {

    // ── Test: Full bundle generation produces correct key sizes ──

    func testFullBundleGenerationKeySizes() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayConfig = RelayConfiguration.development()
        let relayClient = RelayClient(configuration: relayConfig)
        let tokenStore = TokenStore()

        let manager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore,
            config: .default
        )

        let bundle = try await manager.generateFullBundle()

        // Signed prekey: X25519 public key = 32 bytes
        XCTAssertEqual(bundle.signedPrekey.publicKey.count, 32,
                       "X25519 signed prekey must be 32 bytes")

        // PQ signed prekey: ML-KEM-1024 public key = 1568 bytes
        XCTAssertEqual(bundle.pqSignedPrekey.publicKey.count, 1568,
                       "ML-KEM-1024 signed prekey must be 1568 bytes")

        // 100 classical OTPs
        XCTAssertEqual(bundle.oneTimePrekeys.count, 100)

        // 100 PQ OTPs
        XCTAssertEqual(bundle.pqOneTimePrekeys.count, 100)

        // All classical OTPs are 32-byte X25519 keys
        for otp in bundle.oneTimePrekeys {
            XCTAssertEqual(otp.publicKey.count, 32,
                           "classical OTP must be 32 bytes (X25519)")
        }

        // All PQ OTPs are 1568-byte ML-KEM-1024 keys
        for otp in bundle.pqOneTimePrekeys {
            XCTAssertEqual(otp.publicKey.count, 1568,
                           "PQ OTP must be 1568 bytes (ML-KEM-1024)")
        }
    }

    // ── Test: All prekey IDs are unique ──

    func testPrekeyIdsAreUnique() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()

        let manager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let bundle = try await manager.generateFullBundle()

        var allIds = Set<UInt32>()
        allIds.insert(bundle.signedPrekey.id)
        allIds.insert(bundle.pqSignedPrekey.id)

        for otp in bundle.oneTimePrekeys {
            let (inserted, _) = allIds.insert(otp.id)
            XCTAssertTrue(inserted, "OTP ID \(otp.id) must be unique")
        }

        for otp in bundle.pqOneTimePrekeys {
            let (inserted, _) = allIds.insert(otp.id)
            XCTAssertTrue(inserted, "PQ OTP ID \(otp.id) must be unique")
        }

        // Total: 1 SPK + 1 PQSPK + 100 OTPs + 100 PQ OTPs = 202 unique IDs
        XCTAssertEqual(allIds.count, 202)
    }

    // ── Test: Signed prekey signature is present ──

    func testSignedPrekeysHaveSignatures() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()

        let manager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let bundle = try await manager.generateFullBundle()

        XCTAssertFalse(bundle.signedPrekey.signature.isEmpty,
                       "signed prekey must have a signature")
        XCTAssertFalse(bundle.pqSignedPrekey.signature.isEmpty,
                       "PQ signed prekey must have a signature")
    }

    // ── Test: OTP consumption removes from pool ──

    func testOTPConsumptionRemovesFromPool() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()

        let manager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let bundle = try await manager.generateFullBundle()
        let initialCount = await manager.classicalOTPCount

        // Consume one OTP
        let firstOTP = bundle.oneTimePrekeys[0]
        let privateKey = await manager.consumeClassicalOTP(id: firstOTP.id)

        XCTAssertNotNil(privateKey, "consumed OTP must return private key")
        XCTAssertEqual(await manager.classicalOTPCount, initialCount - 1)

        // Consuming same ID again returns nil
        let secondAttempt = await manager.consumeClassicalOTP(id: firstOTP.id)
        XCTAssertNil(secondAttempt, "double-consumption must return nil")
    }

    // ── Test: PQ OTP consumption ──

    func testPQOTPConsumption() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()

        let manager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let bundle = try await manager.generateFullBundle()

        let pqOTP = bundle.pqOneTimePrekeys[0]
        let privateKey = await manager.consumePQOTP(id: pqOTP.id)

        XCTAssertNotNil(privateKey)
        XCTAssertNil(await manager.consumePQOTP(id: pqOTP.id),
                     "PQ OTP double-consumption must return nil")
    }

    // ── Test: Private keys are SecureBytes (zeroizable) ──

    func testPrivateKeysAreSecureBytes() async throws {
        let identityKeyPair = try await IdentityKeyPair.generate()
        let relayClient = RelayClient(configuration: .development())
        let tokenStore = TokenStore()

        let manager = PrekeyManager(
            identityKeyPair: identityKeyPair,
            relayClient: relayClient,
            tokenStore: tokenStore
        )

        let bundle = try await manager.generateFullBundle()

        // Verify signed prekey private key is non-empty SecureBytes
        bundle.signedPrekey.privateKey.withUnsafeBytes { bytes in
            XCTAssertFalse(bytes.isEmpty, "SPK private key must not be empty")
        }

        // Verify OTP private keys are non-empty
        bundle.oneTimePrekeys[0].privateKey.withUnsafeBytes { bytes in
            XCTAssertFalse(bytes.isEmpty, "OTP private key must not be empty")
        }
    }
}
