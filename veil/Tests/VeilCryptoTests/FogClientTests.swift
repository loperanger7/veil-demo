// FogClientTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// VEIL-406: Tests for Fog client types, caching, and TXO detection.

import XCTest
@testable import VeilCrypto

final class FogClientTests: XCTestCase {

    // MARK: - IncomingTXO

    func testIncomingTXOCreation() {
        let txo = IncomingTXO(
            txoPublicKey: Data(repeating: 0x42, count: 32),
            encryptedAmount: Data(repeating: 0x01, count: 16),
            sharedSecret: Data(repeating: 0x02, count: 32),
            blockIndex: 12345
        )

        XCTAssertEqual(txo.txoPublicKey.count, 32)
        XCTAssertEqual(txo.blockIndex, 12345)
        XCTAssertNotNil(txo.detectedAt)
    }

    // MARK: - UnspentTXO

    func testUnspentTXOAmountConversion() {
        let txo = UnspentTXO(
            txoPublicKey: Data(repeating: 0x01, count: 32),
            amount: 1_500_000_000_000, // 1.5 MOB
            blockIndex: 100
        )

        XCTAssertEqual(txo.amountInMOB, 1.5, accuracy: 0.0001)
    }

    func testUnspentTXOIdentifiable() {
        let txo = UnspentTXO(
            txoPublicKey: Data(repeating: 0xAB, count: 32),
            amount: 5000,
            blockIndex: 100
        )

        XCTAssertEqual(txo.id, txo.txoPublicKey,
                        "ID should be the TXO public key.")
    }

    func testUnspentTXOSpentStatus() {
        let unspent = UnspentTXO(
            txoPublicKey: Data(repeating: 0x01, count: 32),
            amount: 5000,
            blockIndex: 100,
            isSpent: false
        )
        XCTAssertFalse(unspent.isSpent)

        let spent = UnspentTXO(
            txoPublicKey: Data(repeating: 0x02, count: 32),
            amount: 5000,
            blockIndex: 100,
            isSpent: true
        )
        XCTAssertTrue(spent.isSpent)
    }

    // MARK: - Fog API Response Types

    func testFogBalanceResponseCodable() throws {
        let json = """
        {
            "balancePicomob": 5000000000000,
            "blockIndex": 12345,
            "timestamp": "2026-03-04T10:00:00Z"
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(FogBalanceResponse.self, from: json)
        XCTAssertEqual(response.balancePicomob, 5_000_000_000_000)
        XCTAssertEqual(response.blockIndex, 12345)
    }

    func testFogAttestationResponseCodable() throws {
        let json = """
        {
            "attestationReport": "\(Data(repeating: 0xAA, count: 64).base64EncodedString())",
            "enclaveId": "fog-enclave-001",
            "enclavePublicKey": "\(Data(repeating: 0xBB, count: 32).base64EncodedString())"
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(FogAttestationResponse.self, from: json)
        XCTAssertEqual(response.enclaveId, "fog-enclave-001")
        XCTAssertNotNil(Data(base64Encoded: response.attestationReport))
    }

    func testFogTXOResponseCodable() throws {
        let json = """
        {
            "txos": [
                {
                    "txoPublicKey": "\(Data(repeating: 0x01, count: 32).base64EncodedString())",
                    "encryptedAmount": "\(Data(repeating: 0x02, count: 16).base64EncodedString())",
                    "sharedSecret": "\(Data(repeating: 0x03, count: 32).base64EncodedString())",
                    "blockIndex": 500
                }
            ]
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(FogTXOResponse.self, from: json)
        XCTAssertEqual(response.txos.count, 1)
        XCTAssertEqual(response.txos[0].blockIndex, 500)
    }

    // MARK: - Mock SDK TXO Decryption

    func testMockDecryptTXOAmount() async {
        let client = MobileCoinClient(sdk: MockMobileCoinSDK())

        // Create a mock encrypted amount and shared secret
        var encAmount = Data(count: 8)
        encAmount[0] = 0x10 // Some value
        var secret = Data(count: 8)
        secret[0] = 0x00 // XOR with 0x10 → 0x10 = 16

        let amount = await client.decryptTXOAmount(
            encryptedAmount: encAmount,
            sharedSecret: secret,
            viewKey: SecureBytes(bytes: Array(repeating: 0x00, count: 32))
        )

        XCTAssertNotNil(amount, "Mock should decrypt successfully.")
    }

    // MARK: - Mock SGX Attestation

    func testMockSGXAttestationAcceptsNonEmpty() async {
        let client = MobileCoinClient(sdk: MockMobileCoinSDK())

        let valid = await client.verifySGXAttestation(
            report: Data(repeating: 0x01, count: 64),
            expectedMrEnclave: Data(repeating: 0xAA, count: 32)
        )
        XCTAssertTrue(valid, "Mock should accept non-empty report.")
    }

    func testMockSGXAttestationRejectsEmptyReport() async {
        let client = MobileCoinClient(sdk: MockMobileCoinSDK())

        let valid = await client.verifySGXAttestation(
            report: Data(),
            expectedMrEnclave: Data(repeating: 0xAA, count: 32)
        )
        XCTAssertFalse(valid, "Mock should reject empty report.")
    }

    func testMockSGXAttestationRejectsBadMrEnclave() async {
        let client = MobileCoinClient(sdk: MockMobileCoinSDK())

        let valid = await client.verifySGXAttestation(
            report: Data(repeating: 0x01, count: 64),
            expectedMrEnclave: Data(repeating: 0xAA, count: 16) // Wrong size
        )
        XCTAssertFalse(valid, "Mock should reject wrong-sized MRENCLAVE.")
    }
}
