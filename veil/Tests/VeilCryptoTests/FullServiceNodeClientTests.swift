// FullServiceNodeClientTests.swift
// VEIL — MobileCoin Payment Integration Tests
//
// VEIL-404: Tests for Full-Service Node client, submission strategy,
// and block polling logic.

import XCTest
@testable import VeilCrypto

final class FullServiceNodeClientTests: XCTestCase {

    // MARK: - Submission Receipt

    func testSubmissionReceiptCodable() throws {
        let receipt = SubmissionReceipt(
            submissionId: "sub-001",
            estimatedBlockHeight: 12345,
            submittedAt: "2026-03-04T10:00:00Z"
        )

        let data = try JSONEncoder().encode(receipt)
        let decoded = try JSONDecoder().decode(SubmissionReceipt.self, from: data)

        XCTAssertEqual(decoded.submissionId, "sub-001")
        XCTAssertEqual(decoded.estimatedBlockHeight, 12345)
        XCTAssertEqual(decoded.submittedAt, "2026-03-04T10:00:00Z")
    }

    // MARK: - Transaction Status Response

    func testTransactionStatusConfirmed() throws {
        let json = """
        {
            "status": "confirmed",
            "blockIndex": 12350,
            "confirmations": 5,
            "failureReason": null
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(TransactionStatusResponse.self, from: json)

        XCTAssertEqual(response.status, "confirmed")
        XCTAssertEqual(response.blockIndex, 12350)
        XCTAssertEqual(response.confirmations, 5)
        XCTAssertNil(response.failureReason)
    }

    func testTransactionStatusFailed() throws {
        let json = """
        {
            "status": "failed",
            "blockIndex": null,
            "confirmations": null,
            "failureReason": "Double spend detected"
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(TransactionStatusResponse.self, from: json)

        XCTAssertEqual(response.status, "failed")
        XCTAssertNil(response.blockIndex)
        XCTAssertEqual(response.failureReason, "Double spend detected")
    }

    func testTransactionStatusPending() throws {
        let json = """
        {
            "status": "pending",
            "blockIndex": null,
            "confirmations": null,
            "failureReason": null
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(TransactionStatusResponse.self, from: json)
        XCTAssertEqual(response.status, "pending")
    }

    // MARK: - Ring Member Response

    func testRingMemberResponseParsing() throws {
        let json = """
        {
            "rings": [
                {
                    "txoPublicKey": "\(Data(repeating: 0x42, count: 32).base64EncodedString())",
                    "members": [
                        {
                            "publicKey": "\(Data(repeating: 0x01, count: 32).base64EncodedString())",
                            "membershipProof": "\(Data(repeating: 0x02, count: 32).base64EncodedString())",
                            "blockIndex": 100
                        },
                        {
                            "publicKey": "\(Data(repeating: 0x03, count: 32).base64EncodedString())",
                            "membershipProof": "\(Data(repeating: 0x04, count: 32).base64EncodedString())",
                            "blockIndex": 101
                        }
                    ]
                }
            ]
        }
        """.data(using: .utf8)!

        let response = try JSONDecoder().decode(RingMemberResponse.self, from: json)
        let ringMembers = response.toRingMembers()

        XCTAssertEqual(ringMembers.count, 1, "Should have 1 TXO's ring members.")
        let key = Data(repeating: 0x42, count: 32)
        XCTAssertEqual(ringMembers[key]?.count, 2, "Should have 2 ring members.")
    }

    // MARK: - MobileCoin Constants

    func testConstants() {
        XCTAssertEqual(MobileCoinConstants.defaultRingSize, 11)
        XCTAssertEqual(MobileCoinConstants.picoMOBPerMOB, 1_000_000_000_000)
        XCTAssertEqual(MobileCoinConstants.maxRetries, 3)
        XCTAssertEqual(MobileCoinConstants.confirmationTimeoutSeconds, 30.0)
        XCTAssertEqual(MobileCoinConstants.maxTransactionSize, 65_536)
    }

    // MARK: - Confirmed Transaction

    func testConfirmedTransactionCodable() throws {
        let confirmed = ConfirmedTransaction(
            txHash: Data(repeating: 0xAB, count: 32),
            blockIndex: 99999,
            confirmations: 3,
            amount: 5_000_000_000_000,
            fee: 400_000_000
        )

        let data = try JSONEncoder().encode(confirmed)
        let decoded = try JSONDecoder().decode(ConfirmedTransaction.self, from: data)

        XCTAssertEqual(decoded.txHash, confirmed.txHash)
        XCTAssertEqual(decoded.blockIndex, 99999)
        XCTAssertEqual(decoded.confirmations, 3)
        XCTAssertEqual(decoded.amount, 5_000_000_000_000)
        XCTAssertEqual(decoded.fee, 400_000_000)
    }

    // MARK: - FSN Error Response

    func testFSNErrorResponseParsing() throws {
        let json = """
        {
            "message": "Invalid transaction format",
            "code": "INVALID_TX"
        }
        """.data(using: .utf8)!

        let error = try JSONDecoder().decode(FSNErrorResponse.self, from: json)
        XCTAssertEqual(error.message, "Invalid transaction format")
        XCTAssertEqual(error.code, "INVALID_TX")
    }
}
