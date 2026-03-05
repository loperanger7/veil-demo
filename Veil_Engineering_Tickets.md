# Veil — Engineering Tickets

**Project:** Veil Post-Quantum Encrypted Chat & Payments (iOS)
**Spec Version:** 1.0 — March 2026
**Notation:** Each ticket is tagged with priority (P0 = launch blocker, P1 = critical, P2 = important, P3 = nice-to-have), a rough estimate in engineering-days, and upstream dependencies.

---

## Epic 1: Cryptographic Core Library

> The foundational cryptographic primitives and protocol implementations that everything else depends on. This is the most security-critical workstream and requires the most rigorous review.

### VEIL-101 — Hybrid Identity Key Generation

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** None

Generate and manage the hybrid identity key pair: Ed25519 (via iOS Secure Enclave) + ML-DSA-65 (via liboqs, encrypted at rest by SEP-derived KEK).

**Acceptance Criteria:**

- Ed25519 key pair is generated inside the Secure Enclave and never leaves it
- ML-DSA-65 key pair is generated in app process, immediately encrypted with a KEK derived via `SecureEnclave.deriveKey("Veil:PQ-Identity")`
- Private keys survive app restart (persisted in Keychain with appropriate protection class)
- Private keys are non-exportable and excluded from device backups
- Unit tests cover generation, signing, verification, and round-trip persistence
- Constant-time verification (dudect) on all signing paths

---

### VEIL-102 — ML-KEM-1024 Integration

**Priority:** P0 · **Estimate:** 4d · **Dependencies:** None

Integrate ML-KEM-1024 (NIST FIPS 203) via liboqs. Wrap in a Swift-friendly API with key generation, encapsulation, and decapsulation.

**Acceptance Criteria:**

- `KeyPair.generate() -> (PublicKey, SecretKey)` produces valid ML-KEM-1024 key pairs
- `encapsulate(pk) -> (SharedSecret, Ciphertext)` and `decapsulate(sk, ct) -> SharedSecret` round-trip correctly
- Shared secrets are 32 bytes; ciphertexts are 1568 bytes
- All liboqs memory is zeroized after use via `OQS_MEM_cleanse`
- Property-based test: `forall pk, sk: decapsulate(sk, encapsulate(pk).ct) == encapsulate(pk).ss`
- Fuzz test on decapsulation with malformed ciphertexts (no crashes, graceful errors)

---

### VEIL-103 — HKDF-SHA-512 with Domain Separation

**Priority:** P0 · **Estimate:** 2d · **Dependencies:** None

Implement HKDF-SHA-512 key derivation with mandatory domain separation strings following the `"Veil:<protocol>:v<n>"` convention from the spec.

**Acceptance Criteria:**

- API requires a non-empty `info` string (compile-time enforcement via type system)
- All domain separation strings from spec Section 3.4 are defined as constants
- Output matches RFC 5869 test vectors
- Intermediate PRK values are zeroized after extraction
- Property-based test: different `info` strings always produce different outputs for the same `ikm`

---

### VEIL-104 — PQXDH Key Agreement Protocol

**Priority:** P0 · **Estimate:** 8d · **Dependencies:** VEIL-101, VEIL-102, VEIL-103

Implement the full PQXDH handshake as specified in Section 3.2. Alice-side (initiator) and Bob-side (responder) key agreement producing the shared session key SK.

**Acceptance Criteria:**

- Initiator computes DH1–DH4 + ML-KEM encapsulations and derives SK via HKDF
- Responder performs corresponding DH + ML-KEM decapsulations and derives the same SK
- Handles the case where one-time prekeys (OPK, PQOPK) are unavailable (falls back to SPK/PQSPK only)
- All ephemeral key material is zeroized immediately after SK derivation
- Prekey signature verification (Ed25519 over SPK and PQSPK) is performed before any DH/KEM operations
- Invalid signatures cause immediate abort with no partial state retained
- Integration test: full Alice-Bob handshake produces matching SK values
- Property test: SK is always 64 bytes and never all-zeros

---

### VEIL-105 — Symmetric Chain Ratchet

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** VEIL-103

Implement the symmetric chain ratchet (Ratchet 1) that derives per-message keys from a chain key using HMAC-SHA-256.

**Acceptance Criteria:**

- `advanceChain(CK) -> (CK_next, MK)` with `CK_next = HMAC(CK, 0x02)` and `MK = HMAC(CK, 0x01)`
- Previous chain key and message key are zeroized after use
- Out-of-order message handling: skipped message keys are stored (up to configurable max, default 2000) and garbage-collected after a timeout
- Property test: advancing chain N times produces N unique message keys
- Property test: no message key equals any chain key

---

### VEIL-106 — Diffie-Hellman Ratchet (Classical)

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** VEIL-103, VEIL-105

Implement the DH ratchet (Ratchet 2) that performs X25519 exchanges on direction changes and mixes output into the root key.

**Acceptance Criteria:**

- New ephemeral X25519 key pair generated on each sending ratchet step
- `(RK_new, CK) = HKDF(salt=RK, ikm=DH(ek_self, ek_peer), info="Veil:DHRatchet:v1")`
- Old root key and old chain keys are zeroized after ratchet step
- Handles multiple messages in the same direction without redundant DH steps
- Integration test: Alice and Bob exchange 1000 messages in random send/receive patterns; all decrypt correctly
- Property test: root key changes on every direction change

---

### VEIL-107 — Sparse Post-Quantum Ratchet (SPQR)

**Priority:** P0 · **Estimate:** 10d · **Dependencies:** VEIL-102, VEIL-103, VEIL-106

Implement the SPQR (Ratchet 3) running in parallel with the DH ratchet, fragmenting ML-KEM-1024 public keys and ciphertexts across messages.

**Acceptance Criteria:**

- ML-KEM public key fragments are attached to outgoing message headers (configurable fragment size, default 256 bytes)
- Receiving side accumulates fragments and triggers encapsulation when a full public key is assembled
- Ciphertext fragments are sent back similarly; decapsulation occurs when all fragments arrive
- PQ shared secret is mixed into root key: `RK = HKDF(RK, ss_pq, "Veil:SPQR:v1")`
- SPQR ratchet step completes within 50–100 messages or 24 hours, whichever is first
- Handles fragment loss gracefully (missed fragments trigger re-send of full key in next epoch)
- Integration test: full session with interleaved DH and SPQR ratchet steps
- Property test: PQ shared secret is always mixed into root key after fragment assembly

---

### VEIL-108 — Triple Ratchet Composition

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** VEIL-105, VEIL-106, VEIL-107

Compose all three ratchets into the unified Triple Ratchet state machine from spec Section 8.2. This is the top-level session encryption/decryption API.

**Acceptance Criteria:**

- `encrypt(session, plaintext) -> (header, ciphertext)` and `decrypt(session, header, ciphertext) -> plaintext` work correctly
- AES-256-GCM with per-message key and associated data (header bytes)
- State machine transitions match spec Section 8.2 exactly
- Graceful handling of out-of-order messages (up to max skip window)
- Integration test: 10,000-message conversation with random patterns, message reordering, and simulated message loss
- Performance test: encrypt + decrypt latency < 1ms on iPhone 14 equivalent

---

### VEIL-109 — Message Key Zeroization & Memory Safety

**Priority:** P0 · **Estimate:** 4d · **Dependencies:** VEIL-108

Audit and harden all cryptographic memory handling across the core library.

**Acceptance Criteria:**

- All secret key material uses a `SecureBytes` type that zeroizes on deallocation
- No secret material appears in Swift `String` types (which may be copied by ARC)
- AddressSanitizer and MemorySanitizer pass on full test suite
- Manual audit confirms no secret key material is logged, serialized to disk in plaintext, or included in crash reports
- Constant-time comparison for all MAC verification and key equality checks

---

## Epic 2: Prekey Management & Registration

> User registration, prekey bundle generation, upload, and replenishment. The bridge between the crypto core and the server.

### VEIL-201 — Prekey Bundle Generation

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** VEIL-101, VEIL-102

Generate the full prekey bundle as specified in Section 3.2: signed prekey (X25519), PQ signed prekey (ML-KEM-1024), pools of one-time prekeys (classical + PQ), and all signatures.

**Acceptance Criteria:**

- Signed prekey rotated weekly; signature by Ed25519 identity key
- PQ signed prekey rotated weekly; signature by Ed25519 identity key
- 100 classical one-time prekeys + 100 PQ one-time prekeys generated initially
- All prekeys persisted in SQLCipher with corresponding private keys
- Used one-time prekeys are deleted after session establishment

---

### VEIL-202 — Prekey Upload & Replenishment

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** VEIL-201, VEIL-301

Upload prekey bundle to the Veil Relay Service. Monitor remaining one-time prekey count and replenish when below 20% threshold.

**Acceptance Criteria:**

- Initial registration uploads full bundle (identity key, SPK, PQSPK, 100 OPKs, 100 PQOPKs)
- Background task checks remaining prekey count on server periodically (and on push notification)
- Replenishment generates and uploads new one-time prekeys to restore pool to 100
- Signed prekey rotation uploads new SPK + PQSPK weekly
- Handles network failure gracefully (retries with exponential backoff)

---

### VEIL-203 — Prekey Fetch & Validation

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** VEIL-201, VEIL-301

Fetch a recipient's prekey bundle from the relay when initiating a new session. Validate all signatures before use.

**Acceptance Criteria:**

- Fetches latest prekey bundle for a given recipient identifier
- Verifies SPK signature and PQSPK signature against recipient's identity key
- Rejects bundle and aborts session if any signature is invalid
- Handles case where no one-time prekeys remain (falls back to SPK/PQSPK only)
- Caches identity keys for safety number computation

---

## Epic 3: Veil Relay Service (Server)

> The untrusted message delivery infrastructure. Stores only opaque ciphertext.

### VEIL-301 — Relay Service Core Infrastructure

**Priority:** P0 · **Estimate:** 8d · **Dependencies:** None

Stand up the Veil Relay Service: HTTP/2 API server with TLS 1.3, prekey storage, and message queue.

**Acceptance Criteria:**

- HTTP/2 server with TLS 1.3 (no downgrade to TLS 1.2)
- Endpoints: register device, upload prekeys, fetch prekeys, send message, retrieve messages
- Message queue per device (opaque blob storage, FIFO delivery)
- Messages deleted from queue after delivery acknowledgment
- No plaintext logging of message content or sender-recipient pairs
- Rate limiting via anonymous credential verification (Ristretto255 tokens)
- Load test: sustains 10,000 concurrent connections with < 100ms p99 latency

---

### VEIL-302 — Sealed Sender Implementation

**Priority:** P1 · **Estimate:** 5d · **Dependencies:** VEIL-301

Implement the sealed sender protocol so the relay cannot determine message sender.

**Acceptance Criteria:**

- Sender certificate is encrypted inside the message envelope (not visible to relay)
- Relay routes messages by recipient registration ID and device ID only
- Sender IP addresses are not logged or associated with message delivery
- Abuse prevention uses anonymous credential tokens (not sender identity)
- Integration test: relay processes message without any way to extract sender

---

### VEIL-303 — Anonymous Credentials (Ristretto255)

**Priority:** P1 · **Estimate:** 5d · **Dependencies:** VEIL-301

Implement blind signature-based anonymous credentials for rate limiting and abuse prevention.

**Acceptance Criteria:**

- Server issues blinded tokens during registration (one token per N messages)
- Client unblinds and stores tokens locally
- Each message send consumes one token (revealed to server, but unlinkable to registration)
- Server verifies token validity without learning which user submitted it
- Token replenishment occurs transparently during message retrieval

---

### VEIL-304 — Push Notification Relay

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-301

Deliver push notifications via APNs when messages arrive for an offline device, without leaking message content.

**Acceptance Criteria:**

- Push payload contains only a "new message available" signal (no preview, no sender)
- Client wakes, connects to relay, retrieves and decrypts messages locally
- APNs token registration flow integrated with device registration
- Handles multiple devices per user (notifications sent to all registered devices)

---

## Epic 4: MobileCoin Payment Integration

> On-device transaction construction, submission, and receipt handling.

### VEIL-401 — MobileCoin Key Derivation from Veil Identity

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** VEIL-101, VEIL-103

Derive MobileCoin spend and view keys deterministically from the Veil identity key, so users have a single identity for both chat and payments.

**Acceptance Criteria:**

- `mob_spend_key = HKDF(ikm=IK, info="Veil:MOB:spend:v1")` produces a valid Ristretto255 scalar
- `mob_view_key = HKDF(ikm=IK, info="Veil:MOB:view:v1")` produces a valid Ristretto255 scalar
- Derived keys are deterministic (same IK always produces same MOB keys)
- Spend key stored in Keychain with biometric access control
- View key stored in Keychain with after-first-unlock access
- Unit test: derived keys are valid on the MobileCoin curve

---

### VEIL-402 — Recipient Address Resolution

**Priority:** P0 · **Estimate:** 2d · **Dependencies:** VEIL-401

Derive a recipient's MobileCoin public subaddress from their Veil identity key, enabling payments without exchanging separate MOB addresses.

**Acceptance Criteria:**

- Given Bob's Veil public identity key, derive his MobileCoin public address
- Derived address matches what Bob's own client computes for itself
- Integration test: Alice derives Bob's address; Bob can spend funds sent to it

---

### VEIL-403 — Transaction Construction

**Priority:** P0 · **Estimate:** 8d · **Dependencies:** VEIL-401, VEIL-402

Construct MobileCoin transactions locally on-device using the MobileCoin SDK. Select inputs, build ring signatures, generate range proofs.

**Acceptance Criteria:**

- Select unspent TXOs from local balance sufficient for amount + fee
- Construct ring signature with mixin count = 11 (MobileCoin default)
- Generate Bulletproofs+ range proof for output amounts
- Change output returns to sender's subaddress
- Transaction is valid and accepted by MobileCoin consensus testnet
- Handles insufficient balance gracefully (clear error before submission)
- Performance: transaction construction < 3 seconds on iPhone 14

---

### VEIL-404 — Transaction Submission & Confirmation

**Priority:** P0 · **Estimate:** 4d · **Dependencies:** VEIL-403

Submit constructed transactions to a MobileCoin Full-Service Node and poll for confirmation.

**Acceptance Criteria:**

- TLS 1.3 connection with certificate pinning to Full-Service Node
- Submit transaction and receive submission receipt
- Poll for block inclusion with configurable timeout (default 30s)
- Return confirmed block index and transaction hash on success
- Timeout or rejection triggers `Failed` state in payment state machine
- Retry logic for transient network failures (max 3 retries)

---

### VEIL-405 — Encrypted Payment Receipt

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** VEIL-404, VEIL-108

After transaction confirmation, construct and send an encrypted payment notification through the Triple Ratchet session.

**Acceptance Criteria:**

- `PaymentMessage` protobuf includes tx_hash, shared_secret, amount_picomob, memo, receipt_proof, block_index
- Message encrypted under existing Triple Ratchet session (no separate channel)
- Recipient can locate incoming TXO using shared_secret + their view key via Fog
- Integration test: Alice pays Bob; Bob receives notification and can verify balance increase

---

### VEIL-406 — Fog Client Integration

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** VEIL-401

Integrate MobileCoin Fog for lightweight mobile balance queries and incoming transaction detection without downloading the full ledger.

**Acceptance Criteria:**

- Register view key with Fog service (SGX-attested)
- Query balance returns correct MOB amount
- Detect incoming TXOs from payment receipt shared secrets
- Background refresh of balance on app foreground and push notification
- Handles Fog service unavailability gracefully (cached last-known balance)

---

### VEIL-407 — Payment State Machine

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-403, VEIL-404, VEIL-405

Implement the payment state machine from spec Section 8.3 governing the full lifecycle from initiation to completion or failure.

**Acceptance Criteria:**

- States: Idle, ConstructingTx, SubmittingTx, AwaitingConfirmation, SendingReceipt, Complete, Failed
- All transitions match spec exactly
- No funds leave wallet if construction or submission fails
- Failed state displays clear error message to user
- State persisted to disk so in-flight payments survive app restart
- Unit test: every state transition is exercised; no unreachable states

---

## Epic 5: iOS Application Shell & UI

> The client application, user interface, and local data layer.

### VEIL-501 — Project Scaffolding & Build Pipeline

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** None

Set up the Xcode project, CI/CD pipeline, and dependency management.

**Acceptance Criteria:**

- Xcode project with Swift strict concurrency enabled
- Swift Package Manager for dependencies (libsignal fork, MobileCoin SDK, liboqs, SQLCipher, SwiftProtobuf)
- CI pipeline: build, lint (SwiftLint), unit tests, AddressSanitizer, ThreadSanitizer
- Nightly pipeline: property-based tests (1M iterations), fuzz tests (72h campaigns)
- Deployment target: iOS 17.0+

---

### VEIL-502 — SQLCipher Local Database

**Priority:** P0 · **Estimate:** 4d · **Dependencies:** VEIL-101

Set up the encrypted local database for storing ratchet state, messages, contacts, and prekeys.

**Acceptance Criteria:**

- SQLCipher database with encryption key derived from Secure Enclave
- Schema: sessions, messages, contacts, prekeys, payment_receipts
- Database file excluded from iCloud backup and iTunes backup
- Migrations framework for future schema changes
- WAL mode enabled for concurrent read performance
- Unit test: database is unreadable without SEP-derived key

---

### VEIL-503 — Registration & Phone Number Verification

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** VEIL-201, VEIL-301

User registration flow: phone number verification via SMS, identity key generation, prekey upload.

**Acceptance Criteria:**

- Phone number input with country code picker
- SMS verification code entry (6-digit code, 60s expiry)
- On verification: generate identity keys (VEIL-101), generate prekeys (VEIL-201), upload bundle (VEIL-202)
- Registration ID assigned by server; stored locally
- Handles re-registration (new device, same number) without breaking existing sessions on other devices

---

### VEIL-504 — Conversation List View

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-502

Main screen showing all conversations, sorted by most recent activity.

**Acceptance Criteria:**

- List of conversations with contact name/number, last message preview (decrypted locally), timestamp
- Unread message count badge
- Swipe to archive/delete conversation
- Pull to refresh
- New conversation button (contact picker)
- Search bar for filtering conversations
- San Francisco typeface, clean minimal styling per spec Section 5.2

---

### VEIL-505 — Chat View

**Priority:** P0 · **Estimate:** 8d · **Dependencies:** VEIL-108, VEIL-502

The core chat interface for sending and receiving encrypted messages.

**Acceptance Criteria:**

- Message bubbles: outgoing (subtle tinted background), incoming (white)
- Text input with send button
- Real-time message delivery via WebSocket to relay
- Decryption via Triple Ratchet on receive
- Encryption via Triple Ratchet on send
- Typing indicators (encrypted, sent via ratchet)
- Read receipts (encrypted)
- Scroll to bottom on new message; smooth scrolling through history
- Timestamps shown contextually (not on every message)

---

### VEIL-506 — Payment UI

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** VEIL-405, VEIL-505

In-chat payment experience: send MOB with a single flow.

**Acceptance Criteria:**

- Payment icon adjacent to message composer
- Tap opens numeric keypad with currency toggle (local currency / MOB)
- Optional memo field (max 256 characters)
- Confirmation screen showing amount, recipient, and fee
- Biometric authentication (Face ID / Touch ID) required to confirm
- Entire flow completes in < 4 seconds (excluding biometric)
- Payment message bubble with subtle gradient border, showing amount in local currency + MOB
- Incoming payment bubble shows amount and memo
- Error states: insufficient balance, network failure, timeout

---

### VEIL-507 — Balance View

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-406

Display current MobileCoin balance and transaction history.

**Acceptance Criteria:**

- Balance displayed in MOB and local currency equivalent
- Transaction history list (sent/received, amount, timestamp, memo, recipient/sender)
- Pull to refresh balance via Fog
- Balance updates in real time when payments are sent/received during active session

---

### VEIL-508 — Safety Number Verification

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-101, VEIL-502

Allow users to verify the identity of their conversation partner via safety numbers.

**Acceptance Criteria:**

- Safety number computed from both parties' identity keys (deterministic)
- Displayed as 60-digit numeric code and scannable QR code
- QR scan uses device camera; match/mismatch result shown clearly
- Safety number changes when a contact re-registers (key change notification in chat)
- Verification status persisted per contact

---

### VEIL-509 — Settings & Linked Devices

**Priority:** P2 · **Estimate:** 4d · **Dependencies:** VEIL-502, VEIL-503

Minimal settings surface: profile, linked devices, notification preferences.

**Acceptance Criteria:**

- Profile: display name, avatar (encrypted profile, shared via profile key)
- Linked devices: list, add via QR scan, remove
- Notifications: on/off, sound, preview (always off by default for privacy)
- No encryption settings (there are no choices to make)
- About screen with version and open-source licenses

---

## Epic 6: Network & Transport Layer

> TLS, certificate pinning, censorship resistance, and traffic analysis protection.

### VEIL-601 — TLS 1.3 with Certificate Pinning

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** VEIL-301

Configure all client-server communication to use TLS 1.3 with pinned certificates.

**Acceptance Criteria:**

- TLS 1.3 only (no fallback to 1.2)
- Certificate pins for relay service and MobileCoin Full-Service Node
- Pin rotation via signed configuration update (out-of-band channel)
- Connection refused if pin validation fails
- Unit test: connection with wrong certificate is rejected

---

### VEIL-602 — Traffic Padding

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-108

Pad all encrypted messages to 256-byte block boundaries to prevent content type inference from ciphertext length.

**Acceptance Criteria:**

- All outgoing ciphertext padded to next multiple of 256 bytes
- Padding is random bytes, stripped after decryption
- Padding scheme is deterministic given message length (for testing)
- Property test: messages of different types but similar length produce same ciphertext size

---

### VEIL-603 — Domain Fronting / Censorship Resistance

**Priority:** P2 · **Estimate:** 5d · **Dependencies:** VEIL-601

Implement domain fronting via CDN infrastructure for use in censored network environments.

**Acceptance Criteria:**

- Configurable per-region CDN fronting domain
- Fronting domain set in TLS SNI; actual relay domain in HTTP Host header
- Configuration delivered via signed update channel
- Fallback to direct connection if fronting is unnecessary
- Manual test in simulated censored network environment

---

## Epic 7: Formal Verification & Proofs

> ProVerif models, computational proof sketches, and the formal verification CI pipeline.

### VEIL-701 — ProVerif Model: PQXDH

**Priority:** P1 · **Estimate:** 8d · **Dependencies:** VEIL-104 (design, not implementation)

Model the PQXDH protocol in ProVerif and verify secrecy, authentication, and forward secrecy.

**Acceptance Criteria:**

- Applied pi-calculus model of full PQXDH handshake (~1,200 lines)
- Verified properties: secrecy of SK, authentication, forward secrecy, key confirmation
- Model uses Dolev-Yao attacker with PQ extensions
- ProVerif terminates with "RESULT ... true" for all queries
- Model checked into `/proofs/proverif/pqxdh_model.pv`

---

### VEIL-702 — ProVerif Model: Triple Ratchet

**Priority:** P1 · **Estimate:** 12d · **Dependencies:** VEIL-108 (design)

Model the Triple Ratchet in ProVerif and verify forward secrecy, PCS (classical + PQ), and no key reuse.

**Acceptance Criteria:**

- Applied pi-calculus model of composed Triple Ratchet (~2,400 lines)
- Verified: FS, PCS-classical (after DH step), PCS-PQ (after SPQR step), no key reuse
- Model covers out-of-order messages and skipped message keys
- ProVerif terminates successfully for all queries
- Model checked into `/proofs/proverif/triple_ratchet_model.pv`

---

### VEIL-703 — ProVerif Model: Sealed Sender & Payment Notification

**Priority:** P1 · **Estimate:** 6d · **Dependencies:** VEIL-302, VEIL-405 (design)

Model sealed sender and payment notification protocols in ProVerif.

**Acceptance Criteria:**

- Sealed sender model: sender anonymity, replay resistance (~600 lines)
- Payment notification model: payment secrecy, receipt integrity (~800 lines)
- Both terminate successfully in ProVerif
- Checked into `/proofs/proverif/`

---

### VEIL-704 — Composition Model

**Priority:** P1 · **Estimate:** 8d · **Dependencies:** VEIL-701, VEIL-702, VEIL-703

Compose all individual ProVerif models into a unified model verifying end-to-end properties.

**Acceptance Criteria:**

- Unified model (~3,200 lines) importing sub-models
- Verified: end-to-end message secrecy, end-to-end payment-chat unlinkability
- Model exercises full lifecycle: registration → PQXDH → ratcheting → payment → receipt
- CI job runs ProVerif verification on every merge to main (acceptable runtime < 30 min)

---

### VEIL-705 — Computational Proof Sketches

**Priority:** P2 · **Estimate:** 5d · **Dependencies:** VEIL-701, VEIL-702

Write the three computational proof sketches (Theorems 1–3) from spec Section 6.2 as LaTeX documents with full reduction arguments.

**Acceptance Criteria:**

- Theorem 1: PQXDH security reduces to CDH + IND-CCA2 of ML-KEM-1024
- Theorem 2: Triple Ratchet composition is secure if DH ratchet and SPQR are individually secure
- Theorem 3: Payment privacy composes correctly due to disjoint key material
- Peer-reviewed by at least one external cryptographer before v1.0 launch

---

## Epic 8: Testing Infrastructure

> Property-based tests, fuzz testing, side-channel tests, and CI integration.

### VEIL-801 — Property-Based Test Suite (SwiftCheck)

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** VEIL-108, VEIL-405

Implement the property-based test invariants from spec Section 6.3.

**Acceptance Criteria:**

- Ratchet symmetry: Alice and Bob derive same message keys for all random message patterns
- Forward secrecy: erased state cannot decrypt prior messages
- No key reuse: all message keys in a session are unique
- Idempotent ratchet: processing same message twice does not advance state
- Payment integrity: decrypted receipt matches constructed receipt
- Each property runs 10,000 cases on CI, 1,000,000 on nightly
- Any failure blocks release pipeline

---

### VEIL-802 — Fuzz Testing Campaign

**Priority:** P1 · **Estimate:** 4d · **Dependencies:** VEIL-108, VEIL-405

Set up AFL++ and libFuzzer harnesses for all deserialization and decryption paths.

**Acceptance Criteria:**

- Fuzz harnesses for: protobuf deserialization, ciphertext decryption, KEM decapsulation, prekey bundle parsing
- 72-hour campaign per release candidate
- Crash-free runs required for release
- Corpus checked into repository for regression testing
- CI runs 1-hour fuzz campaigns on every merge to main

---

### VEIL-803 — Constant-Time Verification

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-109

Run dudect-based timing analysis on all cryptographic operations to verify constant-time behavior.

**Acceptance Criteria:**

- dudect harness for: HMAC comparison, AES-GCM decryption, X25519 scalar multiplication, ML-KEM decapsulation
- All operations pass dudect with p-value > 0.01 (no detectable timing variation)
- Results documented and checked into `/tests/timing/`
- CI runs timing tests on dedicated hardware (no virtualized timing)

---

### VEIL-804 — Integration Test Suite

**Priority:** P0 · **Estimate:** 5d · **Dependencies:** VEIL-108, VEIL-301, VEIL-405

End-to-end integration tests covering the full session lifecycle.

**Acceptance Criteria:**

- Test scenarios: registration → prekey upload → session establishment → 100 messages → payment → session teardown
- Multi-device test: user with 2 devices receives messages on both
- Key change test: contact re-registers; safety number changes; new session established
- Offline test: messages queued while recipient offline; delivered on reconnect
- Payment failure test: insufficient balance, network timeout, malformed transaction
- All tests run on CI with simulated relay and MobileCoin testnet

---

## Epic 9: Security Hardening & Audit Preparation

> Final hardening, audit preparation, and security review.

### VEIL-901 — Threat Model Documentation

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** All design tickets

Document the full threat model from spec Section 7 as a standalone security document for external auditors.

**Acceptance Criteria:**

- Adversary capability matrix (from spec Section 7.1)
- Attack surface enumeration for each component
- Known limitations (spec Section 7.2) clearly stated
- Residual risk assessment
- Recommended mitigations for out-of-scope threats

---

### VEIL-902 — External Cryptographic Audit (Prep)

**Priority:** P1 · **Estimate:** 5d · **Dependencies:** VEIL-108, VEIL-401

Prepare the codebase for external cryptographic audit: code documentation, architecture diagrams, and audit scope definition.

**Acceptance Criteria:**

- All cryptographic code has inline documentation explaining algorithm choices
- Architecture diagrams for each protocol (PQXDH, Triple Ratchet, payment flow)
- Audit scope document defining what the auditor should review
- Clean, auditable code organization (crypto code isolated from UI code)
- Pre-audit internal review completed

---

### VEIL-903 — Penetration Test Preparation

**Priority:** P2 · **Estimate:** 3d · **Dependencies:** VEIL-301, VEIL-601

Prepare the relay service and client for external penetration testing.

**Acceptance Criteria:**

- Staging environment deployed with production-equivalent configuration
- Test accounts provisioned
- Scope document: API endpoints, client-server communication, push notification flow
- Known-good baseline established (all current tests passing)

---

## Epic 10: Launch Preparation

> App Store submission, documentation, and operational readiness.

### VEIL-1001 — App Store Submission

**Priority:** P0 · **Estimate:** 3d · **Dependencies:** All P0 tickets

Prepare and submit the iOS application to the App Store.

**Acceptance Criteria:**

- App Store listing: screenshots, description, privacy nutrition labels
- Privacy nutrition label accurately reflects data collection (minimal: phone number for registration only)
- Export compliance documentation for encryption (CCATS/ERN if required)
- TestFlight beta deployed and validated
- App Review guidelines compliance verified

---

### VEIL-1002 — Open Source Preparation

**Priority:** P2 · **Estimate:** 5d · **Dependencies:** All implementation tickets

Prepare the cryptographic protocol library and ProVerif models for open-source release.

**Acceptance Criteria:**

- Protocol library extracted as standalone Swift package
- ProVerif models in standalone repository with README
- License files (AGPL-3.0 for protocol library)
- Contributing guidelines
- Security disclosure policy (responsible disclosure with 90-day window)
- Build instructions verified on clean macOS environment

---

### VEIL-1003 — Operational Runbook

**Priority:** P1 · **Estimate:** 3d · **Dependencies:** VEIL-301

Document operational procedures for the relay service.

**Acceptance Criteria:**

- Deployment procedures (infrastructure as code)
- Monitoring and alerting configuration
- Incident response playbook
- Certificate rotation procedures
- Scaling guidelines
- Data retention policy (messages deleted after delivery; no long-term storage)

---

## Dependency Graph (Critical Path)

The critical path to a functional MVP runs through these tickets in order:

```
VEIL-101 (Identity Keys)
    ├── VEIL-102 (ML-KEM) ──┐
    ├── VEIL-103 (HKDF) ────┤
    │                        ├── VEIL-104 (PQXDH) ──┐
    │                        │                       │
    ├── VEIL-105 (Sym Chain) ┤                       │
    │                        ├── VEIL-106 (DH Ratch) ┤
    │                        │                       │
    │   VEIL-102 ────────────┼── VEIL-107 (SPQR) ───┤
    │                        │                       │
    │                        └───────────────────────┼── VEIL-108 (Triple Ratchet)
    │                                                │
    ├── VEIL-201 (Prekeys) ──── VEIL-202 (Upload) ──┤
    │                                                │
    ├── VEIL-301 (Relay) ───────────────────────────┤
    │                                                │
    └───────────────────────────────────────────────┼── VEIL-505 (Chat View) ── MVP
                                                     │
    VEIL-401 (MOB Keys) ── VEIL-403 (Tx Build) ─── VEIL-405 (Receipt) ── VEIL-506 (Payment UI)
```

**Estimated total effort:** ~250 engineering-days across all tickets.

**Recommended team allocation:** 3 cryptographic engineers (Epics 1, 7, 8), 2 backend engineers (Epics 2, 3), 3 iOS engineers (Epics 5, 6), 1 MobileCoin integration specialist (Epic 4), 1 security engineer (Epic 9). With this team of ~10, the critical path to MVP is approximately 14–16 weeks.
