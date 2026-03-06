// VEIL — ArchitectureDiagrams.swift
// Ticket: VEIL-902 — External Cryptographic Audit Preparation
// Spec reference: All protocol sections
//
// Mermaid diagram strings as Swift constants, renderable by documentation
// tools (e.g., DocC, GitHub markdown, Mermaid CLI). Each diagram is
// annotated with the security properties it illustrates.
//
// Usage:
//   let svg = try MermaidRenderer.render(ProtocolDiagrams.pqxdhFlow)
//   // or copy the raw string into a .mermaid file

import Foundation

// MARK: - Protocol Diagrams

/// Architecture diagrams for external audit documentation.
///
/// Each diagram is a Mermaid-format string that can be rendered to SVG/PNG
/// for inclusion in audit reports. The diagrams cover every protocol layer
/// in the Veil system.
public enum ProtocolDiagrams: Sendable {

    // MARK: - PQXDH Key Agreement

    /// Full PQXDH handshake sequence diagram.
    ///
    /// Security properties illustrated:
    /// - Forward secrecy (ephemeral keys)
    /// - Post-quantum security (ML-KEM-1024)
    /// - Hybrid key agreement (classical + PQ)
    public static let pqxdhFlow = """
    sequenceDiagram
        participant Alice
        participant Relay as Relay Server
        participant Bob

        Note over Bob: Registration Phase
        Bob->>Bob: Generate IdentityKeyPair (Ed25519 + ML-DSA-65)
        Bob->>Bob: Generate SignedPrekey (X25519)
        Bob->>Bob: Generate PQ SignedPrekey (ML-KEM-1024)
        Bob->>Bob: Generate OneTimePrekeys (X25519 + ML-KEM-1024)
        Bob->>Relay: Upload PrekeyBundle

        Note over Alice: Session Initiation
        Alice->>Relay: Fetch Bob's PrekeyBundle
        Relay->>Alice: PrekeyBundle (IK_B, SPK, PQ-SPK, OPK, PQ-OPK)

        Note over Alice: PQXDH Key Agreement
        Alice->>Alice: Generate EphemeralKey (X25519)
        Alice->>Alice: DH1 = X25519(IK_A, SPK_B)
        Alice->>Alice: DH2 = X25519(EK_A, IK_B)
        Alice->>Alice: DH3 = X25519(EK_A, SPK_B)
        Alice->>Alice: DH4 = X25519(EK_A, OPK_B) [required]
        Alice->>Alice: KEM1 = ML-KEM.Encaps(PQ-SPK_B)
        Alice->>Alice: KEM2 = ML-KEM.Encaps(PQ-OPK_B) [if available]
        Alice->>Alice: IKM = DH1 || DH2 || DH3 || DH4 || KEM1 || KEM2
        Alice->>Alice: SK = HKDF-SHA-512(IKM, domain="veil-pqxdh-v1")

        Alice->>Relay: InitiatorMessage (IK_A, EK_A, CT1, CT2, first_msg)
        Relay->>Bob: InitiatorMessage

        Note over Bob: Derive Same SK
        Bob->>Bob: DH1..DH4 (mirror)
        Bob->>Bob: KEM1 = ML-KEM.Decaps(SK_PQ-SPK, CT1)
        Bob->>Bob: KEM2 = ML-KEM.Decaps(SK_PQ-OPK, CT2)
        Bob->>Bob: SK = HKDF-SHA-512(IKM, domain="veil-pqxdh-v1")
        Bob->>Bob: Decrypt first_msg with SK

        Note over Alice,Bob: Triple Ratchet Session Established
    """

    // MARK: - Triple Ratchet State Machine

    /// Triple Ratchet composition and state transitions.
    ///
    /// Security properties illustrated:
    /// - Forward secrecy (symmetric chain ratchet)
    /// - Post-compromise security (DH ratchet)
    /// - Post-quantum PCS (SPQR ratchet)
    public static let tripleRatchetStateMachine = """
    stateDiagram-v2
        [*] --> Initialized: PQXDH complete (SK derived)

        state "Triple Ratchet Active" as Active {
            state "Symmetric Chain" as Sym {
                [*] --> Sending
                Sending --> Receiving: Direction change
                Receiving --> Sending: Direction change
                Sending --> Sending: KDF chain step (msg key + chain key)
                Receiving --> Receiving: KDF chain step
            }

            state "DH Ratchet" as DH {
                [*] --> WaitingForReply
                WaitingForReply --> NewDHStep: Receive peer DH key
                NewDHStep --> WaitingForReply: Generate new DH pair
                Note right of NewDHStep: Post-compromise security\\nNew root key derived
            }

            state "SPQR Ratchet" as SPQR {
                [*] --> Idle
                Idle --> Scheduling: Trigger (75 msgs OR 24h)
                Scheduling --> SendingFragments: Begin epoch
                SendingFragments --> Collecting: Fragments sent
                Collecting --> Assembling: All fragments received
                Assembling --> Rekeying: ML-KEM-1024 complete
                Rekeying --> Idle: New PQ root key derived
            }

            Sym --> DH: Direction change triggers DH step
            DH --> SPQR: Message count/time triggers PQ step
            SPQR --> Sym: New root key feeds chain
        }

        Initialized --> Active: Begin messaging
        Active --> [*]: Session terminated
    """

    // MARK: - SPQR Lifecycle

    /// The 6-phase SPQR fragment exchange.
    ///
    /// Security properties illustrated:
    /// - Post-quantum post-compromise security
    /// - Fragmented key exchange (amortized bandwidth)
    public static let spqrLifecycle = """
    sequenceDiagram
        participant A as Alice (Initiator)
        participant B as Bob (Responder)

        Note over A,B: SPQR Epoch N (triggered at 75 msgs or 24h)

        rect rgb(240, 240, 255)
            Note over A: Phase 1: Schedule
            A->>A: Decide to start PQ ratchet step
        end

        rect rgb(240, 255, 240)
            Note over A,B: Phase 2: Key Generation
            A->>A: Generate ML-KEM-1024 key pair
            A->>A: Fragment public key into 6 pieces
        end

        rect rgb(255, 240, 240)
            Note over A,B: Phase 3: Fragment Distribution
            A->>B: Fragment 1/6 (piggyback on regular message)
            A->>B: Fragment 2/6
            A->>B: Fragment 3/6
            A->>B: Fragment 4/6
            A->>B: Fragment 5/6
            A->>B: Fragment 6/6
        end

        rect rgb(240, 255, 255)
            Note over B: Phase 4: Assembly
            B->>B: Reassemble ML-KEM public key from fragments
            B->>B: Verify key integrity (hash check)
        end

        rect rgb(255, 255, 240)
            Note over B,A: Phase 5: Encapsulation
            B->>B: ML-KEM.Encaps(pk_A) → (ct, ss)
            B->>B: Fragment ciphertext into 6 pieces
            B->>A: CT Fragment 1/6
            B->>A: CT Fragment 2/6 ... 6/6
        end

        rect rgb(255, 240, 255)
            Note over A: Phase 6: Decapsulation & Rekey
            A->>A: Reassemble ciphertext from fragments
            A->>A: ML-KEM.Decaps(sk, ct) → ss
            A->>A: New root key = HKDF(old_root || ss)
            Note over A,B: Both parties now have PQ-fresh root key
        end
    """

    // MARK: - Payment Flow

    /// Payment state machine with receipt exchange.
    ///
    /// Security properties illustrated:
    /// - Payment privacy (ECDH shared secret)
    /// - Receipt authenticity (Ed25519 signatures)
    /// - Replay protection (nonce tracking)
    public static let paymentFlow = """
    stateDiagram-v2
        [*] --> Idle

        Idle --> ConstructingTx: beginConstruction(context)
        note right of ConstructingTx
            Amount validated (AmountValidator)
            Memo sanitized (MemoSanitizer)
            TXO selection from wallet
        end note

        ConstructingTx --> SubmittingTx: transactionBuilt(envelope)
        note right of SubmittingTx
            ECDH shared secret derived
            (PaymentKeyAgreement)
            Transaction submitted to MobileCoin
        end note

        SubmittingTx --> AwaitingConfirmation: transactionSubmitted()
        note right of AwaitingConfirmation
            Waiting for block confirmation
            (10+ confirmations required)
        end note

        AwaitingConfirmation --> SendingReceipt: transactionConfirmed(tx)
        note right of SendingReceipt
            Receipt signed (ReceiptAuthenticator)
            Nonce generated for replay protection
            Encrypted via Triple Ratchet
        end note

        SendingReceipt --> Complete: receiptSent()

        ConstructingTx --> Failed: fail(reason)
        SubmittingTx --> Failed: fail(reason) [timeout]
        AwaitingConfirmation --> Failed: fail(reason)

        Failed --> Idle: reset() [retry]

        Complete --> [*]
    """

    // MARK: - Message Delivery

    /// End-to-end message flow through sealed sender and relay.
    ///
    /// Security properties illustrated:
    /// - Sealed sender anonymity
    /// - Traffic analysis resistance (exponential padding)
    /// - E2E encryption
    public static let messageDelivery = """
    sequenceDiagram
        participant Alice
        participant AClient as Alice's Client
        participant Relay as Relay Server
        participant BClient as Bob's Client
        participant Bob

        Alice->>AClient: "Hello Bob!"

        Note over AClient: Encryption Pipeline
        AClient->>AClient: 1. Sanitize content
        AClient->>AClient: 2. Triple Ratchet encrypt(plaintext)
        AClient->>AClient: 3. Seal sender identity inside envelope
        AClient->>AClient: 4. Exponential padding (bucket: 512)
        AClient->>AClient: 5. HMAC authenticate padded envelope
        AClient->>AClient: 6. Attach anonymous token + DLEQ proof

        AClient->>Relay: PUT /v1/messages/{bob_reg_id}
        Note over Relay: Relay Processing
        Relay->>Relay: 1. Verify DLEQ token proof
        Relay->>Relay: 2. Check rate limit
        Relay->>Relay: 3. Queue for Bob (FIFO)
        Relay->>Relay: 4. Cannot read sender or content

        Note over BClient: Bob comes online
        BClient->>Relay: GET /v1/messages
        Relay->>BClient: Queued envelopes

        Note over BClient: Decryption Pipeline
        BClient->>BClient: 1. Verify HMAC on padded envelope
        BClient->>BClient: 2. Remove exponential padding
        BClient->>BClient: 3. Unseal sender identity
        BClient->>BClient: 4. Triple Ratchet decrypt(ciphertext)
        BClient->>BClient: 5. Validate content type

        BClient->>Bob: "Hello Bob!" (from Alice)
        BClient->>Relay: ACK message (serverGuid)
    """

    // MARK: - Key Hierarchy

    /// Key derivation tree from identity key to message keys.
    ///
    /// Security properties illustrated:
    /// - Domain separation
    /// - Key hierarchy
    /// - Forward secrecy chain
    public static let keyHierarchy = """
    graph TD
        IK[Identity Key Pair<br/>Ed25519 + ML-DSA-65] --> PQXDH

        subgraph PQXDH [PQXDH Key Agreement]
            DH1[DH1: IK_A × SPK_B]
            DH2[DH2: EK_A × IK_B]
            DH3[DH3: EK_A × SPK_B]
            DH4[DH4: EK_A × OPK_B]
            KEM1[KEM1: ML-KEM<br/>PQ-SPK]
            KEM2[KEM2: ML-KEM<br/>PQ-OPK]
            IKM[IKM = DH1‖DH2‖DH3‖DH4‖KEM1‖KEM2]
            DH1 --> IKM
            DH2 --> IKM
            DH3 --> IKM
            DH4 --> IKM
            KEM1 --> IKM
            KEM2 --> IKM
        end

        IKM --> SK[Session Key SK<br/>HKDF-SHA-512<br/>domain: veil-pqxdh-v1]

        SK --> RK[Root Key]

        subgraph Ratchet [Triple Ratchet]
            RK --> CKs[Sending Chain Key]
            RK --> CKr[Receiving Chain Key]
            CKs --> MK1[Message Key 1<br/>HMAC 0x01]
            CKs --> CKs2[Chain Key 2<br/>HMAC 0x02]
            CKs2 --> MK2[Message Key 2]
            CKs2 --> CKs3[Chain Key 3]

            RK --> DHR[DH Ratchet Step<br/>New X25519 pair]
            DHR --> RK2[New Root Key]

            RK --> SPQR[SPQR Step<br/>ML-KEM-1024]
            SPQR --> RK3[PQ Root Key]
        end

        MK1 --> ENC[AES-256-GCM<br/>Encrypt Message]

        subgraph Payment [Payment Keys]
            PIK[Payment Identity] --> ECDH[X25519 ECDH<br/>Ephemeral × ViewKey]
            ECDH --> PSS[Payment Shared Secret<br/>HKDF-SHA-256<br/>domain: veil-payment-ecdh-v1]
        end

        style IK fill:#f9f,stroke:#333,stroke-width:2px
        style SK fill:#bbf,stroke:#333,stroke-width:2px
        style RK fill:#bfb,stroke:#333,stroke-width:2px
        style ENC fill:#fbb,stroke:#333,stroke-width:2px
        style PSS fill:#fbf,stroke:#333,stroke-width:2px
    """

    // MARK: - Component Overview

    /// High-level system architecture showing all components.
    public static let systemArchitecture = """
    graph TB
        subgraph Client [iOS Client]
            UI[SwiftUI Views]
            VM[ViewModels]
            MP[MessagePipeline<br/>Actor]
            SM[SessionManager<br/>Actor]
            TR[TripleRatchet]
            SS[SealedSender]
            EP[ExponentialPadding]
            RC[RelayClient<br/>Actor]
            MC[MobileCoin<br/>FogClient]
            PSM[PaymentStateMachine<br/>Actor]
            RA[ReceiptAuthenticator]
            AV[AmountValidator]
            MS[MemoSanitizer]
        end

        subgraph Server [Relay Server - Rust]
            API[Axum HTTP API]
            WS[WebSocket Handler]
            TK[Token Verifier<br/>DLEQ Proof]
            RL[Rate Limiter]
            DB[(sled KV Store)]
        end

        subgraph MCN [MobileCoin Network]
            FOG[Fog Service]
            LED[Ledger]
        end

        UI --> VM --> MP
        MP --> SM --> TR
        TR --> SS --> EP --> RC
        RC --> API
        RC --> WS
        API --> TK --> RL --> DB
        MP --> PSM --> MC
        PSM --> RA
        PSM --> AV
        PSM --> MS
        MC --> FOG --> LED

        style TR fill:#bbf,stroke:#333
        style TK fill:#fbb,stroke:#333
        style RA fill:#fbf,stroke:#333
    """
}

// MARK: - Diagram Metadata

/// Metadata about each diagram for documentation generation.
public enum DiagramMetadata: Sendable {
    public struct Entry: Sendable {
        public let name: String
        public let description: String
        public let securityProperties: [AuditScope.SecurityProperty]
        public let diagram: String
    }

    public static let all: [Entry] = [
        Entry(
            name: "PQXDH Key Agreement",
            description: "Full post-quantum extended Diffie-Hellman handshake between Alice and Bob",
            securityProperties: [.forwardSecrecy, .postQuantumSecurity, .keyAgreement],
            diagram: ProtocolDiagrams.pqxdhFlow
        ),
        Entry(
            name: "Triple Ratchet State Machine",
            description: "Composition of symmetric chain, DH, and SPQR ratchets with state transitions",
            securityProperties: [.forwardSecrecy, .postCompromiseSecurity, .postQuantumSecurity],
            diagram: ProtocolDiagrams.tripleRatchetStateMachine
        ),
        Entry(
            name: "SPQR Lifecycle",
            description: "6-phase sparse post-quantum ratchet fragment exchange",
            securityProperties: [.postQuantumSecurity, .postCompromiseSecurity],
            diagram: ProtocolDiagrams.spqrLifecycle
        ),
        Entry(
            name: "Payment Flow",
            description: "Payment state machine from construction through receipt delivery",
            securityProperties: [.paymentPrivacy, .messageAuthenticity, .replayProtection],
            diagram: ProtocolDiagrams.paymentFlow
        ),
        Entry(
            name: "Message Delivery",
            description: "End-to-end message flow through sealed sender and relay",
            securityProperties: [.sealedSenderAnonymity, .trafficAnalysisResistance],
            diagram: ProtocolDiagrams.messageDelivery
        ),
        Entry(
            name: "Key Hierarchy",
            description: "Key derivation tree from identity key to message keys",
            securityProperties: [.domainSeparation, .keyDerivation, .forwardSecrecy],
            diagram: ProtocolDiagrams.keyHierarchy
        ),
        Entry(
            name: "System Architecture",
            description: "High-level component overview showing all actors and data flow",
            securityProperties: [],
            diagram: ProtocolDiagrams.systemArchitecture
        ),
    ]
}
