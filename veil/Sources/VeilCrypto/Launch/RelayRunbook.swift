// VEIL — RelayRunbook.swift
// Ticket: VEIL-1003 — Operational Runbook
//
// Operational procedures for the Veil relay service: deployment,
// monitoring, incident response, certificate rotation, scaling,
// and data retention policies.

import Foundation

// MARK: - Relay Runbook

/// Operational runbook for the Veil relay service.
///
/// The relay service is a Rust WebSocket server that handles message
/// delivery between Veil clients. It processes only sealed-sender
/// encrypted blobs — no plaintext content is ever accessible.
public enum RelayRunbook: Sendable {

    // MARK: - Deployment

    /// Deployment configuration for the relay service.
    public struct DeploymentConfig: Sendable {
        public let environment: Environment
        public let region: String
        public let replicas: Int
        public let resources: ResourceLimits
        public let healthCheck: HealthCheckConfig
    }

    public enum Environment: String, Sendable, CaseIterable {
        case staging = "staging"
        case production = "production"
    }

    public struct ResourceLimits: Sendable {
        public let cpuRequest: String
        public let cpuLimit: String
        public let memoryRequest: String
        public let memoryLimit: String
        public let maxConnections: Int
    }

    public struct HealthCheckConfig: Sendable {
        public let path: String
        public let port: Int
        public let initialDelaySeconds: Int
        public let periodSeconds: Int
        public let timeoutSeconds: Int
        public let failureThreshold: Int
    }

    /// Standard deployment configurations.
    public static let deployments: [DeploymentConfig] = [
        DeploymentConfig(
            environment: .staging,
            region: "us-east-1",
            replicas: 2,
            resources: ResourceLimits(
                cpuRequest: "250m", cpuLimit: "1000m",
                memoryRequest: "256Mi", memoryLimit: "512Mi",
                maxConnections: 5000
            ),
            healthCheck: HealthCheckConfig(
                path: "/health", port: 8080,
                initialDelaySeconds: 5, periodSeconds: 10,
                timeoutSeconds: 3, failureThreshold: 3
            )
        ),
        DeploymentConfig(
            environment: .production,
            region: "us-east-1",
            replicas: 3,
            resources: ResourceLimits(
                cpuRequest: "500m", cpuLimit: "2000m",
                memoryRequest: "512Mi", memoryLimit: "1Gi",
                maxConnections: 50000
            ),
            healthCheck: HealthCheckConfig(
                path: "/health", port: 8080,
                initialDelaySeconds: 10, periodSeconds: 15,
                timeoutSeconds: 5, failureThreshold: 3
            )
        ),
    ]

    /// Required environment variables for the relay service.
    public struct EnvironmentVariable: Sendable {
        public let name: String
        public let description: String
        public let required: Bool
        public let defaultValue: String?
        public let sensitive: Bool
    }

    /// All environment variables.
    public static let environmentVariables: [EnvironmentVariable] = [
        EnvironmentVariable(
            name: "VEIL_RELAY_PORT",
            description: "WebSocket listener port",
            required: false, defaultValue: "8080", sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_RELAY_HOST",
            description: "Bind address",
            required: false, defaultValue: "0.0.0.0", sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_TLS_CERT_PATH",
            description: "Path to TLS certificate file",
            required: true, defaultValue: nil, sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_TLS_KEY_PATH",
            description: "Path to TLS private key file",
            required: true, defaultValue: nil, sensitive: true
        ),
        EnvironmentVariable(
            name: "VEIL_SIGNING_KEY_PATH",
            description: "Path to Ed25519 server signing key",
            required: true, defaultValue: nil, sensitive: true
        ),
        EnvironmentVariable(
            name: "VEIL_MAX_CONNECTIONS",
            description: "Maximum concurrent WebSocket connections",
            required: false, defaultValue: "50000", sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_MESSAGE_TTL_SECONDS",
            description: "Time-to-live for undelivered messages",
            required: false, defaultValue: "604800", sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_METRICS_PORT",
            description: "Prometheus metrics endpoint port",
            required: false, defaultValue: "9090", sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_LOG_LEVEL",
            description: "Logging verbosity (trace, debug, info, warn, error)",
            required: false, defaultValue: "info", sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_RATE_LIMIT_WINDOW",
            description: "Rate limiting window in seconds",
            required: false, defaultValue: "60", sensitive: false
        ),
        EnvironmentVariable(
            name: "VEIL_RATE_LIMIT_MAX",
            description: "Maximum requests per window per IP",
            required: false, defaultValue: "100", sensitive: false
        ),
    ]

    // MARK: - Health Endpoints

    /// Health check endpoint specifications.
    public struct HealthEndpoint: Sendable {
        public let path: String
        public let method: String
        public let description: String
        public let successCode: Int
        public let responseFields: [String]
    }

    /// Health and readiness endpoints.
    public static let healthEndpoints: [HealthEndpoint] = [
        HealthEndpoint(
            path: "/health",
            method: "GET",
            description: "Liveness probe — is the process running and responsive?",
            successCode: 200,
            responseFields: ["status", "uptime_seconds"]
        ),
        HealthEndpoint(
            path: "/ready",
            method: "GET",
            description: "Readiness probe — is the service ready to accept connections?",
            successCode: 200,
            responseFields: ["status", "connections_active", "connections_max", "tls_cert_valid"]
        ),
        HealthEndpoint(
            path: "/metrics",
            method: "GET",
            description: "Prometheus metrics endpoint (internal network only)",
            successCode: 200,
            responseFields: ["prometheus_text_format"]
        ),
    ]

    // MARK: - Incident Response

    /// Incident severity classification.
    public struct IncidentSeverity: Sendable {
        public let level: Int
        public let name: String
        public let description: String
        public let responseTime: String
        public let escalation: String
        public let examples: [String]
    }

    /// Incident severity levels (1 = most severe).
    public static let severityLevels: [IncidentSeverity] = [
        IncidentSeverity(
            level: 1,
            name: "Critical — Service Down",
            description: "Complete service outage affecting all users",
            responseTime: "15 minutes",
            escalation: "All engineers + management notified immediately",
            examples: [
                "All relay instances unreachable",
                "Database corruption preventing message delivery",
                "TLS certificate expired (all connections rejected)",
            ]
        ),
        IncidentSeverity(
            level: 2,
            name: "Major — Degraded Service",
            description: "Significant degradation affecting most users",
            responseTime: "30 minutes",
            escalation: "On-call engineer + team lead notified",
            examples: [
                "Message delivery latency > 5 seconds (p95)",
                "One region completely down (multi-region failover active)",
                "Rate limiting incorrectly blocking legitimate users",
            ]
        ),
        IncidentSeverity(
            level: 3,
            name: "Moderate — Partial Impact",
            description: "Limited degradation affecting some users",
            responseTime: "2 hours",
            escalation: "On-call engineer notified",
            examples: [
                "Elevated error rates (> 1% but < 10%)",
                "Slow WebSocket handshakes for specific client versions",
                "Prekey upload failures for new registrations",
            ]
        ),
        IncidentSeverity(
            level: 4,
            name: "Minor — Low Impact",
            description: "Minimal user impact, operational concern",
            responseTime: "Next business day",
            escalation: "Ticket created for on-call engineer",
            examples: [
                "Monitoring gaps (missing metrics for non-critical path)",
                "Log volume spike from a single misbehaving client",
                "Non-critical dependency deprecation warning",
            ]
        ),
        IncidentSeverity(
            level: 5,
            name: "Informational",
            description: "No current impact, proactive observation",
            responseTime: "Addressed in sprint planning",
            escalation: "No immediate escalation",
            examples: [
                "Approaching connection limit (> 80% capacity)",
                "TLS certificate expiring in < 30 days",
                "Disk usage above 70% threshold",
            ]
        ),
    ]

    /// Incident response procedure steps.
    public struct ResponseStep: Sendable {
        public let order: Int
        public let phase: String
        public let action: String
        public let owner: String
    }

    /// Standard incident response procedure.
    public static let responseSteps: [ResponseStep] = [
        ResponseStep(order: 1, phase: "Detection", action: "Alert triggered by monitoring or user report", owner: "Automated / Support"),
        ResponseStep(order: 2, phase: "Triage", action: "Assign severity level and page appropriate responders", owner: "On-call engineer"),
        ResponseStep(order: 3, phase: "Communication", action: "Update status page and notify stakeholders", owner: "On-call engineer"),
        ResponseStep(order: 4, phase: "Investigation", action: "Identify root cause using logs, metrics, and traces", owner: "Incident commander"),
        ResponseStep(order: 5, phase: "Mitigation", action: "Apply immediate fix (rollback, scaling, failover)", owner: "Incident commander"),
        ResponseStep(order: 6, phase: "Resolution", action: "Deploy permanent fix and verify resolution", owner: "Engineering team"),
        ResponseStep(order: 7, phase: "Post-mortem", action: "Write post-mortem within 48 hours (blameless)", owner: "Incident commander"),
        ResponseStep(order: 8, phase: "Follow-up", action: "Track action items from post-mortem to completion", owner: "Engineering manager"),
    ]

    // MARK: - Certificate Rotation

    /// Certificate and key rotation schedule.
    public struct RotationSchedule: Sendable {
        public let asset: String
        public let rotationPeriod: String
        public let graceWindow: String
        public let procedure: String
        public let rollbackProcedure: String
    }

    /// Rotation schedules for all certificates and keys.
    public static let rotationSchedules: [RotationSchedule] = [
        RotationSchedule(
            asset: "TLS Server Certificate",
            rotationPeriod: "90 days (Let's Encrypt auto-renewal)",
            graceWindow: "30 days before expiry",
            procedure: "Automated via certbot. New cert deployed via rolling restart.",
            rollbackProcedure: "Previous cert retained for 7 days. Manual deploy of backup cert."
        ),
        RotationSchedule(
            asset: "Server Signing Key (Ed25519)",
            rotationPeriod: "365 days",
            graceWindow: "60 days overlap (both old and new key accepted)",
            procedure: "Generate new key pair. Update VEIL_SIGNING_KEY_PATH. Publish new public key to clients via signed config update.",
            rollbackProcedure: "Revert to previous signing key. Issue signed config update with revocation."
        ),
        RotationSchedule(
            asset: "Anonymous Token Issuer Key",
            rotationPeriod: "180 days",
            graceWindow: "30 days overlap",
            procedure: "Generate new issuer key. Update token issuance endpoint. Old tokens remain valid for grace window.",
            rollbackProcedure: "Revert issuer key. Invalidated tokens re-issued on next client connection."
        ),
        RotationSchedule(
            asset: "Certificate Pinning Backup Keys",
            rotationPeriod: "730 days (2 years)",
            graceWindow: "365 days overlap (backup key pre-deployed in client)",
            procedure: "Add new backup key to client via app update before primary rotation.",
            rollbackProcedure: "Activate backup key immediately. Issue emergency app update if needed."
        ),
    ]

    // MARK: - Scaling Guidelines

    /// Horizontal scaling guidelines for the relay service.
    public struct ScalingGuideline: Sendable {
        public let metric: String
        public let scaleUpThreshold: String
        public let scaleDownThreshold: String
        public let cooldownPeriod: String
        public let maxReplicas: Int
    }

    /// Autoscaling guidelines.
    public static let scalingGuidelines: [ScalingGuideline] = [
        ScalingGuideline(
            metric: "Active WebSocket connections per instance",
            scaleUpThreshold: "> 40,000 (80% of 50,000 limit)",
            scaleDownThreshold: "< 15,000 (30% of limit) for 10 minutes",
            cooldownPeriod: "5 minutes",
            maxReplicas: 20
        ),
        ScalingGuideline(
            metric: "CPU utilization",
            scaleUpThreshold: "> 70% sustained for 3 minutes",
            scaleDownThreshold: "< 30% sustained for 10 minutes",
            cooldownPeriod: "3 minutes",
            maxReplicas: 20
        ),
        ScalingGuideline(
            metric: "Message delivery latency (p95)",
            scaleUpThreshold: "> 200ms sustained for 2 minutes",
            scaleDownThreshold: "< 50ms sustained for 15 minutes",
            cooldownPeriod: "5 minutes",
            maxReplicas: 20
        ),
    ]

    /// Connection draining procedure for graceful shutdown.
    public static let drainingProcedure = """
        1. Remove instance from load balancer (stop accepting new connections)
        2. Send WebSocket close frame (code 1001 — Going Away) to all connected clients
        3. Wait up to 30 seconds for clients to disconnect gracefully
        4. Force-close remaining connections after timeout
        5. Flush pending metrics to Prometheus
        6. Terminate process (exit code 0)
        """

    // MARK: - Data Retention

    /// Data retention policies.
    public struct RetentionPolicy: Sendable {
        public let dataType: String
        public let retentionPeriod: String
        public let deletionMethod: String
        public let rationale: String
    }

    /// Data retention policies for the relay service.
    public static let retentionPolicies: [RetentionPolicy] = [
        RetentionPolicy(
            dataType: "Encrypted message blobs",
            retentionPeriod: "Until delivery confirmation, max 7 days",
            deletionMethod: "Immediate deletion from queue after delivery ACK. TTL expiry for undelivered.",
            rationale: "Messages are sealed-sender encrypted. Server cannot read content. Retention minimized to reduce exposure."
        ),
        RetentionPolicy(
            dataType: "Connection metadata (IP, timestamps)",
            retentionPeriod: "24 hours",
            deletionMethod: "Log rotation with secure deletion (shred -u)",
            rationale: "Minimal retention for abuse prevention and rate limiting."
        ),
        RetentionPolicy(
            dataType: "Registration records (hashed phone numbers)",
            retentionPeriod: "Until account deletion",
            deletionMethod: "Cryptographic erasure (delete encryption key wrapping records)",
            rationale: "Required for contact discovery. SHA-256 hashed, not plaintext."
        ),
        RetentionPolicy(
            dataType: "Prekey bundles",
            retentionPeriod: "Until consumed or refreshed by device",
            deletionMethod: "Overwrite with zeros, then delete",
            rationale: "One-time prekeys are consumed on use. Signed prekeys refreshed periodically."
        ),
        RetentionPolicy(
            dataType: "Anonymous token issuance logs",
            retentionPeriod: "0 — not logged",
            deletionMethod: "N/A — tokens are unlinkable by design",
            rationale: "Logging token issuance would defeat anonymity guarantees."
        ),
        RetentionPolicy(
            dataType: "Prometheus metrics",
            retentionPeriod: "90 days",
            deletionMethod: "Automatic TSDB compaction and expiry",
            rationale: "Operational metrics contain no user-identifiable information."
        ),
        RetentionPolicy(
            dataType: "Incident response logs",
            retentionPeriod: "365 days",
            deletionMethod: "Automatic deletion after retention period",
            rationale: "Required for post-mortem analysis and compliance."
        ),
    ]

    /// GDPR/privacy compliance summary.
    public static let privacyCompliance = """
        Data Processing Summary:
        - No plaintext message content is ever processed or stored
        - Phone numbers are SHA-256 hashed before transmission to server
        - IP addresses retained for max 24 hours (abuse prevention only)
        - No behavioral analytics or tracking
        - No data shared with third parties
        - User data deletion: account deletion removes all server-side records
        - Data portability: not applicable (server holds only encrypted blobs)
        """
}
