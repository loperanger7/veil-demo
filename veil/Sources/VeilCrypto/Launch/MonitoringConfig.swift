// VEIL — MonitoringConfig.swift
// Ticket: VEIL-1003 — Operational Runbook
//
// Prometheus metric definitions, Grafana dashboard structure,
// alerting rules, and SLO definitions for the Veil relay service.

import Foundation

// MARK: - Monitoring Configuration

/// Monitoring and observability configuration for the Veil relay service.
///
/// Defines all Prometheus metrics, alerting rules, and SLO targets.
/// Metric names follow the Prometheus naming conventions:
/// `veil_relay_<subsystem>_<metric>_<unit>`.
public enum MonitoringConfig: Sendable {

    // MARK: - Prometheus Metrics

    /// Prometheus metric types.
    public enum MetricType: String, Sendable {
        case counter = "counter"
        case gauge = "gauge"
        case histogram = "histogram"
        case summary = "summary"
    }

    /// A Prometheus metric definition.
    public struct MetricDefinition: Sendable {
        public let name: String
        public let type: MetricType
        public let help: String
        public let labels: [String]
        public let buckets: [Double]?

        public init(name: String, type: MetricType, help: String,
                    labels: [String] = [], buckets: [Double]? = nil) {
            self.name = name
            self.type = type
            self.help = help
            self.labels = labels
            self.buckets = buckets
        }
    }

    /// All Prometheus metrics exposed by the relay service.
    public static let metrics: [MetricDefinition] = [
        // --- Connection metrics ---
        MetricDefinition(
            name: "veil_relay_connections_active",
            type: .gauge,
            help: "Number of currently active WebSocket connections"
        ),
        MetricDefinition(
            name: "veil_relay_connections_total",
            type: .counter,
            help: "Total number of WebSocket connections since startup",
            labels: ["status"] // "opened", "closed_normal", "closed_error"
        ),
        MetricDefinition(
            name: "veil_relay_connection_duration_seconds",
            type: .histogram,
            help: "Duration of WebSocket connections in seconds",
            buckets: [1, 5, 15, 30, 60, 300, 900, 3600, 86400]
        ),

        // --- Message metrics ---
        MetricDefinition(
            name: "veil_relay_messages_received_total",
            type: .counter,
            help: "Total messages received from clients",
            labels: ["type"] // "sealed_sender", "prekey_message", "receipt"
        ),
        MetricDefinition(
            name: "veil_relay_messages_delivered_total",
            type: .counter,
            help: "Total messages successfully delivered to recipients"
        ),
        MetricDefinition(
            name: "veil_relay_messages_queued",
            type: .gauge,
            help: "Number of messages currently queued for offline recipients"
        ),
        MetricDefinition(
            name: "veil_relay_messages_expired_total",
            type: .counter,
            help: "Total messages expired (TTL exceeded without delivery)"
        ),
        MetricDefinition(
            name: "veil_relay_message_delivery_latency_seconds",
            type: .histogram,
            help: "Time from message receipt to delivery confirmation",
            buckets: [0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0]
        ),
        MetricDefinition(
            name: "veil_relay_message_size_bytes",
            type: .histogram,
            help: "Size of encrypted message envelopes in bytes",
            buckets: [256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]
        ),

        // --- Registration metrics ---
        MetricDefinition(
            name: "veil_relay_registrations_total",
            type: .counter,
            help: "Total device registrations",
            labels: ["status"] // "success", "rate_limited", "error"
        ),
        MetricDefinition(
            name: "veil_relay_prekeys_available",
            type: .gauge,
            help: "Number of one-time prekeys available per device",
            labels: ["device_id_hash"]
        ),
        MetricDefinition(
            name: "veil_relay_prekey_uploads_total",
            type: .counter,
            help: "Total prekey bundle uploads"
        ),

        // --- Token metrics ---
        MetricDefinition(
            name: "veil_relay_tokens_issued_total",
            type: .counter,
            help: "Total anonymous tokens issued"
        ),
        MetricDefinition(
            name: "veil_relay_token_verifications_total",
            type: .counter,
            help: "Total DLEQ token verifications",
            labels: ["result"] // "valid", "invalid", "rate_limited"
        ),

        // --- Rate limiting metrics ---
        MetricDefinition(
            name: "veil_relay_rate_limit_rejections_total",
            type: .counter,
            help: "Total requests rejected by rate limiter",
            labels: ["endpoint"]
        ),
        MetricDefinition(
            name: "veil_relay_rate_limit_tracked_ips",
            type: .gauge,
            help: "Number of IPs currently tracked by rate limiter"
        ),

        // --- System metrics ---
        MetricDefinition(
            name: "veil_relay_uptime_seconds",
            type: .gauge,
            help: "Seconds since the relay process started"
        ),
        MetricDefinition(
            name: "veil_relay_memory_bytes",
            type: .gauge,
            help: "Current memory usage in bytes",
            labels: ["type"] // "resident", "virtual"
        ),
        MetricDefinition(
            name: "veil_relay_tls_cert_expiry_seconds",
            type: .gauge,
            help: "Seconds until TLS certificate expires"
        ),

        // --- Error metrics ---
        MetricDefinition(
            name: "veil_relay_errors_total",
            type: .counter,
            help: "Total errors by category",
            labels: ["category"] // "websocket", "tls", "prekey", "token", "internal"
        ),
    ]

    // MARK: - Alert Rules

    /// Prometheus alert rule.
    public struct AlertRule: Sendable {
        public let name: String
        public let expr: String
        public let forDuration: String
        public let severity: AlertSeverity
        public let summary: String
        public let description: String
    }

    public enum AlertSeverity: String, Sendable {
        case critical = "critical"
        case warning = "warning"
        case info = "info"
    }

    /// All alerting rules.
    public static let alertRules: [AlertRule] = [
        // Critical alerts
        AlertRule(
            name: "VeilRelayDown",
            expr: "up{job=\"veil-relay\"} == 0",
            forDuration: "1m",
            severity: .critical,
            summary: "Veil relay instance is down",
            description: "The relay instance {{ $labels.instance }} has been unreachable for more than 1 minute."
        ),
        AlertRule(
            name: "VeilRelayHighErrorRate",
            expr: "rate(veil_relay_errors_total[5m]) / rate(veil_relay_messages_received_total[5m]) > 0.01",
            forDuration: "5m",
            severity: .critical,
            summary: "Error rate exceeds 1%",
            description: "The relay error rate is {{ $value | humanizePercentage }} over the last 5 minutes."
        ),
        AlertRule(
            name: "VeilRelayTLSCertExpiringSoon",
            expr: "veil_relay_tls_cert_expiry_seconds < 259200",
            forDuration: "1h",
            severity: .critical,
            summary: "TLS certificate expires in less than 3 days",
            description: "TLS certificate on {{ $labels.instance }} expires in {{ $value | humanizeDuration }}."
        ),

        // Warning alerts
        AlertRule(
            name: "VeilRelayHighLatency",
            expr: "histogram_quantile(0.99, rate(veil_relay_message_delivery_latency_seconds_bucket[5m])) > 0.5",
            forDuration: "5m",
            severity: .warning,
            summary: "Message delivery p99 latency exceeds 500ms",
            description: "The p99 message delivery latency is {{ $value }}s over the last 5 minutes."
        ),
        AlertRule(
            name: "VeilRelayHighConnectionCount",
            expr: "veil_relay_connections_active / veil_relay_connections_active_max > 0.8",
            forDuration: "5m",
            severity: .warning,
            summary: "Connection count above 80% of limit",
            description: "Active connections ({{ $value | humanize }}) approaching limit on {{ $labels.instance }}."
        ),
        AlertRule(
            name: "VeilRelayMessageQueueGrowing",
            expr: "delta(veil_relay_messages_queued[15m]) > 10000",
            forDuration: "15m",
            severity: .warning,
            summary: "Message queue growing rapidly",
            description: "Queued messages increased by {{ $value }} in the last 15 minutes."
        ),
        AlertRule(
            name: "VeilRelayHighRateLimitRejections",
            expr: "rate(veil_relay_rate_limit_rejections_total[5m]) > 100",
            forDuration: "5m",
            severity: .warning,
            summary: "High rate of rate-limited requests",
            description: "{{ $value }} requests/sec being rate-limited on endpoint {{ $labels.endpoint }}."
        ),
        AlertRule(
            name: "VeilRelayPrekeyLow",
            expr: "veil_relay_prekeys_available < 10",
            forDuration: "30m",
            severity: .warning,
            summary: "Device has fewer than 10 prekeys remaining",
            description: "Device {{ $labels.device_id_hash }} has only {{ $value }} prekeys left."
        ),

        // Info alerts
        AlertRule(
            name: "VeilRelayHighMemory",
            expr: "veil_relay_memory_bytes{type=\"resident\"} > 800000000",
            forDuration: "10m",
            severity: .info,
            summary: "Memory usage above 800MB",
            description: "Resident memory is {{ $value | humanize1024 }} on {{ $labels.instance }}."
        ),
        AlertRule(
            name: "VeilRelayTLSCertExpiringMonth",
            expr: "veil_relay_tls_cert_expiry_seconds < 2592000",
            forDuration: "1h",
            severity: .info,
            summary: "TLS certificate expires in less than 30 days",
            description: "TLS certificate renew should trigger automatically. Verify certbot is running."
        ),
    ]

    // MARK: - SLO Definitions

    /// Service Level Objective definition.
    public struct SLODefinition: Sendable {
        public let name: String
        public let target: Double
        public let window: String
        public let metric: String
        public let description: String
        public let errorBudget: String
    }

    /// Service Level Objectives for the relay service.
    public static let slos: [SLODefinition] = [
        SLODefinition(
            name: "Availability",
            target: 99.9,
            window: "30 days rolling",
            metric: "1 - (sum(rate(veil_relay_errors_total[30d])) / sum(rate(veil_relay_messages_received_total[30d])))",
            description: "Percentage of messages successfully processed without errors",
            errorBudget: "43.2 minutes of downtime per 30-day window"
        ),
        SLODefinition(
            name: "Delivery Latency (p95)",
            target: 99.0,
            window: "7 days rolling",
            metric: "histogram_quantile(0.95, rate(veil_relay_message_delivery_latency_seconds_bucket[7d])) < 0.2",
            description: "95th percentile message delivery latency under 200ms",
            errorBudget: "100.8 minutes per 7-day window where p95 may exceed 200ms"
        ),
        SLODefinition(
            name: "Delivery Latency (p99)",
            target: 99.0,
            window: "7 days rolling",
            metric: "histogram_quantile(0.99, rate(veil_relay_message_delivery_latency_seconds_bucket[7d])) < 0.5",
            description: "99th percentile message delivery latency under 500ms",
            errorBudget: "100.8 minutes per 7-day window where p99 may exceed 500ms"
        ),
        SLODefinition(
            name: "Message Loss Rate",
            target: 99.99,
            window: "30 days rolling",
            metric: "1 - (rate(veil_relay_messages_expired_total[30d]) / rate(veil_relay_messages_received_total[30d]))",
            description: "Percentage of messages that are eventually delivered (not expired)",
            errorBudget: "4.32 minutes equivalent of lost messages per 30-day window"
        ),
    ]

    // MARK: - Grafana Dashboard

    /// Grafana dashboard panel definition.
    public struct DashboardPanel: Sendable {
        public let title: String
        public let type: PanelType
        public let gridPosition: GridPosition
        public let queries: [String]
    }

    public enum PanelType: String, Sendable {
        case graph = "graph"
        case singleStat = "singlestat"
        case heatmap = "heatmap"
        case table = "table"
    }

    public struct GridPosition: Sendable {
        public let x: Int
        public let y: Int
        public let width: Int
        public let height: Int
    }

    /// Grafana dashboard panel definitions.
    public static let dashboardPanels: [DashboardPanel] = [
        // Row 1: Overview stats
        DashboardPanel(
            title: "Active Connections",
            type: .singleStat,
            gridPosition: GridPosition(x: 0, y: 0, width: 6, height: 4),
            queries: ["veil_relay_connections_active"]
        ),
        DashboardPanel(
            title: "Messages/sec",
            type: .singleStat,
            gridPosition: GridPosition(x: 6, y: 0, width: 6, height: 4),
            queries: ["rate(veil_relay_messages_delivered_total[5m])"]
        ),
        DashboardPanel(
            title: "Error Rate",
            type: .singleStat,
            gridPosition: GridPosition(x: 12, y: 0, width: 6, height: 4),
            queries: ["rate(veil_relay_errors_total[5m]) / rate(veil_relay_messages_received_total[5m]) * 100"]
        ),
        DashboardPanel(
            title: "Queued Messages",
            type: .singleStat,
            gridPosition: GridPosition(x: 18, y: 0, width: 6, height: 4),
            queries: ["veil_relay_messages_queued"]
        ),

        // Row 2: Latency and throughput
        DashboardPanel(
            title: "Message Delivery Latency",
            type: .graph,
            gridPosition: GridPosition(x: 0, y: 4, width: 12, height: 8),
            queries: [
                "histogram_quantile(0.50, rate(veil_relay_message_delivery_latency_seconds_bucket[5m]))",
                "histogram_quantile(0.95, rate(veil_relay_message_delivery_latency_seconds_bucket[5m]))",
                "histogram_quantile(0.99, rate(veil_relay_message_delivery_latency_seconds_bucket[5m]))",
            ]
        ),
        DashboardPanel(
            title: "Connection Lifecycle",
            type: .graph,
            gridPosition: GridPosition(x: 12, y: 4, width: 12, height: 8),
            queries: [
                "veil_relay_connections_active",
                "rate(veil_relay_connections_total{status=\"opened\"}[5m])",
                "rate(veil_relay_connections_total{status=\"closed_error\"}[5m])",
            ]
        ),

        // Row 3: Security metrics
        DashboardPanel(
            title: "Token Verification Results",
            type: .graph,
            gridPosition: GridPosition(x: 0, y: 12, width: 12, height: 8),
            queries: [
                "rate(veil_relay_token_verifications_total{result=\"valid\"}[5m])",
                "rate(veil_relay_token_verifications_total{result=\"invalid\"}[5m])",
                "rate(veil_relay_token_verifications_total{result=\"rate_limited\"}[5m])",
            ]
        ),
        DashboardPanel(
            title: "Rate Limit Rejections",
            type: .graph,
            gridPosition: GridPosition(x: 12, y: 12, width: 12, height: 8),
            queries: ["rate(veil_relay_rate_limit_rejections_total[5m])"]
        ),

        // Row 4: Message size distribution
        DashboardPanel(
            title: "Message Size Distribution",
            type: .heatmap,
            gridPosition: GridPosition(x: 0, y: 20, width: 24, height: 8),
            queries: ["rate(veil_relay_message_size_bytes_bucket[5m])"]
        ),
    ]

    /// Dashboard metadata.
    public static let dashboardTitle = "Veil Relay Service"
    public static let dashboardUID = "veil-relay-overview"
    public static let refreshInterval = "30s"
}
