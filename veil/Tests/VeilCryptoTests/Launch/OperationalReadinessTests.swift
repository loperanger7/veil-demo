// VEIL — OperationalReadinessTests.swift
// Ticket: VEIL-1003 — Operational Runbook
//
// Tests validating operational readiness: runbook completeness,
// monitoring metric coverage, alerting rules, SLO definitions,
// and data retention policy compliance.

import XCTest
@testable import VeilCrypto

final class OperationalReadinessTests: XCTestCase {

    // MARK: - Deployment Configuration Tests

    func testDeploymentConfigsExist() {
        XCTAssertGreaterThanOrEqual(RelayRunbook.deployments.count, 2)
    }

    func testStagingAndProductionDefined() {
        let environments = RelayRunbook.deployments.map(\.environment)
        XCTAssertTrue(environments.contains(.staging))
        XCTAssertTrue(environments.contains(.production))
    }

    func testProductionHasMoreReplicas() {
        let staging = RelayRunbook.deployments.first { $0.environment == .staging }
        let production = RelayRunbook.deployments.first { $0.environment == .production }
        XCTAssertNotNil(staging)
        XCTAssertNotNil(production)
        XCTAssertGreaterThan(production!.replicas, staging!.replicas)
    }

    func testProductionHasMoreResources() {
        let production = RelayRunbook.deployments.first { $0.environment == .production }!
        XCTAssertGreaterThan(production.resources.maxConnections, 10000)
    }

    func testHealthCheckConfigured() {
        for deployment in RelayRunbook.deployments {
            XCTAssertEqual(deployment.healthCheck.path, "/health")
            XCTAssertGreaterThan(deployment.healthCheck.port, 0)
            XCTAssertGreaterThan(deployment.healthCheck.failureThreshold, 0)
        }
    }

    // MARK: - Environment Variable Tests

    func testRequiredEnvVarsPresent() {
        let required = RelayRunbook.environmentVariables.filter(\.required)
        XCTAssertGreaterThanOrEqual(required.count, 2, "Must have required environment variables")
    }

    func testSensitiveVarsMarked() {
        let sensitive = RelayRunbook.environmentVariables.filter(\.sensitive)
        XCTAssertGreaterThanOrEqual(sensitive.count, 2, "TLS key and signing key should be sensitive")
    }

    func testTLSConfigRequired() {
        let tlsVars = RelayRunbook.environmentVariables.filter { $0.name.contains("TLS") }
        XCTAssertGreaterThanOrEqual(tlsVars.count, 2)
        for var_ in tlsVars {
            XCTAssertTrue(var_.required, "\(var_.name) should be required")
        }
    }

    func testAllEnvVarsHaveDescriptions() {
        for envVar in RelayRunbook.environmentVariables {
            XCTAssertFalse(envVar.description.isEmpty, "\(envVar.name) missing description")
        }
    }

    // MARK: - Health Endpoint Tests

    func testHealthEndpointsDefined() {
        XCTAssertGreaterThanOrEqual(RelayRunbook.healthEndpoints.count, 3)
    }

    func testHealthEndpointsIncludeRequired() {
        let paths = RelayRunbook.healthEndpoints.map(\.path)
        XCTAssertTrue(paths.contains("/health"), "Must have liveness endpoint")
        XCTAssertTrue(paths.contains("/ready"), "Must have readiness endpoint")
        XCTAssertTrue(paths.contains("/metrics"), "Must have metrics endpoint")
    }

    func testAllEndpointsAreGET() {
        for endpoint in RelayRunbook.healthEndpoints {
            XCTAssertEqual(endpoint.method, "GET")
        }
    }

    // MARK: - Incident Response Tests

    func testSeverityLevelsDefined() {
        XCTAssertEqual(RelayRunbook.severityLevels.count, 5, "Should have 5 severity levels")
    }

    func testSeverityLevelsOrdered() {
        for i in 0..<RelayRunbook.severityLevels.count {
            XCTAssertEqual(RelayRunbook.severityLevels[i].level, i + 1)
        }
    }

    func testAllSeveritiesHaveResponseTimes() {
        for severity in RelayRunbook.severityLevels {
            XCTAssertFalse(severity.responseTime.isEmpty, "Level \(severity.level) missing response time")
        }
    }

    func testAllSeveritiesHaveEscalation() {
        for severity in RelayRunbook.severityLevels {
            XCTAssertFalse(severity.escalation.isEmpty, "Level \(severity.level) missing escalation")
        }
    }

    func testAllSeveritiesHaveExamples() {
        for severity in RelayRunbook.severityLevels {
            XCTAssertGreaterThanOrEqual(
                severity.examples.count, 2,
                "Level \(severity.level) needs at least 2 examples"
            )
        }
    }

    func testResponseStepsOrdered() {
        let steps = RelayRunbook.responseSteps
        XCTAssertGreaterThanOrEqual(steps.count, 7)
        for i in 0..<steps.count {
            XCTAssertEqual(steps[i].order, i + 1)
        }
    }

    func testResponseStepsIncludePostMortem() {
        let phases = RelayRunbook.responseSteps.map(\.phase)
        XCTAssertTrue(phases.contains("Post-mortem"), "Must include post-mortem phase")
    }

    // MARK: - Certificate Rotation Tests

    func testRotationSchedulesDefined() {
        XCTAssertGreaterThanOrEqual(RelayRunbook.rotationSchedules.count, 3)
    }

    func testTLSCertRotation() {
        let tlsCert = RelayRunbook.rotationSchedules.first { $0.asset.contains("TLS") }
        XCTAssertNotNil(tlsCert, "Must have TLS certificate rotation schedule")
        XCTAssertFalse(tlsCert!.procedure.isEmpty)
        XCTAssertFalse(tlsCert!.rollbackProcedure.isEmpty)
    }

    func testSigningKeyRotation() {
        let signingKey = RelayRunbook.rotationSchedules.first { $0.asset.contains("Signing Key") }
        XCTAssertNotNil(signingKey, "Must have signing key rotation schedule")
        XCTAssertTrue(signingKey!.graceWindow.contains("overlap"), "Grace window should allow overlap")
    }

    func testAllRotationsHaveRollback() {
        for schedule in RelayRunbook.rotationSchedules {
            XCTAssertFalse(
                schedule.rollbackProcedure.isEmpty,
                "\(schedule.asset) missing rollback procedure"
            )
        }
    }

    // MARK: - Scaling Guidelines Tests

    func testScalingGuidelinesDefined() {
        XCTAssertGreaterThanOrEqual(RelayRunbook.scalingGuidelines.count, 2)
    }

    func testScalingThresholdsSet() {
        for guideline in RelayRunbook.scalingGuidelines {
            XCTAssertFalse(guideline.scaleUpThreshold.isEmpty)
            XCTAssertFalse(guideline.scaleDownThreshold.isEmpty)
            XCTAssertGreaterThan(guideline.maxReplicas, 1)
        }
    }

    func testDrainingProcedureExists() {
        XCTAssertFalse(RelayRunbook.drainingProcedure.isEmpty)
        XCTAssertTrue(RelayRunbook.drainingProcedure.contains("close frame"))
    }

    // MARK: - Data Retention Tests

    func testRetentionPoliciesDefined() {
        XCTAssertGreaterThanOrEqual(RelayRunbook.retentionPolicies.count, 5)
    }

    func testMessageRetentionMinimal() {
        let messagePolicy = RelayRunbook.retentionPolicies.first {
            $0.dataType.contains("message blob")
        }
        XCTAssertNotNil(messagePolicy)
        XCTAssertTrue(
            messagePolicy!.retentionPeriod.contains("delivery"),
            "Messages should be deleted after delivery"
        )
    }

    func testTokenIssuanceNotLogged() {
        let tokenPolicy = RelayRunbook.retentionPolicies.first {
            $0.dataType.lowercased().contains("token")
        }
        XCTAssertNotNil(tokenPolicy)
        XCTAssertTrue(
            tokenPolicy!.retentionPeriod.contains("0") || tokenPolicy!.retentionPeriod.lowercased().contains("not logged"),
            "Token issuance should not be logged"
        )
    }

    func testConnectionMetadataShortRetention() {
        let connectionPolicy = RelayRunbook.retentionPolicies.first {
            $0.dataType.lowercased().contains("connection") || $0.dataType.lowercased().contains("ip")
        }
        XCTAssertNotNil(connectionPolicy)
        XCTAssertTrue(
            connectionPolicy!.retentionPeriod.contains("24 hours"),
            "Connection metadata should be retained for no more than 24 hours"
        )
    }

    func testAllPoliciesHaveRationale() {
        for policy in RelayRunbook.retentionPolicies {
            XCTAssertFalse(
                policy.rationale.isEmpty,
                "Retention policy for '\(policy.dataType)' missing rationale"
            )
        }
    }

    func testPrivacyComplianceExists() {
        XCTAssertFalse(RelayRunbook.privacyCompliance.isEmpty)
        XCTAssertTrue(RelayRunbook.privacyCompliance.contains("No plaintext message content"))
    }

    // MARK: - Monitoring Metric Tests

    func testMetricsDefined() {
        XCTAssertGreaterThanOrEqual(MonitoringConfig.metrics.count, 15)
    }

    func testAllMetricsFollowNamingConvention() {
        for metric in MonitoringConfig.metrics {
            XCTAssertTrue(
                metric.name.hasPrefix("veil_relay_"),
                "Metric \(metric.name) should start with 'veil_relay_'"
            )
        }
    }

    func testCriticalMetricsPresent() {
        let metricNames = MonitoringConfig.metrics.map(\.name)
        XCTAssertTrue(metricNames.contains("veil_relay_connections_active"))
        XCTAssertTrue(metricNames.contains("veil_relay_messages_delivered_total"))
        XCTAssertTrue(metricNames.contains("veil_relay_message_delivery_latency_seconds"))
        XCTAssertTrue(metricNames.contains("veil_relay_errors_total"))
    }

    func testHistogramsHaveBuckets() {
        let histograms = MonitoringConfig.metrics.filter { $0.type == .histogram }
        for histogram in histograms {
            XCTAssertNotNil(
                histogram.buckets,
                "Histogram \(histogram.name) should have bucket definitions"
            )
            XCTAssertGreaterThan(histogram.buckets?.count ?? 0, 0)
        }
    }

    func testAllMetricsHaveHelp() {
        for metric in MonitoringConfig.metrics {
            XCTAssertFalse(
                metric.help.isEmpty,
                "Metric \(metric.name) missing help text"
            )
        }
    }

    func testMessageSizeBucketsMatchPadding() {
        let sizeMetric = MonitoringConfig.metrics.first {
            $0.name == "veil_relay_message_size_bytes"
        }
        XCTAssertNotNil(sizeMetric)
        let buckets = sizeMetric!.buckets ?? []
        // Should match our exponential padding buckets
        XCTAssertTrue(buckets.contains(256))
        XCTAssertTrue(buckets.contains(65536))
    }

    // MARK: - Alert Rule Tests

    func testAlertRulesDefined() {
        XCTAssertGreaterThanOrEqual(MonitoringConfig.alertRules.count, 8)
    }

    func testCriticalAlertsDefined() {
        let critical = MonitoringConfig.alertRules.filter { $0.severity == .critical }
        XCTAssertGreaterThanOrEqual(critical.count, 2, "Need at least 2 critical alerts")
    }

    func testRelayDownAlertExists() {
        let downAlert = MonitoringConfig.alertRules.first { $0.name == "VeilRelayDown" }
        XCTAssertNotNil(downAlert)
        XCTAssertEqual(downAlert?.severity, .critical)
    }

    func testTLSExpiryAlertExists() {
        let tlsAlert = MonitoringConfig.alertRules.first {
            $0.name.contains("TLSCertExpir")
        }
        XCTAssertNotNil(tlsAlert, "Must have TLS certificate expiry alert")
    }

    func testAllAlertsHaveExpressions() {
        for alert in MonitoringConfig.alertRules {
            XCTAssertFalse(alert.expr.isEmpty, "Alert \(alert.name) missing expression")
            XCTAssertFalse(alert.forDuration.isEmpty, "Alert \(alert.name) missing for duration")
            XCTAssertFalse(alert.summary.isEmpty, "Alert \(alert.name) missing summary")
            XCTAssertFalse(alert.description.isEmpty, "Alert \(alert.name) missing description")
        }
    }

    // MARK: - SLO Tests

    func testSLOsDefined() {
        XCTAssertGreaterThanOrEqual(MonitoringConfig.slos.count, 3)
    }

    func testAvailabilitySLO() {
        let availability = MonitoringConfig.slos.first { $0.name == "Availability" }
        XCTAssertNotNil(availability)
        XCTAssertGreaterThanOrEqual(availability!.target, 99.9, "Availability SLO must be ≥ 99.9%")
    }

    func testLatencySLO() {
        let latencySLO = MonitoringConfig.slos.first { $0.name.contains("Latency") }
        XCTAssertNotNil(latencySLO, "Must have a latency SLO")
    }

    func testAllSLOsHaveErrorBudgets() {
        for slo in MonitoringConfig.slos {
            XCTAssertFalse(
                slo.errorBudget.isEmpty,
                "SLO '\(slo.name)' missing error budget"
            )
        }
    }

    func testAllSLOsHaveMetrics() {
        for slo in MonitoringConfig.slos {
            XCTAssertFalse(
                slo.metric.isEmpty,
                "SLO '\(slo.name)' missing metric definition"
            )
        }
    }

    // MARK: - Dashboard Tests

    func testDashboardPanelsDefined() {
        XCTAssertGreaterThanOrEqual(MonitoringConfig.dashboardPanels.count, 5)
    }

    func testDashboardHasOverviewStats() {
        let singleStats = MonitoringConfig.dashboardPanels.filter { $0.type == .singleStat }
        XCTAssertGreaterThanOrEqual(singleStats.count, 3, "Need overview stat panels")
    }

    func testDashboardHasLatencyGraph() {
        let latencyPanel = MonitoringConfig.dashboardPanels.first {
            $0.title.contains("Latency")
        }
        XCTAssertNotNil(latencyPanel)
        XCTAssertEqual(latencyPanel?.type, .graph)
    }

    func testAllPanelsHaveQueries() {
        for panel in MonitoringConfig.dashboardPanels {
            XCTAssertFalse(
                panel.queries.isEmpty,
                "Panel '\(panel.title)' has no queries"
            )
        }
    }

    func testDashboardMetadata() {
        XCTAssertFalse(MonitoringConfig.dashboardTitle.isEmpty)
        XCTAssertFalse(MonitoringConfig.dashboardUID.isEmpty)
        XCTAssertFalse(MonitoringConfig.refreshInterval.isEmpty)
    }

    // MARK: - Cross-Validation Tests

    func testAlertMetricsExist() {
        let metricNames = MonitoringConfig.metrics.map(\.name)
        for alert in MonitoringConfig.alertRules {
            // Extract metric names from expressions (simplified check)
            let referencedMetrics = metricNames.filter { alert.expr.contains($0) }
            // At least the 'up' metric is a Prometheus built-in
            if !alert.expr.contains("up{") {
                XCTAssertGreaterThan(
                    referencedMetrics.count, 0,
                    "Alert \(alert.name) references metrics not defined in our metric list"
                )
            }
        }
    }

    func testRetentionCoversAllDataTypes() {
        let dataTypes = RelayRunbook.retentionPolicies.map(\.dataType.lowercased())
        XCTAssertTrue(dataTypes.contains(where: { $0.contains("message") }), "Must cover messages")
        XCTAssertTrue(dataTypes.contains(where: { $0.contains("prekey") }), "Must cover prekeys")
        XCTAssertTrue(dataTypes.contains(where: { $0.contains("registration") || $0.contains("phone") }), "Must cover registration data")
        XCTAssertTrue(dataTypes.contains(where: { $0.contains("token") }), "Must cover tokens")
        XCTAssertTrue(dataTypes.contains(where: { $0.contains("metric") }), "Must cover metrics")
    }
}
