package com.example.iam.gateway;

/**
 * WAF integration point. Gateway does not implement a WAF; it exposes an ordered no-op
 * hook so an external WAF / sidecar can be wired without changing business services.
 */
public final class WafIntegrationPoint {

    private WafIntegrationPoint() {
    }
}
