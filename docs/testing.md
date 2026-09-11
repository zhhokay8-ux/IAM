# Testing

Unit: `SecurityRegressionTest`, `IamHighAvailabilityTest`, plus module tests from prior phases.

Testcontainers E2E (Oracle + Redis): `SsoIntegrationTest`, `TokenExchangeIntegrationTest`, `ClientCredentialsIntegrationTest`, `EmbedExchangeIntegrationTest`, `MigrationLoginIntegrationTest`. Named Phase 17 classes `PortalLoginE2ETest` … `MigrationE2ETest` index those suites.

JMeter plans in `performance/`: `iam-login.jmx`, `iam-token.jmx`, `iam-jwt-validation.jmx`, `iam-token-exchange.jmx`. Open Aggregate Report for average, P50/P90/P95/P99, TPS, error rate.

`mvn clean verify` requires Docker for authorization-server integration tests.
