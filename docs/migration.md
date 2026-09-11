# Migration

Dual-run: `iam.enabled` and `iam.migration.mode` = `legacy` | `iam` | `dual`.

Portal verifies `PORTAL_LEGACY_SESSION`, maps identity, `POST /api/migration/ticket`, top-level redirect to `/migration/login?ticket=` only. Ticket TTL 30–60s, one-time, bound to client, subject, browser binding, nonce. Rollback: `iam.enabled=false` restores Legacy login; do not drop legacy tables until IAM is stable.
