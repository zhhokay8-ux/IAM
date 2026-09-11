# Deployment

```bash
export ORACLE_PASSWORD=...
export REDIS_PASSWORD=...
mvn -pl iam-authorization-server -am package -DskipTests
docker compose up --build
```

Services: `iam` (8080), `oracle` (127.0.0.1:1521), `redis` (127.0.0.1:6379). Set `IAM_ISSUER` and `IAM_SSO_COOKIE_SECURE` for TLS. Run at least two `iam` replicas behind a load balancer; share Redis and Oracle. JWKS is cached in each replica (1h TTL, 10m refresh).
