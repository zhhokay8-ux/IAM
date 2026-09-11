# Architecture

Stateless Auth Center nodes. SSO session, authorization code, OAuth state, nonce, PKCE state, embed code, and migration ticket live in Redis. Signing keys and refresh-token hashes live in Oracle. Business APIs validate JWT locally with a JWKS cache (TTL 1h, refresh 10m) and do not call IAM on every request.

HA: multiple Auth nodes behind a load balancer; JWKS cache is per-node in memory. If IAM is fully down, already issued JWTs remain valid until expiry. Redis outage breaks login/code/session but not local JWT checks. Introspection/revocation fail closed on high-risk APIs (`JtiValidator` enabled).
