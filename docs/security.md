# Security

- CORS allowlist only; never `Access-Control-Allow-Origin: *`; credentials cannot combine with `*`.
- Cookie mutating requests require CSRF token + Origin/Referer allowlist.
- CSP `frame-ancestors 'none'` on normal pages; embed pages use configured parent origins. No `X-Frame-Options: ALLOW-FROM`.
- `SensitiveDataMasker` / `TokenLoggingFilter` strip tokens from logs and reject `access_token` in query strings.
- PKCE S256, exact redirect URI match, authorization code and embed/migration tickets are single use.
- `iam-embed.js` forbids `postMessage` wildcard `targetOrigin`.
- High-risk revocation checks fail closed when introspection is unavailable.
