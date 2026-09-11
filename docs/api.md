# API

| Method | Path | Notes |
|---|---|---|
| GET | `/oauth2/authorize` | Authorization Code + PKCE |
| POST | `/oauth2/token` | code, refresh, client_credentials, token-exchange |
| POST | `/oauth2/introspect` | confidential client |
| POST | `/oauth2/revoke` | access or refresh |
| GET | `/.well-known/jwks.json` | public keys |
| GET | `/.well-known/openid-configuration` | OIDC discovery |
| POST | `/sso/login` | IAM SSO cookie |
| GET | `/sso/session` | current SSO session |
| GET/POST | `/oidc/logout` | local or global logout |
| POST | `/oidc/backchannel-logout` | logout_token |
| POST | `/api/embed/code` | parent issues embed code |
| POST | `/api/embed/exchange` | child redeems embed code |
| POST | `/api/migration/ticket` | confidential client |
| GET | `/migration/login` | one-time ticket → SSO |

Authorization redirect contains `code` and `state` only (never `access_token`).
