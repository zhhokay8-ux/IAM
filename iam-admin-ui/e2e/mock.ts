import { expect, type Page } from "@playwright/test";

export const adminMe = {
  subjectId: "11111111-1111-1111-1111-111111111111",
  username: "admin",
  tenantId: "admin-cli",
  authMethod: "COOKIE",
  roles: ["IAM_ADMIN"],
  permissions: [
    "admin.client.read",
    "admin.client.write",
    "admin.resource.read",
    "admin.resource.write",
    "admin.scope.read",
    "admin.scope.write",
    "admin.policy.read",
    "admin.policy.write",
    "admin.user.read",
    "admin.user.write",
    "admin.token.read",
    "admin.token.revoke",
    "admin.session.read",
    "admin.session.revoke",
    "admin.embed.read",
    "admin.embed.write",
    "admin.audit.read",
    "admin.key.read",
    "admin.key.rotate",
    "admin.config.read"
  ]
};

export async function mockAdminApi(page: Page) {
  await page.route("**/api/admin/**", async (route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname;
    const method = req.method();

    if (path === "/api/admin/me") {
      return route.fulfill({ json: adminMe });
    }
    if (path === "/api/admin/dashboard") {
      return route.fulfill({
        json: {
          counts: {
            clientCount: 2,
            activeClientCount: 1,
            resourceCount: 1,
            scopeCount: 1,
            userCount: 3,
            activeSessionCount: 1,
            activeSessionApproximate: false,
            activeSessionFromCache: true,
            activeRefreshTokenCount: 1
          },
          trends: {
            days: 7,
            buckets: [],
            login: [{ day: "2026-09-11", count: 2 }],
            tokenIssued: [{ day: "2026-09-11", count: 4 }],
            tokenExchange: [{ day: "2026-09-11", count: 1 }],
            failure: [{ day: "2026-09-11", count: 1 }]
          },
          recentAdminOperations: []
        }
      });
    }
    if (path === "/api/admin/clients" && method === "GET") {
      return route.fulfill({
        json: {
          content: [{ clientId: "portal", clientName: "Portal", status: "ACTIVE", clientType: "confidential" }],
          page: 0,
          size: 20,
          totalElements: 1
        }
      });
    }
    if (path === "/api/admin/clients" && method === "POST") {
      return route.fulfill({
        json: {
          client: { clientId: "new-app", clientName: "New", status: "INACTIVE", clientType: "confidential" },
          client_secret: "one-time-secret"
        }
      });
    }
    if (path === "/api/admin/clients/portal" && method === "GET") {
      return route.fulfill({
        json: { clientId: "portal", clientName: "Portal", status: "ACTIVE", clientType: "confidential", pkceRequired: true }
      });
    }
    if (path.endsWith("/disable") && path.includes("/clients/")) {
      return route.fulfill({ json: { clientId: "portal", clientName: "Portal", status: "INACTIVE" } });
    }
    if (path.endsWith("/rotate-secret")) {
      return route.fulfill({
        json: { client: { clientId: "portal", status: "ACTIVE" }, client_secret: "rotated-secret" }
      });
    }
    if (path === "/api/admin/resources" && method === "GET") {
      return route.fulfill({ json: { content: [], page: 0, size: 20, totalElements: 0 } });
    }
    if (path === "/api/admin/resources" && method === "POST") {
      return route.fulfill({ json: { resourceCode: "RS1", resourceName: "RS", audience: "rs1", status: "INACTIVE" } });
    }
    if (path === "/api/admin/permissions" && method === "GET") {
      return route.fulfill({
        json: {
          content: [
            {
              clientId: "portal",
              resourceCode: "RS1",
              scopeCode: "openid",
              grantType: "AUTHORIZATION_CODE",
              status: "INACTIVE"
            }
          ],
          page: 0,
          size: 100,
          totalElements: 1
        }
      });
    }
    if (path === "/api/admin/permissions/enable") {
      return route.fulfill({
        json: { clientId: "portal", resourceCode: "RS1", scopeCode: "openid", grantType: "AUTHORIZATION_CODE", status: "ACTIVE" }
      });
    }
    if (path.startsWith("/api/admin/users/") && path.endsWith("/disable")) {
      return route.fulfill({ json: { subjectId: adminMe.subjectId, username: "bob", status: "INACTIVE" } });
    }
    if (path.startsWith("/api/admin/users/") && path.endsWith("/identity-mappings")) {
      return route.fulfill({ json: [] });
    }
    if (path.startsWith("/api/admin/users/") && method === "GET") {
      return route.fulfill({
        json: { subjectId: adminMe.subjectId, username: "bob", status: "ACTIVE", tenantId: "admin-cli" }
      });
    }
    if (path === "/api/admin/users") {
      return route.fulfill({
        json: {
          content: [{ subjectId: adminMe.subjectId, username: "bob", status: "ACTIVE", tenantId: "admin-cli" }],
          page: 0,
          size: 20,
          totalElements: 1
        }
      });
    }
    if (path === "/api/admin/sessions" && method === "GET") {
      return route.fulfill({
        json: {
          content: [
            {
              sid: "sid-1",
              subjectId: adminMe.subjectId,
              clientId: "portal",
              createdAt: "2026-09-11T00:00:00Z",
              lastAccessAt: "2026-09-11T00:00:00Z",
              expiresAt: "2026-09-11T08:00:00Z",
              status: "ACTIVE"
            }
          ],
          page: 0,
          size: 20,
          totalElements: 1
        }
      });
    }
    if (path.endsWith("/revoke") && path.includes("/sessions/")) {
      return route.fulfill({ status: 200, body: "" });
    }
    if (path === "/api/admin/tokens/revoke") {
      return route.fulfill({ status: 200, body: "" });
    }
    if (path === "/api/admin/tokens/introspect") {
      return route.fulfill({ json: { active: true, warning: "High-risk token operation." } });
    }
    if (path === "/api/admin/audit/events") {
      return route.fulfill({ json: ["CLIENT_DISABLED", "TOKEN_REVOKED"] });
    }
    if (path === "/api/admin/audit") {
      return route.fulfill({
        json: {
          content: [
            {
              id: "a1",
              eventType: "CLIENT_DISABLED",
              operatorName: "admin",
              success: true,
              traceId: "tr-1",
              createdAt: "2026-09-11T00:00:00Z",
              result: "SUCCESS"
            }
          ],
          page: 0,
          size: 20,
          totalElements: 1
        }
      });
    }
    if (path === "/api/admin/signing-keys" && method === "GET") {
      return route.fulfill({ json: [{ kid: "k1", algorithm: "RS256", status: "ACTIVE" }] });
    }
    if (path === "/api/admin/signing-keys/rotate") {
      const body = req.postDataJSON() as { confirm?: boolean };
      expect(body.confirm).toBe(true);
      return route.fulfill({ json: { kid: "k2", algorithm: "RS256", status: "ACTIVE" } });
    }
    if (path === "/api/admin/config") {
      return route.fulfill({
        json: { readOnly: true, restartRequired: true, sections: [{ name: "issuer", dangerous: true, items: [] }] }
      });
    }
    if (path === "/api/admin/scopes") {
      return route.fulfill({ json: { content: [], page: 0, size: 20, totalElements: 0 } });
    }
    if (path === "/api/admin/embed-policies") {
      return route.fulfill({ json: { content: [], page: 0, size: 20, totalElements: 0 } });
    }
    if (path === "/api/admin/token-exchange/permissions") {
      return route.fulfill({ json: { content: [], page: 0, size: 20, totalElements: 0 } });
    }
    return route.fulfill({ status: 404, json: { code: "IAM-4040", message: path } });
  });
  await page.route("**/admin/logout", (route) => route.fulfill({ status: 200, body: "" }));
}
