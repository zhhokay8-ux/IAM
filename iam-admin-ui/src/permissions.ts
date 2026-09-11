export const P = {
  CLIENT_READ: "admin.client.read",
  CLIENT_WRITE: "admin.client.write",
  RESOURCE_READ: "admin.resource.read",
  RESOURCE_WRITE: "admin.resource.write",
  SCOPE_READ: "admin.scope.read",
  SCOPE_WRITE: "admin.scope.write",
  POLICY_READ: "admin.policy.read",
  POLICY_WRITE: "admin.policy.write",
  USER_READ: "admin.user.read",
  USER_WRITE: "admin.user.write",
  TOKEN_READ: "admin.token.read",
  TOKEN_REVOKE: "admin.token.revoke",
  SESSION_READ: "admin.session.read",
  SESSION_REVOKE: "admin.session.revoke",
  EMBED_READ: "admin.embed.read",
  EMBED_WRITE: "admin.embed.write",
  AUDIT_READ: "admin.audit.read",
  KEY_READ: "admin.key.read",
  KEY_ROTATE: "admin.key.rotate",
  CONFIG_READ: "admin.config.read"
} as const;

export type PermissionCode = (typeof P)[keyof typeof P];

export function can(permissions: Iterable<string>, code: string): boolean {
  return new Set(permissions).has(code);
}
