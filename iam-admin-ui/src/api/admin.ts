import { http } from "./http";
import type {
  AuditRow,
  Client,
  ConfigSnapshot,
  Dashboard,
  EmbedPolicy,
  IdentityMapping,
  Me,
  PageResponse,
  Permission,
  RefreshTokenRow,
  Resource,
  Scope,
  SessionRow,
  SigningKey,
  User
} from "./types";

export const adminApi = {
  me: () => http.get<Me>("/api/admin/me").then((r) => r.data),
  dashboard: (days = 7) => http.get<Dashboard>("/api/admin/dashboard", { params: { days } }).then((r) => r.data),
  config: () => http.get<ConfigSnapshot>("/api/admin/config").then((r) => r.data),

  clients: (params: Record<string, unknown>) =>
    http.get<PageResponse<Client>>("/api/admin/clients", { params }).then((r) => r.data),
  client: (id: string) => http.get<Client>(`/api/admin/clients/${id}`).then((r) => r.data),
  createClient: (body: Record<string, unknown>) =>
    http.post<{ client: Client; client_secret?: string }>("/api/admin/clients", body).then((r) => r.data),
  updateClient: (id: string, body: Record<string, unknown>) =>
    http.put<Client>(`/api/admin/clients/${id}`, body).then((r) => r.data),
  disableClient: (id: string) => http.post<Client>(`/api/admin/clients/${id}/disable`).then((r) => r.data),
  enableClient: (id: string) => http.post<Client>(`/api/admin/clients/${id}/enable`).then((r) => r.data),
  rotateSecret: (id: string) =>
    http.post<{ client: Client; client_secret: string }>(`/api/admin/clients/${id}/rotate-secret`).then((r) => r.data),
  clientPermissions: (id: string) =>
    http.get<Permission[]>(`/api/admin/clients/${id}/permissions`).then((r) => r.data),

  resources: (params: Record<string, unknown>) =>
    http.get<PageResponse<Resource>>("/api/admin/resources", { params }).then((r) => r.data),
  createResource: (body: Record<string, unknown>) =>
    http.post<Resource>("/api/admin/resources", body).then((r) => r.data),
  disableResource: (code: string) => http.post<Resource>(`/api/admin/resources/${code}/disable`).then((r) => r.data),
  enableResource: (code: string) => http.post<Resource>(`/api/admin/resources/${code}/enable`).then((r) => r.data),

  scopes: (params: Record<string, unknown>) =>
    http.get<PageResponse<Scope>>("/api/admin/scopes", { params }).then((r) => r.data),
  createScope: (body: Record<string, unknown>) => http.post<Scope>("/api/admin/scopes", body).then((r) => r.data),
  disableScope: (resourceCode: string, scopeCode: string) =>
    http.post<Scope>(`/api/admin/scopes/${resourceCode}/${scopeCode}/disable`).then((r) => r.data),
  enableScope: (resourceCode: string, scopeCode: string) =>
    http.post<Scope>(`/api/admin/scopes/${resourceCode}/${scopeCode}/enable`).then((r) => r.data),

  permissions: (params: Record<string, unknown>) =>
    http.get<PageResponse<Permission>>("/api/admin/permissions", { params }).then((r) => r.data),
  createPermission: (body: Record<string, unknown>) =>
    http.post<Permission>("/api/admin/permissions", body).then((r) => r.data),
  enablePermission: (body: Record<string, unknown>) =>
    http.post<Permission>("/api/admin/permissions/enable", body).then((r) => r.data),
  disablePermission: (body: Record<string, unknown>) =>
    http.post<Permission>("/api/admin/permissions/disable", body).then((r) => r.data),

  users: (params: Record<string, unknown>) =>
    http.get<PageResponse<User>>("/api/admin/users", { params }).then((r) => r.data),
  user: (subjectId: string) => http.get<User>(`/api/admin/users/${subjectId}`).then((r) => r.data),
  createUser: (body: Record<string, unknown>) => http.post<User>("/api/admin/users", body).then((r) => r.data),
  disableUser: (subjectId: string) => http.post<User>(`/api/admin/users/${subjectId}/disable`).then((r) => r.data),
  enableUser: (subjectId: string) => http.post<User>(`/api/admin/users/${subjectId}/enable`).then((r) => r.data),
  mappings: (subjectId: string) =>
    http.get<IdentityMapping[]>(`/api/admin/users/${subjectId}/identity-mappings`).then((r) => r.data),
  createMapping: (subjectId: string, body: Record<string, unknown>) =>
    http.post<IdentityMapping>(`/api/admin/users/${subjectId}/identity-mappings`, body).then((r) => r.data),

  sessions: (subjectId: string) =>
    http.get<PageResponse<SessionRow>>("/api/admin/sessions", { params: { subject_id: subjectId } }).then((r) => r.data),
  revokeSession: (sid: string) => http.post(`/api/admin/sessions/${sid}/revoke`),

  refreshTokens: (subjectId: string) =>
    http
      .get<PageResponse<RefreshTokenRow>>("/api/admin/refresh-tokens", { params: { subject_id: subjectId } })
      .then((r) => r.data),
  revokeRefresh: (id: string) => http.post(`/api/admin/refresh-tokens/${id}/revoke`),
  introspect: (token: string) => http.post("/api/admin/tokens/introspect", { token }).then((r) => r.data),
  revokePresentedToken: (token: string, token_type_hint?: string) =>
    http.post("/api/admin/tokens/revoke", { token, token_type_hint: token_type_hint }),

  embedPolicies: (params: Record<string, unknown>) =>
    http.get<PageResponse<EmbedPolicy>>("/api/admin/embed-policies", { params }).then((r) => r.data),
  createEmbed: (body: Record<string, unknown>) =>
    http.post<EmbedPolicy>("/api/admin/embed-policies", body).then((r) => r.data),
  enableEmbed: (id: string) => http.post<EmbedPolicy>(`/api/admin/embed-policies/${id}/enable`).then((r) => r.data),
  disableEmbed: (id: string) => http.post<EmbedPolicy>(`/api/admin/embed-policies/${id}/disable`).then((r) => r.data),

  tokenExchange: (params: Record<string, unknown>) =>
    http.get<PageResponse<Permission>>("/api/admin/token-exchange/permissions", { params }).then((r) => r.data),
  createTokenExchange: (body: Record<string, unknown>) =>
    http.post<Permission>("/api/admin/token-exchange/permissions", body).then((r) => r.data),
  enableTokenExchange: (body: Record<string, unknown>) =>
    http.post<Permission>("/api/admin/token-exchange/permissions/enable", body).then((r) => r.data),
  disableTokenExchange: (body: Record<string, unknown>) =>
    http.post<Permission>("/api/admin/token-exchange/permissions/disable", body).then((r) => r.data),

  audit: (params: Record<string, unknown>) =>
    http.get<PageResponse<AuditRow>>("/api/admin/audit", { params }).then((r) => r.data),
  auditDetail: (id: string) => http.get<AuditRow>(`/api/admin/audit/${id}`).then((r) => r.data),
  auditEvents: () => http.get<string[]>("/api/admin/audit/events").then((r) => r.data),

  signingKeys: () => http.get<SigningKey[]>("/api/admin/signing-keys").then((r) => r.data),
  rotateSigningKey: () => http.post<SigningKey>("/api/admin/signing-keys/rotate", { confirm: true }).then((r) => r.data),

  logout: () => http.post("/admin/logout")
};
