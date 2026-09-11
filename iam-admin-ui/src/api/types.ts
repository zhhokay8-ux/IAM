export interface PageResponse<T> {
  content: T[];
  page: number;
  size: number;
  totalElements: number;
}

export interface Me {
  subjectId: string;
  username: string;
  tenantId: string;
  authMethod: string;
  roles: string[];
  permissions: string[];
}

export interface Client {
  id: string;
  clientId: string;
  clientName: string;
  clientType: string;
  status: string;
  tokenEndpointAuthMethod: string;
  accessTokenTtl: number;
  refreshTokenTtl: number;
  pkceRequired: boolean;
  owner?: string;
  redirectUris: { redirectUri: string; uriType: string }[];
  createdAt?: string;
  updatedAt?: string;
  client_secret?: string;
}

export interface Resource {
  id: string;
  resourceCode: string;
  resourceName: string;
  audience: string;
  status: string;
  owner?: string;
  createdAt?: string;
}

export interface Scope {
  id: string;
  resourceId: string;
  resourceCode: string;
  scopeCode: string;
  scopeName: string;
  description?: string;
  status: string;
}

export interface Permission {
  id: string;
  clientId: string;
  resourceCode: string;
  audience?: string;
  scopeCode: string;
  grantType: string;
  status: string;
  createdAt?: string;
}

export interface User {
  id: string;
  subjectId: string;
  username: string;
  displayName?: string;
  email?: string;
  status: string;
  tenantId: string;
  orgId?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface IdentityMapping {
  id: string;
  subjectId: string;
  systemCode: string;
  externalUserId: string;
  externalUsername?: string;
  mappingStatus: string;
  createdAt?: string;
}

export interface SessionRow {
  sid: string;
  subjectId: string;
  createdAt: string;
  lastAccessAt: string;
  expiresAt: string;
  authenticationLevel: string;
  clientId: string;
  status: string;
}

export interface RefreshTokenRow {
  id: string;
  userPk: string;
  subjectId: string;
  clientId: string;
  familyId: string;
  issuedAt: string;
  expiresAt: string;
  revokedAt?: string;
  status: string;
  scope?: string;
  audience?: string;
}

export interface AuditRow {
  id: string;
  traceId: string;
  eventType: string;
  subjectId?: string;
  clientId?: string;
  resourceId?: string;
  resourceType?: string;
  sourceIp?: string;
  userAgent?: string;
  result: string;
  success: boolean;
  failureReason?: string;
  detail?: string;
  operatorName?: string;
  tenantId?: string;
  createdAt: string;
}

export interface EmbedPolicy {
  id: string;
  parentClientId: string;
  childClientId: string;
  parentOrigin: string;
  allowedPath: string;
  status: string;
  createdAt?: string;
}

export interface SigningKey {
  kid: string;
  algorithm: string;
  status: string;
  createdAt?: string;
  expiresAt?: string;
  kmsKeyId?: string;
}

export interface Dashboard {
  counts: {
    clientCount: number;
    activeClientCount: number;
    resourceCount: number;
    scopeCount: number;
    userCount: number;
    activeSessionCount: number;
    activeSessionApproximate: boolean;
    activeSessionFromCache: boolean;
    activeRefreshTokenCount: number;
  };
  trends: {
    days: number;
    buckets: { day: string; eventType: string; result: string; count: number }[];
    login: { day: string; count: number }[];
    tokenIssued: { day: string; count: number }[];
    tokenExchange: { day: string; count: number }[];
    failure: { day: string; count: number }[];
  };
  recentAdminOperations: AuditRow[];
}

export interface ConfigSnapshot {
  readOnly: boolean;
  restartRequired: boolean;
  sections: {
    name: string;
    dangerous: boolean;
    items: { key: string; value: string; redacted: boolean; dangerous: boolean; restartRequired: boolean }[];
  }[];
}
