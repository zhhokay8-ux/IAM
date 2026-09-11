import { createRouter, createWebHistory, type RouteRecordRaw } from "vue-router";
import { useAuthStore } from "../stores/auth";
import { useTokenMemoryStore } from "../stores/tokenMemory";
import { P } from "../permissions";

const routes: RouteRecordRaw[] = [
  { path: "/login", name: "login", component: () => import("../views/LoginView.vue"), meta: { public: true } },
  {
    path: "/",
    component: () => import("../layouts/AdminLayout.vue"),
    children: [
      { path: "", redirect: "/dashboard" },
      { path: "dashboard", name: "dashboard", component: () => import("../views/DashboardView.vue"), meta: { perm: P.AUDIT_READ, title: "Dashboard" } },
      { path: "clients", name: "clients", component: () => import("../views/ClientsView.vue"), meta: { perm: P.CLIENT_READ, title: "Clients" } },
      { path: "clients/:id", name: "client-detail", component: () => import("../views/ClientDetailView.vue"), meta: { perm: P.CLIENT_READ, title: "Client" } },
      { path: "resources", name: "resources", component: () => import("../views/ResourcesView.vue"), meta: { perm: P.RESOURCE_READ, title: "Resources" } },
      { path: "scopes", name: "scopes", component: () => import("../views/ScopesView.vue"), meta: { perm: P.SCOPE_READ, title: "Scopes" } },
      { path: "permissions", name: "permissions", component: () => import("../views/PermissionsView.vue"), meta: { perm: P.POLICY_READ, title: "Permissions" } },
      { path: "users", name: "users", component: () => import("../views/UsersView.vue"), meta: { perm: P.USER_READ, title: "Users" } },
      { path: "users/:id", name: "user-detail", component: () => import("../views/UserDetailView.vue"), meta: { perm: P.USER_READ, title: "User" } },
      { path: "sessions", name: "sessions", component: () => import("../views/SessionsView.vue"), meta: { perm: P.SESSION_READ, title: "Sessions" } },
      { path: "tokens", name: "tokens", component: () => import("../views/TokensView.vue"), meta: { perm: P.TOKEN_READ, title: "Tokens" } },
      { path: "embed", name: "embed", component: () => import("../views/EmbedView.vue"), meta: { perm: P.EMBED_READ, title: "Embed" } },
      { path: "token-exchange", name: "token-exchange", component: () => import("../views/TokenExchangeView.vue"), meta: { perm: P.POLICY_READ, title: "Token Exchange" } },
      { path: "audit", name: "audit", component: () => import("../views/AuditView.vue"), meta: { perm: P.AUDIT_READ, title: "Audit" } },
      { path: "signing-keys", name: "signing-keys", component: () => import("../views/SigningKeysView.vue"), meta: { perm: P.KEY_READ, title: "Signing Keys" } },
      { path: "config", name: "config", component: () => import("../views/ConfigView.vue"), meta: { perm: P.CONFIG_READ, title: "Config" } }
    ]
  }
];

export const router = createRouter({
  history: createWebHistory("/admin/"),
  routes
});

router.beforeEach(async (to) => {
  useTokenMemoryStore().clear();
  const auth = useAuthStore();
  if (!auth.loaded) {
    await auth.load();
  }
  if (to.meta.public) {
    if (auth.me) {
      return { name: "dashboard" };
    }
    return true;
  }
  if (!auth.me) {
    return { name: "login" };
  }
  const perm = to.meta.perm as string | undefined;
  if (perm && !auth.has(perm)) {
    return { name: "dashboard" };
  }
  return true;
});

window.addEventListener("iam-admin-unauthorized", () => {
  useAuthStore().clear();
  if (router.currentRoute.value.name !== "login") {
    void router.push({ name: "login" });
  }
});
