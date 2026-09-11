<template>
  <el-container class="shell">
    <el-aside :width="collapsed ? '64px' : '220px'" class="aside">
      <div class="brand">{{ collapsed ? "IAM" : "IAM Admin" }}</div>
      <el-menu :default-active="active" router :collapse="collapsed" background-color="#1d1e2c" text-color="#cfd3dc" active-text-color="#ffd04b">
        <el-menu-item v-if="auth.has(P.AUDIT_READ)" index="/dashboard">Dashboard</el-menu-item>
        <el-menu-item v-if="auth.has(P.CLIENT_READ)" index="/clients">Clients</el-menu-item>
        <el-menu-item v-if="auth.has(P.RESOURCE_READ)" index="/resources">Resources</el-menu-item>
        <el-menu-item v-if="auth.has(P.SCOPE_READ)" index="/scopes">Scopes</el-menu-item>
        <el-menu-item v-if="auth.has(P.POLICY_READ)" index="/permissions">Permissions</el-menu-item>
        <el-menu-item v-if="auth.has(P.USER_READ)" index="/users">Users</el-menu-item>
        <el-menu-item v-if="auth.has(P.SESSION_READ)" index="/sessions">Sessions</el-menu-item>
        <el-menu-item v-if="auth.has(P.TOKEN_READ)" index="/tokens">Tokens</el-menu-item>
        <el-menu-item v-if="auth.has(P.EMBED_READ)" index="/embed">Embed</el-menu-item>
        <el-menu-item v-if="auth.has(P.POLICY_READ)" index="/token-exchange">Token Exchange</el-menu-item>
        <el-menu-item v-if="auth.has(P.AUDIT_READ)" index="/audit">Audit</el-menu-item>
        <el-menu-item v-if="auth.has(P.KEY_READ)" index="/signing-keys">Signing Keys</el-menu-item>
        <el-menu-item v-if="auth.has(P.CONFIG_READ)" index="/config">Config</el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="topbar">
        <el-button text @click="collapsed = !collapsed">☰</el-button>
        <el-breadcrumb separator="/">
          <el-breadcrumb-item :to="{ path: '/dashboard' }">Admin</el-breadcrumb-item>
          <el-breadcrumb-item>{{ title }}</el-breadcrumb-item>
        </el-breadcrumb>
        <div class="spacer" />
        <el-dropdown>
          <span class="user" data-testid="user-menu">{{ auth.me?.username }} · {{ auth.roles.join(",") }}</span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item disabled>{{ auth.me?.tenantId }}</el-dropdown-item>
              <el-dropdown-item data-testid="logout" @click="logout">Logout</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main>
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed, ref } from "vue";
import { useRoute, useRouter } from "vue-router";
import { adminApi } from "../api/admin";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";

const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const collapsed = ref(false);
const active = computed(() => route.path);
const title = computed(() => (route.meta.title as string) ?? "Admin");

async function logout() {
  try {
    await adminApi.logout();
  } catch {
    /* still leave */
  }
  auth.clear();
  await router.push({ name: "login" });
}
</script>

<style scoped>
.shell { height: 100%; }
.aside { background: #1d1e2c; color: #fff; overflow: auto; }
.brand { padding: 16px; font-weight: 700; }
.topbar { display: flex; align-items: center; gap: 12px; border-bottom: 1px solid #ebeef5; }
.spacer { flex: 1; }
.user { cursor: pointer; }
@media (max-width: 768px) {
  .aside { width: 64px !important; }
}
</style>
