<template>
  <div class="login">
    <el-card class="card">
      <h2>IAM Admin</h2>
      <p>输入用户名和密码建立 SSO Session，再走 BFF Authorization Code + PKCE。浏览器不保存 Access Token。</p>
      <el-form @submit.prevent="startLogin">
        <el-form-item label="用户名">
          <el-input v-model="username" autocomplete="username" data-testid="username" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input
            v-model="password"
            type="password"
            autocomplete="current-password"
            show-password
            data-testid="password"
          />
        </el-form-item>
        <el-form-item label="租户">
          <el-input v-model="tenantId" data-testid="tenant-id" />
        </el-form-item>
        <p v-if="error" class="error">{{ error }}</p>
        <el-button type="primary" native-type="submit" data-testid="sign-in" :loading="loading">Sign in</el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref } from "vue";
import { http } from "../api/http";
import { ApiError, userMessage } from "../api/errors";

const username = ref("");
const password = ref("");
const tenantId = ref("");
const loading = ref(false);
const error = ref("");

async function startLogin() {
  error.value = "";
  const name = username.value.trim();
  const tenant = tenantId.value.trim();
  if (!name || !password.value || !tenant) {
    error.value = "请填写用户名、密码和租户。该用户必须已存在，且已绑定 Admin 角色。";
    return;
  }
  loading.value = true;
  try {
    await http.post("/sso/login", {
      username: name,
      password: password.value,
      tenant_id: tenant,
      client_id: "iam-admin"
    });
    const start = import.meta.env.VITE_BFF_LOGIN_URL ?? "/admin/oauth-login";
    window.location.assign(start);
  } catch (e) {
    loading.value = false;
    error.value = e instanceof ApiError ? userMessage(e) : "登录失败";
  }
}
</script>

<style scoped>
.login { min-height: 100%; display: grid; place-items: center; background: #f4f6fb; }
.card { width: min(420px, 92vw); }
.error { color: #c45656; font-size: 13px; }
</style>
