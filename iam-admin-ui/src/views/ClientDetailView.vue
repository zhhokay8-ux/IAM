<template>
  <div v-if="client">
    <h3>{{ client.clientId }}</h3>
    <el-descriptions :column="2" border>
      <el-descriptions-item label="Name">{{ client.clientName }}</el-descriptions-item>
      <el-descriptions-item label="Status">{{ client.status }}</el-descriptions-item>
      <el-descriptions-item label="Type">{{ client.clientType }}</el-descriptions-item>
      <el-descriptions-item label="PKCE">{{ client.pkceRequired }}</el-descriptions-item>
    </el-descriptions>
    <div class="page-toolbar" style="margin-top: 12px">
      <el-button v-if="auth.has(P.CLIENT_WRITE) && client.status === 'ACTIVE'" data-testid="disable-client" @click="disable">Disable</el-button>
      <el-button v-if="auth.has(P.CLIENT_WRITE) && client.status !== 'ACTIVE'" type="success" @click="enable">Enable</el-button>
      <el-button v-if="auth.has(P.CLIENT_WRITE)" data-testid="rotate-secret" @click="rotate">Rotate Secret</el-button>
    </div>
    <el-dialog v-model="secretVisible" title="Save this secret now" :close-on-click-modal="false">
      <el-alert type="warning" :closable="false" title="Shown once. Not written to LocalStorage." />
      <div class="secret-box">{{ secret }}</div>
      <el-checkbox v-model="ack" data-testid="secret-ack">我已经安全保存 Secret</el-checkbox>
      <template #footer>
        <el-button type="primary" :disabled="!ack" @click="secretVisible = false">Done</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from "vue";
import { useRoute } from "vue-router";
import { ElMessageBox } from "element-plus";
import { adminApi } from "../api/admin";
import type { Client } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";

const auth = useAuthStore();
const route = useRoute();
const client = ref<Client>();
const secretVisible = ref(false);
const secret = ref("");
const ack = ref(false);

async function load() {
  client.value = await adminApi.client(String(route.params.id));
}
async function disable() {
  await ElMessageBox.confirm("Disable this client? Runtime authorize will reject it.", "Confirm", { confirmButtonText: "Yes" });
  client.value = await adminApi.disableClient(String(route.params.id));
}
async function enable() {
  client.value = await adminApi.enableClient(String(route.params.id));
}
async function rotate() {
  await ElMessageBox.confirm("Rotate client secret? Old secret stops working immediately.", "Confirm", { confirmButtonText: "Yes" });
  const rotated = await adminApi.rotateSecret(String(route.params.id));
  secret.value = rotated.client_secret;
  ack.value = false;
  secretVisible.value = true;
  client.value = rotated.client;
}
onMounted(load);
</script>
