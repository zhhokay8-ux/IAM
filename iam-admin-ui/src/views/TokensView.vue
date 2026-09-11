<template>
  <div>
    <el-alert class="warn-banner" type="error" show-icon :closable="false"
      title="Token 是敏感数据。禁止写入 LocalStorage / SessionStorage / IndexedDB / Cookie。结果只在内存中，离开本页即清除。" />
    <el-card>
      <h4>Introspect / Revoke presented token</h4>
      <el-input v-model="token" type="textarea" :rows="3" placeholder="Paste token (memory only)" data-testid="token-input" />
      <div class="page-toolbar" style="margin-top: 8px">
        <el-button data-testid="introspect" @click="introspect">Introspect</el-button>
        <el-button v-if="auth.has(P.TOKEN_REVOKE)" type="danger" data-testid="revoke-token" @click="revoke">Revoke</el-button>
      </div>
      <pre v-if="result" data-testid="introspect-result">{{ resultText }}</pre>
    </el-card>
    <el-card style="margin-top: 12px">
      <h4>Refresh token metadata</h4>
      <el-input v-model="subjectId" placeholder="JWT subject UUID" style="width: 360px" />
      <el-button @click="loadRefresh">Load</el-button>
      <el-table :data="refresh.content">
        <el-table-column prop="id" label="id" />
        <el-table-column prop="status" label="status" />
        <el-table-column prop="expiresAt" label="expires" />
        <el-table-column v-if="auth.has(P.TOKEN_REVOKE)" label="">
          <template #default="{ row }">
            <el-button size="small" @click="adminApi.revokeRefresh(row.id).then(loadRefresh)">Revoke family</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>
<script setup lang="ts">
import { computed, onUnmounted, ref } from "vue";
import { ElMessageBox } from "element-plus";
import { adminApi } from "../api/admin";
import type { PageResponse, RefreshTokenRow } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
import { useTokenMemoryStore } from "../stores/tokenMemory";
const auth = useAuthStore();
const memory = useTokenMemoryStore();
const token = computed({
  get: () => memory.presentedToken,
  set: (v: string) => memory.setPresented(v)
});
const result = computed(() => memory.result);
const resultText = computed(() => JSON.stringify(memory.result, null, 2));
const subjectId = ref("");
const refresh = ref<PageResponse<RefreshTokenRow>>({ content: [], page: 0, size: 20, totalElements: 0 });
async function introspect() {
  memory.setResult(await adminApi.introspect(memory.presentedToken));
  memory.setPresented("");
}
async function revoke() {
  await ElMessageBox.confirm("Revoke the presented token?", "Confirm", { confirmButtonText: "Yes" });
  await adminApi.revokePresentedToken(memory.presentedToken);
  memory.clear();
}
async function loadRefresh() {
  if (!subjectId.value) return;
  refresh.value = await adminApi.refreshTokens(subjectId.value);
}
onUnmounted(() => memory.clear());
</script>
