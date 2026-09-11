<template>
  <div>
    <div class="page-toolbar">
      <el-input v-model="subjectId" placeholder="subject_id (required)" style="width: 360px" />
      <el-button @click="load">Load</el-button>
    </div>
    <el-table :data="page.content">
      <el-table-column prop="sid" label="sid" />
      <el-table-column prop="subjectId" label="subject" />
      <el-table-column prop="clientId" label="client" />
      <el-table-column prop="createdAt" label="created" />
      <el-table-column prop="lastAccessAt" label="last access" />
      <el-table-column prop="expiresAt" label="expires" />
      <el-table-column prop="status" label="status" width="110" />
      <el-table-column v-if="auth.has(P.SESSION_REVOKE)" label="">
        <template #default="{ row }">
          <el-button size="small" data-testid="revoke-session" @click="revoke(row.sid)">Revoke</el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>
<script setup lang="ts">
import { ref } from "vue";
import { ElMessageBox } from "element-plus";
import { adminApi } from "../api/admin";
import type { PageResponse, SessionRow } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const subjectId = ref("");
const page = ref<PageResponse<SessionRow>>({ content: [], page: 0, size: 20, totalElements: 0 });
async function load() {
  if (!subjectId.value) return;
  page.value = await adminApi.sessions(subjectId.value);
}
async function revoke(sid: string) {
  await ElMessageBox.confirm("Revoke this SSO session?", "Confirm", { confirmButtonText: "Yes" });
  await adminApi.revokeSession(sid);
  await load();
}
</script>
