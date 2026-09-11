<template>
  <div>
    <div class="page-toolbar">
      <el-input v-model="q" placeholder="Search client_id / name" style="width: 240px" @keyup.enter="load" />
      <el-select v-model="status" clearable placeholder="Status" style="width: 140px">
        <el-option label="ACTIVE" value="ACTIVE" />
        <el-option label="INACTIVE" value="INACTIVE" />
      </el-select>
      <el-button @click="load">Search</el-button>
      <el-button v-if="auth.has(P.CLIENT_WRITE)" type="primary" data-testid="create-client" @click="openCreate">Create</el-button>
    </div>
    <el-table :data="page.content" stripe @row-click="(row: Client) => router.push('/clients/' + row.clientId)">
      <el-table-column prop="clientId" label="client_id" />
      <el-table-column prop="clientName" label="Name" />
      <el-table-column prop="status" label="Status" width="120" />
      <el-table-column prop="clientType" label="Type" width="140" />
    </el-table>
    <el-pagination layout="prev, pager, next" :total="page.totalElements" :page-size="20" :current-page="page.page + 1" @current-change="(n: number) => { pageNo = n - 1; load(); }" />

    <el-dialog v-model="createVisible" title="Create Client" width="560">
      <el-form label-width="140px">
        <el-form-item label="client_id"><el-input v-model="form.client_id" data-testid="client-id" /></el-form-item>
        <el-form-item label="name"><el-input v-model="form.client_name" /></el-form-item>
        <el-form-item label="type">
          <el-select v-model="form.client_type"><el-option label="confidential" value="confidential" /><el-option label="public" value="public" /></el-select>
        </el-form-item>
        <el-form-item label="redirect"><el-input v-model="form.redirect" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createVisible = false">Cancel</el-button>
        <el-button type="primary" data-testid="submit-client" @click="create">Create</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="secretVisible" title="Save this secret now" width="640" :close-on-click-modal="false">
      <el-alert type="warning" show-icon :closable="false" title="Client secret is shown once. It is not stored in this browser." />
      <div class="secret-box" data-testid="one-time-secret">{{ oneTimeSecret }}</div>
      <el-checkbox v-model="savedAck" data-testid="secret-ack">我已经安全保存 Secret</el-checkbox>
      <template #footer>
        <el-button type="primary" :disabled="!savedAck" data-testid="secret-done" @click="secretVisible = false">Done</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { adminApi } from "../api/admin";
import type { Client, PageResponse } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";

const auth = useAuthStore();
const router = useRouter();
const q = ref("");
const status = ref("");
const pageNo = ref(0);
const page = ref<PageResponse<Client>>({ content: [], page: 0, size: 20, totalElements: 0 });
const createVisible = ref(false);
const secretVisible = ref(false);
const oneTimeSecret = ref("");
const savedAck = ref(false);
const form = reactive({ client_id: "", client_name: "", client_type: "confidential", redirect: "https://app.example.com/login/callback" });

async function load() {
  page.value = await adminApi.clients({ q: q.value, status: status.value || undefined, page: pageNo.value, size: 20 });
}
function openCreate() {
  createVisible.value = true;
}
async function create() {
  const created = await adminApi.createClient({
    client_id: form.client_id,
    client_name: form.client_name,
    client_type: form.client_type,
    redirect_uris: [{ redirectUri: form.redirect, uriType: "LOGIN_CALLBACK" }]
  });
  oneTimeSecret.value = created.client_secret ?? "";
  savedAck.value = false;
  createVisible.value = false;
  secretVisible.value = Boolean(oneTimeSecret.value);
  await load();
}
onMounted(load);
</script>
