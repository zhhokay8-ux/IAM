<template>
  <div>
    <p>只管理 <code>grant_type=TOKEN_EXCHANGE</code> 的 Permission，没有第二张策略表。</p>
    <el-table :data="page.content">
      <el-table-column prop="clientId" label="client" />
      <el-table-column prop="resourceCode" label="resource" />
      <el-table-column prop="scopeCode" label="scope" />
      <el-table-column prop="status" label="status" />
      <el-table-column v-if="auth.has(P.POLICY_WRITE)" label="">
        <template #default="{ row }">
          <el-button v-if="row.status !== 'ACTIVE'" size="small" @click="enable(row)">Enable</el-button>
          <el-button v-else size="small" @click="disable(row)">Disable</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-space v-if="auth.has(P.POLICY_WRITE)" style="margin-top: 12px">
      <el-input v-model="form.client_id" placeholder="client_id" />
      <el-input v-model="form.resource_code" placeholder="resource_code" />
      <el-input v-model="form.scope_code" placeholder="scope_code" />
      <el-button @click="create">Create TE permission</el-button>
    </el-space>
  </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { adminApi } from "../api/admin";
import type { PageResponse, Permission } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const page = ref<PageResponse<Permission>>({ content: [], page: 0, size: 20, totalElements: 0 });
const form = reactive({ client_id: "", resource_code: "", scope_code: "", grant_type: "TOKEN_EXCHANGE" });
async function load() { page.value = await adminApi.tokenExchange({ page: 0, size: 50 }); }
function key(row: Permission) {
  return { client_id: row.clientId, resource_code: row.resourceCode, scope_code: row.scopeCode, grant_type: "TOKEN_EXCHANGE" };
}
async function enable(row: Permission) { await adminApi.enableTokenExchange(key(row)); await load(); }
async function disable(row: Permission) { await adminApi.disableTokenExchange(key(row)); await load(); }
async function create() { await adminApi.createTokenExchange(form); await load(); }
onMounted(load);
</script>
