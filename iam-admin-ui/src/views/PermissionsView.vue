<template>
  <div>
    <p>矩阵管理 <code>iam_cli_res_perm</code>。隐藏按钮不是安全边界，后端仍校验 <code>admin.policy.write</code>。</p>
    <div class="page-toolbar">
      <el-input v-model="clientId" placeholder="client_id" style="width: 200px" />
      <el-input v-model="resourceCode" placeholder="resource_code" style="width: 200px" />
      <el-button @click="load">Load</el-button>
      <el-button v-if="auth.has(P.POLICY_WRITE)" type="primary" data-testid="save-permissions" @click="save">Save selected</el-button>
    </div>
    <el-table :data="rows" @selection-change="(s: Permission[]) => (selected = s)">
      <el-table-column type="selection" width="48" />
      <el-table-column prop="clientId" label="Client" />
      <el-table-column prop="resourceCode" label="Resource" />
      <el-table-column prop="scopeCode" label="Scope" />
      <el-table-column prop="grantType" label="Grant" />
      <el-table-column prop="status" label="Status" />
      <el-table-column v-if="auth.has(P.POLICY_WRITE)" label="">
        <template #default="{ row }">
          <el-button v-if="row.status !== 'ACTIVE'" size="small" @click="toggle(row, true)">Enable</el-button>
          <el-button v-else size="small" @click="toggle(row, false)">Disable</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-card style="margin-top: 12px" v-if="auth.has(P.POLICY_WRITE)">
      <template #header>Add grant</template>
      <el-space wrap>
        <el-input v-model="add.client_id" placeholder="client_id" />
        <el-input v-model="add.resource_code" placeholder="resource_code" />
        <el-input v-model="add.scope_code" placeholder="scope_code" />
        <el-select v-model="add.grant_type" style="width: 220px">
          <el-option label="AUTHORIZATION_CODE" value="AUTHORIZATION_CODE" />
          <el-option label="CLIENT_CREDENTIALS" value="CLIENT_CREDENTIALS" />
          <el-option label="TOKEN_EXCHANGE" value="TOKEN_EXCHANGE" />
        </el-select>
        <el-button data-testid="add-permission" @click="create">Create (INACTIVE)</el-button>
      </el-space>
    </el-card>
  </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { ElMessageBox } from "element-plus";
import { adminApi } from "../api/admin";
import type { Permission } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const clientId = ref("");
const resourceCode = ref("");
const rows = ref<Permission[]>([]);
const selected = ref<Permission[]>([]);
const add = reactive({ client_id: "", resource_code: "", scope_code: "", grant_type: "AUTHORIZATION_CODE" });
async function load() {
  const page = await adminApi.permissions({
    client_id: clientId.value || undefined,
    resource_code: resourceCode.value || undefined,
    page: 0,
    size: 100
  });
  rows.value = page.content;
}
async function toggle(row: Permission, enable: boolean) {
  const body = { client_id: row.clientId, resource_code: row.resourceCode, scope_code: row.scopeCode, grant_type: row.grantType };
  if (enable) await adminApi.enablePermission(body);
  else await adminApi.disablePermission(body);
  await load();
}
async function save() {
  await ElMessageBox.confirm(`Enable ${selected.value.length} selected permission rows?`, "Confirm matrix change", { confirmButtonText: "Yes" });
  for (const row of selected.value) {
    await adminApi.enablePermission({
      client_id: row.clientId,
      resource_code: row.resourceCode,
      scope_code: row.scopeCode,
      grant_type: row.grantType
    });
  }
  await load();
}
async function create() {
  await adminApi.createPermission({ ...add });
  await load();
}
onMounted(load);
</script>
