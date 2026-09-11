<template>
  <div>
    <div class="page-toolbar">
      <el-input v-model="resource" placeholder="resource_code" style="width: 200px" />
      <el-button @click="load">Search</el-button>
      <el-button v-if="auth.has(P.SCOPE_WRITE)" type="primary" @click="visible = true">Create</el-button>
    </div>
    <el-table :data="page.content">
      <el-table-column prop="resourceCode" label="Resource" />
      <el-table-column prop="scopeCode" label="Scope" />
      <el-table-column prop="scopeName" label="Name" />
      <el-table-column prop="status" label="Status" />
      <el-table-column v-if="auth.has(P.SCOPE_WRITE)" label="">
        <template #default="{ row }">
          <el-button v-if="row.status === 'ACTIVE'" size="small" @click="adminApi.disableScope(row.resourceCode, row.scopeCode).then(load)">Disable</el-button>
          <el-button v-else size="small" @click="adminApi.enableScope(row.resourceCode, row.scopeCode).then(load)">Enable</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-dialog v-model="visible" title="Create Scope">
      <el-form label-width="140px">
        <el-form-item label="resource"><el-input v-model="form.resource_code" /></el-form-item>
        <el-form-item label="scope"><el-input v-model="form.scope_code" /></el-form-item>
        <el-form-item label="name"><el-input v-model="form.scope_name" /></el-form-item>
      </el-form>
      <template #footer><el-button type="primary" @click="create">Save</el-button></template>
    </el-dialog>
  </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { adminApi } from "../api/admin";
import type { PageResponse, Scope } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const resource = ref("");
const visible = ref(false);
const page = ref<PageResponse<Scope>>({ content: [], page: 0, size: 20, totalElements: 0 });
const form = reactive({ resource_code: "", scope_code: "", scope_name: "" });
async function load() { page.value = await adminApi.scopes({ resource_code: resource.value || undefined, page: 0, size: 50 }); }
async function create() { await adminApi.createScope(form); visible.value = false; await load(); }
onMounted(load);
</script>
