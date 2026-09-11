<template>
  <div>
    <div class="page-toolbar">
      <el-input v-model="q" placeholder="Search" style="width: 220px" @keyup.enter="load" />
      <el-button @click="load">Search</el-button>
      <el-button v-if="auth.has(P.RESOURCE_WRITE)" data-testid="create-resource" type="primary" @click="visible = true">Create</el-button>
    </div>
    <el-table :data="page.content">
      <el-table-column prop="resourceCode" label="Code" />
      <el-table-column prop="resourceName" label="Name" />
      <el-table-column prop="audience" label="Audience" />
      <el-table-column prop="status" label="Status" width="120" />
      <el-table-column v-if="auth.has(P.RESOURCE_WRITE)" label="">
        <template #default="{ row }">
          <el-button v-if="row.status === 'ACTIVE'" size="small" @click="adminApi.disableResource(row.resourceCode).then(load)">Disable</el-button>
          <el-button v-else size="small" @click="adminApi.enableResource(row.resourceCode).then(load)">Enable</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-dialog v-model="visible" title="Create Resource">
      <el-form label-width="140px">
        <el-form-item label="code"><el-input v-model="form.resource_code" data-testid="resource-code" /></el-form-item>
        <el-form-item label="name"><el-input v-model="form.resource_name" /></el-form-item>
        <el-form-item label="audience"><el-input v-model="form.audience" /></el-form-item>
      </el-form>
      <template #footer>
        <el-button type="primary" data-testid="submit-resource" @click="create">Save</el-button>
      </template>
    </el-dialog>
  </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { adminApi } from "../api/admin";
import type { PageResponse, Resource } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const q = ref("");
const visible = ref(false);
const page = ref<PageResponse<Resource>>({ content: [], page: 0, size: 20, totalElements: 0 });
const form = reactive({ resource_code: "", resource_name: "", audience: "" });
async function load() { page.value = await adminApi.resources({ q: q.value, page: 0, size: 50 }); }
async function create() {
  await adminApi.createResource({ ...form, owner: "iam" });
  visible.value = false;
  await load();
}
onMounted(load);
</script>
