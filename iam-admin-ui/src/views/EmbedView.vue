<template>
  <div>
    <el-button v-if="auth.has(P.EMBED_WRITE)" type="primary" @click="visible = true">Create policy</el-button>
    <el-table :data="page.content" style="margin-top: 12px">
      <el-table-column prop="parentClientId" label="parent" />
      <el-table-column prop="childClientId" label="child" />
      <el-table-column prop="parentOrigin" label="origin" />
      <el-table-column prop="allowedPath" label="path" />
      <el-table-column prop="status" label="status" />
      <el-table-column v-if="auth.has(P.EMBED_WRITE)" label="">
        <template #default="{ row }">
          <el-button v-if="row.status !== 'ACTIVE'" size="small" @click="adminApi.enableEmbed(row.id).then(load)">Enable</el-button>
          <el-button v-else size="small" @click="adminApi.disableEmbed(row.id).then(load)">Disable</el-button>
        </template>
      </el-table-column>
    </el-table>
    <el-dialog v-model="visible" title="Embed policy">
      <el-form label-width="160px">
        <el-form-item label="parent_client_id"><el-input v-model="form.parent_client_id" /></el-form-item>
        <el-form-item label="child_client_id"><el-input v-model="form.child_client_id" /></el-form-item>
        <el-form-item label="parent_origin"><el-input v-model="form.parent_origin" /></el-form-item>
        <el-form-item label="allowed_path"><el-input v-model="form.allowed_path" /></el-form-item>
      </el-form>
      <template #footer><el-button type="primary" @click="create">Create</el-button></template>
    </el-dialog>
  </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { adminApi } from "../api/admin";
import type { EmbedPolicy, PageResponse } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const visible = ref(false);
const page = ref<PageResponse<EmbedPolicy>>({ content: [], page: 0, size: 20, totalElements: 0 });
const form = reactive({ parent_client_id: "", child_client_id: "", parent_origin: "https://portal.example.com", allowed_path: "/app" });
async function load() { page.value = await adminApi.embedPolicies({ page: 0, size: 50 }); }
async function create() { await adminApi.createEmbed(form); visible.value = false; await load(); }
onMounted(load);
</script>
