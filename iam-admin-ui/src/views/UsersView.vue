<template>
  <div>
    <div class="page-toolbar">
      <el-input v-model="q" placeholder="username" style="width: 200px" @keyup.enter="load" />
      <el-button @click="load">Search</el-button>
      <el-button v-if="auth.has(P.USER_WRITE)" type="primary" @click="visible = true">Create</el-button>
    </div>
    <el-table :data="page.content" @row-click="(row: User) => router.push('/users/' + row.subjectId)">
      <el-table-column prop="username" label="Username" />
      <el-table-column prop="subjectId" label="subject_id" />
      <el-table-column prop="status" label="Status" />
      <el-table-column prop="tenantId" label="Tenant" />
    </el-table>
    <el-dialog v-model="visible" title="Create User">
      <el-form label-width="120px">
        <el-form-item label="username"><el-input v-model="form.username" /></el-form-item>
        <el-form-item label="display"><el-input v-model="form.display_name" /></el-form-item>
        <el-form-item label="email"><el-input v-model="form.email" /></el-form-item>
        <el-form-item label="tenant"><el-input v-model="form.tenant_id" /></el-form-item>
      </el-form>
      <template #footer><el-button type="primary" @click="create">Save</el-button></template>
    </el-dialog>
  </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";
import { adminApi } from "../api/admin";
import type { PageResponse, User } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const router = useRouter();
const q = ref("");
const visible = ref(false);
const page = ref<PageResponse<User>>({ content: [], page: 0, size: 20, totalElements: 0 });
const form = reactive({ username: "", display_name: "", email: "", tenant_id: "admin-cli" });
async function load() { page.value = await adminApi.users({ q: q.value, page: 0, size: 20 }); }
async function create() { await adminApi.createUser(form); visible.value = false; await load(); }
onMounted(load);
</script>
