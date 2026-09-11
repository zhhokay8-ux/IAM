<template>
  <div v-if="user">
    <h3>{{ user.username }}</h3>
    <el-descriptions border :column="2">
      <el-descriptions-item label="subject">{{ user.subjectId }}</el-descriptions-item>
      <el-descriptions-item label="status">{{ user.status }}</el-descriptions-item>
      <el-descriptions-item label="email">{{ user.email }}</el-descriptions-item>
      <el-descriptions-item label="tenant">{{ user.tenantId }}</el-descriptions-item>
    </el-descriptions>
    <div class="page-toolbar" style="margin-top: 12px">
      <el-button v-if="auth.has(P.USER_WRITE) && user.status === 'ACTIVE'" data-testid="disable-user" @click="disable">Disable</el-button>
      <el-button v-if="auth.has(P.USER_WRITE) && user.status !== 'ACTIVE'" @click="enable">Enable</el-button>
    </div>
    <h4>Identity mapping</h4>
    <el-table :data="maps">
      <el-table-column prop="systemCode" label="System" />
      <el-table-column prop="externalUserId" label="External id" />
      <el-table-column prop="mappingStatus" label="Status" />
    </el-table>
    <el-space v-if="auth.has(P.USER_WRITE)" style="margin-top: 8px">
      <el-input v-model="mapForm.system_code" placeholder="system_code" />
      <el-input v-model="mapForm.external_user_id" placeholder="external_user_id" />
      <el-button @click="addMap">Add mapping</el-button>
    </el-space>
  </div>
</template>
<script setup lang="ts">
import { onMounted, reactive, ref } from "vue";
import { useRoute } from "vue-router";
import { ElMessageBox } from "element-plus";
import { adminApi } from "../api/admin";
import type { IdentityMapping, User } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const route = useRoute();
const user = ref<User>();
const maps = ref<IdentityMapping[]>([]);
const mapForm = reactive({ system_code: "", external_user_id: "", mapping_status: "ACTIVE" });
const id = () => String(route.params.id);
async function load() {
  user.value = await adminApi.user(id());
  maps.value = await adminApi.mappings(id());
}
async function disable() {
  await ElMessageBox.confirm("Disable user? Sessions and tokens are revoked by runtime.", "Confirm", { confirmButtonText: "Yes" });
  user.value = await adminApi.disableUser(id());
}
async function enable() { user.value = await adminApi.enableUser(id()); }
async function addMap() {
  await adminApi.createMapping(id(), { ...mapForm, subject_id: id() });
  await load();
}
onMounted(load);
</script>
