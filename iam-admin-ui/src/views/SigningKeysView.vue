<template>
  <div>
    <el-alert type="warning" :closable="false" title="Private key / KMS credential are never returned by Admin APIs." />
    <el-button v-if="auth.has(P.KEY_ROTATE)" type="danger" data-testid="rotate-key" style="margin: 12px 0" @click="rotate">Rotate</el-button>
    <el-table :data="keys">
      <el-table-column prop="kid" label="kid" />
      <el-table-column prop="algorithm" label="alg" width="100" />
      <el-table-column prop="status" label="status" width="120" />
      <el-table-column prop="createdAt" label="created" />
      <el-table-column prop="expiresAt" label="expires" />
      <el-table-column prop="kmsKeyId" label="kms_key_id" />
    </el-table>
  </div>
</template>
<script setup lang="ts">
import { onMounted, ref } from "vue";
import { ElMessageBox } from "element-plus";
import { adminApi } from "../api/admin";
import type { SigningKey } from "../api/types";
import { P } from "../permissions";
import { useAuthStore } from "../stores/auth";
const auth = useAuthStore();
const keys = ref<SigningKey[]>([]);
async function load() { keys.value = await adminApi.signingKeys(); }
async function rotate() {
  await ElMessageBox.confirm("Rotate signing key? confirm=true will be sent. Overlap keeps VERIFYING keys for old JWT.", "Confirm rotate", { confirmButtonText: "Yes" });
  await adminApi.rotateSigningKey();
  await load();
}
onMounted(load);
</script>
