<template>
  <div>
    <el-alert type="info" :closable="false" :title="banner" />
    <el-collapse>
      <el-collapse-item v-for="section in snapshot?.sections ?? []" :key="section.name" :title="section.name + (section.dangerous ? ' (dangerous)' : '')">
        <el-table :data="section.items">
          <el-table-column prop="key" label="key" />
          <el-table-column prop="value" label="value" />
          <el-table-column prop="redacted" label="redacted" width="100" />
        </el-table>
      </el-collapse-item>
    </el-collapse>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { adminApi } from "../api/admin";
import type { ConfigSnapshot } from "../api/types";
const snapshot = ref<ConfigSnapshot>();
const banner = computed(() =>
  snapshot.value
    ? `READ_ONLY=${snapshot.value.readOnly} RESTART_REQUIRED=${snapshot.value.restartRequired}. This UI cannot PATCH iam.issuer.`
    : "Loading"
);
onMounted(async () => { snapshot.value = await adminApi.config(); });
</script>
