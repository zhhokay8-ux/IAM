<template>
  <div>
    <div class="page-toolbar">
      <el-input v-model="operator" placeholder="operator" style="width: 140px" />
      <el-select v-model="eventType" clearable filterable placeholder="event" style="width: 220px">
        <el-option v-for="e in events" :key="e" :label="e" :value="e" />
      </el-select>
      <el-select v-model="success" clearable placeholder="success" style="width: 120px">
        <el-option label="true" :value="'true'" />
        <el-option label="false" :value="'false'" />
      </el-select>
      <el-input v-model="ip" placeholder="ip" style="width: 140px" />
      <el-input v-model="traceId" placeholder="trace_id" style="width: 180px" />
      <el-button data-testid="audit-search" @click="load">Search</el-button>
    </div>
    <el-table :data="page.content" @row-click="open">
      <el-table-column prop="createdAt" label="Time" width="180" />
      <el-table-column prop="eventType" label="Event" />
      <el-table-column prop="operatorName" label="Operator" />
      <el-table-column prop="resourceType" label="Resource" />
      <el-table-column prop="success" label="OK" width="70" />
      <el-table-column prop="sourceIp" label="IP" />
      <el-table-column prop="traceId" label="Trace" />
    </el-table>
    <el-drawer v-model="drawer" title="Audit detail">
      <pre>{{ detailText }}</pre>
    </el-drawer>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { adminApi } from "../api/admin";
import type { AuditRow, PageResponse } from "../api/types";
const operator = ref("");
const eventType = ref("");
const success = ref("");
const ip = ref("");
const traceId = ref("");
const events = ref<string[]>([]);
const page = ref<PageResponse<AuditRow>>({ content: [], page: 0, size: 20, totalElements: 0 });
const drawer = ref(false);
const detail = ref<AuditRow>();
const detailText = computed(() => JSON.stringify(detail.value, null, 2));
async function load() {
  page.value = await adminApi.audit({
    operator: operator.value || undefined,
    event_type: eventType.value || undefined,
    success: success.value || undefined,
    ip: ip.value || undefined,
    trace_id: traceId.value || undefined,
    page: 0,
    size: 20
  });
}
async function open(row: AuditRow) {
  detail.value = await adminApi.auditDetail(row.id);
  drawer.value = true;
}
onMounted(async () => {
  events.value = await adminApi.auditEvents();
  await load();
});
</script>
