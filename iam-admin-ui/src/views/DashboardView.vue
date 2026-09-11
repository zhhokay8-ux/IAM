<template>
  <div>
    <el-row :gutter="12">
      <el-col :xs="12" :sm="8" :md="4" v-for="card in cards" :key="card.label">
        <el-card><div class="n">{{ card.value }}</div><div>{{ card.label }}</div></el-card>
      </el-col>
    </el-row>
    <el-card class="chart-card"><div ref="chartEl" class="chart" data-testid="trend-chart" /></el-card>
    <el-table :data="dash?.recentAdminOperations ?? []" stripe>
      <el-table-column prop="createdAt" label="Time" width="180" />
      <el-table-column prop="eventType" label="Event" />
      <el-table-column prop="operatorName" label="Operator" />
      <el-table-column prop="result" label="Result" width="100" />
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import * as echarts from "echarts";
import { adminApi } from "../api/admin";
import type { Dashboard } from "../api/types";

const dash = ref<Dashboard>();
const chartEl = ref<HTMLDivElement>();
let chart: echarts.ECharts | undefined;

const cards = computed(() => [
  { label: "Users", value: dash.value?.counts.userCount ?? 0 },
  { label: "Clients", value: dash.value?.counts.clientCount ?? 0 },
  { label: "Active Clients", value: dash.value?.counts.activeClientCount ?? 0 },
  { label: "Sessions", value: dash.value?.counts.activeSessionCount ?? 0 },
  { label: "Refresh Tokens", value: dash.value?.counts.activeRefreshTokenCount ?? 0 },
  { label: "Resources", value: dash.value?.counts.resourceCount ?? 0 }
]);

function render() {
  if (!chartEl.value || !dash.value) {
    return;
  }
  chart ??= echarts.init(chartEl.value);
  const days = [...new Set([
    ...dash.value.trends.login.map((x) => x.day),
    ...dash.value.trends.tokenIssued.map((x) => x.day),
    ...dash.value.trends.tokenExchange.map((x) => x.day),
    ...dash.value.trends.failure.map((x) => x.day)
  ])].sort();
  const pick = (series: { day: string; count: number }[]) => days.map((d) => series.find((s) => s.day === d)?.count ?? 0);
  chart.setOption({
    tooltip: { trigger: "axis" },
    legend: { data: ["Login", "Token", "Exchange", "Failure"] },
    xAxis: { type: "category", data: days },
    yAxis: { type: "value" },
    series: [
      { name: "Login", type: "line", data: pick(dash.value.trends.login) },
      { name: "Token", type: "line", data: pick(dash.value.trends.tokenIssued) },
      { name: "Exchange", type: "line", data: pick(dash.value.trends.tokenExchange) },
      { name: "Failure", type: "line", data: pick(dash.value.trends.failure) }
    ]
  });
}

onMounted(async () => {
  dash.value = await adminApi.dashboard();
  render();
});
watch(dash, render);
onUnmounted(() => chart?.dispose());
</script>

<style scoped>
.n { font-size: 22px; font-weight: 700; }
.chart-card { margin: 16px 0; }
.chart { height: 320px; }
</style>
