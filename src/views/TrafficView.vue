<script setup lang="ts">
import TrafficSparkline from "@/components/TrafficSparkline.vue";
import { useAppStore } from "@/stores/app";
const app = useAppStore();
</script>

<template>
  <section class="stack-page">
    <div class="page-intro"><div><h2>流量统计</h2><p>观察实时吞吐、累计用量和服务器分布。</p></div></div>
    <article class="surface-card large-chart-card">
      <div class="card-heading"><div><span class="card-kicker">最近一分钟</span><h3>上下行趋势</h3></div></div>
      <TrafficSparkline :samples="app.traffic" />
    </article>
  </section>
</template>
