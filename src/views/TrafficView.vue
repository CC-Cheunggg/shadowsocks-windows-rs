<script setup lang="ts">
import TrafficSparkline from "@/components/TrafficSparkline.vue";
import { useAppStore } from "@/stores/app";
const app = useAppStore();
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div>
        <h2>流量统计</h2>
        <p>
          {{
            app.previewMode
              ? "浏览器预览使用本地示例曲线。"
              : "当前切片只提供数据包级安全计数，不伪造字节吞吐或服务器分布。"
          }}
        </p>
      </div>
    </div>
    <article class="surface-card large-chart-card">
      <div class="card-heading">
        <div>
          <span class="card-kicker">{{ app.previewMode ? "示例" : "Wintun" }}</span>
          <h3>{{ app.previewMode ? "上下行趋势" : "捕获与回程注入" }}</h3>
        </div>
      </div>
      <TrafficSparkline v-if="app.previewMode" :samples="app.traffic" />
      <div v-else class="runtime-counter-grid traffic-runtime-counters">
        <article class="surface-card runtime-counter">
          <span>tun_rx_packets</span>
          <strong>{{ app.runtime.counters.tunRxPackets.toLocaleString() }}</strong>
        </article>
        <article class="surface-card runtime-counter">
          <span>tun_tx_packets</span>
          <strong>{{ app.runtime.counters.tunTxPackets.toLocaleString() }}</strong>
        </article>
        <article class="surface-card runtime-counter">
          <span>direct_tcp_connections</span>
          <strong>{{ app.runtime.counters.directTcpConnections.toLocaleString() }}</strong>
        </article>
        <article class="surface-card runtime-counter">
          <span>direct_udp_associations</span>
          <strong>{{ app.runtime.counters.directUdpAssociations.toLocaleString() }}</strong>
        </article>
      </div>
    </article>
  </section>
</template>
