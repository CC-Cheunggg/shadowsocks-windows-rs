<script setup lang="ts">
import { computed } from "vue";
import { useAppStore } from "@/stores/app";

const app = useAppStore();

const counters = computed(() => [
  ["tun_rx_packets", app.runtime.counters.tunRxPackets],
  ["tun_tx_packets", app.runtime.counters.tunTxPackets],
  ["captured_tcp_sessions", app.runtime.counters.capturedTcpSessions],
  ["captured_udp_datagrams", app.runtime.counters.capturedUdpDatagrams],
  ["route_direct", app.runtime.counters.routeDirect],
  ["route_proxy", app.runtime.counters.routeProxy],
  ["system_proxy_detected", app.runtime.counters.systemProxyDetected],
  ["route_direct_system_proxy", app.runtime.counters.routeDirectSystemProxy],
  ["direct_tcp_connections", app.runtime.counters.directTcpConnections],
  ["direct_udp_associations", app.runtime.counters.directUdpAssociations],
  ["unsupported_packets", app.runtime.counters.unsupportedPackets],
  ["dropped_packets", app.runtime.counters.droppedPackets],
  ["loop_prevention_drops", app.runtime.counters.loopPreventionDrops],
] as const);
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div>
        <h2>连接</h2>
        <p>仅显示不含 payload、密钥和完整 DNS 内容的 runtime 安全计数。</p>
      </div>
    </div>

    <article class="surface-card runtime-summary">
      <div>
        <span class="card-kicker">运行状态</span>
        <h3>{{ app.runtime.state }}</h3>
      </div>
      <div>
        <span>平台</span>
        <strong>{{ app.runtime.platform }}</strong>
      </div>
      <div>
        <span>Wintun</span>
        <strong>{{ app.runtime.tunAvailable ? "可用" : "不可用" }}</strong>
      </div>
      <div>
        <span>恢复状态</span>
        <strong>{{ app.runtime.recoveryRequired ? "需要恢复" : "无待恢复项" }}</strong>
      </div>
    </article>

    <p v-if="app.runtime.lastError" class="config-error surface-card" role="alert">
      {{ app.runtime.lastError }}
    </p>

    <div class="runtime-counter-grid">
      <article
        v-for="[label, value] in counters"
        :key="label"
        class="surface-card runtime-counter"
      >
        <span>{{ label }}</span>
        <strong>{{ value.toLocaleString() }}</strong>
      </article>
    </div>
  </section>
</template>
