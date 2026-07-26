<script setup lang="ts">
import { useAppStore } from "@/stores/app";

const app = useAppStore();
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div>
        <h2>诊断</h2>
        <p>runtime 不记录 payload、密码、密钥、Cookie、Authorization 或完整 DNS 内容。</p>
      </div>
    </div>
    <article class="log-console surface-card">
      <div>
        <span class="log-time">runtime</span>
        <span class="log-level log-level--info">STATE</span>
        <p>{{ app.runtime.state }}</p>
      </div>
      <div>
        <span class="log-time">router</span>
        <span class="log-level">COUNT</span>
        <p>DIRECT {{ app.runtime.counters.routeDirect }} · PROXY {{ app.runtime.counters.routeProxy }}</p>
      </div>
      <div>
        <span class="log-time">packet</span>
        <span class="log-level">COUNT</span>
        <p>dropped {{ app.runtime.counters.droppedPackets }} · unsupported {{ app.runtime.counters.unsupportedPackets }} · loop {{ app.runtime.counters.loopPreventionDrops }}</p>
      </div>
      <div v-if="app.runtime.lastError">
        <span class="log-time">runtime</span>
        <span class="log-level log-level--warn">ERROR</span>
        <p>{{ app.runtime.lastError }}</p>
      </div>
    </article>
  </section>
</template>
