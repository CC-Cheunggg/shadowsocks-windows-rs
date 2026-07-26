<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useRoute } from "vue-router";
import { useAppStore } from "@/stores/app";
import AppIcon from "./AppIcon.vue";
import AppLogo from "./AppLogo.vue";

const app = useAppStore();
const route = useRoute();

const navigation = [
  { label: "概览", name: "overview", icon: "overview" },
  { label: "服务器", name: "servers", icon: "servers" },
  { label: "订阅", name: "subscriptions", icon: "subscriptions" },
  { label: "路由规则", name: "rules", icon: "rules" },
  { label: "连接", name: "connections", icon: "connections" },
  { label: "流量统计", name: "traffic", icon: "traffic" },
  { label: "日志", name: "logs", icon: "logs" },
] as const;

const currentLabel = computed(
  () =>
    navigation.find((item) => item.name === route.name)?.label ??
    (route.name === "settings" ? "设置" : "Shadowsocks"),
);

const runtimeLabel = computed(() => {
  const labels = {
    stopped: "DIRECT 已停止",
    starting: "DIRECT 启动中",
    running: "DIRECT 运行中",
    stopping: "DIRECT 停止中",
    "recovery-required": "需要网络恢复",
    failed: "DIRECT 失败",
  };
  return labels[app.runtime.state];
});

onMounted(async () => {
  await app.initializeConfig();
  await app.initializeRuntime();
});
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <AppLogo />

      <nav class="sidebar__nav" aria-label="主导航">
        <RouterLink
          v-for="item in navigation"
          :key="item.name"
          :to="{ name: item.name }"
          class="nav-item"
        >
          <AppIcon :name="item.icon" />
          <span>{{ item.label }}</span>
        </RouterLink>
      </nav>

      <div class="sidebar__footer">
        <div class="service-chip">
          <span
            class="status-dot"
            :class="{ 'status-dot--active': app.isConnected }"
          />
          <span>{{ runtimeLabel }}</span>
        </div>
        <RouterLink :to="{ name: 'settings' }" class="nav-item">
          <AppIcon name="settings" />
          <span>设置</span>
        </RouterLink>
      </div>
    </aside>

    <main class="main-area">
      <header class="topbar">
        <div>
          <p class="eyebrow">Shadowsocks / {{ currentLabel }}</p>
          <h1>{{ currentLabel }}</h1>
        </div>
        <div class="topbar__actions">
          <div
            class="engine-state"
            :title="`${app.runtime.platform} · ${runtimeLabel}`"
          >
            <span class="engine-state__pulse" />
            <span>核心 {{ app.runtime.version || "…" }}</span>
          </div>
        </div>
      </header>

      <div class="page-container">
        <RouterView />
      </div>
    </main>
  </div>
</template>
