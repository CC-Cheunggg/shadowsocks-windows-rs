<script setup lang="ts">
import { computed } from "vue";
import { useAppStore } from "@/stores/app";
import AppIcon from "@/components/AppIcon.vue";
import ModeSelector from "@/components/ModeSelector.vue";
import TrafficSparkline from "@/components/TrafficSparkline.vue";

const app = useAppStore();

const connectionTitle = computed(() => {
  const labels = {
    disconnected: "启动 Wintun 数据通路",
    connecting: "正在接管网络流量",
    connected: "DIRECT runtime 正在运行",
    disconnecting: "正在恢复网络状态",
    error: "DIRECT runtime 需要处理",
  };
  return labels[app.connectionState];
});

const modeNotice = computed(() => {
  if (app.mode === "direct") {
    return "全部受支持会话先经 Wintun、session 和 router，再从物理网卡 DIRECT 出站。";
  }
  if (app.mode === "rule") {
    return "DNS 与确认的内网系统代理端点先使用必要 DIRECT；其余流量按顺序规则选择，PROXY 严格失败。";
  }
  return "DNS 与确认的内网系统代理端点保留必要 DIRECT；全局模式的其余普通流量选择 PROXY 并严格失败。";
});

const activePath = computed(() => {
  if (!app.isConnected) return "Wintun 尚未接管";
  if (app.mode === "direct") return "Wintun → Router → DIRECT";
  if (app.mode === "rule") return "Wintun → 有序规则";
  return "Wintun → Router → PROXY（普通流量）";
});

const runtimeBadge = computed(() => {
  const labels = {
    stopped: "STOP",
    starting: "START",
    running: "RUN",
    stopping: "STOP",
    "recovery-required": "FIX",
    failed: "ERR",
  };
  return labels[app.runtime.state];
});

function formatRate(bytes: number) {
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB/s`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB/s`;
}

function formatBytes(bytes: number) {
  if (bytes < 1024 * 1024 * 1024) {
    return `${(bytes / 1024 / 1024).toFixed(0)} MB`;
  }
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}
</script>

<template>
  <section class="overview-grid">
    <article class="connection-card">
      <div class="connection-card__aurora" />
      <div class="connection-card__header">
        <div>
          <span class="card-kicker">连接状态</span>
          <h2>{{ connectionTitle }}</h2>
        </div>
        <span class="privacy-badge">
          <AppIcon name="shield" :size="17" />
          Wintun 接管
        </span>
      </div>

      <div class="connection-card__body">
        <button
          class="connect-button"
          :class="{
            'connect-button--active': app.isConnected,
            'connect-button--busy': app.isTransitioning,
          }"
          type="button"
          :disabled="app.isTransitioning"
          :aria-label="app.isConnected ? '断开连接' : '建立连接'"
          @click="app.toggleConnection"
        >
          <span class="connect-button__inner">
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M12 3v9" />
              <path d="M7.1 5.8a8 8 0 1 0 9.8 0" />
            </svg>
          </span>
        </button>

        <div class="connection-copy">
          <span
            class="state-line"
            :class="{ 'state-line--active': app.isConnected }"
          >
            <i />
            {{
              app.isConnected
                ? activePath
                : "未运行 · 不启用或修改 Windows 系统代理"
            }}
          </span>
          <div class="server-picker">
            <span>
              <small>本轮出站能力</small>
              <strong>{{
                app.mode === "direct" ? "物理网卡 DIRECT" : "PROXY 尚未实现"
              }}</strong>
            </span>
            <span class="server-picker__latency">
              {{ app.mode === "direct" ? "可用" : "FAIL CLOSED" }}
            </span>
          </div>
        </div>
      </div>

      <p
        v-if="app.runtime.lastError"
        class="runtime-error"
        role="alert"
      >
        {{ app.runtime.lastError }}
      </p>
      <p v-else-if="app.previewMode" class="runtime-error runtime-preview">
        浏览器预览：主开关只模拟界面状态，不会创建 Wintun、路由或网络 socket。
      </p>

      <div class="connection-card__footer">
        <ModeSelector
          :model-value="app.mode"
          :disabled="app.isConnected || app.isTransitioning"
          @update:model-value="app.setMode"
        />
        <p>{{ modeNotice }}</p>
      </div>
    </article>

    <article class="health-card surface-card">
      <div class="card-heading">
        <div>
          <span class="card-kicker">网络健康</span>
          <h3>DIRECT runtime</h3>
        </div>
        <span class="score-ring">{{ runtimeBadge }}</span>
      </div>
      <ul class="health-list">
        <li>
          <span
            class="health-icon"
            :class="{ 'health-icon--good': app.runtime.tunAvailable }"
          >
            <AppIcon v-if="app.runtime.tunAvailable" name="check" :size="15" />
            <span v-else class="mini-dot" />
          </span>
          <span><strong>Wintun</strong><small>仅 Windows x86_64 runtime</small></span>
          <em :class="{ muted: !app.runtime.tunAvailable }">{{
            app.runtime.tunAvailable ? "可用" : "不可用"
          }}</em>
        </li>
        <li>
          <span class="health-icon health-icon--good">
            <AppIcon name="check" :size="15" />
          </span>
          <span><strong>捕获 / 注入</strong><small>Wintun packet ring 计数</small></span>
          <em>{{ app.runtime.counters.tunRxPackets }} / {{ app.runtime.counters.tunTxPackets }}</em>
        </li>
        <li>
          <span class="health-icon">
            <span class="mini-dot" />
          </span>
          <span><strong>路由决策</strong><small>DIRECT / PROXY</small></span>
          <em>{{ app.runtime.counters.routeDirect }} / {{ app.runtime.counters.routeProxy }}</em>
        </li>
      </ul>
    </article>

    <article class="traffic-card surface-card">
      <div class="card-heading">
        <div>
          <span class="card-kicker">实时活动</span>
          <h3>{{ app.previewMode ? "预览吞吐" : "安全计数" }}</h3>
        </div>
        <RouterLink :to="{ name: 'traffic' }" class="text-link">
          查看详情
          <AppIcon name="chevron" :size="15" />
        </RouterLink>
      </div>
      <div class="traffic-metrics">
        <div>
          <i class="legend-dot legend-dot--download" />
          <span>{{ app.previewMode ? "下载" : "捕获 TCP" }}</span>
          <strong>{{
            app.previewMode
              ? formatRate(app.latestTraffic.download)
              : app.runtime.counters.capturedTcpSessions
          }}</strong>
        </div>
        <div>
          <i class="legend-dot legend-dot--upload" />
          <span>{{ app.previewMode ? "上传" : "捕获 UDP" }}</span>
          <strong>{{
            app.previewMode
              ? formatRate(app.latestTraffic.upload)
              : app.runtime.counters.capturedUdpDatagrams
          }}</strong>
        </div>
        <div class="traffic-total">
          <span>{{ app.previewMode ? "今日总计" : "丢弃包" }}</span>
          <strong>{{
            app.previewMode
              ? formatBytes(app.uploadTotal + app.downloadTotal)
              : app.runtime.counters.droppedPackets
          }}</strong>
        </div>
      </div>
      <TrafficSparkline :samples="app.traffic" />
    </article>

    <article class="quick-card surface-card">
      <div class="card-heading">
        <div>
          <span class="card-kicker">快速操作</span>
          <h3>常用功能</h3>
        </div>
      </div>
      <div class="quick-grid">
        <RouterLink :to="{ name: 'servers' }">
          <span class="quick-icon quick-icon--blue">
            <AppIcon name="servers" />
          </span>
          <span><strong>管理服务器</strong><small>{{ app.servers.length }}个节点</small></span>
          <AppIcon name="chevron" :size="16" />
        </RouterLink>
        <RouterLink :to="{ name: 'subscriptions' }">
          <span class="quick-icon quick-icon--purple">
            <AppIcon name="subscriptions" />
          </span>
          <span><strong>订阅</strong><small>本轮不实现下载</small></span>
          <AppIcon name="chevron" :size="16" />
        </RouterLink>
        <RouterLink :to="{ name: 'rules' }">
          <span class="quick-icon quick-icon--green">
            <AppIcon name="rules" />
          </span>
          <span><strong>路由规则</strong><small>{{ app.config?.routing.rules.length ?? 0 }} 条有序规则</small></span>
          <AppIcon name="chevron" :size="16" />
        </RouterLink>
      </div>
    </article>
  </section>
</template>
