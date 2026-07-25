<script setup lang="ts">
import { computed } from "vue";
import { useAppStore } from "@/stores/app";
import AppIcon from "@/components/AppIcon.vue";
import ModeSelector from "@/components/ModeSelector.vue";
import TrafficSparkline from "@/components/TrafficSparkline.vue";

const app = useAppStore();

const connectionTitle = computed(() => {
  const labels = {
    disconnected: "点击开启保护",
    connecting: "正在建立安全连接",
    connected: "设备流量已受保护",
    disconnecting: "正在安全断开",
    error: "连接遇到问题",
  };
  return labels[app.connectionState];
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
          TUN防护
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
                ? "已连接 · 所有兼容流量均通过安全隧道"
                : "未连接 · 当前使用系统默认网络"
            }}
          </span>
          <button class="server-picker" type="button">
            <span>
              <small>当前服务器</small>
              <strong>{{ app.selectedServer.name }}</strong>
            </span>
            <span class="server-picker__latency">
              {{ app.selectedServer.id ? "未测试" : "—" }}
            </span>
            <AppIcon name="chevron" :size="17" />
          </button>
        </div>
      </div>

      <div class="connection-card__footer">
        <ModeSelector
          :model-value="app.mode"
          @update:model-value="app.setMode"
        />
        <p>规则模式会根据 GeoSite、GeoIP和用户规则智能分流。</p>
      </div>
    </article>

    <article class="health-card surface-card">
      <div class="card-heading">
        <div>
          <span class="card-kicker">网络健康</span>
          <h3>防泄漏状态</h3>
        </div>
        <span class="score-ring">96</span>
      </div>
      <ul class="health-list">
        <li>
          <span class="health-icon health-icon--good">
            <AppIcon name="check" :size="15" />
          </span>
          <span><strong>IPv4路由</strong><small>接管配置就绪</small></span>
          <em>正常</em>
        </li>
        <li>
          <span class="health-icon health-icon--good">
            <AppIcon name="check" :size="15" />
          </span>
          <span><strong>DNS保护</strong><small>本地解析器</small></span>
          <em>正常</em>
        </li>
        <li>
          <span class="health-icon">
            <span class="mini-dot" />
          </span>
          <span><strong>IPv6</strong><small>等待 Windows服务</small></span>
          <em class="muted">待配置</em>
        </li>
      </ul>
    </article>

    <article class="traffic-card surface-card">
      <div class="card-heading">
        <div>
          <span class="card-kicker">实时活动</span>
          <h3>网络吞吐</h3>
        </div>
        <RouterLink :to="{ name: 'traffic' }" class="text-link">
          查看详情
          <AppIcon name="chevron" :size="15" />
        </RouterLink>
      </div>
      <div class="traffic-metrics">
        <div>
          <i class="legend-dot legend-dot--download" />
          <span>下载</span>
          <strong>{{ formatRate(app.latestTraffic.download) }}</strong>
        </div>
        <div>
          <i class="legend-dot legend-dot--upload" />
          <span>上传</span>
          <strong>{{ formatRate(app.latestTraffic.upload) }}</strong>
        </div>
        <div class="traffic-total">
          <span>今日总计</span>
          <strong>{{
            formatBytes(app.uploadTotal + app.downloadTotal)
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
          <span><strong>更新订阅</strong><small>上次更新 2小时前</small></span>
          <AppIcon name="chevron" :size="16" />
        </RouterLink>
        <RouterLink :to="{ name: 'rules' }">
          <span class="quick-icon quick-icon--green">
            <AppIcon name="rules" />
          </span>
          <span><strong>路由规则</strong><small>规则集已是最新</small></span>
          <AppIcon name="chevron" :size="16" />
        </RouterLink>
      </div>
    </article>
  </section>
</template>
