<script setup lang="ts">
import { computed } from "vue";
import type { DnsSource } from "@/domain/models";
import { useAppStore } from "@/stores/app";

const app = useAppStore();
const networkSettingsLocked = computed(
  () => app.isConnected || app.isTransitioning,
);

const tunIpv6 = computed({
  get: () => app.config?.tun.ipv6 ?? false,
  set: (value: boolean) => {
    if (!app.config) return;
    void app.saveCurrentConfig({
      ...app.config,
      tun: { ...app.config.tun, ipv6: value },
    });
  },
});

const dnsEnabled = computed({
  get: () => app.config?.dns.enabled ?? false,
  set: (value: boolean) => {
    if (!app.config) return;
    void app.saveCurrentConfig({
      ...app.config,
      dns: { ...app.config.dns, enabled: value },
    });
  },
});

const dnsTcpFallback = computed({
  get: () => app.config?.dns.tcp_fallback ?? false,
  set: (value: boolean) => {
    if (!app.config) return;
    void app.saveCurrentConfig({
      ...app.config,
      dns: { ...app.config.dns, tcp_fallback: value },
    });
  },
});

async function updateDnsSource(source: DnsSource) {
  if (!app.config) return;
  await app.saveCurrentConfig({
    ...app.config,
    dns: { ...app.config.dns, source },
  });
}
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div>
        <h2>设置</h2>
        <p>网络配置由 Rust 校验并持久化；runtime 运行期间不可修改。</p>
      </div>
    </div>
    <div v-if="app.configError" class="config-error surface-card" role="alert">
      {{ app.configError }}
    </div>
    <div class="settings-grid">
      <article class="surface-card settings-section">
        <span class="card-kicker">TUN</span><h3>Wintun 接管</h3>
        <div class="setting-row">
          <span><strong>Adapter</strong><small>固定使用应用配置名，不接受 DLL 或系统文件路径</small></span>
          <em>{{ app.config?.tun.interface_name ?? "Shadowsocks" }}</em>
        </div>
        <div class="setting-row">
          <span><strong>MTU</strong><small>当前 packet/session 处理上限</small></span>
          <em>{{ app.config?.tun.mtu ?? 1500 }}</em>
        </div>
        <label class="setting-row">
          <span><strong>IPv6 接管</strong><small>关闭时由 Wintun 捕获后阻断，不绕过接管层</small></span>
          <input v-model="tunIpv6" type="checkbox" :disabled="networkSettingsLocked" />
        </label>
      </article>
      <article class="surface-card settings-section">
        <span class="card-kicker">DNS</span><h3>DIRECT 转发</h3>
        <label class="setting-row">
          <span><strong>捕获 DNS</strong><small>DNS 同样先经过 Wintun；不会记录完整 payload</small></span>
          <input v-model="dnsEnabled" type="checkbox" :disabled="networkSettingsLocked" />
        </label>
        <div class="setting-row">
          <span><strong>上游来源</strong><small>系统配置或受校验的自定义地址</small></span>
          <select
            :value="app.config?.dns.source ?? 'custom'"
            :disabled="networkSettingsLocked"
            @change="updateDnsSource(($event.target as HTMLSelectElement).value as DnsSource)"
          >
            <option value="system">系统 DNS</option>
            <option value="custom">自定义 DNS</option>
          </select>
        </div>
        <label class="setting-row">
          <span><strong>DNS over TCP</strong><small>允许应用或系统主动发起的 TCP DNS；不会因 UDP TC=1 自动合成重试</small></span>
          <input v-model="dnsTcpFallback" type="checkbox" :disabled="networkSettingsLocked" />
        </label>
      </article>
      <article class="surface-card settings-section">
        <span class="card-kicker">兼容与边界</span><h3>不改系统代理</h3>
        <div class="setting-row">
          <span><strong>Windows 系统代理</strong><small>本软件从不启用或修改 Windows 系统代理；已有系统代理可能改变代理感知应用的连接目标，确认的内网系统代理端点会在经过 Wintun 后选择 DIRECT。</small></span>
          <em>只读兼容</em>
        </div>
        <div class="setting-row">
          <span><strong>PROXY outbound</strong><small>rule/global 命中 PROXY 时严格失败，不回退 DIRECT</small></span>
          <em>未实现</em>
        </div>
        <div class="setting-row">
          <span><strong>Kill Switch</strong><small>保留兼容配置，但本轮不实现或启用</small></span>
          <em>未实现</em>
        </div>
      </article>
    </div>
  </section>
</template>
