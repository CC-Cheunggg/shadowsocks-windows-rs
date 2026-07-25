<script setup lang="ts">
import { computed, reactive, ref } from "vue";
import AppIcon from "@/components/AppIcon.vue";
import { useAppStore } from "@/stores/app";

const app = useAppStore();
const query = ref("");
const showForm = ref(false);
const form = reactive({
  name: "",
  host: "",
  port: 8388,
  password: "",
  method: "2022-blake3-aes-256-gcm",
  timeout: 300,
  group: "Personal",
  plugin: "",
  plugin_opts: "",
});

const filteredServers = computed(() => {
  const value = query.value.trim().toLowerCase();
  if (!value) return app.servers;
  return app.servers.filter((server) =>
    [server.name, server.host, server.group, server.method]
      .join(" ")
      .toLowerCase()
      .includes(value),
  );
});

const saving = ref(false);

async function saveServer() {
  if (!form.name.trim() || !form.host.trim() || !form.password) return;
  saving.value = true;
  const saved = await app.addServer({
    name: form.name.trim(),
    host: form.host.trim(),
    port: form.port,
    password: form.password,
    method: form.method,
    timeout: form.timeout,
    group: form.group.trim(),
    plugin: form.plugin.trim() || null,
    plugin_opts: form.plugin_opts.trim() || null,
  });
  saving.value = false;
  if (!saved) return;
  Object.assign(form, {
    name: "",
    host: "",
    port: 8388,
    password: "",
    method: "2022-blake3-aes-256-gcm",
    timeout: 300,
    group: "Personal",
    plugin: "",
    plugin_opts: "",
  });
  showForm.value = false;
}
</script>

<template>
  <section class="stack-page">
    <div class="page-intro">
      <div>
        <h2>服务器</h2>
        <p>管理手动添加和订阅同步的 Shadowsocks节点。</p>
      </div>
      <button class="primary-button" type="button" @click="showForm = true">
        <AppIcon name="plus" :size="18" />
        添加服务器
      </button>
    </div>

    <div v-if="app.previewMode" class="preview-notice surface-card">
      浏览器预览模式：以下示例数据仅保存在当前页面内，不会写入磁盘。
    </div>
    <div v-if="app.configError" class="config-error surface-card" role="alert">
      {{ app.configError }}
    </div>

    <div class="toolbar surface-card">
      <label class="search-box">
        <AppIcon name="search" :size="18" />
        <input v-model="query" type="search" placeholder="搜索名称、地址或分组" />
      </label>
      <div class="toolbar__meta">
        <span>{{ filteredServers.length }}个服务器</span>
        <button class="icon-button" type="button" aria-label="更多操作">
          <AppIcon name="more" />
        </button>
      </div>
    </div>

    <div class="server-list">
      <button
        v-for="server in filteredServers"
        :key="server.id"
        class="server-row surface-card"
        :class="{ 'server-row--active': server.id === app.selectedServerId }"
        type="button"
        @click="app.selectServer(server.id)"
      >
        <span class="server-emblem">{{ server.name.slice(0, 2).toUpperCase() }}</span>
        <span class="server-main">
          <span class="server-title">
            <strong>{{ server.name }}</strong>
            <small>{{ server.group }}</small>
            <em v-if="server.id === app.selectedServerId">当前</em>
          </span>
          <span class="server-address">{{ server.host }}:{{ server.port }}</span>
        </span>
        <span class="server-method">{{ server.method }}</span>
        <span class="server-source">{{
          server.source === "manual" ? "手动" : "订阅"
        }}</span>
        <span class="latency-pill latency-pill--unknown">
          <i />
          未测试
        </span>
        <span class="row-more"><AppIcon name="more" /></span>
      </button>
    </div>

    <div v-if="!filteredServers.length" class="empty-state surface-card">
      <AppIcon name="search" :size="30" />
      <h3>没有找到服务器</h3>
      <p>尝试调整关键词，或者添加一个新的服务器。</p>
    </div>

    <div v-if="showForm" class="dialog-layer" @click.self="showForm = false">
      <form class="server-dialog" @submit.prevent="saveServer">
        <div class="dialog-heading">
          <div>
            <span class="card-kicker">新配置</span>
            <h2>添加服务器</h2>
          </div>
          <button class="icon-button" type="button" @click="showForm = false">
            ×
          </button>
        </div>

        <div class="form-grid">
          <label>
            <span>名称</span>
            <input v-model="form.name" required placeholder="例如 Tokyo Edge" />
          </label>
          <label>
            <span>分组</span>
            <input v-model="form.group" placeholder="Personal" />
          </label>
          <label class="form-grid__wide">
            <span>服务器地址</span>
            <input v-model="form.host" required placeholder="server.example.com" />
          </label>
          <label>
            <span>端口</span>
            <input v-model.number="form.port" required type="number" min="1" max="65535" />
          </label>
          <label>
            <span>加密方式</span>
            <select v-model="form.method">
              <option>2022-blake3-aes-256-gcm</option>
              <option>2022-blake3-chacha20-poly1305</option>
              <option>chacha20-ietf-poly1305</option>
              <option>aes-256-gcm</option>
              <option>aes-128-gcm</option>
            </select>
          </label>
          <label class="form-grid__wide">
            <span>密码</span>
            <input v-model="form.password" required type="password" placeholder="输入服务器密码" />
          </label>
          <label>
            <span>插件</span>
            <input v-model="form.plugin" placeholder="可选" />
          </label>
          <label>
            <span>插件参数</span>
            <input v-model="form.plugin_opts" placeholder="可选" />
          </label>
        </div>

        <div class="dialog-actions">
          <button class="secondary-button" type="button" @click="showForm = false">
            取消
          </button>
          <button class="primary-button" type="submit" :disabled="saving">
            {{ saving ? "正在保存…" : "保存服务器" }}
          </button>
        </div>
      </form>
    </div>
  </section>
</template>
