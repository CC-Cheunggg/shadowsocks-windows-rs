import { computed, ref } from "vue";
import { defineStore } from "pinia";
import { invoke } from "@tauri-apps/api/core";
import type {
  AppConfig,
  ConnectionMode,
  ConnectionState,
  RuntimeSnapshot,
  RuntimeState,
  ServerProfile,
  TrafficSample,
} from "@/domain/models";

const EMPTY_SERVER: ServerProfile = {
  id: "",
  name: "尚未配置",
  host: "",
  port: 0,
  method: "",
  password: "",
  timeout: 300,
  plugin: null,
  plugin_opts: null,
  group: "",
  source: "manual",
};

// Browser-only sample data. Tauri mode always replaces this with Rust-owned config.
const BROWSER_PREVIEW_FALLBACK: AppConfig = {
  version: 2,
  mode: "rule",
  selected_server_id: "preview-tokyo-edge",
  servers: [
    {
      id: "preview-tokyo-edge",
      name: "Tokyo Preview",
      host: "preview.example.net",
      port: 8388,
      method: "2022-blake3-chacha20-poly1305",
      password: "browser-preview-only",
      timeout: 300,
      plugin: null,
      plugin_opts: null,
      group: "浏览器预览",
      source: "manual",
    },
    {
      id: "preview-singapore-core",
      name: "Singapore Preview",
      host: "preview.example.org",
      port: 443,
      method: "chacha20-ietf-poly1305",
      password: "browser-preview-only",
      timeout: 300,
      plugin: null,
      plugin_opts: null,
      group: "浏览器预览",
      source: "subscription",
    },
  ],
  dns: {
    enabled: true,
    source: "custom",
    servers: ["1.1.1.1", "8.8.8.8"],
    ipv6: true,
    tcp_fallback: true,
    cache_capacity: 4096,
    cache_ttl_seconds: 300,
  },
  tun: {
    enabled: true,
    interface_name: "Shadowsocks",
    mtu: 1500,
    ipv6: true,
    management_exclusions: [],
    tcp_session_timeout_seconds: 300,
    udp_idle_timeout_seconds: 60,
  },
  routing: { rules: [], default_action: "proxy" },
  kill_switch: { enabled: false, allow_lan: false },
  subscriptions: [],
};

const EMPTY_COUNTERS = {
  tunRxPackets: 0,
  tunTxPackets: 0,
  capturedTcpSessions: 0,
  capturedUdpDatagrams: 0,
  routeDirect: 0,
  routeProxy: 0,
  systemProxyDetected: 0,
  routeDirectSystemProxy: 0,
  directTcpConnections: 0,
  directUdpAssociations: 0,
  unsupportedPackets: 0,
  droppedPackets: 0,
  loopPreventionDrops: 0,
};

function browserRuntimeSnapshot(
  state: RuntimeState = "stopped",
): RuntimeSnapshot {
  return {
    platform: "browser-preview",
    state,
    tunAvailable: false,
    version: "0.1.0",
    counters: { ...EMPTY_COUNTERS },
    lastError: null,
    recoveryRequired: false,
  };
}

const initialTraffic: TrafficSample[] = Array.from({ length: 24 }, (_, index) => ({
  at: Date.now() - (23 - index) * 2_000,
  upload: [8, 11, 7, 14, 18, 23, 20, 31, 26, 22, 37, 32][index % 12] * 1024,
  download:
    [34, 42, 28, 55, 72, 68, 94, 88, 110, 91, 125, 104][index % 12] * 1024,
}));

function runningInTauri() {
  return "__TAURI_INTERNALS__" in window;
}

function browserPreviewConfig(): AppConfig {
  return structuredClone(BROWSER_PREVIEW_FALLBACK);
}

export const useAppStore = defineStore("app", () => {
  const config = ref<AppConfig | null>(null);
  const configLoading = ref(true);
  const configError = ref<string | null>(null);
  const previewMode = ref(false);
  const runtime = ref<RuntimeSnapshot>(browserRuntimeSnapshot());
  const runtimeLoading = ref(true);
  const traffic = ref<TrafficSample[]>([]);
  const uploadTotal = ref(0);
  const downloadTotal = ref(0);
  let initialization: Promise<void> | null = null;
  let runtimeInitialization: Promise<void> | null = null;

  const mode = computed(() => config.value?.mode ?? "rule");
  const servers = computed(() => config.value?.servers ?? []);
  const selectedServerId = computed(
    () => config.value?.selected_server_id ?? "",
  );
  const connectionState = computed<ConnectionState>(() => {
    const states: Record<RuntimeState, ConnectionState> = {
      stopped: "disconnected",
      starting: "connecting",
      running: "connected",
      stopping: "disconnecting",
      "recovery-required": "error",
      failed: "error",
    };
    return states[runtime.value.state];
  });
  const isConnected = computed(() => runtime.value.state === "running");
  const isTransitioning = computed(
    () =>
      runtime.value.state === "starting" ||
      runtime.value.state === "stopping",
  );
  const selectedServer = computed(
    () =>
      servers.value.find((server) => server.id === selectedServerId.value) ??
      servers.value[0] ??
      EMPTY_SERVER,
  );
  const latestTraffic = computed(
    () => traffic.value.at(-1) ?? { at: Date.now(), upload: 0, download: 0 },
  );

  function applyConfig(next: AppConfig) {
    config.value = next;
    configError.value = null;
  }

  function failConfigOperation() {
    configError.value = "配置操作失败，请检查输入后重试。";
  }

  async function initializeConfig() {
    if (initialization) return initialization;
    initialization = (async () => {
      configLoading.value = true;
      if (!runningInTauri()) {
        previewMode.value = true;
        traffic.value = initialTraffic;
        uploadTotal.value = 182 * 1024 * 1024;
        downloadTotal.value = 1.84 * 1024 * 1024 * 1024;
        applyConfig(browserPreviewConfig());
        configLoading.value = false;
        return;
      }
      try {
        applyConfig(await invoke<AppConfig>("get_config"));
      } catch {
        configError.value = "无法从本地配置目录读取配置。";
      } finally {
        configLoading.value = false;
      }
    })();
    return initialization;
  }

  async function refreshRuntimeSnapshot() {
    if (previewMode.value || !runningInTauri()) return;
    try {
      runtime.value = await invoke<RuntimeSnapshot>("get_runtime_snapshot");
    } catch {
      runtime.value = {
        ...runtime.value,
        state: "failed",
        lastError: "无法读取本地 DIRECT runtime 状态。",
      };
    }
  }

  async function initializeRuntime() {
    if (runtimeInitialization) return runtimeInitialization;
    runtimeInitialization = (async () => {
      runtimeLoading.value = true;
      if (previewMode.value || !runningInTauri()) {
        runtime.value = browserRuntimeSnapshot();
        runtimeLoading.value = false;
        return;
      }
      await refreshRuntimeSnapshot();
      runtimeLoading.value = false;
      window.setInterval(refreshRuntimeSnapshot, 1_500);
    })();
    return runtimeInitialization;
  }

  async function toggleConnection() {
    if (isTransitioning.value) return;

    if (previewMode.value) {
      const stopping = isConnected.value;
      runtime.value = browserRuntimeSnapshot(
        stopping ? "stopping" : "starting",
      );
      await new Promise((resolve) => window.setTimeout(resolve, 320));
      runtime.value = browserRuntimeSnapshot(stopping ? "stopped" : "running");
      return;
    }

    if (runtime.value.recoveryRequired) {
      runtime.value = {
        ...runtime.value,
        state: "recovery-required",
        lastError: "检测到待恢复的网络状态；请先运行受限恢复命令。",
      };
      return;
    }

    const stopping = isConnected.value;
    runtime.value = {
      ...runtime.value,
      state: stopping ? "stopping" : "starting",
      lastError: null,
    };
    try {
      runtime.value = await invoke<RuntimeSnapshot>(
        stopping ? "stop_tunnel" : "start_tunnel",
      );
    } catch {
      await refreshRuntimeSnapshot();
      if (!runtime.value.lastError) {
        runtime.value = {
          ...runtime.value,
          state: "failed",
          lastError: "DIRECT runtime 操作未完成，且无法读取详细状态。",
        };
      }
    }
  }

  async function selectServer(id: string) {
    if (previewMode.value && config.value) {
      config.value.selected_server_id = id;
      return;
    }
    try {
      applyConfig(await invoke<AppConfig>("select_server", { id }));
    } catch {
      failConfigOperation();
    }
  }

  async function saveCurrentConfig(next: AppConfig): Promise<boolean> {
    if (isConnected.value || isTransitioning.value) {
      configError.value = "请先停止 DIRECT runtime，再修改网络配置。";
      return false;
    }
    if (previewMode.value) {
      applyConfig(next);
      return true;
    }
    try {
      applyConfig(await invoke<AppConfig>("save_config", { config: next }));
      return true;
    } catch {
      failConfigOperation();
      return false;
    }
  }

  async function setMode(nextMode: ConnectionMode) {
    if (!config.value) return;
    const next = { ...config.value, mode: nextMode };
    await saveCurrentConfig(next);
  }

  async function addServer(
    server: Omit<ServerProfile, "id" | "source">,
  ): Promise<boolean> {
    const nextServer: ServerProfile = {
      ...server,
      id: previewMode.value ? `preview-${Date.now()}` : "",
      source: "manual",
    };
    if (previewMode.value && config.value) {
      config.value.servers.push(nextServer);
      config.value.selected_server_id = nextServer.id;
      return true;
    }
    try {
      applyConfig(
        await invoke<AppConfig>("add_server", { server: nextServer }),
      );
      return true;
    } catch {
      failConfigOperation();
      return false;
    }
  }

  async function updateServer(server: ServerProfile): Promise<boolean> {
    if (previewMode.value && config.value) {
      const index = config.value.servers.findIndex(({ id }) => id === server.id);
      if (index < 0) return false;
      config.value.servers[index] = server;
      return true;
    }
    try {
      applyConfig(await invoke<AppConfig>("update_server", { server }));
      return true;
    } catch {
      failConfigOperation();
      return false;
    }
  }

  async function deleteServer(id: string): Promise<boolean> {
    if (previewMode.value && config.value) {
      config.value.servers = config.value.servers.filter(
        (server) => server.id !== id,
      );
      if (config.value.selected_server_id === id) {
        config.value.selected_server_id = config.value.servers[0]?.id ?? null;
      }
      return true;
    }
    try {
      applyConfig(await invoke<AppConfig>("delete_server", { id }));
      return true;
    } catch {
      failConfigOperation();
      return false;
    }
  }

  return {
    connectionState,
    config,
    configLoading,
    configError,
    previewMode,
    runtime,
    runtimeLoading,
    mode,
    servers,
    selectedServerId,
    traffic,
    uploadTotal,
    downloadTotal,
    isConnected,
    isTransitioning,
    selectedServer,
    latestTraffic,
    initializeConfig,
    initializeRuntime,
    refreshRuntimeSnapshot,
    toggleConnection,
    selectServer,
    saveCurrentConfig,
    setMode,
    addServer,
    updateServer,
    deleteServer,
  };
});
