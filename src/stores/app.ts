import { computed, ref } from "vue";
import { defineStore } from "pinia";
import { invoke } from "@tauri-apps/api/core";
import type {
  AppConfig,
  ConnectionMode,
  ConnectionState,
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
  version: 1,
  mode: "rule",
  selected_server_id: "preview-tokyo-edge",
  servers: [
    {
      id: "preview-tokyo-edge",
      name: "Tokyo Preview",
      host: "preview.example.net",
      port: 8388,
      method: "2022-blake3-aes-256-gcm",
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
  dns: { enabled: true, servers: ["1.1.1.1", "8.8.8.8"], ipv6: true },
  tun: {
    enabled: false,
    interface_name: "Shadowsocks",
    mtu: 1500,
    ipv6: true,
  },
  kill_switch: { enabled: false, allow_lan: false },
  subscriptions: [],
};

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
  const connectionState = ref<ConnectionState>("disconnected");
  const config = ref<AppConfig | null>(null);
  const configLoading = ref(true);
  const configError = ref<string | null>(null);
  const previewMode = ref(false);
  const traffic = ref<TrafficSample[]>(initialTraffic);
  const uploadTotal = ref(182 * 1024 * 1024);
  const downloadTotal = ref(1.84 * 1024 * 1024 * 1024);
  let initialization: Promise<void> | null = null;

  const mode = computed(() => config.value?.mode ?? "rule");
  const servers = computed(() => config.value?.servers ?? []);
  const selectedServerId = computed(
    () => config.value?.selected_server_id ?? "",
  );
  const isConnected = computed(() => connectionState.value === "connected");
  const isTransitioning = computed(
    () =>
      connectionState.value === "connecting" ||
      connectionState.value === "disconnecting",
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

  async function toggleConnection() {
    if (isTransitioning.value) return;

    connectionState.value = isConnected.value ? "disconnecting" : "connecting";
    await new Promise((resolve) => window.setTimeout(resolve, 520));
    connectionState.value =
      connectionState.value === "connecting" ? "connected" : "disconnected";
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

  async function setMode(nextMode: ConnectionMode) {
    if (!config.value) return;
    const next = { ...config.value, mode: nextMode };
    if (previewMode.value) {
      applyConfig(next);
      return;
    }
    try {
      applyConfig(await invoke<AppConfig>("save_config", { config: next }));
    } catch {
      failConfigOperation();
    }
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
    toggleConnection,
    selectServer,
    setMode,
    addServer,
    updateServer,
    deleteServer,
  };
});
