export type ConnectionMode = "direct" | "rule" | "global";
export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "error";

export interface ServerProfile {
  id: string;
  name: string;
  host: string;
  port: number;
  method: string;
  password: string;
  timeout: number;
  plugin: string | null;
  plugin_opts: string | null;
  group: string;
  source: "manual" | "subscription";
}

export interface DnsConfig {
  enabled: boolean;
  servers: string[];
  ipv6: boolean;
}

export interface TunConfig {
  enabled: boolean;
  interface_name: string;
  mtu: number;
  ipv6: boolean;
}

export interface KillSwitchConfig {
  enabled: boolean;
  allow_lan: boolean;
}

export interface SubscriptionSource {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  update_interval_minutes: number;
  last_updated_at: number | null;
}

export interface AppConfig {
  version: number;
  mode: ConnectionMode;
  selected_server_id: string | null;
  servers: ServerProfile[];
  dns: DnsConfig;
  tun: TunConfig;
  kill_switch: KillSwitchConfig;
  subscriptions: SubscriptionSource[];
}

export interface RuntimeSnapshot {
  platform: string;
  serviceState: string;
  tunAvailable: boolean;
  version: string;
}

export interface TrafficSample {
  at: number;
  upload: number;
  download: number;
}
