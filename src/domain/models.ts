export type ConnectionMode = "direct" | "rule" | "global";
export type ConnectionState =
  | "disconnected"
  | "connecting"
  | "connected"
  | "disconnecting"
  | "error";
export type RouteAction = "direct" | "proxy";
export type RuleMatch = "domain_exact" | "domain_suffix" | "ip_cidr";
export type DnsSource = "system" | "custom";
export type RuntimeState =
  | "stopped"
  | "starting"
  | "running"
  | "stopping"
  | "recovery-required"
  | "failed";

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
  source: DnsSource;
  servers: string[];
  ipv6: boolean;
  tcp_fallback: boolean;
  cache_capacity: number;
  cache_ttl_seconds: number;
}

export interface TunConfig {
  enabled: boolean;
  interface_name: string;
  mtu: number;
  ipv6: boolean;
  management_exclusions: string[];
  tcp_session_timeout_seconds: number;
  udp_idle_timeout_seconds: number;
}

export interface RoutingRule {
  id: string;
  enabled: boolean;
  match_type: RuleMatch;
  value: string;
  action: RouteAction;
}

export interface RoutingConfig {
  rules: RoutingRule[];
  default_action: RouteAction;
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
  routing: RoutingConfig;
  kill_switch: KillSwitchConfig;
  subscriptions: SubscriptionSource[];
}

export interface RuntimeCounters {
  tunRxPackets: number;
  tunTxPackets: number;
  capturedTcpSessions: number;
  capturedUdpDatagrams: number;
  routeDirect: number;
  routeProxy: number;
  systemProxyDetected: number;
  routeDirectSystemProxy: number;
  directTcpConnections: number;
  directUdpAssociations: number;
  unsupportedPackets: number;
  droppedPackets: number;
  loopPreventionDrops: number;
}

export interface RuntimeSnapshot {
  platform: string;
  state: RuntimeState;
  tunAvailable: boolean;
  version: string;
  counters: RuntimeCounters;
  lastError: string | null;
  recoveryRequired: boolean;
}

export interface TrafficSample {
  at: number;
  upload: number;
  download: number;
}
