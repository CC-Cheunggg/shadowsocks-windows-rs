//! Windows route ownership, snapshots, and rollback.
//!
//! Full capture is installed as two `/1` routes per enabled address family.
//! The original physical default route remains present, so sockets constrained
//! with `IP_UNICAST_IF`/`IPV6_UNICAST_IF` can continue to use it. Every route
//! added here uses the volatile `ActiveStore` and is removed by exact identity;
//! no permanent per-destination route is created.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(windows)]
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
const MAX_SNAPSHOT_SECTION_BYTES: usize = 4 * 1024 * 1024;
const CAPTURE_V4_PREFIXES: [&str; 2] = ["0.0.0.0/1", "128.0.0.0/1"];
const CAPTURE_V6_PREFIXES: [&str; 2] = ["::/1", "8000::/1"];
const MAX_SHADOW_CAPTURE_ROUTES: usize = 8_192;
const MAX_RECOVERY_ROUTES: usize = 4 + MAX_SHADOW_CAPTURE_ROUTES + 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    UnsupportedPlatform,
    InvalidPlan(&'static str),
    SnapshotTooLarge,
    DiscoveryFailed { operation: &'static str, code: u32 },
    CommandFailed { operation: &'static str, code: u32 },
    ResourceConflict(&'static str),
    OwnershipMismatch(&'static str),
    JournalUpdateFailed,
    SnapshotEncoding,
    RollbackFailed { failed_routes: usize },
}

impl fmt::Display for RouteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("Windows route management is unavailable on this platform")
            }
            Self::InvalidPlan(message) => write!(formatter, "invalid route plan: {message}"),
            Self::SnapshotTooLarge => {
                formatter.write_str("network snapshot exceeded the safe size limit")
            }
            Self::DiscoveryFailed { operation, code } => {
                write!(formatter, "{operation} failed (Windows error {code})")
            }
            Self::CommandFailed { operation, code } => {
                write!(formatter, "{operation} failed (Windows error {code})")
            }
            Self::ResourceConflict(resource) => {
                write!(formatter, "refusing to claim a pre-existing {resource}")
            }
            Self::OwnershipMismatch(resource) => {
                write!(
                    formatter,
                    "refusing to modify {resource}: interface identity changed"
                )
            }
            Self::JournalUpdateFailed => formatter.write_str("recovery journal update failed"),
            Self::SnapshotEncoding => {
                formatter.write_str("Windows network snapshot was not valid structured data")
            }
            Self::RollbackFailed { failed_routes } => write!(
                formatter,
                "route rollback could not remove {failed_routes} owned route(s)"
            ),
        }
    }
}

impl std::error::Error for RouteError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceIdentity {
    pub interface_index: u32,
    pub interface_luid: u64,
    pub interface_guid: String,
    pub alias: String,
}

impl InterfaceIdentity {
    fn validate(&self) -> Result<(), RouteError> {
        if self.interface_index == 0 {
            return Err(RouteError::InvalidPlan("interface index is zero"));
        }
        if self.interface_luid == 0 {
            return Err(RouteError::InvalidPlan("interface LUID is zero"));
        }
        let guid = self.interface_guid.as_bytes();
        if guid.len() != 36
            || guid.iter().enumerate().any(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte != b'-'
                } else {
                    !byte.is_ascii_hexdigit()
                }
            })
        {
            return Err(RouteError::InvalidPlan("interface GUID is invalid"));
        }
        if self.alias.is_empty()
            || self.alias.encode_utf16().count() >= 128
            || self
                .alias
                .chars()
                .any(|character| character == '\0' || character.is_control())
        {
            return Err(RouteError::InvalidPlan("interface alias is invalid"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhysicalInterface {
    pub identity: InterfaceIdentity,
    pub ipv4_source: Option<Ipv4Addr>,
    pub ipv6_source: Option<Ipv6Addr>,
    pub ipv4_gateway: Option<Ipv4Addr>,
    pub ipv6_gateway: Option<Ipv6Addr>,
    pub dns_servers: Vec<IpAddr>,
    pub route_metric: u32,
}

impl PhysicalInterface {
    pub fn source_for(&self, destination: IpAddr) -> Option<IpAddr> {
        match destination {
            IpAddr::V4(_) => self.ipv4_source.map(IpAddr::V4),
            IpAddr::V6(_) => self.ipv6_source.map(IpAddr::V6),
        }
    }

    pub fn gateway_for(&self, destination: IpAddr) -> Option<IpAddr> {
        match destination {
            IpAddr::V4(_) => self.ipv4_gateway.map(IpAddr::V4),
            IpAddr::V6(_) => self.ipv6_gateway.map(IpAddr::V6),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteBinding {
    pub interface: InterfaceIdentity,
    pub source: IpAddr,
    pub next_hop: IpAddr,
}

/// Central audit vocabulary for the only host exclusions accepted by a full
/// capture route plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    /// Keeps the current remote-management transport reachable during manual
    /// acceptance. It must be accompanied by an automatic rollback watchdog.
    ManagementConnection,
    /// Local IPC/control endpoint required to stop or recover the tunnel.
    LocalControl,
    /// Explicit DNS resolver used by the DIRECT DNS outbound.
    DirectDns,
    /// Reserved for the selected proxy server in a later slice.
    ProxyServerFuture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MandatoryExclusion {
    pub destination: IpAddr,
    pub physical_interface: InterfaceIdentity,
    pub physical_gateway: IpAddr,
    pub reason: ExclusionReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutePlan {
    pub tun_interface: InterfaceIdentity,
    pub enable_ipv4: bool,
    pub enable_ipv6: bool,
    /// Application-owned address assigned to the Wintun interface for this
    /// transaction. It is removed during rollback.
    pub tun_ipv4_address: Option<InterfaceAddress>,
    /// Application-owned address assigned to the Wintun interface for this
    /// transaction. It is removed during rollback.
    pub tun_ipv6_address: Option<InterfaceAddress>,
    pub metric: u32,
    /// Child prefixes derived from the pre-start route snapshot. Each is more
    /// specific than an existing non-default route, preventing LAN, VPN, and
    /// host routes from bypassing Wintun by longest-prefix selection.
    pub shadow_capture_prefixes: Vec<String>,
    /// MTU applied to both IP families on the Wintun interface.
    pub interface_mtu: u32,
    /// Explicit Wintun interface metric used for deterministic host-shadow
    /// priority checks.
    pub interface_metric: u32,
    pub exclusions: Vec<MandatoryExclusion>,
}

impl RoutePlan {
    pub fn validate(&self) -> Result<(), RouteError> {
        self.tun_interface.validate()?;
        if !self.enable_ipv4 && !self.enable_ipv6 {
            return Err(RouteError::InvalidPlan(
                "at least one address family must be captured",
            ));
        }
        validate_interface_address(self.tun_ipv4_address.as_ref(), true, self.enable_ipv4)?;
        validate_interface_address(self.tun_ipv6_address.as_ref(), false, self.enable_ipv6)?;
        if self.metric == 0 || self.metric > 9_999 {
            return Err(RouteError::InvalidPlan("route metric is outside 1..=9999"));
        }
        if !(1280..=9000).contains(&self.interface_mtu) {
            return Err(RouteError::InvalidPlan(
                "interface MTU is outside 1280..=9000",
            ));
        }
        if self.interface_metric == 0 || self.interface_metric > 9_999 {
            return Err(RouteError::InvalidPlan(
                "interface metric is outside 1..=9999",
            ));
        }
        if self.shadow_capture_prefixes.len() > MAX_SHADOW_CAPTURE_ROUTES {
            return Err(RouteError::InvalidPlan("too many shadow capture routes"));
        }
        let mut shadow_prefixes = HashSet::with_capacity(self.shadow_capture_prefixes.len());
        for prefix in &self.shadow_capture_prefixes {
            let (network, length) = parse_network_prefix(prefix)?;
            if length == 0 || is_loopback_prefix(network, length) {
                return Err(RouteError::InvalidPlan(
                    "shadow capture prefix is not eligible",
                ));
            }
            if format_network_prefix(network, length) != *prefix
                || !shadow_prefixes.insert(prefix.as_str())
            {
                return Err(RouteError::InvalidPlan(
                    "shadow capture prefixes must be normalized and unique",
                ));
            }
        }
        if self.exclusions.len() > 64 {
            return Err(RouteError::InvalidPlan("too many mandatory exclusions"));
        }
        for exclusion in &self.exclusions {
            exclusion.physical_interface.validate()?;
            if exclusion.destination.is_ipv4() != exclusion.physical_gateway.is_ipv4() {
                return Err(RouteError::InvalidPlan(
                    "exclusion destination and gateway families differ",
                ));
            }
            if exclusion.physical_interface == self.tun_interface {
                return Err(RouteError::InvalidPlan(
                    "exclusion points back to the TUN interface",
                ));
            }
        }
        Ok(())
    }

    pub fn recovery_plan(&self) -> Result<RecoveryPlan, RouteError> {
        self.validate()?;
        Ok(RecoveryPlan {
            tun_interface: self.tun_interface.clone(),
            interface_addresses: [self.tun_ipv4_address.clone(), self.tun_ipv6_address.clone()]
                .into_iter()
                .flatten()
                .collect(),
            routes: route_specs(self),
            interface_settings: Vec::new(),
            interface_address_states: Vec::new(),
            route_states: Vec::new(),
            interface_setting_states: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InterfaceAddress {
    pub address: IpAddr,
    pub prefix_length: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedRoute {
    pub destination_prefix: String,
    pub interface: InterfaceIdentity,
    pub next_hop: IpAddr,
    pub metric: u32,
}

impl OwnedRoute {
    pub fn on_link_host(
        destination: IpAddr,
        interface: InterfaceIdentity,
        metric: u32,
    ) -> Result<Self, RouteError> {
        interface.validate()?;
        if metric == 0 || metric > 9_999 {
            return Err(RouteError::InvalidPlan("route metric is outside 1..=9999"));
        }
        Ok(Self {
            destination_prefix: match destination {
                IpAddr::V4(address) => format!("{address}/32"),
                IpAddr::V6(address) => format!("{address}/128"),
            },
            interface,
            next_hop: if destination.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            },
            metric,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum IpFamily {
    V4,
    V6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OwnershipState {
    Prepared,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct OwnedInterfaceSetting {
    family: IpFamily,
    original_mtu: u32,
    original_metric: u32,
    original_automatic_metric: bool,
    applied_mtu: u32,
    applied_metric: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryPlan {
    tun_interface: InterfaceIdentity,
    interface_addresses: Vec<InterfaceAddress>,
    routes: Vec<OwnedRoute>,
    interface_settings: Vec<OwnedInterfaceSetting>,
    #[serde(default)]
    interface_address_states: Vec<OwnershipState>,
    #[serde(default)]
    route_states: Vec<OwnershipState>,
    #[serde(default)]
    interface_setting_states: Vec<OwnershipState>,
}

impl RecoveryPlan {
    pub fn empty(tun_interface: InterfaceIdentity) -> Result<Self, RouteError> {
        tun_interface.validate()?;
        Ok(Self {
            tun_interface,
            interface_addresses: Vec::new(),
            routes: Vec::new(),
            interface_settings: Vec::new(),
            interface_address_states: Vec::new(),
            route_states: Vec::new(),
            interface_setting_states: Vec::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_parts_for_runtime_test(
        tun_interface: InterfaceIdentity,
        interface_addresses: Vec<InterfaceAddress>,
        routes: Vec<OwnedRoute>,
    ) -> Self {
        let address_count = interface_addresses.len();
        let route_count = routes.len();
        Self {
            tun_interface,
            interface_addresses,
            routes,
            interface_settings: Vec::new(),
            interface_address_states: vec![OwnershipState::Applied; address_count],
            route_states: vec![OwnershipState::Applied; route_count],
            interface_setting_states: Vec::new(),
        }
    }

    pub fn tun_interface(&self) -> &InterfaceIdentity {
        &self.tun_interface
    }

    pub fn interface_addresses(&self) -> &[InterfaceAddress] {
        &self.interface_addresses
    }

    pub fn owned_routes(&self) -> &[OwnedRoute] {
        &self.routes
    }

    pub(crate) fn has_external_routes(&self) -> bool {
        self.routes
            .iter()
            .any(|route| !self.adapter_owns_route(route))
    }

    pub fn owned_change_count(&self) -> usize {
        self.routes.len() + self.interface_addresses.len() + self.interface_settings.len()
    }

    fn adapter_owns_route(&self, route: &OwnedRoute) -> bool {
        route.interface == self.tun_interface
    }

    fn address_state(&self, index: usize) -> OwnershipState {
        self.interface_address_states
            .get(index)
            .copied()
            // Journals written before the state field existed contained only
            // successfully applied resources.
            .unwrap_or(OwnershipState::Applied)
    }

    fn route_state(&self, index: usize) -> OwnershipState {
        self.route_states
            .get(index)
            .copied()
            .unwrap_or(OwnershipState::Applied)
    }

    fn setting_state(&self, index: usize) -> OwnershipState {
        self.interface_setting_states
            .get(index)
            .copied()
            .unwrap_or(OwnershipState::Applied)
    }

    fn push_prepared_address(&mut self, address: InterfaceAddress) -> usize {
        let index = self.interface_addresses.len();
        self.interface_addresses.push(address);
        self.interface_address_states.push(OwnershipState::Prepared);
        index
    }

    fn push_prepared_route(&mut self, route: OwnedRoute) -> usize {
        let index = self.routes.len();
        self.routes.push(route);
        self.route_states.push(OwnershipState::Prepared);
        index
    }

    fn push_prepared_setting(&mut self, setting: OwnedInterfaceSetting) -> usize {
        let index = self.interface_settings.len();
        self.interface_settings.push(setting);
        self.interface_setting_states.push(OwnershipState::Prepared);
        index
    }

    fn mark_address_applied(&mut self, index: usize) {
        self.interface_address_states[index] = OwnershipState::Applied;
    }

    fn mark_route_applied(&mut self, index: usize) {
        self.route_states[index] = OwnershipState::Applied;
    }

    fn mark_setting_applied(&mut self, index: usize) {
        self.interface_setting_states[index] = OwnershipState::Applied;
    }

    pub(crate) fn validate_journal_state(&self) -> Result<(), RouteError> {
        self.tun_interface.validate()?;
        if self.interface_addresses.len() > 2
            || self.routes.len() > MAX_RECOVERY_ROUTES
            || self.interface_settings.len() > 2
        {
            return Err(RouteError::InvalidPlan(
                "recovery journal resource count is invalid",
            ));
        }
        let mut addresses = HashSet::new();
        for address in &self.interface_addresses {
            validate_interface_address(Some(address), address.address.is_ipv4(), true)?;
            if !addresses.insert((address.address, address.prefix_length)) {
                return Err(RouteError::InvalidPlan(
                    "recovery journal contains duplicate addresses",
                ));
            }
        }
        let mut routes = HashSet::new();
        for route in &self.routes {
            route.interface.validate()?;
            let (network, prefix_length) = parse_network_prefix(&route.destination_prefix)?;
            if format_network_prefix(network, prefix_length) != route.destination_prefix
                || route.next_hop.is_ipv4() != network.is_ipv4()
                || route.metric == 0
                || route.metric > 9_999
                || (route.interface != self.tun_interface
                    && prefix_length != if network.is_ipv4() { 32 } else { 128 })
            {
                return Err(RouteError::InvalidPlan("recovery journal route is invalid"));
            }
            let identity = format!(
                "{}|{}|{}|{}|{}",
                route.destination_prefix,
                route.interface.interface_luid,
                route.interface.interface_index,
                route.next_hop,
                route.metric
            );
            if !routes.insert(identity) {
                return Err(RouteError::InvalidPlan(
                    "recovery journal contains duplicate routes",
                ));
            }
        }
        let mut families = HashSet::new();
        for setting in &self.interface_settings {
            if setting.original_mtu == 0
                || !(1280..=9000).contains(&setting.applied_mtu)
                || setting.applied_metric == 0
                || setting.applied_metric > 9_999
                || !families.insert(setting.family)
            {
                return Err(RouteError::InvalidPlan(
                    "recovery journal interface setting is invalid",
                ));
            }
        }
        for (states, resources) in [
            (
                self.interface_address_states.len(),
                self.interface_addresses.len(),
            ),
            (self.route_states.len(), self.routes.len()),
            (
                self.interface_setting_states.len(),
                self.interface_settings.len(),
            ),
        ] {
            // Empty state vectors are the legacy representation, in which all
            // recorded resources had already been applied.
            if states != 0 && states != resources {
                return Err(RouteError::InvalidPlan(
                    "recovery ownership state is inconsistent",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn validate_journal_encoding(&self, legacy: bool) -> Result<(), RouteError> {
        self.validate_journal_state()?;
        let state_lengths = [
            self.interface_address_states.len(),
            self.route_states.len(),
            self.interface_setting_states.len(),
        ];
        let resource_lengths = [
            self.interface_addresses.len(),
            self.routes.len(),
            self.interface_settings.len(),
        ];
        let valid = if legacy {
            state_lengths.iter().all(|length| *length == 0)
        } else {
            state_lengths == resource_lengths
        };
        if valid {
            Ok(())
        } else {
            Err(RouteError::InvalidPlan(
                "recovery journal ownership encoding is inconsistent",
            ))
        }
    }

    pub(crate) fn is_valid_successor_of(&self, previous: &Self) -> bool {
        self.tun_interface == previous.tun_interface
            && self
                .interface_addresses
                .starts_with(&previous.interface_addresses)
            && self.routes.starts_with(&previous.routes)
            && self
                .interface_settings
                .starts_with(&previous.interface_settings)
            && previous
                .interface_addresses
                .iter()
                .enumerate()
                .all(|(index, _)| {
                    !matches!(
                        (previous.address_state(index), self.address_state(index)),
                        (OwnershipState::Applied, OwnershipState::Prepared)
                    )
                })
            && previous.routes.iter().enumerate().all(|(index, _)| {
                !matches!(
                    (previous.route_state(index), self.route_state(index)),
                    (OwnershipState::Applied, OwnershipState::Prepared)
                )
            })
            && previous
                .interface_settings
                .iter()
                .enumerate()
                .all(|(index, _)| {
                    !matches!(
                        (previous.setting_state(index), self.setting_state(index)),
                        (OwnershipState::Applied, OwnershipState::Prepared)
                    )
                })
    }

    /// Removes only the exact address/route objects recorded in this plan.
    /// It never rewrites the full saved route table, so network changes made
    /// after startup are preserved.
    pub fn restore_owned(&self) -> Result<(), RouteError> {
        self.validate_journal_state()?;
        rollback(self, RouteRestoreScope::All)
    }

    pub(crate) fn restore_adapter_owned_only(&self) -> Result<(), RouteError> {
        self.validate_journal_state()?;
        rollback(self, RouteRestoreScope::AdapterOnly)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemNetworkSnapshot {
    pub captured_unix_ms: u128,
    /// Read-only structured adapter/address/interface data from IP Helper.
    pub adapters_json: String,
    /// Read-only structured forwarding rows from IP Helper.
    pub routes_json: String,
    /// Read-only structured DNS-server data from IP Helper.
    pub dns_json: String,
}

impl SystemNetworkSnapshot {
    pub fn capture() -> Result<Self, RouteError> {
        platform::capture_snapshot()
    }

    /// Converts each pre-existing non-default route into one or two Wintun
    /// shadow prefixes. Child prefixes win by prefix length rather than by
    /// metric, so a low-metric LAN or VPN route cannot silently bypass capture.
    pub fn shadow_capture_prefixes(&self) -> Result<Vec<String>, RouteError> {
        self.shadow_capture_prefixes_filtered(None)
    }

    /// Derives shadow prefixes while excluding every route belonging to one
    /// exact interface generation. Both ifIndex and LUID must match: an ifIndex
    /// alone can be reused after a network or Wintun epoch change.
    pub fn shadow_capture_prefixes_excluding_interface(
        &self,
        excluded: &InterfaceIdentity,
    ) -> Result<Vec<String>, RouteError> {
        excluded.validate()?;
        self.shadow_capture_prefixes_filtered(Some(excluded))
    }

    fn shadow_capture_prefixes_filtered(
        &self,
        excluded: Option<&InterfaceIdentity>,
    ) -> Result<Vec<String>, RouteError> {
        let value: serde_json::Value =
            serde_json::from_str(&self.routes_json).map_err(|_| RouteError::SnapshotEncoding)?;
        let values = snapshot_rows(&value)?;
        let mut prefixes = HashSet::new();
        for value in values {
            let prefix = value
                .get("DestinationPrefix")
                .and_then(serde_json::Value::as_str)
                .ok_or(RouteError::SnapshotEncoding)?;
            let (network, length) = parse_network_prefix(prefix)?;
            if let Some(excluded) = excluded {
                let interface_index = value
                    .get("InterfaceIndex")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(RouteError::SnapshotEncoding)?;
                let interface_luid = value
                    .get("InterfaceLuid")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(RouteError::SnapshotEncoding)?;
                if interface_index == excluded.interface_index
                    && interface_luid == excluded.interface_luid
                {
                    continue;
                }
            }
            if length == 0 || is_loopback_prefix(network, length) {
                continue;
            }
            for prefix in shadow_prefixes_for(network, length) {
                prefixes.insert(prefix);
                if prefixes.len() > MAX_SHADOW_CAPTURE_ROUTES {
                    return Err(RouteError::InvalidPlan("too many shadow capture routes"));
                }
            }
        }
        let mut prefixes = prefixes.into_iter().collect::<Vec<_>>();
        prefixes.sort();
        Ok(prefixes)
    }

    /// Used before a mutation to avoid claiming ownership of a route that was
    /// already present in the original ActiveStore.
    pub fn contains_owned_route(&self, expected: &OwnedRoute) -> Result<bool, RouteError> {
        let value: serde_json::Value =
            serde_json::from_str(&self.routes_json).map_err(|_| RouteError::SnapshotEncoding)?;
        let values = snapshot_rows(&value)?;
        Ok(values.iter().any(|value| {
            let next_hop = value
                .get("NextHop")
                .and_then(serde_json::Value::as_str)
                .and_then(|value| value.parse::<IpAddr>().ok());
            value
                .get("DestinationPrefix")
                .and_then(serde_json::Value::as_str)
                == Some(expected.destination_prefix.as_str())
                && value
                    .get("InterfaceIndex")
                    .and_then(serde_json::Value::as_u64)
                    == Some(u64::from(expected.interface.interface_index))
                && value
                    .get("InterfaceLuid")
                    .and_then(serde_json::Value::as_u64)
                    == Some(expected.interface.interface_luid)
                && next_hop == Some(expected.next_hop)
                && value.get("RouteMetric").and_then(serde_json::Value::as_u64)
                    == Some(u64::from(expected.metric))
        }))
    }

    pub fn default_route_fingerprint(&self) -> Result<String, RouteError> {
        self.external_default_route_selection_fingerprint()
    }

    /// Produces a stable fingerprint for every physical/default-route
    /// selection input represented by this snapshot. Windows adds the route
    /// metric to the corresponding IPv4/IPv6 interface metric, so both values
    /// must be compared across a network epoch.
    pub fn external_default_route_selection_fingerprint(&self) -> Result<String, RouteError> {
        let adapters_value: serde_json::Value =
            serde_json::from_str(&self.adapters_json).map_err(|_| RouteError::SnapshotEncoding)?;
        let mut adapter_metrics = HashMap::new();
        for adapter in strict_snapshot_rows(&adapters_value)? {
            let interface_index = snapshot_u32(adapter, "InterfaceIndex")?;
            let interface_luid = snapshot_u64(adapter, "InterfaceLuid")?;
            if interface_index == 0 || interface_luid == 0 {
                return Err(RouteError::SnapshotEncoding);
            }
            let ipv4_metric = snapshot_u32(adapter, "Ipv4Metric")?;
            let ipv6_metric = snapshot_u32(adapter, "Ipv6Metric")?;
            if adapter_metrics
                .insert(
                    (interface_index, interface_luid),
                    (ipv4_metric, ipv6_metric),
                )
                .is_some()
            {
                return Err(RouteError::SnapshotEncoding);
            }
        }

        let routes_value: serde_json::Value =
            serde_json::from_str(&self.routes_json).map_err(|_| RouteError::SnapshotEncoding)?;
        let mut rows = Vec::new();
        for row in strict_snapshot_rows(&routes_value)? {
            let prefix = snapshot_str(row, "DestinationPrefix")?;
            let (network, prefix_length) = parse_network_prefix(prefix)?;
            if format_network_prefix(network, prefix_length) != prefix {
                return Err(RouteError::SnapshotEncoding);
            }
            if prefix_length != 0 {
                continue;
            }

            let interface_index = snapshot_u32(row, "InterfaceIndex")?;
            let interface_luid = snapshot_u64(row, "InterfaceLuid")?;
            if interface_index == 0 || interface_luid == 0 {
                return Err(RouteError::SnapshotEncoding);
            }
            let next_hop_text = snapshot_str(row, "NextHop")?;
            let next_hop = next_hop_text
                .parse::<IpAddr>()
                .map_err(|_| RouteError::SnapshotEncoding)?;
            if next_hop.is_ipv4() != network.is_ipv4() || next_hop.to_string() != next_hop_text {
                return Err(RouteError::SnapshotEncoding);
            }
            let route_metric = snapshot_u32(row, "RouteMetric")?;
            let (ipv4_metric, ipv6_metric) = adapter_metrics
                .get(&(interface_index, interface_luid))
                .copied()
                .ok_or(RouteError::SnapshotEncoding)?;
            let interface_metric = if network.is_ipv4() {
                ipv4_metric
            } else {
                ipv6_metric
            };
            rows.push(format!(
                "{prefix}|{interface_index}|{interface_luid}|{next_hop}|{route_metric}|{interface_metric}"
            ));
        }
        rows.sort();
        Ok(rows.join("\n"))
    }
}

pub fn resolve_interface_identity(interface_index: u32) -> Result<InterfaceIdentity, RouteError> {
    platform::resolve_interface_identity(interface_index)
}

pub fn find_interface_by_alias(alias: &str) -> Result<Option<InterfaceIdentity>, RouteError> {
    platform::find_interface_by_alias(alias)
}

pub fn find_interface_by_luid(
    interface_luid: u64,
) -> Result<Option<InterfaceIdentity>, RouteError> {
    platform::find_interface_by_luid(interface_luid)
}

pub fn restore_isolated(
    interface: &InterfaceIdentity,
    addresses: &[InterfaceAddress],
    routes: &[OwnedRoute],
) -> Result<(), RouteError> {
    interface.validate()?;
    if routes.iter().any(|route| {
        parse_network_prefix(&route.destination_prefix)
            .map(|(address, length)| {
                route.interface != *interface || length != if address.is_ipv4() { 32 } else { 128 }
            })
            .unwrap_or(true)
    }) {
        return Err(RouteError::InvalidPlan(
            "isolated recovery accepts only host routes",
        ));
    }
    let recovery = RecoveryPlan {
        tun_interface: interface.clone(),
        interface_addresses: addresses.to_vec(),
        routes: routes.to_vec(),
        interface_settings: Vec::new(),
        interface_address_states: vec![OwnershipState::Applied; addresses.len()],
        route_states: vec![OwnershipState::Applied; routes.len()],
        interface_setting_states: Vec::new(),
    };
    rollback(&recovery, RouteRestoreScope::All)
}

pub fn discover_primary_physical_interface(
    excluded_interface_index: Option<u32>,
) -> Result<PhysicalInterface, RouteError> {
    platform::discover_primary_physical_interface(excluded_interface_index)
}

pub fn discover_route_to(
    destination: IpAddr,
    excluded_interface_index: Option<u32>,
) -> Result<RouteBinding, RouteError> {
    platform::discover_route_to(destination, excluded_interface_index)
}

pub fn discover_route_on_interface(
    destination: IpAddr,
    expected_interface: &InterfaceIdentity,
) -> Result<RouteBinding, RouteError> {
    expected_interface.validate()?;
    platform::discover_route_on_interface(destination, expected_interface)
}

fn validate_discovered_binding(
    destination: IpAddr,
    expected_interface: Option<&InterfaceIdentity>,
    binding: &RouteBinding,
) -> Result<(), RouteError> {
    if destination.is_unspecified() || destination.is_multicast() {
        return Err(RouteError::InvalidPlan(
            "route lookup destination is not unicast",
        ));
    }
    if binding.source.is_ipv4() != destination.is_ipv4()
        || binding.next_hop.is_ipv4() != destination.is_ipv4()
        || binding.source.is_unspecified()
        || binding.source.is_multicast()
        || binding.next_hop.is_multicast()
    {
        return Err(RouteError::SnapshotEncoding);
    }
    if expected_interface.is_some_and(|expected| binding.interface != *expected) {
        return Err(RouteError::OwnershipMismatch("constrained route interface"));
    }
    Ok(())
}

/// Owns only routes installed by this process. Drop is a best-effort safety
/// net; normal shutdown should call `restore` so rollback errors are visible.
pub struct RouteTransaction {
    original: SystemNetworkSnapshot,
    recovery: RecoveryPlan,
    restored: bool,
}

impl RouteTransaction {
    pub fn install(plan: &RoutePlan) -> Result<Self, RouteError> {
        Self::install_recording(plan, |_| Ok(()))
    }

    pub fn install_recording(
        plan: &RoutePlan,
        mut record: impl FnMut(&RecoveryPlan) -> Result<(), RouteError>,
    ) -> Result<Self, RouteError> {
        plan.validate()?;
        let original = SystemNetworkSnapshot::capture()?;
        platform::verify_interface(&plan.tun_interface)?;
        let mut planned = plan.recovery_plan()?;
        for address in planned.interface_addresses() {
            platform::ensure_interface_address_absent(&plan.tun_interface, address)?;
        }
        let mut routes_to_create = Vec::with_capacity(planned.routes.len());
        for route in std::mem::take(&mut planned.routes) {
            platform::verify_interface(&route.interface)?;
            // An exact physical exclusion that predates startup is already
            // sufficient and must never be claimed or later deleted.
            if route.interface != plan.tun_interface && original.contains_owned_route(&route)? {
                continue;
            }
            platform::ensure_route_absent(&route)?;
            routes_to_create.push(route);
        }
        planned.routes = routes_to_create;
        platform::validate_shadow_route_priority(plan, planned.owned_routes())?;

        let mut recovery = RecoveryPlan {
            tun_interface: plan.tun_interface.clone(),
            interface_addresses: Vec::new(),
            routes: Vec::new(),
            interface_settings: Vec::new(),
            interface_address_states: Vec::new(),
            route_states: Vec::new(),
            interface_setting_states: Vec::new(),
        };

        for family in [IpFamily::V4, IpFamily::V6] {
            if (family == IpFamily::V4 && !plan.enable_ipv4)
                || (family == IpFamily::V6 && !plan.enable_ipv6)
            {
                continue;
            }
            match platform::plan_interface_configuration(
                &plan.tun_interface,
                family,
                plan.interface_mtu,
                plan.interface_metric,
            ) {
                Ok(Some(setting)) => {
                    let index = recovery.push_prepared_setting(setting.clone());
                    if record(&recovery).is_err() {
                        return Err(fail_after_rollback(
                            &recovery,
                            RouteError::JournalUpdateFailed,
                        ));
                    }
                    if let Err(error) =
                        platform::apply_interface_configuration(&plan.tun_interface, &setting)
                    {
                        return Err(fail_after_rollback(&recovery, error));
                    }
                    // From this point the in-memory state is authoritative even
                    // if the Applied journal transition itself fails.
                    recovery.mark_setting_applied(index);
                    if record(&recovery).is_err() {
                        return Err(fail_after_rollback(
                            &recovery,
                            RouteError::JournalUpdateFailed,
                        ));
                    }
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(fail_after_rollback(&recovery, error));
                }
            }
        }

        for address in planned.interface_addresses() {
            let index = recovery.push_prepared_address(address.clone());
            if record(&recovery).is_err() {
                return Err(fail_after_rollback(
                    &recovery,
                    RouteError::JournalUpdateFailed,
                ));
            }
            if let Err(error) = platform::create_interface_address(&plan.tun_interface, address) {
                return Err(fail_after_rollback(&recovery, error));
            }
            recovery.mark_address_applied(index);
            if record(&recovery).is_err() {
                return Err(fail_after_rollback(
                    &recovery,
                    RouteError::JournalUpdateFailed,
                ));
            }
            if let Err(error) = platform::wait_interface_address_ready(&plan.tun_interface, address)
            {
                return Err(fail_after_rollback(&recovery, error));
            }
        }
        for route in planned.owned_routes() {
            let index = recovery.push_prepared_route(route.clone());
            if record(&recovery).is_err() {
                return Err(fail_after_rollback(
                    &recovery,
                    RouteError::JournalUpdateFailed,
                ));
            }
            if let Err(error) = platform::add_route(route) {
                return Err(fail_after_rollback(&recovery, error));
            }
            recovery.mark_route_applied(index);
            if record(&recovery).is_err() {
                return Err(fail_after_rollback(
                    &recovery,
                    RouteError::JournalUpdateFailed,
                ));
            }
        }

        Ok(Self {
            original,
            recovery,
            restored: false,
        })
    }

    pub fn install_isolated(
        interface: InterfaceIdentity,
        addresses: Vec<InterfaceAddress>,
        routes: Vec<OwnedRoute>,
    ) -> Result<Self, RouteError> {
        interface.validate()?;
        if routes.iter().any(|route| {
            parse_network_prefix(&route.destination_prefix)
                .map(|(address, length)| {
                    route.interface != interface
                        || length != if address.is_ipv4() { 32 } else { 128 }
                })
                .unwrap_or(true)
        }) {
            return Err(RouteError::InvalidPlan(
                "isolated route transaction accepts only host routes",
            ));
        }
        let original = SystemNetworkSnapshot::capture()?;
        platform::verify_interface(&interface)?;
        for address in &addresses {
            validate_interface_address(Some(address), address.address.is_ipv4(), true)?;
            platform::ensure_interface_address_absent(&interface, address)?;
        }
        for route in &routes {
            platform::ensure_route_absent(route)?;
        }
        let mut recovery = RecoveryPlan {
            tun_interface: interface.clone(),
            interface_addresses: Vec::new(),
            routes: Vec::new(),
            interface_settings: Vec::new(),
            interface_address_states: Vec::new(),
            route_states: Vec::new(),
            interface_setting_states: Vec::new(),
        };
        for address in &addresses {
            if let Err(error) = platform::create_interface_address(&interface, address) {
                return Err(fail_after_rollback(&recovery, error));
            }
            let index = recovery.push_prepared_address(address.clone());
            recovery.mark_address_applied(index);
            if let Err(error) = platform::wait_interface_address_ready(&interface, address) {
                return Err(fail_after_rollback(&recovery, error));
            }
        }
        for route in &routes {
            if let Err(error) = platform::add_route(route) {
                return Err(fail_after_rollback(&recovery, error));
            }
            let index = recovery.push_prepared_route(route.clone());
            recovery.mark_route_applied(index);
        }
        Ok(Self {
            original,
            recovery,
            restored: false,
        })
    }

    pub fn original_snapshot(&self) -> &SystemNetworkSnapshot {
        &self.original
    }

    pub fn recovery_plan(&self) -> &RecoveryPlan {
        &self.recovery
    }

    pub fn restore(mut self) -> Result<SystemNetworkSnapshot, RouteError> {
        let result = self.recovery.restore_owned();
        self.restored = result.is_ok();
        result.map(|()| self.original.clone())
    }
}

impl Drop for RouteTransaction {
    fn drop(&mut self) {
        if !self.restored {
            let _ = self.recovery.restore_owned();
            self.restored = true;
        }
    }
}

fn fail_after_rollback(recovery: &RecoveryPlan, primary: RouteError) -> RouteError {
    match recovery.restore_owned() {
        Ok(()) => primary,
        Err(rollback) => rollback,
    }
}

fn should_restore_interface_setting(
    setting: &OwnedInterfaceSetting,
    current_mtu: u32,
    current_metric: u32,
    current_automatic_metric: bool,
) -> Result<bool, RouteError> {
    if current_mtu == setting.original_mtu
        && current_metric == setting.original_metric
        && current_automatic_metric == setting.original_automatic_metric
    {
        return Ok(false);
    }
    if current_mtu == setting.applied_mtu
        && current_metric == setting.applied_metric
        && !current_automatic_metric
    {
        return Ok(true);
    }
    Err(RouteError::OwnershipMismatch("interface configuration"))
}

fn verify_prepared_setting_unchanged(
    setting: &OwnedInterfaceSetting,
    current_mtu: u32,
    current_metric: u32,
    current_automatic_metric: bool,
) -> Result<(), RouteError> {
    if current_mtu == setting.original_mtu
        && current_metric == setting.original_metric
        && current_automatic_metric == setting.original_automatic_metric
    {
        Ok(())
    } else {
        Err(RouteError::OwnershipMismatch(
            "prepared interface configuration",
        ))
    }
}

fn verify_prepared_resource_absent(
    present: bool,
    resource: &'static str,
) -> Result<(), RouteError> {
    if present {
        Err(RouteError::OwnershipMismatch(resource))
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum RouteRestoreScope {
    All,
    AdapterOnly,
}

fn rollback(recovery: &RecoveryPlan, scope: RouteRestoreScope) -> Result<(), RouteError> {
    let route_failures = recovery
        .routes
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, route)| {
            matches!(scope, RouteRestoreScope::All) || recovery.adapter_owns_route(route)
        })
        .filter(|(index, route)| {
            match recovery.route_state(*index) {
                OwnershipState::Prepared => platform::verify_prepared_route_absent(route),
                OwnershipState::Applied => platform::remove_route(route),
            }
            .is_err()
        })
        .count();
    let address_failures = recovery
        .interface_addresses
        .iter()
        .enumerate()
        .rev()
        .filter(|(index, address)| {
            match recovery.address_state(*index) {
                OwnershipState::Prepared => {
                    platform::verify_prepared_address_absent(&recovery.tun_interface, address)
                }
                OwnershipState::Applied => {
                    platform::remove_interface_address(&recovery.tun_interface, address)
                }
            }
            .is_err()
        })
        .count();
    let setting_failures = recovery
        .interface_settings
        .iter()
        .enumerate()
        .rev()
        .filter(|(index, setting)| {
            match recovery.setting_state(*index) {
                OwnershipState::Prepared => platform::verify_prepared_interface_configuration(
                    &recovery.tun_interface,
                    setting,
                ),
                OwnershipState::Applied => {
                    platform::restore_interface_configuration(&recovery.tun_interface, setting)
                }
            }
            .is_err()
        })
        .count();
    let failed_routes = route_failures + address_failures + setting_failures;
    if failed_routes == 0 {
        Ok(())
    } else {
        Err(RouteError::RollbackFailed { failed_routes })
    }
}

fn validate_interface_address(
    address: Option<&InterfaceAddress>,
    ipv4: bool,
    enabled: bool,
) -> Result<(), RouteError> {
    let Some(address) = address else {
        return if enabled {
            Err(RouteError::InvalidPlan(
                "enabled address family has no Wintun interface address",
            ))
        } else {
            Ok(())
        };
    };
    if !enabled {
        return Err(RouteError::InvalidPlan(
            "disabled address family has a Wintun interface address",
        ));
    }
    if address.address.is_ipv4() != ipv4 {
        return Err(RouteError::InvalidPlan(
            "Wintun interface address has the wrong family",
        ));
    }
    let maximum = if ipv4 { 32 } else { 128 };
    if address.prefix_length == 0 || address.prefix_length > maximum {
        return Err(RouteError::InvalidPlan(
            "Wintun interface prefix length is invalid",
        ));
    }
    if address.address.is_unspecified()
        || address.address.is_multicast()
        || address.address.is_loopback()
    {
        return Err(RouteError::InvalidPlan(
            "Wintun interface address is not unicast",
        ));
    }
    Ok(())
}

fn route_specs(plan: &RoutePlan) -> Vec<OwnedRoute> {
    let mut routes =
        Vec::with_capacity(4 + plan.shadow_capture_prefixes.len() + plan.exclusions.len());
    if plan.enable_ipv4 {
        routes.extend(CAPTURE_V4_PREFIXES.map(|prefix| OwnedRoute {
            destination_prefix: prefix.to_owned(),
            interface: plan.tun_interface.clone(),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            metric: plan.metric,
        }));
    }
    if plan.enable_ipv6 {
        routes.extend(CAPTURE_V6_PREFIXES.map(|prefix| OwnedRoute {
            destination_prefix: prefix.to_owned(),
            interface: plan.tun_interface.clone(),
            next_hop: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            metric: plan.metric,
        }));
    }
    routes.extend(
        plan.shadow_capture_prefixes
            .iter()
            .map(|prefix| OwnedRoute {
                destination_prefix: prefix.clone(),
                interface: plan.tun_interface.clone(),
                next_hop: if prefix.contains(':') {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                } else {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                },
                metric: plan.metric,
            }),
    );
    routes.extend(plan.exclusions.iter().map(|exclusion| OwnedRoute {
        destination_prefix: match exclusion.destination {
            IpAddr::V4(address) => format!("{address}/32"),
            IpAddr::V6(address) => format!("{address}/128"),
        },
        interface: exclusion.physical_interface.clone(),
        next_hop: exclusion.physical_gateway,
        metric: 1,
    }));
    routes
}

fn snapshot_rows(value: &serde_json::Value) -> Result<&[serde_json::Value], RouteError> {
    match value {
        serde_json::Value::Array(values) => Ok(values.as_slice()),
        serde_json::Value::Object(_) => Ok(std::slice::from_ref(value)),
        serde_json::Value::Null => Ok(&[]),
        _ => Err(RouteError::SnapshotEncoding),
    }
}

fn strict_snapshot_rows(value: &serde_json::Value) -> Result<&[serde_json::Value], RouteError> {
    match value {
        serde_json::Value::Array(values) => Ok(values.as_slice()),
        serde_json::Value::Object(_) => Ok(std::slice::from_ref(value)),
        _ => Err(RouteError::SnapshotEncoding),
    }
}

fn snapshot_str<'a>(row: &'a serde_json::Value, field: &str) -> Result<&'a str, RouteError> {
    row.get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or(RouteError::SnapshotEncoding)
}

fn snapshot_u64(row: &serde_json::Value, field: &str) -> Result<u64, RouteError> {
    row.get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or(RouteError::SnapshotEncoding)
}

fn snapshot_u32(row: &serde_json::Value, field: &str) -> Result<u32, RouteError> {
    snapshot_u64(row, field)?
        .try_into()
        .map_err(|_| RouteError::SnapshotEncoding)
}

fn parse_network_prefix(value: &str) -> Result<(IpAddr, u8), RouteError> {
    let (address, length) = value.split_once('/').ok_or(RouteError::SnapshotEncoding)?;
    if length.contains('/') {
        return Err(RouteError::SnapshotEncoding);
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| RouteError::SnapshotEncoding)?;
    let length = length
        .parse::<u8>()
        .map_err(|_| RouteError::SnapshotEncoding)?;
    let network = match address {
        IpAddr::V4(address) if length <= 32 => {
            let mask = if length == 0 {
                0
            } else {
                u32::MAX << (32 - length)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
        }
        IpAddr::V6(address) if length <= 128 => {
            let mask = if length == 0 {
                0
            } else {
                u128::MAX << (128 - length)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
        }
        _ => return Err(RouteError::SnapshotEncoding),
    };
    Ok((network, length))
}

fn format_network_prefix(network: IpAddr, length: u8) -> String {
    format!("{network}/{length}")
}

fn is_loopback_prefix(network: IpAddr, length: u8) -> bool {
    match network {
        IpAddr::V4(address) => length >= 8 && address.octets()[0] == 127,
        IpAddr::V6(address) => length == 128 && address == Ipv6Addr::LOCALHOST,
    }
}

fn shadow_prefixes_for(network: IpAddr, length: u8) -> Vec<String> {
    match network {
        IpAddr::V4(network) if length < 32 => {
            let child_length = length + 1;
            let first = u32::from(network);
            let second = first | (1_u32 << (32 - child_length));
            vec![
                format!("{}/{}", Ipv4Addr::from(first), child_length),
                format!("{}/{}", Ipv4Addr::from(second), child_length),
            ]
        }
        IpAddr::V6(network) if length < 128 => {
            let child_length = length + 1;
            let first = u128::from(network);
            let second = first | (1_u128 << (128 - child_length));
            vec![
                format!("{}/{}", Ipv6Addr::from(first), child_length),
                format!("{}/{}", Ipv6Addr::from(second), child_length),
            ]
        }
        _ => vec![format_network_prefix(network, length)],
    }
}

#[cfg(windows)]
fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(windows)]
mod platform {
    use super::{
        InterfaceAddress, InterfaceIdentity, IpFamily, MAX_SNAPSHOT_SECTION_BYTES,
        OwnedInterfaceSetting, OwnedRoute, PhysicalInterface, RouteBinding, RouteError, RoutePlan,
        SystemNetworkSnapshot, format_network_prefix, now_unix_ms, parse_network_prefix,
        should_restore_interface_setting, validate_discovered_binding,
        verify_prepared_resource_absent, verify_prepared_setting_unchanged,
    };
    use serde_json::{Value, json};
    use std::ffi::c_void;
    use std::mem::size_of;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::ptr::{addr_of, null, null_mut};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_TIMEOUT, NO_ERROR,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, ConvertInterfaceLuidToGuid,
        CreateIpForwardEntry2, CreateUnicastIpAddressEntry, DeleteIpForwardEntry2,
        DeleteUnicastIpAddressEntry, FreeMibTable, GAA_FLAG_INCLUDE_ALL_INTERFACES,
        GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses, GetBestRoute2,
        GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressEntry,
        GetUnicastIpAddressTable, IP_ADAPTER_ADDRESSES_LH, InitializeIpForwardEntry,
        InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
        MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
        MIB_UNICASTIPADDRESS_TABLE, SetIpInterfaceEntry,
    };
    use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
    use windows_sys::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, IN_ADDR, IN6_ADDR, IpDadStatePreferred, IpDadStateTentative,
        IpPrefixOriginManual, IpSuffixOriginManual, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6,
        SOCKADDR_INET, SOCKET_ADDRESS,
    };
    use windows_sys::core::GUID;

    const MAX_TABLE_ENTRIES: usize = 65_536;
    const MAX_ADAPTER_CHAIN: usize = 8_192;
    const ADDRESS_READY_TIMEOUT: Duration = Duration::from_secs(12);
    const ADDRESS_READY_POLL_INTERVAL: Duration = Duration::from_millis(500);

    pub(super) fn capture_snapshot() -> Result<SystemNetworkSnapshot, RouteError> {
        let adapters = adapter_records()?;
        let routes = route_rows()?;
        let adapters_json = serde_json::to_string(&adapter_snapshot_json(&adapters))
            .map_err(|_| RouteError::SnapshotEncoding)?;
        let route_values = routes
            .iter()
            .map(route_row_json)
            .collect::<Option<Vec<_>>>()
            .ok_or(RouteError::SnapshotEncoding)?;
        let routes_json =
            serde_json::to_string(&route_values).map_err(|_| RouteError::SnapshotEncoding)?;
        let dns_json = serde_json::to_string(
            &adapters
                .iter()
                .map(|adapter| {
                    json!({
                        "InterfaceIndex": adapter.identity.interface_index,
                        "InterfaceLuid": adapter.identity.interface_luid,
                        "AddressFamily": "unspecified",
                        "ServerAddresses": adapter.dns_servers,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .map_err(|_| RouteError::SnapshotEncoding)?;
        if adapters_json.len() > MAX_SNAPSHOT_SECTION_BYTES
            || routes_json.len() > MAX_SNAPSHOT_SECTION_BYTES
            || dns_json.len() > MAX_SNAPSHOT_SECTION_BYTES
        {
            return Err(RouteError::SnapshotTooLarge);
        }
        Ok(SystemNetworkSnapshot {
            captured_unix_ms: now_unix_ms(),
            adapters_json,
            routes_json,
            dns_json,
        })
    }

    pub(super) fn discover_primary_physical_interface(
        excluded_interface_index: Option<u32>,
    ) -> Result<PhysicalInterface, RouteError> {
        let (ipv4, ipv4_metric) = best_route(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))?;
        if excluded_interface_index == Some(ipv4.interface.interface_index) {
            return Err(RouteError::InvalidPlan(
                "physical interface discovery selected the TUN interface",
            ));
        }
        let adapters = adapter_records()?;
        let adapter = adapters
            .iter()
            .find(|adapter| adapter.identity == ipv4.interface)
            .ok_or(RouteError::DiscoveryFailed {
                operation: "physical adapter enumeration",
                code: ERROR_NOT_FOUND,
            })?;
        let ipv6 = best_route(
            "2606:4700:4700::1111"
                .parse()
                .map_err(|_| RouteError::SnapshotEncoding)?,
        )
        .ok()
        .map(|(binding, _)| binding)
        .filter(|binding| binding.interface == ipv4.interface);
        Ok(PhysicalInterface {
            identity: ipv4.interface,
            ipv4_source: match ipv4.source {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            },
            ipv6_source: ipv6.as_ref().and_then(|binding| match binding.source {
                IpAddr::V6(address) => Some(address),
                IpAddr::V4(_) => None,
            }),
            ipv4_gateway: match ipv4.next_hop {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            },
            ipv6_gateway: ipv6.and_then(|binding| match binding.next_hop {
                IpAddr::V6(address) => Some(address),
                IpAddr::V4(_) => None,
            }),
            dns_servers: adapter.dns_servers.clone(),
            route_metric: ipv4_metric,
        })
    }

    pub(super) fn discover_route_to(
        destination: IpAddr,
        excluded_interface_index: Option<u32>,
    ) -> Result<RouteBinding, RouteError> {
        let (found, _) = best_route(destination)?;
        if excluded_interface_index == Some(found.interface.interface_index) {
            return Err(RouteError::InvalidPlan(
                "management route discovery selected the TUN interface",
            ));
        }
        validate_discovered_binding(destination, None, &found)?;
        Ok(found)
    }

    pub(super) fn discover_route_on_interface(
        destination: IpAddr,
        expected_interface: &InterfaceIdentity,
    ) -> Result<RouteBinding, RouteError> {
        verify_interface(expected_interface)?;
        let (found, _) = best_route_constrained(destination, expected_interface)?;
        validate_discovered_binding(destination, Some(expected_interface), &found)?;
        Ok(found)
    }

    pub(super) fn add_route(route: &OwnedRoute) -> Result<(), RouteError> {
        verify_interface(&route.interface)?;
        // Recheck immediately before the atomic create. The initial planning
        // check can be stale after the Prepared journal write.
        ensure_route_absent(route)?;
        let row = owned_route_row(route)?;
        let status = unsafe { CreateIpForwardEntry2(&row) };
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(RouteError::CommandFailed {
                operation: "route installation",
                code: status,
            })
        }
    }

    pub(super) fn create_interface_address(
        interface: &InterfaceIdentity,
        address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        verify_interface(interface)?;
        // Recheck immediately before the atomic create. If another actor won
        // this race, the Prepared record remains conservative and recovery
        // will not claim the exact address.
        ensure_interface_address_absent(interface, address)?;
        let row = owned_address_row(interface, address);
        let status = unsafe { CreateUnicastIpAddressEntry(&row) };
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(RouteError::CommandFailed {
                operation: "Wintun address installation",
                code: status,
            })
        }
    }

    pub(super) fn wait_interface_address_ready(
        interface: &InterfaceIdentity,
        address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        verify_interface(interface)?;
        let deadline = Instant::now() + ADDRESS_READY_TIMEOUT;
        loop {
            let mut row = owned_address_row(interface, address);
            let status = unsafe { GetUnicastIpAddressEntry(&mut row) };
            if status != NO_ERROR {
                return Err(RouteError::DiscoveryFailed {
                    operation: "Wintun address readiness lookup",
                    code: status,
                });
            }
            match row.DadState {
                state if state == IpDadStatePreferred => return Ok(()),
                state if state == IpDadStateTentative => {
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return Err(RouteError::CommandFailed {
                            operation: "Wintun address duplicate detection timeout",
                            code: ERROR_TIMEOUT,
                        });
                    };
                    std::thread::sleep(remaining.min(ADDRESS_READY_POLL_INTERVAL));
                }
                state => {
                    return Err(RouteError::CommandFailed {
                        operation: "Wintun address duplicate detection",
                        code: u32::try_from(state).unwrap_or(u32::MAX),
                    });
                }
            }
        }
    }

    pub(super) fn verify_prepared_address_absent(
        interface: &InterfaceIdentity,
        address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        if !interface_is_current(interface)? {
            return Ok(());
        }
        let present = unicast_rows()?
            .iter()
            .any(|row| address_row_matches(row, interface, address, false));
        verify_prepared_resource_absent(present, "prepared interface address")
    }

    pub(super) fn remove_interface_address(
        interface: &InterfaceIdentity,
        address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        if !interface_is_current(interface)? {
            return Ok(());
        }
        let rows = unicast_rows()?;
        let Some(row) = rows
            .iter()
            .find(|row| address_row_matches(row, interface, address, true))
            .copied()
        else {
            return if rows
                .iter()
                .any(|row| address_row_matches(row, interface, address, false))
            {
                Err(RouteError::OwnershipMismatch("interface address"))
            } else {
                Ok(())
            };
        };
        let status = unsafe { DeleteUnicastIpAddressEntry(&row) };
        if status == NO_ERROR || is_not_found(status) {
            Ok(())
        } else {
            Err(RouteError::CommandFailed {
                operation: "Wintun address removal",
                code: status,
            })
        }
    }

    pub(super) fn remove_route(route: &OwnedRoute) -> Result<(), RouteError> {
        if !interface_is_current(&route.interface)? {
            return Ok(());
        }
        let rows = route_rows()?;
        let Some(row) = rows
            .iter()
            .find(|row| route_row_matches(row, route, true))
            .copied()
        else {
            return if rows.iter().any(|row| route_row_matches(row, route, false)) {
                Err(RouteError::OwnershipMismatch("route"))
            } else {
                Ok(())
            };
        };
        let status = unsafe { DeleteIpForwardEntry2(&row) };
        if status == NO_ERROR || is_not_found(status) {
            Ok(())
        } else {
            Err(RouteError::CommandFailed {
                operation: "route removal",
                code: status,
            })
        }
    }

    pub(super) fn verify_prepared_route_absent(route: &OwnedRoute) -> Result<(), RouteError> {
        if !interface_is_current(&route.interface)? {
            return Ok(());
        }
        let present = route_rows()?
            .iter()
            .any(|row| route_row_matches(row, route, false));
        verify_prepared_resource_absent(present, "prepared route")
    }

    pub(super) fn ensure_interface_address_absent(
        interface: &InterfaceIdentity,
        address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        verify_interface(interface)?;
        if unicast_rows()?
            .iter()
            .any(|row| address_row_matches(row, interface, address, false))
        {
            Err(RouteError::ResourceConflict("interface address"))
        } else {
            Ok(())
        }
    }

    pub(super) fn ensure_route_absent(route: &OwnedRoute) -> Result<(), RouteError> {
        verify_interface(&route.interface)?;
        if route_rows()?
            .iter()
            .any(|row| route_row_matches(row, route, false))
        {
            Err(RouteError::ResourceConflict("route"))
        } else {
            Ok(())
        }
    }

    pub(super) fn validate_shadow_route_priority(
        plan: &RoutePlan,
        planned_routes: &[OwnedRoute],
    ) -> Result<(), RouteError> {
        let existing = route_rows()?;
        let planned_total = plan.metric.saturating_add(plan.interface_metric);
        for planned in planned_routes.iter().filter(|route| {
            route.interface == plan.tun_interface
                && parse_network_prefix(&route.destination_prefix).is_ok_and(|(address, length)| {
                    length == if address.is_ipv4() { 32 } else { 128 }
                })
        }) {
            for row in existing.iter().filter(|row| {
                row_prefix(row).is_some_and(|prefix| prefix == planned.destination_prefix)
                    && unsafe { row.InterfaceLuid.Value } != plan.tun_interface.interface_luid
            }) {
                let identity = resolve_interface_identity(row.InterfaceIndex)?;
                let family = if planned.destination_prefix.contains(':') {
                    IpFamily::V6
                } else {
                    IpFamily::V4
                };
                let interface_row = get_interface_row(&identity, family)?;
                let existing_total = row.Metric.saturating_add(interface_row.Metric);
                if planned_total >= existing_total {
                    return Err(RouteError::InvalidPlan(
                        "Wintun host shadow route would not outrank an existing route",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(super) fn plan_interface_configuration(
        interface: &InterfaceIdentity,
        family: IpFamily,
        mtu: u32,
        metric: u32,
    ) -> Result<Option<OwnedInterfaceSetting>, RouteError> {
        verify_interface(interface)?;
        let row = get_interface_row(interface, family)?;
        if row.NlMtu == mtu && row.Metric == metric && !row.UseAutomaticMetric {
            return Ok(None);
        }
        Ok(Some(OwnedInterfaceSetting {
            family,
            original_mtu: row.NlMtu,
            original_metric: row.Metric,
            original_automatic_metric: row.UseAutomaticMetric,
            applied_mtu: mtu,
            applied_metric: metric,
        }))
    }

    pub(super) fn apply_interface_configuration(
        interface: &InterfaceIdentity,
        setting: &OwnedInterfaceSetting,
    ) -> Result<(), RouteError> {
        verify_interface(interface)?;
        // Use a fresh row after the Prepared journal commit and reject any
        // concurrent change to the fields this transaction intends to own.
        let mut row = get_interface_row(interface, setting.family)?;
        if row.NlMtu != setting.original_mtu
            || row.Metric != setting.original_metric
            || row.UseAutomaticMetric != setting.original_automatic_metric
        {
            return Err(RouteError::OwnershipMismatch(
                "prepared interface configuration",
            ));
        }
        row.NlMtu = setting.applied_mtu;
        row.Metric = setting.applied_metric;
        row.UseAutomaticMetric = false;
        let status = unsafe { SetIpInterfaceEntry(&mut row) };
        if status == NO_ERROR {
            Ok(())
        } else {
            Err(RouteError::CommandFailed {
                operation: "Wintun interface configuration",
                code: status,
            })
        }
    }

    pub(super) fn verify_prepared_interface_configuration(
        interface: &InterfaceIdentity,
        setting: &OwnedInterfaceSetting,
    ) -> Result<(), RouteError> {
        if !interface_is_current(interface)? {
            return Ok(());
        }
        let row = get_interface_row(interface, setting.family)?;
        verify_prepared_setting_unchanged(setting, row.NlMtu, row.Metric, row.UseAutomaticMetric)
    }

    pub(super) fn restore_interface_configuration(
        interface: &InterfaceIdentity,
        setting: &OwnedInterfaceSetting,
    ) -> Result<(), RouteError> {
        if !interface_is_current(interface)? {
            return Ok(());
        }
        let mut row = get_interface_row(interface, setting.family)?;
        if !should_restore_interface_setting(
            setting,
            row.NlMtu,
            row.Metric,
            row.UseAutomaticMetric,
        )? {
            return Ok(());
        }
        row.NlMtu = setting.original_mtu;
        row.Metric = setting.original_metric;
        row.UseAutomaticMetric = setting.original_automatic_metric;
        let status = unsafe { SetIpInterfaceEntry(&mut row) };
        if status == NO_ERROR || is_not_found(status) {
            Ok(())
        } else {
            Err(RouteError::CommandFailed {
                operation: "Wintun interface restoration",
                code: status,
            })
        }
    }

    pub(super) fn resolve_interface_identity(
        interface_index: u32,
    ) -> Result<InterfaceIdentity, RouteError> {
        resolve_interface_identity_optional(interface_index)?.ok_or(RouteError::DiscoveryFailed {
            operation: "interface identity lookup",
            code: ERROR_NOT_FOUND,
        })
    }

    pub(super) fn find_interface_by_alias(
        alias: &str,
    ) -> Result<Option<InterfaceIdentity>, RouteError> {
        if alias.is_empty() || alias.chars().any(char::is_control) {
            return Err(RouteError::InvalidPlan("interface alias is invalid"));
        }
        Ok(adapter_records()?
            .into_iter()
            .find(|adapter| adapter.identity.alias == alias)
            .map(|adapter| adapter.identity))
    }

    pub(super) fn find_interface_by_luid(
        interface_luid: u64,
    ) -> Result<Option<InterfaceIdentity>, RouteError> {
        if interface_luid == 0 {
            return Err(RouteError::InvalidPlan("interface LUID is zero"));
        }
        Ok(adapter_records()?
            .into_iter()
            .find(|adapter| adapter.identity.interface_luid == interface_luid)
            .map(|adapter| adapter.identity))
    }

    pub(super) fn verify_interface(interface: &InterfaceIdentity) -> Result<(), RouteError> {
        interface.validate()?;
        if interface_is_current(interface)? {
            Ok(())
        } else {
            Err(RouteError::OwnershipMismatch("interface"))
        }
    }

    fn interface_is_current(interface: &InterfaceIdentity) -> Result<bool, RouteError> {
        match resolve_interface_identity_optional(interface.interface_index)? {
            None => Ok(false),
            Some(current) if current == *interface => Ok(true),
            Some(_) => Err(RouteError::OwnershipMismatch("interface")),
        }
    }

    fn resolve_interface_identity_optional(
        interface_index: u32,
    ) -> Result<Option<InterfaceIdentity>, RouteError> {
        if interface_index == 0 {
            return Ok(None);
        }
        let mut luid = NET_LUID_LH::default();
        let status = unsafe { ConvertInterfaceIndexToLuid(interface_index, &mut luid) };
        if is_not_found(status) {
            return Ok(None);
        }
        if status != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "interface LUID lookup",
                code: status,
            });
        }
        let mut guid = GUID::default();
        let status = unsafe { ConvertInterfaceLuidToGuid(&luid, &mut guid) };
        if status != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "interface GUID lookup",
                code: status,
            });
        }
        let mut alias = [0_u16; 257];
        let status = unsafe { ConvertInterfaceLuidToAlias(&luid, alias.as_mut_ptr(), alias.len()) };
        if status != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "interface alias lookup",
                code: status,
            });
        }
        let alias_length = alias
            .iter()
            .position(|value| *value == 0)
            .unwrap_or(alias.len());
        let identity = InterfaceIdentity {
            interface_index,
            interface_luid: unsafe { luid.Value },
            interface_guid: guid_string(guid),
            alias: String::from_utf16(&alias[..alias_length])
                .map_err(|_| RouteError::SnapshotEncoding)?,
        };
        identity.validate()?;
        Ok(Some(identity))
    }

    fn best_route(destination: IpAddr) -> Result<(RouteBinding, u32), RouteError> {
        best_route_impl(destination, None)
    }

    fn best_route_constrained(
        destination: IpAddr,
        expected_interface: &InterfaceIdentity,
    ) -> Result<(RouteBinding, u32), RouteError> {
        best_route_impl(destination, Some(expected_interface))
    }

    fn best_route_impl(
        destination: IpAddr,
        expected_interface: Option<&InterfaceIdentity>,
    ) -> Result<(RouteBinding, u32), RouteError> {
        let destination_address = sockaddr_from_ip(destination, 0);
        let mut route = MIB_IPFORWARD_ROW2::default();
        let mut source = SOCKADDR_INET::default();
        let constrained_luid = expected_interface.map(|interface| luid(interface.interface_luid));
        let interface_luid = constrained_luid
            .as_ref()
            .map_or(null(), |value| value as *const NET_LUID_LH);
        let interface_index = expected_interface
            .map(|interface| interface.interface_index)
            .unwrap_or(0);
        let status = unsafe {
            GetBestRoute2(
                interface_luid,
                interface_index,
                null(),
                &destination_address,
                0,
                &mut route,
                &mut source,
            )
        };
        if status != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "best-route lookup",
                code: status,
            });
        }
        let interface = resolve_interface_identity(route.InterfaceIndex)?;
        if unsafe { route.InterfaceLuid.Value } != interface.interface_luid {
            return Err(RouteError::OwnershipMismatch("best-route interface"));
        }
        if expected_interface.is_some_and(|expected| interface != *expected) {
            return Err(RouteError::OwnershipMismatch(
                "constrained best-route interface",
            ));
        }
        let source = ip_from_sockaddr(&source).ok_or(RouteError::SnapshotEncoding)?;
        let next_hop = ip_from_sockaddr(&route.NextHop).ok_or(RouteError::SnapshotEncoding)?;
        Ok((
            RouteBinding {
                interface,
                source,
                next_hop,
            },
            route.Metric,
        ))
    }

    fn owned_route_row(route: &OwnedRoute) -> Result<MIB_IPFORWARD_ROW2, RouteError> {
        let (network, length) = parse_network_prefix(&route.destination_prefix)?;
        if format_network_prefix(network, length) != route.destination_prefix
            || route.next_hop.is_ipv4() != network.is_ipv4()
        {
            return Err(RouteError::InvalidPlan(
                "owned route fields are inconsistent",
            ));
        }
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = luid(route.interface.interface_luid);
        row.InterfaceIndex = route.interface.interface_index;
        row.DestinationPrefix.Prefix = sockaddr_from_ip(network, 0);
        row.DestinationPrefix.PrefixLength = length;
        row.NextHop = sockaddr_from_ip(route.next_hop, route.interface.interface_index);
        row.Metric = route.metric;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        Ok(row)
    }

    fn owned_address_row(
        interface: &InterfaceIdentity,
        address: &InterfaceAddress,
    ) -> MIB_UNICASTIPADDRESS_ROW {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe { InitializeUnicastIpAddressEntry(&mut row) };
        row.Address = sockaddr_from_ip(address.address, interface.interface_index);
        row.InterfaceLuid = luid(interface.interface_luid);
        row.InterfaceIndex = interface.interface_index;
        row.PrefixOrigin = IpPrefixOriginManual;
        row.SuffixOrigin = IpSuffixOriginManual;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        row.OnLinkPrefixLength = address.prefix_length;
        row
    }

    fn get_interface_row(
        interface: &InterfaceIdentity,
        family: IpFamily,
    ) -> Result<MIB_IPINTERFACE_ROW, RouteError> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = match family {
            IpFamily::V4 => AF_INET,
            IpFamily::V6 => AF_INET6,
        };
        row.InterfaceLuid = luid(interface.interface_luid);
        row.InterfaceIndex = interface.interface_index;
        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status == NO_ERROR {
            Ok(row)
        } else {
            Err(RouteError::DiscoveryFailed {
                operation: "IP interface lookup",
                code: status,
            })
        }
    }

    fn route_rows() -> Result<Vec<MIB_IPFORWARD_ROW2>, RouteError> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
        let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) };
        if status != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "route table enumeration",
                code: status,
            });
        }
        if table.is_null() {
            return Ok(Vec::new());
        }
        let count = unsafe { (*table).NumEntries as usize };
        if count > MAX_TABLE_ENTRIES {
            unsafe { FreeMibTable(table.cast::<c_void>()) };
            return Err(RouteError::SnapshotTooLarge);
        }
        let first = unsafe { addr_of!((*table).Table).cast::<MIB_IPFORWARD_ROW2>() };
        let rows = unsafe { std::slice::from_raw_parts(first, count) }.to_vec();
        unsafe { FreeMibTable(table.cast::<c_void>()) };
        Ok(rows)
    }

    fn unicast_rows() -> Result<Vec<MIB_UNICASTIPADDRESS_ROW>, RouteError> {
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = null_mut();
        let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
        if status != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "unicast address enumeration",
                code: status,
            });
        }
        if table.is_null() {
            return Ok(Vec::new());
        }
        let count = unsafe { (*table).NumEntries as usize };
        if count > MAX_TABLE_ENTRIES {
            unsafe { FreeMibTable(table.cast::<c_void>()) };
            return Err(RouteError::SnapshotTooLarge);
        }
        let first = unsafe { addr_of!((*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>() };
        let rows = unsafe { std::slice::from_raw_parts(first, count) }.to_vec();
        unsafe { FreeMibTable(table.cast::<c_void>()) };
        Ok(rows)
    }

    fn route_row_matches(row: &MIB_IPFORWARD_ROW2, route: &OwnedRoute, exact_metric: bool) -> bool {
        (unsafe { row.InterfaceLuid.Value }) == route.interface.interface_luid
            && row.InterfaceIndex == route.interface.interface_index
            && row_prefix(row).as_deref() == Some(route.destination_prefix.as_str())
            && ip_from_sockaddr(&row.NextHop) == Some(route.next_hop)
            && (!exact_metric
                || (row.Metric == route.metric && row.Protocol == MIB_IPPROTO_NETMGMT))
    }

    fn address_row_matches(
        row: &MIB_UNICASTIPADDRESS_ROW,
        interface: &InterfaceIdentity,
        address: &InterfaceAddress,
        exact_prefix: bool,
    ) -> bool {
        (unsafe { row.InterfaceLuid.Value }) == interface.interface_luid
            && row.InterfaceIndex == interface.interface_index
            && ip_from_sockaddr(&row.Address) == Some(address.address)
            && (!exact_prefix || row.OnLinkPrefixLength == address.prefix_length)
            && (!exact_prefix
                || (row.PrefixOrigin == IpPrefixOriginManual
                    && row.SuffixOrigin == IpSuffixOriginManual))
    }

    fn row_prefix(row: &MIB_IPFORWARD_ROW2) -> Option<String> {
        ip_from_sockaddr(&row.DestinationPrefix.Prefix)
            .map(|address| format_network_prefix(address, row.DestinationPrefix.PrefixLength))
    }

    fn route_row_json(row: &MIB_IPFORWARD_ROW2) -> Option<Value> {
        let prefix = row_prefix(row)?;
        let next_hop = ip_from_sockaddr(&row.NextHop)?;
        Some(json!({
            "AddressFamily": if next_hop.is_ipv4() { "IPv4" } else { "IPv6" },
            "DestinationPrefix": prefix,
            "NextHop": next_hop.to_string(),
            "InterfaceIndex": row.InterfaceIndex,
            "InterfaceLuid": unsafe { row.InterfaceLuid.Value },
            "RouteMetric": row.Metric,
            "Protocol": row.Protocol,
            "PolicyStore": "active",
        }))
    }

    #[derive(Debug)]
    struct AdapterRecord {
        identity: InterfaceIdentity,
        mtu: u32,
        oper_status: i32,
        ipv4_metric: u32,
        ipv6_metric: u32,
        unicast_addresses: Vec<(IpAddr, u8)>,
        gateways: Vec<IpAddr>,
        dns_servers: Vec<IpAddr>,
    }

    fn adapter_records() -> Result<Vec<AdapterRecord>, RouteError> {
        let flags =
            GAA_FLAG_INCLUDE_ALL_INTERFACES | GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_INCLUDE_PREFIX;
        let mut byte_count = 0_u32;
        let initial = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                null(),
                null_mut(),
                &mut byte_count,
            )
        };
        if initial != ERROR_BUFFER_OVERFLOW && initial != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "adapter enumeration sizing",
                code: initial,
            });
        }
        if byte_count == 0 {
            return Ok(Vec::new());
        }
        if byte_count as usize > MAX_SNAPSHOT_SECTION_BYTES {
            return Err(RouteError::SnapshotTooLarge);
        }
        let word_count = (byte_count as usize).div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; word_count];
        let first = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let status = unsafe {
            GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, null(), first, &mut byte_count)
        };
        if status != NO_ERROR {
            return Err(RouteError::DiscoveryFailed {
                operation: "adapter enumeration",
                code: status,
            });
        }
        let mut records = Vec::new();
        let mut current = first;
        for _ in 0..MAX_ADAPTER_CHAIN {
            if current.is_null() {
                break;
            }
            let adapter = unsafe { &*current };
            let ipv4_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            let interface_index = if ipv4_index != 0 {
                ipv4_index
            } else {
                adapter.Ipv6IfIndex
            };
            if interface_index != 0 {
                let identity = resolve_interface_identity(interface_index)?;
                if identity.interface_luid != unsafe { adapter.Luid.Value } {
                    return Err(RouteError::OwnershipMismatch("enumerated adapter"));
                }
                records.push(AdapterRecord {
                    identity,
                    mtu: adapter.Mtu,
                    oper_status: adapter.OperStatus,
                    ipv4_metric: adapter.Ipv4Metric,
                    ipv6_metric: adapter.Ipv6Metric,
                    unicast_addresses: collect_address_chain(
                        adapter.FirstUnicastAddress,
                        |entry| {
                            socket_address_to_ip(entry.Address)
                                .map(|address| (address, entry.OnLinkPrefixLength))
                        },
                    )?,
                    gateways: collect_address_chain(adapter.FirstGatewayAddress, |entry| {
                        socket_address_to_ip(entry.Address)
                    })?,
                    dns_servers: collect_address_chain(adapter.FirstDnsServerAddress, |entry| {
                        socket_address_to_ip(entry.Address)
                    })?,
                });
            }
            current = adapter.Next;
        }
        if !current.is_null() {
            return Err(RouteError::SnapshotTooLarge);
        }
        Ok(records)
    }

    fn adapter_snapshot_json(adapters: &[AdapterRecord]) -> Vec<Value> {
        adapters
            .iter()
            .map(|adapter| {
                json!({
                    "Name": adapter.identity.alias,
                    "InterfaceIndex": adapter.identity.interface_index,
                    "InterfaceLuid": adapter.identity.interface_luid,
                    "InterfaceGuid": adapter.identity.interface_guid,
                    "Mtu": adapter.mtu,
                    "OperStatus": adapter.oper_status,
                    "Ipv4Metric": adapter.ipv4_metric,
                    "Ipv6Metric": adapter.ipv6_metric,
                    "UnicastAddresses": adapter
                        .unicast_addresses
                        .iter()
                        .map(|(address, prefix)| format!("{address}/{prefix}"))
                        .collect::<Vec<_>>(),
                    "Gateways": adapter.gateways,
                })
            })
            .collect()
    }

    fn collect_address_chain<T, U>(
        mut current: *mut T,
        mut convert: impl FnMut(&T) -> Option<U>,
    ) -> Result<Vec<U>, RouteError>
    where
        T: AddressNode,
    {
        let mut values = Vec::new();
        for _ in 0..MAX_ADAPTER_CHAIN {
            if current.is_null() {
                break;
            }
            let entry = unsafe { &*current };
            if let Some(value) = convert(entry) {
                values.push(value);
            }
            current = entry.next();
        }
        if !current.is_null() {
            return Err(RouteError::SnapshotTooLarge);
        }
        Ok(values)
    }

    trait AddressNode {
        fn next(&self) -> *mut Self;
    }

    impl AddressNode
        for windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH
    {
        fn next(&self) -> *mut Self {
            self.Next
        }
    }

    impl AddressNode
        for windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_GATEWAY_ADDRESS_LH
    {
        fn next(&self) -> *mut Self {
            self.Next
        }
    }

    impl AddressNode
        for windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_DNS_SERVER_ADDRESS_XP
    {
        fn next(&self) -> *mut Self {
            self.Next
        }
    }

    fn socket_address_to_ip(address: SOCKET_ADDRESS) -> Option<IpAddr> {
        if address.lpSockaddr.is_null() {
            return None;
        }
        let family = unsafe { (*address.lpSockaddr).sa_family };
        match family {
            AF_INET if address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN>() => {
                let value = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN>() };
                Some(IpAddr::V4(Ipv4Addr::from(
                    unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes(),
                )))
            }
            AF_INET6 if address.iSockaddrLength as usize >= size_of::<SOCKADDR_IN6>() => {
                let value = unsafe { &*address.lpSockaddr.cast::<SOCKADDR_IN6>() };
                Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                    value.sin6_addr.u.Byte
                })))
            }
            _ => None,
        }
    }

    fn sockaddr_from_ip(address: IpAddr, scope_id: u32) -> SOCKADDR_INET {
        let mut value = SOCKADDR_INET::default();
        match address {
            IpAddr::V4(address) => {
                let mut socket = SOCKADDR_IN::default();
                socket.sin_family = AF_INET;
                socket.sin_addr = IN_ADDR::default();
                socket.sin_addr.S_un.S_addr = u32::from_ne_bytes(address.octets());
                value.Ipv4 = socket;
            }
            IpAddr::V6(address) => {
                let mut socket = SOCKADDR_IN6::default();
                socket.sin6_family = AF_INET6;
                socket.sin6_addr = IN6_ADDR::default();
                socket.sin6_addr.u.Byte = address.octets();
                socket.Anonymous.sin6_scope_id = scope_id;
                value.Ipv6 = socket;
            }
        }
        value
    }

    fn ip_from_sockaddr(address: &SOCKADDR_INET) -> Option<IpAddr> {
        match unsafe { address.si_family } {
            AF_INET => {
                let value = unsafe { address.Ipv4 };
                Some(IpAddr::V4(Ipv4Addr::from(
                    unsafe { value.sin_addr.S_un.S_addr }.to_ne_bytes(),
                )))
            }
            AF_INET6 => {
                let value = unsafe { address.Ipv6 };
                Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                    value.sin6_addr.u.Byte
                })))
            }
            _ => None,
        }
    }

    fn luid(value: u64) -> NET_LUID_LH {
        NET_LUID_LH { Value: value }
    }

    fn guid_string(guid: GUID) -> String {
        format!(
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7]
        )
    }

    fn is_not_found(status: u32) -> bool {
        matches!(status, ERROR_FILE_NOT_FOUND | ERROR_NOT_FOUND)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{
        InterfaceAddress, InterfaceIdentity, IpFamily, OwnedInterfaceSetting, OwnedRoute,
        PhysicalInterface, RouteBinding, RouteError, RoutePlan, SystemNetworkSnapshot,
    };

    pub(super) fn capture_snapshot() -> Result<SystemNetworkSnapshot, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn discover_primary_physical_interface(
        _excluded_interface_index: Option<u32>,
    ) -> Result<PhysicalInterface, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn discover_route_to(
        _destination: std::net::IpAddr,
        _excluded_interface_index: Option<u32>,
    ) -> Result<RouteBinding, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn discover_route_on_interface(
        _destination: std::net::IpAddr,
        _expected_interface: &InterfaceIdentity,
    ) -> Result<RouteBinding, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn resolve_interface_identity(
        _interface_index: u32,
    ) -> Result<InterfaceIdentity, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn find_interface_by_alias(
        _alias: &str,
    ) -> Result<Option<InterfaceIdentity>, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn find_interface_by_luid(
        _interface_luid: u64,
    ) -> Result<Option<InterfaceIdentity>, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn verify_interface(_interface: &InterfaceIdentity) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn ensure_route_absent(_route: &OwnedRoute) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn ensure_interface_address_absent(
        _interface: &InterfaceIdentity,
        _address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn validate_shadow_route_priority(
        _plan: &RoutePlan,
        _routes: &[OwnedRoute],
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn plan_interface_configuration(
        _interface: &InterfaceIdentity,
        _family: IpFamily,
        _mtu: u32,
        _metric: u32,
    ) -> Result<Option<OwnedInterfaceSetting>, RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn apply_interface_configuration(
        _interface: &InterfaceIdentity,
        _setting: &OwnedInterfaceSetting,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn verify_prepared_interface_configuration(
        _interface: &InterfaceIdentity,
        _setting: &OwnedInterfaceSetting,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn restore_interface_configuration(
        _interface: &InterfaceIdentity,
        _setting: &OwnedInterfaceSetting,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn add_route(_route: &OwnedRoute) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn create_interface_address(
        _interface: &InterfaceIdentity,
        _address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn wait_interface_address_ready(
        _interface: &InterfaceIdentity,
        _address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn verify_prepared_address_absent(
        _interface: &InterfaceIdentity,
        _address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn remove_interface_address(
        _interface: &InterfaceIdentity,
        _address: &InterfaceAddress,
    ) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn remove_route(_route: &OwnedRoute) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }

    pub(super) fn verify_prepared_route_absent(_route: &OwnedRoute) -> Result<(), RouteError> {
        Err(RouteError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(interface_index: u32, alias: &str) -> InterfaceIdentity {
        InterfaceIdentity {
            interface_index,
            interface_luid: 10_000 + u64::from(interface_index),
            interface_guid: format!("00000000-0000-0000-0000-{interface_index:012x}"),
            alias: alias.to_owned(),
        }
    }

    fn plan() -> RoutePlan {
        RoutePlan {
            tun_interface: identity(42, "Wintun"),
            enable_ipv4: true,
            enable_ipv6: true,
            tun_ipv4_address: Some(InterfaceAddress {
                address: "198.18.0.1".parse().unwrap(),
                prefix_length: 30,
            }),
            tun_ipv6_address: Some(InterfaceAddress {
                address: "fd00:5353:5353::1".parse().unwrap(),
                prefix_length: 126,
            }),
            metric: 5,
            shadow_capture_prefixes: Vec::new(),
            interface_mtu: 1500,
            interface_metric: 1,
            exclusions: vec![MandatoryExclusion {
                destination: "203.0.113.10".parse().unwrap(),
                physical_interface: identity(7, "Ethernet"),
                physical_gateway: "192.0.2.1".parse().unwrap(),
                reason: ExclusionReason::ManagementConnection,
            }],
        }
    }

    #[test]
    fn full_capture_uses_split_defaults_and_volatile_recovery() {
        let recovery = plan().recovery_plan().unwrap();
        let prefixes = recovery
            .owned_routes()
            .iter()
            .map(|route| route.destination_prefix.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            prefixes,
            [
                "0.0.0.0/1",
                "128.0.0.0/1",
                "::/1",
                "8000::/1",
                "203.0.113.10/32"
            ]
        );
        assert_eq!(recovery.owned_change_count(), 7);
        assert_eq!(recovery.tun_interface(), &identity(42, "Wintun"));
    }

    #[test]
    fn exclusions_cannot_point_back_into_wintun() {
        let mut invalid = plan();
        invalid.exclusions[0].physical_interface = invalid.tun_interface.clone();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn interface_identity_rejects_noncanonical_guid_and_oversized_alias() {
        let mut invalid = identity(42, "Wintun");
        invalid.interface_guid = "{00000000-0000-0000-0000-000000000042}".to_owned();
        assert!(invalid.validate().is_err());

        invalid = identity(42, &"x".repeat(127));
        assert!(invalid.validate().is_ok());
        invalid.alias.push('x');
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn adapter_only_recovery_excludes_every_external_interface_route() {
        let tun = identity(42, "Wintun");
        let adapter_route = OwnedRoute {
            destination_prefix: "0.0.0.0/1".to_owned(),
            interface: tun.clone(),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            metric: 5,
        };
        let external_route = OwnedRoute {
            destination_prefix: "203.0.113.10/32".to_owned(),
            interface: identity(7, "Ethernet"),
            next_hop: "192.0.2.1".parse().unwrap(),
            metric: 5,
        };
        let recovery = RecoveryPlan::from_parts_for_runtime_test(
            tun,
            Vec::new(),
            vec![adapter_route.clone(), external_route.clone()],
        );

        assert_eq!(recovery.validate_journal_state(), Ok(()));
        assert!(recovery.has_external_routes());
        assert!(recovery.adapter_owns_route(&adapter_route));
        assert!(!recovery.adapter_owns_route(&external_route));

        let adapter_only = RecoveryPlan::from_parts_for_runtime_test(
            identity(42, "Wintun"),
            Vec::new(),
            vec![adapter_route],
        );
        assert!(!adapter_only.has_external_routes());
    }

    #[cfg(not(windows))]
    #[test]
    fn adapter_only_restore_never_calls_platform_removal_for_external_route() {
        let recovery = RecoveryPlan::from_parts_for_runtime_test(
            identity(42, "Wintun"),
            Vec::new(),
            vec![OwnedRoute {
                destination_prefix: "203.0.113.10/32".to_owned(),
                interface: identity(7, "Ethernet"),
                next_hop: "192.0.2.1".parse().unwrap(),
                metric: 5,
            }],
        );

        // Every non-Windows platform removal returns UnsupportedPlatform. An
        // Ok result therefore proves the external route was never dispatched
        // to the mutation layer.
        assert_eq!(recovery.restore_adapter_owned_only(), Ok(()));
    }

    #[test]
    fn address_family_mismatch_is_rejected() {
        let mut invalid = plan();
        invalid.exclusions[0].physical_gateway = "::1".parse().unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn physical_interface_selects_matching_source_family() {
        let interface = PhysicalInterface {
            identity: identity(7, "Ethernet"),
            ipv4_source: Some("192.0.2.2".parse().unwrap()),
            ipv6_source: Some("2001:db8::2".parse().unwrap()),
            ipv4_gateway: Some("192.0.2.1".parse().unwrap()),
            ipv6_gateway: Some("2001:db8::1".parse().unwrap()),
            dns_servers: Vec::new(),
            route_metric: 10,
        };
        assert_eq!(
            interface.source_for("203.0.113.2".parse().unwrap()),
            Some("192.0.2.2".parse().unwrap())
        );
        assert_eq!(
            interface.source_for("2001:db8::20".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap())
        );
    }

    #[test]
    fn snapshot_derives_normalized_child_and_host_shadows() {
        let snapshot = SystemNetworkSnapshot {
            captured_unix_ms: 1,
            adapters_json: "[]".to_owned(),
            routes_json: serde_json::json!([
                {"DestinationPrefix": "0.0.0.0/0"},
                {"DestinationPrefix": "10.0.0.0/24"},
                {"DestinationPrefix": "203.0.113.9/32"},
                {"DestinationPrefix": "2001:db8::/126"}
            ])
            .to_string(),
            dns_json: "[]".to_owned(),
        };
        assert_eq!(
            snapshot.shadow_capture_prefixes().unwrap(),
            [
                "10.0.0.0/25",
                "10.0.0.128/25",
                "2001:db8::/127",
                "2001:db8::2/127",
                "203.0.113.9/32"
            ]
        );
    }

    #[test]
    fn shadow_snapshot_exclusion_uses_both_index_and_luid_and_keeps_external_growth() {
        let tun = identity(42, "Wintun");
        let snapshot = SystemNetworkSnapshot {
            captured_unix_ms: 1,
            adapters_json: "[]".to_owned(),
            routes_json: serde_json::json!([
                {
                    "DestinationPrefix": "10.0.0.0/24",
                    "InterfaceIndex": tun.interface_index,
                    "InterfaceLuid": tun.interface_luid
                },
                {
                    "DestinationPrefix": "192.168.0.0/24",
                    "InterfaceIndex": tun.interface_index,
                    "InterfaceLuid": tun.interface_luid + 1
                },
                {
                    "DestinationPrefix": "172.16.0.0/16",
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_007
                }
            ])
            .to_string(),
            dns_json: "[]".to_owned(),
        };

        assert_eq!(
            snapshot
                .shadow_capture_prefixes_excluding_interface(&tun)
                .unwrap(),
            [
                "172.16.0.0/17",
                "172.16.128.0/17",
                "192.168.0.0/25",
                "192.168.0.128/25"
            ]
        );
    }

    #[test]
    fn shadow_snapshot_exclusion_rejects_missing_or_mistyped_identity_fields() {
        let tun = identity(42, "Wintun");
        for routes_json in [
            serde_json::json!([{
                "DestinationPrefix": "10.0.0.0/24",
                "InterfaceIndex": tun.interface_index
            }]),
            serde_json::json!([{
                "DestinationPrefix": "10.0.0.0/24",
                "InterfaceIndex": "42",
                "InterfaceLuid": tun.interface_luid
            }]),
            serde_json::json!([{
                "DestinationPrefix": 42,
                "InterfaceIndex": tun.interface_index,
                "InterfaceLuid": tun.interface_luid
            }]),
            serde_json::json!([{
                "DestinationPrefix": "not-a-prefix",
                "InterfaceIndex": tun.interface_index,
                "InterfaceLuid": tun.interface_luid
            }]),
        ] {
            let snapshot = SystemNetworkSnapshot {
                captured_unix_ms: 1,
                adapters_json: "[]".to_owned(),
                routes_json: routes_json.to_string(),
                dns_json: "[]".to_owned(),
            };
            assert_eq!(
                snapshot.shadow_capture_prefixes_excluding_interface(&tun),
                Err(RouteError::SnapshotEncoding)
            );
        }
    }

    #[test]
    fn default_route_selection_fingerprint_binds_family_metric_to_exact_identity() {
        let snapshot = SystemNetworkSnapshot {
            captured_unix_ms: 1,
            adapters_json: serde_json::json!([
                {
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_007,
                    "Ipv4Metric": 35,
                    "Ipv6Metric": 45
                },
                {
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_008,
                    "Ipv4Metric": 85,
                    "Ipv6Metric": 95
                }
            ])
            .to_string(),
            routes_json: serde_json::json!([
                {
                    "DestinationPrefix": "0.0.0.0/0",
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_007,
                    "NextHop": "192.0.2.1",
                    "RouteMetric": 25
                },
                {
                    "DestinationPrefix": "::/0",
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_008,
                    "NextHop": "fe80::1",
                    "RouteMetric": 5
                },
                {
                    "DestinationPrefix": "10.0.0.0/8"
                }
            ])
            .to_string(),
            dns_json: "[]".to_owned(),
        };

        assert_eq!(
            snapshot
                .external_default_route_selection_fingerprint()
                .unwrap(),
            "0.0.0.0/0|7|10007|192.0.2.1|25|35\n::/0|7|10008|fe80::1|5|95"
        );
        assert_eq!(
            snapshot.default_route_fingerprint().unwrap(),
            snapshot
                .external_default_route_selection_fingerprint()
                .unwrap()
        );
    }

    #[test]
    fn default_route_selection_fingerprint_detects_interface_metric_only_change() {
        let snapshot = |ipv4_metric| SystemNetworkSnapshot {
            captured_unix_ms: 1,
            adapters_json: serde_json::json!([{
                "InterfaceIndex": 7,
                "InterfaceLuid": 10_007,
                "Ipv4Metric": ipv4_metric,
                "Ipv6Metric": 45
            }])
            .to_string(),
            routes_json: serde_json::json!([{
                "DestinationPrefix": "0.0.0.0/0",
                "InterfaceIndex": 7,
                "InterfaceLuid": 10_007,
                "NextHop": "192.0.2.1",
                "RouteMetric": 25
            }])
            .to_string(),
            dns_json: "[]".to_owned(),
        };

        assert_ne!(
            snapshot(35)
                .external_default_route_selection_fingerprint()
                .unwrap(),
            snapshot(36)
                .external_default_route_selection_fingerprint()
                .unwrap()
        );
    }

    #[test]
    fn default_route_selection_fingerprint_rejects_incomplete_or_unbound_rows() {
        let valid_adapter = serde_json::json!({
            "InterfaceIndex": 7,
            "InterfaceLuid": 10_007,
            "Ipv4Metric": 35,
            "Ipv6Metric": 45
        });
        let valid_route = serde_json::json!({
            "DestinationPrefix": "0.0.0.0/0",
            "InterfaceIndex": 7,
            "InterfaceLuid": 10_007,
            "NextHop": "192.0.2.1",
            "RouteMetric": 25
        });
        let cases = [
            (
                serde_json::json!([valid_adapter.clone()]),
                serde_json::json!([{
                    "DestinationPrefix": "0.0.0.0/0",
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_007,
                    "NextHop": "192.0.2.1"
                }]),
            ),
            (
                serde_json::json!([{
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_007,
                    "Ipv4Metric": "35",
                    "Ipv6Metric": 45
                }]),
                serde_json::json!([valid_route.clone()]),
            ),
            (
                serde_json::json!([valid_adapter.clone()]),
                serde_json::json!([{
                    "DestinationPrefix": "0.0.0.0/0",
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_008,
                    "NextHop": "192.0.2.1",
                    "RouteMetric": 25
                }]),
            ),
            (
                serde_json::json!([valid_adapter.clone()]),
                serde_json::json!([{
                    "DestinationPrefix": "0.0.0.0/0",
                    "InterfaceIndex": 7,
                    "InterfaceLuid": 10_007,
                    "NextHop": "::1",
                    "RouteMetric": 25
                }]),
            ),
            (
                serde_json::json!([valid_adapter.clone(), valid_adapter]),
                serde_json::json!([valid_route]),
            ),
            (serde_json::Value::Null, serde_json::json!([])),
            (serde_json::json!([]), serde_json::Value::Null),
        ];

        for (adapters_json, routes_json) in cases {
            let snapshot = SystemNetworkSnapshot {
                captured_unix_ms: 1,
                adapters_json: adapters_json.to_string(),
                routes_json: routes_json.to_string(),
                dns_json: "[]".to_owned(),
            };
            assert_eq!(
                snapshot.external_default_route_selection_fingerprint(),
                Err(RouteError::SnapshotEncoding)
            );
        }
    }

    #[test]
    fn snapshot_route_match_includes_stable_luid() {
        let route = OwnedRoute {
            destination_prefix: "198.51.100.2/32".to_owned(),
            interface: identity(7, "Ethernet"),
            next_hop: "192.0.2.1".parse().unwrap(),
            metric: 1,
        };
        let snapshot = SystemNetworkSnapshot {
            captured_unix_ms: 1,
            adapters_json: "[]".to_owned(),
            routes_json: serde_json::json!([{
                "DestinationPrefix": route.destination_prefix,
                "InterfaceIndex": route.interface.interface_index,
                "InterfaceLuid": route.interface.interface_luid,
                "NextHop": route.next_hop.to_string(),
                "RouteMetric": route.metric
            }])
            .to_string(),
            dns_json: "[]".to_owned(),
        };
        assert!(snapshot.contains_owned_route(&route).unwrap());
        let mut reused_index = route;
        reused_index.interface.interface_luid += 1;
        assert!(!snapshot.contains_owned_route(&reused_index).unwrap());
    }

    #[test]
    fn interface_setting_restore_is_idempotent_but_rejects_foreign_changes() {
        let setting = OwnedInterfaceSetting {
            family: IpFamily::V4,
            original_mtu: 1500,
            original_metric: 25,
            original_automatic_metric: true,
            applied_mtu: 1400,
            applied_metric: 1,
        };
        assert_eq!(
            should_restore_interface_setting(&setting, 1400, 1, false),
            Ok(true)
        );
        assert_eq!(
            should_restore_interface_setting(&setting, 1500, 25, true),
            Ok(false)
        );
        assert_eq!(
            should_restore_interface_setting(&setting, 1300, 5, false),
            Err(RouteError::OwnershipMismatch("interface configuration"))
        );
    }

    #[test]
    fn write_ahead_state_transitions_are_monotonic_and_serializable() {
        let mut prepared = RecoveryPlan::empty(identity(42, "Wintun")).unwrap();
        let setting_index = prepared.push_prepared_setting(OwnedInterfaceSetting {
            family: IpFamily::V4,
            original_mtu: 1500,
            original_metric: 25,
            original_automatic_metric: true,
            applied_mtu: 1400,
            applied_metric: 1,
        });
        let address_index = prepared.push_prepared_address(InterfaceAddress {
            address: "198.18.0.1".parse().unwrap(),
            prefix_length: 15,
        });
        let route_index = prepared.push_prepared_route(OwnedRoute {
            destination_prefix: "0.0.0.0/1".to_owned(),
            interface: identity(42, "Wintun"),
            next_hop: "0.0.0.0".parse().unwrap(),
            metric: 1,
        });
        assert_eq!(
            (
                prepared.setting_state(setting_index),
                prepared.address_state(address_index),
                prepared.route_state(route_index),
            ),
            (
                OwnershipState::Prepared,
                OwnershipState::Prepared,
                OwnershipState::Prepared,
            )
        );

        let mut applied = prepared.clone();
        applied.mark_setting_applied(setting_index);
        applied.mark_address_applied(address_index);
        applied.mark_route_applied(route_index);
        assert!(applied.is_valid_successor_of(&prepared));
        assert!(!prepared.is_valid_successor_of(&applied));

        let encoded = serde_json::to_vec(&applied).unwrap();
        let decoded: RecoveryPlan = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, applied);
        assert_eq!(decoded.validate_journal_state(), Ok(()));
    }

    #[test]
    fn prepared_recovery_is_absence_only() {
        assert_eq!(
            verify_prepared_resource_absent(false, "prepared route"),
            Ok(())
        );
        assert_eq!(
            verify_prepared_resource_absent(true, "prepared route"),
            Err(RouteError::OwnershipMismatch("prepared route"))
        );

        let setting = OwnedInterfaceSetting {
            family: IpFamily::V4,
            original_mtu: 1500,
            original_metric: 25,
            original_automatic_metric: true,
            applied_mtu: 1400,
            applied_metric: 1,
        };
        assert_eq!(
            verify_prepared_setting_unchanged(&setting, 1500, 25, true),
            Ok(())
        );
        assert_eq!(
            verify_prepared_setting_unchanged(&setting, 1400, 1, false),
            Err(RouteError::OwnershipMismatch(
                "prepared interface configuration"
            ))
        );
    }

    #[test]
    fn constrained_route_validation_checks_full_identity_and_families() {
        let expected = identity(7, "Ethernet");
        let binding = RouteBinding {
            interface: expected.clone(),
            source: "192.0.2.2".parse().unwrap(),
            next_hop: "192.0.2.1".parse().unwrap(),
        };
        let destination = "203.0.113.9".parse().unwrap();
        assert_eq!(
            validate_discovered_binding(destination, Some(&expected), &binding),
            Ok(())
        );

        let mut reused = binding.clone();
        reused.interface.interface_luid += 1;
        assert_eq!(
            validate_discovered_binding(destination, Some(&expected), &reused),
            Err(RouteError::OwnershipMismatch("constrained route interface"))
        );

        let mut wrong_family = binding;
        wrong_family.source = "::1".parse().unwrap();
        assert_eq!(
            validate_discovered_binding(destination, Some(&expected), &wrong_family),
            Err(RouteError::SnapshotEncoding)
        );
    }

    #[test]
    fn inconsistent_journal_state_lengths_are_rejected() {
        let mut recovery = RecoveryPlan::empty(identity(42, "Wintun")).unwrap();
        recovery.push_prepared_route(OwnedRoute {
            destination_prefix: "0.0.0.0/1".to_owned(),
            interface: identity(42, "Wintun"),
            next_hop: "0.0.0.0".parse().unwrap(),
            metric: 1,
        });
        recovery.route_states.clear();
        // An entirely absent state vector is the supported legacy encoding.
        assert_eq!(recovery.validate_journal_state(), Ok(()));
        assert_eq!(recovery.validate_journal_encoding(true), Ok(()));
        assert!(recovery.validate_journal_encoding(false).is_err());
        recovery.route_states = vec![OwnershipState::Prepared, OwnershipState::Applied];
        assert!(recovery.validate_journal_state().is_err());
    }
}
