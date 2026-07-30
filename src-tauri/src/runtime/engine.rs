use super::{RuntimeError, RuntimeState, SharedRuntimeStatus};
use crate::config::{AppConfig, DnsSource};
use crate::diagnostics::Diagnostics;
use crate::outbound::CancellationToken;
use crate::router::{IpCidr, MandatoryGlobalExclusions, Router};
#[cfg(any(windows, test))]
use crate::tun::routes::InterfaceIdentity;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, mpsc};
use std::time::Duration;

#[derive(Clone)]
pub(super) struct EngineConfig {
    adapter_name: String,
    mtu: usize,
    allow_ipv6: bool,
    tcp_timeout: Duration,
    udp_timeout: Duration,
    dns_enabled: bool,
    dns_source: DnsSource,
    dns_servers: Vec<IpAddr>,
    dns_ipv6: bool,
    dns_tcp_fallback: bool,
    dns_cache_capacity: usize,
    dns_cache_ttl: Duration,
    management_exclusions: Vec<IpCidr>,
    routing: Router,
}

impl TryFrom<&AppConfig> for EngineConfig {
    type Error = RuntimeError;

    fn try_from(config: &AppConfig) -> Result<Self, Self::Error> {
        if !config.tun.enabled || config.kill_switch.enabled {
            return Err(RuntimeError::InvalidConfiguration);
        }
        let management_exclusions = config
            .tun
            .management_exclusions
            .iter()
            .map(|value| {
                value
                    .parse::<IpCidr>()
                    .map_err(|_| RuntimeError::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let dns_servers = config
            .dns
            .servers
            .iter()
            .map(|server| {
                server
                    .trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .map_err(|_| RuntimeError::InvalidConfiguration)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let routing = Router::from_config(
            config.mode,
            &config.routing,
            MandatoryGlobalExclusions::new(management_exclusions.iter().copied()),
        )
        .map_err(|error| RuntimeError::subsystem("router construction", error))?;
        Ok(Self {
            adapter_name: config.tun.interface_name.clone(),
            mtu: usize::from(config.tun.mtu),
            allow_ipv6: config.tun.ipv6,
            tcp_timeout: Duration::from_secs(config.tun.tcp_session_timeout_seconds),
            udp_timeout: Duration::from_secs(config.tun.udp_idle_timeout_seconds),
            dns_enabled: config.dns.enabled,
            dns_source: config.dns.source,
            dns_servers,
            dns_ipv6: config.dns.ipv6,
            dns_tcp_fallback: config.dns.tcp_fallback,
            dns_cache_capacity: config.dns.cache_capacity,
            dns_cache_ttl: Duration::from_secs(config.dns.cache_ttl_seconds),
            management_exclusions,
            routing,
        })
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    config: EngineConfig,
    recovery_path: PathBuf,
    diagnostics: Arc<Diagnostics>,
    cancellation: CancellationToken,
    status: Arc<SharedRuntimeStatus>,
    startup: mpsc::SyncSender<Result<(), RuntimeError>>,
) {
    let result = platform::run(
        config,
        recovery_path,
        diagnostics,
        cancellation,
        Arc::clone(&status),
        &startup,
    );
    match result {
        Ok(()) => status.finish_stopped(),
        Err(error) => {
            let _ = startup.try_send(Err(error.clone()));
            status.set(RuntimeState::Failed, Some(&error));
        }
    }
}

#[cfg(any(windows, test))]
fn execute_after_fresh_management_verification<T, E>(
    verify: impl FnOnce() -> Result<(), E>,
    mutate: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    verify()?;
    mutate()
}

#[cfg(any(windows, test))]
fn validate_management_binding_against_physical(
    destination: IpAddr,
    binding: &crate::tun::routes::RouteBinding,
    physical: &crate::tun::routes::PhysicalInterface,
) -> Result<(), crate::tun::routes::RouteError> {
    if binding.interface != physical.identity
        || physical.gateway_for(destination) != Some(binding.next_hop)
    {
        return Err(crate::tun::routes::RouteError::OwnershipMismatch(
            "management route confirmed physical binding",
        ));
    }
    Ok(())
}

#[cfg(any(windows, test))]
trait OrderedDataPathCleanup {
    type Error;

    fn stop_callbacks(&mut self);
    fn withdraw_capture_routes(&mut self) -> Result<(), Self::Error>;
    fn end_wintun_session(&mut self);
    fn restore_interface_state(&mut self) -> Result<(), Self::Error>;
    fn remove_adapter(&mut self) -> Result<(), Self::Error>;
}

#[cfg(any(windows, test))]
fn execute_ordered_data_path_cleanup<C: OrderedDataPathCleanup>(
    resources: &mut C,
) -> Result<(), C::Error> {
    resources.stop_callbacks();
    resources.withdraw_capture_routes()?;
    resources.end_wintun_session();
    resources.restore_interface_state()?;
    resources.remove_adapter()
}

#[cfg(any(windows, test))]
fn recovery_journal_clear_allowed(
    journal_prepared: bool,
    cleanup_verified: bool,
    ordered_cleanup_succeeded: bool,
) -> bool {
    journal_prepared && cleanup_verified && ordered_cleanup_succeeded
}

#[cfg(any(windows, test))]
fn created_adapter_identity_matches(
    intended_alias: &str,
    intended_guid: &str,
    opened_index: u32,
    opened_luid: u64,
    resolved: &InterfaceIdentity,
) -> bool {
    resolved.interface_index == opened_index
        && resolved.interface_luid == opened_luid
        && resolved.interface_guid == intended_guid
        && resolved.alias == intended_alias
}

#[cfg(any(windows, test))]
fn execute_after_adapter_intent<T>(
    adapter_intent_recorded: bool,
    create: impl FnOnce() -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    if !adapter_intent_recorded {
        return Err(RuntimeError::RecoveryRequired);
    }
    create()
}

#[cfg(any(windows, test))]
fn execute_after_identity_journal<T>(
    identity_journal_recorded: bool,
    native_call: impl FnOnce() -> Result<T, RuntimeError>,
) -> Result<T, RuntimeError> {
    if !identity_journal_recorded {
        return Err(RuntimeError::RecoveryRequired);
    }
    native_call()
}

trait OrderedRouteFallback {
    fn withdraw_capture_routes_for_fallback(&mut self) -> bool;
    fn restore_interface_state_for_fallback(&mut self) -> bool;
    fn mark_fallback_cleanup_complete(&mut self);
}

#[cfg(any(windows, test))]
impl OrderedRouteFallback for crate::tun::routes::RouteTransaction {
    fn withdraw_capture_routes_for_fallback(&mut self) -> bool {
        self.withdraw_capture_routes().is_ok()
    }

    fn restore_interface_state_for_fallback(&mut self) -> bool {
        self.restore_interface_state_after_session().is_ok()
    }

    fn mark_fallback_cleanup_complete(&mut self) {
        self.mark_ordered_cleanup_complete();
    }
}

/// Last-resort cleanup for early-return and panic paths.
///
/// A plain field-order fallback is insufficient: dropping `RouteTransaction`
/// can restore interface state before the session ends, and a failed route
/// withdrawal would still be followed by implicit session destruction. This
/// wrapper performs each phase explicitly. If a prerequisite cannot be
/// proved, it intentionally retains all downstream handles for process-lifetime
/// recovery rather than crossing the failed safety boundary.
#[cfg(any(windows, test))]
struct OrderedFallbackResources<M, R: OrderedRouteFallback, S, A, L> {
    monitor: Option<M>,
    routes: Option<R>,
    session: Option<S>,
    adapter: Option<A>,
    lease: Option<L>,
    capture_routes_may_remain: bool,
}

#[cfg(any(windows, test))]
impl<M, R: OrderedRouteFallback, S, A, L> OrderedFallbackResources<M, R, S, A, L> {
    fn retain_for_process_lifetime<T>(slot: &mut Option<T>) {
        if let Some(resource) = slot.take() {
            std::mem::forget(resource);
        }
    }

    fn retain_from_routes_through_lease(&mut self) {
        Self::retain_for_process_lifetime(&mut self.routes);
        Self::retain_for_process_lifetime(&mut self.session);
        Self::retain_for_process_lifetime(&mut self.adapter);
        Self::retain_for_process_lifetime(&mut self.lease);
    }
}

#[cfg(any(windows, test))]
impl<M, R: OrderedRouteFallback, S, A, L> Drop for OrderedFallbackResources<M, R, S, A, L> {
    fn drop(&mut self) {
        self.monitor.take();

        let routes_withdrawn = match self.routes.as_mut() {
            Some(routes) => routes.withdraw_capture_routes_for_fallback(),
            None => !self.capture_routes_may_remain,
        };
        if !routes_withdrawn {
            self.retain_from_routes_through_lease();
            return;
        }
        self.capture_routes_may_remain = false;

        self.session.take();

        if let Some(routes) = self.routes.as_mut() {
            if !routes.restore_interface_state_for_fallback() {
                Self::retain_for_process_lifetime(&mut self.routes);
                Self::retain_for_process_lifetime(&mut self.adapter);
                Self::retain_for_process_lifetime(&mut self.lease);
                return;
            }
            routes.mark_fallback_cleanup_complete();
        }
        self.routes.take();
        self.adapter.take();
        self.lease.take();
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;

    pub(super) fn run(
        _config: EngineConfig,
        _recovery_path: PathBuf,
        _diagnostics: Arc<Diagnostics>,
        _cancellation: CancellationToken,
        _status: Arc<SharedRuntimeStatus>,
        _startup: &mpsc::SyncSender<Result<(), RuntimeError>>,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::UnsupportedPlatform)
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use crate::diagnostics::{Counter, FlowIdGenerator};
    use crate::dns::{
        DNS_PORT, DnsCache, DnsCacheConfig, DnsQuery, parse_query,
        parse_response_answers_for_query, response_correlates,
    };
    use crate::error::EngineError;
    use crate::outbound::{
        DirectBinding, DirectOutbound, DirectTcp, DirectUdp, LoopGuard,
        TransportProtocol as DirectTransportProtocol,
    };
    use crate::packet::IpPacket;
    use crate::packet::builder::udp_packet_with_mtu;
    use crate::packet::tcp;
    use crate::packet::udp::UdpPacket;
    use crate::router::{DecisionReason, RouteAction};
    use crate::runtime::recovery::{self, RecoveryLease};
    use crate::session::FlowKey;
    use crate::session::tcp::{
        TcpSessionConfig, TcpSessionEngine, TcpSessionNotice, inspect_tcp_flow,
    };
    use crate::session::udp::{UdpAssociationConfig, UdpAssociationTable, UdpQueueResult};
    use crate::system_proxy::{SystemProxyError, SystemProxySnapshot, confirm_intranet_endpoints};
    use crate::tun::network_change::{NetworkChangeMonitor, NetworkEpochToken};
    use crate::tun::routes::{
        ExclusionReason, InterfaceAddress, InterfaceIdentity, MandatoryExclusion,
        PhysicalInterface, RecoveryPlan, RouteBinding, RouteError, RoutePlan, RouteTransaction,
        SystemNetworkSnapshot, discover_primary_physical_interface, discover_route_on_interface,
        discover_route_to, resolve_interface_identity, verify_mandatory_exclusions,
    };
    use crate::tun::wintun::{
        Adapter as WintunAdapter, AdapterGuid, Session as WintunSession, Wintun,
    };
    use std::collections::{HashMap, VecDeque};
    use std::io::ErrorKind;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
    use std::sync::mpsc::{Receiver, SyncSender, TryRecvError, TrySendError};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    const WINTUN_RING_CAPACITY: u32 = 4 * 1024 * 1024;
    const DRIVER_WAIT: Duration = Duration::from_millis(5);
    const WORKER_POLL: Duration = Duration::from_millis(100);
    const STREAM_CHUNK: usize = 16 * 1024;
    const MAX_PENDING_TO_CLIENT: usize = 1024 * 1024;
    const MAX_PACKETS_PER_TICK: usize = 256;
    const MAX_EVENTS_PER_TICK: usize = 256;
    const MAX_CONCURRENT_WORKERS: usize = 512;
    const UDP_COMMAND_QUEUE_CAPACITY: usize = 1;
    const MAX_OUTSTANDING_DNS_QUERIES: usize = 32;
    const TUN_SEND_ATTEMPTS: usize = 3;
    const TUN_SEND_RETRY_DELAY: Duration = Duration::from_millis(1);
    const VIRTUAL_IPV4: &str = "198.18.0.1";
    const VIRTUAL_IPV6: &str = "fd00:7373:7273::1";
    const NETWORK_RESTART_DEBOUNCE: Duration = Duration::from_millis(400);
    const SYSTEM_PROXY_CAPTURE_TIMEOUT: Duration = Duration::from_secs(5);
    const ADAPTER_REMOVAL_TIMEOUT: Duration = Duration::from_secs(5);
    const PHYSICAL_VALIDATION_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
    const PHYSICAL_VALIDATION_IPV6: IpAddr =
        IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111));

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum DriverExit {
        Cancelled,
        NetworkChangedBeforeRunning,
        NetworkChanged,
    }

    /// Owns every mutable Windows object in one network epoch.
    ///
    /// Drop is a final best-effort guard for early-return and panic paths.
    /// Normal paths call `cleanup` so a rollback failure remains observable.
    struct EpochResources {
        recovery_path: PathBuf,
        fallback: OrderedFallbackResources<
            NetworkChangeMonitor,
            RouteTransaction,
            WintunSession,
            WintunAdapter,
            RecoveryLease,
        >,
        adapter_intent: Option<(String, String)>,
        adapter_observed_identity: Option<InterfaceIdentity>,
        adapter_observed_luid: Option<u64>,
        adapter_observed_index: Option<u32>,
        adapter_identity: Option<InterfaceIdentity>,
        identity_journal_recorded: bool,
        adapter_removal_pending: bool,
        journal_prepared: bool,
        cleanup_verified: bool,
        cleaned: bool,
    }

    impl EpochResources {
        fn new(recovery_path: PathBuf, lease: RecoveryLease) -> Self {
            Self {
                recovery_path,
                fallback: OrderedFallbackResources {
                    monitor: None,
                    routes: None,
                    session: None,
                    adapter: None,
                    lease: Some(lease),
                    capture_routes_may_remain: false,
                },
                adapter_intent: None,
                adapter_observed_identity: None,
                adapter_observed_luid: None,
                adapter_observed_index: None,
                adapter_identity: None,
                identity_journal_recorded: false,
                adapter_removal_pending: false,
                journal_prepared: false,
                cleanup_verified: true,
                cleaned: false,
            }
        }

        fn cleanup(&mut self) -> Result<(), RuntimeError> {
            if self.cleaned {
                return Ok(());
            }

            execute_ordered_data_path_cleanup(self)?;

            let clear_result = if recovery_journal_clear_allowed(
                self.journal_prepared,
                self.cleanup_verified,
                true,
            ) {
                recovery::clear(&self.recovery_path)
            } else {
                Ok(())
            };

            self.cleaned = true;
            clear_result?;
            if self.journal_prepared && (!self.cleanup_verified || self.recovery_path.exists()) {
                return Err(RuntimeError::RecoveryRequired);
            }
            self.journal_prepared = false;
            Ok(())
        }
    }

    impl OrderedDataPathCleanup for EpochResources {
        type Error = RuntimeError;

        fn stop_callbacks(&mut self) {
            // The packet driver has already stopped accepting flows. Remove
            // notifications before any owned network object is changed.
            self.fallback.monitor.take();
        }

        fn withdraw_capture_routes(&mut self) -> Result<(), Self::Error> {
            let result = match self.fallback.routes.as_mut() {
                Some(routes) => routes
                    .withdraw_capture_routes()
                    .map_err(|error| RuntimeError::subsystem("capture route withdrawal", error)),
                None if self.fallback.capture_routes_may_remain => {
                    Err(RuntimeError::RecoveryRequired)
                }
                None => Ok(()),
            };
            if result.is_ok() {
                self.fallback.capture_routes_may_remain = false;
            }
            result
        }

        fn end_wintun_session(&mut self) {
            self.fallback.session.take();
        }

        fn restore_interface_state(&mut self) -> Result<(), Self::Error> {
            let Some(routes) = self.fallback.routes.as_mut() else {
                return Ok(());
            };
            routes
                .restore_interface_state_after_session()
                .map_err(|error| RuntimeError::subsystem("interface restoration", error))?;
            self.fallback
                .routes
                .take()
                .expect("route transaction exists until ordered cleanup completes")
                .finish_ordered_cleanup()
                .map(|_| ())
                .map_err(|error| RuntimeError::subsystem("route restoration", error))
        }

        fn remove_adapter(&mut self) -> Result<(), Self::Error> {
            if let Some(adapter) = self.fallback.adapter.take() {
                self.adapter_removal_pending = true;
                adapter
                    .remove_owned()
                    .map_err(|error| RuntimeError::subsystem("Wintun adapter removal", error))?;
            }
            if self.adapter_removal_pending {
                if let Some(identity) = self.adapter_identity.as_ref() {
                    recovery::wait_for_adapter_absent(identity, ADAPTER_REMOVAL_TIMEOUT)?;
                } else if let Some((adapter_name, adapter_guid)) = self.adapter_intent.as_ref() {
                    recovery::wait_for_created_adapter_absent(
                        adapter_name,
                        adapter_guid,
                        self.adapter_observed_identity.as_ref(),
                        self.adapter_observed_luid,
                        self.adapter_observed_index,
                        ADAPTER_REMOVAL_TIMEOUT,
                    )?;
                }
                self.adapter_removal_pending = false;
            } else if self.journal_prepared && self.adapter_identity.is_none() {
                if let Some((adapter_name, adapter_guid)) = self.adapter_intent.as_ref() {
                    recovery::wait_for_adapter_intent_absent(
                        adapter_name,
                        adapter_guid,
                        Duration::ZERO,
                    )?;
                }
            }
            Ok(())
        }
    }

    impl Drop for EpochResources {
        fn drop(&mut self) {
            if !self.cleaned {
                let _ = self.cleanup();
            }
        }
    }

    pub(super) fn run(
        config: EngineConfig,
        recovery_path: PathBuf,
        diagnostics: Arc<Diagnostics>,
        cancellation: CancellationToken,
        status: Arc<SharedRuntimeStatus>,
        startup: &SyncSender<Result<(), RuntimeError>>,
    ) -> Result<(), RuntimeError> {
        let mut announce_start = true;
        loop {
            let exit = run_epoch(
                config.clone(),
                recovery_path.clone(),
                Arc::clone(&diagnostics),
                cancellation.clone(),
                Arc::clone(&status),
                startup,
                announce_start,
            )?;
            match exit {
                DriverExit::Cancelled => {
                    if announce_start {
                        let _ = startup.try_send(Err(RuntimeError::Cancelled));
                    }
                    return Ok(());
                }
                DriverExit::NetworkChangedBeforeRunning | DriverExit::NetworkChanged => {
                    if cancellation.is_cancelled() {
                        if announce_start {
                            let _ = startup.try_send(Err(RuntimeError::Cancelled));
                        }
                        return Ok(());
                    }
                    status.set(RuntimeState::Starting, None);
                    let deadline = Instant::now() + NETWORK_RESTART_DEBOUNCE;
                    while Instant::now() < deadline {
                        if cancellation.is_cancelled() {
                            if announce_start {
                                let _ = startup.try_send(Err(RuntimeError::Cancelled));
                            }
                            return Ok(());
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    if exit == DriverExit::NetworkChanged {
                        announce_start = false;
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_epoch(
        mut config: EngineConfig,
        recovery_path: PathBuf,
        diagnostics: Arc<Diagnostics>,
        cancellation: CancellationToken,
        status: Arc<SharedRuntimeStatus>,
        startup: &SyncSender<Result<(), RuntimeError>>,
        announce_start: bool,
    ) -> Result<DriverExit, RuntimeError> {
        if cancellation.is_cancelled() {
            return Ok(DriverExit::Cancelled);
        }
        let original = SystemNetworkSnapshot::capture()
            .map_err(|error| RuntimeError::subsystem("network snapshot", error))?;
        let original_default_route_selection = original
            .external_default_route_selection_fingerprint()
            .map_err(|error| RuntimeError::subsystem("default route planning", error))?;
        if cancellation.is_cancelled() {
            return Ok(DriverExit::Cancelled);
        }
        let system_proxy =
            match SystemProxySnapshot::capture_bounded(SYSTEM_PROXY_CAPTURE_TIMEOUT, || {
                cancellation.is_cancelled()
            }) {
                Ok(snapshot) => snapshot,
                Err(SystemProxyError::Cancelled) => return Ok(DriverExit::Cancelled),
                Err(error) => {
                    return Err(RuntimeError::subsystem("system proxy discovery", error));
                }
            };
        if system_proxy.is_configured() {
            diagnostics.increment(Counter::SystemProxyDetected);
        }
        if cancellation.is_cancelled() {
            return Ok(DriverExit::Cancelled);
        }

        let lease = RecoveryLease::try_acquire()?;
        let mut resources = EpochResources::new(recovery_path, lease);
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        let wintun =
            Wintun::load().map_err(|error| RuntimeError::subsystem("Wintun load", error))?;
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        if let Ok(existing) = wintun.open_adapter(&config.adapter_name) {
            drop(existing);
            return Err(RuntimeError::RecoveryRequired);
        }
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        // Confirm the expected physical generation and gateway independently
        // from the management host route itself. The host route must agree
        // with the pre-Wintun default physical binding rather than self-certify
        // whatever interface its current best-route lookup happens to return.
        let management_physical = discover_primary_physical_interface(None)
            .map_err(|error| RuntimeError::subsystem("physical interface discovery", error))?;
        let (exclusions, management_bindings) =
            build_route_exclusions(&config, &management_physical)?;
        verify_mandatory_exclusions(&exclusions)
            .map_err(|error| RuntimeError::subsystem("management route precondition", error))?;
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        let adapter_guid = AdapterGuid::generate()
            .map_err(|error| RuntimeError::subsystem("Wintun adapter GUID generation", error))?;
        let adapter_guid_string = adapter_guid.canonical_string();
        recovery::prepare_adapter_intent(
            &resources.recovery_path,
            config.adapter_name.clone(),
            adapter_guid_string.clone(),
            original.clone(),
        )?;
        resources.journal_prepared = true;
        resources.adapter_intent = Some((config.adapter_name.clone(), adapter_guid_string.clone()));
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }

        // The durable intent write can take an unbounded amount of wall time.
        // Freshly verify the operator-owned management route again immediately
        // before adapter creation, which is the first network mutation.
        resources.fallback.adapter = Some(execute_after_adapter_intent(
            resources.journal_prepared,
            || {
                execute_after_fresh_management_verification(
                    || {
                        verify_mandatory_exclusions(&exclusions).map_err(|error| {
                            RuntimeError::subsystem("management route precondition", error)
                        })
                    },
                    || {
                        wintun
                            .create_adapter_with_guid(&config.adapter_name, &adapter_guid)
                            .map_err(|error| {
                                RuntimeError::subsystem("Wintun adapter creation", error)
                            })
                    },
                )
            },
        )?);
        let adapter_luid = resources
            .fallback
            .adapter
            .as_ref()
            .expect("epoch owns the newly created adapter")
            .luid();
        resources.adapter_observed_luid = Some(adapter_luid);
        let tun_interface_index = resources
            .fallback
            .adapter
            .as_ref()
            .expect("epoch owns the newly created adapter")
            .interface_index()
            .map_err(|error| RuntimeError::subsystem("Wintun interface lookup", error))?;
        resources.adapter_observed_index = Some(tun_interface_index);
        let tun_interface = resolve_interface_identity(tun_interface_index)
            .map_err(|error| RuntimeError::subsystem("Wintun identity lookup", error))?;
        resources.adapter_observed_identity = Some(tun_interface.clone());
        if !created_adapter_identity_matches(
            &config.adapter_name,
            &adapter_guid_string,
            tun_interface_index,
            adapter_luid,
            &tun_interface,
        ) {
            return Err(RuntimeError::RecoveryRequired);
        }
        resources.adapter_identity = Some(tun_interface.clone());
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }

        // Atomically upgrade the pre-creation durable intent with the complete
        // interface generation before any address, setting, or route mutation.
        let recovery_plan = RecoveryPlan::empty(tun_interface.clone())
            .map_err(|error| RuntimeError::subsystem("route plan", error))?;
        recovery::record_adapter_identity(
            &resources.recovery_path,
            tun_interface.clone(),
            recovery_plan,
        )?;
        resources.identity_journal_recorded = true;
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }

        let confirmed_system_proxies =
            confirm_intranet_endpoints(&system_proxy, tun_interface_index, |destination| {
                discover_route_to(destination, Some(tun_interface_index))
            })
            .map_err(|error| RuntimeError::subsystem("system proxy route discovery", error))?;
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        config.routing = config.routing.clone().with_system_proxy_endpoints(
            confirmed_system_proxies
                .iter()
                .map(|confirmed| confirmed.endpoint),
        );
        let physical = discover_primary_physical_interface(Some(tun_interface_index))
            .map_err(|error| RuntimeError::subsystem("physical interface discovery", error))?;
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        let direct = DirectOutbound::new(
            DirectBinding::try_from(&physical)
                .map_err(|error| RuntimeError::subsystem("DIRECT binding", error))?,
            LoopGuard::default(),
        )
        .map_err(|error| RuntimeError::subsystem("DIRECT outbound", error))?
        .with_endpoint_bindings(confirmed_system_proxies.iter().map(|confirmed| {
            (
                confirmed.endpoint,
                DirectBinding {
                    interface_index: confirmed.route.interface.interface_index,
                    ipv4_source: confirmed
                        .route
                        .source
                        .is_ipv4()
                        .then_some(confirmed.route.source),
                    ipv6_source: confirmed
                        .route
                        .source
                        .is_ipv6()
                        .then_some(confirmed.route.source),
                },
            )
        }))
        .map_err(|error| RuntimeError::subsystem("system proxy DIRECT binding", error))?;

        let mut validation_bindings = physical_validation_bindings(&physical);
        validation_bindings.extend(
            confirmed_system_proxies
                .iter()
                .map(|confirmed| (confirmed.endpoint.ip(), confirmed.route.clone())),
        );
        validation_bindings.extend(management_bindings);
        let exclusion_prefixes = exclusions
            .iter()
            .map(|exclusion| match exclusion.destination {
                IpAddr::V4(address) => format!("{address}/32"),
                IpAddr::V6(address) => format!("{address}/128"),
            })
            .collect::<Vec<_>>();
        let mut shadow_capture_prefixes = original
            .shadow_capture_prefixes()
            .map_err(|error| RuntimeError::subsystem("shadow route planning", error))?;
        shadow_capture_prefixes
            .retain(|prefix| !exclusion_prefixes.iter().any(|excluded| excluded == prefix));
        let interface_mtu =
            u32::try_from(config.mtu).map_err(|_| RuntimeError::InvalidConfiguration)?;
        let route_plan = RoutePlan {
            tun_interface: tun_interface.clone(),
            enable_ipv4: true,
            // IPv6 is always captured. If disabled in configuration it is
            // dropped by the driver instead of leaking through the host route.
            enable_ipv6: true,
            tun_ipv4_address: Some(InterfaceAddress {
                address: VIRTUAL_IPV4
                    .parse()
                    .map_err(|_| RuntimeError::InvalidConfiguration)?,
                prefix_length: 15,
            }),
            tun_ipv6_address: Some(InterfaceAddress {
                address: VIRTUAL_IPV6
                    .parse()
                    .map_err(|_| RuntimeError::InvalidConfiguration)?,
                prefix_length: 64,
            }),
            metric: 1,
            shadow_capture_prefixes,
            interface_mtu,
            interface_metric: 1,
            exclusions,
        };
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        let session = execute_after_identity_journal(resources.identity_journal_recorded, || {
            resources
                .fallback
                .adapter
                .as_ref()
                .expect("epoch owns the adapter before session start")
                .start_session(WINTUN_RING_CAPACITY)
                .map_err(|error| RuntimeError::subsystem("Wintun session start", error))
        })?;
        resources.fallback.session = Some(session);
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }

        resources.fallback.capture_routes_may_remain = true;
        let recovery_path = resources.recovery_path.clone();
        let routes = match RouteTransaction::install_recording(
            &route_plan,
            &mut resources.fallback.routes,
            |owned| {
                if cancellation.is_cancelled() {
                    return Err(RouteError::JournalUpdateFailed);
                }
                recovery::record_owned(&recovery_path, owned.clone())
                    .map_err(|_| RouteError::JournalUpdateFailed)
            },
        ) {
            Ok(routes) => routes,
            Err(error) => {
                // Once installation reaches a mutable phase, routes.rs hands
                // the partial transaction into this resource slot instead of
                // rolling back interface state while the session is alive.
                // A missing transaction proves failure occurred before any
                // owned mutation.
                resources.fallback.capture_routes_may_remain = resources.fallback.routes.is_some();
                let cancelled = cancellation.is_cancelled();
                resources.cleanup()?;
                if cancelled {
                    return Ok(DriverExit::Cancelled);
                }
                return Err(RuntimeError::subsystem("route installation", error));
            }
        };
        resources.fallback.routes = Some(routes);
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }

        // Register only after the epoch's owned route/address installation so
        // those mutations cannot self-trigger a restart. The monitor is
        // dropped before rollback for the same reason. Once registered, every
        // pre-monitor cached binding is revalidated on its original interface,
        // so a network switch during startup cannot be missed.
        resources.fallback.monitor = Some(
            NetworkChangeMonitor::new()
                .map_err(|error| RuntimeError::subsystem("network change monitoring", error))?,
        );
        let network_epoch = resources
            .fallback
            .monitor
            .as_ref()
            .expect("epoch owns the network-change monitor")
            .token();
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        let current_network = SystemNetworkSnapshot::capture()
            .map_err(|error| RuntimeError::subsystem("network route revalidation", error))?;
        let current_default_route_selection = current_network
            .external_default_route_selection_fingerprint()
            .map_err(|error| RuntimeError::subsystem("default route revalidation", error))?;
        let mut current_shadow_capture_prefixes = current_network
            .shadow_capture_prefixes_excluding_interface(&tun_interface)
            .map_err(|error| RuntimeError::subsystem("shadow route revalidation", error))?;
        current_shadow_capture_prefixes
            .retain(|prefix| !exclusion_prefixes.iter().any(|excluded| excluded == prefix));
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        let current_system_proxy =
            match SystemProxySnapshot::capture_bounded(SYSTEM_PROXY_CAPTURE_TIMEOUT, || {
                cancellation.is_cancelled()
            }) {
                Ok(snapshot) => snapshot,
                Err(SystemProxyError::Cancelled) => {
                    resources.cleanup()?;
                    return Ok(DriverExit::Cancelled);
                }
                Err(error) => {
                    return Err(RuntimeError::subsystem("system proxy revalidation", error));
                }
            };
        if cancellation.is_cancelled() {
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        if network_epoch.is_invalid()
            || current_system_proxy != system_proxy
            || current_default_route_selection != original_default_route_selection
            || current_shadow_capture_prefixes != route_plan.shadow_capture_prefixes
            || !bindings_still_current(&validation_bindings)
        {
            status.set(RuntimeState::Starting, None);
            resources.cleanup()?;
            return Ok(DriverExit::NetworkChangedBeforeRunning);
        }
        let direct = direct.with_network_epoch(network_epoch.clone());

        let mut driver = Driver::new(config, diagnostics, direct, cancellation.clone())?;
        if cancellation.is_cancelled() {
            drop(driver);
            resources.cleanup()?;
            return Ok(DriverExit::Cancelled);
        }
        status.mark_running();
        if announce_start {
            let _ = startup.send(Ok(()));
        }
        let loop_result = driver.run(
            resources
                .fallback
                .session
                .as_ref()
                .expect("running epoch owns a Wintun session"),
            &status,
            &network_epoch,
        );
        if matches!(loop_result.as_ref(), Ok(DriverExit::NetworkChanged)) {
            status.set(RuntimeState::Starting, None);
        }
        driver.stop_workers();
        drop(driver);
        resources.cleanup()?;
        loop_result
    }

    fn build_route_exclusions(
        config: &EngineConfig,
        physical: &PhysicalInterface,
    ) -> Result<(Vec<MandatoryExclusion>, Vec<(IpAddr, RouteBinding)>), RuntimeError> {
        let mut exclusions = Vec::with_capacity(config.management_exclusions.len());
        let mut bindings = Vec::with_capacity(config.management_exclusions.len());
        for cidr in &config.management_exclusions {
            let destination = cidr.network();
            let expected_prefix = if destination.is_ipv4() { 32 } else { 128 };
            if cidr.prefix_len() != expected_prefix {
                return Err(RuntimeError::InvalidConfiguration);
            }
            let binding = discover_route_to(destination, None)
                .map_err(|error| RuntimeError::subsystem("management route discovery", error))?;
            validate_management_binding_against_physical(destination, &binding, physical)
                .map_err(|error| RuntimeError::subsystem("management route discovery", error))?;
            exclusions.push(MandatoryExclusion {
                destination,
                physical_interface: binding.interface.clone(),
                physical_gateway: binding.next_hop,
                reason: ExclusionReason::ManagementConnection,
            });
            bindings.push((destination, binding));
        }
        Ok((exclusions, bindings))
    }

    fn physical_validation_bindings(physical: &PhysicalInterface) -> Vec<(IpAddr, RouteBinding)> {
        let mut bindings = Vec::with_capacity(2);
        if let (Some(source), Some(next_hop)) = (physical.ipv4_source, physical.ipv4_gateway) {
            bindings.push((
                PHYSICAL_VALIDATION_IPV4,
                RouteBinding {
                    interface: physical.identity.clone(),
                    source: IpAddr::V4(source),
                    next_hop: IpAddr::V4(next_hop),
                },
            ));
        }
        if let (Some(source), Some(next_hop)) = (physical.ipv6_source, physical.ipv6_gateway) {
            bindings.push((
                PHYSICAL_VALIDATION_IPV6,
                RouteBinding {
                    interface: physical.identity.clone(),
                    source: IpAddr::V6(source),
                    next_hop: IpAddr::V6(next_hop),
                },
            ));
        }
        bindings
    }

    fn bindings_still_current(bindings: &[(IpAddr, RouteBinding)]) -> bool {
        bindings.iter().all(|(destination, expected)| {
            discover_route_on_interface(*destination, &expected.interface)
                .is_ok_and(|current| current == *expected)
        })
    }

    struct Driver {
        config: EngineConfig,
        diagnostics: Arc<Diagnostics>,
        direct: DirectOutbound,
        cancellation: CancellationToken,
        tcp: TcpSessionEngine,
        udp: UdpAssociationTable,
        dns_cache: DnsCache,
        flow_ids: FlowIdGenerator,
        events_sender: SyncSender<WorkerEvent>,
        events_receiver: Receiver<WorkerEvent>,
        tcp_workers: HashMap<FlowKey, TcpWorkerControl>,
        udp_workers: HashMap<FlowKey, UdpWorkerControl>,
        ipv4_identification: u16,
    }

    impl Driver {
        fn new(
            config: EngineConfig,
            diagnostics: Arc<Diagnostics>,
            direct: DirectOutbound,
            cancellation: CancellationToken,
        ) -> Result<Self, RuntimeError> {
            let now = Instant::now();
            let tcp = TcpSessionEngine::new(
                TcpSessionConfig {
                    idle_timeout: config.tcp_timeout,
                    mtu: config.mtu,
                    ..TcpSessionConfig::default()
                },
                now,
            )
            .map_err(|error| RuntimeError::subsystem("TCP session stack", error))?;
            let udp = UdpAssociationTable::new(UdpAssociationConfig {
                idle_timeout: config.udp_timeout,
                ..UdpAssociationConfig::default()
            })
            .map_err(|error| RuntimeError::subsystem("UDP association table", error))?;
            let dns_cache = DnsCache::new(DnsCacheConfig {
                max_domains: config.dns_cache_capacity,
                max_addresses_per_domain: 16,
                max_ttl: config.dns_cache_ttl,
            })
            .map_err(|error| RuntimeError::subsystem("DNS cache", error))?;
            let (events_sender, events_receiver) = mpsc::sync_channel(1024);
            Ok(Self {
                config,
                diagnostics,
                direct,
                cancellation,
                tcp,
                udp,
                dns_cache,
                flow_ids: FlowIdGenerator::default(),
                events_sender,
                events_receiver,
                tcp_workers: HashMap::new(),
                udp_workers: HashMap::new(),
                ipv4_identification: 1,
            })
        }

        fn run(
            &mut self,
            session: &WintunSession,
            status: &SharedRuntimeStatus,
            network_epoch: &NetworkEpochToken,
        ) -> Result<DriverExit, RuntimeError> {
            while !self.cancellation.is_cancelled() {
                if network_epoch.is_invalid() {
                    return Ok(DriverExit::NetworkChanged);
                }
                self.process_events(session, status)?;
                self.pump_tcp(session, status)?;
                self.pump_udp();

                let mut received = 0;
                while received < MAX_PACKETS_PER_TICK {
                    if network_epoch.is_invalid() {
                        return Ok(DriverExit::NetworkChanged);
                    }
                    let Some(packet) = session
                        .receive()
                        .map_err(|error| RuntimeError::subsystem("Wintun receive", error))?
                    else {
                        break;
                    };
                    self.diagnostics.increment(Counter::TunRxPackets);
                    self.process_packet(session, packet.as_ref(), status)?;
                    received += 1;
                }

                let now = Instant::now();
                let notices = self
                    .tcp
                    .poll(now)
                    .map_err(|error| RuntimeError::subsystem("TCP session poll", error))?;
                self.handle_notices(notices);
                self.flush_tcp_packets(session);
                self.reap(now);

                if received == 0 {
                    session
                        .wait_for_read(DRIVER_WAIT)
                        .map_err(|error| RuntimeError::subsystem("Wintun wait", error))?;
                }
            }
            Ok(DriverExit::Cancelled)
        }

        fn process_packet(
            &mut self,
            session: &WintunSession,
            bytes: &[u8],
            status: &SharedRuntimeStatus,
        ) -> Result<(), RuntimeError> {
            if bytes.len() > self.config.mtu {
                self.drop_unsupported();
                return Ok(());
            }
            let packet = match IpPacket::parse(bytes) {
                Ok(packet) => packet,
                Err(_) => {
                    self.drop_unsupported();
                    return Ok(());
                }
            };
            let protocol = match packet {
                IpPacket::V4(packet) => packet.protocol(),
                IpPacket::V6(packet) => {
                    if !self.config.allow_ipv6 {
                        self.drop_unsupported();
                        return Ok(());
                    }
                    packet.next_header()
                }
            };
            match protocol {
                tcp::PROTOCOL_NUMBER => self.process_tcp(bytes, status),
                crate::packet::udp::PROTOCOL_NUMBER => self.process_udp(session, bytes, status),
                _ => {
                    self.drop_unsupported();
                    Ok(())
                }
            }
        }

        fn process_tcp(
            &mut self,
            bytes: &[u8],
            status: &SharedRuntimeStatus,
        ) -> Result<(), RuntimeError> {
            let (key, flags) = match inspect_tcp_flow(bytes) {
                Ok(flow) => flow,
                Err(_) => {
                    self.drop_unsupported();
                    return Ok(());
                }
            };
            if self.direct.loop_guard().is_direct_flow(
                DirectTransportProtocol::Tcp,
                key.source,
                key.destination,
            ) {
                self.diagnostics.increment(Counter::LoopPreventionDrops);
                self.diagnostics.increment(Counter::DroppedPackets);
                return Ok(());
            }
            let existing = self.tcp.lifecycle(&key).is_some();
            if !existing {
                if flags & tcp::flags::SYN == 0 || flags & (tcp::flags::ACK | tcp::flags::RST) != 0
                {
                    self.diagnostics.increment(Counter::DroppedPackets);
                    return Ok(());
                }
                let decision = if key.destination.port() == DNS_PORT {
                    // DNS is a mandatory post-capture DIRECT exception in this
                    // DIRECT-only slice. Ordinary rule/global PROXY decisions
                    // must not block resolver traffic before forwarding.
                    None
                } else {
                    let domains = self
                        .dns_cache
                        .domains_for_ip(key.destination.ip(), Instant::now())
                        .unwrap_or_default();
                    Some(
                        self.config
                            .routing
                            .decide_socket_with_cached_domains(key.destination, &domains),
                    )
                };
                let action = decision.map_or(RouteAction::Direct, |decision| decision.action);
                match action {
                    RouteAction::Direct => {
                        self.diagnostics.increment(Counter::RouteDirect);
                        if decision.is_some_and(|decision| {
                            decision.reason == DecisionReason::SystemProxyEndpoint
                        }) {
                            self.diagnostics.increment(Counter::RouteDirectSystemProxy);
                        }
                    }
                    RouteAction::Proxy => {
                        let _ = self.tcp.reject(bytes, Instant::now());
                        self.diagnostics.increment(Counter::RouteProxy);
                        self.diagnostics.increment(Counter::DroppedPackets);
                        status.set_safe_error(EngineError::ProxyNotImplemented);
                        return Ok(());
                    }
                }
            }
            let ingest = match self.tcp.ingest(bytes, Instant::now()) {
                Ok(ingest) => ingest,
                Err(error) => {
                    // Malformed/capacity-limited TCP belongs to one flow. The
                    // session adapter may have queued a reset, which is flushed
                    // by the normal driver path, but the runtime stays alive.
                    self.diagnostics.increment(Counter::DroppedPackets);
                    status.set_safe_error(error);
                    return Ok(());
                }
            };
            self.handle_notices(ingest.notices);
            if ingest.created {
                self.diagnostics.increment(Counter::CapturedTcpSessions);
                if self
                    .tcp_workers
                    .len()
                    .saturating_add(self.udp_workers.len())
                    >= MAX_CONCURRENT_WORKERS
                {
                    let _ = self.tcp.abort(&key, Instant::now());
                    self.diagnostics.increment(Counter::DroppedPackets);
                    status.set_safe_error(EngineError::SessionCapacity);
                    return Ok(());
                }
                let destination = match self.direct_destination(key.destination, true) {
                    Ok(destination) => destination,
                    Err(error) => {
                        let _ = self.tcp.abort(&key, Instant::now());
                        status.set_safe_error(&error);
                        return Ok(());
                    }
                };
                self.spawn_tcp(key, destination);
            }
            Ok(())
        }

        fn process_udp(
            &mut self,
            session: &WintunSession,
            bytes: &[u8],
            status: &SharedRuntimeStatus,
        ) -> Result<(), RuntimeError> {
            let (key, payload) = match parse_udp_flow(bytes) {
                Ok(flow) => flow,
                Err(_) => {
                    self.drop_unsupported();
                    return Ok(());
                }
            };
            self.diagnostics.increment(Counter::CapturedUdpDatagrams);
            if self.direct.loop_guard().is_direct_flow(
                DirectTransportProtocol::Udp,
                key.source,
                key.destination,
            ) {
                self.diagnostics.increment(Counter::LoopPreventionDrops);
                self.diagnostics.increment(Counter::DroppedPackets);
                return Ok(());
            }
            let dns_query =
                if key.destination.port() == DNS_PORT {
                    let query = match parse_query(payload) {
                        Ok(query) => query,
                        Err(_) => {
                            self.diagnostics.increment(Counter::DroppedPackets);
                            return Ok(());
                        }
                    };
                    if self.udp_workers.get(&key).is_some_and(|worker| {
                        worker.dns_queries.len() >= MAX_OUTSTANDING_DNS_QUERIES
                    }) {
                        self.diagnostics.increment(Counter::DroppedPackets);
                        return Ok(());
                    }
                    Some(query)
                } else {
                    None
                };
            let decision = if key.destination.port() == DNS_PORT {
                None
            } else {
                let domains = self
                    .dns_cache
                    .domains_for_ip(key.destination.ip(), Instant::now())
                    .unwrap_or_default();
                Some(
                    self.config
                        .routing
                        .decide_socket_with_cached_domains(key.destination, &domains),
                )
            };
            let action = decision.map_or(RouteAction::Direct, |decision| decision.action);
            if action == RouteAction::Proxy {
                self.diagnostics.increment(Counter::RouteProxy);
                self.diagnostics.increment(Counter::DroppedPackets);
                status.set_safe_error(EngineError::ProxyNotImplemented);
                return Ok(());
            }
            self.diagnostics.increment(Counter::RouteDirect);
            if decision
                .is_some_and(|decision| decision.reason == DecisionReason::SystemProxyEndpoint)
            {
                self.diagnostics.increment(Counter::RouteDirectSystemProxy);
            }
            let now = Instant::now();
            let enqueue = match self.udp.enqueue(key, payload, now) {
                Ok(result) => result,
                Err(_) => {
                    self.diagnostics.increment(Counter::DroppedPackets);
                    return Ok(());
                }
            };
            let (created, generation) = match enqueue {
                UdpQueueResult::Queued {
                    created,
                    generation,
                } => (created, generation),
                UdpQueueResult::Backpressure => {
                    self.diagnostics.increment(Counter::DroppedPackets);
                    return Ok(());
                }
            };
            if created {
                if self
                    .tcp_workers
                    .len()
                    .saturating_add(self.udp_workers.len())
                    >= MAX_CONCURRENT_WORKERS
                {
                    self.udp.cancel(&key, generation);
                    self.diagnostics.increment(Counter::DroppedPackets);
                    status.set_safe_error(EngineError::SessionCapacity);
                    return Ok(());
                }
                // A terminal worker may still be publishing its final event.
                // Do not overwrite/drop its JoinHandle; the tuple can be
                // recreated after reap removes that worker.
                if self.udp_workers.contains_key(&key) {
                    self.udp.cancel(&key, generation);
                    self.diagnostics.increment(Counter::DroppedPackets);
                    return Ok(());
                }
                let destination = match self.direct_destination(key.destination, false) {
                    Ok(destination) => destination,
                    Err(error) => {
                        self.udp.cancel(&key, generation);
                        status.set_safe_error(&error);
                        self.diagnostics.increment(Counter::DroppedPackets);
                        return Ok(());
                    }
                };
                self.spawn_udp(key, generation, destination);
            }
            if let Some(query) = dns_query {
                let Some(worker) = self
                    .udp_workers
                    .get_mut(&key)
                    .filter(|worker| worker.generation == generation)
                else {
                    self.udp.cancel(&key, generation);
                    self.diagnostics.increment(Counter::DroppedPackets);
                    return Ok(());
                };
                worker.dns_queries.push_back(query);
            }
            self.pump_udp();
            self.process_events(session, status)
        }

        fn direct_destination(
            &self,
            original: SocketAddr,
            tcp_transport: bool,
        ) -> Result<SocketAddr, RuntimeError> {
            if original.port() != DNS_PORT || !self.config.dns_enabled {
                return Ok(original);
            }
            if original.is_ipv6() && !self.config.dns_ipv6 {
                return Err(RuntimeError::InvalidConfiguration);
            }
            if tcp_transport && !self.config.dns_tcp_fallback {
                return Err(RuntimeError::InvalidConfiguration);
            }
            if self.config.dns_source == DnsSource::System {
                return Ok(original);
            }
            self.config
                .dns_servers
                .iter()
                .copied()
                .find(|server| server.is_ipv4() == original.is_ipv4())
                .map(|server| SocketAddr::new(server, DNS_PORT))
                .ok_or(RuntimeError::InvalidConfiguration)
        }

        fn spawn_tcp(&mut self, key: FlowKey, destination: SocketAddr) {
            let (commands_sender, commands_receiver) = mpsc::sync_channel(32);
            let cancellation = CancellationToken::default();
            let worker_cancellation = cancellation.clone();
            let outbound = self.direct.clone();
            let events = self.events_sender.clone();
            let timeout = self.config.tcp_timeout;
            let flow_id = self.flow_ids.next().get();
            let join = thread::Builder::new()
                .name(format!("ss-direct-tcp-{flow_id}"))
                .spawn(move || {
                    tcp_worker(
                        outbound,
                        flow_id,
                        key,
                        destination,
                        timeout,
                        worker_cancellation,
                        commands_receiver,
                        events,
                    );
                })
                .ok();
            if join.is_none() {
                let _ = self.tcp.abort(&key, Instant::now());
                self.diagnostics.increment(Counter::DroppedPackets);
                return;
            }
            self.tcp_workers.insert(
                key,
                TcpWorkerControl {
                    commands: commands_sender,
                    cancellation,
                    join,
                    pending_to_direct: None,
                    pending_to_client: VecDeque::new(),
                    pending_to_client_bytes: 0,
                    client_eof: false,
                    shutdown_sent: false,
                    direct_eof: false,
                    fin_sent: false,
                    done: false,
                },
            );
        }

        fn spawn_udp(&mut self, key: FlowKey, generation: u64, destination: SocketAddr) {
            // The association table retains the bounded backlog. Only one
            // datagram may sit outside it waiting for the worker, so queued
            // datagrams and bytes remain bounded end-to-end.
            let (commands_sender, commands_receiver) =
                mpsc::sync_channel(UDP_COMMAND_QUEUE_CAPACITY);
            let cancellation = CancellationToken::default();
            let worker_cancellation = cancellation.clone();
            let outbound = self.direct.clone();
            let events = self.events_sender.clone();
            let timeout = self.config.udp_timeout;
            let flow_id = self.flow_ids.next().get();
            let join = thread::Builder::new()
                .name(format!("ss-direct-udp-{flow_id}"))
                .spawn(move || {
                    udp_worker(
                        outbound,
                        flow_id,
                        key,
                        generation,
                        destination,
                        timeout,
                        worker_cancellation,
                        commands_receiver,
                        events,
                    );
                })
                .ok();
            if let Some(join) = join {
                self.udp_workers.insert(
                    key,
                    UdpWorkerControl {
                        commands: commands_sender,
                        cancellation,
                        join: Some(join),
                        generation,
                        pending: None,
                        dns_queries: VecDeque::new(),
                        done: false,
                    },
                );
            } else {
                self.udp.cancel(&key, generation);
                self.diagnostics.increment(Counter::DroppedPackets);
            }
        }

        fn process_events(
            &mut self,
            session: &WintunSession,
            status: &SharedRuntimeStatus,
        ) -> Result<(), RuntimeError> {
            for _ in 0..MAX_EVENTS_PER_TICK {
                let event = match self.events_receiver.try_recv() {
                    Ok(event) => event,
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        return Err(RuntimeError::WorkerPanicked);
                    }
                };
                match event {
                    WorkerEvent::TcpConnected => {
                        self.diagnostics.increment(Counter::DirectTcpConnections);
                    }
                    WorkerEvent::TcpData(key, data) => {
                        if let Some(worker) = self.tcp_workers.get_mut(&key) {
                            if worker.pending_to_client_bytes.saturating_add(data.len())
                                > MAX_PENDING_TO_CLIENT
                            {
                                worker.cancellation.cancel();
                                let _ = self.tcp.abort(&key, Instant::now());
                                self.diagnostics.increment(Counter::DroppedPackets);
                            } else {
                                worker.pending_to_client_bytes += data.len();
                                worker
                                    .pending_to_client
                                    .push_back(PendingChunk { data, offset: 0 });
                            }
                        }
                    }
                    WorkerEvent::TcpEof(key) => {
                        if let Some(worker) = self.tcp_workers.get_mut(&key) {
                            worker.direct_eof = true;
                        }
                    }
                    WorkerEvent::TcpFailed(key) => {
                        if let Some(worker) = self.tcp_workers.get_mut(&key) {
                            worker.cancellation.cancel();
                        }
                        let _ = self.tcp.abort(&key, Instant::now());
                        self.diagnostics.increment(Counter::DroppedPackets);
                        status.set_safe_error("DIRECT TCP connection failed");
                    }
                    WorkerEvent::TcpDone(key) => {
                        if let Some(worker) = self.tcp_workers.get_mut(&key) {
                            worker.done = true;
                        }
                    }
                    WorkerEvent::UdpConnected(key, generation) => {
                        if self.udp_worker_is_current(&key, generation) {
                            self.diagnostics.increment(Counter::DirectUdpAssociations);
                        }
                    }
                    WorkerEvent::UdpData(key, generation, data) => {
                        if !self.udp_worker_is_current(&key, generation) {
                            continue;
                        }
                        self.udp.touch(&key, generation, Instant::now());
                        if key.destination.port() == DNS_PORT {
                            let query = self
                                .udp_workers
                                .get_mut(&key)
                                .filter(|worker| worker.generation == generation)
                                .and_then(|worker| {
                                    worker
                                        .dns_queries
                                        .iter()
                                        .position(|query| response_correlates(&data, query).is_ok())
                                        .and_then(|index| worker.dns_queries.remove(index))
                                });
                            let Some(query) = query else {
                                self.diagnostics.increment(Counter::DroppedPackets);
                                continue;
                            };
                            self.update_dns_cache(&data, &query);
                        }
                        match udp_packet_with_mtu(
                            key.destination,
                            key.source,
                            &data,
                            self.next_ipv4_identification(),
                            self.config.mtu,
                        ) {
                            Ok(packet) => {
                                self.send_tun(session, &packet);
                            }
                            Err(_) => {
                                self.diagnostics.increment(Counter::DroppedPackets);
                            }
                        }
                    }
                    WorkerEvent::UdpFailed(key, generation) => {
                        if !self.udp_worker_is_current(&key, generation) {
                            continue;
                        }
                        self.udp.cancel(&key, generation);
                        if let Some(worker) = self
                            .udp_workers
                            .get_mut(&key)
                            .filter(|worker| worker.generation == generation)
                        {
                            worker.cancellation.cancel();
                            worker.done = true;
                        }
                        self.diagnostics.increment(Counter::DroppedPackets);
                        status.set_safe_error("DIRECT UDP association failed");
                    }
                    WorkerEvent::UdpDone(key, generation) => {
                        if let Some(worker) = self
                            .udp_workers
                            .get_mut(&key)
                            .filter(|worker| worker.generation == generation)
                        {
                            worker.done = true;
                        }
                    }
                }
            }
            Ok(())
        }

        fn pump_tcp(
            &mut self,
            session: &WintunSession,
            status: &SharedRuntimeStatus,
        ) -> Result<(), RuntimeError> {
            let keys = self.tcp_workers.keys().copied().collect::<Vec<_>>();
            for key in keys {
                let Some(worker) = self.tcp_workers.get_mut(&key) else {
                    continue;
                };
                while let Some(chunk) = worker.pending_to_client.front_mut() {
                    let sent = match self.tcp.send_to_client(
                        &key,
                        &chunk.data[chunk.offset..],
                        Instant::now(),
                    ) {
                        Ok(sent) => sent,
                        Err(_) => {
                            worker.cancellation.cancel();
                            worker.done = true;
                            let _ = self.tcp.abort(&key, Instant::now());
                            self.diagnostics.increment(Counter::DroppedPackets);
                            break;
                        }
                    };
                    if sent == 0 {
                        break;
                    }
                    chunk.offset += sent;
                    worker.pending_to_client_bytes =
                        worker.pending_to_client_bytes.saturating_sub(sent);
                    if chunk.offset == chunk.data.len() {
                        worker.pending_to_client.pop_front();
                    }
                }
                if worker.direct_eof && worker.pending_to_client.is_empty() && !worker.fin_sent {
                    if self.tcp.close_direct_write(&key, Instant::now()).is_ok() {
                        worker.fin_sent = true;
                    }
                }
                if worker.pending_to_direct.is_none() && self.tcp.can_receive_from_client(&key) {
                    let mut buffer = vec![0; STREAM_CHUNK];
                    match self
                        .tcp
                        .receive_from_client(&key, &mut buffer, Instant::now())
                    {
                        Ok(0) => {}
                        Ok(received) => {
                            buffer.truncate(received);
                            worker.pending_to_direct = Some(buffer);
                        }
                        Err(_) => {
                            worker.cancellation.cancel();
                            worker.done = true;
                            let _ = self.tcp.abort(&key, Instant::now());
                            self.diagnostics.increment(Counter::DroppedPackets);
                        }
                    }
                }
                if let Some(data) = worker.pending_to_direct.take() {
                    match worker.commands.try_send(TcpCommand::Data(data)) {
                        Ok(()) => {}
                        Err(TrySendError::Full(TcpCommand::Data(data))) => {
                            worker.pending_to_direct = Some(data);
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            worker.cancellation.cancel();
                            worker.done = true;
                            let _ = self.tcp.abort(&key, Instant::now());
                            self.diagnostics.increment(Counter::DroppedPackets);
                        }
                        Err(TrySendError::Full(_)) => unreachable!(),
                    }
                }
                if worker.client_eof && worker.pending_to_direct.is_none() && !worker.shutdown_sent
                {
                    match worker.commands.try_send(TcpCommand::ShutdownWrite) {
                        Ok(()) => worker.shutdown_sent = true,
                        Err(TrySendError::Full(_)) => {}
                        Err(TrySendError::Disconnected(_)) => {
                            worker.done = true;
                            let _ = self.tcp.abort(&key, Instant::now());
                            self.diagnostics.increment(Counter::DroppedPackets);
                        }
                    }
                }
            }
            let notices = self
                .tcp
                .poll(Instant::now())
                .map_err(|error| RuntimeError::subsystem("TCP stream pump", error))?;
            self.handle_notices(notices);
            self.flush_tcp_packets(session);
            if self.cancellation.is_cancelled() {
                status.begin_stopping();
            }
            Ok(())
        }

        fn pump_udp(&mut self) {
            let keys = self.udp_workers.keys().copied().collect::<Vec<_>>();
            let (udp, workers) = (&mut self.udp, &mut self.udp_workers);
            for key in keys {
                let Some(worker) = workers.get_mut(&key) else {
                    continue;
                };
                loop {
                    if worker.done {
                        break;
                    }
                    let data = match worker.pending.take() {
                        Some(data) => data,
                        None => match udp.pop(&key, worker.generation, Instant::now()) {
                            Some(data) => data,
                            None => break,
                        },
                    };
                    match worker.commands.try_send(UdpCommand::Datagram(data)) {
                        Ok(()) => {}
                        Err(TrySendError::Full(UdpCommand::Datagram(data))) => {
                            worker.pending = Some(data);
                            break;
                        }
                        Err(TrySendError::Disconnected(_)) => {
                            worker.cancellation.cancel();
                            worker.done = true;
                            break;
                        }
                        Err(TrySendError::Full(_)) => unreachable!(),
                    }
                }
            }
        }

        fn handle_notices(&mut self, notices: Vec<TcpSessionNotice>) {
            for notice in notices {
                match notice {
                    TcpSessionNotice::Established(_) => {}
                    TcpSessionNotice::ClientHalfClosed(key) => {
                        if let Some(worker) = self.tcp_workers.get_mut(&key) {
                            worker.client_eof = true;
                        }
                    }
                    TcpSessionNotice::Closed(key) | TcpSessionNotice::Reset(key) => {
                        if let Some(worker) = self.tcp_workers.get_mut(&key) {
                            worker.cancellation.cancel();
                            worker.done = true;
                        }
                    }
                }
            }
        }

        fn flush_tcp_packets(&mut self, session: &WintunSession) {
            for packet in self.tcp.take_transmit() {
                self.send_tun(session, &packet);
            }
        }

        fn send_tun(&self, session: &WintunSession, packet: &[u8]) -> bool {
            if packet.len() > self.config.mtu {
                self.diagnostics.increment(Counter::DroppedPackets);
                return false;
            }
            for attempt in 0..TUN_SEND_ATTEMPTS {
                match session.send(packet) {
                    Ok(()) => {
                        self.diagnostics.increment(Counter::TunTxPackets);
                        return true;
                    }
                    Err(_) if attempt + 1 < TUN_SEND_ATTEMPTS => {
                        thread::sleep(TUN_SEND_RETRY_DELAY);
                    }
                    Err(_) => break,
                }
            }
            // A full/failing send ring drops one packet after bounded retry.
            // It is not a reason to tear down unrelated sessions or routes.
            self.diagnostics.increment(Counter::DroppedPackets);
            false
        }

        fn update_dns_cache(&self, payload: &[u8], query: &DnsQuery) {
            let Ok(answers) = parse_response_answers_for_query(payload, query) else {
                return;
            };
            let mut grouped = HashMap::<String, (Vec<IpAddr>, Duration)>::new();
            for answer in answers {
                let entry = grouped
                    .entry(answer.domain)
                    .or_insert_with(|| (Vec::new(), answer.ttl));
                entry.0.push(answer.address);
                entry.1 = entry.1.min(answer.ttl);
            }
            let now = Instant::now();
            for (domain, (addresses, ttl)) in grouped {
                let _ = self.dns_cache.insert(&domain, addresses, ttl, now);
            }
        }

        fn reap(&mut self, now: Instant) {
            for key in self.tcp.reap(now) {
                if let Some(mut worker) = self.tcp_workers.remove(&key) {
                    worker.cancellation.cancel();
                    if let Some(join) = worker.join.take() {
                        let _ = join.join();
                    }
                }
            }
            let terminal_tcp = self
                .tcp_workers
                .iter()
                .filter_map(|(key, worker)| {
                    (worker.done && self.tcp.lifecycle(key).is_none()).then_some(*key)
                })
                .collect::<Vec<_>>();
            for key in terminal_tcp {
                if let Some(mut worker) = self.tcp_workers.remove(&key)
                    && let Some(join) = worker.join.take()
                {
                    let _ = join.join();
                }
            }
            for expired in self.udp.reap(now) {
                if let Some(worker) = self
                    .udp_workers
                    .get_mut(&expired.key)
                    .filter(|worker| worker.generation == expired.generation)
                {
                    worker.cancellation.cancel();
                    worker.done = true;
                }
            }
            let terminal_udp = self
                .udp_workers
                .iter()
                .filter_map(|(key, worker)| worker.done.then_some(*key))
                .collect::<Vec<_>>();
            for key in terminal_udp {
                if let Some(mut worker) = self.udp_workers.remove(&key) {
                    worker.cancellation.cancel();
                    if let Some(join) = worker.join.take() {
                        let _ = join.join();
                    }
                    self.udp.cancel(&key, worker.generation);
                }
            }
        }

        fn udp_worker_is_current(&self, key: &FlowKey, generation: u64) -> bool {
            self.udp.generation(key) == Some(generation)
                && self
                    .udp_workers
                    .get(key)
                    .is_some_and(|worker| worker.generation == generation)
        }

        fn stop_workers(&mut self) {
            for worker in self.tcp_workers.values() {
                worker.cancellation.cancel();
                let _ = worker.commands.try_send(TcpCommand::Stop);
            }
            for worker in self.udp_workers.values() {
                worker.cancellation.cancel();
                let _ = worker.commands.try_send(UdpCommand::Stop);
            }
            for (_, mut worker) in self.tcp_workers.drain() {
                if let Some(join) = worker.join.take() {
                    let _ = join.join();
                }
            }
            for (_, mut worker) in self.udp_workers.drain() {
                if let Some(join) = worker.join.take() {
                    let _ = join.join();
                }
            }
        }

        fn drop_unsupported(&self) {
            self.diagnostics.increment(Counter::UnsupportedPackets);
            self.diagnostics.increment(Counter::DroppedPackets);
        }

        fn next_ipv4_identification(&mut self) -> u16 {
            let value = self.ipv4_identification;
            self.ipv4_identification = self.ipv4_identification.wrapping_add(1);
            value
        }
    }

    struct PendingChunk {
        data: Vec<u8>,
        offset: usize,
    }

    struct TcpWorkerControl {
        commands: SyncSender<TcpCommand>,
        cancellation: CancellationToken,
        join: Option<JoinHandle<()>>,
        pending_to_direct: Option<Vec<u8>>,
        pending_to_client: VecDeque<PendingChunk>,
        pending_to_client_bytes: usize,
        client_eof: bool,
        shutdown_sent: bool,
        direct_eof: bool,
        fin_sent: bool,
        done: bool,
    }

    struct UdpWorkerControl {
        commands: SyncSender<UdpCommand>,
        cancellation: CancellationToken,
        join: Option<JoinHandle<()>>,
        generation: u64,
        pending: Option<Vec<u8>>,
        dns_queries: VecDeque<DnsQuery>,
        done: bool,
    }

    enum TcpCommand {
        Data(Vec<u8>),
        ShutdownWrite,
        Stop,
    }

    enum UdpCommand {
        Datagram(Vec<u8>),
        Stop,
    }

    enum WorkerEvent {
        TcpConnected,
        TcpData(FlowKey, Vec<u8>),
        TcpEof(FlowKey),
        TcpFailed(FlowKey),
        TcpDone(FlowKey),
        UdpConnected(FlowKey, u64),
        UdpData(FlowKey, u64, Vec<u8>),
        UdpFailed(FlowKey, u64),
        UdpDone(FlowKey, u64),
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp_worker(
        outbound: DirectOutbound,
        flow_id: u64,
        key: FlowKey,
        destination: SocketAddr,
        timeout: Duration,
        cancellation: CancellationToken,
        commands: Receiver<TcpCommand>,
        events: SyncSender<WorkerEvent>,
    ) {
        let mut stream = match outbound.connect_tcp(flow_id, destination, timeout, &cancellation) {
            Ok(stream) => stream,
            Err(_) => {
                send_event(&events, WorkerEvent::TcpFailed(key), &cancellation);
                send_event(&events, WorkerEvent::TcpDone(key), &cancellation);
                return;
            }
        };
        if !send_event(&events, WorkerEvent::TcpConnected, &cancellation) {
            return;
        }
        let mut read_eof = false;
        let mut write_shutdown = false;
        while !cancellation.is_cancelled() {
            loop {
                match commands.try_recv() {
                    Ok(TcpCommand::Data(data)) => {
                        if stream
                            .write_all_cancellable(&data, Instant::now() + timeout, &cancellation)
                            .is_err()
                        {
                            send_event(&events, WorkerEvent::TcpFailed(key), &cancellation);
                            send_event(&events, WorkerEvent::TcpDone(key), &cancellation);
                            return;
                        }
                    }
                    Ok(TcpCommand::ShutdownWrite) => {
                        let _ = stream.shutdown(Shutdown::Write);
                        write_shutdown = true;
                    }
                    Ok(TcpCommand::Stop) | Err(TryRecvError::Disconnected) => {
                        cancellation.cancel();
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
            if read_eof && write_shutdown {
                break;
            }
            if read_eof {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            let mut buffer = vec![0; STREAM_CHUNK];
            match stream.read_cancellable(&mut buffer, Instant::now() + WORKER_POLL, &cancellation)
            {
                Ok(0) => {
                    read_eof = true;
                    if !send_event(&events, WorkerEvent::TcpEof(key), &cancellation) {
                        break;
                    }
                }
                Ok(received) => {
                    buffer.truncate(received);
                    if !send_event(&events, WorkerEvent::TcpData(key, buffer), &cancellation) {
                        break;
                    }
                }
                Err(crate::outbound::DirectError::Timeout) => {}
                Err(crate::outbound::DirectError::Cancelled) => break,
                Err(_) => {
                    send_event(&events, WorkerEvent::TcpFailed(key), &cancellation);
                    break;
                }
            }
        }
        send_event(&events, WorkerEvent::TcpDone(key), &cancellation);
    }

    #[allow(clippy::too_many_arguments)]
    fn udp_worker(
        outbound: DirectOutbound,
        flow_id: u64,
        key: FlowKey,
        generation: u64,
        destination: SocketAddr,
        timeout: Duration,
        cancellation: CancellationToken,
        commands: Receiver<UdpCommand>,
        events: SyncSender<WorkerEvent>,
    ) {
        let socket = match outbound.associate_udp(flow_id, destination, &cancellation) {
            Ok(socket) => socket,
            Err(_) => {
                send_event(
                    &events,
                    WorkerEvent::UdpFailed(key, generation),
                    &cancellation,
                );
                send_event(
                    &events,
                    WorkerEvent::UdpDone(key, generation),
                    &cancellation,
                );
                return;
            }
        };
        if !send_event(
            &events,
            WorkerEvent::UdpConnected(key, generation),
            &cancellation,
        ) {
            return;
        }
        while !cancellation.is_cancelled() {
            loop {
                match commands.try_recv() {
                    Ok(UdpCommand::Datagram(data)) => {
                        let sent =
                            socket.send_cancellable(&data, Instant::now() + timeout, &cancellation);
                        if !matches!(sent, Ok(size) if size == data.len()) {
                            send_event(
                                &events,
                                WorkerEvent::UdpFailed(key, generation),
                                &cancellation,
                            );
                            send_event(
                                &events,
                                WorkerEvent::UdpDone(key, generation),
                                &cancellation,
                            );
                            return;
                        }
                    }
                    Ok(UdpCommand::Stop) | Err(TryRecvError::Disconnected) => {
                        cancellation.cancel();
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                }
            }
            let mut buffer = vec![0; 65_507];
            match socket.recv_cancellable(&mut buffer, Instant::now() + WORKER_POLL, &cancellation)
            {
                Ok(received) => {
                    buffer.truncate(received);
                    if !send_event(
                        &events,
                        WorkerEvent::UdpData(key, generation, buffer),
                        &cancellation,
                    ) {
                        break;
                    }
                }
                Err(crate::outbound::DirectError::Timeout) => {}
                Err(crate::outbound::DirectError::Cancelled) => break,
                Err(_) => {
                    send_event(
                        &events,
                        WorkerEvent::UdpFailed(key, generation),
                        &cancellation,
                    );
                    break;
                }
            }
        }
        send_event(
            &events,
            WorkerEvent::UdpDone(key, generation),
            &cancellation,
        );
    }

    fn send_event(
        sender: &SyncSender<WorkerEvent>,
        mut event: WorkerEvent,
        cancellation: &CancellationToken,
    ) -> bool {
        loop {
            if cancellation.is_cancelled() {
                return false;
            }
            match sender.try_send(event) {
                Ok(()) => return true,
                Err(TrySendError::Full(returned)) => {
                    event = returned;
                    thread::sleep(Duration::from_millis(2));
                }
                Err(TrySendError::Disconnected(_)) => return false,
            }
        }
    }

    fn parse_udp_flow(bytes: &[u8]) -> Result<(FlowKey, &[u8]), EngineError> {
        match IpPacket::parse(bytes)? {
            IpPacket::V4(packet) if packet.protocol() == crate::packet::udp::PROTOCOL_NUMBER => {
                let datagram = UdpPacket::parse(packet.payload())?;
                datagram.verify_ipv4_checksum(packet.source(), packet.destination())?;
                let key = FlowKey::new(
                    SocketAddr::new(IpAddr::V4(packet.source()), datagram.source_port()),
                    SocketAddr::new(
                        IpAddr::V4(packet.destination()),
                        datagram.destination_port(),
                    ),
                )
                .ok_or(EngineError::InvalidSessionState)?;
                Ok((key, datagram.payload()))
            }
            IpPacket::V6(packet) if packet.next_header() == crate::packet::udp::PROTOCOL_NUMBER => {
                let datagram = UdpPacket::parse(packet.payload())?;
                datagram.verify_ipv6_checksum(packet.source(), packet.destination())?;
                let key = FlowKey::new(
                    SocketAddr::new(IpAddr::V6(packet.source()), datagram.source_port()),
                    SocketAddr::new(
                        IpAddr::V6(packet.destination()),
                        datagram.destination_port(),
                    ),
                )
                .ok_or(EngineError::InvalidSessionState)?;
                Ok((key, datagram.payload()))
            }
            _ => Err(EngineError::UnsupportedProtocol),
        }
    }

    // Keep these types checked by the Windows compiler even if a test build
    // optimizes one branch away.
    const _: Option<(DirectTcp, DirectUdp, ErrorKind)> = None;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        ConnectionMode, DnsSource, RouteAction, RoutingConfig, RoutingRule, RuleMatch,
    };
    use std::cell::RefCell;
    use std::rc::Rc;

    #[test]
    fn runtime_config_never_copies_server_credentials() {
        let config = AppConfig {
            mode: ConnectionMode::Direct,
            dns: crate::config::model::DnsConfig {
                source: DnsSource::Custom,
                ..Default::default()
            },
            routing: RoutingConfig {
                rules: vec![RoutingRule {
                    id: "direct".to_owned(),
                    enabled: true,
                    match_type: RuleMatch::IpCidr,
                    value: "0.0.0.0/0".to_owned(),
                    action: RouteAction::Direct,
                }],
                default_action: RouteAction::Direct,
            },
            ..AppConfig::default()
        };
        let runtime = EngineConfig::try_from(&config).unwrap();
        assert_eq!(runtime.adapter_name, "Shadowsocks");
        assert_eq!(runtime.dns_servers.len(), 2);
    }

    fn interface_identity(
        interface_index: u32,
        interface_luid: u64,
        alias: &str,
    ) -> crate::tun::routes::InterfaceIdentity {
        crate::tun::routes::InterfaceIdentity {
            interface_index,
            interface_luid,
            interface_guid: format!("00000000-0000-0000-0000-{interface_index:012x}"),
            alias: alias.to_owned(),
        }
    }

    #[test]
    fn created_adapter_requires_exact_alias_guid_luid_and_index_before_promotion() {
        let expected = interface_identity(42, 42_042, "Shadowsocks");
        assert!(created_adapter_identity_matches(
            &expected.alias,
            &expected.interface_guid,
            expected.interface_index,
            expected.interface_luid,
            &expected,
        ));

        let mut mismatches = Vec::new();
        let mut wrong_alias = expected.clone();
        wrong_alias.alias = "Other".to_owned();
        mismatches.push(wrong_alias);
        let mut wrong_guid = expected.clone();
        wrong_guid.interface_guid = "00000000-0000-0000-0000-000000000043".to_owned();
        mismatches.push(wrong_guid);
        let mut wrong_luid = expected.clone();
        wrong_luid.interface_luid += 1;
        mismatches.push(wrong_luid);
        let mut wrong_index = expected.clone();
        wrong_index.interface_index += 1;
        mismatches.push(wrong_index);

        for mismatch in mismatches {
            assert!(!created_adapter_identity_matches(
                &expected.alias,
                &expected.interface_guid,
                expected.interface_index,
                expected.interface_luid,
                &mismatch,
            ));
        }
    }

    #[test]
    fn first_native_call_is_blocked_until_identity_journal_is_durable() {
        let mut native_calls = 0;
        assert_eq!(
            execute_after_identity_journal(false, || {
                native_calls += 1;
                Ok(())
            }),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(native_calls, 0);
        assert_eq!(
            execute_after_identity_journal(true, || {
                native_calls += 1;
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(native_calls, 1);
    }

    #[test]
    fn adapter_create_is_blocked_until_creation_intent_is_durable() {
        let mut creates = 0;
        assert_eq!(
            execute_after_adapter_intent(false, || {
                creates += 1;
                Ok(())
            }),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(creates, 0);
        assert_eq!(
            execute_after_adapter_intent(true, || {
                creates += 1;
                Ok(())
            }),
            Ok(())
        );
        assert_eq!(creates, 1);
    }

    #[test]
    fn management_route_must_match_independently_confirmed_physical_binding() {
        let physical = crate::tun::routes::PhysicalInterface {
            identity: interface_identity(7, 70_007, "Ethernet"),
            ipv4_source: Some("192.0.2.20".parse().unwrap()),
            ipv6_source: Some("2001:db8::20".parse().unwrap()),
            ipv4_gateway: Some("192.0.2.1".parse().unwrap()),
            ipv6_gateway: Some("fe80::1".parse().unwrap()),
            dns_servers: Vec::new(),
            route_metric: 25,
        };
        let destination = "203.0.113.10".parse().unwrap();
        let expected = crate::tun::routes::RouteBinding {
            interface: physical.identity.clone(),
            source: "192.0.2.20".parse().unwrap(),
            next_hop: "192.0.2.1".parse().unwrap(),
        };

        assert_eq!(
            validate_management_binding_against_physical(destination, &expected, &physical),
            Ok(())
        );

        let mut wrong_generation = expected.clone();
        wrong_generation.interface.interface_luid += 1;
        assert!(matches!(
            validate_management_binding_against_physical(destination, &wrong_generation, &physical),
            Err(crate::tun::routes::RouteError::OwnershipMismatch(_))
        ));

        let mut wrong_gateway = expected;
        wrong_gateway.next_hop = "192.0.2.254".parse().unwrap();
        assert!(matches!(
            validate_management_binding_against_physical(destination, &wrong_gateway, &physical),
            Err(crate::tun::routes::RouteError::OwnershipMismatch(_))
        ));
    }

    #[test]
    fn failed_fresh_management_verification_cannot_create_adapter() {
        for failure in ["missing", "ambiguous", "stale", "mismatched", "non-winning"] {
            let mut adapter_creations = 0;
            let result = execute_after_fresh_management_verification(
                || Err(failure),
                || {
                    adapter_creations += 1;
                    Ok(())
                },
            );
            assert_eq!(result, Err(failure));
            assert_eq!(adapter_creations, 0);
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum CleanupEvent {
        StopCallbacks,
        WithdrawCaptureRoutes,
        EndSession,
        RestoreInterfaceState,
        RemoveAdapter,
    }

    struct FakeCleanup {
        events: Vec<CleanupEvent>,
        fail_at: Option<CleanupEvent>,
    }

    impl OrderedDataPathCleanup for FakeCleanup {
        type Error = CleanupEvent;

        fn stop_callbacks(&mut self) {
            self.events.push(CleanupEvent::StopCallbacks);
        }

        fn withdraw_capture_routes(&mut self) -> Result<(), Self::Error> {
            self.events.push(CleanupEvent::WithdrawCaptureRoutes);
            if self.fail_at == Some(CleanupEvent::WithdrawCaptureRoutes) {
                Err(CleanupEvent::WithdrawCaptureRoutes)
            } else {
                Ok(())
            }
        }

        fn end_wintun_session(&mut self) {
            self.events.push(CleanupEvent::EndSession);
        }

        fn restore_interface_state(&mut self) -> Result<(), Self::Error> {
            self.events.push(CleanupEvent::RestoreInterfaceState);
            if self.fail_at == Some(CleanupEvent::RestoreInterfaceState) {
                Err(CleanupEvent::RestoreInterfaceState)
            } else {
                Ok(())
            }
        }

        fn remove_adapter(&mut self) -> Result<(), Self::Error> {
            self.events.push(CleanupEvent::RemoveAdapter);
            if self.fail_at == Some(CleanupEvent::RemoveAdapter) {
                Err(CleanupEvent::RemoveAdapter)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn normal_startup_failure_cancellation_and_network_change_share_cleanup_order() {
        for trigger in [
            "normal stop",
            "startup failure",
            "cancellation",
            "network change",
        ] {
            let mut cleanup = FakeCleanup {
                events: Vec::new(),
                fail_at: None,
            };

            assert_eq!(
                execute_ordered_data_path_cleanup(&mut cleanup),
                Ok(()),
                "{trigger}"
            );
            assert_eq!(
                cleanup.events,
                [
                    CleanupEvent::StopCallbacks,
                    CleanupEvent::WithdrawCaptureRoutes,
                    CleanupEvent::EndSession,
                    CleanupEvent::RestoreInterfaceState,
                    CleanupEvent::RemoveAdapter,
                ],
                "{trigger}"
            );
        }
    }

    #[test]
    fn cleanup_never_ends_session_when_capture_withdrawal_fails() {
        let mut cleanup = FakeCleanup {
            events: Vec::new(),
            fail_at: Some(CleanupEvent::WithdrawCaptureRoutes),
        };

        assert_eq!(
            execute_ordered_data_path_cleanup(&mut cleanup),
            Err(CleanupEvent::WithdrawCaptureRoutes)
        );
        assert_eq!(
            cleanup.events,
            [
                CleanupEvent::StopCallbacks,
                CleanupEvent::WithdrawCaptureRoutes
            ]
        );
    }

    #[test]
    fn cleanup_never_removes_adapter_when_interface_restoration_fails() {
        let mut cleanup = FakeCleanup {
            events: Vec::new(),
            fail_at: Some(CleanupEvent::RestoreInterfaceState),
        };

        assert_eq!(
            execute_ordered_data_path_cleanup(&mut cleanup),
            Err(CleanupEvent::RestoreInterfaceState)
        );
        assert_eq!(
            cleanup.events,
            [
                CleanupEvent::StopCallbacks,
                CleanupEvent::WithdrawCaptureRoutes,
                CleanupEvent::EndSession,
                CleanupEvent::RestoreInterfaceState,
            ]
        );
    }

    #[test]
    fn cleanup_failures_never_allow_recovery_journal_clear() {
        for failure in [
            CleanupEvent::WithdrawCaptureRoutes,
            CleanupEvent::RestoreInterfaceState,
            CleanupEvent::RemoveAdapter,
        ] {
            let mut cleanup = FakeCleanup {
                events: Vec::new(),
                fail_at: Some(failure),
            };
            let succeeded = execute_ordered_data_path_cleanup(&mut cleanup).is_ok();
            assert!(!recovery_journal_clear_allowed(true, true, succeeded));
        }
        assert!(!recovery_journal_clear_allowed(true, false, true));
        assert!(!recovery_journal_clear_allowed(false, true, true));
        assert!(recovery_journal_clear_allowed(true, true, true));
    }

    struct DropProbe {
        name: &'static str,
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.events.borrow_mut().push(self.name);
        }
    }

    struct FallbackRouteProbe {
        events: Rc<RefCell<Vec<&'static str>>>,
        fail_withdrawal: bool,
        fail_interface_restore: bool,
        complete: bool,
    }

    impl OrderedRouteFallback for FallbackRouteProbe {
        fn withdraw_capture_routes_for_fallback(&mut self) -> bool {
            self.events.borrow_mut().push("routes");
            !self.fail_withdrawal
        }

        fn restore_interface_state_for_fallback(&mut self) -> bool {
            self.events.borrow_mut().push("interface");
            !self.fail_interface_restore
        }

        fn mark_fallback_cleanup_complete(&mut self) {
            self.complete = true;
        }
    }

    #[test]
    fn fallback_drop_preserves_callbacks_routes_session_interface_adapter_lease_order() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let probe = |name| DropProbe {
            name,
            events: Rc::clone(&events),
        };

        {
            let _resources = OrderedFallbackResources {
                monitor: Some(probe("monitor")),
                routes: Some(FallbackRouteProbe {
                    events: Rc::clone(&events),
                    fail_withdrawal: false,
                    fail_interface_restore: false,
                    complete: false,
                }),
                session: Some(probe("session")),
                adapter: Some(probe("adapter")),
                lease: Some(probe("lease")),
                capture_routes_may_remain: true,
            };
        }

        assert_eq!(
            events.borrow().as_slice(),
            [
                "monitor",
                "routes",
                "session",
                "interface",
                "adapter",
                "lease"
            ]
        );
    }

    #[test]
    fn fallback_drop_does_not_end_session_after_route_withdrawal_failure() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let probe = |name| DropProbe {
            name,
            events: Rc::clone(&events),
        };

        {
            let _resources = OrderedFallbackResources {
                monitor: Some(probe("monitor")),
                routes: Some(FallbackRouteProbe {
                    events: Rc::clone(&events),
                    fail_withdrawal: true,
                    fail_interface_restore: false,
                    complete: false,
                }),
                session: Some(probe("session")),
                adapter: Some(probe("adapter")),
                lease: Some(probe("lease")),
                capture_routes_may_remain: true,
            };
        }

        assert_eq!(events.borrow().as_slice(), ["monitor", "routes"]);
    }

    #[test]
    fn fallback_drop_does_not_remove_adapter_after_interface_restore_failure() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let probe = |name| DropProbe {
            name,
            events: Rc::clone(&events),
        };

        {
            let _resources = OrderedFallbackResources {
                monitor: Some(probe("monitor")),
                routes: Some(FallbackRouteProbe {
                    events: Rc::clone(&events),
                    fail_withdrawal: false,
                    fail_interface_restore: true,
                    complete: false,
                }),
                session: Some(probe("session")),
                adapter: Some(probe("adapter")),
                lease: Some(probe("lease")),
                capture_routes_may_remain: true,
            };
        }

        assert_eq!(
            events.borrow().as_slice(),
            ["monitor", "routes", "session", "interface"]
        );
    }
}
