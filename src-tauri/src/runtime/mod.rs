mod engine;
mod manager;
pub mod recovery;

pub use manager::RuntimeManager;

use crate::diagnostics::DiagnosticsSnapshot;
use serde::Serialize;
use std::fmt;
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeState {
    Stopped,
    Starting,
    Running,
    Stopping,
    RecoveryRequired,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeError {
    UnsupportedPlatform,
    AlreadyRunning,
    NotRunning,
    InvalidConfiguration,
    RecoveryRequired,
    RuntimeActive,
    Cancelled,
    StartupTimeout,
    WorkerPanicked,
    Subsystem {
        stage: &'static str,
        safe_detail: String,
    },
}

impl RuntimeError {
    pub(crate) fn subsystem(stage: &'static str, error: impl fmt::Display) -> Self {
        Self::Subsystem {
            stage,
            safe_detail: error.to_string(),
        }
    }
}

impl fmt::Display for RuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("the Wintun runtime is available only on Windows")
            }
            Self::AlreadyRunning => formatter.write_str("the Wintun runtime is already active"),
            Self::NotRunning => formatter.write_str("the Wintun runtime is not active"),
            Self::InvalidConfiguration => {
                formatter.write_str("the DIRECT runtime configuration is invalid")
            }
            Self::RecoveryRequired => formatter
                .write_str("a previous network mutation journal must be recovered before startup"),
            Self::RuntimeActive => {
                formatter.write_str("the active runtime holds the network recovery lease")
            }
            Self::Cancelled => formatter.write_str("the Wintun runtime startup was cancelled"),
            Self::StartupTimeout => formatter.write_str("the Wintun runtime startup timed out"),
            Self::WorkerPanicked => formatter.write_str("the Wintun runtime worker stopped"),
            Self::Subsystem { stage, safe_detail } => {
                write!(formatter, "{stage} failed: {safe_detail}")
            }
        }
    }
}

impl std::error::Error for RuntimeError {}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCounters {
    pub tun_rx_packets: u64,
    pub tun_tx_packets: u64,
    pub captured_tcp_sessions: u64,
    pub captured_udp_datagrams: u64,
    pub route_direct: u64,
    pub route_proxy: u64,
    pub system_proxy_detected: u64,
    pub route_direct_system_proxy: u64,
    pub direct_tcp_connections: u64,
    pub direct_udp_associations: u64,
    pub unsupported_packets: u64,
    pub dropped_packets: u64,
    pub loop_prevention_drops: u64,
}

impl From<DiagnosticsSnapshot> for RuntimeCounters {
    fn from(snapshot: DiagnosticsSnapshot) -> Self {
        Self {
            tun_rx_packets: snapshot.tun_rx_packets,
            tun_tx_packets: snapshot.tun_tx_packets,
            captured_tcp_sessions: snapshot.captured_tcp_sessions,
            captured_udp_datagrams: snapshot.captured_udp_datagrams,
            route_direct: snapshot.route_direct,
            route_proxy: snapshot.route_proxy,
            system_proxy_detected: snapshot.system_proxy_detected,
            route_direct_system_proxy: snapshot.route_direct_system_proxy,
            direct_tcp_connections: snapshot.direct_tcp_connections,
            direct_udp_associations: snapshot.direct_udp_associations,
            unsupported_packets: snapshot.unsupported_packets,
            dropped_packets: snapshot.dropped_packets,
            loop_prevention_drops: snapshot.loop_prevention_drops,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSnapshot {
    pub platform: &'static str,
    pub state: RuntimeState,
    pub tun_available: bool,
    pub version: &'static str,
    pub counters: RuntimeCounters,
    pub last_error: Option<String>,
    pub recovery_required: bool,
}

#[derive(Debug)]
pub(crate) struct SharedRuntimeStatus {
    value: Mutex<StatusValue>,
}

#[derive(Debug, Clone)]
struct StatusValue {
    state: RuntimeState,
    last_error: Option<String>,
}

impl Default for SharedRuntimeStatus {
    fn default() -> Self {
        Self {
            value: Mutex::new(StatusValue {
                state: RuntimeState::Stopped,
                last_error: None,
            }),
        }
    }
}

impl SharedRuntimeStatus {
    pub(crate) fn set(&self, state: RuntimeState, error: Option<&RuntimeError>) {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        value.state = state;
        value.last_error = error.map(ToString::to_string);
    }

    pub(crate) fn set_safe_error(&self, error: impl fmt::Display) {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        value.last_error = Some(error.to_string());
    }

    pub(crate) fn begin_stopping(&self) {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if value.state != RuntimeState::Failed {
            value.state = RuntimeState::Stopping;
        }
    }

    pub(crate) fn mark_running(&self) {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if value.state != RuntimeState::Failed {
            value.state = RuntimeState::Running;
            value.last_error = None;
        }
    }

    pub(crate) fn finish_stopped(&self) {
        let mut value = self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if value.state != RuntimeState::Failed {
            value.state = RuntimeState::Stopped;
            value.last_error = None;
        }
    }

    fn get(&self) -> StatusValue {
        self.value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_transitions_do_not_overwrite_a_real_failure() {
        let status = SharedRuntimeStatus::default();
        status.set(RuntimeState::Failed, Some(&RuntimeError::StartupTimeout));
        status.begin_stopping();
        status.mark_running();
        status.finish_stopped();

        let value = status.get();
        assert_eq!(value.state, RuntimeState::Failed);
        assert_eq!(
            value.last_error.as_deref(),
            Some("the Wintun runtime startup timed out")
        );
    }
}
