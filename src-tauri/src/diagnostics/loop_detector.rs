use super::{Counter, Diagnostics};
use crate::error::EngineError;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// Exact outbound socket tuple registered before a DIRECT connect/send.
/// Capturing the same tuple at Wintun indicates that interface binding or
/// route exclusion failed and the packet must be dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoopKey {
    pub protocol: TransportProtocol,
    pub source: IpAddr,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopDetectorConfig {
    pub max_flows: usize,
    pub registration_ttl: Duration,
}

impl Default for LoopDetectorConfig {
    fn default() -> Self {
        Self {
            max_flows: 16_384,
            registration_ttl: Duration::from_secs(120),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Registration {
    expires_at: Instant,
    generation: u64,
}

#[derive(Debug, Default)]
struct LoopState {
    registrations: HashMap<LoopKey, Registration>,
    next_generation: u64,
}

#[derive(Debug)]
pub struct LoopDetector {
    config: LoopDetectorConfig,
    state: Mutex<LoopState>,
}

impl LoopDetector {
    pub fn new(config: LoopDetectorConfig) -> Result<Self, EngineError> {
        if config.max_flows == 0 || config.registration_ttl.is_zero() {
            return Err(EngineError::InvalidCacheConfiguration);
        }
        Ok(Self {
            config,
            state: Mutex::new(LoopState::default()),
        })
    }

    pub fn register(&self, key: LoopKey, now: Instant) -> Result<(), EngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        purge(&mut state, now);
        if !state.registrations.contains_key(&key)
            && state.registrations.len() == self.config.max_flows
        {
            evict_oldest(&mut state);
        }
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1);
        let expires_at = now.checked_add(self.config.registration_ttl).unwrap_or(now);
        state.registrations.insert(
            key,
            Registration {
                expires_at,
                generation,
            },
        );
        Ok(())
    }

    /// Returns true when capture must fail closed. Matching registrations are
    /// retained until expiry so repeated recapture cannot escape after one
    /// dropped packet.
    pub fn should_drop(
        &self,
        key: &LoopKey,
        now: Instant,
        diagnostics: &Diagnostics,
    ) -> Result<bool, EngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        purge(&mut state, now);
        let detected = state.registrations.contains_key(key);
        drop(state);
        if detected {
            diagnostics.increment(Counter::LoopPreventionDrops);
            diagnostics.increment(Counter::DroppedPackets);
        }
        Ok(detected)
    }

    pub fn remove(&self, key: &LoopKey) -> Result<(), EngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        state.registrations.remove(key);
        Ok(())
    }

    pub fn len(&self, now: Instant) -> Result<usize, EngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        purge(&mut state, now);
        Ok(state.registrations.len())
    }
}

fn purge(state: &mut LoopState, now: Instant) {
    state
        .registrations
        .retain(|_, registration| registration.expires_at > now);
}

fn evict_oldest(state: &mut LoopState) {
    if let Some(oldest) = state
        .registrations
        .iter()
        .min_by_key(|(_, registration)| registration.generation)
        .map(|(key, _)| *key)
    {
        state.registrations.remove(&oldest);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn key(port: u16) -> LoopKey {
        LoopKey {
            protocol: TransportProtocol::Tcp,
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
            source_port: port,
            destination: IpAddr::V6(Ipv6Addr::LOCALHOST),
            destination_port: 443,
        }
    }

    #[test]
    fn registered_direct_flow_is_dropped_and_counted_repeatedly() {
        let detector = LoopDetector::new(LoopDetectorConfig::default()).unwrap();
        let diagnostics = Diagnostics::default();
        let now = Instant::now();
        detector.register(key(40_000), now).unwrap();

        assert!(
            detector
                .should_drop(&key(40_000), now, &diagnostics)
                .unwrap()
        );
        assert!(
            detector
                .should_drop(&key(40_000), now, &diagnostics)
                .unwrap()
        );
        assert_eq!(diagnostics.snapshot().loop_prevention_drops, 2);
        assert_eq!(diagnostics.snapshot().dropped_packets, 2);
    }

    #[test]
    fn expiry_and_removal_allow_non_matching_capture() {
        let detector = LoopDetector::new(LoopDetectorConfig {
            max_flows: 2,
            registration_ttl: Duration::from_secs(5),
        })
        .unwrap();
        let diagnostics = Diagnostics::default();
        let now = Instant::now();
        detector.register(key(40_000), now).unwrap();
        assert!(
            !detector
                .should_drop(&key(40_000), now + Duration::from_secs(5), &diagnostics)
                .unwrap()
        );

        detector.register(key(40_001), now).unwrap();
        detector.remove(&key(40_001)).unwrap();
        assert!(
            !detector
                .should_drop(&key(40_001), now, &diagnostics)
                .unwrap()
        );
    }

    #[test]
    fn registrations_are_bounded_with_deterministic_eviction() {
        let detector = LoopDetector::new(LoopDetectorConfig {
            max_flows: 2,
            registration_ttl: Duration::from_secs(60),
        })
        .unwrap();
        let diagnostics = Diagnostics::default();
        let now = Instant::now();
        detector.register(key(1), now).unwrap();
        detector.register(key(2), now).unwrap();
        detector.register(key(3), now).unwrap();
        assert_eq!(detector.len(now).unwrap(), 2);
        assert!(!detector.should_drop(&key(1), now, &diagnostics).unwrap());
        assert!(detector.should_drop(&key(2), now, &diagnostics).unwrap());
        assert!(detector.should_drop(&key(3), now, &diagnostics).unwrap());
    }
}
