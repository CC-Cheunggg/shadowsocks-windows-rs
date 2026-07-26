use super::FlowKey;
use crate::error::EngineError;
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpAssociationConfig {
    pub max_associations: usize,
    pub idle_timeout: Duration,
    pub max_queued_datagrams: usize,
    pub max_queued_bytes: usize,
    pub max_datagram_bytes: usize,
}

impl Default for UdpAssociationConfig {
    fn default() -> Self {
        Self {
            max_associations: 4096,
            idle_timeout: Duration::from_secs(60),
            max_queued_datagrams: 32,
            max_queued_bytes: 256 * 1024,
            max_datagram_bytes: 65_507,
        }
    }
}

impl UdpAssociationConfig {
    fn validate(self) -> Result<Self, EngineError> {
        if self.max_associations == 0
            || self.idle_timeout.is_zero()
            || self.max_queued_datagrams == 0
            || self.max_queued_bytes == 0
            || self.max_datagram_bytes == 0
            || self.max_datagram_bytes > 65_507
        {
            return Err(EngineError::InvalidSessionState);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpQueueResult {
    Queued { created: bool, generation: u64 },
    Backpressure,
}

struct Association {
    generation: u64,
    last_activity: Instant,
    queued_bytes: usize,
    queue: VecDeque<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiredUdpAssociation {
    pub key: FlowKey,
    pub generation: u64,
}

/// Bounded five-tuple UDP association state.
///
/// Network sockets are owned by the DIRECT runtime; this table supplies
/// deterministic lifetime and queue/backpressure semantics without retaining
/// any datagram after it is sent or cancelled.
pub struct UdpAssociationTable {
    config: UdpAssociationConfig,
    associations: HashMap<FlowKey, Association>,
    next_generation: u64,
}

impl UdpAssociationTable {
    pub fn new(config: UdpAssociationConfig) -> Result<Self, EngineError> {
        Ok(Self {
            config: config.validate()?,
            associations: HashMap::new(),
            next_generation: 1,
        })
    }

    pub fn enqueue(
        &mut self,
        key: FlowKey,
        payload: &[u8],
        now: Instant,
    ) -> Result<UdpQueueResult, EngineError> {
        if payload.len() > self.config.max_datagram_bytes {
            return Err(EngineError::InvalidSessionState);
        }
        if payload.len() > self.config.max_queued_bytes {
            return Ok(UdpQueueResult::Backpressure);
        }
        let created = if self.associations.contains_key(&key) {
            false
        } else {
            if self.associations.len() >= self.config.max_associations {
                return Err(EngineError::SessionCapacity);
            }
            let generation = self.next_generation;
            self.next_generation = self.next_generation.wrapping_add(1);
            if self.next_generation == 0 {
                self.next_generation = 1;
            }
            self.associations.insert(
                key,
                Association {
                    generation,
                    last_activity: now,
                    queued_bytes: 0,
                    queue: VecDeque::new(),
                },
            );
            true
        };

        let association = self
            .associations
            .get_mut(&key)
            .expect("association inserted above");
        association.last_activity = now;
        if association.queue.len() >= self.config.max_queued_datagrams
            || association.queued_bytes.saturating_add(payload.len()) > self.config.max_queued_bytes
        {
            return Ok(UdpQueueResult::Backpressure);
        }
        association.queue.push_back(payload.to_vec());
        association.queued_bytes += payload.len();
        Ok(UdpQueueResult::Queued {
            created,
            generation: association.generation,
        })
    }

    pub fn pop(&mut self, key: &FlowKey, generation: u64, now: Instant) -> Option<Vec<u8>> {
        let association = self.associations.get_mut(key)?;
        if association.generation != generation {
            return None;
        }
        let datagram = association.queue.pop_front()?;
        association.queued_bytes = association.queued_bytes.saturating_sub(datagram.len());
        if now > association.last_activity {
            association.last_activity = now;
        }
        Some(datagram)
    }

    pub fn touch(&mut self, key: &FlowKey, generation: u64, now: Instant) -> bool {
        if let Some(association) = self.associations.get_mut(key) {
            if association.generation != generation {
                return false;
            }
            if now > association.last_activity {
                association.last_activity = now;
            }
            true
        } else {
            false
        }
    }

    pub fn cancel(&mut self, key: &FlowKey, generation: u64) -> bool {
        if self
            .associations
            .get(key)
            .is_some_and(|association| association.generation == generation)
        {
            self.associations.remove(key);
            true
        } else {
            false
        }
    }

    pub fn reap(&mut self, now: Instant) -> Vec<ExpiredUdpAssociation> {
        let expired = self
            .associations
            .iter()
            .filter_map(|(key, association)| {
                (now.saturating_duration_since(association.last_activity)
                    >= self.config.idle_timeout)
                    .then_some(ExpiredUdpAssociation {
                        key: *key,
                        generation: association.generation,
                    })
            })
            .collect::<Vec<_>>();
        for association in &expired {
            self.associations.remove(&association.key);
        }
        expired
    }

    pub fn generation(&self, key: &FlowKey) -> Option<u64> {
        self.associations
            .get(key)
            .map(|association| association.generation)
    }

    pub fn len(&self) -> usize {
        self.associations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.associations.is_empty()
    }

    pub fn queued_datagrams(&self, key: &FlowKey) -> usize {
        self.associations
            .get(key)
            .map_or(0, |association| association.queue.len())
    }

    pub fn queued_bytes(&self, key: &FlowKey) -> usize {
        self.associations
            .get(key)
            .map_or(0, |association| association.queued_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(port: u16) -> FlowKey {
        FlowKey::new(
            format!("192.0.2.10:{port}").parse().unwrap(),
            "198.51.100.20:53".parse().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn association_is_created_reused_and_expired_by_five_tuple() {
        let now = Instant::now();
        let mut table = UdpAssociationTable::new(UdpAssociationConfig {
            idle_timeout: Duration::from_secs(10),
            ..UdpAssociationConfig::default()
        })
        .unwrap();
        assert_eq!(
            table.enqueue(key(50000), b"one", now).unwrap(),
            UdpQueueResult::Queued {
                created: true,
                generation: 1,
            }
        );
        assert_eq!(
            table
                .enqueue(key(50000), b"two", now + Duration::from_secs(1))
                .unwrap(),
            UdpQueueResult::Queued {
                created: false,
                generation: 1,
            }
        );
        assert_eq!(table.pop(&key(50000), 1, now).unwrap(), b"one");
        assert_eq!(table.pop(&key(50000), 1, now).unwrap(), b"two");
        assert!(table.reap(now + Duration::from_secs(10)).is_empty());
        assert_eq!(
            table.reap(now + Duration::from_secs(11)),
            vec![ExpiredUdpAssociation {
                key: key(50000),
                generation: 1,
            }]
        );
    }

    #[test]
    fn queue_backpressure_does_not_discard_already_queued_datagrams() {
        let now = Instant::now();
        let mut table = UdpAssociationTable::new(UdpAssociationConfig {
            max_queued_datagrams: 1,
            max_queued_bytes: 4,
            ..UdpAssociationConfig::default()
        })
        .unwrap();
        assert!(matches!(
            table.enqueue(key(50000), b"1234", now).unwrap(),
            UdpQueueResult::Queued {
                created: true,
                generation: 1,
            }
        ));
        assert_eq!(
            table.enqueue(key(50000), b"x", now).unwrap(),
            UdpQueueResult::Backpressure
        );
        assert_eq!(table.queued_bytes(&key(50000)), 4);
        assert_eq!(table.pop(&key(50000), 1, now).unwrap(), b"1234");
        assert_eq!(table.queued_bytes(&key(50000)), 0);
    }

    #[test]
    fn cancellation_and_capacity_are_bounded() {
        let now = Instant::now();
        let mut table = UdpAssociationTable::new(UdpAssociationConfig {
            max_associations: 1,
            ..UdpAssociationConfig::default()
        })
        .unwrap();
        let UdpQueueResult::Queued { generation, .. } =
            table.enqueue(key(50000), b"a", now).unwrap()
        else {
            panic!("first datagram should be queued");
        };
        assert_eq!(
            table.enqueue(key(50001), b"b", now).unwrap_err(),
            EngineError::SessionCapacity
        );
        assert!(table.cancel(&key(50000), generation));
        assert!(table.is_empty());
        assert!(matches!(
            table.enqueue(key(50001), b"b", now).unwrap(),
            UdpQueueResult::Queued {
                created: true,
                generation: 2,
            }
        ));
    }

    #[test]
    fn stale_generation_cannot_touch_cancel_or_consume_reused_tuple() {
        let now = Instant::now();
        let flow = key(50000);
        let mut table = UdpAssociationTable::new(UdpAssociationConfig::default()).unwrap();
        let UdpQueueResult::Queued {
            generation: first, ..
        } = table.enqueue(flow, b"old", now).unwrap()
        else {
            panic!("first datagram should be queued");
        };
        assert!(table.cancel(&flow, first));

        let UdpQueueResult::Queued {
            generation: second, ..
        } = table
            .enqueue(flow, b"new", now + Duration::from_secs(1))
            .unwrap()
        else {
            panic!("replacement datagram should be queued");
        };
        assert_ne!(first, second);
        assert!(!table.touch(&flow, first, now + Duration::from_secs(2)));
        assert!(!table.cancel(&flow, first));
        assert_eq!(table.pop(&flow, first, now), None);
        assert_eq!(table.pop(&flow, second, now).unwrap(), b"new");
    }

    #[test]
    fn datagram_larger_than_byte_budget_does_not_leave_empty_association() {
        let now = Instant::now();
        let mut table = UdpAssociationTable::new(UdpAssociationConfig {
            max_queued_bytes: 3,
            max_datagram_bytes: 4,
            ..UdpAssociationConfig::default()
        })
        .unwrap();
        assert_eq!(
            table.enqueue(key(50000), b"1234", now).unwrap(),
            UdpQueueResult::Backpressure
        );
        assert!(table.is_empty());
    }
}
