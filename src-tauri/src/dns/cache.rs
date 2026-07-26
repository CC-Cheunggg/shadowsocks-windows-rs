use crate::error::EngineError;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsCacheConfig {
    pub max_domains: usize,
    pub max_addresses_per_domain: usize,
    pub max_ttl: Duration,
}

impl Default for DnsCacheConfig {
    fn default() -> Self {
        Self {
            max_domains: 4096,
            max_addresses_per_domain: 16,
            max_ttl: Duration::from_secs(24 * 60 * 60),
        }
    }
}

#[derive(Debug, Clone)]
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
    generation: u64,
}

#[derive(Debug, Default)]
struct CacheState {
    entries: HashMap<String, CacheEntry>,
    next_generation: u64,
}

/// Bounded, expiring DNS metadata used for rule matching.
///
/// Only normalized domain names, resolved IP addresses, and expiry metadata
/// are retained. DNS wire payloads and query identifiers are never stored.
#[derive(Debug)]
pub struct DnsCache {
    config: DnsCacheConfig,
    state: Mutex<CacheState>,
}

impl DnsCache {
    pub fn new(config: DnsCacheConfig) -> Result<Self, EngineError> {
        if config.max_domains == 0
            || config.max_addresses_per_domain == 0
            || config.max_ttl.is_zero()
        {
            return Err(EngineError::InvalidCacheConfiguration);
        }
        Ok(Self {
            config,
            state: Mutex::new(CacheState::default()),
        })
    }

    /// Inserts A/AAAA results. Duplicates are removed in first-seen order.
    /// TTL is capped by `max_ttl`; a zero TTL removes an existing mapping.
    pub fn insert(
        &self,
        domain: &str,
        addresses: impl IntoIterator<Item = IpAddr>,
        ttl: Duration,
        now: Instant,
    ) -> Result<(), EngineError> {
        let domain = normalize_domain(domain)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        purge_expired(&mut state, now);

        if ttl.is_zero() {
            state.entries.remove(&domain);
            return Ok(());
        }

        let mut unique = Vec::with_capacity(self.config.max_addresses_per_domain);
        for address in addresses {
            if !unique.contains(&address) {
                unique.push(address);
                if unique.len() == self.config.max_addresses_per_domain {
                    break;
                }
            }
        }
        if unique.is_empty() {
            state.entries.remove(&domain);
            return Ok(());
        }

        if !state.entries.contains_key(&domain) && state.entries.len() == self.config.max_domains {
            evict_oldest(&mut state);
        }

        let ttl = ttl.min(self.config.max_ttl);
        let expires_at = now.checked_add(ttl).unwrap_or(now);
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1);
        state.entries.insert(
            domain,
            CacheEntry {
                addresses: unique,
                expires_at,
                generation,
            },
        );
        Ok(())
    }

    pub fn lookup(&self, domain: &str, now: Instant) -> Result<Vec<IpAddr>, EngineError> {
        let domain = normalize_domain(domain)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        purge_expired(&mut state, now);
        Ok(state
            .entries
            .get(&domain)
            .map_or_else(Vec::new, |entry| entry.addresses.clone()))
    }

    /// Returns normalized domains associated with an IP, sorted for
    /// deterministic ordered-rule evaluation.
    pub fn domains_for_ip(
        &self,
        address: IpAddr,
        now: Instant,
    ) -> Result<Vec<String>, EngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        purge_expired(&mut state, now);
        let mut domains = state
            .entries
            .iter()
            .filter(|(_, entry)| entry.addresses.contains(&address))
            .map(|(domain, _)| domain.clone())
            .collect::<Vec<_>>();
        domains.sort_unstable();
        Ok(domains)
    }

    pub fn len(&self, now: Instant) -> Result<usize, EngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        purge_expired(&mut state, now);
        Ok(state.entries.len())
    }

    pub fn clear(&self) -> Result<(), EngineError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| EngineError::StateUnavailable)?;
        state.entries.clear();
        Ok(())
    }
}

fn purge_expired(state: &mut CacheState, now: Instant) {
    state.entries.retain(|_, entry| entry.expires_at > now);
}

fn evict_oldest(state: &mut CacheState) {
    if let Some(oldest) = state
        .entries
        .iter()
        .min_by_key(|(_, entry)| entry.generation)
        .map(|(domain, _)| domain.clone())
    {
        state.entries.remove(&oldest);
    }
}

fn normalize_domain(domain: &str) -> Result<String, EngineError> {
    let domain = domain.strip_suffix('.').unwrap_or(domain);
    if domain.is_empty()
        || domain.len() > 253
        || !domain.is_ascii()
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(EngineError::InvalidDomain);
    }
    Ok(domain.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(max_domains: usize, max_addresses_per_domain: usize) -> DnsCache {
        DnsCache::new(DnsCacheConfig {
            max_domains,
            max_addresses_per_domain,
            max_ttl: Duration::from_secs(300),
        })
        .unwrap()
    }

    #[test]
    fn expires_without_retaining_dns_payloads() {
        let cache = cache(4, 4);
        let now = Instant::now();
        let address = "192.0.2.1".parse().unwrap();
        cache
            .insert("Example.COM.", [address], Duration::from_secs(30), now)
            .unwrap();
        assert_eq!(cache.lookup("example.com", now).unwrap(), vec![address]);
        assert!(
            cache
                .lookup("example.com", now + Duration::from_secs(30))
                .unwrap()
                .is_empty()
        );
        assert_eq!(cache.len(now + Duration::from_secs(30)).unwrap(), 0);
    }

    #[test]
    fn capacity_evicts_oldest_and_address_list_is_bounded() {
        let cache = cache(2, 2);
        let now = Instant::now();
        cache
            .insert(
                "one.example",
                [
                    "192.0.2.1".parse().unwrap(),
                    "192.0.2.2".parse().unwrap(),
                    "192.0.2.3".parse().unwrap(),
                ],
                Duration::from_secs(60),
                now,
            )
            .unwrap();
        assert_eq!(cache.lookup("one.example", now).unwrap().len(), 2);

        cache
            .insert(
                "two.example",
                ["192.0.2.4".parse().unwrap()],
                Duration::from_secs(60),
                now,
            )
            .unwrap();
        cache
            .insert(
                "three.example",
                ["192.0.2.5".parse().unwrap()],
                Duration::from_secs(60),
                now,
            )
            .unwrap();
        assert!(cache.lookup("one.example", now).unwrap().is_empty());
        assert_eq!(cache.len(now).unwrap(), 2);
    }

    #[test]
    fn ttl_is_capped_and_zero_removes_mapping() {
        let cache = cache(2, 2);
        let now = Instant::now();
        cache
            .insert(
                "ttl.example",
                ["2001:db8::1".parse().unwrap()],
                Duration::from_secs(3600),
                now,
            )
            .unwrap();
        assert!(
            cache
                .lookup("ttl.example", now + Duration::from_secs(299))
                .unwrap()
                .len()
                == 1
        );
        assert!(
            cache
                .lookup("ttl.example", now + Duration::from_secs(300))
                .unwrap()
                .is_empty()
        );

        cache
            .insert(
                "ttl.example",
                ["192.0.2.1".parse().unwrap()],
                Duration::from_secs(60),
                now,
            )
            .unwrap();
        cache
            .insert("ttl.example", [], Duration::ZERO, now)
            .unwrap();
        assert!(cache.lookup("ttl.example", now).unwrap().is_empty());
    }

    #[test]
    fn reverse_mapping_is_expiring_and_deterministic() {
        let cache = cache(4, 2);
        let now = Instant::now();
        let address = "203.0.113.9".parse().unwrap();
        cache
            .insert("z.example", [address], Duration::from_secs(10), now)
            .unwrap();
        cache
            .insert("a.example", [address], Duration::from_secs(20), now)
            .unwrap();
        assert_eq!(
            cache.domains_for_ip(address, now).unwrap(),
            vec!["a.example", "z.example"]
        );
        assert_eq!(
            cache
                .domains_for_ip(address, now + Duration::from_secs(10))
                .unwrap(),
            vec!["a.example"]
        );
    }

    #[test]
    fn invalid_configuration_and_domains_are_rejected_safely() {
        assert_eq!(
            DnsCache::new(DnsCacheConfig {
                max_domains: 0,
                ..DnsCacheConfig::default()
            })
            .unwrap_err(),
            EngineError::InvalidCacheConfiguration
        );
        let cache = cache(2, 2);
        assert_eq!(
            cache
                .lookup("sensitive invalid domain", Instant::now())
                .unwrap_err()
                .to_string(),
            "domain name is invalid"
        );
    }
}
