use crate::error::EngineError;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

/// Routing policy applied after Wintun capture and session reconstruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingMode {
    Direct,
    Rule,
    Global,
}

impl From<crate::config::model::ConnectionMode> for RoutingMode {
    fn from(mode: crate::config::model::ConnectionMode) -> Self {
        match mode {
            crate::config::model::ConnectionMode::Direct => Self::Direct,
            crate::config::model::ConnectionMode::Rule => Self::Rule,
            crate::config::model::ConnectionMode::Global => Self::Global,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteAction {
    Direct,
    Proxy,
}

impl From<crate::config::model::RouteAction> for RouteAction {
    fn from(action: crate::config::model::RouteAction) -> Self {
        match action {
            crate::config::model::RouteAction::Direct => Self::Direct,
            crate::config::model::RouteAction::Proxy => Self::Proxy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionReason {
    DirectMode,
    OrderedRule,
    RuleDefault,
    /// Exact endpoint confirmed from read-only Windows system-proxy settings
    /// and the pre-capture physical route. This user-space exception is
    /// evaluated after Wintun capture and never installs a physical host route.
    SystemProxyEndpoint,
    MandatoryGlobalExclusion,
    GlobalMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDecision {
    pub action: RouteAction,
    pub reason: DecisionReason,
    pub matched_rule_index: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirectPermit {
    pub reason: DecisionReason,
    pub matched_rule_index: Option<usize>,
}

impl RouteDecision {
    /// Execution gate for the current DIRECT-only slice.
    ///
    /// A proxy selection is never converted to DIRECT. It fails closed until a
    /// real proxy outbound is implemented.
    pub fn require_direct(self) -> Result<DirectPermit, EngineError> {
        match self.action {
            RouteAction::Direct => Ok(DirectPermit {
                reason: self.reason,
                matched_rule_index: self.matched_rule_index,
            }),
            RouteAction::Proxy => Err(EngineError::ProxyNotImplemented),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RouteContext<'a> {
    pub destination: IpAddr,
    /// Domain inferred from the bounded DNS cache, if one is available. It is
    /// used only during matching and is not retained in a decision.
    pub domain: Option<&'a str>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IpCidr {
    network: IpAddr,
    prefix_len: u8,
}

impl IpCidr {
    pub fn new(address: IpAddr, prefix_len: u8) -> Result<Self, EngineError> {
        let network = match address {
            IpAddr::V4(address) if prefix_len <= 32 => {
                let mask = prefix_mask_v4(prefix_len);
                IpAddr::V4(Ipv4Addr::from(u32::from(address) & mask))
            }
            IpAddr::V6(address) if prefix_len <= 128 => {
                let mask = prefix_mask_v6(prefix_len);
                IpAddr::V6(Ipv6Addr::from(u128::from(address) & mask))
            }
            _ => return Err(EngineError::InvalidRule),
        };
        Ok(Self {
            network,
            prefix_len,
        })
    }

    pub fn network(self) -> IpAddr {
        self.network
    }

    pub fn prefix_len(self) -> u8 {
        self.prefix_len
    }

    pub fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = prefix_mask_v4(self.prefix_len);
                u32::from(address) & mask == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = prefix_mask_v6(self.prefix_len);
                u128::from(address) & mask == u128::from(network)
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = EngineError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (address, prefix) = value.split_once('/').ok_or(EngineError::InvalidRule)?;
        if address.is_empty() || prefix.is_empty() || prefix.contains('/') {
            return Err(EngineError::InvalidRule);
        }
        let address = address
            .parse::<IpAddr>()
            .map_err(|_| EngineError::InvalidRule)?;
        let prefix = prefix.parse::<u8>().map_err(|_| EngineError::InvalidRule)?;
        Self::new(address, prefix)
    }
}

fn prefix_mask_v4(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

fn prefix_mask_v6(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RuleMatcher {
    DomainExact(String),
    DomainSuffix(String),
    Cidr(IpCidr),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutingRule {
    matcher: RuleMatcher,
    action: RouteAction,
}

impl RoutingRule {
    pub fn domain_exact(domain: &str, action: RouteAction) -> Result<Self, EngineError> {
        Ok(Self {
            matcher: RuleMatcher::DomainExact(normalize_domain(domain)?),
            action,
        })
    }

    pub fn domain_suffix(domain: &str, action: RouteAction) -> Result<Self, EngineError> {
        Ok(Self {
            matcher: RuleMatcher::DomainSuffix(normalize_domain(domain)?),
            action,
        })
    }

    pub fn cidr(cidr: IpCidr, action: RouteAction) -> Self {
        Self {
            matcher: RuleMatcher::Cidr(cidr),
            action,
        }
    }

    fn matches(&self, context: RouteContext<'_>) -> bool {
        match &self.matcher {
            RuleMatcher::DomainExact(expected) => context
                .domain
                .and_then(|domain| normalize_domain(domain).ok())
                .is_some_and(|domain| domain == *expected),
            RuleMatcher::DomainSuffix(expected) => context
                .domain
                .and_then(|domain| normalize_domain(domain).ok())
                .is_some_and(|domain| {
                    domain == *expected
                        || domain
                            .strip_suffix(expected)
                            .is_some_and(|prefix| prefix.ends_with('.'))
                }),
            RuleMatcher::Cidr(cidr) => cidr.contains(context.destination),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSet {
    ordered: Vec<RoutingRule>,
    default_action: RouteAction,
}

impl RuleSet {
    pub fn new(ordered: Vec<RoutingRule>, default_action: RouteAction) -> Self {
        Self {
            ordered,
            default_action,
        }
    }

    pub fn ordered(&self) -> &[RoutingRule] {
        &self.ordered
    }

    pub fn default_action(&self) -> RouteAction {
        self.default_action
    }
}

impl TryFrom<&crate::config::model::RoutingConfig> for RuleSet {
    type Error = EngineError;

    fn try_from(config: &crate::config::model::RoutingConfig) -> Result<Self, Self::Error> {
        let mut ordered = Vec::with_capacity(config.rules.len());
        for rule in config.rules.iter().filter(|rule| rule.enabled) {
            let action = rule.action.into();
            let rule = match rule.match_type {
                crate::config::model::RuleMatch::DomainExact => {
                    RoutingRule::domain_exact(&rule.value, action)?
                }
                crate::config::model::RuleMatch::DomainSuffix => {
                    RoutingRule::domain_suffix(&rule.value, action)?
                }
                crate::config::model::RuleMatch::IpCidr => {
                    RoutingRule::cidr(rule.value.parse()?, action)
                }
            };
            ordered.push(rule);
        }
        Ok(Self::new(ordered, config.default_action.into()))
    }
}

/// The built-in global exclusions are intentionally minimal and auditable.
///
/// Runtime code may add the selected proxy endpoint or local control endpoint
/// explicitly. LAN ranges, DNS servers, and arbitrary destinations are not
/// silently excluded.
pub const BUILTIN_GLOBAL_EXCLUSION_CIDRS: [&str; 2] = ["127.0.0.0/8", "::1/128"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MandatoryGlobalExclusions {
    cidrs: Vec<IpCidr>,
}

impl MandatoryGlobalExclusions {
    pub fn new(additional: impl IntoIterator<Item = IpCidr>) -> Self {
        let mut cidrs = vec![
            "127.0.0.0/8".parse().expect("valid built-in IPv4 CIDR"),
            "::1/128".parse().expect("valid built-in IPv6 CIDR"),
        ];
        cidrs.extend(additional);
        Self { cidrs }
    }

    pub fn cidrs(&self) -> &[IpCidr] {
        &self.cidrs
    }

    pub fn contains(&self, address: IpAddr) -> bool {
        self.cidrs.iter().any(|cidr| cidr.contains(address))
    }
}

impl Default for MandatoryGlobalExclusions {
    fn default() -> Self {
        Self::new([])
    }
}

#[derive(Debug, Clone)]
pub struct Router {
    mode: RoutingMode,
    rules: RuleSet,
    global_exclusions: MandatoryGlobalExclusions,
    system_proxy_endpoints: HashSet<SocketAddr>,
}

impl Router {
    pub fn new(
        mode: RoutingMode,
        rules: RuleSet,
        global_exclusions: MandatoryGlobalExclusions,
    ) -> Self {
        Self {
            mode,
            rules,
            global_exclusions,
            system_proxy_endpoints: HashSet::new(),
        }
    }

    /// Adds only endpoints that startup discovery has already confirmed.
    /// Private address ranges are intentionally not inferred or expanded here.
    pub fn with_system_proxy_endpoints(
        mut self,
        endpoints: impl IntoIterator<Item = SocketAddr>,
    ) -> Self {
        self.system_proxy_endpoints = endpoints.into_iter().collect();
        self
    }

    pub fn system_proxy_endpoints(&self) -> &HashSet<SocketAddr> {
        &self.system_proxy_endpoints
    }

    pub fn from_config(
        mode: crate::config::model::ConnectionMode,
        rules: &crate::config::model::RoutingConfig,
        global_exclusions: MandatoryGlobalExclusions,
    ) -> Result<Self, EngineError> {
        Ok(Self::new(
            mode.into(),
            RuleSet::try_from(rules)?,
            global_exclusions,
        ))
    }

    pub fn decide(&self, context: RouteContext<'_>) -> RouteDecision {
        self.decide_without_socket_exception(context)
    }

    /// Evaluates the exact destination endpoint first. This is the runtime
    /// entry point for TCP/UDP flows because a detected proxy exception must
    /// never broaden from one port to every service on the same host.
    pub fn decide_socket(&self, destination: SocketAddr, domain: Option<&str>) -> RouteDecision {
        if self.system_proxy_endpoints.contains(&destination) {
            return RouteDecision {
                action: RouteAction::Direct,
                reason: DecisionReason::SystemProxyEndpoint,
                matched_rule_index: None,
            };
        }
        self.decide_without_socket_exception(RouteContext {
            destination: destination.ip(),
            domain,
        })
    }

    fn decide_without_socket_exception(&self, context: RouteContext<'_>) -> RouteDecision {
        match self.mode {
            RoutingMode::Direct => RouteDecision {
                action: RouteAction::Direct,
                reason: DecisionReason::DirectMode,
                matched_rule_index: None,
            },
            RoutingMode::Rule => {
                if let Some((index, rule)) = self
                    .rules
                    .ordered
                    .iter()
                    .enumerate()
                    .find(|(_, rule)| rule.matches(context))
                {
                    RouteDecision {
                        action: rule.action,
                        reason: DecisionReason::OrderedRule,
                        matched_rule_index: Some(index),
                    }
                } else {
                    RouteDecision {
                        action: self.rules.default_action,
                        reason: DecisionReason::RuleDefault,
                        matched_rule_index: None,
                    }
                }
            }
            RoutingMode::Global if self.global_exclusions.contains(context.destination) => {
                RouteDecision {
                    action: RouteAction::Direct,
                    reason: DecisionReason::MandatoryGlobalExclusion,
                    matched_rule_index: None,
                }
            }
            RoutingMode::Global => RouteDecision {
                action: RouteAction::Proxy,
                reason: DecisionReason::GlobalMode,
                matched_rule_index: None,
            },
        }
    }

    /// Evaluates every cached domain for the destination while preserving rule
    /// order. This avoids making the result depend on hash-map or DNS-answer
    /// iteration order when multiple names map to the same IP.
    pub fn decide_with_cached_domains(
        &self,
        destination: IpAddr,
        domains: &[String],
    ) -> RouteDecision {
        if self.mode != RoutingMode::Rule {
            return self.decide(RouteContext {
                destination,
                domain: None,
            });
        }

        if let Some((index, rule)) = self.rules.ordered.iter().enumerate().find(|(_, rule)| {
            rule.matches(RouteContext {
                destination,
                domain: None,
            }) || domains.iter().any(|domain| {
                rule.matches(RouteContext {
                    destination,
                    domain: Some(domain),
                })
            })
        }) {
            RouteDecision {
                action: rule.action,
                reason: DecisionReason::OrderedRule,
                matched_rule_index: Some(index),
            }
        } else {
            RouteDecision {
                action: self.rules.default_action,
                reason: DecisionReason::RuleDefault,
                matched_rule_index: None,
            }
        }
    }

    pub fn decide_socket_with_cached_domains(
        &self,
        destination: SocketAddr,
        domains: &[String],
    ) -> RouteDecision {
        if self.system_proxy_endpoints.contains(&destination) {
            return self.decide_socket(destination, None);
        }
        self.decide_with_cached_domains(destination.ip(), domains)
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

    fn context<'a>(destination: &str, domain: Option<&'a str>) -> RouteContext<'a> {
        RouteContext {
            destination: destination.parse().unwrap(),
            domain,
        }
    }

    #[test]
    fn cidr_normalizes_and_matches_both_families() {
        let v4: IpCidr = "192.0.2.129/24".parse().unwrap();
        assert_eq!(v4.network(), "192.0.2.0".parse::<IpAddr>().unwrap());
        assert!(v4.contains("192.0.2.255".parse().unwrap()));
        assert!(!v4.contains("192.0.3.1".parse().unwrap()));
        assert!(!v4.contains("::ffff:192.0.2.1".parse().unwrap()));

        let v6: IpCidr = "2001:db8:1::1234/48".parse().unwrap();
        assert_eq!(v6.network(), "2001:db8:1::".parse::<IpAddr>().unwrap());
        assert!(v6.contains("2001:db8:1:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db8:2::1".parse().unwrap()));
        assert!("192.0.2.1/33".parse::<IpCidr>().is_err());
        assert!("2001:db8::1/129".parse::<IpCidr>().is_err());
    }

    #[test]
    fn exact_and_suffix_domains_are_case_insensitive_and_boundary_safe() {
        let exact = RoutingRule::domain_exact("Example.COM.", RouteAction::Direct).unwrap();
        let suffix = RoutingRule::domain_suffix("example.com", RouteAction::Direct).unwrap();
        assert!(exact.matches(context("192.0.2.1", Some("example.com"))));
        assert!(!exact.matches(context("192.0.2.1", Some("www.example.com"))));
        assert!(suffix.matches(context("192.0.2.1", Some("WWW.Example.Com."))));
        assert!(!suffix.matches(context("192.0.2.1", Some("badexample.com"))));
        assert!(RoutingRule::domain_exact("-bad.example", RouteAction::Direct).is_err());
    }

    #[test]
    fn rule_mode_uses_first_match_then_explicit_default() {
        let rules = RuleSet::new(
            vec![
                RoutingRule::domain_suffix("example.com", RouteAction::Proxy).unwrap(),
                RoutingRule::domain_exact("api.example.com", RouteAction::Direct).unwrap(),
                RoutingRule::cidr("192.0.2.0/24".parse().unwrap(), RouteAction::Direct),
            ],
            RouteAction::Proxy,
        );
        let router = Router::new(
            RoutingMode::Rule,
            rules,
            MandatoryGlobalExclusions::default(),
        );

        let decision = router.decide(context("192.0.2.1", Some("api.example.com")));
        assert_eq!(decision.action, RouteAction::Proxy);
        assert_eq!(decision.matched_rule_index, Some(0));

        let decision = router.decide(context("192.0.2.1", None));
        assert_eq!(decision.action, RouteAction::Direct);
        assert_eq!(decision.matched_rule_index, Some(2));

        let decision = router.decide(context("203.0.113.1", None));
        assert_eq!(decision.action, RouteAction::Proxy);
        assert_eq!(decision.reason, DecisionReason::RuleDefault);
    }

    #[test]
    fn direct_mode_still_returns_a_routing_decision() {
        let router = Router::new(
            RoutingMode::Direct,
            RuleSet::new(vec![], RouteAction::Proxy),
            MandatoryGlobalExclusions::default(),
        );
        let decision = router.decide(context("203.0.113.9", None));
        assert_eq!(decision.action, RouteAction::Direct);
        assert_eq!(decision.reason, DecisionReason::DirectMode);
        decision.require_direct().unwrap();
    }

    #[test]
    fn global_mode_is_proxy_except_audited_exclusions_and_fails_closed() {
        let additional = ["192.0.2.10/32".parse().unwrap()];
        let router = Router::new(
            RoutingMode::Global,
            RuleSet::new(vec![], RouteAction::Direct),
            MandatoryGlobalExclusions::new(additional),
        );

        for excluded in ["127.0.0.1", "::1", "192.0.2.10"] {
            let decision = router.decide(context(excluded, None));
            assert_eq!(decision.action, RouteAction::Direct);
            assert_eq!(decision.reason, DecisionReason::MandatoryGlobalExclusion);
        }

        let decision = router.decide(context("8.8.8.8", None));
        assert_eq!(decision.action, RouteAction::Proxy);
        assert_eq!(
            decision.require_direct().unwrap_err(),
            EngineError::ProxyNotImplemented
        );
    }

    #[test]
    fn proxy_rule_never_falls_back_to_direct() {
        let router = Router::new(
            RoutingMode::Rule,
            RuleSet::new(vec![], RouteAction::Proxy),
            MandatoryGlobalExclusions::default(),
        );
        assert_eq!(
            router
                .decide(context("203.0.113.9", None))
                .require_direct()
                .unwrap_err(),
            EngineError::ProxyNotImplemented
        );
    }

    #[test]
    fn only_confirmed_system_proxy_endpoint_overrides_rule_and_global_proxy() {
        let endpoint = "10.0.0.20:8080".parse::<SocketAddr>().unwrap();
        for mode in [RoutingMode::Rule, RoutingMode::Global] {
            let router = Router::new(
                mode,
                RuleSet::new(vec![], RouteAction::Proxy),
                MandatoryGlobalExclusions::default(),
            )
            .with_system_proxy_endpoints([endpoint]);

            let decision = router.decide_socket(endpoint, None);
            assert_eq!(decision.action, RouteAction::Direct);
            assert_eq!(decision.reason, DecisionReason::SystemProxyEndpoint);

            // Neither a different service on the same host nor another
            // private address is exempt.
            let same_host_other_port =
                router.decide_socket("10.0.0.20:8443".parse().unwrap(), None);
            assert_eq!(same_host_other_port.action, RouteAction::Proxy);
            let ordinary_private = router.decide_socket("10.0.0.21:8080".parse().unwrap(), None);
            assert_eq!(ordinary_private.action, RouteAction::Proxy);
        }
    }

    #[test]
    fn converts_enabled_config_rules_without_reordering() {
        use crate::config::model::{
            ConnectionMode, RouteAction as ConfigAction, RoutingConfig, RoutingRule as ConfigRule,
            RuleMatch,
        };

        let config = RoutingConfig {
            rules: vec![
                ConfigRule {
                    id: "disabled".into(),
                    enabled: false,
                    match_type: RuleMatch::DomainExact,
                    value: "ignored.example".into(),
                    action: ConfigAction::Proxy,
                },
                ConfigRule {
                    id: "exact".into(),
                    enabled: true,
                    match_type: RuleMatch::DomainExact,
                    value: "direct.example".into(),
                    action: ConfigAction::Direct,
                },
            ],
            default_action: ConfigAction::Proxy,
        };
        let router = Router::from_config(
            ConnectionMode::Rule,
            &config,
            MandatoryGlobalExclusions::default(),
        )
        .unwrap();
        let decision = router.decide(context("192.0.2.1", Some("direct.example")));
        assert_eq!(decision.action, RouteAction::Direct);
        assert_eq!(decision.matched_rule_index, Some(0));
        assert_eq!(
            router.decide(context("192.0.2.1", None)).action,
            RouteAction::Proxy
        );
    }

    #[test]
    fn multiple_cached_domains_do_not_change_rule_priority() {
        let router = Router::new(
            RoutingMode::Rule,
            RuleSet::new(
                vec![
                    RoutingRule::domain_exact("high.example", RouteAction::Proxy).unwrap(),
                    RoutingRule::domain_exact("low.example", RouteAction::Direct).unwrap(),
                ],
                RouteAction::Direct,
            ),
            MandatoryGlobalExclusions::default(),
        );
        let domains = vec!["low.example".to_owned(), "high.example".to_owned()];
        let decision = router.decide_with_cached_domains("192.0.2.1".parse().unwrap(), &domains);
        assert_eq!(decision.action, RouteAction::Proxy);
        assert_eq!(decision.matched_rule_index, Some(0));
    }
}
