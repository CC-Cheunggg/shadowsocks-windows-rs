//! Read-only Windows system-proxy discovery.
//!
//! The runtime never enables, disables, or modifies WinINet/WinHTTP proxy
//! configuration. It reads the current-user IE/WinINet-compatible settings and
//! the machine WinHTTP default settings before route mutation, reduces manual
//! proxy strings to bounded socket endpoints, and discards the raw strings.

use crate::tun::routes::RouteBinding;
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};

const MAX_PROXY_AUTHORITIES: usize = 64;
const MAX_RESOLVED_ENDPOINTS: usize = 128;
const MAX_PROXY_FIELD_CHARS: usize = 16 * 1024;
const CAPTURE_CANCELLATION_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemProxyError {
    UnsupportedPlatform,
    InvalidProxyConfiguration,
    Cancelled,
    TimedOut,
    CaptureWorkerUnavailable,
    Api { operation: &'static str, code: u32 },
}

impl fmt::Display for SystemProxyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("Windows system-proxy discovery is unavailable")
            }
            Self::InvalidProxyConfiguration => {
                formatter.write_str("Windows system-proxy configuration is invalid")
            }
            Self::Cancelled => formatter.write_str("Windows system-proxy discovery was cancelled"),
            Self::TimedOut => formatter.write_str("Windows system-proxy discovery timed out"),
            Self::CaptureWorkerUnavailable => {
                formatter.write_str("Windows system-proxy discovery worker is unavailable")
            }
            Self::Api { operation, code } => {
                write!(formatter, "{operation} failed (OS error {code})")
            }
        }
    }
}

impl std::error::Error for SystemProxyError {}

/// Safe, bounded proxy state retained by the runtime.
///
/// Raw proxy lists, bypass strings, PAC URLs, and credentials are deliberately
/// not retained or exposed through diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SystemProxySnapshot {
    pub endpoints: Vec<SocketAddr>,
    pub manual_proxy_configured: bool,
    pub auto_detect_enabled: bool,
    pub auto_config_url_configured: bool,
    pub winhttp_default_proxy_configured: bool,
}

impl SystemProxySnapshot {
    pub fn capture() -> Result<Self, SystemProxyError> {
        let raw = platform::capture_raw()?;
        snapshot_from_raw(raw)
    }

    /// Captures proxy state without allowing WinHTTP or hostname resolution to
    /// block the caller past `total_timeout`.
    ///
    /// Windows does not offer a safe way to interrupt every blocking API used
    /// by discovery. One worker performs the complete capture and is detached
    /// if the caller cancels or the deadline expires. No per-authority workers
    /// are created, and the result channel has capacity one.
    pub fn capture_bounded(
        total_timeout: Duration,
        is_cancelled: impl FnMut() -> bool,
    ) -> Result<Self, SystemProxyError> {
        capture_bounded_with(total_timeout, is_cancelled, Self::capture)
    }

    pub fn is_configured(&self) -> bool {
        self.manual_proxy_configured
            || self.auto_detect_enabled
            || self.auto_config_url_configured
            || self.winhttp_default_proxy_configured
    }
}

#[derive(Default)]
struct RawProxySnapshot {
    proxy_lists: Vec<String>,
    manual_proxy_configured: bool,
    auto_detect_enabled: bool,
    auto_config_url_configured: bool,
    winhttp_default_proxy_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProxyAuthority {
    host: String,
    port: u16,
}

fn capture_bounded_with<T>(
    total_timeout: Duration,
    mut is_cancelled: impl FnMut() -> bool,
    capture: impl FnOnce() -> Result<T, SystemProxyError> + Send + 'static,
) -> Result<T, SystemProxyError>
where
    T: Send + 'static,
{
    let started = Instant::now();
    if is_cancelled() {
        return Err(SystemProxyError::Cancelled);
    }
    if total_timeout.is_zero() {
        return Err(SystemProxyError::TimedOut);
    }

    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("system-proxy-capture".to_owned())
        .spawn(move || {
            let _ = sender.send(capture());
        })
        .map_err(|_| SystemProxyError::CaptureWorkerUnavailable)?;

    loop {
        if is_cancelled() {
            return Err(SystemProxyError::Cancelled);
        }

        let elapsed = started.elapsed();
        if elapsed >= total_timeout {
            return Err(SystemProxyError::TimedOut);
        }
        let wait = (total_timeout - elapsed).min(CAPTURE_CANCELLATION_POLL_INTERVAL);
        match receiver.recv_timeout(wait) {
            Ok(result) => return result,
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(SystemProxyError::CaptureWorkerUnavailable);
            }
        }
    }
}

fn snapshot_from_raw(raw: RawProxySnapshot) -> Result<SystemProxySnapshot, SystemProxyError> {
    let RawProxySnapshot {
        proxy_lists,
        manual_proxy_configured,
        auto_detect_enabled,
        auto_config_url_configured,
        winhttp_default_proxy_configured,
    } = raw;
    let mut authorities = Vec::new();
    let mut unique_authorities = HashSet::new();
    for proxy_list in &proxy_lists {
        for authority in parse_proxy_list(proxy_list)? {
            if unique_authorities.insert(authority.clone()) {
                authorities.push(authority);
                if authorities.len() >= MAX_PROXY_AUTHORITIES {
                    break;
                }
            }
        }
        if authorities.len() >= MAX_PROXY_AUTHORITIES {
            break;
        }
    }
    // Proxy strings may contain credentials. Discard them before any hostname
    // resolution can block; only sanitized host/port authorities remain.
    drop(proxy_lists);

    let mut endpoints = Vec::new();
    let mut unique_endpoints = HashSet::new();
    for authority in authorities {
        let resolved = (authority.host.as_str(), authority.port)
            .to_socket_addrs()
            .map_err(|_| SystemProxyError::InvalidProxyConfiguration)?;
        for endpoint in resolved {
            let endpoint = normalize_endpoint(endpoint);
            if unique_endpoints.insert(endpoint) {
                endpoints.push(endpoint);
                if endpoints.len() >= MAX_RESOLVED_ENDPOINTS {
                    break;
                }
            }
        }
        if endpoints.len() >= MAX_RESOLVED_ENDPOINTS {
            break;
        }
    }
    endpoints.sort_unstable();

    Ok(SystemProxySnapshot {
        endpoints,
        manual_proxy_configured,
        auto_detect_enabled,
        auto_config_url_configured,
        winhttp_default_proxy_configured,
    })
}

fn parse_proxy_list(value: &str) -> Result<Vec<ProxyAuthority>, SystemProxyError> {
    if value.chars().count() > MAX_PROXY_FIELD_CHARS
        || value
            .chars()
            .any(|character| character.is_control() && !character.is_whitespace())
    {
        return Err(SystemProxyError::InvalidProxyConfiguration);
    }

    let mut parsed = Vec::new();
    // WINHTTP_PROXY_INFO documents semicolon or whitespace delimiters. Parse
    // each item independently so `http=one https=two` does not accidentally
    // treat the second protocol selector as part of the first authority.
    for entry in value.split(|character: char| character == ';' || character.is_whitespace()) {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let (default_port, authority) = match entry.split_once('=') {
            Some((protocol, authority)) => (default_proxy_port(protocol)?, authority.trim()),
            None => (80, entry),
        };
        if let Some(authority) = parse_proxy_authority(authority, default_port)? {
            parsed.push(authority);
            if parsed.len() >= MAX_PROXY_AUTHORITIES {
                return Ok(parsed);
            }
        }
    }
    Ok(parsed)
}

fn default_proxy_port(scheme: &str) -> Result<u16, SystemProxyError> {
    match scheme.trim().to_ascii_lowercase().as_str() {
        "http" => Ok(80),
        "https" => Ok(443),
        "ftp" => Ok(21),
        "socks" | "socks4" | "socks5" => Ok(1080),
        _ => Err(SystemProxyError::InvalidProxyConfiguration),
    }
}

fn parse_proxy_authority(
    value: &str,
    mut default_port: u16,
) -> Result<Option<ProxyAuthority>, SystemProxyError> {
    let mut value = value.trim().trim_matches('/');
    if value.is_empty()
        || value.eq_ignore_ascii_case("direct")
        || value.eq_ignore_ascii_case("<local>")
    {
        return Ok(None);
    }
    if let Some((scheme, remainder)) = value.split_once("://") {
        default_port = default_proxy_port(scheme)?;
        value = remainder;
    }
    value = value.split('/').next().unwrap_or(value);
    if let Some((_, remainder)) = value.rsplit_once('@') {
        // Credentials are never retained. Only the authority after the final
        // user-info delimiter is considered.
        value = remainder;
    }

    let (host, port) = if let Some(remainder) = value.strip_prefix('[') {
        let (host, suffix) = remainder
            .split_once(']')
            .ok_or(SystemProxyError::InvalidProxyConfiguration)?;
        let port = match suffix {
            "" => default_port,
            value => value
                .strip_prefix(':')
                .ok_or(SystemProxyError::InvalidProxyConfiguration)?
                .parse::<u16>()
                .map_err(|_| SystemProxyError::InvalidProxyConfiguration)?,
        };
        (host, port)
    } else if value
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_ipv6())
    {
        (value, default_port)
    } else if let Some((host, port)) = value.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| SystemProxyError::InvalidProxyConfiguration)?;
        (host, port)
    } else {
        (value, default_port)
    };

    if port == 0
        || host.is_empty()
        || host.len() > 253
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains('*')
        || host.chars().any(|character| {
            character.is_control()
                || character.is_whitespace()
                || matches!(character, '\\' | '/' | '[' | ']' | '@')
        })
    {
        return Err(SystemProxyError::InvalidProxyConfiguration);
    }

    Ok(Some(ProxyAuthority {
        host: host.to_ascii_lowercase(),
        port,
    }))
}

/// Captured IP packets carry only an IPv6 address and port, not the Winsock
/// scope/flow metadata returned by name resolution. Keep the routing key in
/// that same canonical form; the confirmed physical interface supplies the
/// link-local scope when the replacement socket is created.
fn normalize_endpoint(endpoint: SocketAddr) -> SocketAddr {
    match endpoint {
        SocketAddr::V4(_) => endpoint,
        SocketAddr::V6(endpoint) => {
            SocketAddr::V6(SocketAddrV6::new(*endpoint.ip(), endpoint.port(), 0, 0))
        }
    }
}

/// Conservative address classification used before granting the exact,
/// user-space-only DIRECT exception.
///
/// A public address is not treated as an intranet proxy merely because it was
/// present in a proxy string. An on-link public endpoint may still be accepted
/// separately when `GetBestRoute2` reports an unspecified next hop.
pub fn is_local_or_intranet_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let octets = address.octets();
            address.is_loopback()
                || address.is_private()
                || address.is_link_local()
                || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(address) => {
            let first = address.octets()[0];
            address.is_loopback() || address.is_unicast_link_local() || first & 0xfe == 0xfc
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmedSystemProxyEndpoint {
    pub endpoint: SocketAddr,
    /// Complete pre-capture route identity. Keeping the stable interface
    /// identity and next hop prevents a reused ifIndex from being treated as
    /// the same network after an epoch restart.
    pub route: RouteBinding,
}

/// Confirms the exact remote proxy endpoints against the pre-capture route
/// view. Loopback proxies deliberately remain on the Windows loopback path and
/// therefore are not added to the Wintun router exception set.
pub fn confirm_intranet_endpoints<E>(
    snapshot: &SystemProxySnapshot,
    excluded_interface_index: u32,
    mut route_to: impl FnMut(IpAddr) -> Result<RouteBinding, E>,
) -> Result<Vec<ConfirmedSystemProxyEndpoint>, E> {
    let mut confirmed = Vec::new();
    for endpoint in &snapshot.endpoints {
        if endpoint.ip().is_loopback() {
            continue;
        }
        let route = route_to(endpoint.ip())?;
        if route.interface.interface_index == 0
            || route.interface.interface_index == excluded_interface_index
            || route.source.is_unspecified()
            || route.source.is_loopback()
            || route.source.is_ipv4() != endpoint.is_ipv4()
            || route.next_hop.is_ipv4() != endpoint.is_ipv4()
        {
            continue;
        }
        if is_local_or_intranet_address(endpoint.ip()) || route.next_hop.is_unspecified() {
            confirmed.push(ConfirmedSystemProxyEndpoint {
                endpoint: *endpoint,
                route,
            });
        }
    }
    confirmed.sort_unstable_by_key(|confirmed| confirmed.endpoint);
    confirmed.dedup_by_key(|confirmed| confirmed.endpoint);
    Ok(confirmed)
}

#[cfg(windows)]
mod platform {
    use super::{RawProxySnapshot, SystemProxyError};
    use std::ptr;
    use windows_sys::Win32::Foundation::{GetLastError, GlobalFree};
    use windows_sys::Win32::Networking::WinHttp::{
        WINHTTP_ACCESS_TYPE_NAMED_PROXY, WINHTTP_CURRENT_USER_IE_PROXY_CONFIG, WINHTTP_PROXY_INFO,
        WinHttpGetDefaultProxyConfiguration, WinHttpGetIEProxyConfigForCurrentUser,
    };
    use windows_sys::core::PWSTR;

    const ERROR_FILE_NOT_FOUND: u32 = 2;
    const MAX_WIDE_CHARS: usize = 16 * 1024;

    pub(super) fn capture_raw() -> Result<RawProxySnapshot, SystemProxyError> {
        let mut raw = RawProxySnapshot::default();
        let mut ie_config = WINHTTP_CURRENT_USER_IE_PROXY_CONFIG::default();
        // SAFETY: `ie_config` is valid writable storage. The function is
        // read-only with respect to Windows proxy configuration.
        let ie_ok = unsafe { WinHttpGetIEProxyConfigForCurrentUser(&mut ie_config) } != 0;
        if ie_ok {
            let auto_config = OwnedGlobalWide::new(ie_config.lpszAutoConfigUrl);
            let proxy = OwnedGlobalWide::new(ie_config.lpszProxy);
            let _bypass = OwnedGlobalWide::new(ie_config.lpszProxyBypass);
            raw.auto_detect_enabled = ie_config.fAutoDetect != 0;
            raw.auto_config_url_configured = auto_config.is_nonempty()?;
            if let Some(proxy) = proxy.into_string()? {
                raw.manual_proxy_configured = true;
                raw.proxy_lists.push(proxy);
            }
        } else {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            if code != ERROR_FILE_NOT_FOUND {
                return Err(SystemProxyError::Api {
                    operation: "current-user proxy discovery",
                    code,
                });
            }
        }

        let mut default_config = WINHTTP_PROXY_INFO::default();
        // SAFETY: `default_config` is valid writable storage. This API only
        // reads the machine WinHTTP default proxy configuration.
        let default_ok = unsafe { WinHttpGetDefaultProxyConfiguration(&mut default_config) } != 0;
        if default_ok {
            let proxy = OwnedGlobalWide::new(default_config.lpszProxy);
            let _bypass = OwnedGlobalWide::new(default_config.lpszProxyBypass);
            if default_config.dwAccessType == WINHTTP_ACCESS_TYPE_NAMED_PROXY {
                if let Some(proxy) = proxy.into_string()? {
                    raw.winhttp_default_proxy_configured = true;
                    raw.proxy_lists.push(proxy);
                }
            }
        } else {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            if code != ERROR_FILE_NOT_FOUND {
                return Err(SystemProxyError::Api {
                    operation: "WinHTTP default proxy discovery",
                    code,
                });
            }
        }
        Ok(raw)
    }

    struct OwnedGlobalWide(PWSTR);

    impl OwnedGlobalWide {
        fn new(pointer: PWSTR) -> Self {
            Self(pointer)
        }

        fn is_nonempty(&self) -> Result<bool, SystemProxyError> {
            self.read()
                .map(|value| value.is_some_and(|value| !value.is_empty()))
        }

        fn into_string(mut self) -> Result<Option<String>, SystemProxyError> {
            let value = self.read();
            self.free();
            value
        }

        fn read(&self) -> Result<Option<String>, SystemProxyError> {
            if self.0.is_null() {
                return Ok(None);
            }
            let mut length = 0;
            // SAFETY: WinHTTP returned a NUL-terminated allocation. The bound
            // prevents an invalid allocation from causing an unbounded scan.
            unsafe {
                while length < MAX_WIDE_CHARS && *self.0.add(length) != 0 {
                    length += 1;
                }
            }
            if length == MAX_WIDE_CHARS {
                return Err(SystemProxyError::InvalidProxyConfiguration);
            }
            // SAFETY: the preceding scan established the initialized range.
            let slice = unsafe { std::slice::from_raw_parts(self.0, length) };
            String::from_utf16(slice)
                .map(Some)
                .map_err(|_| SystemProxyError::InvalidProxyConfiguration)
        }

        fn free(&mut self) {
            if !self.0.is_null() {
                // SAFETY: WinHTTP documents these strings as GlobalAlloc
                // allocations owned by the caller.
                unsafe {
                    GlobalFree(self.0.cast());
                }
                self.0 = ptr::null_mut();
            }
        }
    }

    impl Drop for OwnedGlobalWide {
        fn drop(&mut self) {
            self.free();
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{RawProxySnapshot, SystemProxyError};

    pub(super) fn capture_raw() -> Result<RawProxySnapshot, SystemProxyError> {
        Err(SystemProxyError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::routes::InterfaceIdentity;

    fn route_binding(next_hop: IpAddr) -> RouteBinding {
        RouteBinding {
            interface: InterfaceIdentity {
                interface_index: 7,
                interface_luid: 70,
                interface_guid: "{00000000-0000-0000-0000-000000000007}".to_owned(),
                alias: "Ethernet".to_owned(),
            },
            source: "192.0.2.10".parse().unwrap(),
            next_hop,
        }
    }

    #[test]
    fn parses_protocol_lists_ipv6_and_credentials_without_retaining_secrets() {
        let parsed = parse_proxy_list(
            "http=proxy.example:8080;https=https://user:secret@10.0.0.20:8443;\
             socks=[fd00::20]:1080",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ProxyAuthority {
                    host: "proxy.example".to_owned(),
                    port: 8080,
                },
                ProxyAuthority {
                    host: "10.0.0.20".to_owned(),
                    port: 8443,
                },
                ProxyAuthority {
                    host: "fd00::20".to_owned(),
                    port: 1080,
                },
            ]
        );
        assert!(!format!("{parsed:?}").contains("secret"));
    }

    #[test]
    fn parses_whitespace_delimited_protocols_and_inner_scheme_default_ports() {
        let parsed = parse_proxy_list(
            "http=first.example:8080 https=second.example:8443 \
             ftp=ftp.example socks=socks.example http=https://secure-proxy.example",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ProxyAuthority {
                    host: "first.example".to_owned(),
                    port: 8080,
                },
                ProxyAuthority {
                    host: "second.example".to_owned(),
                    port: 8443,
                },
                ProxyAuthority {
                    host: "ftp.example".to_owned(),
                    port: 21,
                },
                ProxyAuthority {
                    host: "socks.example".to_owned(),
                    port: 1080,
                },
                ProxyAuthority {
                    host: "secure-proxy.example".to_owned(),
                    port: 443,
                },
            ]
        );
    }

    #[test]
    fn direct_tokens_and_malformed_authorities_are_rejected_safely() {
        assert!(parse_proxy_list("DIRECT;<local>").unwrap().is_empty());
        assert_eq!(
            parse_proxy_list("http=proxy.example:0").unwrap_err(),
            SystemProxyError::InvalidProxyConfiguration
        );
        assert_eq!(
            parse_proxy_list("http=*.example:8080").unwrap_err(),
            SystemProxyError::InvalidProxyConfiguration
        );
        assert_eq!(
            parse_proxy_list("unknown=proxy.example").unwrap_err(),
            SystemProxyError::InvalidProxyConfiguration
        );
    }

    #[test]
    fn only_explicit_local_or_intranet_addresses_qualify() {
        for value in [
            "127.0.0.1",
            "10.0.0.20",
            "169.254.1.1",
            "100.64.0.1",
            "::1",
            "fe80::1",
            "fd00::1",
        ] {
            assert!(is_local_or_intranet_address(value.parse().unwrap()));
        }
        assert!(!is_local_or_intranet_address("8.8.8.8".parse().unwrap()));
        assert!(!is_local_or_intranet_address(
            "2001:4860:4860::8888".parse().unwrap()
        ));
    }

    #[test]
    fn ipv6_scope_is_normalized_for_packet_endpoint_matching() {
        let endpoint = SocketAddr::V6(SocketAddrV6::new("fe80::20".parse().unwrap(), 8080, 9, 7));
        assert_eq!(
            normalize_endpoint(endpoint),
            "[fe80::20]:8080".parse().unwrap()
        );
    }

    #[test]
    fn confirmation_is_exact_route_checked_and_keeps_loopback_local() {
        let snapshot = SystemProxySnapshot {
            endpoints: vec![
                "127.0.0.1:8080".parse().unwrap(),
                "10.0.0.20:8080".parse().unwrap(),
                "8.8.8.8:8080".parse().unwrap(),
                "203.0.113.20:8080".parse().unwrap(),
            ],
            manual_proxy_configured: true,
            ..SystemProxySnapshot::default()
        };
        let confirmed = confirm_intranet_endpoints(&snapshot, 42, |address| {
            let next_hop = if address == "203.0.113.20".parse::<IpAddr>().unwrap() {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            } else {
                "192.0.2.1".parse().unwrap()
            };
            Ok::<_, ()>(route_binding(next_hop))
        })
        .unwrap();
        assert_eq!(
            confirmed,
            vec![
                ConfirmedSystemProxyEndpoint {
                    endpoint: "10.0.0.20:8080".parse().unwrap(),
                    route: route_binding("192.0.2.1".parse().unwrap()),
                },
                ConfirmedSystemProxyEndpoint {
                    endpoint: "203.0.113.20:8080".parse().unwrap(),
                    route: route_binding(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                },
            ]
        );
    }

    #[test]
    fn confirmed_route_retains_stable_identity_source_and_gateway() {
        let snapshot = SystemProxySnapshot {
            endpoints: vec!["10.0.0.20:8080".parse().unwrap()],
            manual_proxy_configured: true,
            ..SystemProxySnapshot::default()
        };
        let original = route_binding("192.0.2.1".parse().unwrap());
        let confirmed =
            confirm_intranet_endpoints(&snapshot, 42, |_| Ok::<_, ()>(original.clone())).unwrap();
        assert_eq!(confirmed[0].route, original);

        let mut reused_index = confirmed[0].route.clone();
        reused_index.interface.interface_luid = 71;
        reused_index.interface.interface_guid = "{00000000-0000-0000-0000-000000000008}".to_owned();
        assert_ne!(confirmed[0].route, reused_index);
    }

    #[test]
    fn errors_do_not_include_proxy_strings_or_credentials() {
        let error = SystemProxyError::Api {
            operation: "current-user proxy discovery",
            code: 5,
        };
        let display = error.to_string();
        assert_eq!(display, "current-user proxy discovery failed (OS error 5)");
        assert!(!display.contains("secret.example"));
        assert!(!display.contains("password="));
    }

    #[test]
    fn bounded_capture_returns_worker_result_promptly() {
        let started = Instant::now();
        let result = capture_bounded_with(
            Duration::from_secs(1),
            || false,
            || Ok::<_, SystemProxyError>(42),
        )
        .unwrap();
        assert_eq!(result, 42);
        assert!(started.elapsed() < Duration::from_millis(500));
    }

    #[test]
    fn bounded_capture_times_out_without_waiting_for_worker() {
        let started = Instant::now();
        let error = capture_bounded_with(
            Duration::from_millis(25),
            || false,
            || {
                std::thread::sleep(Duration::from_millis(500));
                Ok::<_, SystemProxyError>(())
            },
        )
        .unwrap_err();
        assert_eq!(error, SystemProxyError::TimedOut);
        assert!(started.elapsed() < Duration::from_millis(400));
    }

    #[test]
    fn bounded_capture_polls_cancellation_without_waiting_for_worker() {
        let started = Instant::now();
        let mut cancellation_checks = 0;
        let error = capture_bounded_with(
            Duration::from_secs(1),
            || {
                cancellation_checks += 1;
                cancellation_checks >= 2
            },
            || {
                std::thread::sleep(Duration::from_millis(500));
                Ok::<_, SystemProxyError>(())
            },
        )
        .unwrap_err();
        assert_eq!(error, SystemProxyError::Cancelled);
        assert!(started.elapsed() < Duration::from_millis(400));
    }
}
