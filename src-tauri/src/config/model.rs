use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;

pub const CURRENT_CONFIG_VERSION: u32 = 1;
pub const DEFAULT_CONFIG_FILE_NAME: &str = "config.json";
pub const SUPPORTED_METHODS: [&str; 3] = [
    "2022-blake3-chacha20-poly1305",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionMode {
    Direct,
    Rule,
    Global,
}

impl Default for ConnectionMode {
    fn default() -> Self {
        Self::Rule
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub enabled: bool,
    pub servers: Vec<String>,
    pub ipv6: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            servers: vec!["1.1.1.1".to_owned(), "8.8.8.8".to_owned()],
            ipv6: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunConfig {
    pub enabled: bool,
    pub interface_name: String,
    pub mtu: u16,
    pub ipv6: bool,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface_name: "Shadowsocks".to_owned(),
            mtu: 1500,
            ipv6: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct KillSwitchConfig {
    pub enabled: bool,
    pub allow_lan: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServerSource {
    #[default]
    Manual,
    Subscription,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerProfile {
    pub id: String,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub password: String,
    pub method: String,
    pub timeout: u64,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    pub group: String,
    pub source: ServerSource,
}

impl fmt::Debug for ServerProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerProfile")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[REDACTED]")
            .field("method", &self.method)
            .field("timeout", &self.timeout)
            .field("plugin", &self.plugin)
            .field("plugin_opts", &self.plugin_opts)
            .field("group", &self.group)
            .field("source", &self.source)
            .finish()
    }
}

impl Default for ServerProfile {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            host: String::new(),
            port: 8388,
            password: String::new(),
            method: SUPPORTED_METHODS[0].to_owned(),
            timeout: 300,
            plugin: None,
            plugin_opts: None,
            group: String::new(),
            source: ServerSource::Manual,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SubscriptionSource {
    pub id: String,
    pub name: String,
    pub url: String,
    pub enabled: bool,
    pub update_interval_minutes: u32,
    pub last_updated_at: Option<u64>,
}

impl Default for SubscriptionSource {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            url: String::new(),
            enabled: true,
            update_interval_minutes: 1440,
            last_updated_at: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppConfig {
    pub version: u32,
    #[serde(default)]
    pub mode: ConnectionMode,
    #[serde(default)]
    pub selected_server_id: Option<String>,
    #[serde(default)]
    pub servers: Vec<ServerProfile>,
    #[serde(default)]
    pub dns: DnsConfig,
    #[serde(default)]
    pub tun: TunConfig,
    #[serde(default)]
    pub kill_switch: KillSwitchConfig,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionSource>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            version: CURRENT_CONFIG_VERSION,
            mode: ConnectionMode::Rule,
            selected_server_id: None,
            servers: Vec::new(),
            dns: DnsConfig::default(),
            tun: TunConfig::default(),
            kill_switch: KillSwitchConfig::default(),
            subscriptions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError(&'static str);

impl ValidationError {
    fn new(message: &'static str) -> Self {
        Self(message)
    }

    pub(super) fn from_static(message: &'static str) -> Self {
        Self::new(message)
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl std::error::Error for ValidationError {}

impl AppConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.version != CURRENT_CONFIG_VERSION {
            return Err(ValidationError::new("unsupported configuration version"));
        }
        if self.servers.len() > 10_000 {
            return Err(ValidationError::new("too many server profiles"));
        }
        if self.subscriptions.len() > 1_000 {
            return Err(ValidationError::new("too many subscription sources"));
        }
        if !(576..=9000).contains(&self.tun.mtu) {
            return Err(ValidationError::new("TUN MTU is outside the allowed range"));
        }
        validate_short_text(
            &self.tun.interface_name,
            "TUN interface name is invalid",
            false,
        )?;

        if self.dns.enabled && self.dns.servers.is_empty() {
            return Err(ValidationError::new(
                "at least one DNS server is required when DNS is enabled",
            ));
        }
        for server in &self.dns.servers {
            validate_short_text(server, "DNS server entry is invalid", false)?;
        }

        let mut server_ids = HashSet::with_capacity(self.servers.len());
        for server in &self.servers {
            server.validate()?;
            if !server_ids.insert(server.id.as_str()) {
                return Err(ValidationError::new("server profile IDs must be unique"));
            }
        }
        if let Some(selected_id) = &self.selected_server_id
            && !server_ids.contains(selected_id.as_str())
        {
            return Err(ValidationError::new(
                "selected server does not exist in the configuration",
            ));
        }

        let mut subscription_ids = HashSet::with_capacity(self.subscriptions.len());
        for subscription in &self.subscriptions {
            subscription.validate()?;
            if !subscription_ids.insert(subscription.id.as_str()) {
                return Err(ValidationError::new(
                    "subscription source IDs must be unique",
                ));
            }
        }
        Ok(())
    }
}

impl ServerProfile {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_id(&self.id, "server profile ID is invalid")?;
        validate_short_text(&self.name, "server profile name is invalid", false)?;
        validate_host(&self.host)?;
        if self.port == 0 {
            return Err(ValidationError::new(
                "server port must be between 1 and 65535",
            ));
        }
        if self.password.is_empty() || self.password.len() > 4096 {
            return Err(ValidationError::new("server password is invalid"));
        }
        if !SUPPORTED_METHODS.contains(&self.method.as_str()) {
            return Err(ValidationError::new("encryption method is not supported"));
        }
        if !(1..=86_400).contains(&self.timeout) {
            return Err(ValidationError::new(
                "server timeout must be between 1 and 86400 seconds",
            ));
        }
        validate_optional_text(&self.plugin, "plugin name is invalid")?;
        validate_optional_text(&self.plugin_opts, "plugin options are invalid")?;
        validate_short_text(&self.group, "server group is invalid", true)?;
        Ok(())
    }
}

impl SubscriptionSource {
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_id(&self.id, "subscription source ID is invalid")?;
        validate_short_text(&self.name, "subscription source name is invalid", false)?;
        if self.url.len() > 4096
            || self.url.chars().any(char::is_control)
            || self.url.chars().any(char::is_whitespace)
            || !(self.url.starts_with("https://") || self.url.starts_with("http://"))
        {
            return Err(ValidationError::new("subscription source URL is invalid"));
        }
        if !(15..=100_800).contains(&self.update_interval_minutes) {
            return Err(ValidationError::new(
                "subscription update interval is outside the allowed range",
            ));
        }
        Ok(())
    }
}

fn validate_id(value: &str, message: &'static str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ValidationError::new(message));
    }
    Ok(())
}

fn validate_host(host: &str) -> Result<(), ValidationError> {
    if host.is_empty()
        || host.len() > 253
        || host.chars().any(char::is_control)
        || host.chars().any(char::is_whitespace)
        || host.contains('/')
    {
        return Err(ValidationError::new("server host is invalid"));
    }
    Ok(())
}

fn validate_optional_text(
    value: &Option<String>,
    message: &'static str,
) -> Result<(), ValidationError> {
    if let Some(value) = value {
        validate_short_text(value, message, true)?;
    }
    Ok(())
}

fn validate_short_text(
    value: &str,
    message: &'static str,
    allow_empty: bool,
) -> Result<(), ValidationError> {
    if (!allow_empty && value.trim().is_empty())
        || value.len() > 255
        || value.chars().any(char::is_control)
    {
        return Err(ValidationError::new(message));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_server() -> ServerProfile {
        ServerProfile {
            id: "server-1".to_owned(),
            name: "Test server".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 8388,
            password: "do-not-expose-this".to_owned(),
            method: "2022-blake3-chacha20-poly1305".to_owned(),
            group: "Test".to_owned(),
            ..ServerProfile::default()
        }
    }

    #[test]
    fn default_config_is_valid() {
        AppConfig::default().validate().unwrap();
    }

    #[test]
    fn validates_server_fields_and_selection() {
        let mut config = AppConfig {
            servers: vec![valid_server()],
            selected_server_id: Some("server-1".to_owned()),
            ..AppConfig::default()
        };
        config.validate().unwrap();

        config.servers[0].port = 0;
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("port"));
        assert!(!error.contains("do-not-expose-this"));
    }

    #[test]
    fn validation_errors_never_include_password_values() {
        let mut server = valid_server();
        server.host = "invalid host".to_owned();
        let error = server.validate().unwrap_err().to_string();
        assert!(!error.contains(&server.password));

        server.host = "localhost".to_owned();
        server.password.clear();
        assert_eq!(
            server.validate().unwrap_err().to_string(),
            "server password is invalid"
        );
    }

    #[test]
    fn debug_output_redacts_password_values() {
        let server = valid_server();
        let debug = format!("{server:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains(&server.password));
    }

    #[test]
    fn only_explicitly_supported_encryption_methods_are_accepted() {
        for method in SUPPORTED_METHODS {
            let mut server = valid_server();
            server.method = method.to_owned();
            server.validate().unwrap();
        }

        for method in ["aes-256-gcm", "2022-blake3-aes-256-gcm", "plain"] {
            let mut server = valid_server();
            server.method = method.to_owned();
            assert_eq!(
                server.validate().unwrap_err().to_string(),
                "encryption method is not supported"
            );
        }
    }
}
