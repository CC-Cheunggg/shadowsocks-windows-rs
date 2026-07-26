use super::model::{
    AppConfig, CURRENT_CONFIG_VERSION, DEFAULT_CONFIG_FILE_NAME, LEGACY_CONFIG_VERSION,
    ServerProfile, ValidationError,
};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration storage operation failed")]
    Io(#[source] io::Error),
    #[error("configuration JSON could not be processed")]
    Json(#[source] serde_json::Error),
    #[error("configuration version is not supported")]
    UnsupportedVersion,
    #[error("{0}")]
    Validation(#[from] ValidationError),
    #[error("configuration state is unavailable")]
    Lock,
    #[error("server profile was not found")]
    ServerNotFound,
}

impl From<io::Error> for ConfigError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<serde_json::Error> for ConfigError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error)
    }
}

#[derive(Debug)]
pub struct LoadResult {
    pub config: AppConfig,
    pub recovered_backup: Option<PathBuf>,
    pub migrated_backup: Option<PathBuf>,
}

pub struct ConfigStore {
    path: PathBuf,
    config: Mutex<AppConfig>,
}

impl ConfigStore {
    pub fn initialize(app_config_dir: PathBuf) -> Result<Self, ConfigError> {
        let path = app_config_dir.join(DEFAULT_CONFIG_FILE_NAME);
        let LoadResult {
            config,
            recovered_backup: _recovered_backup,
            migrated_backup: _migrated_backup,
        } = load_or_recover(&path)?;
        Ok(Self {
            path,
            config: Mutex::new(config),
        })
    }

    pub fn get_config(&self) -> Result<AppConfig, ConfigError> {
        Ok(self.lock()?.clone())
    }

    pub fn save_config(&self, config: AppConfig) -> Result<AppConfig, ConfigError> {
        config.validate()?;
        let mut current = self.lock()?;
        atomic_save(&self.path, &config)?;
        *current = config.clone();
        Ok(config)
    }

    pub fn add_server(&self, mut server: ServerProfile) -> Result<AppConfig, ConfigError> {
        let mut current = self.lock()?;
        let mut next = current.clone();
        if server.id.is_empty() {
            server.id = unique_server_id(&next);
        }
        server.validate()?;
        if next.servers.iter().any(|existing| existing.id == server.id) {
            return Err(ConfigError::Validation(ValidationError::from_static(
                "server profile ID already exists",
            )));
        }
        let server_id = server.id.clone();
        next.servers.push(server);
        next.selected_server_id = Some(server_id);
        persist_and_replace(&self.path, &mut current, next)
    }

    pub fn update_server(&self, server: ServerProfile) -> Result<AppConfig, ConfigError> {
        server.validate()?;
        let mut current = self.lock()?;
        let mut next = current.clone();
        let existing = next
            .servers
            .iter_mut()
            .find(|existing| existing.id == server.id)
            .ok_or(ConfigError::ServerNotFound)?;
        *existing = server;
        persist_and_replace(&self.path, &mut current, next)
    }

    pub fn delete_server(&self, id: &str) -> Result<AppConfig, ConfigError> {
        let mut current = self.lock()?;
        let mut next = current.clone();
        let previous_len = next.servers.len();
        next.servers.retain(|server| server.id != id);
        if next.servers.len() == previous_len {
            return Err(ConfigError::ServerNotFound);
        }
        if next.selected_server_id.as_deref() == Some(id) {
            next.selected_server_id = next.servers.first().map(|server| server.id.clone());
        }
        persist_and_replace(&self.path, &mut current, next)
    }

    pub fn select_server(&self, id: &str) -> Result<AppConfig, ConfigError> {
        let mut current = self.lock()?;
        let mut next = current.clone();
        if !next.servers.iter().any(|server| server.id == id) {
            return Err(ConfigError::ServerNotFound);
        }
        next.selected_server_id = Some(id.to_owned());
        persist_and_replace(&self.path, &mut current, next)
    }

    fn lock(&self) -> Result<MutexGuard<'_, AppConfig>, ConfigError> {
        self.config.lock().map_err(|_| ConfigError::Lock)
    }
}

fn persist_and_replace(
    path: &Path,
    current: &mut MutexGuard<'_, AppConfig>,
    next: AppConfig,
) -> Result<AppConfig, ConfigError> {
    next.validate()?;
    atomic_save(path, &next)?;
    **current = next.clone();
    Ok(next)
}

pub fn load_or_recover(path: &Path) -> Result<LoadResult, ConfigError> {
    if !path.exists() {
        let config = AppConfig::default();
        atomic_save(path, &config)?;
        return Ok(LoadResult {
            config,
            recovered_backup: None,
            migrated_backup: None,
        });
    }

    let bytes = fs::read(path)?;
    match decode_config(&bytes) {
        Ok((config, None)) => Ok(LoadResult {
            config,
            recovered_backup: None,
            migrated_backup: None,
        }),
        Ok((config, Some(previous_version))) => {
            let backup = backup_before_migration(path, &bytes, previous_version)?;
            atomic_save(path, &config)?;
            Ok(LoadResult {
                config,
                recovered_backup: None,
                migrated_backup: Some(backup),
            })
        }
        Err(ConfigError::UnsupportedVersion) => Err(ConfigError::UnsupportedVersion),
        Err(ConfigError::Json(_) | ConfigError::Validation(_)) => {
            let backup = backup_corrupt_config(path)?;
            let config = AppConfig::default();
            atomic_save(path, &config)?;
            Ok(LoadResult {
                config,
                recovered_backup: Some(backup),
                migrated_backup: None,
            })
        }
        Err(error) => Err(error),
    }
}

fn decode_config(bytes: &[u8]) -> Result<(AppConfig, Option<u32>), ConfigError> {
    let mut value: serde_json::Value = serde_json::from_slice(bytes)?;
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(ConfigError::UnsupportedVersion)?;

    let migrated_from = match version {
        CURRENT_CONFIG_VERSION => None,
        LEGACY_CONFIG_VERSION => {
            migrate_v1_to_v2(&mut value)?;
            Some(LEGACY_CONFIG_VERSION)
        }
        _ => return Err(ConfigError::UnsupportedVersion),
    };

    let config: AppConfig = serde_json::from_value(value)?;
    config.validate()?;
    Ok((config, migrated_from))
}

fn migrate_v1_to_v2(value: &mut serde_json::Value) -> Result<(), ConfigError> {
    let object = value.as_object_mut().ok_or_else(|| {
        ConfigError::Json(json_type_error("configuration root must be an object"))
    })?;
    object.insert(
        "version".to_owned(),
        serde_json::Value::from(CURRENT_CONFIG_VERSION),
    );

    // Version 1 exposed `tun.enabled` only as an inert placeholder. Version 2
    // makes Wintun the sole traffic entry point, so migration explicitly turns
    // it on. All credentials and server objects remain untouched.
    match object.get_mut("tun") {
        Some(serde_json::Value::Object(tun)) => {
            tun.insert("enabled".to_owned(), serde_json::Value::Bool(true));
        }
        Some(_) => {
            return Err(ConfigError::Json(json_type_error(
                "TUN configuration must be an object",
            )));
        }
        None => {
            object.insert(
                "tun".to_owned(),
                serde_json::to_value(super::model::TunConfig::default())?,
            );
        }
    }
    Ok(())
}

fn json_type_error(message: &'static str) -> serde_json::Error {
    <serde_json::Error as serde::de::Error>::custom(message)
}

fn backup_before_migration(
    path: &Path,
    bytes: &[u8],
    previous_version: u32,
) -> Result<PathBuf, ConfigError> {
    let parent = path.parent().ok_or_else(|| {
        ConfigError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration path has no parent directory",
        ))
    })?;
    let stamp = timestamp_nanos();
    for suffix in 0..1000_u16 {
        let backup = parent.join(format!(
            "config.pre-migration-v{previous_version}-{stamp}-{suffix}.json"
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&backup)
        {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
                return Ok(backup);
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ConfigError::Io(error)),
        }
    }
    Err(ConfigError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate a configuration migration backup name",
    )))
}

pub fn load_config(path: &Path) -> Result<AppConfig, ConfigError> {
    let bytes = fs::read(path)?;
    let (config, _) = decode_config(&bytes)?;
    Ok(config)
}

pub fn atomic_save(path: &Path, config: &AppConfig) -> Result<(), ConfigError> {
    config.validate()?;
    let parent = path.parent().ok_or_else(|| {
        ConfigError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration path has no parent directory",
        ))
    })?;
    fs::create_dir_all(parent)?;

    let bytes = serde_json::to_vec_pretty(config)?;
    let temp_path = unique_temp_path(path);
    let result = (|| -> Result<(), ConfigError> {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        temp.write_all(&bytes)?;
        temp.write_all(b"\n")?;
        temp.sync_all()?;
        drop(temp);
        replace_file(&temp_path, path)?;
        sync_parent(parent)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn backup_corrupt_config(path: &Path) -> Result<PathBuf, ConfigError> {
    let parent = path.parent().ok_or_else(|| {
        ConfigError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration path has no parent directory",
        ))
    })?;
    let stamp = timestamp_nanos();
    for suffix in 0..1000_u16 {
        let backup = parent.join(format!("config.corrupt-{stamp}-{suffix}.json"));
        match fs::rename(path, &backup) {
            Ok(()) => return Ok(backup),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(ConfigError::Io(error)),
        }
    }
    Err(ConfigError::Io(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to allocate a corrupt configuration backup name",
    )))
}

fn unique_server_id(config: &AppConfig) -> String {
    let base = format!("server-{:x}", timestamp_nanos());
    if !config.servers.iter().any(|server| server.id == base) {
        return base;
    }
    for suffix in 1..=u32::MAX {
        let candidate = format!("{base}-{suffix}");
        if !config.servers.iter().any(|server| server.id == candidate) {
            return candidate;
        }
    }
    unreachable!("server ID space exhausted")
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(DEFAULT_CONFIG_FILE_NAME);
    parent.join(format!(".{file_name}.{}.tmp", timestamp_nanos()))
}

fn timestamp_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(not(target_os = "windows"))]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(target_os = "windows")]
fn replace_file(source: &Path, destination: &Path) -> io::Result<()> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(iter::once(0))
        .collect();
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
fn sync_parent(_parent: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::model::{CURRENT_CONFIG_VERSION, ServerSource, TunConfig};

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "shadowsocks-windows-rs-{label}-{}",
                timestamp_nanos()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn config_path(&self) -> PathBuf {
            self.0.join(DEFAULT_CONFIG_FILE_NAME)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn valid_server() -> ServerProfile {
        ServerProfile {
            id: "test-server".to_owned(),
            name: "Local test".to_owned(),
            host: "127.0.0.1".to_owned(),
            port: 8388,
            password: "test-secret-that-must-not-leak".to_owned(),
            method: "2022-blake3-chacha20-poly1305".to_owned(),
            timeout: 300,
            plugin: None,
            plugin_opts: None,
            group: "Tests".to_owned(),
            source: ServerSource::Manual,
        }
    }

    #[test]
    fn missing_configuration_creates_and_loads_defaults() {
        let directory = TestDirectory::new("default");
        let result = load_or_recover(&directory.config_path()).unwrap();
        assert_eq!(result.config, AppConfig::default());
        assert!(result.recovered_backup.is_none());
        assert_eq!(
            load_config(&directory.config_path()).unwrap(),
            AppConfig::default()
        );
    }

    #[test]
    fn atomically_saves_and_loads_configuration() {
        let directory = TestDirectory::new("save");
        let path = directory.config_path();
        let config = AppConfig {
            selected_server_id: Some("test-server".to_owned()),
            servers: vec![valid_server()],
            ..AppConfig::default()
        };
        atomic_save(&path, &config).unwrap();
        assert_eq!(load_config(&path).unwrap(), config);
        assert!(fs::read_dir(&directory.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with(".tmp")
        }));
    }

    #[test]
    fn rejects_invalid_configuration_without_exposing_password() {
        let directory = TestDirectory::new("validation");
        let path = directory.config_path();
        let mut config = AppConfig {
            servers: vec![valid_server()],
            ..AppConfig::default()
        };
        config.tun = TunConfig {
            mtu: 1,
            ..TunConfig::default()
        };
        let error = atomic_save(&path, &config).unwrap_err().to_string();
        assert!(error.contains("MTU"));
        assert!(!error.contains("test-secret-that-must-not-leak"));
        assert!(!path.exists());
    }

    #[test]
    fn corrupt_configuration_is_backed_up_and_recovered() {
        let directory = TestDirectory::new("recovery");
        let path = directory.config_path();
        fs::write(&path, b"{ definitely not valid JSON").unwrap();

        let result = load_or_recover(&path).unwrap();
        let backup = result.recovered_backup.expect("corrupt backup path");
        assert_eq!(result.config, AppConfig::default());
        assert_eq!(
            fs::read_to_string(backup).unwrap(),
            "{ definitely not valid JSON"
        );
        assert_eq!(load_config(&path).unwrap(), AppConfig::default());
    }

    #[test]
    fn store_mutations_are_validated_and_persisted() {
        let directory = TestDirectory::new("mutations");
        let store = ConfigStore::initialize(directory.0.clone()).unwrap();
        let added = store.add_server(valid_server()).unwrap();
        assert_eq!(added.selected_server_id.as_deref(), Some("test-server"));

        let selected = store.select_server("test-server").unwrap();
        assert_eq!(selected, load_config(&directory.config_path()).unwrap());

        let deleted = store.delete_server("test-server").unwrap();
        assert!(deleted.servers.is_empty());
        assert!(deleted.selected_server_id.is_none());
    }

    #[test]
    fn serialized_config_contains_an_explicit_version() {
        let json = serde_json::to_value(AppConfig::default()).unwrap();
        assert_eq!(json["version"], CURRENT_CONFIG_VERSION);
    }

    #[test]
    fn version_one_is_backed_up_and_migrated_without_losing_credentials() {
        let directory = TestDirectory::new("migration");
        let path = directory.config_path();
        let mut legacy = serde_json::to_value(AppConfig {
            servers: vec![valid_server()],
            selected_server_id: Some("test-server".to_owned()),
            ..AppConfig::default()
        })
        .unwrap();
        legacy["version"] = serde_json::Value::from(LEGACY_CONFIG_VERSION);
        legacy.as_object_mut().unwrap().remove("routing");
        for key in [
            "management_exclusions",
            "tcp_session_timeout_seconds",
            "udp_idle_timeout_seconds",
        ] {
            legacy["tun"].as_object_mut().unwrap().remove(key);
        }
        legacy["tun"]["enabled"] = serde_json::Value::Bool(false);
        for key in [
            "source",
            "tcp_fallback",
            "cache_capacity",
            "cache_ttl_seconds",
        ] {
            legacy["dns"].as_object_mut().unwrap().remove(key);
        }
        let legacy_bytes = serde_json::to_vec_pretty(&legacy).unwrap();
        fs::write(&path, &legacy_bytes).unwrap();

        let result = load_or_recover(&path).unwrap();
        let backup = result.migrated_backup.expect("migration backup");
        assert_eq!(fs::read(backup).unwrap(), legacy_bytes);
        assert_eq!(result.config.version, CURRENT_CONFIG_VERSION);
        assert!(result.config.tun.enabled);
        assert_eq!(result.config.servers[0].password, valid_server().password);
        assert_eq!(load_config(&path).unwrap(), result.config);
    }

    #[test]
    fn unknown_future_version_is_not_replaced_with_defaults() {
        let directory = TestDirectory::new("future-version");
        let path = directory.config_path();
        let mut future = serde_json::to_value(AppConfig::default()).unwrap();
        future["version"] = serde_json::Value::from(CURRENT_CONFIG_VERSION + 1);
        let bytes = serde_json::to_vec_pretty(&future).unwrap();
        fs::write(&path, &bytes).unwrap();

        assert!(matches!(
            load_or_recover(&path),
            Err(ConfigError::UnsupportedVersion)
        ));
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
