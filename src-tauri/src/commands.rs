use crate::config::{AppConfig, ConfigStore, ServerProfile};
use serde::Serialize;
use tauri::State;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSnapshot {
    platform: &'static str,
    service_state: &'static str,
    tun_available: bool,
    version: &'static str,
}

#[tauri::command]
pub fn get_runtime_snapshot() -> RuntimeSnapshot {
    RuntimeSnapshot {
        platform: std::env::consts::OS,
        service_state: "not-installed",
        tun_available: cfg!(target_os = "windows"),
        version: env!("CARGO_PKG_VERSION"),
    }
}

#[tauri::command]
pub fn get_config(store: State<'_, ConfigStore>) -> Result<AppConfig, String> {
    store.get_config().map_err(|error| error.to_string())
}

#[tauri::command]
pub fn save_config(store: State<'_, ConfigStore>, config: AppConfig) -> Result<AppConfig, String> {
    store.save_config(config).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn add_server(
    store: State<'_, ConfigStore>,
    server: ServerProfile,
) -> Result<AppConfig, String> {
    store.add_server(server).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn update_server(
    store: State<'_, ConfigStore>,
    server: ServerProfile,
) -> Result<AppConfig, String> {
    store
        .update_server(server)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub fn delete_server(store: State<'_, ConfigStore>, id: String) -> Result<AppConfig, String> {
    store.delete_server(&id).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn select_server(store: State<'_, ConfigStore>, id: String) -> Result<AppConfig, String> {
    store.select_server(&id).map_err(|error| error.to_string())
}
