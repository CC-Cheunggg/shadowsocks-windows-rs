mod config;

use config::{AppConfig, ConfigStore, ServerProfile};
use serde::Serialize;
use tauri::{Manager, State};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct RuntimeSnapshot {
    platform: &'static str,
    service_state: &'static str,
    tun_available: bool,
    version: &'static str,
}

#[tauri::command]
fn get_runtime_snapshot() -> RuntimeSnapshot {
    RuntimeSnapshot {
        platform: std::env::consts::OS,
        service_state: "not-installed",
        tun_available: cfg!(target_os = "windows"),
        version: env!("CARGO_PKG_VERSION"),
    }
}

#[tauri::command]
fn get_config(store: State<'_, ConfigStore>) -> Result<AppConfig, String> {
    store.get_config().map_err(|error| error.to_string())
}

#[tauri::command]
fn save_config(store: State<'_, ConfigStore>, config: AppConfig) -> Result<AppConfig, String> {
    store.save_config(config).map_err(|error| error.to_string())
}

#[tauri::command]
fn add_server(store: State<'_, ConfigStore>, server: ServerProfile) -> Result<AppConfig, String> {
    store.add_server(server).map_err(|error| error.to_string())
}

#[tauri::command]
fn update_server(
    store: State<'_, ConfigStore>,
    server: ServerProfile,
) -> Result<AppConfig, String> {
    store
        .update_server(server)
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn delete_server(store: State<'_, ConfigStore>, id: String) -> Result<AppConfig, String> {
    store.delete_server(&id).map_err(|error| error.to_string())
}

#[tauri::command]
fn select_server(store: State<'_, ConfigStore>, id: String) -> Result<AppConfig, String> {
    store.select_server(&id).map_err(|error| error.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            app.manage(ConfigStore::initialize(config_dir)?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_runtime_snapshot,
            get_config,
            save_config,
            add_server,
            update_server,
            delete_server,
            select_server
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Tauri application");
}
