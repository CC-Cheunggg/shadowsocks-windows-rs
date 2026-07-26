use crate::config::{AppConfig, ConfigStore, ServerProfile};
use crate::runtime::{RuntimeManager, RuntimeSnapshot};
use tauri::State;

#[tauri::command]
pub fn get_runtime_snapshot(manager: State<'_, RuntimeManager>) -> RuntimeSnapshot {
    manager.snapshot()
}

#[tauri::command]
pub fn start_tunnel(
    store: State<'_, ConfigStore>,
    manager: State<'_, RuntimeManager>,
) -> Result<RuntimeSnapshot, String> {
    let config = store.get_config().map_err(|error| error.to_string())?;
    manager.start(&config).map_err(|error| error.to_string())
}

#[tauri::command]
pub fn stop_tunnel(manager: State<'_, RuntimeManager>) -> Result<RuntimeSnapshot, String> {
    manager.stop().map_err(|error| error.to_string())
}

#[tauri::command]
pub fn recover_network(manager: State<'_, RuntimeManager>) -> Result<RuntimeSnapshot, String> {
    manager.recover().map_err(|error| error.to_string())
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
