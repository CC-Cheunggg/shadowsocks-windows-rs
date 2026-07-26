mod commands;
pub mod config;
pub mod diagnostics;
pub mod dns;
pub mod error;
pub mod outbound;
pub mod packet;
pub mod router;
pub mod runtime;
pub mod session;
pub mod system_proxy;
pub mod tun;

use config::ConfigStore;
use runtime::RuntimeManager;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let config_dir = app.path().app_config_dir()?;
            app.manage(ConfigStore::initialize(config_dir.clone())?);
            app.manage(RuntimeManager::new(config_dir));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_runtime_snapshot,
            commands::start_tunnel,
            commands::stop_tunnel,
            commands::recover_network,
            commands::get_config,
            commands::save_config,
            commands::add_server,
            commands::update_server,
            commands::delete_server,
            commands::select_server
        ])
        .run(tauri::generate_context!())
        .expect("error while running the Tauri application");
}
