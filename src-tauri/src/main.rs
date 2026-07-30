#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

fn main() {
    #[cfg(target_os = "windows")]
    if shadowsocks_windows_rs_lib::webview2_bootstrap::prepare_before_tauri().is_err() {
        std::process::exit(1);
    }

    shadowsocks_windows_rs_lib::run();
}
