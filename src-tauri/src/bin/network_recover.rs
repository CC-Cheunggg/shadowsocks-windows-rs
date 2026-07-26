//! Standalone recovery helper for an interrupted Wintun runtime.
//!
//! The journal location is intentionally fixed to this application's config
//! directory. No caller-controlled DLL, script, or system-file path is
//! accepted.

use shadowsocks_windows_rs_lib::runtime::recovery;
use std::path::PathBuf;
use std::process::ExitCode;

const APPLICATION_IDENTIFIER: &str = "dev.shadowsocks-windows-rs.app";

fn main() -> ExitCode {
    if !cfg!(windows) {
        eprintln!("network recovery is available only on Windows");
        return ExitCode::from(2);
    }

    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let action = arguments
        .next()
        .and_then(|argument| argument.into_string().ok())
        .unwrap_or_else(|| "--status".to_owned());
    if arguments.next().is_some() || !matches!(action.as_str(), "--status" | "--apply") {
        eprintln!("usage: network_recover.exe [--status|--apply]");
        return ExitCode::from(2);
    }

    let Some(config_directory) = application_config_directory() else {
        eprintln!("the application config directory is unavailable");
        return ExitCode::from(2);
    };
    let journal_path = recovery::journal_path(&config_directory);

    match action.as_str() {
        "--status" => match recovery::load(&journal_path) {
            Ok(Some(journal)) => {
                println!(
                    "recovery required: adapter={}, interface_index={}, interface_luid={}, \
                     interface_guid={}, owned_changes={}",
                    journal.adapter_name,
                    journal.adapter_identity.interface_index,
                    journal.adapter_identity.interface_luid,
                    journal.adapter_identity.interface_guid,
                    journal.owned_change_count()
                );
                ExitCode::SUCCESS
            }
            Ok(None) => {
                println!("no recovery journal is present");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("recovery journal inspection failed: {error}");
                ExitCode::from(1)
            }
        },
        "--apply" => match recovery::recover(&journal_path) {
            Ok(true) => {
                println!("recorded Wintun addresses and routes were restored");
                ExitCode::SUCCESS
            }
            Ok(false) => {
                println!("no recovery journal is present");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("network recovery failed: {error}");
                ExitCode::from(1)
            }
        },
        _ => unreachable!(),
    }
}

fn application_config_directory() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|directory| directory.join(APPLICATION_IDENTIFIER))
}
