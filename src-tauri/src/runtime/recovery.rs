use super::RuntimeError;
use crate::tun::routes::{
    InterfaceIdentity, RecoveryPlan, SystemNetworkSnapshot, find_interface_by_alias,
    find_interface_by_luid, resolve_interface_identity,
};
use crate::tun::wintun::{Adapter as WintunAdapter, Wintun};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(not(windows))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

pub const RECOVERY_FILE_NAME: &str = "network-recovery-v1.json";
const LEGACY_RECOVERY_VERSION: u32 = 1;
const RECOVERY_VERSION: u32 = 2;
const MAX_RECOVERY_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const ADAPTER_ABSENCE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const ADAPTER_ABSENCE_TIMEOUT: Duration = Duration::from_secs(5);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const RECOVERY_MUTEX_NAME: &str =
    "Global\\dev.shadowsocks-windows-rs.app.network-recovery.7f807e7b-8310-4d73-aaca-cf7e83b87095";

pub struct RecoveryLease {
    _platform: lease_platform::Lease,
}

impl RecoveryLease {
    pub fn try_acquire() -> Result<Self, RuntimeError> {
        lease_platform::Lease::try_acquire(RECOVERY_MUTEX_NAME).map(|platform| Self {
            _platform: platform,
        })
    }
}

#[cfg(windows)]
mod lease_platform {
    use super::RuntimeError;
    use std::ffi::c_void;
    use std::ptr::null;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::Threading::{ReleaseMutex, WaitForSingleObject};

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateMutexW(
            mutex_attributes: *const c_void,
            initial_owner: i32,
            name: *const u16,
        ) -> HANDLE;
    }

    pub(super) struct Lease {
        handle: HANDLE,
    }

    impl Lease {
        pub(super) fn try_acquire(name: &str) -> Result<Self, RuntimeError> {
            let name = name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            let handle = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
            if handle.is_null() {
                return Err(RuntimeError::subsystem(
                    "network recovery lease creation",
                    std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32),
                ));
            }
            match unsafe { WaitForSingleObject(handle, 0) } {
                WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self { handle }),
                WAIT_TIMEOUT => {
                    unsafe {
                        CloseHandle(handle);
                    }
                    Err(RuntimeError::RuntimeActive)
                }
                WAIT_FAILED => {
                    let error = std::io::Error::from_raw_os_error(unsafe { GetLastError() } as i32);
                    unsafe {
                        CloseHandle(handle);
                    }
                    Err(RuntimeError::subsystem(
                        "network recovery lease acquisition",
                        error,
                    ))
                }
                status => {
                    unsafe {
                        CloseHandle(handle);
                    }
                    Err(RuntimeError::subsystem(
                        "network recovery lease acquisition",
                        format!("unexpected Windows wait status {status}"),
                    ))
                }
            }
        }
    }

    impl Drop for Lease {
        fn drop(&mut self) {
            unsafe {
                ReleaseMutex(self.handle);
                CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod lease_platform {
    use super::{AtomicBool, Ordering, RuntimeError};

    static HELD: AtomicBool = AtomicBool::new(false);

    pub(super) struct Lease;

    impl Lease {
        pub(super) fn try_acquire(_name: &str) -> Result<Self, RuntimeError> {
            HELD.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .map(|_| Self)
                .map_err(|_| RuntimeError::RuntimeActive)
        }
    }

    impl Drop for Lease {
        fn drop(&mut self) {
            HELD.store(false, Ordering::Release);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryJournal {
    version: u32,
    pub adapter_name: String,
    pub adapter_identity: InterfaceIdentity,
    pub original: SystemNetworkSnapshot,
    pub recovery: RecoveryPlan,
}

impl RecoveryJournal {
    pub fn owned_change_count(&self) -> usize {
        self.recovery.owned_change_count()
    }
}

pub fn journal_path(config_directory: &Path) -> PathBuf {
    config_directory.join(RECOVERY_FILE_NAME)
}

pub(crate) fn prepare(
    path: &Path,
    adapter_name: String,
    original: SystemNetworkSnapshot,
    recovery: RecoveryPlan,
) -> Result<(), RuntimeError> {
    let parent = path.parent().ok_or(RuntimeError::RecoveryRequired)?;
    fs::create_dir_all(parent)
        .map_err(|error| RuntimeError::subsystem("recovery directory creation", error))?;
    let journal = RecoveryJournal {
        version: RECOVERY_VERSION,
        adapter_name,
        adapter_identity: recovery.tun_interface().clone(),
        original,
        recovery,
    };
    write_atomic(path, &journal, AtomicWriteMode::Create)
}

pub(crate) fn record_owned(path: &Path, recovery: RecoveryPlan) -> Result<(), RuntimeError> {
    let Some(mut journal) = load(path)? else {
        return Err(RuntimeError::RecoveryRequired);
    };
    if journal.adapter_identity != *recovery.tun_interface()
        || recovery.validate_journal_state().is_err()
        || !recovery.is_valid_successor_of(&journal.recovery)
    {
        return Err(RuntimeError::RecoveryRequired);
    }
    journal.recovery = recovery;
    write_atomic(path, &journal, AtomicWriteMode::Replace)
}

#[derive(Clone, Copy)]
enum AtomicWriteMode {
    Create,
    Replace,
}

fn write_atomic(
    path: &Path,
    journal: &RecoveryJournal,
    mode: AtomicWriteMode,
) -> Result<(), RuntimeError> {
    let parent = path.parent().ok_or(RuntimeError::RecoveryRequired)?;
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(RuntimeError::RecoveryRequired)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = parent.join(format!(
        ".{file_name}.tmp-{}-{sequence}",
        std::process::id()
    ));
    let bytes = serde_json::to_vec_pretty(journal)
        .map_err(|error| RuntimeError::subsystem("recovery journal encoding", error))?;
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        commit_atomic(&temporary, path, mode)?;
        sync_parent(parent)
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result.map_err(|error| {
        if matches!(mode, AtomicWriteMode::Create)
            && error.kind() == std::io::ErrorKind::AlreadyExists
        {
            RuntimeError::RecoveryRequired
        } else {
            RuntimeError::subsystem("recovery journal atomic write", error)
        }
    })
}

#[cfg(not(windows))]
fn commit_atomic(
    temporary: &Path,
    destination: &Path,
    mode: AtomicWriteMode,
) -> std::io::Result<()> {
    match mode {
        AtomicWriteMode::Create => {
            fs::hard_link(temporary, destination)?;
            fs::remove_file(temporary)
        }
        AtomicWriteMode::Replace => fs::rename(temporary, destination),
    }
}

#[cfg(windows)]
fn commit_atomic(
    temporary: &Path,
    destination: &Path,
    mode: AtomicWriteMode,
) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{
        MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
    };

    let temporary = temporary
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let destination = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = match mode {
        AtomicWriteMode::Create => MOVEFILE_WRITE_THROUGH,
        AtomicWriteMode::Replace => MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
    };
    let succeeded = unsafe { MoveFileExW(temporary.as_ptr(), destination.as_ptr(), flags) };
    if succeeded != 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() } as i32
        ))
    }
}

#[cfg(not(windows))]
fn sync_parent(parent: &Path) -> std::io::Result<()> {
    fs::File::open(parent)?.sync_all()
}

#[cfg(windows)]
fn sync_parent(_parent: &Path) -> std::io::Result<()> {
    // The native commit path requests write-through semantics for the rename.
    Ok(())
}

pub(crate) fn clear(path: &Path) -> Result<(), RuntimeError> {
    match fs::remove_file(path) {
        Ok(()) => {
            if let Some(parent) = path.parent() {
                sync_parent(parent)
                    .map_err(|error| RuntimeError::subsystem("recovery directory sync", error))?;
            }
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RuntimeError::subsystem("recovery journal removal", error)),
    }
}

pub fn load(path: &Path) -> Result<Option<RecoveryJournal>, RuntimeError> {
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(RuntimeError::subsystem("recovery journal read", error));
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| RuntimeError::subsystem("recovery journal metadata", error))?;
    if metadata.len() > MAX_RECOVERY_JOURNAL_BYTES {
        return Err(RuntimeError::RecoveryRequired);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_RECOVERY_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| RuntimeError::subsystem("recovery journal read", error))?;
    if bytes.len() as u64 > MAX_RECOVERY_JOURNAL_BYTES {
        return Err(RuntimeError::RecoveryRequired);
    }
    let journal: RecoveryJournal = serde_json::from_slice(&bytes)
        .map_err(|error| RuntimeError::subsystem("recovery journal decode", error))?;
    if !matches!(journal.version, LEGACY_RECOVERY_VERSION | RECOVERY_VERSION)
        || journal.adapter_identity != *journal.recovery.tun_interface()
        || journal.adapter_identity.interface_index == 0
        || journal.adapter_name != journal.adapter_identity.alias
    {
        return Err(RuntimeError::RecoveryRequired);
    }
    journal
        .recovery
        .validate_journal_encoding(journal.version == LEGACY_RECOVERY_VERSION)
        .map_err(|_| RuntimeError::RecoveryRequired)?;
    Ok(Some(journal))
}

pub fn recover(path: &Path) -> Result<bool, RuntimeError> {
    let lease = RecoveryLease::try_acquire()?;
    recover_with_lease(&lease, path)
}

pub(crate) fn recover_with_lease(
    _lease: &RecoveryLease,
    path: &Path,
) -> Result<bool, RuntimeError> {
    let Some(journal) = load(path)? else {
        return Ok(false);
    };

    // The journal is stored in the user's application-data directory and is
    // therefore not an authority for elevated network mutation. Prove that
    // its target is the exact Wintun adapter opened through the bundled API
    // before applying any recorded operation. Keep the handle alive across
    // restoration so the verified adapter cannot disappear and have its
    // index reused between the provenance check and the mutations.
    let adapter = open_verified_adapter(&journal)?;
    let has_external_routes = journal.recovery.has_external_routes();
    journal
        .recovery
        .restore_adapter_owned_only()
        .map_err(|error| RuntimeError::subsystem("network recovery", error))?;
    drop(adapter);

    if has_external_routes {
        // Physical host routes are safe to restore only from the runtime's
        // trusted in-memory transaction. The user-writable journal cannot
        // prove that an arbitrary physical route was created by this
        // application, even after the Wintun adapter itself is authenticated.
        return Err(RuntimeError::RecoveryRequired);
    }

    // An adapter opened after its creating process is gone cannot be deleted
    // independently through this Wintun API. It may already be disappearing,
    // though, and Windows interface enumeration can lag the close/removal
    // request. Wait for a bounded interval before retaining the journal.
    wait_for_adapter_absent(&journal.adapter_identity, ADAPTER_ABSENCE_TIMEOUT)?;
    clear(path)?;
    Ok(true)
}

fn open_verified_adapter(journal: &RecoveryJournal) -> Result<WintunAdapter, RuntimeError> {
    let wintun = Wintun::load().map_err(|_| RuntimeError::RecoveryRequired)?;
    let adapter = wintun
        .open_adapter(&journal.adapter_name)
        .map_err(|_| RuntimeError::RecoveryRequired)?;
    let opened_luid = adapter.luid();
    let opened_index = adapter
        .interface_index()
        .map_err(|_| RuntimeError::RecoveryRequired)?;
    let current =
        resolve_interface_identity(opened_index).map_err(|_| RuntimeError::RecoveryRequired)?;
    if !adapter_provenance_matches(
        &journal.adapter_identity,
        opened_luid,
        opened_index,
        &current,
    ) {
        return Err(RuntimeError::RecoveryRequired);
    }
    Ok(adapter)
}

fn adapter_provenance_matches(
    expected: &InterfaceIdentity,
    opened_luid: u64,
    opened_index: u32,
    current: &InterfaceIdentity,
) -> bool {
    opened_luid == expected.interface_luid
        && opened_index == expected.interface_index
        && current == expected
}

pub(crate) fn wait_for_adapter_absent(
    identity: &InterfaceIdentity,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    let started = Instant::now();
    loop {
        let adapter_by_alias = find_interface_by_alias(&identity.alias)
            .map_err(|error| RuntimeError::subsystem("recovered adapter verification", error))?;
        let adapter_by_luid = find_interface_by_luid(identity.interface_luid)
            .map_err(|error| RuntimeError::subsystem("recovered adapter verification", error))?;
        if adapter_by_alias.is_none() && adapter_by_luid.is_none() {
            return Ok(());
        }

        let elapsed = started.elapsed();
        if elapsed >= timeout {
            // Keep the journal: an operator must not mistake a partial
            // recovery or a residual adapter for complete cleanup.
            return Err(RuntimeError::RecoveryRequired);
        }
        thread::sleep((timeout - elapsed).min(ADAPTER_ABSENCE_POLL_INTERVAL));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tun::routes::{InterfaceAddress, OwnedRoute};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_path() -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ss-recovery-test-{}-{sequence}.json",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    fn identity() -> InterfaceIdentity {
        InterfaceIdentity {
            interface_index: 42,
            interface_luid: 4242,
            interface_guid: "00000000-0000-0000-0000-000000000042".to_owned(),
            alias: "Shadowsocks".to_owned(),
        }
    }

    fn snapshot() -> SystemNetworkSnapshot {
        SystemNetworkSnapshot {
            captured_unix_ms: 1,
            adapters_json: "[]".to_owned(),
            routes_json: "[]".to_owned(),
            dns_json: "[]".to_owned(),
        }
    }

    fn recorded_plan() -> RecoveryPlan {
        let identity = identity();
        RecoveryPlan::from_parts_for_runtime_test(
            identity.clone(),
            vec![InterfaceAddress {
                address: IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1)),
                prefix_length: 15,
            }],
            vec![OwnedRoute {
                destination_prefix: "0.0.0.0/1".to_owned(),
                interface: identity,
                next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                metric: 5,
            }],
        )
    }

    #[test]
    fn journal_round_trip_records_stable_identity_and_exact_count() {
        let path = unique_path();
        prepare(&path, "Shadowsocks".to_owned(), snapshot(), recorded_plan()).unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.version, RECOVERY_VERSION);
        assert_eq!(loaded.adapter_identity, identity());
        assert_eq!(loaded.owned_change_count(), 2);
        clear(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn journal_create_is_non_overwriting_and_atomic_update_preserves_identity() {
        let path = unique_path();
        let empty = RecoveryPlan::empty(identity()).unwrap();
        prepare(&path, "Shadowsocks".to_owned(), snapshot(), empty).unwrap();
        assert_eq!(
            prepare(&path, "Shadowsocks".to_owned(), snapshot(), recorded_plan(),),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(load(&path).unwrap().unwrap().owned_change_count(), 0);
        let mut other_identity = identity();
        other_identity.interface_luid += 1;
        assert_eq!(
            record_owned(&path, RecoveryPlan::empty(other_identity).unwrap()),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(load(&path).unwrap().unwrap().owned_change_count(), 0);
        record_owned(&path, recorded_plan()).unwrap();
        assert_eq!(load(&path).unwrap().unwrap().owned_change_count(), 2);
        clear(&path).unwrap();
        clear(&path).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn recovery_lease_rejects_a_second_process_equivalent_holder() {
        let lease = RecoveryLease::try_acquire().unwrap();
        assert!(matches!(
            RecoveryLease::try_acquire(),
            Err(RuntimeError::RuntimeActive)
        ));
        drop(lease);
        assert!(RecoveryLease::try_acquire().is_ok());
    }

    #[test]
    fn adapter_provenance_requires_luid_index_and_full_current_identity() {
        let expected = identity();
        assert!(adapter_provenance_matches(
            &expected,
            expected.interface_luid,
            expected.interface_index,
            &expected,
        ));

        let mut reused_index = expected.clone();
        reused_index.interface_luid += 1;
        reused_index.interface_guid = "00000000-0000-0000-0000-000000000043".to_owned();
        assert!(!adapter_provenance_matches(
            &expected,
            reused_index.interface_luid,
            expected.interface_index,
            &reused_index,
        ));
        assert!(!adapter_provenance_matches(
            &expected,
            expected.interface_luid,
            expected.interface_index + 1,
            &expected,
        ));
    }
}
