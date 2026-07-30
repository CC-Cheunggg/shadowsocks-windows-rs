use super::RuntimeError;
use crate::tun::routes::{
    InterfaceIdentity, RecoveryPlan, SystemNetworkSnapshot, interface_identities,
    resolve_interface_identity,
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
const RECOVERY_SCHEMA: &str = "dev.shadowsocks-windows-rs.network-recovery";
const LEGACY_RECOVERY_VERSION: u32 = 1;
const PREVIOUS_RECOVERY_VERSION: u32 = 2;
const RECOVERY_VERSION: u32 = 3;
const MAX_RECOVERY_JOURNAL_BYTES: u64 = 32 * 1024 * 1024;
const ADAPTER_ABSENCE_POLL_INTERVAL: Duration = Duration::from_millis(50);
const ADAPTER_ABSENCE_TIMEOUT: Duration = Duration::from_secs(5);
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);
const RECOVERY_MUTEX_NAME: &str =
    "Global\\dev.shadowsocks-windows-rs.app.network-recovery.7f807e7b-8310-4d73-aaca-cf7e83b87095";

pub struct RecoveryLease {
    _platform: lease_platform::Lease,
}

/// A completed, exactly verified recovery whose journal is intentionally
/// retained until the caller durably records its own completion evidence.
///
/// The recovery lease remains held while this value exists. Dropping it
/// without calling [`VerifiedRecovery::clear_journal`] preserves the journal.
pub struct VerifiedRecovery {
    path: PathBuf,
    _lease: RecoveryLease,
}

impl VerifiedRecovery {
    pub fn clear_journal(self) -> Result<(), RuntimeError> {
        clear(&self.path)?;
        if load(&self.path)?.is_some() {
            return Err(RuntimeError::RecoveryRequired);
        }
        Ok(())
    }
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

fn valid_adapter_name(name: &str) -> bool {
    !name.is_empty()
        && name.encode_utf16().count() < 128
        && !name
            .chars()
            .any(|character| character == '\0' || character.is_control())
}

fn valid_canonical_guid(guid: &str) -> bool {
    let bytes = guid.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                *byte == b'-'
            } else {
                byte.is_ascii_digit() || matches!(*byte, b'a'..=b'f')
            }
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryJournal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    schema: Option<String>,
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    phase: Option<RecoveryJournalPhase>,
    pub adapter_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_guid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_identity: Option<InterfaceIdentity>,
    pub original: SystemNetworkSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<RecoveryPlan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RecoveryJournalPhase {
    AdapterCreationIntent,
    AdapterIdentity,
}

impl RecoveryJournal {
    pub fn owned_change_count(&self) -> usize {
        self.recovery
            .as_ref()
            .map_or(0, RecoveryPlan::owned_change_count)
    }

    pub fn is_adapter_creation_intent(&self) -> bool {
        matches!(
            self.kind(),
            Ok(RecoveryJournalKind::AdapterCreationIntent { .. })
        )
    }
}

#[derive(Debug, Clone, Copy)]
enum RecoveryJournalKind<'a> {
    AdapterCreationIntent {
        adapter_guid: &'a str,
    },
    Active {
        adapter_identity: &'a InterfaceIdentity,
        recovery: &'a RecoveryPlan,
    },
}

impl RecoveryJournal {
    fn kind(&self) -> Result<RecoveryJournalKind<'_>, RuntimeError> {
        match (
            self.adapter_guid.as_deref(),
            self.adapter_identity.as_ref(),
            self.recovery.as_ref(),
        ) {
            (Some(adapter_guid), None, None)
                if self.version == RECOVERY_VERSION
                    && self.schema.as_deref() == Some(RECOVERY_SCHEMA)
                    && self.phase == Some(RecoveryJournalPhase::AdapterCreationIntent)
                    && valid_adapter_name(&self.adapter_name)
                    && valid_canonical_guid(adapter_guid) =>
            {
                Ok(RecoveryJournalKind::AdapterCreationIntent { adapter_guid })
            }
            (adapter_guid, Some(adapter_identity), Some(recovery))
                if valid_adapter_name(&self.adapter_name)
                    && self.adapter_name == adapter_identity.alias
                    && adapter_identity == recovery.tun_interface()
                    && recovery
                        .validate_journal_encoding(self.version == LEGACY_RECOVERY_VERSION)
                        .is_ok()
                    && !recovery.has_external_routes()
                    && match self.version {
                        LEGACY_RECOVERY_VERSION | PREVIOUS_RECOVERY_VERSION => {
                            self.schema.is_none() && self.phase.is_none() && adapter_guid.is_none()
                        }
                        RECOVERY_VERSION => adapter_guid.is_some_and(|guid| {
                            self.schema.as_deref() == Some(RECOVERY_SCHEMA)
                                && self.phase == Some(RecoveryJournalPhase::AdapterIdentity)
                                && valid_canonical_guid(guid)
                                && guid == adapter_identity.interface_guid
                        }),
                        _ => false,
                    } =>
            {
                Ok(RecoveryJournalKind::Active {
                    adapter_identity,
                    recovery,
                })
            }
            _ => Err(RuntimeError::RecoveryRequired),
        }
    }
}

pub fn journal_path(config_directory: &Path) -> PathBuf {
    config_directory.join(RECOVERY_FILE_NAME)
}

pub(crate) fn prepare_adapter_intent(
    path: &Path,
    adapter_name: String,
    adapter_guid: String,
    original: SystemNetworkSnapshot,
) -> Result<(), RuntimeError> {
    if !valid_adapter_name(&adapter_name) || !valid_canonical_guid(&adapter_guid) {
        return Err(RuntimeError::RecoveryRequired);
    }
    let parent = path.parent().ok_or(RuntimeError::RecoveryRequired)?;
    fs::create_dir_all(parent)
        .map_err(|error| RuntimeError::subsystem("recovery directory creation", error))?;
    let journal = RecoveryJournal {
        schema: Some(RECOVERY_SCHEMA.to_owned()),
        version: RECOVERY_VERSION,
        phase: Some(RecoveryJournalPhase::AdapterCreationIntent),
        adapter_name,
        adapter_guid: Some(adapter_guid),
        adapter_identity: None,
        original,
        recovery: None,
    };
    write_atomic(path, &journal, AtomicWriteMode::Create)
}

pub(crate) fn record_adapter_identity(
    path: &Path,
    adapter_identity: InterfaceIdentity,
    recovery: RecoveryPlan,
) -> Result<(), RuntimeError> {
    let Some(mut journal) = load(path)? else {
        return Err(RuntimeError::RecoveryRequired);
    };
    if adapter_identity != *recovery.tun_interface()
        || recovery.owned_change_count() != 0
        || recovery.validate_journal_encoding(false).is_err()
        || recovery.has_external_routes()
    {
        return Err(RuntimeError::RecoveryRequired);
    }
    match journal.kind()? {
        RecoveryJournalKind::AdapterCreationIntent { adapter_guid }
            if journal.adapter_name == adapter_identity.alias
                && adapter_guid == adapter_identity.interface_guid => {}
        RecoveryJournalKind::Active {
            adapter_identity: existing_identity,
            recovery: existing_recovery,
            ..
        } if existing_identity == &adapter_identity && existing_recovery == &recovery => {
            return Ok(());
        }
        _ => return Err(RuntimeError::RecoveryRequired),
    }
    journal.phase = Some(RecoveryJournalPhase::AdapterIdentity);
    journal.adapter_identity = Some(adapter_identity);
    journal.recovery = Some(recovery);
    write_atomic(path, &journal, AtomicWriteMode::Replace)
}

pub(crate) fn record_owned(path: &Path, recovery: RecoveryPlan) -> Result<(), RuntimeError> {
    let Some(mut journal) = load(path)? else {
        return Err(RuntimeError::RecoveryRequired);
    };
    let RecoveryJournalKind::Active {
        adapter_identity,
        recovery: previous,
        ..
    } = journal.kind()?
    else {
        return Err(RuntimeError::RecoveryRequired);
    };
    if adapter_identity != recovery.tun_interface()
        || recovery.validate_journal_encoding(false).is_err()
        || recovery.has_external_routes()
        || !recovery.is_valid_successor_of(previous)
    {
        return Err(RuntimeError::RecoveryRequired);
    }
    journal.recovery = Some(recovery);
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
    write_atomic_with(path, journal, mode, commit_atomic, sync_parent)
}

fn write_atomic_with(
    path: &Path,
    journal: &RecoveryJournal,
    mode: AtomicWriteMode,
    commit: impl Fn(&Path, &Path, AtomicWriteMode) -> std::io::Result<()>,
    sync_directory: impl Fn(&Path) -> std::io::Result<()>,
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
    if (bytes.len() as u64).saturating_add(1) > MAX_RECOVERY_JOURNAL_BYTES {
        return Err(RuntimeError::RecoveryRequired);
    }
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        commit(&temporary, path, mode)?;
        sync_directory(parent)
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
    clear_with(path, |candidate| fs::remove_file(candidate), sync_parent)
}

fn clear_with(
    path: &Path,
    remove: impl Fn(&Path) -> std::io::Result<()>,
    sync_directory: impl Fn(&Path) -> std::io::Result<()>,
) -> Result<(), RuntimeError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(RuntimeError::subsystem("recovery journal metadata", error));
        }
    }
    let parent = path.parent().ok_or(RuntimeError::RecoveryRequired)?;
    // Any synchronization failure reported to the caller occurs before the
    // unlink, so a failed clear always leaves the canonical evidence in place.
    sync_directory(parent)
        .map_err(|error| RuntimeError::subsystem("recovery directory sync", error))?;
    match remove(path) {
        Ok(()) => {
            // A post-unlink sync failure cannot be rolled back safely. Treat
            // it as a conservative durability uncertainty: a crash may make
            // the already-restored, idempotent journal reappear.
            let _ = sync_directory(parent);
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
    let journal: RecoveryJournal =
        serde_json::from_slice(&bytes).map_err(|_| RuntimeError::RecoveryRequired)?;
    if !matches!(
        journal.version,
        LEGACY_RECOVERY_VERSION | PREVIOUS_RECOVERY_VERSION | RECOVERY_VERSION
    ) {
        return Err(RuntimeError::RecoveryRequired);
    }
    journal.kind()?;
    Ok(Some(journal))
}

pub fn recover(path: &Path) -> Result<bool, RuntimeError> {
    let Some(recovery) = recover_preserving_journal(path)? else {
        return Ok(false);
    };
    recovery.clear_journal()?;
    Ok(true)
}

/// Performs the existing constrained recovery and exact post-recovery checks,
/// but keeps both the recovery lease and journal until the returned capability
/// explicitly clears it. This lets the watchdog sync its final audit evidence
/// before journal deletion without granting any additional network authority.
pub fn recover_preserving_journal(path: &Path) -> Result<Option<VerifiedRecovery>, RuntimeError> {
    let lease = RecoveryLease::try_acquire()?;
    if !recover_to_journal_clear(&lease, path)? {
        return Ok(None);
    }
    Ok(Some(VerifiedRecovery {
        path: path.to_path_buf(),
        _lease: lease,
    }))
}

pub(crate) fn recover_with_lease(lease: &RecoveryLease, path: &Path) -> Result<bool, RuntimeError> {
    if !recover_to_journal_clear(lease, path)? {
        return Ok(false);
    }
    clear(path)?;
    Ok(true)
}

fn recover_to_journal_clear(_lease: &RecoveryLease, path: &Path) -> Result<bool, RuntimeError> {
    let Some(journal) = load(path)? else {
        return Ok(false);
    };

    match journal.kind()? {
        RecoveryJournalKind::AdapterCreationIntent { adapter_guid } => {
            return recover_adapter_creation_intent(&journal.adapter_name, adapter_guid);
        }
        RecoveryJournalKind::Active {
            adapter_identity,
            recovery,
            ..
        } => recover_active_journal(&journal, adapter_identity, recovery),
    }
}

fn recover_active_journal(
    journal: &RecoveryJournal,
    adapter_identity: &InterfaceIdentity,
    recovery: &RecoveryPlan,
) -> Result<bool, RuntimeError> {
    // Older journal encodings could contain a physical-interface host route.
    // The journal is user-writable and therefore cannot prove ownership of
    // that route. Reject it before adapter inspection or any native mutation.
    if recovery.has_external_routes() {
        return Err(RuntimeError::RecoveryRequired);
    }

    match inspect_adapter_generation(adapter_identity)? {
        AdapterGeneration::Absent => {
            // Windows removes addresses, routes, and interface settings with
            // an absent adapter generation. Since this journal contains only
            // adapter-owned objects, journal clearing is safe and idempotent
            // after the caller records any required completion evidence.
            prove_absent_adapter_recovery(adapter_identity, recovery)?;
            return Ok(true);
        }
        AdapterGeneration::Present => {}
    }

    // The journal is stored in the user's application-data directory and is
    // therefore not an authority for elevated network mutation. Prove that
    // its target is the exact Wintun adapter opened through the bundled API
    // before applying any recorded operation. Keep the handle alive across
    // restoration so the verified adapter cannot disappear and have its
    // index reused between the provenance check and the mutations.
    let adapter = match open_verified_adapter(journal, adapter_identity) {
        Ok(adapter) => adapter,
        Err(error) => {
            // The adapter can disappear after enumeration but before Wintun
            // opens it. Re-prove absence before treating that race as an
            // already-completed recovery.
            return match inspect_adapter_generation(adapter_identity)? {
                AdapterGeneration::Absent => {
                    prove_absent_adapter_recovery(adapter_identity, recovery)?;
                    Ok(true)
                }
                AdapterGeneration::Present => Err(error),
            };
        }
    };
    restore_with_pinned_adapter(adapter, || {
        recovery
            .restore_adapter_owned_only()
            .map_err(|error| RuntimeError::subsystem("network recovery", error))
    })?;

    // An adapter opened after its creating process is gone cannot be deleted
    // independently through this Wintun API. It may already be disappearing,
    // though, and Windows interface enumeration can lag the close/removal
    // request. Wait for a bounded interval before retaining the journal.
    wait_for_adapter_absent(adapter_identity, ADAPTER_ABSENCE_TIMEOUT)?;
    Ok(true)
}

fn restore_with_pinned_adapter<H, T, E>(
    adapter: H,
    restore: impl FnOnce() -> Result<T, E>,
) -> Result<T, E> {
    let result = restore();
    drop(adapter);
    result
}

fn recover_adapter_creation_intent(
    adapter_name: &str,
    adapter_guid: &str,
) -> Result<bool, RuntimeError> {
    if !adapter_creation_intent_is_absent(adapter_name, adapter_guid)? {
        return Err(RuntimeError::RecoveryRequired);
    }

    // Query both independent identities again immediately before clearing.
    // The application-wide recovery lease prevents this runtime from creating
    // the intended adapter concurrently.
    if !adapter_creation_intent_is_absent(adapter_name, adapter_guid)? {
        return Err(RuntimeError::RecoveryRequired);
    }
    Ok(true)
}

fn complete_absent_adapter_intent(path: &Path) -> Result<bool, RuntimeError> {
    clear(path)?;
    Ok(true)
}

fn adapter_creation_intent_is_absent(
    adapter_name: &str,
    adapter_guid: &str,
) -> Result<bool, RuntimeError> {
    let identities = interface_identities().map_err(|_| RuntimeError::RecoveryRequired)?;
    Ok(classify_created_adapter_absence(
        &identities,
        adapter_name,
        adapter_guid,
        None,
        None,
        None,
    ))
}

fn classify_created_adapter_absence(
    identities: &[InterfaceIdentity],
    adapter_name: &str,
    adapter_guid: &str,
    observed_identity: Option<&InterfaceIdentity>,
    observed_luid: Option<u64>,
    observed_index: Option<u32>,
) -> bool {
    !identities.iter().any(|identity| {
        identity.alias == adapter_name
            || identity.interface_guid == adapter_guid
            || observed_luid == Some(identity.interface_luid)
            || observed_index == Some(identity.interface_index)
            || observed_identity.is_some_and(|observed| {
                identity.alias == observed.alias
                    || identity.interface_guid == observed.interface_guid
                    || identity.interface_luid == observed.interface_luid
                    || identity.interface_index == observed.interface_index
            })
    })
}

pub(crate) fn wait_for_adapter_intent_absent(
    adapter_name: &str,
    adapter_guid: &str,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    wait_for_created_adapter_absent(adapter_name, adapter_guid, None, None, None, timeout)
}

pub(crate) fn wait_for_created_adapter_absent(
    adapter_name: &str,
    adapter_guid: &str,
    observed_identity: Option<&InterfaceIdentity>,
    observed_luid: Option<u64>,
    observed_index: Option<u32>,
    timeout: Duration,
) -> Result<(), RuntimeError> {
    if !valid_adapter_name(adapter_name) || !valid_canonical_guid(adapter_guid) {
        return Err(RuntimeError::RecoveryRequired);
    }
    if observed_luid == Some(0) || observed_index == Some(0) {
        return Err(RuntimeError::RecoveryRequired);
    }
    let started = Instant::now();
    loop {
        let identities = interface_identities().map_err(|_| RuntimeError::RecoveryRequired)?;
        if classify_created_adapter_absence(
            &identities,
            adapter_name,
            adapter_guid,
            observed_identity,
            observed_luid,
            observed_index,
        ) {
            return Ok(());
        }
        let elapsed = started.elapsed();
        if elapsed >= timeout {
            return Err(RuntimeError::RecoveryRequired);
        }
        thread::sleep((timeout - elapsed).min(ADAPTER_ABSENCE_POLL_INTERVAL));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdapterGeneration {
    Absent,
    Present,
}

fn inspect_adapter_generation(
    expected: &InterfaceIdentity,
) -> Result<AdapterGeneration, RuntimeError> {
    let identities = interface_identities().map_err(|_| RuntimeError::RecoveryRequired)?;
    classify_adapter_generation(expected, &identities)
}

fn classify_adapter_generation(
    expected: &InterfaceIdentity,
    identities: &[InterfaceIdentity],
) -> Result<AdapterGeneration, RuntimeError> {
    let matching = identities
        .iter()
        .filter(|identity| {
            identity.alias == expected.alias
                || identity.interface_luid == expected.interface_luid
                || identity.interface_guid == expected.interface_guid
                || identity.interface_index == expected.interface_index
        })
        .collect::<Vec<_>>();
    if matching.is_empty() {
        Ok(AdapterGeneration::Absent)
    } else if matching.len() == 1 && matching[0] == expected {
        Ok(AdapterGeneration::Present)
    } else {
        Err(RuntimeError::RecoveryRequired)
    }
}

fn complete_absent_adapter_recovery(
    path: &Path,
    expected: &InterfaceIdentity,
    recovery: &RecoveryPlan,
) -> Result<bool, RuntimeError> {
    prove_absent_adapter_recovery(expected, recovery)?;
    clear(path)?;
    Ok(true)
}

fn prove_absent_adapter_recovery(
    expected: &InterfaceIdentity,
    recovery: &RecoveryPlan,
) -> Result<(), RuntimeError> {
    if recovery.has_external_routes() {
        return Err(RuntimeError::RecoveryRequired);
    }
    // Repeat the complete four-key proof immediately before clearing. The
    // recovery lease prevents this runtime from creating a new generation,
    // while any external reuse or ambiguity keeps the evidence intact.
    if inspect_adapter_generation(expected)? != AdapterGeneration::Absent {
        return Err(RuntimeError::RecoveryRequired);
    }
    Ok(())
}

fn clear_proven_absent_adapter_recovery(
    path: &Path,
    recovery: &RecoveryPlan,
) -> Result<bool, RuntimeError> {
    if recovery.has_external_routes() {
        return Err(RuntimeError::RecoveryRequired);
    }
    clear(path)?;
    Ok(true)
}

fn open_verified_adapter(
    journal: &RecoveryJournal,
    expected: &InterfaceIdentity,
) -> Result<WintunAdapter, RuntimeError> {
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
    if !adapter_provenance_matches(expected, opened_luid, opened_index, &current) {
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
        match inspect_adapter_generation(identity)? {
            AdapterGeneration::Absent => return Ok(()),
            AdapterGeneration::Present => {}
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
    #[cfg(not(windows))]
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(not(windows))]
    static RECOVERY_LEASE_TEST_LOCK: Mutex<()> = Mutex::new(());

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

    fn adapter_guid() -> String {
        identity().interface_guid
    }

    fn prepare_active(path: &Path, recovery: RecoveryPlan) {
        prepare_adapter_intent(path, "Shadowsocks".to_owned(), adapter_guid(), snapshot()).unwrap();
        record_adapter_identity(path, identity(), recovery).unwrap();
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

    fn external_route_plan() -> RecoveryPlan {
        RecoveryPlan::from_parts_for_runtime_test(
            identity(),
            Vec::new(),
            vec![OwnedRoute {
                destination_prefix: "203.0.113.10/32".to_owned(),
                interface: InterfaceIdentity {
                    interface_index: 7,
                    interface_luid: 7007,
                    interface_guid: "00000000-0000-0000-0000-000000000007".to_owned(),
                    alias: "Ethernet".to_owned(),
                },
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                metric: 25,
            }],
        )
    }

    fn current_active_journal(recovery: RecoveryPlan) -> RecoveryJournal {
        RecoveryJournal {
            schema: Some(RECOVERY_SCHEMA.to_owned()),
            version: RECOVERY_VERSION,
            phase: Some(RecoveryJournalPhase::AdapterIdentity),
            adapter_name: "Shadowsocks".to_owned(),
            adapter_guid: Some(adapter_guid()),
            adapter_identity: Some(identity()),
            original: snapshot(),
            recovery: Some(recovery),
        }
    }

    fn previous_active_journal(recovery: RecoveryPlan) -> RecoveryJournal {
        RecoveryJournal {
            schema: None,
            version: PREVIOUS_RECOVERY_VERSION,
            phase: None,
            adapter_name: "Shadowsocks".to_owned(),
            adapter_guid: None,
            adapter_identity: Some(identity()),
            original: snapshot(),
            recovery: Some(recovery),
        }
    }

    fn write_raw(path: &Path, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
    }

    #[test]
    fn journal_round_trip_records_explicit_schema_phase_and_stable_identity() {
        let path = unique_path();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();
        let intent = load(&path).unwrap().unwrap();
        assert!(intent.is_adapter_creation_intent());
        assert_eq!(intent.schema.as_deref(), Some(RECOVERY_SCHEMA));
        assert_eq!(
            intent.phase,
            Some(RecoveryJournalPhase::AdapterCreationIntent)
        );
        assert_eq!(
            intent.adapter_guid.as_deref(),
            Some(adapter_guid().as_str())
        );
        assert_eq!(intent.adapter_identity, None);
        assert_eq!(intent.owned_change_count(), 0);

        record_adapter_identity(&path, identity(), RecoveryPlan::empty(identity()).unwrap())
            .unwrap();
        let loaded = load(&path).unwrap().unwrap();
        assert_eq!(loaded.version, RECOVERY_VERSION);
        assert_eq!(loaded.schema.as_deref(), Some(RECOVERY_SCHEMA));
        assert_eq!(loaded.phase, Some(RecoveryJournalPhase::AdapterIdentity));
        assert_eq!(loaded.adapter_guid, Some(adapter_guid()));
        assert_eq!(loaded.adapter_identity, Some(identity()));
        assert_eq!(loaded.owned_change_count(), 0);
        clear(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn journal_create_is_non_overwriting_and_atomic_update_preserves_identity() {
        let path = unique_path();
        let empty = RecoveryPlan::empty(identity()).unwrap();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();
        assert_eq!(
            prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot(),),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(load(&path).unwrap().unwrap().owned_change_count(), 0);
        record_adapter_identity(&path, identity(), empty).unwrap();
        record_adapter_identity(&path, identity(), RecoveryPlan::empty(identity()).unwrap())
            .unwrap();
        let mut other_identity = identity();
        other_identity.interface_luid += 1;
        assert_eq!(
            record_owned(&path, RecoveryPlan::empty(other_identity).unwrap()),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(load(&path).unwrap().unwrap().owned_change_count(), 0);
        assert_eq!(
            record_owned(&path, recorded_plan()),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(load(&path).unwrap().unwrap().owned_change_count(), 0);
        clear(&path).unwrap();
        clear(&path).unwrap();
    }

    #[test]
    fn current_journals_reject_external_interface_routes_before_creation_or_update() {
        let path = unique_path();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();
        assert_eq!(
            record_adapter_identity(&path, identity(), external_route_plan(),),
            Err(RuntimeError::RecoveryRequired)
        );
        assert!(load(&path).unwrap().unwrap().is_adapter_creation_intent());
        clear(&path).unwrap();

        prepare_active(&path, RecoveryPlan::empty(identity()).unwrap());
        assert_eq!(
            record_owned(&path, external_route_plan()),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(load(&path).unwrap().unwrap().owned_change_count(), 0);
        clear(&path).unwrap();
    }

    #[test]
    fn tampered_current_journal_with_external_route_is_rejected_on_load() {
        let path = unique_path();
        let journal = current_active_journal(external_route_plan());
        write_atomic(&path, &journal, AtomicWriteMode::Create).unwrap();
        assert!(matches!(load(&path), Err(RuntimeError::RecoveryRequired)));
        clear(&path).unwrap();
    }

    #[cfg(not(windows))]
    #[test]
    fn legacy_external_route_fails_before_any_platform_recovery_call() {
        let _serial = RECOVERY_LEASE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for version in [LEGACY_RECOVERY_VERSION, PREVIOUS_RECOVERY_VERSION] {
            let path = unique_path();
            let journal = previous_active_journal(external_route_plan());
            let mut value = serde_json::to_value(journal).unwrap();
            value["version"] = serde_json::Value::from(version);
            if version == LEGACY_RECOVERY_VERSION {
                value["recovery"]["interface_address_states"] =
                    serde_json::Value::Array(Vec::new());
                value["recovery"]["route_states"] = serde_json::Value::Array(Vec::new());
                value["recovery"]["interface_setting_states"] =
                    serde_json::Value::Array(Vec::new());
            }
            write_raw(&path, &serde_json::to_vec_pretty(&value).unwrap());
            assert!(matches!(load(&path), Err(RuntimeError::RecoveryRequired)));
            assert_eq!(recover(&path), Err(RuntimeError::RecoveryRequired));
            assert!(path.exists());
            clear(&path).unwrap();
        }
    }

    #[test]
    fn asynchronous_adapter_disappearance_makes_repeated_recovery_idempotent() {
        let expected = identity();
        assert_eq!(
            classify_adapter_generation(&expected, std::slice::from_ref(&expected)),
            Ok(AdapterGeneration::Present)
        );
        assert_eq!(
            classify_adapter_generation(&expected, &[]),
            Ok(AdapterGeneration::Absent)
        );

        let path = unique_path();
        let journal = current_active_journal(recorded_plan());
        write_atomic(&path, &journal, AtomicWriteMode::Create).unwrap();
        let recovery = journal.recovery.as_ref().unwrap();
        assert_eq!(
            clear_proven_absent_adapter_recovery(&path, recovery),
            Ok(true)
        );
        assert!(!path.exists());
        assert_eq!(
            clear_proven_absent_adapter_recovery(&path, recovery),
            Ok(true)
        );
        assert!(!path.exists());
    }

    #[test]
    fn absent_adapter_completion_preserves_external_route_evidence() {
        let path = unique_path();
        let journal = previous_active_journal(external_route_plan());
        write_atomic(&path, &journal, AtomicWriteMode::Create).unwrap();
        assert_eq!(
            clear_proven_absent_adapter_recovery(&path, journal.recovery.as_ref().unwrap(),),
            Err(RuntimeError::RecoveryRequired)
        );
        assert!(path.exists());
        clear(&path).unwrap();
    }

    #[test]
    fn adapter_identity_upgrade_requires_the_durable_alias_and_guid() {
        let path = unique_path();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();

        let mut wrong_guid = identity();
        wrong_guid.interface_guid = "00000000-0000-0000-0000-000000000043".to_owned();
        assert_eq!(
            record_adapter_identity(
                &path,
                wrong_guid.clone(),
                RecoveryPlan::empty(wrong_guid).unwrap(),
            ),
            Err(RuntimeError::RecoveryRequired)
        );
        let still_intent = load(&path).unwrap().unwrap();
        assert!(still_intent.is_adapter_creation_intent());
        assert_eq!(still_intent.adapter_identity, None);

        let mut wrong_alias = identity();
        wrong_alias.alias = "Other".to_owned();
        assert_eq!(
            record_adapter_identity(
                &path,
                wrong_alias.clone(),
                RecoveryPlan::empty(wrong_alias).unwrap(),
            ),
            Err(RuntimeError::RecoveryRequired)
        );
        assert!(load(&path).unwrap().unwrap().is_adapter_creation_intent());
        clear(&path).unwrap();
    }

    #[test]
    fn intent_only_absence_requires_both_alias_and_guid_to_be_missing() {
        let current = identity();
        assert!(classify_created_adapter_absence(
            &[],
            &current.alias,
            &current.interface_guid,
            None,
            None,
            None,
        ));
        assert!(!classify_created_adapter_absence(
            std::slice::from_ref(&current),
            &current.alias,
            "00000000-0000-0000-0000-000000000099",
            None,
            None,
            None,
        ));
        assert!(!classify_created_adapter_absence(
            std::slice::from_ref(&current),
            "Other",
            &current.interface_guid,
            None,
            None,
            None,
        ));

        let mut alias_reused = current.clone();
        alias_reused.interface_guid = "00000000-0000-0000-0000-000000000099".to_owned();
        let mut guid_reused = current.clone();
        guid_reused.alias = "Other".to_owned();
        assert!(!classify_created_adapter_absence(
            &[alias_reused, guid_reused],
            &current.alias,
            &current.interface_guid,
            None,
            None,
            None,
        ));
    }

    #[test]
    fn intent_only_completion_is_idempotent_after_proven_absence() {
        let path = unique_path();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();
        assert_eq!(complete_absent_adapter_intent(&path), Ok(true));
        assert!(!path.exists());
        assert_eq!(complete_absent_adapter_intent(&path), Ok(true));
    }

    #[test]
    fn adapter_creation_failure_and_pre_create_crash_preserve_durable_intent() {
        let path = unique_path();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();

        // A crash before WintunCreateAdapter or an immediate native creation
        // failure has the same durable state: the exact alias/GUID intent is
        // still the only authority on disk.
        let simulated_create = Err::<(), _>(RuntimeError::subsystem(
            "Wintun adapter creation",
            "injected failure",
        ));
        assert!(simulated_create.is_err());
        let journal = load(&path).unwrap().unwrap();
        assert!(journal.is_adapter_creation_intent());
        assert_eq!(journal.adapter_guid, Some(adapter_guid()));
        clear(&path).unwrap();
    }

    #[test]
    fn created_adapter_or_observed_mismatch_blocks_intent_clear_until_exact_absence() {
        let intended = identity();
        assert!(!classify_created_adapter_absence(
            std::slice::from_ref(&intended),
            &intended.alias,
            &intended.interface_guid,
            None,
            None,
            None,
        ));

        let actual = InterfaceIdentity {
            interface_index: 77,
            interface_luid: 7_777,
            interface_guid: "00000000-0000-0000-0000-000000000077".to_owned(),
            alias: "Unexpected Wintun".to_owned(),
        };
        assert!(!classify_created_adapter_absence(
            std::slice::from_ref(&actual),
            &intended.alias,
            &intended.interface_guid,
            Some(&actual),
            Some(actual.interface_luid),
            Some(actual.interface_index),
        ));
        assert!(!classify_created_adapter_absence(
            std::slice::from_ref(&actual),
            &intended.alias,
            &intended.interface_guid,
            None,
            Some(actual.interface_luid),
            Some(actual.interface_index),
        ));
        assert!(classify_created_adapter_absence(
            &[],
            &intended.alias,
            &intended.interface_guid,
            Some(&actual),
            Some(actual.interface_luid),
            Some(actual.interface_index),
        ));
    }

    #[test]
    fn failed_atomic_create_or_identity_upgrade_never_exposes_a_partial_journal() {
        let create_path = unique_path();
        let intent = RecoveryJournal {
            schema: Some(RECOVERY_SCHEMA.to_owned()),
            version: RECOVERY_VERSION,
            phase: Some(RecoveryJournalPhase::AdapterCreationIntent),
            adapter_name: "Shadowsocks".to_owned(),
            adapter_guid: Some(adapter_guid()),
            adapter_identity: None,
            original: snapshot(),
            recovery: None,
        };
        let injected_commit_failure = |_: &Path, _: &Path, _: AtomicWriteMode| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "injected commit failure",
            ))
        };
        assert!(
            write_atomic_with(
                &create_path,
                &intent,
                AtomicWriteMode::Create,
                injected_commit_failure,
                |_| Ok(()),
            )
            .is_err()
        );
        assert!(!create_path.exists());

        let upgrade_path = unique_path();
        prepare_adapter_intent(
            &upgrade_path,
            "Shadowsocks".to_owned(),
            adapter_guid(),
            snapshot(),
        )
        .unwrap();
        let promoted = current_active_journal(RecoveryPlan::empty(identity()).unwrap());
        assert!(
            write_atomic_with(
                &upgrade_path,
                &promoted,
                AtomicWriteMode::Replace,
                injected_commit_failure,
                |_| Ok(()),
            )
            .is_err()
        );
        let still_intent = load(&upgrade_path).unwrap().unwrap();
        assert!(still_intent.is_adapter_creation_intent());
        assert_eq!(still_intent.adapter_identity, None);
        clear(&upgrade_path).unwrap();

        let post_commit_sync_path = unique_path();
        prepare_adapter_intent(
            &post_commit_sync_path,
            "Shadowsocks".to_owned(),
            adapter_guid(),
            snapshot(),
        )
        .unwrap();
        assert!(
            write_atomic_with(
                &post_commit_sync_path,
                &promoted,
                AtomicWriteMode::Replace,
                commit_atomic,
                |_| {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "injected post-commit sync failure",
                    ))
                },
            )
            .is_err()
        );
        let fully_promoted = load(&post_commit_sync_path).unwrap().unwrap();
        assert_eq!(
            fully_promoted.phase,
            Some(RecoveryJournalPhase::AdapterIdentity)
        );
        assert_eq!(fully_promoted.adapter_identity, Some(identity()));
        clear(&post_commit_sync_path).unwrap();
    }

    #[test]
    fn clear_failure_always_leaves_loadable_evidence() {
        let path = unique_path();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();
        let removal_failure = clear_with(
            &path,
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "injected removal failure",
                ))
            },
            |_| Ok(()),
        );
        assert!(removal_failure.is_err());
        assert!(load(&path).unwrap().unwrap().is_adapter_creation_intent());

        let sync_failure = clear_with(
            &path,
            |_| panic!("remove must not run after a reported pre-unlink sync failure"),
            |_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "injected sync failure",
                ))
            },
        );
        assert!(sync_failure.is_err());
        assert!(load(&path).unwrap().unwrap().is_adapter_creation_intent());
        clear(&path).unwrap();
    }

    #[test]
    fn load_rejects_incomplete_oversized_illegal_version_phase_and_state_arrays() {
        let incomplete_path = unique_path();
        write_raw(&incomplete_path, br#"{"schema":"incomplete""#);
        assert_eq!(load(&incomplete_path), Err(RuntimeError::RecoveryRequired));
        clear(&incomplete_path).unwrap();

        let oversized_path = unique_path();
        let oversized = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&oversized_path)
            .unwrap();
        oversized.set_len(MAX_RECOVERY_JOURNAL_BYTES + 1).unwrap();
        oversized.sync_all().unwrap();
        assert_eq!(load(&oversized_path), Err(RuntimeError::RecoveryRequired));
        clear(&oversized_path).unwrap();

        let illegal_version_path = unique_path();
        let mut illegal_version = current_active_journal(RecoveryPlan::empty(identity()).unwrap());
        illegal_version.version = RECOVERY_VERSION + 1;
        write_atomic(
            &illegal_version_path,
            &illegal_version,
            AtomicWriteMode::Create,
        )
        .unwrap();
        assert_eq!(
            load(&illegal_version_path),
            Err(RuntimeError::RecoveryRequired)
        );
        clear(&illegal_version_path).unwrap();

        let illegal_phase_path = unique_path();
        let mut illegal_phase = current_active_journal(RecoveryPlan::empty(identity()).unwrap());
        illegal_phase.phase = Some(RecoveryJournalPhase::AdapterCreationIntent);
        write_atomic(&illegal_phase_path, &illegal_phase, AtomicWriteMode::Create).unwrap();
        assert_eq!(
            load(&illegal_phase_path),
            Err(RuntimeError::RecoveryRequired)
        );
        clear(&illegal_phase_path).unwrap();

        let inconsistent_state_path = unique_path();
        let journal = current_active_journal(recorded_plan());
        let mut value = serde_json::to_value(journal).unwrap();
        value["recovery"]["route_states"] = serde_json::Value::Array(Vec::new());
        write_raw(
            &inconsistent_state_path,
            &serde_json::to_vec_pretty(&value).unwrap(),
        );
        assert_eq!(
            load(&inconsistent_state_path),
            Err(RuntimeError::RecoveryRequired)
        );
        clear(&inconsistent_state_path).unwrap();
    }

    #[test]
    fn oversized_new_journal_is_rejected_before_commit() {
        let path = unique_path();
        let mut journal = current_active_journal(RecoveryPlan::empty(identity()).unwrap());
        journal.original.adapters_json = "x".repeat(MAX_RECOVERY_JOURNAL_BYTES as usize);
        assert_eq!(
            write_atomic(&path, &journal, AtomicWriteMode::Create),
            Err(RuntimeError::RecoveryRequired)
        );
        assert!(!path.exists());
    }

    #[test]
    fn intent_rejects_noncanonical_or_unsafe_identity_text() {
        let path = unique_path();
        assert_eq!(
            prepare_adapter_intent(
                &path,
                "Shadowsocks".to_owned(),
                "ABCDEF00-0000-0000-0000-000000000042".to_owned(),
                snapshot(),
            ),
            Err(RuntimeError::RecoveryRequired)
        );
        assert_eq!(
            prepare_adapter_intent(&path, "bad\0alias".to_owned(), adapter_guid(), snapshot(),),
            Err(RuntimeError::RecoveryRequired)
        );
        assert!(!path.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn recovery_lease_rejects_a_second_process_equivalent_holder() {
        let _serial = RECOVERY_LEASE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let lease = RecoveryLease::try_acquire().unwrap();
        assert!(matches!(
            RecoveryLease::try_acquire(),
            Err(RuntimeError::RuntimeActive)
        ));
        drop(lease);
        assert!(RecoveryLease::try_acquire().is_ok());
    }

    #[cfg(not(windows))]
    #[test]
    fn verified_recovery_retains_journal_until_explicit_clear() {
        let _serial = RECOVERY_LEASE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = unique_path();
        prepare_adapter_intent(&path, "Shadowsocks".to_owned(), adapter_guid(), snapshot())
            .unwrap();

        let verified = VerifiedRecovery {
            path: path.clone(),
            _lease: RecoveryLease::try_acquire().unwrap(),
        };
        assert!(load(&path).unwrap().is_some());
        drop(verified);
        assert!(load(&path).unwrap().is_some());

        let verified = VerifiedRecovery {
            path: path.clone(),
            _lease: RecoveryLease::try_acquire().unwrap(),
        };
        verified.clear_journal().unwrap();
        assert!(load(&path).unwrap().is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn ordinary_recover_still_reports_an_absent_journal_without_mutation() {
        let _serial = RECOVERY_LEASE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let path = unique_path();
        assert_eq!(recover(&path), Ok(false));
        assert!(!path.exists());
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

    #[test]
    fn verified_adapter_handle_stays_alive_for_the_entire_owned_restoration() {
        use std::cell::Cell;
        use std::rc::Rc;

        struct DropProbe(Rc<Cell<bool>>);
        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }

        let dropped = Rc::new(Cell::new(false));
        let result = restore_with_pinned_adapter(DropProbe(Rc::clone(&dropped)), || {
            assert!(!dropped.get());
            Ok::<_, RuntimeError>(42)
        });
        assert_eq!(result, Ok(42));
        assert!(dropped.get());
    }

    #[test]
    fn adapter_generation_requires_all_four_identity_fields_on_all_lookups() {
        let expected = identity();
        assert_eq!(
            classify_adapter_generation(&expected, &[]),
            Ok(AdapterGeneration::Absent)
        );
        assert_eq!(
            classify_adapter_generation(&expected, std::slice::from_ref(&expected)),
            Ok(AdapterGeneration::Present)
        );

        let mut conflicts = Vec::new();
        let mut alias_reused = expected.clone();
        alias_reused.interface_index += 10;
        alias_reused.interface_luid += 10;
        alias_reused.interface_guid = "00000000-0000-0000-0000-000000000052".to_owned();
        conflicts.push(alias_reused);
        let mut luid_reused = expected.clone();
        luid_reused.interface_index += 20;
        luid_reused.interface_guid = "00000000-0000-0000-0000-000000000062".to_owned();
        luid_reused.alias = "Other LUID".to_owned();
        conflicts.push(luid_reused);
        let mut guid_reused = expected.clone();
        guid_reused.interface_index += 30;
        guid_reused.interface_luid += 30;
        guid_reused.alias = "Other GUID".to_owned();
        conflicts.push(guid_reused);
        let mut index_reused = expected.clone();
        index_reused.interface_luid += 40;
        index_reused.interface_guid = "00000000-0000-0000-0000-000000000082".to_owned();
        index_reused.alias = "Other index".to_owned();
        conflicts.push(index_reused);

        for conflict in conflicts {
            assert_eq!(
                classify_adapter_generation(&expected, &[conflict]),
                Err(RuntimeError::RecoveryRequired)
            );
        }
        assert_eq!(
            classify_adapter_generation(&expected, &[expected.clone(), expected.clone()]),
            Err(RuntimeError::RecoveryRequired)
        );
    }
}
