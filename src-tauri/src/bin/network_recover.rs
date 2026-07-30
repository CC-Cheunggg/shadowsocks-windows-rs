//! Standalone recovery helper for an interrupted Wintun runtime.
//!
//! Caller-controlled recovery, DLL, manifest, and audit paths are never
//! accepted. Mutating modes use only the current executable's fixed directory
//! and the current interactive user's fixed application configuration.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use shadowsocks_windows_rs_lib::runtime::{RuntimeError, recovery};
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const APPLICATION_IDENTIFIER: &str = "dev.shadowsocks-windows-rs.app";
const RECOVERY_HELPER_NAME: &str = "network_recover.exe";
const WINTUN_DLL_NAME: &str = "wintun.dll";
const HASH_MANIFEST_NAME: &str = "SHA256SUMS";
const WATCHDOG_CONTEXT_NAME: &str = "WATCHDOG-CONTEXT.json";
const WATCHDOG_CONTEXT_SCHEMA: &str = "dev.shadowsocks-windows-rs.watchdog-context";
const WATCHDOG_CONTEXT_VERSION: u32 = 1;
const WATCHDOG_AUDIT_DIRECTORY: &str = "network-recovery-watchdog-audit";
const WATCHDOG_LOG_PREFIX: &str = "watchdog";
const WATCHDOG_AUDIT_SCHEMA: &str = "dev.shadowsocks-windows-rs.recovery-watchdog-audit";
const WATCHDOG_AUDIT_VERSION: u32 = 1;
const EXPECTED_WINTUN_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";
const MAX_HASH_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_WATCHDOG_CONTEXT_BYTES: u64 = 4096;
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const WATCHDOG_RETRY_INTERVAL: Duration = Duration::from_secs(2);
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Status,
    Apply,
    Watchdog,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UserContext {
    roaming_app_data: PathBuf,
    config_directory: PathBuf,
    sid_fingerprint: String,
}

#[derive(Debug)]
struct RawUserContext {
    roaming_app_data: PathBuf,
    sid_bytes: Vec<u8>,
    service_account: bool,
    appdata_matches_known_folder: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextFailure {
    #[cfg(not(windows))]
    Unsupported,
    IdentityUnavailable,
    ServiceAccount,
    AppDataUnavailable,
    AppDataMismatch,
}

impl ContextFailure {
    fn code(self) -> &'static str {
        match self {
            #[cfg(not(windows))]
            Self::Unsupported => "unsupported_platform",
            Self::IdentityUnavailable => "identity_unavailable",
            Self::ServiceAccount => "service_account_rejected",
            Self::AppDataUnavailable => "appdata_unavailable",
            Self::AppDataMismatch => "appdata_context_mismatch",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedAssets {
    directory: PathBuf,
    helper_hash: String,
    wintun_hash: String,
    context_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssetFailure {
    ExecutableName,
    DirectoryLookup,
    MissingAsset,
    UnsafeAsset,
    ManifestTooLarge,
    ManifestRead,
    ManifestEncoding,
    ManifestEntry,
    ManifestDuplicate,
    ManifestMissingHelper,
    ManifestMissingWintun,
    HelperRead,
    WintunRead,
    HelperHash,
    WintunManifestHash,
    WintunApprovedHash,
    ContextBindingRead,
    ContextBindingInvalid,
    ContextBindingMismatch,
}

impl AssetFailure {
    fn failure_class(self) -> FailureClass {
        match self {
            Self::ContextBindingRead
            | Self::ContextBindingInvalid
            | Self::ContextBindingMismatch => FailureClass::UserContext,
            _ => FailureClass::AssetVerification,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FailureClass {
    UserContext,
    AssetVerification,
    RecoveryRequired,
    RecoveryError,
    JournalClear,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecoveryAttempt {
    RecoveryVerified,
    NoJournal,
    RuntimeActive,
    Terminal(FailureClass),
}

trait RecoveryRunner {
    fn attempt(&mut self) -> RecoveryAttempt;
    fn clear_verified_journal(&mut self) -> Result<(), FailureClass>;
}

trait AssetVerifier {
    fn verify(&mut self) -> Result<StagedAssets, AssetFailure>;
}

struct FixedAssetVerifier<'a> {
    executable: &'a Path,
    expected_sid_fingerprint: &'a str,
}

impl AssetVerifier for FixedAssetVerifier<'_> {
    fn verify(&mut self) -> Result<StagedAssets, AssetFailure> {
        verify_watchdog_assets(self.executable, self.expected_sid_fingerprint)
    }
}

trait PendingJournalClear {
    fn clear(self: Box<Self>) -> Result<(), FailureClass>;
}

impl PendingJournalClear for recovery::VerifiedRecovery {
    fn clear(self: Box<Self>) -> Result<(), FailureClass> {
        (*self)
            .clear_journal()
            .map_err(|_| FailureClass::JournalClear)
    }
}

enum BackendAttempt {
    RecoveryVerified(Box<dyn PendingJournalClear>),
    NoJournal,
    RuntimeActive,
    Terminal(FailureClass),
}

trait RecoveryBackend {
    fn attempt(&mut self) -> BackendAttempt;
}

struct ConstrainedRecoveryBackend<'a> {
    journal_path: &'a Path,
}

impl RecoveryBackend for ConstrainedRecoveryBackend<'_> {
    fn attempt(&mut self) -> BackendAttempt {
        match recovery::recover_preserving_journal(self.journal_path) {
            Ok(Some(verified)) => BackendAttempt::RecoveryVerified(Box::new(verified)),
            Ok(None) => BackendAttempt::NoJournal,
            Err(RuntimeError::RuntimeActive) => BackendAttempt::RuntimeActive,
            Err(RuntimeError::RecoveryRequired) => {
                BackendAttempt::Terminal(FailureClass::RecoveryRequired)
            }
            Err(_) => BackendAttempt::Terminal(FailureClass::RecoveryError),
        }
    }
}

struct GuardedRecoveryRunner<'a, A, B> {
    asset_verifier: A,
    recovery_backend: B,
    initial_assets: &'a StagedAssets,
    verified: Option<Box<dyn PendingJournalClear>>,
}

impl<A, B> RecoveryRunner for GuardedRecoveryRunner<'_, A, B>
where
    A: AssetVerifier,
    B: RecoveryBackend,
{
    fn attempt(&mut self) -> RecoveryAttempt {
        if self.verified.is_some() {
            return RecoveryAttempt::Terminal(FailureClass::RecoveryError);
        }
        let assets = match self.asset_verifier.verify() {
            Ok(assets) => assets,
            Err(error) => return RecoveryAttempt::Terminal(error.failure_class()),
        };
        if assets != *self.initial_assets {
            return RecoveryAttempt::Terminal(FailureClass::AssetVerification);
        }

        match self.recovery_backend.attempt() {
            BackendAttempt::RecoveryVerified(verified) => {
                self.verified = Some(verified);
                RecoveryAttempt::RecoveryVerified
            }
            BackendAttempt::NoJournal => RecoveryAttempt::NoJournal,
            BackendAttempt::RuntimeActive => RecoveryAttempt::RuntimeActive,
            BackendAttempt::Terminal(failure) => RecoveryAttempt::Terminal(failure),
        }
    }

    fn clear_verified_journal(&mut self) -> Result<(), FailureClass> {
        let verified = self.verified.take().ok_or(FailureClass::JournalClear)?;
        verified.clear()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WatchdogPolicy {
    deadline: Duration,
    retry_interval: Duration,
    max_attempts: u64,
}

impl WatchdogPolicy {
    fn new(deadline: Duration, retry_interval: Duration) -> Option<Self> {
        if deadline.is_zero() || retry_interval.is_zero() {
            return None;
        }
        let deadline_nanos = deadline.as_nanos();
        let interval_nanos = retry_interval.as_nanos();
        let intervals =
            deadline_nanos.saturating_add(interval_nanos.saturating_sub(1)) / interval_nanos;
        let max_attempts = u64::try_from(intervals)
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        Some(Self {
            deadline,
            retry_interval,
            max_attempts,
        })
    }

    fn fixed() -> Self {
        Self::new(WATCHDOG_TIMEOUT, WATCHDOG_RETRY_INTERVAL)
            .expect("the fixed watchdog policy is valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ClockReading {
    elapsed: Duration,
    utc_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuditRecordType {
    Precondition,
    Attempt,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum AuditState {
    ContextVerified,
    AssetsVerified,
    AttemptStarted,
    RuntimeActive,
    RecoveryVerified,
    JournalClearAuthorized,
    NoJournal,
    Timeout,
    TerminalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum FinalStatus {
    RecoveryVerified,
    NoJournal,
    Timeout,
    TerminalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ExitClass {
    SuccessAfterJournalClear,
    Success,
    Timeout,
    TerminalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuditEvent {
    record_type: AuditRecordType,
    attempt_number: Option<u64>,
    state: AuditState,
    will_retry: Option<bool>,
    final_status: Option<FinalStatus>,
    exit_class: Option<ExitClass>,
    failure_class: Option<FailureClass>,
}

impl AuditEvent {
    fn precondition(state: AuditState) -> Self {
        Self {
            record_type: AuditRecordType::Precondition,
            attempt_number: None,
            state,
            will_retry: None,
            final_status: None,
            exit_class: None,
            failure_class: None,
        }
    }

    fn attempt(attempt_number: u64, state: AuditState, will_retry: Option<bool>) -> Self {
        Self {
            record_type: AuditRecordType::Attempt,
            attempt_number: Some(attempt_number),
            state,
            will_retry,
            final_status: None,
            exit_class: None,
            failure_class: None,
        }
    }

    fn attempt_failure(attempt_number: u64, failure_class: FailureClass) -> Self {
        Self {
            record_type: AuditRecordType::Attempt,
            attempt_number: Some(attempt_number),
            state: AuditState::TerminalFailure,
            will_retry: Some(false),
            final_status: None,
            exit_class: None,
            failure_class: Some(failure_class),
        }
    }

    fn final_record(
        state: AuditState,
        final_status: FinalStatus,
        exit_class: ExitClass,
        failure_class: Option<FailureClass>,
    ) -> Self {
        Self {
            record_type: AuditRecordType::Final,
            attempt_number: None,
            state,
            will_retry: Some(false),
            final_status: Some(final_status),
            exit_class: Some(exit_class),
            failure_class,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuditFailure;

trait AuditSink {
    fn record(&mut self, event: AuditEvent, reading: ClockReading) -> Result<(), AuditFailure>;
}

#[derive(Serialize)]
struct AuditRecord<'a> {
    schema: &'static str,
    version: u32,
    watchdog_run_id: &'a str,
    record_type: AuditRecordType,
    attempt_number: Option<u64>,
    utc_unix_ms: u64,
    elapsed_ms: u64,
    deadline_ms: u64,
    state: AuditState,
    will_retry: Option<bool>,
    final_status: Option<FinalStatus>,
    exit_class: Option<ExitClass>,
    failure_class: Option<FailureClass>,
    user_sid_fingerprint: &'a str,
    helper_sha256: Option<&'a str>,
    wintun_sha256: Option<&'a str>,
}

struct AuditLog {
    file: File,
    path: PathBuf,
    run_id: String,
    sid_fingerprint: String,
    deadline_ms: u64,
    helper_hash: Option<String>,
    wintun_hash: Option<String>,
}

impl AuditLog {
    fn create(context: &UserContext, policy: WatchdogPolicy) -> Result<Self, AuditFailure> {
        let directory = prepare_audit_directory(context)?;
        for _ in 0..32 {
            let run_id = new_run_id();
            let path = directory.join(format!("{WATCHDOG_LOG_PREFIX}-{run_id}.jsonl"));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => {
                    return Ok(Self {
                        file,
                        path,
                        run_id,
                        sid_fingerprint: context.sid_fingerprint.clone(),
                        deadline_ms: duration_millis(policy.deadline),
                        helper_hash: None,
                        wintun_hash: None,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(AuditFailure),
            }
        }
        Err(AuditFailure)
    }

    fn set_assets(&mut self, assets: &StagedAssets) {
        self.helper_hash = Some(assets.helper_hash.clone());
        self.wintun_hash = Some(assets.wintun_hash.clone());
    }
}

impl AuditSink for AuditLog {
    fn record(&mut self, event: AuditEvent, reading: ClockReading) -> Result<(), AuditFailure> {
        let record = AuditRecord {
            schema: WATCHDOG_AUDIT_SCHEMA,
            version: WATCHDOG_AUDIT_VERSION,
            watchdog_run_id: &self.run_id,
            record_type: event.record_type,
            attempt_number: event.attempt_number,
            utc_unix_ms: reading.utc_unix_ms,
            elapsed_ms: duration_millis(reading.elapsed),
            deadline_ms: self.deadline_ms,
            state: event.state,
            will_retry: event.will_retry,
            final_status: event.final_status,
            exit_class: event.exit_class,
            failure_class: event.failure_class,
            user_sid_fingerprint: &self.sid_fingerprint,
            helper_sha256: self.helper_hash.as_deref(),
            wintun_sha256: self.wintun_hash.as_deref(),
        };
        serde_json::to_writer(&mut self.file, &record).map_err(|_| AuditFailure)?;
        self.file.write_all(b"\n").map_err(|_| AuditFailure)?;
        self.file.flush().map_err(|_| AuditFailure)?;
        self.file.sync_all().map_err(|_| AuditFailure)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogCompletion {
    Recovered,
    NoJournal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WatchdogFailure {
    Timeout,
    Terminal(FailureClass),
    Audit,
}

fn main() -> ExitCode {
    if !cfg!(windows) {
        eprintln!("network recovery is available only on Windows");
        return ExitCode::from(2);
    }

    let action = match parse_action(std::env::args_os().skip(1)) {
        Ok(action) => action,
        Err(message) => {
            eprintln!("{message}");
            eprintln!("usage: network_recover.exe [--status|--apply|--watchdog]");
            return ExitCode::from(2);
        }
    };
    let watchdog_started = (action == Action::Watchdog).then(Instant::now);
    let context = match current_user_context() {
        Ok(context) => context,
        Err(error) => {
            eprintln!("recovery user/config context rejected: {}", error.code());
            return ExitCode::from(1);
        }
    };
    let journal_path = recovery::journal_path(&context.config_directory);

    match action {
        Action::Status => run_status(&journal_path),
        Action::Apply => run_apply(&journal_path),
        Action::Watchdog => run_watchdog_action(
            &context,
            &journal_path,
            watchdog_started.expect("watchdog action has a start time"),
        ),
    }
}

fn parse_action(
    mut arguments: impl Iterator<Item = std::ffi::OsString>,
) -> Result<Action, &'static str> {
    let action = match arguments.next() {
        Some(argument) => argument
            .into_string()
            .map_err(|_| "recovery helper action is not valid Unicode")?,
        None => "--status".to_owned(),
    };
    if arguments.next().is_some() {
        return Err("too many recovery helper arguments");
    }
    match action.as_str() {
        "--status" => Ok(Action::Status),
        "--apply" => Ok(Action::Apply),
        "--watchdog" => Ok(Action::Watchdog),
        _ => Err("unknown recovery helper action"),
    }
}

fn current_recovery_executable() -> Result<PathBuf, AssetFailure> {
    std::env::current_exe().map_err(|_| AssetFailure::DirectoryLookup)
}

fn run_status(journal_path: &Path) -> ExitCode {
    match recovery::load(journal_path) {
        Ok(Some(journal)) => {
            if journal.is_adapter_creation_intent() {
                println!(
                    "recovery required: adapter={}, requested_interface_guid={}, \
                     state=adapter-creation-intent, owned_changes=0",
                    journal.adapter_name,
                    journal.adapter_guid.as_deref().unwrap_or("invalid")
                );
            } else if let Some(identity) = journal.adapter_identity.as_ref() {
                println!(
                    "recovery required: adapter={}, interface_index={}, interface_luid={}, \
                     interface_guid={}, owned_changes={}",
                    journal.adapter_name,
                    identity.interface_index,
                    identity.interface_luid,
                    identity.interface_guid,
                    journal.owned_change_count()
                );
            } else {
                eprintln!("recovery journal state is inconsistent");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("no recovery journal is present");
            ExitCode::SUCCESS
        }
        Err(RuntimeError::RecoveryRequired) => {
            eprintln!("recovery journal inspection failed: recovery_required");
            ExitCode::from(1)
        }
        Err(_) => {
            eprintln!("recovery journal inspection failed: journal_read_failed");
            ExitCode::from(1)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApplyOutcome {
    Recovered,
    NoJournal,
    RuntimeActive,
    RecoveryRequired,
    Failed,
}

fn classify_apply_result(result: Result<bool, RuntimeError>) -> ApplyOutcome {
    match result {
        Ok(true) => ApplyOutcome::Recovered,
        Ok(false) => ApplyOutcome::NoJournal,
        Err(RuntimeError::RuntimeActive) => ApplyOutcome::RuntimeActive,
        Err(RuntimeError::RecoveryRequired) => ApplyOutcome::RecoveryRequired,
        Err(_) => ApplyOutcome::Failed,
    }
}

fn run_apply(journal_path: &Path) -> ExitCode {
    match classify_apply_result(recovery::recover(journal_path)) {
        ApplyOutcome::Recovered => {
            println!("recorded Wintun addresses and routes were restored");
            ExitCode::SUCCESS
        }
        ApplyOutcome::NoJournal => {
            println!("no recovery journal is present");
            ExitCode::SUCCESS
        }
        ApplyOutcome::RuntimeActive => {
            eprintln!("network recovery failed: runtime_active");
            ExitCode::from(1)
        }
        ApplyOutcome::RecoveryRequired => {
            eprintln!("network recovery failed: recovery_required");
            ExitCode::from(1)
        }
        ApplyOutcome::Failed => {
            eprintln!("network recovery failed: recovery_error");
            ExitCode::from(1)
        }
    }
}

fn run_watchdog_action(context: &UserContext, journal_path: &Path, started: Instant) -> ExitCode {
    let policy = WatchdogPolicy::fixed();
    let initialized = with_initialized_audit(context, policy, |audit| {
        let executable = match current_recovery_executable() {
            Ok(executable) => executable,
            Err(error) => {
                let failure = error.failure_class();
                return audit
                    .record(
                        AuditEvent::final_record(
                            AuditState::TerminalFailure,
                            FinalStatus::TerminalFailure,
                            ExitClass::TerminalFailure,
                            Some(failure),
                        ),
                        ClockReading {
                            elapsed: started.elapsed(),
                            utc_unix_ms: unix_time_millis(),
                        },
                    )
                    .map(|_| Err(WatchdogFailure::Terminal(failure)))
                    .unwrap_or(Err(WatchdogFailure::Audit));
            }
        };
        let assets = match verify_watchdog_assets(&executable, &context.sid_fingerprint) {
            Ok(assets) => assets,
            Err(error) => {
                let failure = error.failure_class();
                let reading = ClockReading {
                    elapsed: started.elapsed(),
                    utc_unix_ms: unix_time_millis(),
                };
                let event = AuditEvent::final_record(
                    AuditState::TerminalFailure,
                    FinalStatus::TerminalFailure,
                    ExitClass::TerminalFailure,
                    Some(failure),
                );
                return audit
                    .record(event, reading)
                    .map(|_| Err(WatchdogFailure::Terminal(failure)))
                    .unwrap_or(Err(WatchdogFailure::Audit));
            }
        };
        audit.set_assets(&assets);
        if audit
            .record(
                AuditEvent::precondition(AuditState::AssetsVerified),
                ClockReading {
                    elapsed: started.elapsed(),
                    utc_unix_ms: unix_time_millis(),
                },
            )
            .is_err()
        {
            return Err(WatchdogFailure::Audit);
        }

        let mut recovery = GuardedRecoveryRunner {
            asset_verifier: FixedAssetVerifier {
                executable: &executable,
                expected_sid_fingerprint: &context.sid_fingerprint,
            },
            recovery_backend: ConstrainedRecoveryBackend { journal_path },
            initial_assets: &assets,
            verified: None,
        };
        run_watchdog(
            policy,
            &mut recovery,
            audit,
            || ClockReading {
                elapsed: started.elapsed(),
                utc_unix_ms: unix_time_millis(),
            },
            thread::sleep,
        )
    });

    let (result, audit_path) = match initialized {
        Ok(value) => value,
        Err(_) => {
            eprintln!("watchdog audit initialization failed");
            return ExitCode::from(1);
        }
    };
    match result {
        Ok(WatchdogCompletion::Recovered) => {
            println!(
                "watchdog recovery completed; audit_log={}",
                audit_path.display()
            );
            ExitCode::SUCCESS
        }
        Ok(WatchdogCompletion::NoJournal) => {
            println!(
                "no recovery journal is present in the verified user context; audit_log={}",
                audit_path.display()
            );
            ExitCode::SUCCESS
        }
        Err(WatchdogFailure::Timeout) => {
            eprintln!(
                "watchdog timed out; the recovery journal was preserved; audit_log={}",
                audit_path.display()
            );
            ExitCode::from(1)
        }
        Err(WatchdogFailure::Terminal(failure)) => {
            eprintln!(
                "watchdog recovery failed: {failure:?}; audit_log={}",
                audit_path.display()
            );
            ExitCode::from(1)
        }
        Err(WatchdogFailure::Audit) => {
            eprintln!(
                "watchdog audit write failed; further recovery stopped; audit_log={}",
                audit_path.display()
            );
            ExitCode::from(1)
        }
    }
}

fn with_initialized_audit<T>(
    context: &UserContext,
    policy: WatchdogPolicy,
    operation: impl FnOnce(&mut AuditLog) -> T,
) -> Result<(T, PathBuf), AuditFailure> {
    let mut audit = AuditLog::create(context, policy)?;
    audit.record(
        AuditEvent::precondition(AuditState::ContextVerified),
        zero_elapsed_reading(),
    )?;
    let path = audit.path.clone();
    Ok((operation(&mut audit), path))
}

fn require_deadline_remaining<L: AuditSink>(
    policy: WatchdogPolicy,
    audit: &mut L,
    reading: ClockReading,
) -> Result<(), WatchdogFailure> {
    if reading.elapsed < policy.deadline {
        return Ok(());
    }
    audit
        .record(
            AuditEvent::final_record(
                AuditState::Timeout,
                FinalStatus::Timeout,
                ExitClass::Timeout,
                None,
            ),
            reading,
        )
        .map_err(|_| WatchdogFailure::Audit)?;
    Err(WatchdogFailure::Timeout)
}

fn run_watchdog<R, L, N, S>(
    policy: WatchdogPolicy,
    recovery: &mut R,
    audit: &mut L,
    mut now: N,
    mut sleep: S,
) -> Result<WatchdogCompletion, WatchdogFailure>
where
    R: RecoveryRunner,
    L: AuditSink,
    N: FnMut() -> ClockReading,
    S: FnMut(Duration),
{
    let mut attempt_number = 0_u64;
    loop {
        let before = now();
        if before.elapsed >= policy.deadline || attempt_number >= policy.max_attempts {
            audit
                .record(
                    AuditEvent::final_record(
                        AuditState::Timeout,
                        FinalStatus::Timeout,
                        ExitClass::Timeout,
                        None,
                    ),
                    before,
                )
                .map_err(|_| WatchdogFailure::Audit)?;
            return Err(WatchdogFailure::Timeout);
        }

        attempt_number = attempt_number.saturating_add(1);
        audit
            .record(
                AuditEvent::attempt(attempt_number, AuditState::AttemptStarted, None),
                before,
            )
            .map_err(|_| WatchdogFailure::Audit)?;

        match recovery.attempt() {
            RecoveryAttempt::RecoveryVerified => {
                let reading = now();
                audit
                    .record(
                        AuditEvent::attempt(
                            attempt_number,
                            AuditState::RecoveryVerified,
                            Some(false),
                        ),
                        reading,
                    )
                    .map_err(|_| WatchdogFailure::Audit)?;
                let reading = now();
                require_deadline_remaining(policy, audit, reading)?;
                // Sync a write-ahead authorization for the only remaining
                // mutation: clearing the already-restored journal. It does
                // not claim that the clear has succeeded. A failed clear
                // appends a terminal record; a successful clear is verified
                // before the helper exits 0.
                audit
                    .record(
                        AuditEvent::final_record(
                            AuditState::JournalClearAuthorized,
                            FinalStatus::RecoveryVerified,
                            ExitClass::SuccessAfterJournalClear,
                            None,
                        ),
                        reading,
                    )
                    .map_err(|_| WatchdogFailure::Audit)?;

                // The synchronized authorization write can itself cross the
                // deadline. Re-read the clock after that final audit commit so
                // no journal clear can rely on a pre-sync reading.
                require_deadline_remaining(policy, audit, now())?;
                if let Err(failure) = recovery.clear_verified_journal() {
                    audit
                        .record(
                            AuditEvent::final_record(
                                AuditState::TerminalFailure,
                                FinalStatus::TerminalFailure,
                                ExitClass::TerminalFailure,
                                Some(failure),
                            ),
                            now(),
                        )
                        .map_err(|_| WatchdogFailure::Audit)?;
                    return Err(WatchdogFailure::Terminal(failure));
                }
                return Ok(WatchdogCompletion::Recovered);
            }
            RecoveryAttempt::NoJournal => {
                let reading = now();
                audit
                    .record(
                        AuditEvent::attempt(attempt_number, AuditState::NoJournal, Some(false)),
                        reading,
                    )
                    .map_err(|_| WatchdogFailure::Audit)?;
                let reading = now();
                require_deadline_remaining(policy, audit, reading)?;
                audit
                    .record(
                        AuditEvent::final_record(
                            AuditState::NoJournal,
                            FinalStatus::NoJournal,
                            ExitClass::Success,
                            None,
                        ),
                        reading,
                    )
                    .map_err(|_| WatchdogFailure::Audit)?;
                // A no-journal result is a network no-op, but it must not be
                // reported as watchdog success using a clock reading taken
                // before the synchronized final audit write.
                require_deadline_remaining(policy, audit, now())?;
                return Ok(WatchdogCompletion::NoJournal);
            }
            RecoveryAttempt::RuntimeActive => {
                let reading = now();
                let will_retry =
                    reading.elapsed < policy.deadline && attempt_number < policy.max_attempts;
                audit
                    .record(
                        AuditEvent::attempt(
                            attempt_number,
                            AuditState::RuntimeActive,
                            Some(will_retry),
                        ),
                        reading,
                    )
                    .map_err(|_| WatchdogFailure::Audit)?;
                if !will_retry {
                    audit
                        .record(
                            AuditEvent::final_record(
                                AuditState::Timeout,
                                FinalStatus::Timeout,
                                ExitClass::Timeout,
                                None,
                            ),
                            reading,
                        )
                        .map_err(|_| WatchdogFailure::Audit)?;
                    return Err(WatchdogFailure::Timeout);
                }
                let remaining = policy.deadline.saturating_sub(reading.elapsed);
                sleep(policy.retry_interval.min(remaining));
            }
            RecoveryAttempt::Terminal(failure) => {
                let reading = now();
                audit
                    .record(
                        AuditEvent::attempt_failure(attempt_number, failure),
                        reading,
                    )
                    .map_err(|_| WatchdogFailure::Audit)?;
                audit
                    .record(
                        AuditEvent::final_record(
                            AuditState::TerminalFailure,
                            FinalStatus::TerminalFailure,
                            ExitClass::TerminalFailure,
                            Some(failure),
                        ),
                        reading,
                    )
                    .map_err(|_| WatchdogFailure::Audit)?;
                return Err(WatchdogFailure::Terminal(failure));
            }
        }
    }
}

fn current_user_context() -> Result<UserContext, ContextFailure> {
    validate_user_context(platform_user_context()?)
}

fn validate_user_context(raw: RawUserContext) -> Result<UserContext, ContextFailure> {
    if raw.service_account {
        return Err(ContextFailure::ServiceAccount);
    }
    if raw.sid_bytes.is_empty() {
        return Err(ContextFailure::IdentityUnavailable);
    }
    if !raw.roaming_app_data.is_absolute() {
        return Err(ContextFailure::AppDataUnavailable);
    }
    if !raw.appdata_matches_known_folder {
        return Err(ContextFailure::AppDataMismatch);
    }
    let config_directory = raw.roaming_app_data.join(APPLICATION_IDENTIFIER);
    Ok(UserContext {
        roaming_app_data: raw.roaming_app_data,
        config_directory,
        sid_fingerprint: sha256_bytes(&raw.sid_bytes),
    })
}

#[cfg(not(windows))]
fn platform_user_context() -> Result<RawUserContext, ContextFailure> {
    Err(ContextFailure::Unsupported)
}

#[cfg(windows)]
fn platform_user_context() -> Result<RawUserContext, ContextFailure> {
    windows_user_context()
}

#[cfg(windows)]
fn windows_user_context() -> Result<RawUserContext, ContextFailure> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, GetLastError, HANDLE,
    };
    use windows_sys::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, IsValidSid, IsWellKnownSid, TOKEN_QUERY, TOKEN_USER,
        TokenUser, WinLocalServiceSid, WinLocalSystemSid, WinNetworkServiceSid,
    };
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::UI::Shell::{FOLDERID_RoamingAppData, SHGetKnownFolderPath};

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(ContextFailure::IdentityUnavailable);
    }
    let token = HandleGuard(token);
    let mut required = 0_u32;
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required);
    }
    if required < u32::try_from(std::mem::size_of::<TOKEN_USER>()).unwrap_or(u32::MAX)
        || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER
    {
        return Err(ContextFailure::IdentityUnavailable);
    }
    let word_size = std::mem::size_of::<usize>();
    let words = (required as usize).saturating_add(word_size - 1) / word_size;
    let mut buffer = vec![0_usize; words];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            required,
            &mut required,
        )
    } == 0
    {
        return Err(ContextFailure::IdentityUnavailable);
    }
    let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let sid = token_user.User.Sid;
    let buffer_start = buffer.as_ptr() as usize;
    let buffer_end = buffer_start.saturating_add(buffer.len().saturating_mul(word_size));
    let sid_start = sid as usize;
    if sid.is_null()
        || sid_start < buffer_start
        || sid_start >= buffer_end
        || unsafe { IsValidSid(sid) } == 0
    {
        return Err(ContextFailure::IdentityUnavailable);
    }
    let sid_length = unsafe { GetLengthSid(sid) } as usize;
    if sid_length == 0 || sid_start.saturating_add(sid_length) > buffer_end {
        return Err(ContextFailure::IdentityUnavailable);
    }
    let service_account = unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinLocalServiceSid) != 0
            || IsWellKnownSid(sid, WinNetworkServiceSid) != 0
    };
    if service_account {
        return Err(ContextFailure::ServiceAccount);
    }
    let sid_bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), sid_length) }.to_vec();

    let mut known_path = null_mut();
    let result =
        unsafe { SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, null_mut(), &mut known_path) };
    if result != 0 || known_path.is_null() {
        if !known_path.is_null() {
            unsafe {
                CoTaskMemFree(known_path.cast());
            }
        }
        return Err(ContextFailure::AppDataUnavailable);
    }
    let mut length = 0_usize;
    while length < 32_768 && unsafe { *known_path.add(length) } != 0 {
        length += 1;
    }
    if length == 32_768 {
        unsafe {
            CoTaskMemFree(known_path.cast());
        }
        return Err(ContextFailure::AppDataUnavailable);
    }
    let roaming_app_data = PathBuf::from(OsString::from_wide(unsafe {
        std::slice::from_raw_parts(known_path, length)
    }));
    unsafe {
        CoTaskMemFree(known_path.cast());
    }

    let environment_app_data = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .ok_or(ContextFailure::AppDataUnavailable)?;
    let normalize = |path: &Path| {
        let mut wide = path
            .as_os_str()
            .encode_wide()
            .map(|value| {
                if value == u16::from(b'/') {
                    u16::from(b'\\')
                } else {
                    value
                }
            })
            .collect::<Vec<_>>();
        while wide.last() == Some(&u16::from(b'\\')) {
            wide.pop();
        }
        wide
    };
    let known = normalize(&roaming_app_data);
    let environment = normalize(&environment_app_data);
    let lengths_fit = known.len() <= i32::MAX as usize && environment.len() <= i32::MAX as usize;
    let appdata_matches_known_folder = lengths_fit
        && unsafe {
            CompareStringOrdinal(
                known.as_ptr(),
                known.len() as i32,
                environment.as_ptr(),
                environment.len() as i32,
                1,
            )
        } == CSTR_EQUAL;

    Ok(RawUserContext {
        roaming_app_data,
        sid_bytes,
        service_account: false,
        appdata_matches_known_folder,
    })
}

fn prepare_audit_directory(context: &UserContext) -> Result<PathBuf, AuditFailure> {
    let canonical_roaming =
        fs::canonicalize(&context.roaming_app_data).map_err(|_| AuditFailure)?;
    fs::create_dir_all(&context.config_directory).map_err(|_| AuditFailure)?;
    let canonical_config = fs::canonicalize(&context.config_directory).map_err(|_| AuditFailure)?;
    if canonical_config.parent() != Some(canonical_roaming.as_path())
        || canonical_config.file_name() != Some(OsStr::new(APPLICATION_IDENTIFIER))
    {
        return Err(AuditFailure);
    }

    let audit_directory = context.config_directory.join(WATCHDOG_AUDIT_DIRECTORY);
    fs::create_dir_all(&audit_directory).map_err(|_| AuditFailure)?;
    let canonical_audit = fs::canonicalize(&audit_directory).map_err(|_| AuditFailure)?;
    if canonical_audit.parent() != Some(canonical_config.as_path())
        || canonical_audit.file_name() != Some(OsStr::new(WATCHDOG_AUDIT_DIRECTORY))
    {
        return Err(AuditFailure);
    }
    Ok(canonical_audit)
}

fn verify_staged_assets(executable: &Path) -> Result<StagedAssets, AssetFailure> {
    verify_staged_assets_with_expected(executable, EXPECTED_WINTUN_SHA256)
}

fn verify_watchdog_assets(
    executable: &Path,
    expected_sid_fingerprint: &str,
) -> Result<StagedAssets, AssetFailure> {
    let mut assets = verify_staged_assets(executable)?;
    verify_watchdog_context_binding(&assets.directory, expected_sid_fingerprint)?;
    assets.context_fingerprint = Some(expected_sid_fingerprint.to_owned());
    Ok(assets)
}

#[cfg(test)]
fn verify_watchdog_assets_with_expected(
    executable: &Path,
    expected_sid_fingerprint: &str,
    expected_wintun_hash: &str,
) -> Result<StagedAssets, AssetFailure> {
    let mut assets = verify_staged_assets_with_expected(executable, expected_wintun_hash)?;
    verify_watchdog_context_binding(&assets.directory, expected_sid_fingerprint)?;
    assets.context_fingerprint = Some(expected_sid_fingerprint.to_owned());
    Ok(assets)
}

fn verify_staged_assets_with_expected(
    executable: &Path,
    expected_wintun_hash: &str,
) -> Result<StagedAssets, AssetFailure> {
    if executable.file_name() != Some(OsStr::new(RECOVERY_HELPER_NAME)) {
        return Err(AssetFailure::ExecutableName);
    }
    if !is_sha256(expected_wintun_hash) {
        return Err(AssetFailure::WintunApprovedHash);
    }
    let directory = executable.parent().ok_or(AssetFailure::DirectoryLookup)?;
    let canonical_directory =
        fs::canonicalize(directory).map_err(|_| AssetFailure::DirectoryLookup)?;
    let canonical_executable =
        canonical_sibling(&canonical_directory, executable, RECOVERY_HELPER_NAME)?;
    let wintun = canonical_sibling(
        &canonical_directory,
        &directory.join(WINTUN_DLL_NAME),
        WINTUN_DLL_NAME,
    )?;
    let manifest = canonical_sibling(
        &canonical_directory,
        &directory.join(HASH_MANIFEST_NAME),
        HASH_MANIFEST_NAME,
    )?;

    let metadata = fs::metadata(&manifest).map_err(|_| AssetFailure::ManifestRead)?;
    if metadata.len() > MAX_HASH_MANIFEST_BYTES {
        return Err(AssetFailure::ManifestTooLarge);
    }
    let manifest_bytes = fs::read(&manifest).map_err(|_| AssetFailure::ManifestRead)?;
    if !manifest_bytes.is_ascii() {
        return Err(AssetFailure::ManifestEncoding);
    }
    let manifest_text =
        std::str::from_utf8(&manifest_bytes).map_err(|_| AssetFailure::ManifestEncoding)?;
    let entries = parse_hash_manifest(manifest_text)?;
    let expected_helper = exact_manifest_entry(&entries, RECOVERY_HELPER_NAME)
        .ok_or(AssetFailure::ManifestMissingHelper)?;
    let expected_wintun = exact_manifest_entry(&entries, WINTUN_DLL_NAME)
        .ok_or(AssetFailure::ManifestMissingWintun)?;

    let helper_hash = sha256_file(&canonical_executable).map_err(|_| AssetFailure::HelperRead)?;
    let wintun_hash = sha256_file(&wintun).map_err(|_| AssetFailure::WintunRead)?;
    if helper_hash != expected_helper {
        return Err(AssetFailure::HelperHash);
    }
    if wintun_hash != expected_wintun {
        return Err(AssetFailure::WintunManifestHash);
    }
    if wintun_hash != expected_wintun_hash {
        return Err(AssetFailure::WintunApprovedHash);
    }

    Ok(StagedAssets {
        directory: canonical_directory,
        helper_hash,
        wintun_hash,
        context_fingerprint: None,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchdogContextBinding {
    schema: String,
    version: u32,
    user_sid_sha256: String,
}

fn verify_watchdog_context_binding(
    canonical_directory: &Path,
    expected_sid_fingerprint: &str,
) -> Result<(), AssetFailure> {
    if !is_sha256(expected_sid_fingerprint) {
        return Err(AssetFailure::ContextBindingInvalid);
    }
    let path = canonical_directory.join(WATCHDOG_CONTEXT_NAME);
    let binding = canonical_sibling(canonical_directory, &path, WATCHDOG_CONTEXT_NAME)
        .map_err(|_| AssetFailure::ContextBindingRead)?;
    let metadata = fs::metadata(&binding).map_err(|_| AssetFailure::ContextBindingRead)?;
    if metadata.len() > MAX_WATCHDOG_CONTEXT_BYTES {
        return Err(AssetFailure::ContextBindingInvalid);
    }
    let bytes = fs::read(binding).map_err(|_| AssetFailure::ContextBindingRead)?;
    if !bytes.is_ascii() {
        return Err(AssetFailure::ContextBindingInvalid);
    }
    let context: WatchdogContextBinding =
        serde_json::from_slice(&bytes).map_err(|_| AssetFailure::ContextBindingInvalid)?;
    if context.schema != WATCHDOG_CONTEXT_SCHEMA
        || context.version != WATCHDOG_CONTEXT_VERSION
        || !is_sha256(&context.user_sid_sha256)
    {
        return Err(AssetFailure::ContextBindingInvalid);
    }
    if context.user_sid_sha256 != expected_sid_fingerprint {
        return Err(AssetFailure::ContextBindingMismatch);
    }
    Ok(())
}

fn canonical_sibling(
    canonical_directory: &Path,
    path: &Path,
    expected_name: &str,
) -> Result<PathBuf, AssetFailure> {
    if path.file_name() != Some(OsStr::new(expected_name)) {
        return Err(AssetFailure::UnsafeAsset);
    }
    let link_metadata = fs::symlink_metadata(path).map_err(|_| AssetFailure::MissingAsset)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_file() {
        return Err(AssetFailure::UnsafeAsset);
    }
    let canonical = fs::canonicalize(path).map_err(|_| AssetFailure::MissingAsset)?;
    if canonical.parent() != Some(canonical_directory)
        || canonical.file_name() != Some(OsStr::new(expected_name))
    {
        return Err(AssetFailure::UnsafeAsset);
    }
    Ok(canonical)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestEntry {
    original_name: String,
    hash: String,
}

fn parse_hash_manifest(manifest: &str) -> Result<HashMap<String, ManifestEntry>, AssetFailure> {
    let mut entries = HashMap::new();
    for line in manifest.lines() {
        if line.len() < 67 || line.get(64..66) != Some("  ") {
            return Err(AssetFailure::ManifestEntry);
        }
        let hash = &line[..64];
        let name = &line[66..];
        if !is_sha256(hash) || !safe_manifest_filename(name) {
            return Err(AssetFailure::ManifestEntry);
        }
        let key = name.to_ascii_lowercase();
        let entry = ManifestEntry {
            original_name: name.to_owned(),
            hash: hash.to_ascii_lowercase(),
        };
        if entries.insert(key, entry).is_some() {
            return Err(AssetFailure::ManifestDuplicate);
        }
    }
    if entries.is_empty() {
        return Err(AssetFailure::ManifestEntry);
    }
    Ok(entries)
}

fn exact_manifest_entry<'a>(
    entries: &'a HashMap<String, ManifestEntry>,
    expected_name: &str,
) -> Option<&'a str> {
    let entry = entries.get(&expected_name.to_ascii_lowercase())?;
    (entry.original_name == expected_name).then_some(entry.hash.as_str())
}

fn safe_manifest_filename(name: &str) -> bool {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with([' ', '.'])
        || name.ends_with([' ', '.'])
        || name
            .bytes()
            .any(|byte| byte.is_ascii_control() || b"<>:\"/\\|?*".contains(&byte))
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    !matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        && !(stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex_digest(hasher.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_digest(hasher.finalize())
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    let bytes = digest.as_ref();
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(HEX[usize::from(byte >> 4)] as char);
        output.push(HEX[usize::from(byte & 0x0f)] as char);
    }
    output
}

fn new_run_id() -> String {
    let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut material = Vec::with_capacity(28);
    material.extend_from_slice(&timestamp.to_le_bytes());
    material.extend_from_slice(&std::process::id().to_le_bytes());
    material.extend_from_slice(&sequence.to_le_bytes());
    sha256_bytes(&material)[..32].to_owned()
}

fn unix_time_millis() -> u64 {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn zero_elapsed_reading() -> ClockReading {
    ClockReading {
        elapsed: Duration::ZERO,
        utc_unix_ms: unix_time_millis(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::rc::Rc;

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn unique_directory() -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ss-network-recover-test-{}-{sequence}",
            std::process::id()
        ))
    }

    fn stage_test_assets() -> (PathBuf, String) {
        let directory = unique_directory();
        fs::create_dir_all(&directory).unwrap();
        let executable = directory.join(RECOVERY_HELPER_NAME);
        let wintun = directory.join(WINTUN_DLL_NAME);
        fs::write(&executable, b"test recovery helper").unwrap();
        fs::write(&wintun, b"test wintun dll").unwrap();
        let helper_hash = sha256_file(&executable).unwrap();
        let wintun_hash = sha256_file(&wintun).unwrap();
        fs::write(
            directory.join(HASH_MANIFEST_NAME),
            format!(
                "{helper_hash}  {RECOVERY_HELPER_NAME}\n\
                 {wintun_hash}  {WINTUN_DLL_NAME}\n"
            ),
        )
        .unwrap();
        (executable, wintun_hash)
    }

    fn write_context_binding(directory: &Path, sid_fingerprint: &str) {
        fs::write(
            directory.join(WATCHDOG_CONTEXT_NAME),
            format!(
                "{{\"schema\":\"{WATCHDOG_CONTEXT_SCHEMA}\",\
                 \"version\":{WATCHDOG_CONTEXT_VERSION},\
                 \"user_sid_sha256\":\"{sid_fingerprint}\"}}\n"
            ),
        )
        .unwrap();
    }

    fn test_context(roaming: PathBuf) -> UserContext {
        UserContext {
            config_directory: roaming.join(APPLICATION_IDENTIFIER),
            roaming_app_data: roaming,
            sid_fingerprint: sha256_bytes(b"test sid"),
        }
    }

    #[derive(Default)]
    struct MemoryAudit {
        records: Vec<(AuditEvent, ClockReading)>,
        fail_on_record: Option<usize>,
    }

    impl AuditSink for MemoryAudit {
        fn record(&mut self, event: AuditEvent, reading: ClockReading) -> Result<(), AuditFailure> {
            if self.fail_on_record == Some(self.records.len().saturating_add(1)) {
                return Err(AuditFailure);
            }
            self.records.push((event, reading));
            Ok(())
        }
    }

    struct AdvancingAudit<'a> {
        inner: &'a mut MemoryAudit,
        elapsed: Rc<Cell<Duration>>,
        advance_after_record: usize,
        advance_to: Duration,
    }

    impl AuditSink for AdvancingAudit<'_> {
        fn record(&mut self, event: AuditEvent, reading: ClockReading) -> Result<(), AuditFailure> {
            self.inner.record(event, reading)?;
            if self.inner.records.len() == self.advance_after_record {
                self.elapsed.set(self.advance_to);
            }
            Ok(())
        }
    }

    struct MockRecovery {
        outcomes: VecDeque<RecoveryAttempt>,
        attempts: u64,
        clears: u64,
        clear_result: Result<(), FailureClass>,
    }

    impl MockRecovery {
        fn new(outcomes: impl IntoIterator<Item = RecoveryAttempt>) -> Self {
            Self {
                outcomes: outcomes.into_iter().collect(),
                attempts: 0,
                clears: 0,
                clear_result: Ok(()),
            }
        }
    }

    impl RecoveryRunner for MockRecovery {
        fn attempt(&mut self) -> RecoveryAttempt {
            self.attempts += 1;
            self.outcomes
                .pop_front()
                .unwrap_or(RecoveryAttempt::RuntimeActive)
        }

        fn clear_verified_journal(&mut self) -> Result<(), FailureClass> {
            self.clears += 1;
            self.clear_result
        }
    }

    fn run_mock(
        policy: WatchdogPolicy,
        recovery: &mut MockRecovery,
        audit: &mut MemoryAudit,
        elapsed: Rc<Cell<Duration>>,
        sleeps: Rc<std::cell::RefCell<Vec<Duration>>>,
    ) -> Result<WatchdogCompletion, WatchdogFailure> {
        let clock_elapsed = Rc::clone(&elapsed);
        let sleeper_elapsed = Rc::clone(&elapsed);
        run_watchdog(
            policy,
            recovery,
            audit,
            move || ClockReading {
                elapsed: clock_elapsed.get(),
                utc_unix_ms: 1_700_000_000_000 + duration_millis(clock_elapsed.get()),
            },
            move |duration| {
                sleeps.borrow_mut().push(duration);
                sleeper_elapsed.set(sleeper_elapsed.get().saturating_add(duration));
            },
        )
    }

    #[test]
    fn cli_accepts_only_fixed_actions_and_no_paths() {
        assert_eq!(
            parse_action(Vec::<OsString>::new().into_iter()),
            Ok(Action::Status)
        );
        assert_eq!(
            parse_action(vec![OsString::from("--status")].into_iter()),
            Ok(Action::Status)
        );
        assert_eq!(
            parse_action(vec![OsString::from("--apply")].into_iter()),
            Ok(Action::Apply)
        );
        assert_eq!(
            parse_action(vec![OsString::from("--watchdog")].into_iter()),
            Ok(Action::Watchdog)
        );
        assert!(parse_action(vec![OsString::from("--timeout=0")].into_iter()).is_err());
        assert!(
            parse_action(
                vec![
                    OsString::from("--watchdog"),
                    OsString::from("caller-selected.json")
                ]
                .into_iter()
            )
            .is_err()
        );
    }

    #[test]
    fn status_and_apply_result_contracts_are_preserved() {
        let directory = unique_directory();
        fs::create_dir_all(&directory).unwrap();
        assert_eq!(
            run_status(&directory.join("absent.json")),
            ExitCode::SUCCESS
        );
        assert_eq!(classify_apply_result(Ok(true)), ApplyOutcome::Recovered);
        assert_eq!(classify_apply_result(Ok(false)), ApplyOutcome::NoJournal);
        assert_eq!(
            classify_apply_result(Err(RuntimeError::RuntimeActive)),
            ApplyOutcome::RuntimeActive
        );
        assert_eq!(
            classify_apply_result(Err(RuntimeError::RecoveryRequired)),
            ApplyOutcome::RecoveryRequired
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn first_attempt_success_records_final_and_clears_after_audit() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([RecoveryAttempt::RecoveryVerified]);
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(policy, &mut recovery, &mut audit, elapsed, sleeps),
            Ok(WatchdogCompletion::Recovered)
        );
        assert_eq!(recovery.attempts, 1);
        assert_eq!(recovery.clears, 1);
        assert!(audit.records.iter().any(|(event, _)| {
            event.record_type == AuditRecordType::Final
                && event.state == AuditState::JournalClearAuthorized
                && event.final_status == Some(FinalStatus::RecoveryVerified)
                && event.exit_class == Some(ExitClass::SuccessAfterJournalClear)
        }));
        assert!(!audit.records.iter().any(|(event, _)| {
            event.record_type == AuditRecordType::Final
                && event.exit_class == Some(ExitClass::Success)
                && event.final_status != Some(FinalStatus::NoJournal)
        }));
    }

    #[test]
    fn no_journal_is_success_only_after_context_precondition() {
        let raw = RawUserContext {
            roaming_app_data: unique_directory(),
            sid_bytes: b"interactive sid".to_vec(),
            service_account: false,
            appdata_matches_known_folder: true,
        };
        assert!(validate_user_context(raw).is_ok());

        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([RecoveryAttempt::NoJournal]);
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(policy, &mut recovery, &mut audit, elapsed, sleeps),
            Ok(WatchdogCompletion::NoJournal)
        );
        assert_eq!(recovery.clears, 0);
    }

    #[test]
    fn runtime_active_retries_then_succeeds() {
        let policy = WatchdogPolicy::new(Duration::from_secs(10), Duration::from_secs(2)).unwrap();
        let mut recovery = MockRecovery::new([
            RecoveryAttempt::RuntimeActive,
            RecoveryAttempt::RuntimeActive,
            RecoveryAttempt::RecoveryVerified,
        ]);
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(
                policy,
                &mut recovery,
                &mut audit,
                elapsed,
                Rc::clone(&sleeps)
            ),
            Ok(WatchdogCompletion::Recovered)
        );
        assert_eq!(recovery.attempts, 3);
        assert_eq!(
            sleeps.borrow().as_slice(),
            &[Duration::from_secs(2), Duration::from_secs(2)]
        );
    }

    #[test]
    fn runtime_active_until_timeout_is_nonzero_and_preserves_evidence() {
        let directory = unique_directory();
        fs::create_dir_all(&directory).unwrap();
        let journal = directory.join("journal.json");
        fs::write(&journal, b"evidence").unwrap();

        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(2)).unwrap();
        let mut recovery =
            MockRecovery::new(std::iter::repeat_n(RecoveryAttempt::RuntimeActive, 10));
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(policy, &mut recovery, &mut audit, elapsed, sleeps),
            Err(WatchdogFailure::Timeout)
        );
        assert_eq!(fs::read(&journal).unwrap(), b"evidence");
        assert_eq!(recovery.clears, 0);
        assert!(audit.records.iter().any(|(event, _)| {
            event.record_type == AuditRecordType::Final
                && event.final_status == Some(FinalStatus::Timeout)
        }));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn terminal_recovery_error_does_not_retry() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery =
            MockRecovery::new([RecoveryAttempt::Terminal(FailureClass::RecoveryRequired)]);
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(
                policy,
                &mut recovery,
                &mut audit,
                elapsed,
                Rc::clone(&sleeps)
            ),
            Err(WatchdogFailure::Terminal(FailureClass::RecoveryRequired))
        );
        assert_eq!(recovery.attempts, 1);
        assert!(sleeps.borrow().is_empty());
    }

    #[test]
    fn wrong_user_and_system_context_are_rejected() {
        let wrong_appdata = RawUserContext {
            roaming_app_data: unique_directory(),
            sid_bytes: b"user sid".to_vec(),
            service_account: false,
            appdata_matches_known_folder: false,
        };
        assert_eq!(
            validate_user_context(wrong_appdata),
            Err(ContextFailure::AppDataMismatch)
        );
        let system = RawUserContext {
            roaming_app_data: unique_directory(),
            sid_bytes: b"system sid".to_vec(),
            service_account: true,
            appdata_matches_known_folder: true,
        };
        assert_eq!(
            validate_user_context(system),
            Err(ContextFailure::ServiceAccount)
        );
    }

    #[test]
    fn watchdog_context_binding_rejects_an_ordinary_wrong_user_and_missing_binding() {
        let (executable, wintun_hash) = stage_test_assets();
        let directory = executable.parent().unwrap();
        let intended_sid = sha256_bytes(b"intended interactive sid");
        let other_sid = sha256_bytes(b"different interactive sid");
        write_context_binding(directory, &intended_sid);

        let verified =
            verify_watchdog_assets_with_expected(&executable, &intended_sid, &wintun_hash).unwrap();
        assert_eq!(
            verified.context_fingerprint.as_deref(),
            Some(intended_sid.as_str())
        );
        assert_eq!(
            verify_watchdog_assets_with_expected(&executable, &other_sid, &wintun_hash),
            Err(AssetFailure::ContextBindingMismatch)
        );

        fs::remove_file(directory.join(WATCHDOG_CONTEXT_NAME)).unwrap();
        assert_eq!(
            verify_watchdog_assets_with_expected(&executable, &intended_sid, &wintun_hash),
            Err(AssetFailure::ContextBindingRead)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn helper_and_wintun_tampering_are_rejected() {
        let (executable, wintun_hash) = stage_test_assets();
        assert!(verify_staged_assets_with_expected(&executable, &wintun_hash).is_ok());
        fs::write(&executable, b"tampered helper").unwrap();
        assert_eq!(
            verify_staged_assets_with_expected(&executable, &wintun_hash),
            Err(AssetFailure::HelperHash)
        );
        fs::remove_dir_all(executable.parent().unwrap()).unwrap();

        let (executable, wintun_hash) = stage_test_assets();
        fs::write(
            executable.parent().unwrap().join(WINTUN_DLL_NAME),
            b"tampered wintun",
        )
        .unwrap();
        assert_eq!(
            verify_staged_assets_with_expected(&executable, &wintun_hash),
            Err(AssetFailure::WintunManifestHash)
        );
        fs::remove_dir_all(executable.parent().unwrap()).unwrap();

        let (executable, approved_wintun_hash) = stage_test_assets();
        let directory = executable.parent().unwrap();
        let wintun = directory.join(WINTUN_DLL_NAME);
        fs::write(&wintun, b"tampered wintun with updated manifest").unwrap();
        let helper_hash = sha256_file(&executable).unwrap();
        let tampered_wintun_hash = sha256_file(&wintun).unwrap();
        fs::write(
            directory.join(HASH_MANIFEST_NAME),
            format!(
                "{helper_hash}  {RECOVERY_HELPER_NAME}\n\
                 {tampered_wintun_hash}  {WINTUN_DLL_NAME}\n"
            ),
        )
        .unwrap();
        assert_eq!(
            verify_staged_assets_with_expected(&executable, &approved_wintun_hash),
            Err(AssetFailure::WintunApprovedHash)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn injected_asset_failure_prevents_recovery_backend_call() {
        struct RejectAssets(AssetFailure);
        impl AssetVerifier for RejectAssets {
            fn verify(&mut self) -> Result<StagedAssets, AssetFailure> {
                Err(self.0)
            }
        }

        struct CountingBackend(Rc<Cell<u32>>);
        impl RecoveryBackend for CountingBackend {
            fn attempt(&mut self) -> BackendAttempt {
                self.0.set(self.0.get() + 1);
                BackendAttempt::NoJournal
            }
        }

        let baseline = StagedAssets {
            directory: PathBuf::from("fixed"),
            helper_hash: "0".repeat(64),
            wintun_hash: "1".repeat(64),
            context_fingerprint: None,
        };
        let calls = Rc::new(Cell::new(0));
        let mut runner = GuardedRecoveryRunner {
            asset_verifier: RejectAssets(AssetFailure::HelperHash),
            recovery_backend: CountingBackend(Rc::clone(&calls)),
            initial_assets: &baseline,
            verified: None,
        };
        assert_eq!(
            runner.attempt(),
            RecoveryAttempt::Terminal(FailureClass::AssetVerification)
        );
        assert_eq!(calls.get(), 0);

        let mut wrong_context_runner = GuardedRecoveryRunner {
            asset_verifier: RejectAssets(AssetFailure::ContextBindingMismatch),
            recovery_backend: CountingBackend(Rc::clone(&calls)),
            initial_assets: &baseline,
            verified: None,
        };
        assert_eq!(
            wrong_context_runner.attempt(),
            RecoveryAttempt::Terminal(FailureClass::UserContext)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn missing_manifest_duplicate_and_traversal_entries_are_rejected() {
        let (executable, wintun_hash) = stage_test_assets();
        fs::remove_file(executable.parent().unwrap().join(HASH_MANIFEST_NAME)).unwrap();
        assert_eq!(
            verify_staged_assets_with_expected(&executable, &wintun_hash),
            Err(AssetFailure::MissingAsset)
        );
        fs::remove_dir_all(executable.parent().unwrap()).unwrap();

        let hash = "0".repeat(64);
        assert_eq!(
            parse_hash_manifest(&format!("{hash}  {WINTUN_DLL_NAME}\n{hash}  WINTUN.DLL\n")),
            Err(AssetFailure::ManifestDuplicate)
        );
        assert_eq!(
            parse_hash_manifest(&format!("{hash}  ../{WINTUN_DLL_NAME}\n")),
            Err(AssetFailure::ManifestEntry)
        );
        assert_eq!(
            parse_hash_manifest(&format!("{hash}  C:{WINTUN_DLL_NAME}\n")),
            Err(AssetFailure::ManifestEntry)
        );
    }

    #[test]
    fn audit_creation_failure_causes_zero_recovery_calls() {
        let roaming = unique_directory();
        fs::create_dir_all(&roaming).unwrap();
        let context = test_context(roaming.clone());
        fs::create_dir_all(&context.config_directory).unwrap();
        fs::write(
            context.config_directory.join(WATCHDOG_AUDIT_DIRECTORY),
            b"blocks directory creation",
        )
        .unwrap();
        let calls = Cell::new(0_u32);
        let result = with_initialized_audit(
            &context,
            WatchdogPolicy::new(Duration::from_secs(1), Duration::from_millis(10)).unwrap(),
            |_audit| calls.set(calls.get() + 1),
        );
        assert!(result.is_err());
        assert_eq!(calls.get(), 0);
        fs::remove_dir_all(roaming).unwrap();
    }

    #[test]
    fn attempt_log_failure_stops_before_recovery_and_stops_retry() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([
            RecoveryAttempt::RuntimeActive,
            RecoveryAttempt::RecoveryVerified,
        ]);
        let mut audit = MemoryAudit {
            records: Vec::new(),
            fail_on_record: Some(1),
        };
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(policy, &mut recovery, &mut audit, elapsed, sleeps),
            Err(WatchdogFailure::Audit)
        );
        assert_eq!(recovery.attempts, 0);
        assert_eq!(recovery.clears, 0);
    }

    #[test]
    fn runtime_active_result_log_failure_stops_before_next_attempt() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([
            RecoveryAttempt::RuntimeActive,
            RecoveryAttempt::RecoveryVerified,
        ]);
        let mut audit = MemoryAudit {
            records: Vec::new(),
            fail_on_record: Some(2),
        };
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(
                policy,
                &mut recovery,
                &mut audit,
                elapsed,
                Rc::clone(&sleeps)
            ),
            Err(WatchdogFailure::Audit)
        );
        assert_eq!(recovery.attempts, 1);
        assert_eq!(recovery.clears, 0);
        assert!(sleeps.borrow().is_empty());
    }

    #[test]
    fn final_log_failure_preserves_verified_journal_clear_capability() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([RecoveryAttempt::RecoveryVerified]);
        let mut audit = MemoryAudit {
            records: Vec::new(),
            fail_on_record: Some(3),
        };
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(policy, &mut recovery, &mut audit, elapsed, sleeps),
            Err(WatchdogFailure::Audit)
        );
        assert_eq!(recovery.attempts, 1);
        assert_eq!(recovery.clears, 0);
    }

    #[test]
    fn journal_clear_failure_appends_terminal_without_a_false_success_record() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([RecoveryAttempt::RecoveryVerified]);
        recovery.clear_result = Err(FailureClass::JournalClear);
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));

        assert_eq!(
            run_mock(policy, &mut recovery, &mut audit, elapsed, sleeps),
            Err(WatchdogFailure::Terminal(FailureClass::JournalClear))
        );
        assert_eq!(recovery.attempts, 1);
        assert_eq!(recovery.clears, 1);
        let final_records = audit
            .records
            .iter()
            .filter_map(|(event, _)| {
                (event.record_type == AuditRecordType::Final).then_some(*event)
            })
            .collect::<Vec<_>>();
        assert_eq!(final_records.len(), 2);
        assert_eq!(
            final_records[0].final_status,
            Some(FinalStatus::RecoveryVerified)
        );
        assert_eq!(
            final_records[0].exit_class,
            Some(ExitClass::SuccessAfterJournalClear)
        );
        assert_eq!(
            final_records[1].final_status,
            Some(FinalStatus::TerminalFailure)
        );
        assert_eq!(
            final_records[1].failure_class,
            Some(FailureClass::JournalClear)
        );
        assert!(
            !final_records
                .iter()
                .any(|event| event.exit_class == Some(ExitClass::Success))
        );
    }

    #[test]
    fn journal_clear_failure_plus_audit_failure_never_leaves_a_success_claim() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([RecoveryAttempt::RecoveryVerified]);
        recovery.clear_result = Err(FailureClass::JournalClear);
        let mut audit = MemoryAudit {
            records: Vec::new(),
            fail_on_record: Some(4),
        };
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));

        assert_eq!(
            run_mock(policy, &mut recovery, &mut audit, elapsed, sleeps),
            Err(WatchdogFailure::Audit)
        );
        assert_eq!(recovery.clears, 1);
        assert_eq!(audit.records.len(), 3);
        let last = audit.records.last().unwrap().0;
        assert_eq!(last.state, AuditState::JournalClearAuthorized);
        assert_eq!(last.final_status, Some(FinalStatus::RecoveryVerified));
        assert_eq!(last.exit_class, Some(ExitClass::SuccessAfterJournalClear));
        assert!(
            !audit
                .records
                .iter()
                .any(|(event, _)| event.exit_class == Some(ExitClass::Success))
        );
    }

    #[test]
    fn recovery_finishing_at_deadline_times_out_without_clearing_journal() {
        struct SlowVerifiedRecovery {
            elapsed: Rc<Cell<Duration>>,
            clears: u64,
        }
        impl RecoveryRunner for SlowVerifiedRecovery {
            fn attempt(&mut self) -> RecoveryAttempt {
                self.elapsed.set(Duration::from_secs(5));
                RecoveryAttempt::RecoveryVerified
            }

            fn clear_verified_journal(&mut self) -> Result<(), FailureClass> {
                self.clears += 1;
                Ok(())
            }
        }

        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let clock_elapsed = Rc::clone(&elapsed);
        let mut recovery = SlowVerifiedRecovery { elapsed, clears: 0 };
        let mut audit = MemoryAudit::default();
        assert_eq!(
            run_watchdog(
                policy,
                &mut recovery,
                &mut audit,
                move || ClockReading {
                    elapsed: clock_elapsed.get(),
                    utc_unix_ms: 1_700_000_000_000,
                },
                |_| {},
            ),
            Err(WatchdogFailure::Timeout)
        );
        assert_eq!(recovery.clears, 0);
    }

    #[test]
    fn final_audit_sync_reaching_deadline_blocks_journal_clear() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let clock_elapsed = Rc::clone(&elapsed);
        let mut recovery = MockRecovery::new([RecoveryAttempt::RecoveryVerified]);
        let mut records = MemoryAudit::default();
        let result = {
            let mut audit = AdvancingAudit {
                inner: &mut records,
                elapsed,
                // Attempt-started, recovery-verified, then the synchronized
                // journal-clear authorization record.
                advance_after_record: 3,
                advance_to: policy.deadline,
            };
            run_watchdog(
                policy,
                &mut recovery,
                &mut audit,
                move || ClockReading {
                    elapsed: clock_elapsed.get(),
                    utc_unix_ms: 1_700_000_000_000 + duration_millis(clock_elapsed.get()),
                },
                |_| {},
            )
        };

        assert_eq!(result, Err(WatchdogFailure::Timeout));
        assert_eq!(recovery.clears, 0);
        assert_eq!(
            records.records.last().unwrap().0.final_status,
            Some(FinalStatus::Timeout)
        );
    }

    #[test]
    fn no_journal_audit_sync_cannot_cross_deadline_into_success() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        for advance_after_record in [2, 3] {
            let elapsed = Rc::new(Cell::new(Duration::ZERO));
            let clock_elapsed = Rc::clone(&elapsed);
            let mut recovery = MockRecovery::new([RecoveryAttempt::NoJournal]);
            let mut records = MemoryAudit::default();
            let result = {
                let mut audit = AdvancingAudit {
                    inner: &mut records,
                    elapsed,
                    // Cover both the no-journal attempt record and its final
                    // success record advancing the clock to the boundary.
                    advance_after_record,
                    advance_to: policy.deadline,
                };
                run_watchdog(
                    policy,
                    &mut recovery,
                    &mut audit,
                    move || ClockReading {
                        elapsed: clock_elapsed.get(),
                        utc_unix_ms: 1_700_000_000_000 + duration_millis(clock_elapsed.get()),
                    },
                    |_| {},
                )
            };

            assert_eq!(result, Err(WatchdogFailure::Timeout));
            assert_eq!(recovery.clears, 0);
            assert_eq!(
                records.records.last().unwrap().0.final_status,
                Some(FinalStatus::Timeout)
            );
        }
    }

    #[test]
    fn preflight_consuming_the_deadline_causes_zero_recovery_calls() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut recovery = MockRecovery::new([RecoveryAttempt::RecoveryVerified]);
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(policy.deadline));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));

        assert_eq!(
            run_mock(
                policy,
                &mut recovery,
                &mut audit,
                elapsed,
                Rc::clone(&sleeps)
            ),
            Err(WatchdogFailure::Timeout)
        );
        assert_eq!(recovery.attempts, 0);
        assert_eq!(recovery.clears, 0);
        assert!(sleeps.borrow().is_empty());
        assert_eq!(
            audit.records.last().unwrap().0.final_status,
            Some(FinalStatus::Timeout)
        );
    }

    #[test]
    fn bounded_policy_caps_attempts_deadline_and_each_sleep() {
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(2)).unwrap();
        let mut recovery =
            MockRecovery::new(std::iter::repeat_n(RecoveryAttempt::RuntimeActive, 20));
        let mut audit = MemoryAudit::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let sleeps = Rc::new(std::cell::RefCell::new(Vec::new()));
        assert_eq!(
            run_mock(
                policy,
                &mut recovery,
                &mut audit,
                Rc::clone(&elapsed),
                Rc::clone(&sleeps)
            ),
            Err(WatchdogFailure::Timeout)
        );
        assert!(recovery.attempts <= policy.max_attempts);
        assert!(elapsed.get() <= policy.deadline);
        assert!(
            sleeps
                .borrow()
                .iter()
                .all(|duration| *duration <= policy.retry_interval)
        );
        assert_eq!(
            sleeps.borrow().iter().copied().sum::<Duration>(),
            policy.deadline
        );
    }

    #[test]
    fn jsonl_final_record_has_required_safe_fields() {
        let roaming = unique_directory();
        fs::create_dir_all(&roaming).unwrap();
        let context = test_context(roaming.clone());
        let policy = WatchdogPolicy::new(Duration::from_secs(5), Duration::from_secs(1)).unwrap();
        let mut audit = AuditLog::create(&context, policy).unwrap();
        audit
            .record(
                AuditEvent::final_record(
                    AuditState::Timeout,
                    FinalStatus::Timeout,
                    ExitClass::Timeout,
                    None,
                ),
                ClockReading {
                    elapsed: policy.deadline,
                    utc_unix_ms: 1_700_000_000_000,
                },
            )
            .unwrap();
        let path = audit.path.clone();
        drop(audit);
        let line = fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        assert_eq!(value["schema"], WATCHDOG_AUDIT_SCHEMA);
        assert_eq!(value["version"], WATCHDOG_AUDIT_VERSION);
        assert!(
            value["watchdog_run_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        assert_eq!(value["elapsed_ms"], 5_000);
        assert_eq!(value["deadline_ms"], 5_000);
        assert_eq!(value["final_status"], "timeout");
        assert_eq!(value["exit_class"], "timeout");
        assert!(value.get("path").is_none());
        assert!(value.get("username").is_none());
        assert!(value.get("detail").is_none());
        fs::remove_dir_all(roaming).unwrap();
    }
}
