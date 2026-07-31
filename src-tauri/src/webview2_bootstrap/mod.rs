#![cfg_attr(not(any(target_os = "windows", test)), allow(dead_code))]

use std::path::Path;
use std::time::Duration;
use url::{Host, Url};

#[cfg(target_os = "windows")]
mod windows;

const OFFICIAL_BOOTSTRAPPER_URL: &str = "https://go.microsoft.com/fwlink/p/?LinkId=2124703";
const MICROSOFT_SIGNER_ORGANIZATION: &str = "Microsoft Corporation";
const INSTALL_ARGUMENTS: [&str; 2] = ["/silent", "/install"];
const SUCCESS_EXIT_CODE: u32 = 0;

const MAX_REDIRECTS: usize = 4;
const MAX_DOWNLOAD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCATION_HEADER_BYTES: usize = 8 * 1024;
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
const SEND_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const TOTAL_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(3 * 60);
const MUTEX_WAIT_TIMEOUT: Duration = Duration::from_secs(20 * 60);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const RUNTIME_DETECTION_POLL_INTERVAL: Duration = Duration::from_millis(250);

fn runtime_version_is_present(value: Option<&str>) -> bool {
    let Some(value) = value else {
        return false;
    };
    let value = value.trim();
    !value.is_empty() && value != "0.0.0.0"
}

fn registry_string_byte_length_is_valid(byte_len: usize, buffer_capacity: usize) -> bool {
    byte_len > 0 && byte_len <= buffer_capacity && byte_len % std::mem::size_of::<u16>() == 0
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DownloadTimeouts {
    resolve: Duration,
    connect: Duration,
    send: Duration,
    read: Duration,
    total: Duration,
}

impl DownloadTimeouts {
    const FIXED: Self = Self {
        resolve: RESOLVE_TIMEOUT,
        connect: CONNECT_TIMEOUT,
        send: SEND_TIMEOUT,
        read: READ_TIMEOUT,
        total: TOTAL_DOWNLOAD_TIMEOUT,
    };

    fn validate_elapsed(self, elapsed: Duration) -> Result<(), BootstrapError> {
        if elapsed >= self.total {
            Err(BootstrapError::DownloadTimeout)
        } else {
            Ok(())
        }
    }
}

fn remaining_call_timeout(
    total: Duration,
    elapsed: Duration,
    per_call: Duration,
) -> Result<Duration, BootstrapError> {
    if elapsed >= total {
        return Err(BootstrapError::DownloadTimeout);
    }
    let remaining = total.saturating_sub(elapsed);
    if remaining < Duration::from_millis(1) {
        return Err(BootstrapError::DownloadTimeout);
    }
    Ok(per_call.min(remaining))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DownloadLimits {
    max_bytes: u64,
    max_location_header_bytes: usize,
}

impl DownloadLimits {
    const FIXED: Self = Self {
        max_bytes: MAX_DOWNLOAD_BYTES,
        max_location_header_bytes: MAX_LOCATION_HEADER_BYTES,
    };

    fn validate_content_length(self, length: u64) -> Result<(), BootstrapError> {
        if length > self.max_bytes {
            Err(BootstrapError::DownloadTooLarge)
        } else {
            Ok(())
        }
    }

    fn add_chunk(self, downloaded: u64, chunk: usize) -> Result<u64, BootstrapError> {
        let total = downloaded
            .checked_add(chunk as u64)
            .ok_or(BootstrapError::DownloadTooLarge)?;
        self.validate_content_length(total)?;
        Ok(total)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DownloadPolicy {
    initial_url: &'static str,
    redirects: RedirectPolicy,
    limits: DownloadLimits,
    timeouts: DownloadTimeouts,
}

impl DownloadPolicy {
    const FIXED: Self = Self {
        initial_url: OFFICIAL_BOOTSTRAPPER_URL,
        redirects: RedirectPolicy {
            max_redirects: MAX_REDIRECTS,
        },
        limits: DownloadLimits::FIXED,
        timeouts: DownloadTimeouts::FIXED,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InstallPolicy {
    arguments: [&'static str; 2],
    timeout: Duration,
}

impl InstallPolicy {
    const FIXED: Self = Self {
        arguments: INSTALL_ARGUMENTS,
        timeout: INSTALL_TIMEOUT,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RedirectPolicy {
    max_redirects: usize,
}

impl RedirectPolicy {
    fn initial_url(self, raw: &str) -> Result<Url, BootstrapError> {
        let url = Url::parse(raw).map_err(|_| BootstrapError::DownloadUrl)?;
        self.validate(&url)?;
        Ok(url)
    }

    fn follow(
        self,
        current: &Url,
        location: &str,
        redirects_already_followed: usize,
    ) -> Result<Url, BootstrapError> {
        if redirects_already_followed >= self.max_redirects {
            return Err(BootstrapError::TooManyRedirects);
        }

        let next = current
            .join(location)
            .map_err(|_| BootstrapError::DownloadUrl.at_stage(BootstrapStage::HttpRedirect))?;
        self.validate(&next)
            .map_err(|error| error.at_stage(BootstrapStage::HttpRedirect))?;
        Ok(next)
    }

    fn validate(self, url: &Url) -> Result<(), BootstrapError> {
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.port().is_some_and(|port| port != 443)
        {
            return Err(BootstrapError::DownloadUrl);
        }

        let host = match url.host() {
            Some(Host::Domain(host)) => host.to_ascii_lowercase(),
            _ => return Err(BootstrapError::DownloadUrl),
        };
        if host != "go.microsoft.com"
            && host != "msedge.api.cdp.microsoft.com"
            && host != "download.microsoft.com"
            && !host.ends_with(".download.microsoft.com")
            && host != "dl.delivery.mp.microsoft.com"
            && !host.ends_with(".dl.delivery.mp.microsoft.com")
        {
            return Err(BootstrapError::RedirectDomain);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SignatureEvidence {
    Trusted { organization: String },
    Unsigned,
    Invalid,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootstrapErrorKind {
    RuntimeDetection,
    MutexAcquire,
    MutexRelease,
    ProgressWindow,
    DownloadUrl,
    RedirectDomain,
    TooManyRedirects,
    DownloadTooLarge,
    DownloadTimeout,
    DownloadFailed,
    TemporaryFile,
    SignatureInspection,
    SignatureRejected,
    InstallerLaunch,
    InstallerTimeout,
    InstallerFailed,
    RuntimeStillMissing,
    Cleanup,
}

impl BootstrapErrorKind {
    fn id(self) -> &'static str {
        match self {
            Self::RuntimeDetection => "runtime_detection",
            Self::MutexAcquire => "mutex_acquire",
            Self::MutexRelease => "mutex_release",
            Self::ProgressWindow => "progress_window",
            Self::DownloadUrl => "download_url",
            Self::RedirectDomain => "redirect_domain",
            Self::TooManyRedirects => "too_many_redirects",
            Self::DownloadTooLarge => "download_too_large",
            Self::DownloadTimeout => "download_timeout",
            Self::DownloadFailed => "download_failed",
            Self::TemporaryFile => "temporary_file",
            Self::SignatureInspection => "signature_inspection",
            Self::SignatureRejected => "signature_rejected",
            Self::InstallerLaunch => "installer_launch",
            Self::InstallerTimeout => "installer_timeout",
            Self::InstallerFailed => "installer_failed",
            Self::RuntimeStillMissing => "runtime_still_missing",
            Self::Cleanup => "cleanup",
        }
    }

    fn user_message(self) -> &'static str {
        match self {
            Self::DownloadUrl
            | Self::RedirectDomain
            | Self::TooManyRedirects
            | Self::DownloadTooLarge
            | Self::DownloadTimeout
            | Self::DownloadFailed
            | Self::TemporaryFile => {
                "运行环境下载失败。请检查网络连接后重试；如仍失败，请联系管理员。"
            }
            Self::SignatureInspection | Self::SignatureRejected => {
                "下载的运行环境安装程序未通过 Microsoft 签名验证。请稍后重试或联系管理员。"
            }
            Self::InstallerLaunch
            | Self::InstallerTimeout
            | Self::InstallerFailed
            | Self::RuntimeStillMissing => "运行环境安装失败。请重试；如仍失败，请联系管理员。",
            Self::RuntimeDetection
            | Self::MutexAcquire
            | Self::MutexRelease
            | Self::ProgressWindow
            | Self::Cleanup => "无法初始化 WebView2 运行环境。请重启应用；如仍失败，请联系管理员。",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootstrapStage {
    RuntimeInitialDetection,
    RuntimeLockedDetection,
    RuntimeRedetection,
    MutexCreate,
    MutexWait,
    MutexRelease,
    ProgressOpen,
    ProgressMessageLoop,
    ProgressClose,
    DownloadPolicy,
    WinHttpSession,
    WinHttpConnect,
    WinHttpRequestOpen,
    WinHttpRequestSend,
    WinHttpResponseReceive,
    HttpStatus,
    HttpRedirect,
    DownloadRead,
    TemporaryFileCreate,
    TemporaryFileWrite,
    TemporaryFileFlush,
    TemporaryFileLock,
    AuthenticodeVerify,
    AuthenticodeSigner,
    AuthenticodeClose,
    InstallerJobCreate,
    InstallerJobConfigure,
    InstallerCreateProcess,
    InstallerAssignJob,
    InstallerResume,
    InstallerWait,
    InstallerExit,
    InstallerJobDrain,
    InstallerTerminate,
    TemporaryFileCleanup,
}

impl BootstrapStage {
    fn id(self) -> &'static str {
        match self {
            Self::RuntimeInitialDetection => "runtime.initial_detection",
            Self::RuntimeLockedDetection => "runtime.locked_detection",
            Self::RuntimeRedetection => "runtime.redetection",
            Self::MutexCreate => "mutex.create",
            Self::MutexWait => "mutex.wait",
            Self::MutexRelease => "mutex.release",
            Self::ProgressOpen => "progress.open",
            Self::ProgressMessageLoop => "progress.message_loop",
            Self::ProgressClose => "progress.close",
            Self::DownloadPolicy => "download.policy",
            Self::WinHttpSession => "winhttp.session",
            Self::WinHttpConnect => "winhttp.connect",
            Self::WinHttpRequestOpen => "winhttp.request_open",
            Self::WinHttpRequestSend => "winhttp.request_send",
            Self::WinHttpResponseReceive => "winhttp.response_receive",
            Self::HttpStatus => "http.status",
            Self::HttpRedirect => "http.redirect",
            Self::DownloadRead => "download.read",
            Self::TemporaryFileCreate => "temporary_file.create",
            Self::TemporaryFileWrite => "temporary_file.write",
            Self::TemporaryFileFlush => "temporary_file.flush",
            Self::TemporaryFileLock => "temporary_file.lock",
            Self::AuthenticodeVerify => "authenticode.verify",
            Self::AuthenticodeSigner => "authenticode.signer",
            Self::AuthenticodeClose => "authenticode.close",
            Self::InstallerJobCreate => "installer.job_create",
            Self::InstallerJobConfigure => "installer.job_configure",
            Self::InstallerCreateProcess => "installer.create_process",
            Self::InstallerAssignJob => "installer.assign_job",
            Self::InstallerResume => "installer.resume",
            Self::InstallerWait => "installer.wait",
            Self::InstallerExit => "installer.exit",
            Self::InstallerJobDrain => "installer.job_drain",
            Self::InstallerTerminate => "installer.terminate",
            Self::TemporaryFileCleanup => "temporary_file.cleanup",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BootstrapSystemCode {
    Win32(u32),
    WinHttp(u32),
    HttpStatus(u32),
    WinTrust(i32),
    HResult(i32),
    InstallerExit(u32),
    WaitStatus(u32),
}

impl BootstrapSystemCode {
    fn render(self) -> String {
        match self {
            Self::Win32(code) => format!("win32:{code} (0x{code:08X})"),
            Self::WinHttp(code) => format!("winhttp:{code} (0x{code:08X})"),
            Self::HttpStatus(code) => format!("http_status:{code}"),
            Self::WinTrust(code) => format!("wintrust:0x{:08X}", code as u32),
            Self::HResult(code) => format!("hresult:0x{:08X}", code as u32),
            Self::InstallerExit(code) => format!("installer_exit:{code} (0x{code:08X})"),
            Self::WaitStatus(code) => format!("wait_status:{code} (0x{code:08X})"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BootstrapDiagnostic {
    kind: BootstrapErrorKind,
    stage: BootstrapStage,
    system_code: Option<BootstrapSystemCode>,
}

impl BootstrapDiagnostic {
    const fn new(kind: BootstrapErrorKind, stage: BootstrapStage) -> Self {
        Self {
            kind,
            stage,
            system_code: None,
        }
    }

    fn line(self, label: &str) -> String {
        let mut line = format!(
            "{label}: stage={}; category={}",
            self.stage.id(),
            self.kind.id()
        );
        if let Some(code) = self.system_code {
            line.push_str("; code=");
            line.push_str(&code.render());
        }
        line
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BootstrapError {
    primary: BootstrapDiagnostic,
    secondary: Option<BootstrapDiagnostic>,
}

#[allow(non_upper_case_globals)]
impl BootstrapError {
    const RuntimeDetection: Self = Self::new(
        BootstrapErrorKind::RuntimeDetection,
        BootstrapStage::RuntimeInitialDetection,
    );
    const MutexAcquire: Self =
        Self::new(BootstrapErrorKind::MutexAcquire, BootstrapStage::MutexWait);
    const MutexRelease: Self = Self::new(
        BootstrapErrorKind::MutexRelease,
        BootstrapStage::MutexRelease,
    );
    const ProgressWindow: Self = Self::new(
        BootstrapErrorKind::ProgressWindow,
        BootstrapStage::ProgressOpen,
    );
    const DownloadUrl: Self = Self::new(
        BootstrapErrorKind::DownloadUrl,
        BootstrapStage::DownloadPolicy,
    );
    const RedirectDomain: Self = Self::new(
        BootstrapErrorKind::RedirectDomain,
        BootstrapStage::HttpRedirect,
    );
    const TooManyRedirects: Self = Self::new(
        BootstrapErrorKind::TooManyRedirects,
        BootstrapStage::HttpRedirect,
    );
    const DownloadTooLarge: Self = Self::new(
        BootstrapErrorKind::DownloadTooLarge,
        BootstrapStage::DownloadRead,
    );
    const DownloadTimeout: Self = Self::new(
        BootstrapErrorKind::DownloadTimeout,
        BootstrapStage::DownloadRead,
    );
    const DownloadFailed: Self = Self::new(
        BootstrapErrorKind::DownloadFailed,
        BootstrapStage::DownloadRead,
    );
    const TemporaryFile: Self = Self::new(
        BootstrapErrorKind::TemporaryFile,
        BootstrapStage::TemporaryFileCreate,
    );
    const SignatureInspection: Self = Self::new(
        BootstrapErrorKind::SignatureInspection,
        BootstrapStage::AuthenticodeVerify,
    );
    const SignatureRejected: Self = Self::new(
        BootstrapErrorKind::SignatureRejected,
        BootstrapStage::AuthenticodeSigner,
    );
    const InstallerLaunch: Self = Self::new(
        BootstrapErrorKind::InstallerLaunch,
        BootstrapStage::InstallerCreateProcess,
    );
    const InstallerTimeout: Self = Self::new(
        BootstrapErrorKind::InstallerTimeout,
        BootstrapStage::InstallerWait,
    );
    const InstallerFailed: Self = Self::new(
        BootstrapErrorKind::InstallerFailed,
        BootstrapStage::InstallerExit,
    );
    const RuntimeStillMissing: Self = Self::new(
        BootstrapErrorKind::RuntimeStillMissing,
        BootstrapStage::RuntimeRedetection,
    );
    const Cleanup: Self = Self::new(
        BootstrapErrorKind::Cleanup,
        BootstrapStage::TemporaryFileCleanup,
    );

    const fn new(kind: BootstrapErrorKind, stage: BootstrapStage) -> Self {
        Self {
            primary: BootstrapDiagnostic::new(kind, stage),
            secondary: None,
        }
    }

    fn at_stage(mut self, stage: BootstrapStage) -> Self {
        self.primary.stage = stage;
        self
    }

    fn with_system_code(mut self, system_code: BootstrapSystemCode) -> Self {
        self.primary.system_code = Some(system_code);
        self
    }

    fn with_secondary(mut self, secondary: Self) -> Self {
        if self.secondary.is_none() {
            self.secondary = Some(secondary.primary);
        }
        self
    }

    fn kind(self) -> BootstrapErrorKind {
        self.primary.kind
    }

    fn stage(self) -> BootstrapStage {
        self.primary.stage
    }

    fn system_code(self) -> Option<BootstrapSystemCode> {
        self.primary.system_code
    }

    fn user_message(self) -> &'static str {
        self.primary.kind.user_message()
    }

    fn report_message(self) -> String {
        let mut message = format!(
            "{}\n\n{}",
            self.user_message(),
            self.primary.line("diagnostic")
        );
        if let Some(secondary) = self.secondary {
            message.push('\n');
            message.push_str(&secondary.line("secondary"));
        }
        message
    }
}

trait RuntimeDetector {
    fn is_installed(&mut self) -> Result<bool, BootstrapError>;
}

trait BootstrapClock {
    fn now(&mut self) -> Duration;
    fn sleep(&mut self, duration: Duration);
}

trait BootstrapMutex {
    fn acquire(&mut self, timeout: Duration) -> Result<(), BootstrapError>;
    fn release(&mut self) -> Result<(), BootstrapError>;
}

trait ProgressUi {
    fn open(&mut self) -> Result<(), BootstrapError>;
    fn close(&mut self) -> Result<(), BootstrapError>;
    fn show_error(&mut self, message: &str) -> Result<(), BootstrapError>;
}

trait InstallerArtifact {
    fn path(&self) -> &Path;

    fn native_handle(&self) -> Option<isize> {
        None
    }

    fn cleanup(&mut self) -> Result<(), BootstrapError>;
}

trait InstallerDownloader {
    fn download(
        &mut self,
        policy: DownloadPolicy,
    ) -> Result<Box<dyn InstallerArtifact>, BootstrapError>;
}

trait SignatureVerifier {
    fn verify(
        &mut self,
        artifact: &dyn InstallerArtifact,
    ) -> Result<SignatureEvidence, BootstrapError>;
}

trait SilentInstaller {
    fn install(
        &mut self,
        artifact: &dyn InstallerArtifact,
        policy: InstallPolicy,
    ) -> Result<u32, BootstrapError>;
}

struct BootstrapComponents<'a> {
    detector: &'a mut dyn RuntimeDetector,
    clock: &'a mut dyn BootstrapClock,
    mutex: &'a mut dyn BootstrapMutex,
    ui: &'a mut dyn ProgressUi,
    downloader: &'a mut dyn InstallerDownloader,
    verifier: &'a mut dyn SignatureVerifier,
    installer: &'a mut dyn SilentInstaller,
}

fn initialize_under_progress(
    components: &mut BootstrapComponents<'_>,
) -> Result<(), BootstrapError> {
    let mut artifact = components.downloader.download(DownloadPolicy::FIXED)?;

    let initialization = (|| {
        match components.verifier.verify(artifact.as_ref())? {
            SignatureEvidence::Trusted { organization }
                if organization == MICROSOFT_SIGNER_ORGANIZATION => {}
            SignatureEvidence::Trusted { .. }
            | SignatureEvidence::Unsigned
            | SignatureEvidence::Invalid => {
                return Err(
                    BootstrapError::SignatureRejected.at_stage(BootstrapStage::AuthenticodeSigner)
                );
            }
        }

        let install_started = components.clock.now();
        let exit_code = components
            .installer
            .install(artifact.as_ref(), InstallPolicy::FIXED)?;
        if exit_code != SUCCESS_EXIT_CODE {
            return Err(BootstrapError::InstallerFailed
                .with_system_code(BootstrapSystemCode::InstallerExit(exit_code)));
        }

        loop {
            if components
                .detector
                .is_installed()
                .map_err(|error| error.at_stage(BootstrapStage::RuntimeRedetection))?
            {
                break;
            }
            let elapsed = components.clock.now().saturating_sub(install_started);
            if elapsed >= InstallPolicy::FIXED.timeout {
                return Err(BootstrapError::RuntimeStillMissing);
            }
            components.clock.sleep(
                RUNTIME_DETECTION_POLL_INTERVAL
                    .min(InstallPolicy::FIXED.timeout.saturating_sub(elapsed)),
            );
        }
        Ok(())
    })();

    let cleanup = artifact.cleanup();
    match (initialization, cleanup) {
        (Err(error), Err(cleanup_error)) => Err(error.with_secondary(cleanup_error)),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(cleanup_error)) => Err(cleanup_error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn initialize_while_locked(components: &mut BootstrapComponents<'_>) -> Result<(), BootstrapError> {
    if components
        .detector
        .is_installed()
        .map_err(|error| error.at_stage(BootstrapStage::RuntimeLockedDetection))?
    {
        return Ok(());
    }

    components.ui.open()?;
    let initialization = initialize_under_progress(components);
    let close = components.ui.close();
    match (initialization, close) {
        (Err(error), Err(close_error)) => Err(error.with_secondary(close_error)),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(close_error)) => Err(close_error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn bootstrap(components: &mut BootstrapComponents<'_>) -> Result<(), BootstrapError> {
    if components
        .detector
        .is_installed()
        .map_err(|error| error.at_stage(BootstrapStage::RuntimeInitialDetection))?
    {
        return Ok(());
    }

    components.mutex.acquire(MUTEX_WAIT_TIMEOUT)?;
    let initialization = initialize_while_locked(components);
    let release = components.mutex.release();
    match (initialization, release) {
        (Err(error), Err(release_error)) => Err(error.with_secondary(release_error)),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(release_error)) => Err(release_error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn bootstrap_and_report(components: &mut BootstrapComponents<'_>) -> Result<(), BootstrapError> {
    match bootstrap(components) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = components.ui.close();
            let message = error.report_message();
            let _ = components.ui.show_error(&message);
            Err(error)
        }
    }
}

#[cfg(target_os = "windows")]
pub fn prepare_before_tauri() -> Result<(), ()> {
    windows::prepare_before_tauri().map_err(|_| ())
}

#[cfg(not(target_os = "windows"))]
pub fn prepare_before_tauri() -> Result<(), ()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier, Condvar, Mutex};
    use std::thread;
    use std::time::Instant;

    #[derive(Clone)]
    struct Shared(Rc<RefCell<FakeState>>);

    struct FakeState {
        calls: Vec<&'static str>,
        detections: VecDeque<Result<bool, BootstrapError>>,
        detection_fallback: Result<bool, BootstrapError>,
        clock_now: Duration,
        install_elapsed: Duration,
        signature: Result<SignatureEvidence, BootstrapError>,
        install: Result<u32, BootstrapError>,
        download: Result<(), BootstrapError>,
        cleanup: Result<(), BootstrapError>,
        partial_download_cleanup: bool,
        progress_open: bool,
        cleaned: bool,
        fixed_download_policy_seen: bool,
        fixed_install_policy_seen: bool,
        error_message: Option<String>,
    }

    impl Default for FakeState {
        fn default() -> Self {
            Self {
                calls: Vec::new(),
                detections: VecDeque::new(),
                detection_fallback: Err(BootstrapError::RuntimeDetection),
                clock_now: Duration::ZERO,
                install_elapsed: Duration::ZERO,
                signature: Ok(SignatureEvidence::Trusted {
                    organization: MICROSOFT_SIGNER_ORGANIZATION.to_owned(),
                }),
                install: Ok(SUCCESS_EXIT_CODE),
                download: Ok(()),
                cleanup: Ok(()),
                partial_download_cleanup: false,
                progress_open: false,
                cleaned: false,
                fixed_download_policy_seen: false,
                fixed_install_policy_seen: false,
                error_message: None,
            }
        }
    }

    struct FakeDetector(Shared);
    struct FakeClock(Shared);
    struct FakeMutex(Shared);
    struct FakeUi(Shared);
    struct FakeDownloader(Shared);
    struct FakeVerifier(Shared);
    struct FakeInstaller(Shared);

    struct FakeArtifact {
        shared: Shared,
        path: PathBuf,
        cleaned: bool,
    }

    impl Drop for FakeArtifact {
        fn drop(&mut self) {
            if !self.cleaned {
                let mut state = self.shared.0.borrow_mut();
                state.calls.push("drop_cleanup");
                state.cleaned = true;
            }
        }
    }

    impl InstallerArtifact for FakeArtifact {
        fn path(&self) -> &Path {
            &self.path
        }

        fn cleanup(&mut self) -> Result<(), BootstrapError> {
            if !self.cleaned {
                let mut state = self.shared.0.borrow_mut();
                state.calls.push("cleanup");
                if let Err(error) = state.cleanup {
                    return Err(error);
                }
                state.cleaned = true;
                self.cleaned = true;
            }
            Ok(())
        }
    }

    impl RuntimeDetector for FakeDetector {
        fn is_installed(&mut self) -> Result<bool, BootstrapError> {
            let mut state = self.0.0.borrow_mut();
            state.calls.push("detect");
            state
                .detections
                .pop_front()
                .unwrap_or_else(|| state.detection_fallback)
        }
    }

    impl BootstrapClock for FakeClock {
        fn now(&mut self) -> Duration {
            self.0.0.borrow().clock_now
        }

        fn sleep(&mut self, duration: Duration) {
            self.0.0.borrow_mut().clock_now += duration;
        }
    }

    impl BootstrapMutex for FakeMutex {
        fn acquire(&mut self, timeout: Duration) -> Result<(), BootstrapError> {
            assert_eq!(timeout, MUTEX_WAIT_TIMEOUT);
            self.0.0.borrow_mut().calls.push("lock");
            Ok(())
        }

        fn release(&mut self) -> Result<(), BootstrapError> {
            self.0.0.borrow_mut().calls.push("unlock");
            Ok(())
        }
    }

    impl ProgressUi for FakeUi {
        fn open(&mut self) -> Result<(), BootstrapError> {
            let mut state = self.0.0.borrow_mut();
            state.calls.push("ui_open");
            state.progress_open = true;
            Ok(())
        }

        fn close(&mut self) -> Result<(), BootstrapError> {
            let mut state = self.0.0.borrow_mut();
            if state.progress_open {
                state.calls.push("ui_close");
                state.progress_open = false;
            }
            Ok(())
        }

        fn show_error(&mut self, message: &str) -> Result<(), BootstrapError> {
            assert!(!message.is_empty());
            let mut state = self.0.0.borrow_mut();
            state.calls.push("error_dialog");
            state.error_message = Some(message.to_owned());
            Ok(())
        }
    }

    impl InstallerDownloader for FakeDownloader {
        fn download(
            &mut self,
            policy: DownloadPolicy,
        ) -> Result<Box<dyn InstallerArtifact>, BootstrapError> {
            let mut state = self.0.0.borrow_mut();
            state.calls.push("download");
            state.fixed_download_policy_seen =
                policy == DownloadPolicy::FIXED && policy.initial_url == OFFICIAL_BOOTSTRAPPER_URL;
            if let Err(error) = state.download {
                state.calls.push("partial_cleanup");
                state.partial_download_cleanup = true;
                return Err(error);
            }
            drop(state);
            Ok(Box::new(FakeArtifact {
                shared: self.0.clone(),
                path: PathBuf::from("fake-webview2-bootstrapper.exe"),
                cleaned: false,
            }))
        }
    }

    impl SignatureVerifier for FakeVerifier {
        fn verify(
            &mut self,
            artifact: &dyn InstallerArtifact,
        ) -> Result<SignatureEvidence, BootstrapError> {
            assert_eq!(artifact.path(), Path::new("fake-webview2-bootstrapper.exe"));
            let mut state = self.0.0.borrow_mut();
            state.calls.push("verify");
            state.signature.clone()
        }
    }

    impl SilentInstaller for FakeInstaller {
        fn install(
            &mut self,
            artifact: &dyn InstallerArtifact,
            policy: InstallPolicy,
        ) -> Result<u32, BootstrapError> {
            assert_eq!(artifact.path(), Path::new("fake-webview2-bootstrapper.exe"));
            let mut state = self.0.0.borrow_mut();
            state.calls.push("install");
            state.fixed_install_policy_seen = policy == InstallPolicy::FIXED
                && policy.arguments == ["/silent", "/install"]
                && policy.timeout == INSTALL_TIMEOUT;
            let install_elapsed = state.install_elapsed;
            state.clock_now += install_elapsed;
            state.install
        }
    }

    struct Harness {
        shared: Shared,
        detector: FakeDetector,
        clock: FakeClock,
        mutex: FakeMutex,
        ui: FakeUi,
        downloader: FakeDownloader,
        verifier: FakeVerifier,
        installer: FakeInstaller,
    }

    impl Harness {
        fn new(detections: impl IntoIterator<Item = Result<bool, BootstrapError>>) -> Self {
            let shared = Shared(Rc::new(RefCell::new(FakeState {
                detections: detections.into_iter().collect(),
                ..FakeState::default()
            })));
            Self {
                detector: FakeDetector(shared.clone()),
                clock: FakeClock(shared.clone()),
                mutex: FakeMutex(shared.clone()),
                ui: FakeUi(shared.clone()),
                downloader: FakeDownloader(shared.clone()),
                verifier: FakeVerifier(shared.clone()),
                installer: FakeInstaller(shared.clone()),
                shared,
            }
        }

        fn run(&mut self) -> Result<(), BootstrapError> {
            bootstrap_and_report(&mut BootstrapComponents {
                detector: &mut self.detector,
                clock: &mut self.clock,
                mutex: &mut self.mutex,
                ui: &mut self.ui,
                downloader: &mut self.downloader,
                verifier: &mut self.verifier,
                installer: &mut self.installer,
            })
        }

        fn calls(&self) -> Vec<&'static str> {
            self.shared.0.borrow().calls.clone()
        }
    }

    struct ConcurrentState {
        installed: AtomicBool,
        first_detection_barrier: Barrier,
        lock_busy: Mutex<bool>,
        lock_changed: Condvar,
        downloads: AtomicUsize,
        installs: AtomicUsize,
        cleanups: AtomicUsize,
    }

    impl ConcurrentState {
        fn new() -> Self {
            Self {
                installed: AtomicBool::new(false),
                first_detection_barrier: Barrier::new(2),
                lock_busy: Mutex::new(false),
                lock_changed: Condvar::new(),
                downloads: AtomicUsize::new(0),
                installs: AtomicUsize::new(0),
                cleanups: AtomicUsize::new(0),
            }
        }
    }

    struct ConcurrentDetector {
        state: Arc<ConcurrentState>,
        first: bool,
    }

    impl RuntimeDetector for ConcurrentDetector {
        fn is_installed(&mut self) -> Result<bool, BootstrapError> {
            let installed = self.state.installed.load(Ordering::SeqCst);
            if self.first {
                self.first = false;
                self.state.first_detection_barrier.wait();
            }
            Ok(installed)
        }
    }

    struct ConcurrentClock(Instant);

    impl BootstrapClock for ConcurrentClock {
        fn now(&mut self) -> Duration {
            self.0.elapsed()
        }

        fn sleep(&mut self, duration: Duration) {
            thread::sleep(duration);
        }
    }

    struct ConcurrentMutex {
        state: Arc<ConcurrentState>,
        owned: bool,
    }

    impl BootstrapMutex for ConcurrentMutex {
        fn acquire(&mut self, timeout: Duration) -> Result<(), BootstrapError> {
            let busy = self
                .state
                .lock_busy
                .lock()
                .map_err(|_| BootstrapError::MutexAcquire)?;
            let (mut busy, wait) = self
                .state
                .lock_changed
                .wait_timeout_while(busy, timeout, |busy| *busy)
                .map_err(|_| BootstrapError::MutexAcquire)?;
            if wait.timed_out() && *busy {
                return Err(BootstrapError::MutexAcquire);
            }
            *busy = true;
            self.owned = true;
            Ok(())
        }

        fn release(&mut self) -> Result<(), BootstrapError> {
            if !self.owned {
                return Err(BootstrapError::MutexRelease);
            }
            let mut busy = self
                .state
                .lock_busy
                .lock()
                .map_err(|_| BootstrapError::MutexRelease)?;
            *busy = false;
            self.owned = false;
            self.state.lock_changed.notify_one();
            Ok(())
        }
    }

    #[derive(Default)]
    struct ConcurrentUi {
        open: bool,
    }

    impl ProgressUi for ConcurrentUi {
        fn open(&mut self) -> Result<(), BootstrapError> {
            self.open = true;
            Ok(())
        }

        fn close(&mut self) -> Result<(), BootstrapError> {
            self.open = false;
            Ok(())
        }

        fn show_error(&mut self, _message: &str) -> Result<(), BootstrapError> {
            Ok(())
        }
    }

    struct ConcurrentArtifact {
        state: Arc<ConcurrentState>,
        path: PathBuf,
        cleaned: bool,
    }

    impl InstallerArtifact for ConcurrentArtifact {
        fn path(&self) -> &Path {
            &self.path
        }

        fn cleanup(&mut self) -> Result<(), BootstrapError> {
            if !self.cleaned {
                self.cleaned = true;
                self.state.cleanups.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    struct ConcurrentDownloader(Arc<ConcurrentState>);

    impl InstallerDownloader for ConcurrentDownloader {
        fn download(
            &mut self,
            policy: DownloadPolicy,
        ) -> Result<Box<dyn InstallerArtifact>, BootstrapError> {
            assert_eq!(policy, DownloadPolicy::FIXED);
            self.0.downloads.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(ConcurrentArtifact {
                state: self.0.clone(),
                path: PathBuf::from("concurrent-bootstrapper.exe"),
                cleaned: false,
            }))
        }
    }

    struct ConcurrentVerifier;

    impl SignatureVerifier for ConcurrentVerifier {
        fn verify(
            &mut self,
            _artifact: &dyn InstallerArtifact,
        ) -> Result<SignatureEvidence, BootstrapError> {
            Ok(SignatureEvidence::Trusted {
                organization: MICROSOFT_SIGNER_ORGANIZATION.to_owned(),
            })
        }
    }

    struct ConcurrentInstaller(Arc<ConcurrentState>);

    impl SilentInstaller for ConcurrentInstaller {
        fn install(
            &mut self,
            _artifact: &dyn InstallerArtifact,
            policy: InstallPolicy,
        ) -> Result<u32, BootstrapError> {
            assert_eq!(policy, InstallPolicy::FIXED);
            self.0.installs.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(20));
            self.0.installed.store(true, Ordering::SeqCst);
            Ok(SUCCESS_EXIT_CODE)
        }
    }

    fn run_concurrent_bootstrap(state: Arc<ConcurrentState>) -> Result<(), BootstrapError> {
        let mut detector = ConcurrentDetector {
            state: state.clone(),
            first: true,
        };
        let mut clock = ConcurrentClock(Instant::now());
        let mut mutex = ConcurrentMutex {
            state: state.clone(),
            owned: false,
        };
        let mut ui = ConcurrentUi::default();
        let mut downloader = ConcurrentDownloader(state.clone());
        let mut verifier = ConcurrentVerifier;
        let mut installer = ConcurrentInstaller(state);
        bootstrap_and_report(&mut BootstrapComponents {
            detector: &mut detector,
            clock: &mut clock,
            mutex: &mut mutex,
            ui: &mut ui,
            downloader: &mut downloader,
            verifier: &mut verifier,
            installer: &mut installer,
        })
    }

    #[test]
    fn installed_runtime_is_a_strict_fast_path() {
        let mut harness = Harness::new([Ok(true)]);

        assert_eq!(harness.run(), Ok(()));
        assert_eq!(harness.calls(), ["detect"]);
    }

    #[test]
    fn missing_runtime_runs_the_complete_initialization_flow() {
        let mut harness = Harness::new([Ok(false), Ok(false), Ok(true)]);

        assert_eq!(harness.run(), Ok(()));
        assert_eq!(
            harness.calls(),
            [
                "detect", "lock", "detect", "ui_open", "download", "verify", "install", "detect",
                "cleanup", "ui_close", "unlock"
            ]
        );
        let state = harness.shared.0.borrow();
        assert!(state.cleaned);
        assert!(state.fixed_download_policy_seen);
        assert!(state.fixed_install_policy_seen);
    }

    #[test]
    fn concurrent_instance_rechecks_after_lock_and_does_not_install_twice() {
        let mut harness = Harness::new([Ok(false), Ok(true)]);

        assert_eq!(harness.run(), Ok(()));
        assert_eq!(harness.calls(), ["detect", "lock", "detect", "unlock"]);
    }

    #[test]
    fn two_concurrent_bootstraps_download_and_install_only_once() {
        let state = Arc::new(ConcurrentState::new());
        let first_state = state.clone();
        let second_state = state.clone();
        let first = thread::spawn(move || run_concurrent_bootstrap(first_state));
        let second = thread::spawn(move || run_concurrent_bootstrap(second_state));

        assert_eq!(first.join().expect("first bootstrap thread"), Ok(()));
        assert_eq!(second.join().expect("second bootstrap thread"), Ok(()));
        assert_eq!(state.downloads.load(Ordering::SeqCst), 1);
        assert_eq!(state.installs.load(Ordering::SeqCst), 1);
        assert_eq!(state.cleanups.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn non_https_url_is_rejected() {
        let policy = DownloadPolicy::FIXED.redirects;
        assert_eq!(
            policy.initial_url("http://go.microsoft.com/bootstrapper.exe"),
            Err(BootstrapError::DownloadUrl)
        );
    }

    #[test]
    fn non_microsoft_redirect_domain_is_rejected() {
        let policy = DownloadPolicy::FIXED.redirects;
        let current = policy
            .initial_url(OFFICIAL_BOOTSTRAPPER_URL)
            .expect("fixed URL must be valid");

        assert_eq!(
            policy.follow(&current, "https://microsoft.com.example.test/setup.exe", 0),
            Err(BootstrapError::RedirectDomain)
        );
        assert_eq!(
            policy.follow(&current, "https://example.test/microsoft.com/setup.exe", 0),
            Err(BootstrapError::RedirectDomain)
        );
        assert_eq!(
            policy.follow(&current, "https://evil-microsoft.com/setup.exe", 0),
            Err(BootstrapError::RedirectDomain)
        );
        assert_eq!(
            policy.follow(
                &current,
                "https://dl.delivery.mp.microsoft.com.example.test/setup.exe",
                0,
            ),
            Err(BootstrapError::RedirectDomain)
        );
        assert_eq!(
            policy.follow(
                &current,
                "https://user@msedge.sf.dl.delivery.mp.microsoft.com/setup.exe",
                0,
            ),
            Err(BootstrapError::DownloadUrl.at_stage(BootstrapStage::HttpRedirect))
        );
        assert_eq!(
            policy.follow(
                &current,
                "https://msedge.sf.dl.delivery.mp.microsoft.com:444/setup.exe",
                0,
            ),
            Err(BootstrapError::DownloadUrl.at_stage(BootstrapStage::HttpRedirect))
        );
    }

    #[test]
    fn microsoft_https_redirect_is_accepted() {
        let policy = DownloadPolicy::FIXED.redirects;
        let current = policy
            .initial_url(OFFICIAL_BOOTSTRAPPER_URL)
            .expect("fixed URL must be valid");
        let redirect = policy
            .follow(
                &current,
                "https://msedge.sf.dl.delivery.mp.microsoft.com/files/setup.exe",
                0,
            )
            .expect("Microsoft HTTPS redirect should pass");

        assert_eq!(
            redirect.host_str(),
            Some("msedge.sf.dl.delivery.mp.microsoft.com")
        );
    }

    #[test]
    fn redirect_count_is_bounded() {
        let policy = DownloadPolicy::FIXED.redirects;
        let current = policy
            .initial_url(OFFICIAL_BOOTSTRAPPER_URL)
            .expect("fixed URL must be valid");

        assert_eq!(
            policy.follow(
                &current,
                "https://download.microsoft.com/setup.exe",
                MAX_REDIRECTS,
            ),
            Err(BootstrapError::TooManyRedirects)
        );
    }

    #[test]
    fn download_size_is_bounded_for_headers_and_streaming() {
        let limits = DownloadLimits::FIXED;
        assert_eq!(limits.validate_content_length(MAX_DOWNLOAD_BYTES), Ok(()));
        assert_eq!(
            limits.validate_content_length(MAX_DOWNLOAD_BYTES + 1),
            Err(BootstrapError::DownloadTooLarge)
        );
        assert_eq!(
            limits.add_chunk(MAX_DOWNLOAD_BYTES - 1, 2),
            Err(BootstrapError::DownloadTooLarge)
        );
    }

    #[test]
    fn connection_read_and_total_timeouts_are_finite_and_total_is_enforced() {
        let timeouts = DownloadTimeouts::FIXED;
        assert!(timeouts.resolve > Duration::ZERO);
        assert!(timeouts.connect > Duration::ZERO);
        assert!(timeouts.send > Duration::ZERO);
        assert!(timeouts.read > Duration::ZERO);
        assert!(timeouts.total > timeouts.connect);
        assert_eq!(
            timeouts.validate_elapsed(timeouts.total),
            Err(BootstrapError::DownloadTimeout)
        );
        assert_eq!(
            remaining_call_timeout(
                timeouts.total,
                timeouts.total - Duration::from_millis(5),
                timeouts.read,
            ),
            Ok(Duration::from_millis(5))
        );
        assert_eq!(
            remaining_call_timeout(
                timeouts.total,
                timeouts.total - Duration::from_nanos(1),
                timeouts.read,
            ),
            Err(BootstrapError::DownloadTimeout)
        );
    }

    #[test]
    fn unsigned_installer_is_rejected_and_cleaned() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        harness.shared.0.borrow_mut().signature = Ok(SignatureEvidence::Unsigned);

        assert_eq!(harness.run(), Err(BootstrapError::SignatureRejected));
        assert_eq!(
            harness.calls(),
            [
                "detect",
                "lock",
                "detect",
                "ui_open",
                "download",
                "verify",
                "cleanup",
                "ui_close",
                "unlock",
                "error_dialog"
            ]
        );
    }

    #[test]
    fn invalid_signature_chain_is_rejected() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        harness.shared.0.borrow_mut().signature = Ok(SignatureEvidence::Invalid);

        assert_eq!(harness.run(), Err(BootstrapError::SignatureRejected));
        assert!(!harness.calls().contains(&"install"));
    }

    #[test]
    fn forged_microsoft_lookalike_signer_is_rejected() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        harness.shared.0.borrow_mut().signature = Ok(SignatureEvidence::Trusted {
            organization: "Microsoft Corporation LLC".to_owned(),
        });

        assert_eq!(harness.run(), Err(BootstrapError::SignatureRejected));
        assert!(!harness.calls().contains(&"install"));
    }

    #[test]
    fn non_microsoft_signer_is_rejected() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        harness.shared.0.borrow_mut().signature = Ok(SignatureEvidence::Trusted {
            organization: "Example Software, Inc.".to_owned(),
        });

        assert_eq!(harness.run(), Err(BootstrapError::SignatureRejected));
        assert!(!harness.calls().contains(&"install"));
    }

    #[test]
    fn installer_non_success_exit_code_is_rejected() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        harness.shared.0.borrow_mut().install = Ok(3010);

        let error = harness.run().expect_err("installer exit must fail");
        assert_eq!(error.kind(), BootstrapErrorKind::InstallerFailed);
        assert_eq!(error.stage(), BootstrapStage::InstallerExit);
        assert_eq!(
            error.system_code(),
            Some(BootstrapSystemCode::InstallerExit(3010))
        );
        assert_eq!(
            harness.calls(),
            [
                "detect",
                "lock",
                "detect",
                "ui_open",
                "download",
                "verify",
                "install",
                "cleanup",
                "ui_close",
                "unlock",
                "error_dialog"
            ]
        );
        let message = harness
            .shared
            .0
            .borrow()
            .error_message
            .clone()
            .expect("native diagnostic message");
        assert!(message.contains("stage=installer.exit"));
        assert!(message.contains("category=installer_failed"));
        assert!(message.contains("code=installer_exit:3010 (0x00000BC2)"));
        assert!(!message.contains(OFFICIAL_BOOTSTRAPPER_URL));
        assert!(!message.contains("fake-webview2-bootstrapper.exe"));
    }

    #[test]
    fn installer_timeout_is_rejected_and_cleaned() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        harness.shared.0.borrow_mut().install = Err(BootstrapError::InstallerTimeout);

        assert_eq!(harness.run(), Err(BootstrapError::InstallerTimeout));
        assert!(harness.shared.0.borrow().cleaned);
        assert!(!harness.shared.0.borrow().progress_open);
    }

    #[test]
    fn successful_exit_without_runtime_is_failure() {
        let mut harness = Harness::new([Ok(false), Ok(false), Ok(false)]);
        {
            let mut state = harness.shared.0.borrow_mut();
            state.detection_fallback = Ok(false);
            state.install_elapsed = INSTALL_TIMEOUT;
        }

        assert_eq!(harness.run(), Err(BootstrapError::RuntimeStillMissing));
        assert!(harness.shared.0.borrow().cleaned);
        assert!(!harness.shared.0.borrow().progress_open);
    }

    #[test]
    fn successful_installer_waits_for_runtime_to_appear() {
        let mut harness = Harness::new([Ok(false), Ok(false), Ok(false), Ok(true)]);

        assert_eq!(harness.run(), Ok(()));
        assert_eq!(
            harness
                .calls()
                .iter()
                .filter(|call| **call == "detect")
                .count(),
            4
        );
        assert_eq!(
            harness.shared.0.borrow().clock_now,
            RUNTIME_DETECTION_POLL_INTERVAL
        );
    }

    #[test]
    fn download_failure_cleans_partial_file_and_closes_window() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        harness.shared.0.borrow_mut().download = Err(BootstrapError::DownloadTimeout);

        assert_eq!(harness.run(), Err(BootstrapError::DownloadTimeout));
        let state = harness.shared.0.borrow();
        assert!(state.partial_download_cleanup);
        assert!(!state.progress_open);
        assert_eq!(
            state.calls,
            [
                "detect",
                "lock",
                "detect",
                "ui_open",
                "download",
                "partial_cleanup",
                "ui_close",
                "unlock",
                "error_dialog"
            ]
        );
    }

    #[test]
    fn cleanup_failure_is_fatal_and_drop_retries_before_ui_closes() {
        let mut harness = Harness::new([Ok(false), Ok(false), Ok(true)]);
        harness.shared.0.borrow_mut().cleanup = Err(BootstrapError::Cleanup);

        assert_eq!(harness.run(), Err(BootstrapError::Cleanup));
        assert_eq!(
            harness.calls(),
            [
                "detect",
                "lock",
                "detect",
                "ui_open",
                "download",
                "verify",
                "install",
                "detect",
                "cleanup",
                "drop_cleanup",
                "ui_close",
                "unlock",
                "error_dialog"
            ]
        );
    }

    #[test]
    fn operation_failure_keeps_primary_when_cleanup_also_fails() {
        let mut harness = Harness::new([Ok(false), Ok(false)]);
        {
            let mut state = harness.shared.0.borrow_mut();
            state.install = Err(BootstrapError::InstallerLaunch
                .at_stage(BootstrapStage::InstallerCreateProcess)
                .with_system_code(BootstrapSystemCode::Win32(32)));
            state.cleanup =
                Err(BootstrapError::Cleanup.with_system_code(BootstrapSystemCode::Win32(5)));
        }

        let error = harness.run().expect_err("operation and cleanup must fail");
        assert_eq!(error.kind(), BootstrapErrorKind::InstallerLaunch);
        assert_eq!(error.stage(), BootstrapStage::InstallerCreateProcess);
        assert_eq!(error.system_code(), Some(BootstrapSystemCode::Win32(32)));
        assert_eq!(
            error.secondary,
            Some(BootstrapDiagnostic {
                kind: BootstrapErrorKind::Cleanup,
                stage: BootstrapStage::TemporaryFileCleanup,
                system_code: Some(BootstrapSystemCode::Win32(5)),
            })
        );
        let message = harness
            .shared
            .0
            .borrow()
            .error_message
            .clone()
            .expect("native diagnostic message");
        assert!(message.contains(
            "diagnostic: stage=installer.create_process; category=installer_launch; \
             code=win32:32 (0x00000020)"
        ));
        assert!(message.contains(
            "secondary: stage=temporary_file.cleanup; category=cleanup; \
             code=win32:5 (0x00000005)"
        ));
    }

    #[test]
    fn detector_failure_shows_native_error_boundary_without_progress() {
        let mut harness = Harness::new([Err(BootstrapError::RuntimeDetection)]);

        let error = harness.run().expect_err("initial detection must fail");
        assert_eq!(error.kind(), BootstrapErrorKind::RuntimeDetection);
        assert_eq!(error.stage(), BootstrapStage::RuntimeInitialDetection);
        assert_eq!(harness.calls(), ["detect", "error_dialog"]);
    }

    #[test]
    fn detector_failures_identify_locked_and_post_install_phases() {
        let mut locked = Harness::new([
            Ok(false),
            Err(BootstrapError::RuntimeDetection.with_system_code(BootstrapSystemCode::Win32(5))),
        ]);
        let locked_error = locked.run().expect_err("locked detection must fail");
        assert_eq!(locked_error.stage(), BootstrapStage::RuntimeLockedDetection);
        assert_eq!(
            locked_error.system_code(),
            Some(BootstrapSystemCode::Win32(5))
        );

        let mut post_install = Harness::new([
            Ok(false),
            Ok(false),
            Err(BootstrapError::RuntimeDetection.with_system_code(BootstrapSystemCode::Win32(2))),
        ]);
        let post_install_error = post_install
            .run()
            .expect_err("post-install detection must fail");
        assert_eq!(
            post_install_error.stage(),
            BootstrapStage::RuntimeRedetection
        );
        assert_eq!(
            post_install_error.system_code(),
            Some(BootstrapSystemCode::Win32(2))
        );
    }

    #[test]
    fn diagnostic_codes_have_stable_bounded_rendering() {
        let cases = [
            (
                BootstrapError::DownloadFailed
                    .at_stage(BootstrapStage::WinHttpConnect)
                    .with_system_code(BootstrapSystemCode::WinHttp(12_002)),
                "code=winhttp:12002 (0x00002EE2)",
            ),
            (
                BootstrapError::DownloadFailed
                    .at_stage(BootstrapStage::HttpStatus)
                    .with_system_code(BootstrapSystemCode::HttpStatus(503)),
                "code=http_status:503",
            ),
            (
                BootstrapError::SignatureRejected
                    .at_stage(BootstrapStage::AuthenticodeVerify)
                    .with_system_code(BootstrapSystemCode::WinTrust(0x800B0109u32 as i32)),
                "code=wintrust:0x800B0109",
            ),
            (
                BootstrapError::TemporaryFile
                    .at_stage(BootstrapStage::TemporaryFileCreate)
                    .with_system_code(BootstrapSystemCode::HResult(0x80004005u32 as i32)),
                "code=hresult:0x80004005",
            ),
            (
                BootstrapError::InstallerLaunch
                    .at_stage(BootstrapStage::InstallerWait)
                    .with_system_code(BootstrapSystemCode::WaitStatus(0xFFFF_FFFF)),
                "code=wait_status:4294967295 (0xFFFFFFFF)",
            ),
            (
                BootstrapError::ProgressWindow
                    .at_stage(BootstrapStage::ProgressMessageLoop)
                    .with_system_code(BootstrapSystemCode::Win32(87)),
                "diagnostic: stage=progress.message_loop; category=progress_window; \
                 code=win32:87 (0x00000057)",
            ),
        ];

        for (error, expected) in cases {
            let message = error.report_message();
            assert!(message.contains(expected));
            assert!(!message.contains(OFFICIAL_BOOTSTRAPPER_URL));
            assert!(!message.contains("fake-webview2-bootstrapper.exe"));
            assert!(!message.contains(MICROSOFT_SIGNER_ORGANIZATION));
        }
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn non_windows_public_entry_is_a_noop() {
        assert_eq!(prepare_before_tauri(), Ok(()));
    }

    #[test]
    fn runtime_registry_version_requires_a_real_nonzero_pv() {
        assert!(!registry_string_byte_length_is_valid(0, 512));
        assert!(!registry_string_byte_length_is_valid(1, 512));
        assert!(registry_string_byte_length_is_valid(2, 512));
        assert!(registry_string_byte_length_is_valid(512, 512));
        assert!(!registry_string_byte_length_is_valid(513, 512));
        assert!(!registry_string_byte_length_is_valid(514, 512));
        assert!(!runtime_version_is_present(None));
        assert!(!runtime_version_is_present(Some("")));
        assert!(!runtime_version_is_present(Some("   ")));
        assert!(!runtime_version_is_present(Some("0.0.0.0")));
        assert!(!runtime_version_is_present(Some(" 0.0.0.0 ")));
        assert!(runtime_version_is_present(Some("138.0.3351.121")));
    }
}
