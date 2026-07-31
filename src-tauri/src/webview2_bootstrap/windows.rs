use super::{
    BootstrapClock, BootstrapComponents, BootstrapError, BootstrapMutex, BootstrapStage,
    BootstrapSystemCode, DownloadPolicy, InstallPolicy, InstallerArtifact, InstallerDownloader,
    ProgressUi, RuntimeDetector, SignatureEvidence, SignatureVerifier, SilentInstaller,
    bootstrap_and_report, registry_string_byte_length_is_valid, remaining_call_timeout,
    runtime_version_is_present,
};
use std::ffi::{OsStr, OsString, c_void};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::mpsc::{self, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use url::Url;
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, ERROR_ALREADY_EXISTS, ERROR_CLASS_ALREADY_EXISTS,
    ERROR_FILE_NOT_FOUND, ERROR_INSUFFICIENT_BUFFER, ERROR_PATH_NOT_FOUND, ERROR_SUCCESS,
    GENERIC_READ, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_ABANDONED, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Graphics::Gdi::{
    COLOR_WINDOW, DEFAULT_GUI_FONT, GetStockObject, GetSysColorBrush, UpdateWindow,
};
use windows_sys::Win32::Networking::WinHttp::{
    ERROR_WINHTTP_HEADER_NOT_FOUND, ERROR_WINHTTP_TIMEOUT, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_FLAG_SECURE, WINHTTP_FLAG_SECURE_DEFAULTS, WINHTTP_OPEN_REQUEST_FLAGS,
    WINHTTP_OPTION_CONNECT_RETRIES, WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,
    WINHTTP_OPTION_REDIRECT_POLICY, WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
    WINHTTP_OPTION_REJECT_USERPWD_IN_URL, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_LOCATION, WINHTTP_QUERY_STATUS_CODE, WinHttpCloseHandle, WinHttpConnect,
    WinHttpOpen, WinHttpOpenRequest, WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse,
    WinHttpSendRequest, WinHttpSetOption, WinHttpSetTimeouts,
};
use windows_sys::Win32::Security::Cryptography::{
    CERT_NAME_ATTR_TYPE, CertGetNameStringW, szOID_ORGANIZATION_NAME,
};
use windows_sys::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_DISABLE_MD2_MD4, WTD_MOTW, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
    WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
    WTD_UICONTEXT_INSTALL, WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain,
    WTHelperProvDataFromStateData, WinVerifyTrust,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_TEMPORARY, FILE_SHARE_READ, GetTempPathW,
};
use windows_sys::Win32::System::Com::CoCreateGuid;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_32KEY, KEY_WOW64_64KEY,
    REG_VALUE_TYPE, RRF_RT_REG_SZ, RRF_ZEROONFAILURE, RegCloseKey, RegGetValueW, RegOpenKeyExW,
};
use windows_sys::Win32::System::SystemServices::{SS_CENTER, SS_CENTERIMAGE};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateMutexW, CreateProcessW, GetCurrentProcess,
    GetExitCodeProcess, PROCESS_INFORMATION, ReleaseMutex, ResumeThread, STARTF_USESHOWWINDOW,
    STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};
use windows_sys::Win32::UI::Controls::{
    ICC_PROGRESS_CLASS, INITCOMMONCONTROLSEX, InitCommonControlsEx, PBM_SETMARQUEE, PBS_MARQUEE,
    PROGRESS_CLASSW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CS_HREDRAW, CS_VREDRAW, CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW,
    GetMessageW, GetSystemMetrics, IDC_WAIT, LoadCursorW, MB_ICONERROR, MB_OK, MB_TASKMODAL, MSG,
    MessageBoxW, PostMessageW, PostQuitMessage, PostThreadMessageW, RegisterClassW, SM_CXSCREEN,
    SM_CYSCREEN, SW_HIDE, SW_SHOWNORMAL, SendMessageW, ShowWindow, TranslateMessage, WM_APP,
    WM_CLOSE, WM_DESTROY, WM_QUIT, WM_SETFONT, WNDCLASSW, WS_CAPTION, WS_CHILD,
    WS_EX_DLGMODALFRAME, WS_OVERLAPPED, WS_VISIBLE,
};
use windows_sys::core::GUID;

const WEBVIEW2_CLIENT_KEY: &str =
    r"SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}";
const WEBVIEW2_MUTEX_NAME: &str = r"Local\dev.shadowsocks-windows-rs.webview2-bootstrap.v1";
const WINDOW_CLASS_NAME: &str = "dev.shadowsocks-windows-rs.webview2-bootstrap.progress.v1";
const WINDOW_TITLE: &str = "Shadowsocks 初始化";
const PROGRESS_TEXT: &str = "正在初始化运行环境，请稍候…";
const ERROR_TITLE: &str = "Shadowsocks 初始化失败";
const CLOSE_PROGRESS_MESSAGE: u32 = WM_APP + 0x351;

const RESPONSE_HEADER_LIMIT: u32 = 64 * 1024;
const READ_BUFFER_BYTES: usize = 64 * 1024;
const REGISTRY_VALUE_U16_LIMIT: usize = 256;
const TEMP_PATH_U16_LIMIT: usize = 32_768;
const PROCESS_TERMINATION_WAIT: Duration = Duration::from_secs(10);
const PROGRESS_START_TIMEOUT: Duration = Duration::from_secs(15);
const PROGRESS_CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
const PROGRESS_CLOSE_FALLBACK_TIMEOUT: Duration = Duration::from_secs(2);
const JOB_IDLE_POLL_INTERVAL: Duration = Duration::from_millis(100);
const TEMP_DELETE_RETRY_INTERVAL: Duration = Duration::from_millis(100);
const TEMP_DELETE_ATTEMPTS: usize = 101;

pub(super) fn prepare_before_tauri() -> Result<(), BootstrapError> {
    let mut detector = RegistryRuntimeDetector;
    let mut clock = NativeClock::new();
    let mut mutex = NamedBootstrapMutex::default();
    let mut ui = NativeProgressUi::default();
    let mut downloader = WinHttpDownloader;
    let mut verifier = WinTrustSignatureVerifier;
    let mut installer = JobControlledInstaller;

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

struct NativeClock(Instant);

impl NativeClock {
    fn new() -> Self {
        Self(Instant::now())
    }
}

impl BootstrapClock for NativeClock {
    fn now(&mut self) -> Duration {
        self.0.elapsed()
    }

    fn sleep(&mut self, duration: Duration) {
        thread::sleep(duration);
    }
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value
        .as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn duration_millis(duration: Duration) -> u32 {
    duration.as_millis().clamp(1, u32::MAX as u128) as u32
}

fn last_win32_error(error: BootstrapError, stage: BootstrapStage) -> BootstrapError {
    // SAFETY: The caller invokes this immediately after the failed Win32 API.
    let code = unsafe { GetLastError() };
    error
        .at_stage(stage)
        .with_system_code(BootstrapSystemCode::Win32(code))
}

fn returned_win32_error(error: BootstrapError, stage: BootstrapStage, code: u32) -> BootstrapError {
    error
        .at_stage(stage)
        .with_system_code(BootstrapSystemCode::Win32(code))
}

fn io_error(error: BootstrapError, stage: BootstrapStage, source: &io::Error) -> BootstrapError {
    let error = error.at_stage(stage);
    match source.raw_os_error() {
        Some(code) => error.with_system_code(BootstrapSystemCode::Win32(code as u32)),
        None => error,
    }
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: The handle was returned by RegOpenKeyExW and is owned here.
            unsafe {
                RegCloseKey(self.0);
            }
        }
    }
}

struct RegistryRuntimeDetector;

impl RegistryRuntimeDetector {
    fn query_view(root: HKEY, view: u32) -> Result<Option<String>, BootstrapError> {
        let key_path = wide(WEBVIEW2_CLIENT_KEY);
        let mut raw_key: HKEY = null_mut();
        // SAFETY: All pointers reference initialized buffers for the duration of the call.
        let status =
            unsafe { RegOpenKeyExW(root, key_path.as_ptr(), 0, KEY_READ | view, &mut raw_key) };
        match status {
            ERROR_SUCCESS => {}
            ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => {
                return Ok(None);
            }
            _ => {
                return Err(returned_win32_error(
                    BootstrapError::RuntimeDetection,
                    BootstrapStage::RuntimeInitialDetection,
                    status,
                ));
            }
        }
        let key = RegistryKey(raw_key);
        let value_name = wide("pv");
        let mut value_type: REG_VALUE_TYPE = 0;
        let mut buffer = [0u16; REGISTRY_VALUE_U16_LIMIT];
        let mut byte_len = size_of::<[u16; REGISTRY_VALUE_U16_LIMIT]>() as u32;
        // SAFETY: The opened key and bounded output buffer remain valid for the call.
        let status = unsafe {
            RegGetValueW(
                key.0,
                null(),
                value_name.as_ptr(),
                RRF_RT_REG_SZ | RRF_ZEROONFAILURE,
                &mut value_type,
                buffer.as_mut_ptr().cast(),
                &mut byte_len,
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(returned_win32_error(
                BootstrapError::RuntimeDetection,
                BootstrapStage::RuntimeInitialDetection,
                status,
            ));
        }
        if !registry_string_byte_length_is_valid(byte_len as usize, size_of_val(&buffer)) {
            return Err(
                BootstrapError::RuntimeDetection.at_stage(BootstrapStage::RuntimeInitialDetection)
            );
        }

        let units = (byte_len as usize / size_of::<u16>()).min(buffer.len());
        let terminator = buffer[..units]
            .iter()
            .position(|unit| *unit == 0)
            .unwrap_or(units);
        let value = String::from_utf16(&buffer[..terminator])
            .map_err(|_| BootstrapError::RuntimeDetection)?;
        Ok(Some(value))
    }
}

impl RuntimeDetector for RegistryRuntimeDetector {
    fn is_installed(&mut self) -> Result<bool, BootstrapError> {
        let mut first_probe_error = None;
        for root in [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER] {
            for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
                match Self::query_view(root, view) {
                    Ok(version) if runtime_version_is_present(version.as_deref()) => {
                        return Ok(true);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        first_probe_error.get_or_insert(error);
                    }
                }
            }
        }
        match first_probe_error {
            Some(error) => Err(error),
            None => Ok(false),
        }
    }
}

#[derive(Default)]
struct NamedBootstrapMutex {
    handle: HANDLE,
    owned: bool,
}

impl NamedBootstrapMutex {
    fn close_handle(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: This object owns the kernel handle.
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = null_mut();
        }
    }
}

impl BootstrapMutex for NamedBootstrapMutex {
    fn acquire(&mut self, timeout: Duration) -> Result<(), BootstrapError> {
        if !self.handle.is_null() || self.owned {
            return Err(BootstrapError::MutexAcquire);
        }
        let name = wide(WEBVIEW2_MUTEX_NAME);
        // SAFETY: The name is a valid, terminated UTF-16 string.
        self.handle = unsafe { CreateMutexW(null(), 1, name.as_ptr()) };
        if self.handle.is_null() {
            return Err(last_win32_error(
                BootstrapError::MutexAcquire,
                BootstrapStage::MutexCreate,
            ));
        }
        // SAFETY: GetLastError is read immediately after CreateMutexW.
        let already_exists = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
        if !already_exists {
            self.owned = true;
            return Ok(());
        }

        // SAFETY: self.handle is a valid mutex handle.
        let wait = unsafe { WaitForSingleObject(self.handle, duration_millis(timeout)) };
        match wait {
            WAIT_OBJECT_0 | WAIT_ABANDONED => {
                self.owned = true;
                Ok(())
            }
            WAIT_TIMEOUT => {
                self.close_handle();
                Err(BootstrapError::MutexAcquire
                    .at_stage(BootstrapStage::MutexWait)
                    .with_system_code(BootstrapSystemCode::WaitStatus(WAIT_TIMEOUT)))
            }
            WAIT_FAILED => {
                let error =
                    last_win32_error(BootstrapError::MutexAcquire, BootstrapStage::MutexWait);
                self.close_handle();
                Err(error)
            }
            status => {
                self.close_handle();
                Err(BootstrapError::MutexAcquire
                    .at_stage(BootstrapStage::MutexWait)
                    .with_system_code(BootstrapSystemCode::WaitStatus(status)))
            }
        }
    }

    fn release(&mut self) -> Result<(), BootstrapError> {
        if self.handle.is_null() || !self.owned {
            self.close_handle();
            return Err(BootstrapError::MutexRelease);
        }
        // SAFETY: The current thread owns this mutex after a successful acquire.
        let released = unsafe { ReleaseMutex(self.handle) } != 0;
        let release_error = if released {
            None
        } else {
            Some(last_win32_error(
                BootstrapError::MutexRelease,
                BootstrapStage::MutexRelease,
            ))
        };
        self.owned = false;
        self.close_handle();
        match release_error {
            None => Ok(()),
            Some(error) => Err(error),
        }
    }
}

impl Drop for NamedBootstrapMutex {
    fn drop(&mut self) {
        if self.owned && !self.handle.is_null() {
            // SAFETY: Best-effort release of a mutex owned by this thread.
            unsafe {
                ReleaseMutex(self.handle);
            }
            self.owned = false;
        }
        self.close_handle();
    }
}

struct InternetHandle(*mut c_void);

impl InternetHandle {
    fn new(raw: *mut c_void, stage: BootstrapStage) -> Result<Self, BootstrapError> {
        if raw.is_null() {
            Err(last_download_error(stage))
        } else {
            Ok(Self(raw))
        }
    }
}

impl Drop for InternetHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: This wrapper uniquely owns the WinHTTP handle.
            unsafe {
                WinHttpCloseHandle(self.0);
            }
        }
    }
}

struct HttpResponse {
    request: InternetHandle,
    _connection: InternetHandle,
}

fn last_download_error(stage: BootstrapStage) -> BootstrapError {
    // SAFETY: Reading the current thread's last-error value has no preconditions.
    let code = unsafe { GetLastError() };
    let error = if code == ERROR_WINHTTP_TIMEOUT {
        BootstrapError::DownloadTimeout
    } else {
        BootstrapError::DownloadFailed
    };
    error
        .at_stage(stage)
        .with_system_code(BootstrapSystemCode::WinHttp(code))
}

fn set_http_option<T>(
    handle: *const c_void,
    option: u32,
    value: &T,
    stage: BootstrapStage,
) -> Result<(), BootstrapError> {
    // SAFETY: value points to an initialized fixed-size option value.
    let ok = unsafe {
        WinHttpSetOption(
            handle,
            option,
            (value as *const T).cast(),
            size_of::<T>() as u32,
        )
    };
    if ok == 0 {
        Err(last_download_error(stage))
    } else {
        Ok(())
    }
}

fn set_deadline_timeouts(
    handle: *mut c_void,
    started: Instant,
    policy: DownloadPolicy,
    stage: BootstrapStage,
) -> Result<(), BootstrapError> {
    let elapsed = started.elapsed();
    let timeouts = policy.timeouts;
    let resolve = remaining_call_timeout(timeouts.total, elapsed, timeouts.resolve)
        .map_err(|error| error.at_stage(stage))?;
    let connect = remaining_call_timeout(timeouts.total, elapsed, timeouts.connect)
        .map_err(|error| error.at_stage(stage))?;
    let send = remaining_call_timeout(timeouts.total, elapsed, timeouts.send)
        .map_err(|error| error.at_stage(stage))?;
    let read = remaining_call_timeout(timeouts.total, elapsed, timeouts.read)
        .map_err(|error| error.at_stage(stage))?;
    // SAFETY: The handle is a live WinHTTP request and all timeout values are finite.
    let ok = unsafe {
        WinHttpSetTimeouts(
            handle,
            duration_millis(resolve) as i32,
            duration_millis(connect) as i32,
            duration_millis(send) as i32,
            duration_millis(read) as i32,
        )
    };
    if ok == 0 {
        Err(last_download_error(stage))
    } else {
        Ok(())
    }
}

fn open_session(policy: DownloadPolicy) -> Result<InternetHandle, BootstrapError> {
    let agent = wide("ShadowsocksWindowsRS-WebView2Bootstrap/1");
    // SAFETY: All strings are terminated and optional proxy pointers are null.
    let session = InternetHandle::new(
        unsafe {
            WinHttpOpen(
                agent.as_ptr(),
                WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                null(),
                null(),
                WINHTTP_FLAG_SECURE_DEFAULTS,
            )
        },
        BootstrapStage::WinHttpSession,
    )?;
    let timeouts = policy.timeouts;
    // SAFETY: The handle is a live WinHTTP session and timeout values are bounded i32 values.
    let ok = unsafe {
        WinHttpSetTimeouts(
            session.0,
            duration_millis(timeouts.resolve) as i32,
            duration_millis(timeouts.connect) as i32,
            duration_millis(timeouts.send) as i32,
            duration_millis(timeouts.read) as i32,
        )
    };
    if ok == 0 {
        return Err(last_download_error(BootstrapStage::WinHttpSession));
    }
    set_http_option(
        session.0.cast_const(),
        WINHTTP_OPTION_REDIRECT_POLICY,
        &WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
        BootstrapStage::WinHttpSession,
    )?;
    let reject_user_info: i32 = 1;
    set_http_option(
        session.0.cast_const(),
        WINHTTP_OPTION_REJECT_USERPWD_IN_URL,
        &reject_user_info,
        BootstrapStage::WinHttpSession,
    )?;
    set_http_option(
        session.0.cast_const(),
        WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE,
        &RESPONSE_HEADER_LIMIT,
        BootstrapStage::WinHttpSession,
    )?;
    let connect_retries = 1u32;
    set_http_option(
        session.0.cast_const(),
        WINHTTP_OPTION_CONNECT_RETRIES,
        &connect_retries,
        BootstrapStage::WinHttpSession,
    )?;
    Ok(session)
}

fn request_path(url: &Url) -> String {
    let mut path = if url.path().is_empty() {
        "/".to_owned()
    } else {
        url.path().to_owned()
    };
    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }
    path
}

fn open_response(
    session: &InternetHandle,
    url: &Url,
    started: Instant,
    policy: DownloadPolicy,
) -> Result<HttpResponse, BootstrapError> {
    policy
        .timeouts
        .validate_elapsed(started.elapsed())
        .map_err(|error| error.at_stage(BootstrapStage::WinHttpConnect))?;
    let host = wide(url.host_str().ok_or(BootstrapError::DownloadUrl)?);
    let port = url
        .port_or_known_default()
        .ok_or(BootstrapError::DownloadUrl)?;
    // SAFETY: session is valid and host is a terminated UTF-16 string.
    let connection = InternetHandle::new(
        unsafe { WinHttpConnect(session.0, host.as_ptr(), port, 0) },
        BootstrapStage::WinHttpConnect,
    )?;
    let method = wide("GET");
    let object = wide(request_path(url));
    // SAFETY: All handles and strings remain valid for the call.
    let request = InternetHandle::new(
        unsafe {
            WinHttpOpenRequest(
                connection.0,
                method.as_ptr(),
                object.as_ptr(),
                null(),
                null(),
                null(),
                WINHTTP_FLAG_SECURE as WINHTTP_OPEN_REQUEST_FLAGS,
            )
        },
        BootstrapStage::WinHttpRequestOpen,
    )?;
    set_http_option(
        request.0.cast_const(),
        WINHTTP_OPTION_REDIRECT_POLICY,
        &WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
        BootstrapStage::WinHttpRequestOpen,
    )?;
    set_deadline_timeouts(
        request.0,
        started,
        policy,
        BootstrapStage::WinHttpRequestOpen,
    )?;
    // SAFETY: The request is valid and this GET has no additional headers or body.
    if unsafe { WinHttpSendRequest(request.0, null(), 0, null(), 0, 0, 0) } == 0 {
        return Err(last_download_error(BootstrapStage::WinHttpRequestSend));
    }
    policy
        .timeouts
        .validate_elapsed(started.elapsed())
        .map_err(|error| error.at_stage(BootstrapStage::WinHttpRequestSend))?;
    set_deadline_timeouts(
        request.0,
        started,
        policy,
        BootstrapStage::WinHttpResponseReceive,
    )?;
    // SAFETY: The request is valid; the reserved parameter must be null.
    if unsafe { WinHttpReceiveResponse(request.0, null_mut()) } == 0 {
        return Err(last_download_error(BootstrapStage::WinHttpResponseReceive));
    }
    policy
        .timeouts
        .validate_elapsed(started.elapsed())
        .map_err(|error| error.at_stage(BootstrapStage::WinHttpResponseReceive))?;
    Ok(HttpResponse {
        request,
        _connection: connection,
    })
}

fn response_status(request: &InternetHandle) -> Result<u32, BootstrapError> {
    let mut status = 0u32;
    let mut length = size_of::<u32>() as u32;
    // SAFETY: status and length are valid bounded output buffers.
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            null(),
            (&mut status as *mut u32).cast(),
            &mut length,
            null_mut(),
        )
    };
    if ok == 0 {
        Err(last_download_error(BootstrapStage::HttpStatus))
    } else {
        Ok(status)
    }
}

fn stage_for_header_query(query: u32) -> BootstrapStage {
    if query == WINHTTP_QUERY_LOCATION {
        BootstrapStage::HttpRedirect
    } else {
        BootstrapStage::HttpStatus
    }
}

fn optional_header(
    request: &InternetHandle,
    query: u32,
    byte_limit: usize,
) -> Result<Option<String>, BootstrapError> {
    let mut byte_len = 0u32;
    // SAFETY: A null output buffer is the documented size-query form.
    let first = unsafe {
        WinHttpQueryHeaders(
            request.0,
            query,
            null(),
            null_mut(),
            &mut byte_len,
            null_mut(),
        )
    };
    if first != 0 {
        return Ok(Some(String::new()));
    }
    // SAFETY: Read immediately after WinHttpQueryHeaders.
    let error = unsafe { GetLastError() };
    if error == ERROR_WINHTTP_HEADER_NOT_FOUND {
        return Ok(None);
    }
    if error != ERROR_INSUFFICIENT_BUFFER {
        return Err(BootstrapError::DownloadFailed
            .at_stage(stage_for_header_query(query))
            .with_system_code(BootstrapSystemCode::WinHttp(error)));
    }
    if byte_len == 0 {
        return Err(BootstrapError::DownloadFailed.at_stage(stage_for_header_query(query)));
    }
    if byte_len as usize > byte_limit {
        return Err(BootstrapError::DownloadTooLarge.at_stage(stage_for_header_query(query)));
    }

    let mut buffer = vec![0u16; (byte_len as usize / size_of::<u16>()) + 1];
    let mut actual = byte_len;
    // SAFETY: buffer is sized from the bounded length returned by WinHTTP.
    let ok = unsafe {
        WinHttpQueryHeaders(
            request.0,
            query,
            null(),
            buffer.as_mut_ptr().cast(),
            &mut actual,
            null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_download_error(stage_for_header_query(query)));
    }
    let units = (actual as usize / size_of::<u16>()).min(buffer.len());
    let terminator = buffer[..units]
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units);
    let value = String::from_utf16(&buffer[..terminator])
        .map_err(|_| BootstrapError::DownloadFailed.at_stage(stage_for_header_query(query)))?;
    Ok(Some(value))
}

fn content_length(request: &InternetHandle, policy: DownloadPolicy) -> Result<(), BootstrapError> {
    if let Some(raw) = optional_header(request, WINHTTP_QUERY_CONTENT_LENGTH, 128)? {
        let length = raw
            .trim()
            .parse::<u64>()
            .map_err(|_| BootstrapError::DownloadFailed.at_stage(BootstrapStage::HttpStatus))?;
        policy
            .limits
            .validate_content_length(length)
            .map_err(|error| error.at_stage(BootstrapStage::HttpStatus))?;
    }
    Ok(())
}

fn is_redirect(status: u32) -> bool {
    matches!(status, 301 | 302 | 303 | 307 | 308)
}

struct NativeInstallerArtifact {
    path: PathBuf,
    locked_file: Option<File>,
    cleaned: bool,
}

impl NativeInstallerArtifact {
    fn new(path: PathBuf, file: File) -> Self {
        Self {
            path,
            locked_file: Some(file),
            cleaned: false,
        }
    }
}

impl InstallerArtifact for NativeInstallerArtifact {
    fn path(&self) -> &Path {
        &self.path
    }

    fn native_handle(&self) -> Option<isize> {
        self.locked_file
            .as_ref()
            .map(|file| file.as_raw_handle() as isize)
    }

    fn cleanup(&mut self) -> Result<(), BootstrapError> {
        if self.cleaned {
            return Ok(());
        }
        self.locked_file.take();
        for attempt in 0..TEMP_DELETE_ATTEMPTS {
            match std::fs::remove_file(&self.path) {
                Ok(()) => {
                    self.cleaned = true;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    self.cleaned = true;
                    return Ok(());
                }
                Err(_) if attempt + 1 < TEMP_DELETE_ATTEMPTS => {
                    thread::sleep(TEMP_DELETE_RETRY_INTERVAL);
                }
                Err(error) => {
                    return Err(io_error(
                        BootstrapError::Cleanup,
                        BootstrapStage::TemporaryFileCleanup,
                        &error,
                    ));
                }
            }
        }
        Err(BootstrapError::Cleanup)
    }
}

impl Drop for NativeInstallerArtifact {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn create_secure_temp_file() -> Result<(PathBuf, File), BootstrapError> {
    let mut temp_buffer = vec![0u16; TEMP_PATH_U16_LIMIT];
    // SAFETY: The bounded writable UTF-16 buffer is valid.
    let length =
        unsafe { GetTempPathW(temp_buffer.len() as u32, temp_buffer.as_mut_ptr()) } as usize;
    if length == 0 {
        return Err(last_win32_error(
            BootstrapError::TemporaryFile,
            BootstrapStage::TemporaryFileCreate,
        ));
    }
    if length >= temp_buffer.len() {
        return Err(BootstrapError::TemporaryFile.at_stage(BootstrapStage::TemporaryFileCreate));
    }
    let temp_directory = PathBuf::from(OsString::from_wide(&temp_buffer[..length]));

    for _ in 0..16 {
        let mut guid = GUID::default();
        // SAFETY: guid points to initialized writable storage.
        let status = unsafe { CoCreateGuid(&mut guid) };
        if status != 0 {
            return Err(BootstrapError::TemporaryFile
                .at_stage(BootstrapStage::TemporaryFileCreate)
                .with_system_code(BootstrapSystemCode::HResult(status)));
        }
        let name = format!(
            "sswrs-webview2-{:08x}{:04x}{:04x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}.exe",
            guid.data1,
            guid.data2,
            guid.data3,
            guid.data4[0],
            guid.data4[1],
            guid.data4[2],
            guid.data4[3],
            guid.data4[4],
            guid.data4[5],
            guid.data4[6],
            guid.data4[7],
        );
        let path = temp_directory.join(name);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_ATTRIBUTE_TEMPORARY)
            .open(&path)
        {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(io_error(
                    BootstrapError::TemporaryFile,
                    BootstrapStage::TemporaryFileCreate,
                    &error,
                ));
            }
        }
    }
    Err(BootstrapError::TemporaryFile)
}

fn duplicate_read_only(file: &File) -> Result<File, BootstrapError> {
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate: HANDLE = null_mut();
    // SAFETY: The source handle is live, target is the current process, and output is writable.
    let ok = unsafe {
        DuplicateHandle(
            process,
            file.as_raw_handle().cast(),
            process,
            &mut duplicate,
            GENERIC_READ,
            0,
            0,
        )
    };
    if ok == 0 {
        return Err(last_win32_error(
            BootstrapError::TemporaryFile,
            BootstrapStage::TemporaryFileLock,
        ));
    }
    if duplicate.is_null() {
        return Err(BootstrapError::TemporaryFile.at_stage(BootstrapStage::TemporaryFileLock));
    }
    // SAFETY: DuplicateHandle returned a newly owned file handle.
    Ok(unsafe { File::from_raw_handle(duplicate as RawHandle) })
}

struct WinHttpDownloader;

impl InstallerDownloader for WinHttpDownloader {
    fn download(
        &mut self,
        policy: DownloadPolicy,
    ) -> Result<Box<dyn InstallerArtifact>, BootstrapError> {
        if policy != DownloadPolicy::FIXED {
            return Err(BootstrapError::DownloadUrl);
        }
        let started = Instant::now();
        let session = open_session(policy)?;
        let mut current = policy.redirects.initial_url(policy.initial_url)?;
        let mut redirects = 0usize;

        loop {
            policy
                .timeouts
                .validate_elapsed(started.elapsed())
                .map_err(|error| error.at_stage(BootstrapStage::WinHttpRequestOpen))?;
            let response = open_response(&session, &current, started, policy)?;
            let status = response_status(&response.request)?;
            if is_redirect(status) {
                let location = optional_header(
                    &response.request,
                    WINHTTP_QUERY_LOCATION,
                    policy.limits.max_location_header_bytes,
                )?
                .ok_or(BootstrapError::DownloadFailed.at_stage(BootstrapStage::HttpRedirect))?;
                current = policy.redirects.follow(&current, &location, redirects)?;
                redirects += 1;
                policy
                    .timeouts
                    .validate_elapsed(started.elapsed())
                    .map_err(|error| error.at_stage(BootstrapStage::HttpRedirect))?;
                continue;
            }
            if status != 200 {
                return Err(BootstrapError::DownloadFailed
                    .at_stage(BootstrapStage::HttpStatus)
                    .with_system_code(BootstrapSystemCode::HttpStatus(status)));
            }
            content_length(&response.request, policy)?;

            let (path, file) = create_secure_temp_file()?;
            let mut artifact = NativeInstallerArtifact::new(path, file);
            let result = (|| {
                let mut downloaded = 0u64;
                let mut buffer = vec![0u8; READ_BUFFER_BYTES];
                loop {
                    set_deadline_timeouts(
                        response.request.0,
                        started,
                        policy,
                        BootstrapStage::DownloadRead,
                    )?;
                    let mut read = 0u32;
                    // SAFETY: request is valid and buffer is writable for the advertised length.
                    let ok = unsafe {
                        WinHttpReadData(
                            response.request.0,
                            buffer.as_mut_ptr().cast(),
                            buffer.len() as u32,
                            &mut read,
                        )
                    };
                    if ok == 0 {
                        return Err(last_download_error(BootstrapStage::DownloadRead));
                    }
                    if read == 0 {
                        break;
                    }
                    downloaded = policy.limits.add_chunk(downloaded, read as usize)?;
                    artifact
                        .locked_file
                        .as_mut()
                        .ok_or(
                            BootstrapError::TemporaryFile
                                .at_stage(BootstrapStage::TemporaryFileWrite),
                        )?
                        .write_all(&buffer[..read as usize])
                        .map_err(|error| {
                            io_error(
                                BootstrapError::TemporaryFile,
                                BootstrapStage::TemporaryFileWrite,
                                &error,
                            )
                        })?;
                    policy
                        .timeouts
                        .validate_elapsed(started.elapsed())
                        .map_err(|error| error.at_stage(BootstrapStage::DownloadRead))?;
                }
                artifact
                    .locked_file
                    .as_ref()
                    .ok_or(
                        BootstrapError::TemporaryFile.at_stage(BootstrapStage::TemporaryFileFlush),
                    )?
                    .sync_all()
                    .map_err(|error| {
                        io_error(
                            BootstrapError::TemporaryFile,
                            BootstrapStage::TemporaryFileFlush,
                            &error,
                        )
                    })?;
                policy
                    .timeouts
                    .validate_elapsed(started.elapsed())
                    .map_err(|error| error.at_stage(BootstrapStage::TemporaryFileFlush))?;
                let locked = duplicate_read_only(artifact.locked_file.as_ref().ok_or(
                    BootstrapError::TemporaryFile.at_stage(BootstrapStage::TemporaryFileLock),
                )?)?;
                artifact.locked_file = Some(locked);
                Ok(())
            })();

            if let Err(error) = result {
                return match artifact.cleanup() {
                    Ok(()) => Err(error),
                    Err(cleanup_error) => Err(error.with_secondary(cleanup_error)),
                };
            }
            return Ok(Box::new(artifact));
        }
    }
}

struct WinTrustSignatureVerifier;

impl WinTrustSignatureVerifier {
    unsafe fn signer_organization(trust_data: &WINTRUST_DATA) -> Result<String, BootstrapError> {
        if trust_data.hWVTStateData.is_null() {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        // SAFETY: The state handle is live until WTD_STATEACTION_CLOSE.
        let provider = unsafe { WTHelperProvDataFromStateData(trust_data.hWVTStateData) };
        if provider.is_null() {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        let provider_error = unsafe { (*provider).dwError };
        if provider_error != 0 {
            return Err(BootstrapError::SignatureInspection
                .at_stage(BootstrapStage::AuthenticodeSigner)
                .with_system_code(BootstrapSystemCode::WinTrust(provider_error as i32)));
        }
        // SAFETY: provider is returned from the active WinTrust state.
        let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
        if signer.is_null() {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        let signer_error = unsafe { (*signer).dwError };
        if signer_error != 0 {
            return Err(BootstrapError::SignatureInspection
                .at_stage(BootstrapStage::AuthenticodeSigner)
                .with_system_code(BootstrapSystemCode::WinTrust(signer_error as i32)));
        }
        // SAFETY: signer is the primary publisher signer from the active state.
        let provider_certificate = unsafe { WTHelperGetProvCertFromChain(signer, 0) };
        if provider_certificate.is_null() {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        let certificate_error = unsafe { (*provider_certificate).dwError };
        if certificate_error != 0 {
            return Err(BootstrapError::SignatureInspection
                .at_stage(BootstrapStage::AuthenticodeSigner)
                .with_system_code(BootstrapSystemCode::WinTrust(certificate_error as i32)));
        }
        if unsafe { (*provider_certificate).pCert }.is_null()
            || unsafe { (*provider_certificate).fTestCert } != 0
        {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        let certificate = unsafe { (*provider_certificate).pCert };
        // SAFETY: certificate and the organization OID are valid for the active state.
        let length = unsafe {
            CertGetNameStringW(
                certificate,
                CERT_NAME_ATTR_TYPE,
                0,
                szOID_ORGANIZATION_NAME.cast(),
                null_mut(),
                0,
            )
        };
        if length == 0 {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        if length <= 1 || length > 512 {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        let mut buffer = vec![0u16; length as usize];
        // SAFETY: buffer has the exact bounded size requested by CertGetNameStringW.
        let written = unsafe {
            CertGetNameStringW(
                certificate,
                CERT_NAME_ATTR_TYPE,
                0,
                szOID_ORGANIZATION_NAME.cast(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
            )
        };
        if written == 0 {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        if written != length {
            return Err(
                BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
            );
        }
        String::from_utf16(&buffer[..buffer.len() - 1]).map_err(|_| {
            BootstrapError::SignatureInspection.at_stage(BootstrapStage::AuthenticodeSigner)
        })
    }
}

impl SignatureVerifier for WinTrustSignatureVerifier {
    fn verify(
        &mut self,
        artifact: &dyn InstallerArtifact,
    ) -> Result<SignatureEvidence, BootstrapError> {
        let raw_handle = artifact
            .native_handle()
            .ok_or(BootstrapError::SignatureInspection)? as HANDLE;
        let path = wide(artifact.path().as_os_str());
        let mut file_info = WINTRUST_FILE_INFO {
            cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
            pcwszFilePath: path.as_ptr(),
            hFile: raw_handle,
            pgKnownSubject: null_mut(),
        };
        let mut trust_data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            pPolicyCallbackData: null_mut(),
            pSIPClientData: null_mut(),
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_FILE,
            Anonymous: WINTRUST_DATA_0 {
                pFile: &mut file_info,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            hWVTStateData: null_mut(),
            pwszURLReference: null_mut(),
            dwProvFlags: WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT | WTD_DISABLE_MD2_MD4 | WTD_MOTW,
            dwUIContext: WTD_UICONTEXT_INSTALL,
            pSignatureSettings: null_mut(),
        };
        let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        // SAFETY: The structures and locked file handle remain live through VERIFY and CLOSE.
        let status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut trust_data as *mut WINTRUST_DATA).cast(),
            )
        };
        let evidence = if status == 0 {
            // SAFETY: WinVerifyTrust succeeded and the state remains open.
            unsafe { Self::signer_organization(&trust_data) }
                .map(|organization| SignatureEvidence::Trusted { organization })
        } else {
            Err(BootstrapError::SignatureRejected
                .at_stage(BootstrapStage::AuthenticodeVerify)
                .with_system_code(BootstrapSystemCode::WinTrust(status)))
        };

        trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: This is the required matching close call for the verification state.
        let close_status = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut trust_data as *mut WINTRUST_DATA).cast(),
            )
        };
        if close_status != 0 {
            let close_error = BootstrapError::SignatureInspection
                .at_stage(BootstrapStage::AuthenticodeClose)
                .with_system_code(BootstrapSystemCode::WinTrust(close_status));
            return match evidence {
                Ok(_) => Err(close_error),
                Err(error) => Err(error.with_secondary(close_error)),
            };
        }
        evidence
    }
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn new(handle: HANDLE, stage: BootstrapStage) -> Result<Self, BootstrapError> {
        if handle.is_null() {
            Err(last_win32_error(BootstrapError::InstallerLaunch, stage))
        } else {
            Ok(Self(handle))
        }
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: This wrapper uniquely owns the kernel handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

fn terminate_suspended_process(process: HANDLE) -> Result<(), BootstrapError> {
    if process.is_null() {
        return Ok(());
    }
    // SAFETY: Best-effort termination of a process we created suspended.
    let termination_error = if unsafe { TerminateProcess(process, 1) } == 0 {
        Some(last_win32_error(
            BootstrapError::InstallerLaunch,
            BootstrapStage::InstallerTerminate,
        ))
    } else {
        None
    };
    // SAFETY: process is a live waitable process handle.
    let wait = unsafe { WaitForSingleObject(process, duration_millis(PROCESS_TERMINATION_WAIT)) };
    let wait_error = match wait {
        WAIT_OBJECT_0 => None,
        WAIT_FAILED => Some(last_win32_error(
            BootstrapError::InstallerLaunch,
            BootstrapStage::InstallerTerminate,
        )),
        status => Some(
            BootstrapError::InstallerLaunch
                .at_stage(BootstrapStage::InstallerTerminate)
                .with_system_code(BootstrapSystemCode::WaitStatus(status)),
        ),
    };
    match (termination_error, wait_error) {
        (Some(error), Some(wait_error)) => Err(error.with_secondary(wait_error)),
        (Some(error), None) | (None, Some(error)) => Err(error),
        (None, None) => Ok(()),
    }
}

fn installer_command_line(path: &Path, arguments: [&str; 2]) -> Vec<u16> {
    let mut command_line = Vec::new();
    command_line.push('"' as u16);
    command_line.extend(path.as_os_str().encode_wide());
    command_line.push('"' as u16);
    for argument in arguments {
        command_line.push(' ' as u16);
        command_line.extend(OsStr::new(argument).encode_wide());
    }
    command_line.push(0);
    command_line
}

fn active_job_processes(job: HANDLE) -> Result<u32, BootstrapError> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    let mut returned = 0u32;
    // SAFETY: accounting is an initialized output buffer of the documented size.
    let ok = unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            &mut returned,
        )
    };
    if ok == 0 {
        Err(last_win32_error(
            BootstrapError::InstallerLaunch,
            BootstrapStage::InstallerJobDrain,
        ))
    } else {
        Ok(accounting.ActiveProcesses)
    }
}

fn terminate_job_and_wait_idle(job: HANDLE) -> Result<(), BootstrapError> {
    // SAFETY: The handle is an owned Job Object configured for this installer tree.
    if unsafe { TerminateJobObject(job, 1) } == 0 {
        return Err(last_win32_error(
            BootstrapError::InstallerLaunch,
            BootstrapStage::InstallerTerminate,
        ));
    }
    let started = Instant::now();
    loop {
        match active_job_processes(job) {
            Ok(0) => return Ok(()),
            Ok(_) if started.elapsed() < PROCESS_TERMINATION_WAIT => {
                thread::sleep(
                    JOB_IDLE_POLL_INTERVAL
                        .min(PROCESS_TERMINATION_WAIT.saturating_sub(started.elapsed())),
                );
            }
            Ok(_) => {
                return Err(
                    BootstrapError::InstallerLaunch.at_stage(BootstrapStage::InstallerJobDrain)
                );
            }
            Err(error) => return Err(error),
        }
    }
}

struct JobControlledInstaller;

impl SilentInstaller for JobControlledInstaller {
    fn install(
        &mut self,
        artifact: &dyn InstallerArtifact,
        policy: InstallPolicy,
    ) -> Result<u32, BootstrapError> {
        if policy != InstallPolicy::FIXED {
            return Err(BootstrapError::InstallerLaunch);
        }
        let started = Instant::now();
        // SAFETY: Null security/name pointers request an unnamed job with default security.
        let job = OwnedHandle::new(
            unsafe { CreateJobObjectW(null(), null()) },
            BootstrapStage::InstallerJobCreate,
        )?;
        let mut job_limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        job_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: job_limits is initialized and has the exact documented structure size.
        let configured = unsafe {
            SetInformationJobObject(
                job.0,
                JobObjectExtendedLimitInformation,
                (&job_limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            return Err(last_win32_error(
                BootstrapError::InstallerLaunch,
                BootstrapStage::InstallerJobConfigure,
            ));
        }

        let application = wide(artifact.path().as_os_str());
        let mut command_line = installer_command_line(artifact.path(), policy.arguments);
        let startup = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_HIDE as u16,
            ..STARTUPINFOW::default()
        };
        let mut process_info = PROCESS_INFORMATION::default();
        // SAFETY: lpApplicationName is an exact executable path, command line is mutable and
        // terminated, no handles are inherited, and output structures are initialized.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                null(),
                null(),
                &startup,
                &mut process_info,
            )
        };
        if created == 0 || process_info.hProcess.is_null() || process_info.hThread.is_null() {
            let create_error = if created == 0 {
                last_win32_error(
                    BootstrapError::InstallerLaunch,
                    BootstrapStage::InstallerCreateProcess,
                )
            } else {
                BootstrapError::InstallerLaunch.at_stage(BootstrapStage::InstallerCreateProcess)
            };
            let termination = terminate_suspended_process(process_info.hProcess);
            if !process_info.hProcess.is_null() {
                unsafe {
                    CloseHandle(process_info.hProcess);
                }
            }
            if !process_info.hThread.is_null() {
                unsafe {
                    CloseHandle(process_info.hThread);
                }
            }
            return match termination {
                Ok(()) => Err(create_error),
                Err(termination_error) => Err(create_error.with_secondary(termination_error)),
            };
        }
        let process = OwnedHandle(process_info.hProcess);
        let thread = OwnedHandle(process_info.hThread);
        // SAFETY: The child is still suspended, so it cannot escape before job assignment.
        if unsafe { AssignProcessToJobObject(job.0, process.0) } == 0 {
            let error = last_win32_error(
                BootstrapError::InstallerLaunch,
                BootstrapStage::InstallerAssignJob,
            );
            return match terminate_suspended_process(process.0) {
                Ok(()) => Err(error),
                Err(termination_error) => Err(error.with_secondary(termination_error)),
            };
        }
        // SAFETY: thread is the suspended primary thread from CreateProcessW.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let error = last_win32_error(
                BootstrapError::InstallerLaunch,
                BootstrapStage::InstallerResume,
            );
            return match terminate_job_and_wait_idle(job.0) {
                Ok(()) => Err(error),
                Err(termination_error) => Err(error.with_secondary(termination_error)),
            };
        }
        drop(thread);

        let remaining = policy.timeout.saturating_sub(started.elapsed());
        // SAFETY: process is a live waitable process handle.
        let wait = unsafe { WaitForSingleObject(process.0, duration_millis(remaining)) };
        match wait {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                let error = BootstrapError::InstallerTimeout
                    .at_stage(BootstrapStage::InstallerWait)
                    .with_system_code(BootstrapSystemCode::WaitStatus(WAIT_TIMEOUT));
                return match terminate_job_and_wait_idle(job.0) {
                    Ok(()) => Err(error),
                    Err(termination_error) => Err(error.with_secondary(termination_error)),
                };
            }
            WAIT_FAILED => {
                let error = last_win32_error(
                    BootstrapError::InstallerLaunch,
                    BootstrapStage::InstallerWait,
                );
                return match terminate_job_and_wait_idle(job.0) {
                    Ok(()) => Err(error),
                    Err(termination_error) => Err(error.with_secondary(termination_error)),
                };
            }
            status => {
                let error = BootstrapError::InstallerLaunch
                    .at_stage(BootstrapStage::InstallerWait)
                    .with_system_code(BootstrapSystemCode::WaitStatus(status));
                return match terminate_job_and_wait_idle(job.0) {
                    Ok(()) => Err(error),
                    Err(termination_error) => Err(error.with_secondary(termination_error)),
                };
            }
        }
        let mut exit_code = u32::MAX;
        // SAFETY: process is signaled and exit_code is writable.
        if unsafe { GetExitCodeProcess(process.0, &mut exit_code) } == 0 {
            let error = last_win32_error(
                BootstrapError::InstallerLaunch,
                BootstrapStage::InstallerExit,
            );
            return match terminate_job_and_wait_idle(job.0) {
                Ok(()) => Err(error),
                Err(termination_error) => Err(error.with_secondary(termination_error)),
            };
        }
        if exit_code != 0 {
            let error = BootstrapError::InstallerFailed
                .at_stage(BootstrapStage::InstallerExit)
                .with_system_code(BootstrapSystemCode::InstallerExit(exit_code));
            return match terminate_job_and_wait_idle(job.0) {
                Ok(()) => Ok(exit_code),
                Err(termination_error) => Err(error.with_secondary(termination_error)),
            };
        }
        loop {
            match active_job_processes(job.0) {
                Ok(0) => break,
                Ok(_) => {}
                Err(error) => {
                    return match terminate_job_and_wait_idle(job.0) {
                        Ok(()) => Err(error),
                        Err(termination_error) => Err(error.with_secondary(termination_error)),
                    };
                }
            }
            if started.elapsed() >= policy.timeout {
                let error =
                    BootstrapError::InstallerTimeout.at_stage(BootstrapStage::InstallerJobDrain);
                return match terminate_job_and_wait_idle(job.0) {
                    Ok(()) => Err(error),
                    Err(termination_error) => Err(error.with_secondary(termination_error)),
                };
            }
            thread::sleep(
                JOB_IDLE_POLL_INTERVAL.min(policy.timeout.saturating_sub(started.elapsed())),
            );
        }
        Ok(exit_code)
    }
}

struct ProgressWindow {
    hwnd: isize,
    thread_id: u32,
    done: mpsc::Receiver<Result<(), BootstrapError>>,
    join: Option<JoinHandle<()>>,
}

impl ProgressWindow {
    fn open() -> Result<Self, BootstrapError> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (acknowledge, acknowledged) = mpsc::sync_channel(1);
        let (done_sender, done) = mpsc::sync_channel(1);
        let join = thread::Builder::new()
            .name("webview2-bootstrap-progress".to_owned())
            .spawn(move || progress_thread(sender, acknowledged, done_sender))
            .map_err(|error| {
                io_error(
                    BootstrapError::ProgressWindow,
                    BootstrapStage::ProgressOpen,
                    &error,
                )
            })?;
        match receiver.recv_timeout(PROGRESS_START_TIMEOUT) {
            Ok(Ok((hwnd, thread_id))) if acknowledge.send(()).is_ok() => Ok(Self {
                hwnd,
                thread_id,
                done,
                join: Some(join),
            }),
            Ok(Err(error)) => Err(error),
            _ => Err(BootstrapError::ProgressWindow.at_stage(BootstrapStage::ProgressOpen)),
        }
    }

    fn close(mut self) -> Result<(), BootstrapError> {
        // SAFETY: hwnd/thread_id were reported by the live UI thread after queue creation.
        let posted = unsafe { PostMessageW(self.hwnd as _, CLOSE_PROGRESS_MESSAGE, 0, 0) };
        let mut post_error = None;
        if posted == 0 {
            let window_post_error = last_win32_error(
                BootstrapError::ProgressWindow,
                BootstrapStage::ProgressClose,
            );
            // SAFETY: WM_QUIT is a safe fallback that prevents an unbounded join.
            if unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0) } == 0 {
                post_error = Some(window_post_error.with_secondary(last_win32_error(
                    BootstrapError::ProgressWindow,
                    BootstrapStage::ProgressClose,
                )));
            }
        }

        let thread_result = match self.done.recv_timeout(PROGRESS_CLOSE_TIMEOUT) {
            Ok(result) => result,
            Err(_) => {
                // SAFETY: Force the UI message loop to return without touching installer state.
                if unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, 0, 0) } == 0 {
                    let fallback_error = last_win32_error(
                        BootstrapError::ProgressWindow,
                        BootstrapStage::ProgressClose,
                    );
                    post_error = Some(match post_error {
                        Some(error) => error.with_secondary(fallback_error),
                        None => fallback_error,
                    });
                }
                match self.done.recv_timeout(PROGRESS_CLOSE_FALLBACK_TIMEOUT) {
                    Ok(result) => result,
                    Err(_) => {
                        return Err(post_error.unwrap_or(
                            BootstrapError::ProgressWindow.at_stage(BootstrapStage::ProgressClose),
                        ));
                    }
                }
            }
        };
        let Some(join) = self.join.take() else {
            return Err(BootstrapError::ProgressWindow.at_stage(BootstrapStage::ProgressClose));
        };
        let joined = join.join();
        match (thread_result, joined) {
            (Err(error), Err(_)) => Err(error.with_secondary(
                BootstrapError::ProgressWindow.at_stage(BootstrapStage::ProgressClose),
            )),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(_)) => {
                Err(BootstrapError::ProgressWindow.at_stage(BootstrapStage::ProgressClose))
            }
            (Ok(()), Ok(())) => Ok(()),
        }
    }
}

unsafe extern "system" fn progress_window_proc(
    hwnd: windows_sys::Win32::Foundation::HWND,
    message: u32,
    wparam: usize,
    lparam: isize,
) -> isize {
    match message {
        WM_CLOSE => 0,
        CLOSE_PROGRESS_MESSAGE => {
            // SAFETY: hwnd belongs to this UI thread and is still live.
            unsafe {
                DestroyWindow(hwnd);
            }
            0
        }
        WM_DESTROY => {
            // SAFETY: Ends this thread's message loop.
            unsafe {
                PostQuitMessage(0);
            }
            0
        }
        _ => {
            // SAFETY: Default processing for messages we do not handle.
            unsafe { DefWindowProcW(hwnd, message, wparam, lparam) }
        }
    }
}

fn progress_thread(
    sender: SyncSender<Result<(isize, u32), BootstrapError>>,
    acknowledged: mpsc::Receiver<()>,
    done: SyncSender<Result<(), BootstrapError>>,
) {
    let result = run_progress_thread(sender, acknowledged);
    let _ = done.send(result);
}

fn run_progress_thread(
    sender: SyncSender<Result<(isize, u32), BootstrapError>>,
    acknowledged: mpsc::Receiver<()>,
) -> Result<(), BootstrapError> {
    let (hwnd, thread_id) = match create_progress_window() {
        Ok(window) => window,
        Err(error) => {
            let _ = sender.send(Err(error));
            return Err(error);
        }
    };
    if sender.send(Ok((hwnd as isize, thread_id))).is_err()
        || acknowledged.recv_timeout(PROGRESS_START_TIMEOUT).is_err()
    {
        // SAFETY: The opener disappeared or timed out; close our own window before returning.
        unsafe {
            DestroyWindow(hwnd);
        }
        return Ok(());
    }

    let mut message = MSG::default();
    loop {
        // SAFETY: message is writable; null hwnd receives this thread's queue messages.
        let status = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
        if status > 0 {
            // SAFETY: message was populated by GetMessageW.
            unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }
        } else if status == 0 {
            return Ok(());
        } else {
            return Err(last_win32_error(
                BootstrapError::ProgressWindow,
                BootstrapStage::ProgressMessageLoop,
            ));
        }
    }
}

fn create_progress_window() -> Result<(windows_sys::Win32::Foundation::HWND, u32), BootstrapError> {
    let class_name = wide(WINDOW_CLASS_NAME);
    let title = wide(WINDOW_TITLE);
    let text = wide(PROGRESS_TEXT);
    let static_class = wide("STATIC");
    let mut controls = INITCOMMONCONTROLSEX {
        dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_PROGRESS_CLASS,
    };
    // SAFETY: controls has the documented size and flags.
    if unsafe { InitCommonControlsEx(&mut controls) } == 0 {
        return Err(BootstrapError::ProgressWindow.at_stage(BootstrapStage::ProgressOpen));
    }
    // SAFETY: Null requests the current executable module.
    let instance = unsafe { GetModuleHandleW(null()) };
    if instance.is_null() {
        return Err(last_win32_error(
            BootstrapError::ProgressWindow,
            BootstrapStage::ProgressOpen,
        ));
    }
    let window_class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(progress_window_proc),
        hInstance: instance,
        // SAFETY: Loads the system wait cursor and system color brush.
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_WAIT) },
        hbrBackground: unsafe { GetSysColorBrush(COLOR_WINDOW) },
        lpszClassName: class_name.as_ptr(),
        ..WNDCLASSW::default()
    };
    // SAFETY: window_class and all referenced strings live through registration.
    if unsafe { RegisterClassW(&window_class) } == 0 {
        // SAFETY: Captured immediately after RegisterClassW returned zero.
        let code = unsafe { GetLastError() };
        if code != ERROR_CLASS_ALREADY_EXISTS {
            return Err(returned_win32_error(
                BootstrapError::ProgressWindow,
                BootstrapStage::ProgressOpen,
                code,
            ));
        }
    }

    let width = 460;
    let height = 170;
    // SAFETY: System metric queries have no preconditions.
    let x = (unsafe { GetSystemMetrics(SM_CXSCREEN) } - width).max(0) / 2;
    let y = (unsafe { GetSystemMetrics(SM_CYSCREEN) } - height).max(0) / 2;
    // SAFETY: The registered class and all parameters are valid.
    let window = unsafe {
        CreateWindowExW(
            WS_EX_DLGMODALFRAME,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPED | WS_CAPTION,
            x,
            y,
            width,
            height,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if window.is_null() {
        return Err(last_win32_error(
            BootstrapError::ProgressWindow,
            BootstrapStage::ProgressOpen,
        ));
    }

    // SAFETY: Creates non-interactive child controls owned by the progress window.
    let label = unsafe {
        CreateWindowExW(
            0,
            static_class.as_ptr(),
            text.as_ptr(),
            WS_CHILD | WS_VISIBLE | SS_CENTER | SS_CENTERIMAGE,
            28,
            25,
            width - 56,
            58,
            window,
            null_mut(),
            instance,
            null(),
        )
    };
    if label.is_null() {
        let error = last_win32_error(BootstrapError::ProgressWindow, BootstrapStage::ProgressOpen);
        unsafe {
            DestroyWindow(window);
        }
        return Err(error);
    }
    // SAFETY: Creates a marquee-only progress control with no interaction.
    let progress = unsafe {
        CreateWindowExW(
            0,
            PROGRESS_CLASSW,
            null(),
            WS_CHILD | WS_VISIBLE | PBS_MARQUEE,
            50,
            96,
            width - 100,
            20,
            window,
            null_mut(),
            instance,
            null(),
        )
    };
    if progress.is_null() {
        let error = last_win32_error(BootstrapError::ProgressWindow, BootstrapStage::ProgressOpen);
        unsafe {
            DestroyWindow(window);
        }
        return Err(error);
    }
    // SAFETY: DEFAULT_GUI_FONT is a process-lifetime stock object; controls are live.
    let font = unsafe { GetStockObject(DEFAULT_GUI_FONT) };
    unsafe {
        SendMessageW(label, WM_SETFONT, font as usize, 1);
        SendMessageW(progress, PBM_SETMARQUEE, 1, 30);
        ShowWindow(window, SW_SHOWNORMAL);
        UpdateWindow(window);
    }
    // SAFETY: Returns the current UI thread identifier.
    let thread_id = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
    Ok((window, thread_id))
}

#[derive(Default)]
struct NativeProgressUi {
    progress: Option<ProgressWindow>,
}

impl ProgressUi for NativeProgressUi {
    fn open(&mut self) -> Result<(), BootstrapError> {
        if self.progress.is_some() {
            return Err(BootstrapError::ProgressWindow.at_stage(BootstrapStage::ProgressOpen));
        }
        self.progress = Some(ProgressWindow::open()?);
        Ok(())
    }

    fn close(&mut self) -> Result<(), BootstrapError> {
        let Some(progress) = self.progress.take() else {
            return Ok(());
        };
        progress.close()
    }

    fn show_error(&mut self, message: &str) -> Result<(), BootstrapError> {
        let message = wide(message);
        let title = wide(ERROR_TITLE);
        // SAFETY: Both strings are valid for the synchronous native dialog call.
        let result = unsafe {
            MessageBoxW(
                null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR | MB_TASKMODAL,
            )
        };
        if result == 0 {
            Err(last_win32_error(
                BootstrapError::ProgressWindow,
                BootstrapStage::ProgressClose,
            ))
        } else {
            Ok(())
        }
    }
}

impl Drop for NativeProgressUi {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
