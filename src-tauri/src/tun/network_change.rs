//! Read-only Windows network-change notifications for one runtime epoch.
//!
//! A monitor should be created after the runtime has installed its owned
//! routes and dropped before those routes are restored. The callbacks never
//! inspect Windows state or perform I/O; they only invalidate the shared token.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

/// Shared validity marker for one set of validated network bindings.
///
/// Clones refer to the same one-way state. A token never becomes valid again;
/// the runtime must construct a new monitor and token for the next epoch.
#[derive(Debug, Clone)]
pub struct NetworkEpochToken {
    invalid: Arc<AtomicBool>,
}

impl NetworkEpochToken {
    pub fn new() -> Self {
        Self {
            invalid: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_valid(&self) -> bool {
        !self.is_invalid()
    }

    pub fn is_invalid(&self) -> bool {
        self.invalid.load(Ordering::Acquire)
    }

    /// Invalidates this epoch, returning true only for the first transition.
    ///
    /// The return value lets platform-independent callers coalesce a burst of
    /// notifications without a queue or a counter.
    pub(crate) fn invalidate(&self) -> bool {
        !self.invalid.swap(true, Ordering::AcqRel)
    }
}

impl Default for NetworkEpochToken {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkChangeError {
    UnsupportedPlatform,
    Registration { operation: &'static str, code: u32 },
}

impl fmt::Display for NetworkChangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => {
                formatter.write_str("network-change monitoring is available only on Windows")
            }
            Self::Registration { operation, code } => {
                write!(
                    formatter,
                    "{operation} notification registration failed (OS error {code})"
                )
            }
        }
    }
}

impl std::error::Error for NetworkChangeError {}

/// Owns the three Windows notification registrations for one network epoch.
///
/// Dropping the monitor deregisters every notification. Tokens already handed
/// to DIRECT workers remain readable and retain their final validity state.
pub struct NetworkChangeMonitor {
    token: NetworkEpochToken,
    _registrations: platform::Registrations,
}

impl NetworkChangeMonitor {
    pub fn new() -> Result<Self, NetworkChangeError> {
        let token = NetworkEpochToken::new();
        let registrations = platform::register(&token)?;
        Ok(Self {
            token,
            _registrations: registrations,
        })
    }

    pub fn token(&self) -> NetworkEpochToken {
        self.token.clone()
    }
}

#[cfg(windows)]
mod platform {
    use super::{NetworkChangeError, NetworkEpochToken};
    use std::ffi::c_void;
    use std::mem;
    use std::ptr;
    use std::sync::atomic::{AtomicBool, Ordering};
    use windows_sys::Win32::Foundation::{ERROR_INVALID_HANDLE, HANDLE, NO_ERROR};
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        CancelMibChangeNotify2, MIB_IPFORWARD_ROW2, MIB_IPINTERFACE_ROW, MIB_NOTIFICATION_TYPE,
        MIB_UNICASTIPADDRESS_ROW, NotifyIpInterfaceChange, NotifyRouteChange2,
        NotifyUnicastIpAddressChange,
    };
    use windows_sys::Win32::Networking::WinSock::AF_UNSPEC;

    pub(super) struct Registrations {
        route: HANDLE,
        interface: HANDLE,
        address: HANDLE,
        context: NetworkEpochToken,
    }

    impl Registrations {
        fn new(context: NetworkEpochToken) -> Self {
            Self {
                route: ptr::null_mut(),
                interface: ptr::null_mut(),
                address: ptr::null_mut(),
                context,
            }
        }

        fn caller_context(&self) -> *const c_void {
            ArcContext::from_token(&self.context)
        }

        fn register_route(&mut self) -> Result<(), NetworkChangeError> {
            let mut handle = ptr::null_mut();
            // SAFETY: the callback has the documented ABI, the shared atomic
            // context remains alive through cancellation, and the output
            // pointer is valid writable storage.
            let status = unsafe {
                NotifyRouteChange2(
                    AF_UNSPEC,
                    Some(route_changed),
                    self.caller_context(),
                    false,
                    &mut handle,
                )
            };
            self.route = checked_handle(status, handle, "route-change")?;
            Ok(())
        }

        fn register_interface(&mut self) -> Result<(), NetworkChangeError> {
            let mut handle = ptr::null_mut();
            // SAFETY: see register_route; InitialNotification is deliberately
            // false so registration itself cannot invalidate the epoch.
            let status = unsafe {
                NotifyIpInterfaceChange(
                    AF_UNSPEC,
                    Some(interface_changed),
                    self.caller_context(),
                    false,
                    &mut handle,
                )
            };
            self.interface = checked_handle(status, handle, "IP-interface-change")?;
            Ok(())
        }

        fn register_address(&mut self) -> Result<(), NetworkChangeError> {
            let mut handle = ptr::null_mut();
            // SAFETY: see register_route; the callback ignores OS-owned row
            // memory and only stores to the shared atomic flag.
            let status = unsafe {
                NotifyUnicastIpAddressChange(
                    AF_UNSPEC,
                    Some(address_changed),
                    self.caller_context(),
                    false,
                    &mut handle,
                )
            };
            self.address = checked_handle(status, handle, "unicast-address-change")?;
            Ok(())
        }
    }

    impl Drop for Registrations {
        fn drop(&mut self) {
            let mut cancellation_failed = false;
            for handle in [&mut self.route, &mut self.interface, &mut self.address] {
                let handle = mem::replace(handle, ptr::null_mut());
                if handle.is_null() {
                    continue;
                }
                // SAFETY: each non-null handle came from a successful Notify*
                // registration. Drop never runs in one of the callbacks.
                if unsafe { CancelMibChangeNotify2(handle) } != NO_ERROR {
                    cancellation_failed = true;
                }
            }
            if cancellation_failed {
                // A failed cancellation may leave a callback registered.
                // Leaking one Arc on this exceptional path is preferable to
                // allowing that callback to dereference freed context.
                mem::forget(self.context.clone());
            }
        }
    }

    struct ArcContext;

    impl ArcContext {
        fn from_token(token: &NetworkEpochToken) -> *const c_void {
            std::sync::Arc::as_ptr(&token.invalid).cast::<c_void>()
        }
    }

    fn checked_handle(
        status: u32,
        handle: HANDLE,
        operation: &'static str,
    ) -> Result<HANDLE, NetworkChangeError> {
        if status != NO_ERROR {
            return Err(NetworkChangeError::Registration {
                operation,
                code: status,
            });
        }
        if handle.is_null() {
            return Err(NetworkChangeError::Registration {
                operation,
                code: ERROR_INVALID_HANDLE,
            });
        }
        Ok(handle)
    }

    fn invalidate(context: *const c_void) {
        if context.is_null() {
            return;
        }
        // SAFETY: caller_context points to the AtomicBool inside an Arc kept
        // alive until all registrations have been cancelled. The callbacks
        // never mutate or free the context.
        unsafe {
            context
                .cast::<AtomicBool>()
                .as_ref()
                .expect("network-change callback context was null")
                .store(true, Ordering::Release);
        }
    }

    unsafe extern "system" fn route_changed(
        context: *const c_void,
        _row: *const MIB_IPFORWARD_ROW2,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        invalidate(context);
    }

    unsafe extern "system" fn interface_changed(
        context: *const c_void,
        _row: *const MIB_IPINTERFACE_ROW,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        invalidate(context);
    }

    unsafe extern "system" fn address_changed(
        context: *const c_void,
        _row: *const MIB_UNICASTIPADDRESS_ROW,
        _notification_type: MIB_NOTIFICATION_TYPE,
    ) {
        invalidate(context);
    }

    pub(super) fn register(token: &NetworkEpochToken) -> Result<Registrations, NetworkChangeError> {
        let mut registrations = Registrations::new(token.clone());
        registrations.register_route()?;
        registrations.register_interface()?;
        registrations.register_address()?;
        Ok(registrations)
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{NetworkChangeError, NetworkEpochToken};

    pub(super) struct Registrations;

    pub(super) fn register(
        _token: &NetworkEpochToken,
    ) -> Result<Registrations, NetworkChangeError> {
        Err(NetworkChangeError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::NetworkEpochToken;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::thread;

    #[test]
    fn epoch_token_is_one_way_and_shared_by_clones() {
        let token = NetworkEpochToken::new();
        let clone = token.clone();

        assert!(token.is_valid());
        assert!(!clone.is_invalid());
        assert!(clone.invalidate());
        assert!(token.is_invalid());
        assert!(!token.invalidate());
    }

    #[test]
    fn concurrent_notification_burst_has_one_transition() {
        let token = NetworkEpochToken::new();
        let transitions = Arc::new(AtomicUsize::new(0));
        let workers = (0..32)
            .map(|_| {
                let token = token.clone();
                let transitions = Arc::clone(&transitions);
                thread::spawn(move || {
                    if token.invalidate() {
                        transitions.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect::<Vec<_>>();

        for worker in workers {
            worker.join().expect("burst worker panicked");
        }

        assert_eq!(transitions.load(Ordering::Relaxed), 1);
        assert!(token.is_invalid());
    }

    #[cfg(not(windows))]
    #[test]
    fn monitor_is_explicitly_unsupported_off_windows() {
        assert!(matches!(
            super::NetworkChangeMonitor::new(),
            Err(super::NetworkChangeError::UnsupportedPlatform)
        ));
    }
}
