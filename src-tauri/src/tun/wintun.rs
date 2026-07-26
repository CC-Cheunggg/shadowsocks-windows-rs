//! Minimal RAII wrapper for the official Wintun binary API.
//!
//! The DLL path is deliberately not configurable. On Windows the loader asks
//! the OS for the fixed application-local resource name `wintun.dll` using
//! `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`. This prevents a Tauri command (or any
//! other caller) from supplying an arbitrary DLL path.

use std::fmt;

pub const WINTUN_DLL_NAME: &str = "wintun.dll";
pub const MIN_RING_CAPACITY: u32 = 0x2_0000;
pub const MAX_RING_CAPACITY: u32 = 0x400_0000;
pub const MAX_IP_PACKET_SIZE: usize = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterOwnership {
    Created,
    Opened,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WintunError {
    UnsupportedPlatform,
    InvalidAdapterName,
    InvalidRingCapacity,
    PacketTooLarge,
    LibraryLoad { code: u32 },
    MissingSymbol { symbol: &'static str, code: u32 },
    Operation { operation: &'static str, code: u32 },
}

impl fmt::Display for WintunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedPlatform => formatter.write_str("Wintun is supported only on Windows"),
            Self::InvalidAdapterName => formatter.write_str("Wintun adapter name is invalid"),
            Self::InvalidRingCapacity => formatter.write_str(
                "Wintun ring capacity must be a power of two between 128 KiB and 64 MiB",
            ),
            Self::PacketTooLarge => {
                formatter.write_str("packet is larger than the Wintun packet limit")
            }
            Self::LibraryLoad { code } => {
                write!(
                    formatter,
                    "failed to load the bundled Wintun library (OS error {code})"
                )
            }
            Self::MissingSymbol { symbol, code } => write!(
                formatter,
                "bundled Wintun library does not export {symbol} (OS error {code})"
            ),
            Self::Operation { operation, code } => {
                write!(formatter, "Wintun {operation} failed (OS error {code})")
            }
        }
    }
}

impl std::error::Error for WintunError {}

fn validate_ring_capacity(capacity: u32) -> Result<(), WintunError> {
    if !(MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&capacity) || !capacity.is_power_of_two() {
        return Err(WintunError::InvalidRingCapacity);
    }
    Ok(())
}

fn validate_adapter_name(name: &str) -> Result<(), WintunError> {
    // Wintun's MAX_ADAPTER_NAME is 128 wide characters including NUL.
    if name.is_empty()
        || name.encode_utf16().count() >= 128
        || name
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(WintunError::InvalidAdapterName);
    }
    Ok(())
}

#[cfg(windows)]
mod platform {
    use super::{
        AdapterOwnership, MAX_IP_PACKET_SIZE, WINTUN_DLL_NAME, WintunError, validate_adapter_name,
        validate_ring_capacity,
    };
    use std::ffi::{c_char, c_void};
    use std::ops::Deref;
    use std::ptr::{self, NonNull};
    use std::sync::Arc;
    use std::time::Duration;

    type ModuleHandle = *mut c_void;
    type AdapterHandle = *mut c_void;
    type SessionHandle = *mut c_void;
    type EventHandle = *mut c_void;

    type CreateAdapter =
        unsafe extern "system" fn(*const u16, *const u16, *const c_void) -> AdapterHandle;
    type OpenAdapter = unsafe extern "system" fn(*const u16) -> AdapterHandle;
    type CloseAdapter = unsafe extern "system" fn(AdapterHandle);
    type GetAdapterLuid = unsafe extern "system" fn(AdapterHandle, *mut u64);
    type StartSession = unsafe extern "system" fn(AdapterHandle, u32) -> SessionHandle;
    type EndSession = unsafe extern "system" fn(SessionHandle);
    type GetReadWaitEvent = unsafe extern "system" fn(SessionHandle) -> EventHandle;
    type ReceivePacket = unsafe extern "system" fn(SessionHandle, *mut u32) -> *mut u8;
    type ReleaseReceivePacket = unsafe extern "system" fn(SessionHandle, *const u8);
    type AllocateSendPacket = unsafe extern "system" fn(SessionHandle, u32) -> *mut u8;
    type SendPacket = unsafe extern "system" fn(SessionHandle, *const u8);

    const LOAD_LIBRARY_SEARCH_APPLICATION_DIR: u32 = 0x0000_0200;
    const ERROR_NO_MORE_ITEMS: u32 = 259;
    const WAIT_OBJECT_0: u32 = 0;
    const WAIT_TIMEOUT: u32 = 258;
    const WAIT_FAILED: u32 = u32::MAX;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LoadLibraryExW(file_name: *const u16, file: *mut c_void, flags: u32) -> ModuleHandle;
        fn FreeLibrary(module: ModuleHandle) -> i32;
        fn GetProcAddress(module: ModuleHandle, name: *const c_char) -> *mut c_void;
        fn GetLastError() -> u32;
        fn WaitForSingleObject(handle: EventHandle, milliseconds: u32) -> u32;
    }

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn ConvertInterfaceLuidToIndex(
            interface_luid: *const u64,
            interface_index: *mut u32,
        ) -> u32;
    }

    struct Api {
        module: NonNull<c_void>,
        create_adapter: CreateAdapter,
        open_adapter: OpenAdapter,
        close_adapter: CloseAdapter,
        get_adapter_luid: GetAdapterLuid,
        start_session: StartSession,
        end_session: EndSession,
        get_read_wait_event: GetReadWaitEvent,
        receive_packet: ReceivePacket,
        release_receive_packet: ReleaseReceivePacket,
        allocate_send_packet: AllocateSendPacket,
        send_packet: SendPacket,
    }

    // The module and Wintun function table are immutable. Wintun documents its
    // session ring entry points as thread-safe.
    unsafe impl Send for Api {}
    unsafe impl Sync for Api {}

    impl Api {
        fn load() -> Result<Self, WintunError> {
            let dll_name = wide(WINTUN_DLL_NAME);
            // SAFETY: `dll_name` is NUL terminated. The flags restrict lookup to
            // the executable's application directory; no caller path is used.
            let module = unsafe {
                LoadLibraryExW(
                    dll_name.as_ptr(),
                    ptr::null_mut(),
                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
                )
            };
            let module = NonNull::new(module).ok_or_else(|| WintunError::LibraryLoad {
                // SAFETY: GetLastError has no preconditions.
                code: unsafe { GetLastError() },
            })?;

            macro_rules! symbol {
                ($name:literal, $ty:ty) => {{
                    // SAFETY: the name is a static NUL-terminated C string and
                    // `module` remains loaded for the lifetime of `Api`.
                    let address = unsafe {
                        GetProcAddress(
                            module.as_ptr(),
                            concat!($name, "\0").as_ptr().cast::<c_char>(),
                        )
                    };
                    if address.is_null() {
                        // SAFETY: GetLastError has no preconditions.
                        let code = unsafe { GetLastError() };
                        // SAFETY: this is the only owner during construction.
                        unsafe { FreeLibrary(module.as_ptr()) };
                        return Err(WintunError::MissingSymbol {
                            symbol: $name,
                            code,
                        });
                    }
                    // SAFETY: Wintun's published API fixes the signature
                    // corresponding to each exported symbol.
                    unsafe { std::mem::transmute::<*mut c_void, $ty>(address) }
                }};
            }

            Ok(Self {
                module,
                create_adapter: symbol!("WintunCreateAdapter", CreateAdapter),
                open_adapter: symbol!("WintunOpenAdapter", OpenAdapter),
                close_adapter: symbol!("WintunCloseAdapter", CloseAdapter),
                get_adapter_luid: symbol!("WintunGetAdapterLUID", GetAdapterLuid),
                start_session: symbol!("WintunStartSession", StartSession),
                end_session: symbol!("WintunEndSession", EndSession),
                get_read_wait_event: symbol!("WintunGetReadWaitEvent", GetReadWaitEvent),
                receive_packet: symbol!("WintunReceivePacket", ReceivePacket),
                release_receive_packet: symbol!("WintunReleaseReceivePacket", ReleaseReceivePacket),
                allocate_send_packet: symbol!("WintunAllocateSendPacket", AllocateSendPacket),
                send_packet: symbol!("WintunSendPacket", SendPacket),
            })
        }
    }

    impl Drop for Api {
        fn drop(&mut self) {
            // SAFETY: this module handle is owned by Api and all adapters and
            // sessions retain an Arc<Api>, so no function can still be active.
            unsafe {
                FreeLibrary(self.module.as_ptr());
            }
        }
    }

    #[derive(Clone)]
    pub struct Wintun {
        api: Arc<Api>,
    }

    impl Wintun {
        pub fn load() -> Result<Self, WintunError> {
            Ok(Self {
                api: Arc::new(Api::load()?),
            })
        }

        pub fn create_adapter(&self, name: &str) -> Result<Adapter, WintunError> {
            self.create_adapter_with_type(name, "Shadowsocks")
        }

        pub fn create_adapter_with_type(
            &self,
            name: &str,
            tunnel_type: &str,
        ) -> Result<Adapter, WintunError> {
            validate_adapter_name(name)?;
            validate_adapter_name(tunnel_type)?;
            let name = wide(name);
            let tunnel_type = wide(tunnel_type);
            // SAFETY: strings are NUL terminated and pointers remain valid for
            // the duration of the call. A random adapter GUID is requested.
            let handle = unsafe {
                (self.api.create_adapter)(name.as_ptr(), tunnel_type.as_ptr(), ptr::null())
            };
            let handle = NonNull::new(handle).ok_or_else(|| WintunError::Operation {
                operation: "adapter creation",
                // SAFETY: GetLastError has no preconditions.
                code: unsafe { GetLastError() },
            })?;
            Ok(Adapter::new(
                Arc::clone(&self.api),
                handle,
                AdapterOwnership::Created,
            ))
        }

        pub fn open_adapter(&self, name: &str) -> Result<Adapter, WintunError> {
            validate_adapter_name(name)?;
            let name = wide(name);
            // SAFETY: the string is NUL terminated and remains alive.
            let handle = unsafe { (self.api.open_adapter)(name.as_ptr()) };
            let handle = NonNull::new(handle).ok_or_else(|| WintunError::Operation {
                operation: "adapter open",
                // SAFETY: GetLastError has no preconditions.
                code: unsafe { GetLastError() },
            })?;
            Ok(Adapter::new(
                Arc::clone(&self.api),
                handle,
                AdapterOwnership::Opened,
            ))
        }
    }

    struct AdapterInner {
        api: Arc<Api>,
        handle: NonNull<c_void>,
        ownership: AdapterOwnership,
    }

    unsafe impl Send for AdapterInner {}
    unsafe impl Sync for AdapterInner {}

    impl Drop for AdapterInner {
        fn drop(&mut self) {
            // Current Wintun releases an opened adapter and removes an adapter
            // created through this handle. Sessions retain this Arc, so they
            // have already ended before this runs.
            unsafe {
                (self.api.close_adapter)(self.handle.as_ptr());
            }
        }
    }

    #[derive(Clone)]
    pub struct Adapter {
        inner: Arc<AdapterInner>,
    }

    impl Adapter {
        fn new(api: Arc<Api>, handle: NonNull<c_void>, ownership: AdapterOwnership) -> Self {
            Self {
                inner: Arc::new(AdapterInner {
                    api,
                    handle,
                    ownership,
                }),
            }
        }

        pub fn ownership(&self) -> AdapterOwnership {
            self.inner.ownership
        }

        pub fn luid(&self) -> u64 {
            let mut luid = 0_u64;
            // SAFETY: both the adapter handle and output pointer are valid.
            unsafe {
                (self.inner.api.get_adapter_luid)(self.inner.handle.as_ptr(), &mut luid);
            }
            luid
        }

        pub fn interface_index(&self) -> Result<u32, WintunError> {
            let luid = self.luid();
            let mut index = 0_u32;
            // SAFETY: both pointers reference correctly aligned writable/input
            // storage for the documented NET_LUID (64-bit) and NET_IFINDEX.
            let status = unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) };
            if status == 0 && index != 0 {
                Ok(index)
            } else {
                Err(WintunError::Operation {
                    operation: "adapter interface-index lookup",
                    code: status,
                })
            }
        }

        pub fn start_session(&self, capacity: u32) -> Result<Session, WintunError> {
            validate_ring_capacity(capacity)?;
            // SAFETY: adapter handle is valid and the capacity was checked.
            let handle =
                unsafe { (self.inner.api.start_session)(self.inner.handle.as_ptr(), capacity) };
            let handle = NonNull::new(handle).ok_or_else(|| WintunError::Operation {
                operation: "session start",
                // SAFETY: GetLastError has no preconditions.
                code: unsafe { GetLastError() },
            })?;
            Ok(Session {
                inner: Arc::clone(&self.inner),
                handle,
            })
        }

        /// Explicitly closes this handle. A uniquely owned adapter created by
        /// `create_adapter` is removed by WintunCloseAdapter.
        pub fn close(self) {}

        pub fn remove_owned(self) -> Result<(), WintunError> {
            if self.ownership() != AdapterOwnership::Created {
                return Err(WintunError::Operation {
                    operation: "adapter removal refused for a non-owned adapter",
                    code: 0,
                });
            }
            drop(self);
            Ok(())
        }
    }

    pub struct Session {
        // Retains adapter and DLL until WintunEndSession completes.
        inner: Arc<AdapterInner>,
        handle: NonNull<c_void>,
    }

    unsafe impl Send for Session {}
    unsafe impl Sync for Session {}

    impl Session {
        pub fn receive(&self) -> Result<Option<ReceivedPacket<'_>>, WintunError> {
            let mut packet_size = 0_u32;
            // SAFETY: session handle and size pointer are valid.
            let packet =
                unsafe { (self.inner.api.receive_packet)(self.handle.as_ptr(), &mut packet_size) };
            let Some(packet) = NonNull::new(packet) else {
                // SAFETY: GetLastError has no preconditions.
                let code = unsafe { GetLastError() };
                return if code == ERROR_NO_MORE_ITEMS {
                    Ok(None)
                } else {
                    Err(WintunError::Operation {
                        operation: "packet receive",
                        code,
                    })
                };
            };
            if packet_size as usize > MAX_IP_PACKET_SIZE {
                // Release even a malformed oversized ring entry.
                unsafe {
                    (self.inner.api.release_receive_packet)(self.handle.as_ptr(), packet.as_ptr());
                }
                return Err(WintunError::PacketTooLarge);
            }
            Ok(Some(ReceivedPacket {
                session: self,
                packet,
                packet_size: packet_size as usize,
            }))
        }

        pub fn send(&self, packet: &[u8]) -> Result<(), WintunError> {
            if packet.is_empty() || packet.len() > MAX_IP_PACKET_SIZE {
                return Err(WintunError::PacketTooLarge);
            }
            let packet_size =
                u32::try_from(packet.len()).map_err(|_| WintunError::PacketTooLarge)?;
            // SAFETY: session handle is valid and packet size is in range.
            let destination =
                unsafe { (self.inner.api.allocate_send_packet)(self.handle.as_ptr(), packet_size) };
            let destination = NonNull::new(destination).ok_or_else(|| WintunError::Operation {
                operation: "send-ring allocation",
                // SAFETY: GetLastError has no preconditions.
                code: unsafe { GetLastError() },
            })?;
            // SAFETY: Wintun allocated exactly packet_size writable bytes and
            // the source slice has that same length. Regions do not overlap.
            unsafe {
                ptr::copy_nonoverlapping(packet.as_ptr(), destination.as_ptr(), packet.len());
                (self.inner.api.send_packet)(self.handle.as_ptr(), destination.as_ptr());
            }
            Ok(())
        }

        /// Returns the Wintun-owned receive event. The caller must not close it.
        pub fn read_wait_handle(&self) -> isize {
            // SAFETY: the session remains valid for this call.
            unsafe { (self.inner.api.get_read_wait_event)(self.handle.as_ptr()) as isize }
        }

        pub fn wait_for_read(&self, timeout: Duration) -> Result<bool, WintunError> {
            let milliseconds = timeout.as_millis().min(u128::from(u32::MAX - 1)) as u32;
            // SAFETY: the event belongs to this live Wintun session and is only
            // waited on; it is never closed by the caller.
            let result = unsafe {
                WaitForSingleObject(
                    (self.inner.api.get_read_wait_event)(self.handle.as_ptr()),
                    milliseconds,
                )
            };
            match result {
                WAIT_OBJECT_0 => Ok(true),
                WAIT_TIMEOUT => Ok(false),
                WAIT_FAILED => Err(WintunError::Operation {
                    operation: "receive-event wait",
                    // SAFETY: GetLastError has no preconditions.
                    code: unsafe { GetLastError() },
                }),
                code => Err(WintunError::Operation {
                    operation: "receive-event wait",
                    code,
                }),
            }
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            // SAFETY: this Session uniquely owns the session handle.
            unsafe {
                (self.inner.api.end_session)(self.handle.as_ptr());
            }
        }
    }

    pub struct ReceivedPacket<'session> {
        session: &'session Session,
        packet: NonNull<u8>,
        packet_size: usize,
    }

    impl Deref for ReceivedPacket<'_> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            // SAFETY: Wintun owns this immutable view until Drop releases it,
            // and the packet size was returned by Wintun.
            unsafe { std::slice::from_raw_parts(self.packet.as_ptr(), self.packet_size) }
        }
    }

    impl AsRef<[u8]> for ReceivedPacket<'_> {
        fn as_ref(&self) -> &[u8] {
            self
        }
    }

    impl Drop for ReceivedPacket<'_> {
        fn drop(&mut self) {
            // SAFETY: packet came from this session and is released once.
            unsafe {
                (self.session.inner.api.release_receive_packet)(
                    self.session.handle.as_ptr(),
                    self.packet.as_ptr(),
                );
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{AdapterOwnership, WintunError, validate_adapter_name, validate_ring_capacity};
    use std::ops::Deref;
    use std::time::Duration;

    #[derive(Clone)]
    pub struct Wintun;

    impl Wintun {
        pub fn load() -> Result<Self, WintunError> {
            Err(WintunError::UnsupportedPlatform)
        }

        pub fn create_adapter(&self, name: &str) -> Result<Adapter, WintunError> {
            validate_adapter_name(name)?;
            Err(WintunError::UnsupportedPlatform)
        }

        pub fn create_adapter_with_type(
            &self,
            name: &str,
            tunnel_type: &str,
        ) -> Result<Adapter, WintunError> {
            validate_adapter_name(name)?;
            validate_adapter_name(tunnel_type)?;
            Err(WintunError::UnsupportedPlatform)
        }

        pub fn open_adapter(&self, name: &str) -> Result<Adapter, WintunError> {
            validate_adapter_name(name)?;
            Err(WintunError::UnsupportedPlatform)
        }
    }

    #[derive(Clone)]
    pub struct Adapter;

    impl Adapter {
        pub fn ownership(&self) -> AdapterOwnership {
            AdapterOwnership::Opened
        }

        pub fn luid(&self) -> u64 {
            0
        }

        pub fn interface_index(&self) -> Result<u32, WintunError> {
            Err(WintunError::UnsupportedPlatform)
        }

        pub fn start_session(&self, capacity: u32) -> Result<Session, WintunError> {
            validate_ring_capacity(capacity)?;
            Err(WintunError::UnsupportedPlatform)
        }

        pub fn close(self) {}

        pub fn remove_owned(self) -> Result<(), WintunError> {
            Err(WintunError::UnsupportedPlatform)
        }
    }

    pub struct Session;

    impl Session {
        pub fn receive(&self) -> Result<Option<ReceivedPacket<'_>>, WintunError> {
            Err(WintunError::UnsupportedPlatform)
        }

        pub fn send(&self, _packet: &[u8]) -> Result<(), WintunError> {
            Err(WintunError::UnsupportedPlatform)
        }

        pub fn read_wait_handle(&self) -> isize {
            0
        }

        pub fn wait_for_read(&self, _timeout: Duration) -> Result<bool, WintunError> {
            Err(WintunError::UnsupportedPlatform)
        }
    }

    pub struct ReceivedPacket<'session> {
        _session: &'session Session,
    }

    impl Deref for ReceivedPacket<'_> {
        type Target = [u8];

        fn deref(&self) -> &Self::Target {
            &[]
        }
    }

    impl AsRef<[u8]> for ReceivedPacket<'_> {
        fn as_ref(&self) -> &[u8] {
            self
        }
    }
}

pub use platform::{Adapter, ReceivedPacket, Session, Wintun};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_capacity_is_bounded_power_of_two() {
        assert!(validate_ring_capacity(MIN_RING_CAPACITY).is_ok());
        assert!(validate_ring_capacity(MAX_RING_CAPACITY).is_ok());
        assert_eq!(
            validate_ring_capacity(MIN_RING_CAPACITY - 1),
            Err(WintunError::InvalidRingCapacity)
        );
        assert_eq!(
            validate_ring_capacity(MIN_RING_CAPACITY + 1),
            Err(WintunError::InvalidRingCapacity)
        );
    }

    #[test]
    fn adapter_names_cannot_smuggle_paths_or_nuls() {
        assert!(validate_adapter_name("Shadowsocks Direct").is_ok());
        assert_eq!(
            validate_adapter_name("bad\0name"),
            Err(WintunError::InvalidAdapterName)
        );
        assert_eq!(
            validate_adapter_name(""),
            Err(WintunError::InvalidAdapterName)
        );
    }

    #[test]
    fn dll_name_is_fixed_and_contains_no_path() {
        assert_eq!(WINTUN_DLL_NAME, "wintun.dll");
        assert!(
            !WINTUN_DLL_NAME
                .chars()
                .any(|character| matches!(character, '/' | '\\'))
        );
    }

    #[test]
    fn errors_do_not_include_packet_contents_or_paths() {
        let message = WintunError::LibraryLoad { code: 126 }.to_string();
        assert!(!message.contains('\\'));
        assert!(!message.contains('/'));
        assert!(message.contains("126"));
    }
}
