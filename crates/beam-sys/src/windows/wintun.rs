//! WinTun dynamic loader and Layer 3 ring-buffer session wrapper.
//!
//! Beam ships the official WHQL-signed WireGuard WinTun 0.14.1 `wintun.dll`
//! next to the executable. The loader never searches `PATH`, the current
//! directory, or the system directory: it builds an absolute path from the
//! running executable and passes `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`, so
//! only that directory can supply the module and its dependencies. A caller
//! that ships its own copy can pin the exact bytes with
//! [`verify_dll_sha256`] or the `expected_sha256` argument of the loaders.
//!
//! A session exposes the Layer 3 ring buffer through
//! [`WinTunSession::try_recv_into`], [`WinTunSession::recv_blocking`], and
//! [`WinTunSession::send_packet`]. A manual-reset Win32 event (see
//! [`WinTunSession::shutdown_handle`]) wakes a reader that is blocked in a
//! wait, so shutdown never depends on a packet arriving.

use std::ffi::{CStr, c_void};
use std::fmt::Write as _;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NO_MORE_ITEMS, FreeLibrary, HANDLE, HMODULE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LoadLibraryExW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, SetEvent, WaitForMultipleObjects,
};
use windows_sys::core::{GUID, PCWSTR};

/// File name of the WinTun userspace driver API library.
pub const WINTUN_DLL_NAME: &str = "wintun.dll";

/// WinTun release that Beam pins.
pub const WINTUN_VERSION: &str = "0.14.1";

/// SHA-256 of `bin/amd64/wintun.dll` from the official
/// `https://www.wintun.net/builds/wintun-0.14.1.zip` archive.
///
/// The archive itself is
/// `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
/// (750 540 bytes) and the extracted DLL is 427 552 bytes.
///
/// The loaders only enforce a digest that the caller passes in, so packaging
/// pins the bytes it actually ships; this constant is what the pinned release
/// archives contain, not a fallback that weakens the check.
pub const WINTUN_0_14_1_AMD64_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

/// Smallest ring capacity WinTun accepts, in bytes
/// (`WINTUN_MIN_RING_CAPACITY`).
pub const MIN_RING_CAPACITY: u32 = 0x2_0000;

/// Largest ring capacity WinTun accepts, in bytes
/// (`WINTUN_MAX_RING_CAPACITY`).
pub const MAX_RING_CAPACITY: u32 = 0x400_0000;

/// Default ring capacity, in bytes (4 MiB).
pub const DEFAULT_RING_CAPACITY: u32 = 0x40_0000;

/// Largest DLL size the SHA-256 check reads, in bytes (16 MiB).
///
/// The official DLL is 427 KiB; the bound keeps a replaced or padded file from
/// turning verification into an unbounded read.
pub const MAX_DLL_BYTES: u64 = 16 * 1024 * 1024;

/// Largest packet `WintunAllocateSendPacket` accepts, in bytes.
pub const MAX_PACKET_LEN: usize = 65_535;

/// Longest tunnel type string accepted by [`WinTunAdapter::create`].
const MAX_TUNNEL_TYPE_LEN: usize = 64;

/// WinTun entry points, resolved once per loaded module.
///
/// The signatures follow `wintun.h` 0.14.1. Every pointer is unretained except
/// the adapter and session handles, which the wrappers in this module own.
type CreateAdapterFn = unsafe extern "system" fn(
    name: PCWSTR,
    tunnel_type: PCWSTR,
    requested_guid: *const GUID,
) -> *mut c_void;
type OpenAdapterFn = unsafe extern "system" fn(name: PCWSTR) -> *mut c_void;
type CloseAdapterFn = unsafe extern "system" fn(adapter: *mut c_void);
type GetAdapterLuidFn = unsafe extern "system" fn(adapter: *mut c_void, luid: *mut u64);
type StartSessionFn = unsafe extern "system" fn(adapter: *mut c_void, capacity: u32) -> *mut c_void;
type EndSessionFn = unsafe extern "system" fn(session: *mut c_void);
type GetReadWaitEventFn = unsafe extern "system" fn(session: *mut c_void) -> HANDLE;
type ReceivePacketFn =
    unsafe extern "system" fn(session: *mut c_void, packet_size: *mut u32) -> *mut u8;
type ReleaseReceivePacketFn = unsafe extern "system" fn(session: *mut c_void, packet: *const u8);
type AllocateSendPacketFn =
    unsafe extern "system" fn(session: *mut c_void, packet_size: u32) -> *mut u8;
type SendPacketFn = unsafe extern "system" fn(session: *mut c_void, packet: *const u8);
type RunningDriverVersionFn = unsafe extern "system" fn() -> u32;

/// Resolves every WinTun export into a struct field.
///
/// `transmute` from the untyped `FARPROC` the loader returns cannot be checked
/// by the compiler, so each name and its Rust signature stay on one line at the
/// call site.
macro_rules! resolve_exports {
    ($module:expr, $path:expr, { $($field:ident : $ty:ty = $name:literal),+ $(,)? }) => {
        Exports {
            $($field: {
                // SAFETY: `$module` came from `LoadLibraryExW` and is still
                // loaded, so `GetProcAddress` only reads that module's export
                // table. `$name` is a NUL-terminated ASCII name.
                let proc = unsafe { GetProcAddress($module, $name.as_ptr().cast::<u8>()) };
                match proc {
                    // SAFETY: WinTun 0.14.1 exports each name with exactly the
                    // `$ty` signature declared above, and `FARPROC` and `$ty`
                    // are both thin function pointers of pointer width.
                    Some(proc) => unsafe {
                        std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(proc)
                    },
                    None => return Err(missing_export($path, $name)),
                }
            }),+
        }
    };
}

/// Resolved WinTun exports.
struct Exports {
    create_adapter: CreateAdapterFn,
    open_adapter: OpenAdapterFn,
    close_adapter: CloseAdapterFn,
    get_adapter_luid: GetAdapterLuidFn,
    start_session: StartSessionFn,
    end_session: EndSessionFn,
    get_read_wait_event: GetReadWaitEventFn,
    receive_packet: ReceivePacketFn,
    release_receive_packet: ReleaseReceivePacketFn,
    allocate_send_packet: AllocateSendPacketFn,
    send_packet: SendPacketFn,
    running_driver_version: RunningDriverVersionFn,
}

impl Exports {
    fn resolve(module: HMODULE, path: &Path) -> io::Result<Self> {
        Ok(resolve_exports!(
            module,
            path,
            {
                create_adapter: CreateAdapterFn = c"WintunCreateAdapter",
                open_adapter: OpenAdapterFn = c"WintunOpenAdapter",
                close_adapter: CloseAdapterFn = c"WintunCloseAdapter",
                get_adapter_luid: GetAdapterLuidFn = c"WintunGetAdapterLUID",
                start_session: StartSessionFn = c"WintunStartSession",
                end_session: EndSessionFn = c"WintunEndSession",
                get_read_wait_event: GetReadWaitEventFn = c"WintunGetReadWaitEvent",
                receive_packet: ReceivePacketFn = c"WintunReceivePacket",
                release_receive_packet: ReleaseReceivePacketFn = c"WintunReleaseReceivePacket",
                allocate_send_packet: AllocateSendPacketFn = c"WintunAllocateSendPacket",
                send_packet: SendPacketFn = c"WintunSendPacket",
                running_driver_version: RunningDriverVersionFn = c"WintunGetRunningDriverVersion",
            }
        ))
    }
}

/// A loaded `wintun.dll` and its entry points.
///
/// The module stays loaded until the last [`Arc`] clone drops; adapters and
/// sessions hold one so their entry points outlive every use.
pub struct WinTunLib {
    module: HMODULE,
    path: PathBuf,
    exports: Exports,
}

impl WinTunLib {
    /// Loads `wintun.dll` from the directory that holds the running
    /// executable.
    ///
    /// The directory comes from the image path (`GetModuleFileNameW` through
    /// `std::env::current_exe`), so a service and a console run of the same
    /// binary look in the same place. `expected_sha256` pins the exact file
    /// bytes; `None` loads the file without a digest check.
    pub fn load_from_exe_dir(expected_sha256: Option<&[u8; 32]>) -> io::Result<Self> {
        let exe = std::env::current_exe()?;
        let dir = exe.parent().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("executable path {} has no parent directory", exe.display()),
            )
        })?;
        Self::load_from_path(&dir.join(WINTUN_DLL_NAME), expected_sha256)
    }

    /// Loads `wintun.dll` from an absolute `path`.
    ///
    /// The module is loaded with `LOAD_LIBRARY_SEARCH_APPLICATION_DIR`, which
    /// replaces the default search order, so neither `PATH` nor the current
    /// directory can supply the DLL or one of its dependencies.
    pub fn load_from_path(path: &Path, expected_sha256: Option<&[u8; 32]>) -> io::Result<Self> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{} must be loaded by absolute path", path.display()),
            ));
        }
        if let Some(expected) = expected_sha256 {
            verify_dll_sha256(path, expected)?;
        }
        let path_wide = wide_os_str(path.as_os_str())?;
        // SAFETY: `path_wide` is NUL-terminated and lives for the call, and the
        // handle argument is documented to be NULL. `LOAD_LIBRARY_SEARCH_*`
        // flags replace the default search order, so the call cannot reach
        // `PATH` or the current directory.
        //
        // shortcut: verification and load are separate opens, so a writer with
        // access to the install directory could swap the file in between; the
        // install directory ACL is SYSTEM+Administrators, so revisit this only
        // if the DLL ever moves to a user-writable directory.
        let module = unsafe {
            LoadLibraryExW(
                path_wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR,
            )
        };
        if module.is_null() {
            return Err(os_error_with(
                "LoadLibraryExW",
                path.display(),
                io::Error::last_os_error(),
            ));
        }
        // `Exports::resolve` may return early; the loaded module then has no
        // owner, so release it before propagating the error.
        let exports = match Exports::resolve(module, path) {
            Ok(exports) => exports,
            Err(err) => {
                // SAFETY: `module` was loaded here, nothing else references it,
                // and it is not used after this call.
                unsafe { FreeLibrary(module) };
                return Err(err);
            }
        };
        Ok(Self {
            module,
            path: path.to_path_buf(),
            exports,
        })
    }

    /// Path this module was loaded from.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Version of the running WinTun driver, as `major << 16 | minor`.
    pub fn running_driver_version(&self) -> u32 {
        // SAFETY: the export takes no arguments and touches no caller memory.
        unsafe { (self.exports.running_driver_version)() }
    }
}

impl Drop for WinTunLib {
    fn drop(&mut self) {
        // SAFETY: `self.module` is a handle from `LoadLibraryExW` that this
        // value owns exclusively, and no entry point is called after drop
        // because every adapter and session holds an `Arc` to this library.
        unsafe { FreeLibrary(self.module) };
    }
}

// SAFETY: the module handle is an opaque kernel object that any thread may
// pass to `FreeLibrary`; `Drop` runs only when the last `Arc` clone is gone,
// so no thread can resolve or call an entry point afterwards.
unsafe impl Send for WinTunLib {}

// SAFETY: reading `path`, `module`, and the immutable function pointers
// through a shared reference touches no interior mutable state; entry points
// resolved from the same module are safe to call concurrently, which is what
// WinTun documents for an adapter or session handle.
unsafe impl Sync for WinTunLib {}

/// A WinTun adapter, created or opened by name.
pub struct WinTunAdapter {
    lib: Arc<WinTunLib>,
    handle: NonNull<c_void>,
    name: String,
    luid: u64,
}

impl WinTunAdapter {
    /// Creates the named adapter, or returns the existing one.
    ///
    /// The adapter GUID is derived from `name`, so a given name always maps to
    /// the same Windows network interface instead of a new "Network 2", "3",
    /// "4" each time the service restarts.
    pub fn create(lib: Arc<WinTunLib>, name: &str, tunnel_type: &str) -> io::Result<Self> {
        super::validate_ifname(name)?;
        validate_tunnel_type(tunnel_type)?;
        let name_wide = wide_str(name, super::MAX_IFNAME_LEN)?;
        let tunnel_type_wide = wide_str(tunnel_type, MAX_TUNNEL_TYPE_LEN)?;
        // SAFETY: both name buffers are NUL-terminated and live for the call,
        // the `GUID` temporary returned by `adapter_guid` lives until the end of
        // the statement, and the export has the documented signature.
        let handle = unsafe {
            (lib.exports.create_adapter)(
                name_wide.as_ptr(),
                tunnel_type_wide.as_ptr(),
                &adapter_guid(name),
            )
        };
        Self::from_handle(lib, handle, name, "WintunCreateAdapter")
    }

    /// Opens an existing adapter by name.
    pub fn open(lib: Arc<WinTunLib>, name: &str) -> io::Result<Self> {
        super::validate_ifname(name)?;
        let name_wide = wide_str(name, super::MAX_IFNAME_LEN)?;
        // SAFETY: `name_wide` is NUL-terminated and lives for the call, and the
        // export has the documented signature.
        let handle = unsafe { (lib.exports.open_adapter)(name_wide.as_ptr()) };
        Self::from_handle(lib, handle, name, "WintunOpenAdapter")
    }

    fn from_handle(
        lib: Arc<WinTunLib>,
        handle: *mut c_void,
        name: &str,
        operation: &str,
    ) -> io::Result<Self> {
        let Some(handle) = NonNull::new(handle) else {
            return Err(os_error_with(operation, name, io::Error::last_os_error()));
        };
        let mut luid = 0_u64;
        // SAFETY: `handle` is a live adapter owned by this function and
        // `WintunGetAdapterLUID` writes exactly one `NET_LUID`, a 64-bit value,
        // to the pointer it is given.
        unsafe { (lib.exports.get_adapter_luid)(handle.as_ptr(), &raw mut luid) };
        let adapter = Self {
            lib,
            handle,
            name: name.to_owned(),
            luid,
        };
        if luid == 0 {
            // `adapter` drops here, which closes the handle again.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("WinTun adapter {name:?} reported LUID 0"),
            ));
        }
        Ok(adapter)
    }

    /// LUID of the adapter's network interface, for IP Helper and WFP calls.
    pub fn luid(&self) -> u64 {
        self.luid
    }

    /// Adapter name as passed to [`WinTunAdapter::create`].
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Starts a Layer 3 session on this adapter.
    ///
    /// `ring_capacity` is the ring buffer size in bytes and must be a power of
    /// two in `0x20000..=0x4000000`; [`DEFAULT_RING_CAPACITY`] is 4 MiB.
    pub fn start_session(self: &Arc<Self>, ring_capacity: u32) -> io::Result<WinTunSession> {
        validate_ring_capacity(ring_capacity)?;
        // SAFETY: `self.handle` is a live adapter owned by this value, and
        // `ring_capacity` is a validated power of two inside the range WinTun
        // documents, so the export only allocates the ring for this adapter.
        let session =
            unsafe { (self.lib.exports.start_session)(self.handle.as_ptr(), ring_capacity) };
        let Some(session) = NonNull::new(session) else {
            return Err(os_error_with(
                "WintunStartSession",
                ring_capacity,
                io::Error::last_os_error(),
            ));
        };
        // SAFETY: `session` is a live session created just above.
        let read_wait = unsafe { (self.lib.exports.get_read_wait_event)(session.as_ptr()) };
        if read_wait.is_null() {
            let err = io::Error::last_os_error();
            return Err(end_failed_session(
                &self.lib,
                session,
                os_error_with("WintunGetReadWaitEvent", &self.name, err),
            ));
        }
        let shutdown = match ShutdownEvent::new() {
            Ok(shutdown) => Arc::new(shutdown),
            Err(err) => return Err(end_failed_session(&self.lib, session, err)),
        };
        Ok(WinTunSession {
            adapter: Arc::clone(self),
            session,
            read_wait,
            shutdown,
            rx_lock: Mutex::new(()),
            tx_lock: Mutex::new(()),
        })
    }
}

impl Drop for WinTunAdapter {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is a live adapter that this value owns
        // exclusively; every session holds an `Arc` to the adapter, so none can
        // outlive this call.
        unsafe { (self.lib.exports.close_adapter)(self.handle.as_ptr()) };
    }
}

// SAFETY: the adapter handle names a kernel object that accepts calls from any
// thread, and `Drop` runs only after the last `Arc` clone, so no session can
// reach a closed adapter.
unsafe impl Send for WinTunAdapter {}

// SAFETY: the only values read through a shared reference are the immutable
// name, LUID, module `Arc`, and handle; starting a session takes `&Arc<Self>`
// and WinTun documents concurrent session creation on one adapter.
unsafe impl Sync for WinTunAdapter {}

/// An active WinTun ring-buffer session.
pub struct WinTunSession {
    adapter: Arc<WinTunAdapter>,
    session: NonNull<c_void>,
    read_wait: HANDLE,
    shutdown: Arc<ShutdownEvent>,
    /// Serialises a `WintunReceivePacket`/`WintunReleaseReceivePacket` pair so
    /// one ring slot is never handed to two readers.
    rx_lock: Mutex<()>,
    /// Serialises a `WintunAllocateSendPacket`/`WintunSendPacket` pair so one
    /// caller never writes into a slot another caller already sent.
    tx_lock: Mutex<()>,
}

impl WinTunSession {
    /// Cloneable handle that wakes a reader blocked in
    /// [`WinTunSession::recv_blocking`].
    pub fn shutdown_handle(&self) -> WinTunShutdown {
        WinTunShutdown(Arc::clone(&self.shutdown))
    }

    /// LUID of the adapter this session runs on.
    pub fn luid(&self) -> u64 {
        self.adapter.luid
    }

    /// Receives one packet if the ring buffer has one.
    ///
    /// `buf` must hold at least the adapter MTU. Returns `Ok(None)` when the
    /// ring is empty (`ERROR_NO_MORE_ITEMS`), and `Err` with
    /// [`io::ErrorKind::InvalidData`] when the packet is larger than `buf`. In
    /// both cases the packet is released back to WinTun; a packet that does not
    /// fit is dropped rather than truncated.
    pub fn try_recv_into(&self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        // The reader may live on any thread, so the receive pair stays
        // exclusive. A poisoned lock is recovered: the guard holds no data, and
        // a panic before `WintunReleaseReceivePacket` cannot leave a half-taken
        // slot behind.
        let _rx = self
            .rx_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        let mut packet_size = 0_u32;
        // SAFETY: `self.session` is a live session owned by this value, and the
        // export writes the packet length to the `u32` it is given.
        let packet = unsafe {
            (self.adapter.lib.exports.receive_packet)(self.session.as_ptr(), &raw mut packet_size)
        };
        if packet.is_null() {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NO_MORE_ITEMS as i32) {
                return Ok(None);
            }
            return Err(err);
        }
        let packet_size = packet_size as usize;
        // SAFETY: a non-null return means WinTun handed over a packet of
        // `packet_size` valid bytes inside the ring, which stays readable until
        // `WintunReleaseReceivePacket`.
        let received = unsafe { std::slice::from_raw_parts(packet, packet_size) };
        let fits = packet_size <= buf.len();
        if fits {
            buf[..packet_size].copy_from_slice(received);
        }
        // SAFETY: `packet` was returned by `WintunReceivePacket` on this
        // session and is released exactly once here, before the ring slot can
        // be reused.
        unsafe { (self.adapter.lib.exports.release_receive_packet)(self.session.as_ptr(), packet) };
        if fits {
            Ok(Some(packet_size))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "WinTun packet of {packet_size} bytes exceeds the {}-byte receive buffer",
                    buf.len()
                ),
            ))
        }
    }

    /// Receives one packet, waiting until one arrives or the session shuts
    /// down.
    ///
    /// Returns `Err` with [`io::ErrorKind::UnexpectedEof`] when
    /// [`WinTunSession::shutdown_handle`] was signaled on any thread.
    pub fn recv_blocking(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if let Some(len) = self.try_recv_into(buf)? {
                return Ok(len);
            }
            let handles: [HANDLE; 2] = [self.shutdown.handle, self.read_wait];
            // SAFETY: `handles` holds two live handles for the whole call,
            // `bwaitall` is false, and no pointer outlives the wait.
            let result = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
            if result == WAIT_OBJECT_0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("WinTun session on {:?} was shut down", self.adapter.name),
                ));
            }
            if result == WAIT_OBJECT_0 + 1 {
                // The read-wait event is signaled: the ring has a packet.
                continue;
            }
            if result == WAIT_FAILED {
                return Err(io::Error::last_os_error());
            }
            return Err(io::Error::other(format!(
                "unexpected WaitForMultipleObjects result {result}"
            )));
        }
    }

    /// Sends one IP packet through the adapter.
    ///
    /// The ring buffer holds a bounded number of packets, so a full ring
    /// reports `ERROR_BUFFER_OVERFLOW` (111), which is transient: callers count
    /// the drop and continue. `ERROR_HANDLE_EOF` (38) means the adapter is
    /// terminating and only a new adapter recovers from it.
    pub fn send_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.is_empty() || packet.len() > MAX_PACKET_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "WinTun packet must be 1..={MAX_PACKET_LEN} bytes, got {}",
                    packet.len()
                ),
            ));
        }
        let size = packet.len() as u32;
        // Several threads may send, so an allocate/send pair stays exclusive.
        // A poisoned lock is recovered: the guard holds no data and the ring
        // slot itself is allocated per call.
        let _tx = self
            .tx_lock
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: `self.session` is a live session owned by this value, and the
        // length is validated to fit the packet size WinTun accepts.
        let slot =
            unsafe { (self.adapter.lib.exports.allocate_send_packet)(self.session.as_ptr(), size) };
        if slot.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a non-null return from `WintunAllocateSendPacket` is a
        // writable slot of exactly `size` bytes that this thread owns until
        // `WintunSendPacket`; source and destination do not overlap.
        unsafe { ptr::copy_nonoverlapping(packet.as_ptr(), slot, packet.len()) };
        // SAFETY: `slot` was allocated just above on this session and is
        // handed back exactly once.
        unsafe { (self.adapter.lib.exports.send_packet)(self.session.as_ptr(), slot) };
        Ok(())
    }
}

impl Drop for WinTunSession {
    fn drop(&mut self) {
        // Wake any reader that is about to wait on the shutdown event, so it
        // cannot sleep past the end of the session.
        let _ = self.shutdown.signal();
        // SAFETY: `self.session` is a live session that this value owns
        // exclusively; no reader can be blocked here because a blocked reader
        // holds a reference to this session.
        unsafe { (self.adapter.lib.exports.end_session)(self.session.as_ptr()) };
    }
}

// SAFETY: WinTun documents that one session may be used from several threads
// (one receiver, any number of senders); every field is an `Arc`, an immutable
// handle, a `Mutex`, or a pointer the DLL manages internally, so moving the
// session moves no state another thread reads.
unsafe impl Send for WinTunSession {}

// SAFETY: the two WinTun call pairs that share ring state are serialised:
// `try_recv_into` holds `rx_lock` across receive and release, and `send_packet`
// holds `tx_lock` across allocate and send. The remaining fields read through
// `&self` are `Arc`s, an immutable handle, and a session pointer the driver
// manages, so dedicated reader and writer threads cannot race inside a pair.
unsafe impl Sync for WinTunSession {}

/// Cloneable wake handle for a [`WinTunSession`].
///
/// The underlying manual-reset Win32 event stays open until the last clone and
/// the session are gone, so signaling after the session stopped is harmless.
#[derive(Clone)]
pub struct WinTunShutdown(Arc<ShutdownEvent>);

impl WinTunShutdown {
    /// Wakes a reader blocked in [`WinTunSession::recv_blocking`].
    pub fn signal(&self) -> io::Result<()> {
        self.0.signal()
    }
}

/// Owned manual-reset Win32 event used as the shutdown signal.
struct ShutdownEvent {
    handle: HANDLE,
}

impl ShutdownEvent {
    fn new() -> io::Result<Self> {
        // SAFETY: a null security-attribute pointer and a null name ask for an
        // unnamed, uninheritable event that this process owns; the two `BOOL`
        // arguments are plain integers.
        let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { handle })
    }

    fn signal(&self) -> io::Result<()> {
        // SAFETY: `self.handle` is a live event owned by this value and valid
        // until `Drop`, and `SetEvent` only sets its state.
        let result = unsafe { SetEvent(self.handle) };
        if result == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for ShutdownEvent {
    fn drop(&mut self) {
        // SAFETY: `self.handle` was created by `CreateEventW` and is not used
        // after this call, because every user holds an `Arc` to this value.
        unsafe { CloseHandle(self.handle) };
    }
}

// SAFETY: an event handle names a kernel object that any thread may call
// `SetEvent` or `CloseHandle` on, and the handle value never changes.
unsafe impl Send for ShutdownEvent {}

// SAFETY: `signal` reads only the immutable handle; the kernel serialises
// concurrent `SetEvent` calls.
unsafe impl Sync for ShutdownEvent {}

/// Derives the adapter GUID that Windows uses as the interface
/// `NetCfgInstanceId`.
///
/// The value is the first 16 bytes of SHA-256 over
/// `"beam-wintun-adapter:" + name`, stamped with the RFC 4122 version 5 and
/// variant bits, so a given adapter name always yields the same network
/// interface instead of a new "Network N" profile on every restart.
pub fn adapter_guid(name: &str) -> GUID {
    GUID::from_u128(u128::from_be_bytes(adapter_guid_bytes(name)))
}

/// Builds the 16 RFC 4122 bytes that [`adapter_guid`] converts into a `GUID`.
fn adapter_guid_bytes(name: &str) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(b"beam-wintun-adapter:");
    hasher.update(name.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Version 5 (SHA-256 name-based) and RFC 4122 variant.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes
}

/// Ends a session that could not be fully set up and returns `err`.
fn end_failed_session(lib: &WinTunLib, session: NonNull<c_void>, err: io::Error) -> io::Error {
    // SAFETY: `session` was created by `WintunStartSession` on this adapter and
    // is not used after this call, because the caller only holds a raw handle
    // and no session value exists yet.
    unsafe { (lib.exports.end_session)(session.as_ptr()) };
    err
}

/// Checks that `capacity` is a ring size WinTun accepts.
fn validate_ring_capacity(capacity: u32) -> io::Result<()> {
    if !(MIN_RING_CAPACITY..=MAX_RING_CAPACITY).contains(&capacity) || !capacity.is_power_of_two() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "WinTun ring capacity must be a power of two in \
                 {MIN_RING_CAPACITY:#x}..={MAX_RING_CAPACITY:#x}, got {capacity:#x}"
            ),
        ));
    }
    Ok(())
}

/// Checks that the tunnel type is a short, NUL-free driver string.
fn validate_tunnel_type(tunnel_type: &str) -> io::Result<()> {
    if tunnel_type.is_empty()
        || tunnel_type.encode_utf16().count() > MAX_TUNNEL_TYPE_LEN
        || tunnel_type.chars().any(char::is_control)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("tunnel type must be 1..={MAX_TUNNEL_TYPE_LEN} printable UTF-16 code units"),
        ));
    }
    Ok(())
}

/// Encodes `value` as a NUL-terminated UTF-16 string of at most `max_units`
/// code units.
fn wide_str(value: &str, max_units: usize) -> io::Result<Vec<u16>> {
    if value.contains('\0') || value.encode_utf16().count() > max_units {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("string must be at most {max_units} UTF-16 code units without NUL"),
        ));
    }
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    Ok(wide)
}

/// Encodes a path as a NUL-terminated UTF-16 string.
fn wide_os_str(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut wide: Vec<u16> = value.encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path must not contain NUL",
        ));
    }
    wide.push(0);
    Ok(wide)
}

/// Builds the error for an OS call that failed with `error`.
fn os_error_with(operation: &str, subject: impl std::fmt::Display, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!("{operation} {subject} failed: {error}"),
    )
}

/// Builds the error for a DLL that is missing an expected export.
fn missing_export(path: &Path, name: &CStr) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!(
            "{} does not export {} (WinTun {WINTUN_VERSION} is required)",
            path.display(),
            name.to_string_lossy()
        ),
    )
}

/// Verifies that the file at `path` has the SHA-256 digest `expected`.
///
/// The file is read in bounded chunks and must be at most [`MAX_DLL_BYTES`].
pub fn verify_dll_sha256(path: &Path, expected: &[u8; 32]) -> io::Result<()> {
    let actual = sha256_file(path, MAX_DLL_BYTES)?;
    if !constant_time_eq(&actual, expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} has SHA-256 {}, which does not match the pinned {}",
                path.display(),
                encode_sha256_hex(&actual),
                encode_sha256_hex(expected)
            ),
        ));
    }
    Ok(())
}

/// Hashes at most `max_bytes` of the file at `path`.
fn sha256_file(path: &Path, max_bytes: u64) -> io::Result<[u8; 32]> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} is not a regular file", path.display()),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(too_large(path, metadata.len(), max_bytes));
    }
    // Read one byte past the limit so a file that grew after `metadata` still
    // trips the bound.
    let mut reader = BufReader::new(file).take(max_bytes.saturating_add(1));
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > max_bytes {
            return Err(too_large(path, total, max_bytes));
        }
        hasher.update(&buffer[..read]);
    }
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    Ok(digest)
}

fn too_large(path: &Path, size: u64, max_bytes: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} is {size} bytes, above the {max_bytes}-byte limit",
            path.display()
        ),
    )
}

/// Decodes a 64-character lowercase or uppercase SHA-256 hex string.
pub fn decode_sha256_hex(hex: &str) -> io::Result<[u8; 32]> {
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("SHA-256 hex must be 64 characters, got {}", bytes.len()),
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, slot) in digest.iter_mut().enumerate() {
        let (Some(high), Some(low)) = (
            hex_nibble(bytes[index * 2]),
            hex_nibble(bytes[index * 2 + 1]),
        ) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SHA-256 hex contains a non-hex character",
            ));
        };
        *slot = (high << 4) | low;
    }
    Ok(digest)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn encode_sha256_hex(digest: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Compares two digests without an early exit.
fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right.iter()) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RING_CAPACITY, MAX_PACKET_LEN, MAX_RING_CAPACITY, MIN_RING_CAPACITY,
        WINTUN_0_14_1_AMD64_SHA256, adapter_guid, decode_sha256_hex, sha256_file,
        validate_ring_capacity, validate_tunnel_type, verify_dll_sha256,
    };
    use sha2::{Digest, Sha256};
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn adapter_guid_is_deterministic_and_version_five() {
        let first = adapter_guid("Beam TUN 0");
        let second = adapter_guid("Beam TUN 0");
        assert_eq!(
            guid_bytes(first),
            guid_bytes(second),
            "the same name must map to one interface"
        );
        assert_ne!(guid_bytes(first), guid_bytes(adapter_guid("Beam TUN 1")));

        let bytes = guid_bytes(first);
        assert_eq!(bytes[6] >> 4, 5, "RFC 4122 version 5");
        assert_eq!(bytes[8] >> 6, 0b10, "RFC 4122 variant");

        // Pinned so a change to the derivation cannot silently move every
        // existing installation to a new network profile.
        assert_eq!(
            bytes,
            [
                0xe2, 0xd9, 0x13, 0x4b, 0x3d, 0xd1, 0x54, 0xbd, 0xbe, 0x76, 0xd0, 0xfd, 0x12, 0xd1,
                0x83, 0xcd,
            ]
        );
    }

    fn guid_bytes(guid: windows_sys::core::GUID) -> [u8; 16] {
        let mut bytes = [0_u8; 16];
        bytes[..4].copy_from_slice(&guid.data1.to_be_bytes());
        bytes[4..6].copy_from_slice(&guid.data2.to_be_bytes());
        bytes[6..8].copy_from_slice(&guid.data3.to_be_bytes());
        bytes[8..].copy_from_slice(&guid.data4);
        bytes
    }

    #[test]
    fn ring_capacity_accepts_powers_of_two_in_range_only() {
        for capacity in [MIN_RING_CAPACITY, DEFAULT_RING_CAPACITY, MAX_RING_CAPACITY] {
            assert!(
                validate_ring_capacity(capacity).is_ok(),
                "{capacity:#x} must be accepted"
            );
        }
        for capacity in [
            0,
            MIN_RING_CAPACITY / 2,
            DEFAULT_RING_CAPACITY + 1,
            MAX_RING_CAPACITY * 2,
        ] {
            assert!(
                validate_ring_capacity(capacity).is_err(),
                "{capacity:#x} must be rejected"
            );
        }
    }

    #[test]
    fn tunnel_type_rejects_empty_control_and_overlong_values() {
        assert!(validate_tunnel_type("beam").is_ok());
        assert!(validate_tunnel_type("").is_err());
        assert!(validate_tunnel_type("beam\0").is_err());
        assert!(validate_tunnel_type("beam\n").is_err());
        assert!(validate_tunnel_type(&"a".repeat(65)).is_err());
    }

    #[test]
    fn pinned_sha256_constant_decodes_to_thirty_two_bytes() {
        let digest = decode_sha256_hex(WINTUN_0_14_1_AMD64_SHA256).expect("pinned digest");
        assert_eq!(&digest[..4], &[0xe5, 0xda, 0x84, 0x47]);
        assert_eq!(&digest[28..], &[0x22, 0x0d, 0xaf, 0xce]);
        assert!(decode_sha256_hex("00").is_err());
        assert!(decode_sha256_hex(&"z".repeat(64)).is_err());
        assert_eq!(
            decode_sha256_hex(&"AB".repeat(32)).expect("uppercase hex"),
            [0xab; 32]
        );
    }

    #[test]
    fn verify_dll_sha256_accepts_the_matching_file_and_rejects_others() {
        let path = temp_file("wintun-verify.bin");
        fs::write(&path, b"beam wintun fixture").expect("write fixture");
        let expected = Sha256::digest(b"beam wintun fixture");
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&expected);

        assert!(verify_dll_sha256(&path, &digest).is_ok());
        assert!(verify_dll_sha256(&path, &[0x11; 32]).is_err());
        assert!(verify_dll_sha256(&temp_file("wintun-missing.dll"), &digest).is_err());

        fs::remove_file(&path).expect("remove fixture");
    }

    #[test]
    fn sha256_file_stops_at_the_size_bound() {
        let path = temp_file("wintun-limit.bin");
        fs::write(&path, [0_u8; 8]).expect("write fixture");
        assert!(sha256_file(&path, 8).is_ok());
        assert!(sha256_file(&path, 7).is_err());
        fs::remove_file(&path).expect("remove fixture");
    }

    #[test]
    fn packet_size_bound_matches_the_u16_frame_limit() {
        assert_eq!(MAX_PACKET_LEN, u16::MAX as usize);
    }

    fn temp_file(name: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("beam-{}-{unique}-{name}", std::process::id()))
    }
}
