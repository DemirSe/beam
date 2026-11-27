//! Windows Named Pipe IPC server/client wrappers with SDDL DACL enforcement.
//!
//! The pipe is the only channel between the unelevated tray and the
//! `LocalSystem` service, so the DACL is built here from an explicit SDDL
//! string: `SYSTEM` and `Administrators` always get full access and an optional
//! user SID gets read/write. A missing user SID fails closed instead of opening
//! the pipe to everyone.
//!
//! The wire format is one UTF-8 line per direction, at most
//! [`MAX_IPC_MESSAGE_BYTES`] bytes, one request and one response per connection.
//! Every overlapped operation below follows the same rule: either it completes,
//! or [`cancel_and_drain`] waits until the kernel no longer references the
//! [`OVERLAPPED`], so the structure and its buffer can never outlive the
//! operation they describe.

use std::io;
use std::mem::size_of;
use std::ptr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
};

/// Default pipe the tray and the CLI use to reach the service.
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\beam-client-ipc";

/// Largest IPC message accepted in either direction.
pub const MAX_IPC_MESSAGE_BYTES: usize = 4096;

/// Prefix every local named pipe name carries.
const PIPE_NAME_PREFIX: &str = r"\\.\pipe\";

/// Maximum named pipe name length, in UTF-16 code units.
const MAX_PIPE_NAME_CHARS: usize = 256;

/// Buffer size for each direction of the pipe.
const PIPE_BUFFER_BYTES: u32 = 4096;

/// One server instance: the service serializes IPC requests itself.
const PIPE_INSTANCES: u32 = 1;

/// Bytes read from the pipe per overlapped read.
const READ_CHUNK_BYTES: usize = 256;

/// Shortest SID string this module considers (`S-1-5`).
const MIN_SID_CHARS: usize = 5;

/// Longest SID string Windows produces (184 bytes for 15 sub-authorities).
const MAX_SID_CHARS: usize = 184;

/// A SID carries at most 15 sub-authorities.
const MAX_SID_SUBAUTHORITIES: usize = 15;

/// DACL that grants full access to `SYSTEM` and `Administrators` only.
const BASE_PIPE_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

/// Verifies that `sid` is a canonical Windows SID string such as
/// `S-1-5-21-3623811015-3361044348-30300820-1013`.
///
/// The check is strict on purpose: the SID is spliced into an SDDL DACL, so any
/// character SDDL treats as syntax (`(`, `)`, `;`, `,`) must be rejected before
/// the string reaches [`ConvertStringSecurityDescriptorToSecurityDescriptorW`].
/// Only canonical `S-1-<authority>-<sub-authority>...` strings are accepted:
/// ASCII only, no leading zeros, at most 15 sub-authorities, and every numeric
/// component must fit in 32 bits.
pub fn validate_windows_sid(sid: &str) -> io::Result<()> {
    if sid.len() < MIN_SID_CHARS || sid.len() > MAX_SID_CHARS {
        return Err(invalid_input(format!(
            "SID length must be {MIN_SID_CHARS}..={MAX_SID_CHARS} bytes"
        )));
    }
    if !sid.is_ascii() {
        return Err(invalid_input("SID must be ASCII"));
    }

    let mut parts = sid.split('-');
    if parts.next() != Some("S") {
        return Err(invalid_input("SID must start with `S-1-`"));
    }
    if parts.next() != Some("1") {
        return Err(invalid_input("SID revision must be 1"));
    }
    let authority = parts
        .next()
        .ok_or_else(|| invalid_input("SID is missing its identifier authority"))?;
    sid_component(authority)?;

    let mut sub_authorities = 0;
    for part in parts {
        sid_component(part)?;
        sub_authorities += 1;
    }
    if sub_authorities == 0 || sub_authorities > MAX_SID_SUBAUTHORITIES {
        return Err(invalid_input(format!(
            "SID must have 1..={MAX_SID_SUBAUTHORITIES} sub-authorities"
        )));
    }
    Ok(())
}

/// Parses one numeric SID component: decimal digits, no leading zero, `u32`.
fn sid_component(component: &str) -> io::Result<u32> {
    if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_input("SID components must be decimal numbers"));
    }
    if component.len() > 1 && component.starts_with('0') {
        return Err(invalid_input("SID components must not have leading zeros"));
    }
    component
        .parse::<u32>()
        .map_err(|_| invalid_input("SID component does not fit in 32 bits"))
}

/// Builds the SDDL DACL for the IPC pipe.
///
/// `SYSTEM` and `Administrators` always get full access. `None` keeps the pipe
/// closed to every other principal, which is the fail-closed result when the
/// allowed-user SID file is missing. `Some(sid)` grants that user read/write
/// after [`validate_windows_sid`] accepts it.
pub fn build_pipe_sddl(allowed_user_sid: Option<&str>) -> io::Result<String> {
    match allowed_user_sid {
        None => Ok(BASE_PIPE_SDDL.to_owned()),
        Some(sid) => {
            validate_windows_sid(sid)?;
            Ok(format!("{BASE_PIPE_SDDL}(A;;GRGW;;;{sid})"))
        }
    }
}

/// Owned self-relative security descriptor built from an SDDL string.
pub struct SecurityDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

impl SecurityDescriptor {
    /// Converts `sddl` into a security descriptor the kernel accepts.
    pub fn from_sddl(sddl: &str) -> io::Result<Self> {
        let sddl = nul_terminated(sddl);
        let mut raw: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let mut size = 0_u32;
        // SAFETY: `sddl` is NUL-terminated UTF-16 and outlives the call; `raw`
        // and `size` are live out-parameters of the declared types. On success
        // the API allocates one descriptor with `LocalAlloc` and transfers
        // ownership to this value, which frees it in `Drop`.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                &raw mut size,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if raw.is_null() {
            return Err(io::Error::other(
                "security descriptor conversion returned a null pointer",
            ));
        }
        Ok(Self { raw })
    }

    /// Returns the descriptor pointer for a `SECURITY_ATTRIBUTES` value.
    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.raw
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: `raw` was allocated by
        // `ConvertStringSecurityDescriptorToSecurityDescriptorW` with
        // `LocalAlloc`, and `LocalFree` is the matching deallocator. The
        // pointer is freed exactly once, here, and never used afterwards.
        unsafe {
            LocalFree(self.raw.cast());
        }
    }
}

/// Owning wrapper around a kernel handle, closed exactly once.
struct OwnedHandle(HANDLE);

// SAFETY: a Win32 kernel handle is a process-wide value, not a thread-bound
// resource, and every call this module makes with it (`ReadFile`, `WriteFile`,
// `CancelIoEx`, `SetEvent`, `GetOverlappedResult`) is safe to issue from any
// thread. The handle is closed once, by `Drop`, after the owner has drained any
// pending overlapped operation.
unsafe impl Send for OwnedHandle {}
// SAFETY: shared references only expose `raw()`, which copies the handle value;
// `Drop` requires exclusive ownership, so the handle is never closed twice.
unsafe impl Sync for OwnedHandle {}

impl OwnedHandle {
    /// Takes ownership of a handle returned by a creation call.
    fn from_create(handle: HANDLE) -> io::Result<Self> {
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            let error = io::Error::last_os_error();
            return Err(match error.raw_os_error() {
                Some(0) | None => io::Error::other("handle creation failed without an error code"),
                Some(_) => error,
            });
        }
        Ok(Self(handle))
    }

    /// Returns the raw handle for a Win32 call.
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `0` is a live handle owned by this value, and `Drop` runs once,
        // so it is closed exactly once.
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Manual-reset event that asks a pending accept to stop.
///
/// Cloning shares the same kernel event, so one `set` releases every clone.
#[derive(Clone)]
pub struct CancelEvent(Arc<OwnedHandle>);

impl CancelEvent {
    /// Creates an unsignalled manual-reset event.
    pub fn new() -> io::Result<Self> {
        let handle = create_event()?;
        Ok(Self(Arc::new(handle)))
    }

    /// Signals every [`NamedPipeServer::accept_or_cancel`] waiting on a clone.
    pub fn set(&self) -> io::Result<()> {
        // SAFETY: `0` is a live manual-reset event handle that this value owns.
        if unsafe { SetEvent(self.0.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Clears the signal so a later accept can wait on this event again.
    pub fn reset(&self) -> io::Result<()> {
        // SAFETY: `0` is a live manual-reset event handle that this value owns.
        if unsafe { ResetEvent(self.0.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Returns the raw handle for `WaitForMultipleObjects`.
    fn raw(&self) -> HANDLE {
        self.0.raw()
    }
}

/// Creates an unnamed, unsignalled, manual-reset event.
fn create_event() -> io::Result<OwnedHandle> {
    // SAFETY: all three optional arguments are null or plain values: default
    // security, manual reset, initially unsignalled, unnamed. The returned
    // handle is the only reference to the new event.
    let handle = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    OwnedHandle::from_create(handle)
}

/// Listening end of the `\\.\pipe\beam-client-ipc` IPC pipe.
///
/// The first instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`, so a
/// squatter that already created the name makes [`create`](Self::create) fail
/// instead of handing the service a pipe owned by another security context.
///
/// Every method either completes its overlapped operation or cancels and drains
/// it before returning, so `Drop` only has to close the handles.
pub struct NamedPipeServer {
    /// Pipe handle, closed by `Drop`.
    handle: OwnedHandle,
    /// Completion event, also stored in `overlapped.hEvent`.
    event: OwnedHandle,
    /// Reused `OVERLAPPED`; boxed so its address is stable while pending.
    overlapped: Box<OVERLAPPED>,
    /// True between a successful accept and the next disconnect.
    connected: bool,
}

impl NamedPipeServer {
    /// Creates the first pipe instance with the SDDL DACL from
    /// [`build_pipe_sddl`].
    ///
    /// The pipe is byte-oriented, blocking, and rejects remote clients. Exactly
    /// one instance is created, so the service accepts one peer at a time.
    pub fn create(pipe_name: &str, allowed_user_sid: Option<&str>) -> io::Result<Self> {
        validate_pipe_name(pipe_name)?;
        let sddl = build_pipe_sddl(allowed_user_sid)?;
        let descriptor = SecurityDescriptor::from_sddl(&sddl)?;
        let name = nul_terminated(pipe_name);
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.as_ptr(),
            bInheritHandle: 0,
        };
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: `name` is NUL-terminated UTF-16 and `attributes` points at the
        // live descriptor for the whole call, which the kernel copies before
        // returning. The default time-out only affects `WaitNamedPipe` callers
        // and is unused here.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                pipe_mode,
                PIPE_INSTANCES,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &raw const attributes,
            )
        };
        let handle = OwnedHandle::from_create(handle)?;
        let event = create_event()?;
        let mut overlapped = Box::new(OVERLAPPED::default());
        overlapped.hEvent = event.raw();
        Ok(Self {
            handle,
            event,
            overlapped,
            connected: false,
        })
    }

    /// Waits until a client connects or `cancel_event` is signalled.
    ///
    /// Returns `Ok(true)` when a client connected, including the
    /// `ERROR_PIPE_CONNECTED` case where the client connected before the call.
    /// Returns `Ok(false)` when the event was signalled; the pending
    /// `ConnectNamedPipe` is cancelled and drained first, and no client is
    /// connected afterwards.
    pub fn accept_or_cancel(&mut self, cancel_event: &CancelEvent) -> io::Result<bool> {
        self.connected = false;
        prepare_io(&mut self.overlapped)?;
        // SAFETY: the pipe handle is live and owned by `self`, and
        // `self.overlapped` is a boxed, zeroed `OVERLAPPED` whose event is a live
        // manual-reset event. The box is not moved or freed until the operation
        // completes or `cancel_and_drain` has waited for the cancellation.
        let ok = unsafe { ConnectNamedPipe(self.handle.raw(), &raw mut *self.overlapped) };
        if ok != 0 {
            self.connected = true;
            return Ok(true);
        }
        match last_error_code() {
            ERROR_PIPE_CONNECTED => {
                self.connected = true;
                Ok(true)
            }
            ERROR_IO_PENDING => self.wait_for_client(cancel_event),
            code => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    /// Waits for the pending accept, with the cancel event as the second handle.
    fn wait_for_client(&mut self, cancel_event: &CancelEvent) -> io::Result<bool> {
        let handles = [cancel_event.raw(), self.event.raw()];
        // SAFETY: `handles` holds two live event handles and the count matches
        // the array length; `bWaitAll` is false so the lowest signalled index is
        // returned. No pointer outlives the call.
        let wait = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
        if wait == WAIT_OBJECT_0 {
            cancel_and_drain(self.handle.raw(), &mut self.overlapped);
            // A client can connect between the wait and the cancellation, which
            // would leave it attached even though `Ok(false)` says otherwise.
            // `ERROR_PIPE_NOT_CONNECTED` means there was nothing to disconnect,
            // which is the state the caller asked for.
            // SAFETY: `0` is the live pipe handle owned by `self`; the accept
            // above has been drained, so no overlapped operation is pending.
            if unsafe { DisconnectNamedPipe(self.handle.raw()) } == 0 {
                let code = last_error_code();
                if code != ERROR_PIPE_NOT_CONNECTED {
                    return Err(io::Error::from_raw_os_error(code as i32));
                }
            }
            return Ok(false);
        }
        if wait == WAIT_OBJECT_0 + 1 {
            return match finish_io(self.handle.raw(), &mut self.overlapped) {
                Ok(_) => {
                    self.connected = true;
                    Ok(true)
                }
                // The client connected between `CreateNamedPipeW` and
                // `ConnectNamedPipe`; the overlapped operation reports the
                // documented `ERROR_PIPE_CONNECTED` in that race.
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) => {
                    self.connected = true;
                    Ok(true)
                }
                Err(error) => Err(error),
            };
        }
        let error = io::Error::last_os_error();
        cancel_and_drain(self.handle.raw(), &mut self.overlapped);
        Err(error)
    }

    /// Reads one line of at most `max_bytes` bytes, without the terminator.
    ///
    /// The timeout covers the whole message, not each read. A line that is not
    /// terminated within `max_bytes` fails with [`io::ErrorKind::InvalidData`]; a
    /// peer that closes without sending anything yields an empty vector.
    pub fn read_line_bounded(&mut self, max_bytes: usize, timeout_ms: u32) -> io::Result<Vec<u8>> {
        if !self.connected {
            return Err(not_connected());
        }
        let handle = self.handle.raw();
        let overlapped = &mut self.overlapped;
        read_line(max_bytes, timeout_ms, |buffer, budget_ms| {
            read_some(handle, overlapped, buffer, budget_ms)
        })
    }

    /// Writes `data` into the pipe buffer within `timeout_ms`.
    ///
    /// No flush follows the write: every message fits the 4 KiB pipe buffer, so
    /// the overlapped `WriteFile` hands the whole message to the kernel, and a
    /// client that stops reading cannot block the server here.
    pub fn write_all_bounded(&mut self, data: &[u8], timeout_ms: u32) -> io::Result<()> {
        if !self.connected {
            return Err(not_connected());
        }
        if data.is_empty() || data.len() > MAX_IPC_MESSAGE_BYTES {
            return Err(invalid_input(format!(
                "IPC message must be 1..={MAX_IPC_MESSAGE_BYTES} bytes"
            )));
        }
        let timeout = checked_timeout(timeout_ms)?;
        write_all(self.handle.raw(), &mut self.overlapped, data, timeout)
    }

    /// Waits up to `timeout_ms` for the connected client to close its end.
    ///
    /// The kernel reports a client close as a zero-byte read, so one bounded
    /// overlapped byte read turns "the client finished the conversation" into a
    /// wait instead of a poll: it returns on `ERROR_BROKEN_PIPE` /
    /// `ERROR_PIPE_NOT_CONNECTED`, or once the timeout elapses, and a timed-out
    /// read is cancelled and drained. A byte read means the client is still
    /// sending, so it is consumed and the call returns at once.
    ///
    /// Callers write a response, call `wait_client_close(200)`, then
    /// [`disconnect`](Self::disconnect): `DisconnectNamedPipe` discards reply
    /// bytes the client has not read yet, so the wait is what prevents a lost
    /// response.
    pub fn wait_client_close(&mut self, timeout_ms: u32) -> io::Result<()> {
        checked_timeout(timeout_ms)?;
        if !self.connected {
            return Ok(());
        }
        let mut byte = [0_u8; 1];
        match read_some(
            self.handle.raw(),
            &mut self.overlapped,
            &mut byte,
            timeout_ms,
        ) {
            Ok(_) => Ok(()),
            // The wait is bounded by design; a timeout is the documented result.
            Err(error) if error.kind() == io::ErrorKind::TimedOut => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Writes `line` as one `\n`-terminated message within `timeout_ms`.
    ///
    /// One optional trailing `\n` is accepted and not doubled. Any other `\r` or
    /// `\n` is rejected because it would encode a second message, and the
    /// terminated message must fit [`MAX_IPC_MESSAGE_BYTES`].
    pub fn write_line_bounded(&mut self, line: &[u8], timeout_ms: u32) -> io::Result<()> {
        let body = reply_line_body(line)?;
        let mut message = Vec::with_capacity(body.len() + 1);
        message.extend_from_slice(body);
        message.push(b'\n');
        self.write_all_bounded(&message, timeout_ms)
    }

    /// Disconnects the current client so the instance can accept again.
    ///
    /// Call [`wait_client_close`](Self::wait_client_close) first: a disconnect
    /// discards reply bytes the client has not read yet.
    pub fn disconnect(&mut self) -> io::Result<()> {
        self.connected = false;
        // SAFETY: `0` is the live pipe handle owned by `self`; no overlapped
        // operation is pending because every method drains its own I/O.
        if unsafe { DisconnectNamedPipe(self.handle.raw()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

/// Client end of the IPC pipe, used by the CLI and the integration tests.
pub struct NamedPipeClient;

impl NamedPipeClient {
    /// Sends one request line and returns the response line.
    ///
    /// `line` must not contain a line terminator; one is appended. Both the
    /// write and the read are bounded by `timeout_ms` and by
    /// [`MAX_IPC_MESSAGE_BYTES`].
    pub fn request(pipe_name: &str, line: &[u8], timeout_ms: u32) -> io::Result<Vec<u8>> {
        validate_pipe_name(pipe_name)?;
        validate_request(line)?;
        let timeout = checked_timeout(timeout_ms)?;
        let name = nul_terminated(pipe_name);
        // SAFETY: `name` is NUL-terminated UTF-16 and outlives the call; there is
        // no template handle and no security attributes, so both pointers are
        // null. `FILE_FLAG_OVERLAPPED` makes every later operation cancellable.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        let handle = OwnedHandle::from_create(handle)?;
        let event = create_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..OVERLAPPED::default()
        };

        let mut request = Vec::with_capacity(line.len() + 1);
        request.extend_from_slice(line);
        request.push(b'\n');
        write_all(handle.raw(), &mut overlapped, &request, timeout)?;

        let raw = handle.raw();
        read_line(MAX_IPC_MESSAGE_BYTES, timeout_ms, |buffer, budget_ms| {
            read_some(raw, &mut overlapped, buffer, budget_ms)
        })
    }
}

/// Clears the completion fields of a reusable `OVERLAPPED` and resets its event.
///
/// The caller must have no operation pending on `overlapped`; every path in this
/// module either completes the operation or calls [`cancel_and_drain`] first, so
/// the zeroing below can never hide a completion the kernel still needs.
fn prepare_io(overlapped: &mut OVERLAPPED) -> io::Result<()> {
    let event = overlapped.hEvent;
    if event.is_null() {
        return Err(io::Error::other("overlapped operation has no event"));
    }
    // The kernel requires the completion fields to be zero before the next
    // operation; the event handle is preserved.
    *overlapped = OVERLAPPED {
        hEvent: event,
        ..OVERLAPPED::default()
    };
    // SAFETY: `event` is the live manual-reset event owned by the server or
    // client that owns this `OVERLAPPED`; `ResetEvent` only clears its signalled
    // state and retains no pointer.
    if unsafe { ResetEvent(event) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Waits for a completed overlapped operation and returns the byte count.
fn finish_io(handle: HANDLE, overlapped: &mut OVERLAPPED) -> io::Result<u32> {
    let mut transferred = 0_u32;
    // SAFETY: `overlapped` is live and owned by the caller; `bWait` is true, so
    // the call returns only when the operation completed and the kernel no
    // longer references the structure. `transferred` is a live `u32` output.
    let ok =
        unsafe { GetOverlappedResult(handle, &raw const *overlapped, &raw mut transferred, 1) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(transferred)
}

/// Cancels a pending overlapped operation and waits until the kernel finished
/// with the `OVERLAPPED`.
///
/// This is the invariant that lets the caller reuse or free the `OVERLAPPED` and
/// its buffer: `CancelIoEx` only marks the request for cancellation, and the
/// blocking `GetOverlappedResult` is what guarantees completion.
fn cancel_and_drain(handle: HANDLE, overlapped: &mut OVERLAPPED) {
    // SAFETY: `handle` and `overlapped` are live. Cancelling an operation that
    // already completed only reports `ERROR_NOT_FOUND`, which is ignored
    // because the drain below establishes the real state.
    unsafe {
        CancelIoEx(handle, &raw const *overlapped);
    }
    let mut transferred = 0_u32;
    // SAFETY: `bWait` is true, so this returns only after the cancelled
    // operation completed; the kernel then holds no reference into the
    // `OVERLAPPED`. The result is intentionally ignored: the operation was
    // abandoned and its error is not useful to the caller.
    unsafe {
        GetOverlappedResult(handle, &raw const *overlapped, &raw mut transferred, 1);
    }
}

/// Waits for a pending overlapped operation, cancelling it on timeout.
fn wait_io(handle: HANDLE, overlapped: &mut OVERLAPPED, timeout_ms: u32) -> io::Result<u32> {
    // SAFETY: `overlapped.hEvent` is the live manual-reset event belonging to
    // `handle`; no pointer is retained.
    let wait = unsafe { WaitForSingleObject(overlapped.hEvent, timeout_ms) };
    if wait == WAIT_OBJECT_0 {
        return finish_io(handle, overlapped);
    }
    cancel_and_drain(handle, overlapped);
    if wait == WAIT_TIMEOUT {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "named pipe I/O timed out",
        ));
    }
    Err(io::Error::last_os_error())
}

/// Reads one chunk from the pipe, returning `0` when the peer closed.
fn read_some(
    handle: HANDLE,
    overlapped: &mut OVERLAPPED,
    buffer: &mut [u8],
    timeout_ms: u32,
) -> io::Result<usize> {
    let len = u32::try_from(buffer.len())
        .map_err(|_| invalid_input("read buffer does not fit in 32 bits"))?;
    if len == 0 {
        return Err(invalid_input("read buffer must not be empty"));
    }
    prepare_io(overlapped)?;
    // SAFETY: `buffer` and `len` describe the same live region for the whole
    // call, and the region outlives the wait below. The byte-count output is
    // null because overlapped calls must not report it; `GetOverlappedResult`
    // supplies the count after completion.
    let ok = unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr(),
            len,
            ptr::null_mut(),
            &raw mut *overlapped,
        )
    };
    if ok != 0 {
        return Ok(finish_io(handle, overlapped)? as usize);
    }
    match last_error_code() {
        ERROR_IO_PENDING => match wait_io(handle, overlapped, timeout_ms) {
            Ok(n) => Ok(n as usize),
            Err(err)
                if matches!(
                    err.raw_os_error().map(|c| c as u32),
                    Some(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA)
                ) =>
            {
                Ok(0)
            }
            Err(err) => Err(err),
        },
        // The peer closed; for a line protocol that is a clean end of stream.
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA => Ok(0),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

/// Writes one chunk to the pipe.
fn write_some(
    handle: HANDLE,
    overlapped: &mut OVERLAPPED,
    data: &[u8],
    timeout_ms: u32,
) -> io::Result<usize> {
    let len =
        u32::try_from(data.len()).map_err(|_| invalid_input("write buffer does not fit in u32"))?;
    if len == 0 {
        return Err(invalid_input("write buffer must not be empty"));
    }
    prepare_io(overlapped)?;
    // SAFETY: `data` and `len` describe the same live region, and the caller's
    // slice outlives the wait below. The byte-count output is null for the same
    // reason as in `read_some`.
    let ok = unsafe {
        WriteFile(
            handle,
            data.as_ptr(),
            len,
            ptr::null_mut(),
            &raw mut *overlapped,
        )
    };
    if ok != 0 {
        return Ok(finish_io(handle, overlapped)? as usize);
    }
    match last_error_code() {
        ERROR_IO_PENDING => Ok(wait_io(handle, overlapped, timeout_ms)? as usize),
        code => Err(io::Error::from_raw_os_error(code as i32)),
    }
}

/// Writes all of `data` into the pipe buffer within `timeout`.
fn write_all(
    handle: HANDLE,
    overlapped: &mut OVERLAPPED,
    data: &[u8],
    timeout: Duration,
) -> io::Result<()> {
    let started = Instant::now();
    let mut written = 0;
    while written < data.len() {
        let budget = remaining_budget(timeout, started);
        let count = write_some(handle, overlapped, &data[written..], budget)?;
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "named pipe write made no progress",
            ));
        }
        written += count;
    }
    Ok(())
}

/// Reads one line of at most `max_bytes` bytes using `read_chunk`.
///
/// Returns the line without `\n` or a trailing `\r`. Chunks are capped at the
/// remaining room, so the result never exceeds `max_bytes` and an unterminated
/// message is reported as [`io::ErrorKind::InvalidData`].
fn read_line(
    max_bytes: usize,
    timeout_ms: u32,
    mut read_chunk: impl FnMut(&mut [u8], u32) -> io::Result<usize>,
) -> io::Result<Vec<u8>> {
    validate_message_bound(max_bytes)?;
    let timeout = checked_timeout(timeout_ms)?;
    let started = Instant::now();
    let mut line = Vec::new();
    let mut chunk = [0_u8; READ_CHUNK_BYTES];
    loop {
        let limit = (max_bytes - line.len()).min(READ_CHUNK_BYTES);
        let budget = remaining_budget(timeout, started);
        let read = read_chunk(&mut chunk[..limit], budget)?.min(limit);
        if read == 0 {
            return if line.is_empty() {
                // Clean end of stream: the peer closed without a partial line.
                Ok(line)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "named pipe closed inside a message",
                ))
            };
        }
        let read = &chunk[..read];
        if let Some(end) = read.iter().position(|&byte| byte == b'\n') {
            line.extend_from_slice(&read[..end]);
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(line);
        }
        line.extend_from_slice(read);
        if line.len() >= max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("IPC message exceeds {max_bytes} bytes"),
            ));
        }
    }
}

/// Verifies `pipe_name` names a local pipe.
fn validate_pipe_name(pipe_name: &str) -> io::Result<()> {
    let Some(rest) = pipe_name.strip_prefix(PIPE_NAME_PREFIX) else {
        return Err(invalid_input(format!(
            "pipe name must start with `{PIPE_NAME_PREFIX}`"
        )));
    };
    if rest.is_empty() || pipe_name.encode_utf16().count() > MAX_PIPE_NAME_CHARS {
        return Err(invalid_input(format!(
            "pipe name must have a name of at most {MAX_PIPE_NAME_CHARS} UTF-16 code units"
        )));
    }
    if pipe_name.contains('\0') {
        return Err(invalid_input("pipe name must not contain NUL"));
    }
    // The prefix already names the pipe namespace, so a separator inside `rest`
    // would address a different object than the caller named.
    if rest.contains('\\') || rest.contains('/') {
        return Err(invalid_input(
            "pipe name must not contain a path separator after the prefix",
        ));
    }
    Ok(())
}

/// Returns the body of a reply line without its single optional `\n`.
fn reply_line_body(line: &[u8]) -> io::Result<&[u8]> {
    let body = line.strip_suffix(b"\n").unwrap_or(line);
    if body.iter().any(|&byte| byte == b'\n' || byte == b'\r') {
        return Err(invalid_input("IPC reply must be a single line"));
    }
    if body.len() >= MAX_IPC_MESSAGE_BYTES {
        return Err(invalid_input(format!(
            "IPC reply must be at most {MAX_IPC_MESSAGE_BYTES} bytes, terminator included"
        )));
    }
    Ok(body)
}

/// Verifies a request line: non-empty, bounded (leaving room for `\n`), and
/// free of terminators.
fn validate_request(line: &[u8]) -> io::Result<()> {
    if line.is_empty() || line.len() >= MAX_IPC_MESSAGE_BYTES {
        return Err(invalid_input(format!(
            "IPC request must be 1..={} bytes, excluding terminator",
            MAX_IPC_MESSAGE_BYTES - 1
        )));
    }
    if line.iter().any(|&byte| byte == b'\n' || byte == b'\r') {
        return Err(invalid_input("IPC request must be a single line"));
    }
    Ok(())
}

/// Verifies a caller-supplied message bound.
fn validate_message_bound(max_bytes: usize) -> io::Result<()> {
    if max_bytes == 0 || max_bytes > MAX_IPC_MESSAGE_BYTES {
        return Err(invalid_input(format!(
            "IPC message bound must be 1..={MAX_IPC_MESSAGE_BYTES} bytes"
        )));
    }
    Ok(())
}

/// Converts a caller timeout into a duration, rejecting zero and `INFINITE`.
fn checked_timeout(timeout_ms: u32) -> io::Result<Duration> {
    if timeout_ms == 0 || timeout_ms == INFINITE {
        return Err(invalid_input(
            "pipe timeout must be 1..=4294967294 milliseconds",
        ));
    }
    Ok(Duration::from_millis(u64::from(timeout_ms)))
}

/// Returns the milliseconds left in `timeout`, or zero once it elapsed.
fn remaining_budget(timeout: Duration, started: Instant) -> u32 {
    let left = timeout.saturating_sub(started.elapsed());
    u32::try_from(left.as_millis()).unwrap_or(INFINITE - 1)
}

/// Encodes `value` as UTF-16 with a trailing NUL.
fn nul_terminated(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads the thread's Win32 error code.
fn last_error_code() -> u32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0) as u32
}

/// Builds an `InvalidInput` error.
fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

/// Error returned when an operation needs a connected client.
fn not_connected() -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        "named pipe has no connected client",
    )
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_IPC_MESSAGE_BYTES, MAX_SID_SUBAUTHORITIES, build_pipe_sddl, read_line, reply_line_body,
        validate_pipe_name, validate_windows_sid,
    };
    use std::io;

    #[test]
    fn sid_validation_accepts_canonical_user_and_well_known_sids() {
        for sid in [
            "S-1-5-21-3623811015-3361044348-30300820-1013",
            "S-1-5-18",
            "S-1-5-32-544",
            "S-1-5-21-0-0-0-1000",
            "S-1-0-0",
            "S-1-16-12288",
            "S-1-5-21-4294967295-4294967295-4294967295-4294967295",
        ] {
            assert!(validate_windows_sid(sid).is_ok(), "{sid}");
        }
    }

    #[test]
    fn sid_validation_rejects_sddl_injection() {
        for sid in [
            "S-1-5-21-1)(A;;GA;;;WD",
            "S-1-5-)(A;;GA;;;WD",
            "S-1-5-18;",
            "S-1-5-18)(A;;GA;;;BA)",
            "S-1-5-18 D:(A;;GA;;;WD)",
            "S-1-5-18\n",
            "S-1-5-21-1-2-3-4)(A;;GA;;;WD)",
            "S-1-5-18(Local)",
        ] {
            assert!(validate_windows_sid(sid).is_err(), "{sid}");
        }
    }

    #[test]
    fn sid_validation_rejects_malformed_shapes() {
        for sid in [
            "",
            "S",
            "S-1",
            "S-1-",
            "S-1-5",
            "S-1-5-",
            "S-1-5-18-",
            "s-1-5-18",
            "S-2-5-18",
            "X-1-5-18",
            "S-1-5-18 ",
            " S-1-5-18",
            "S-1-5--18",
            "S-1-5-0x12",
            "S-1-5-1a",
            "S-1-5-00018",
            "S-1-5-4294967296",
        ] {
            assert!(validate_windows_sid(sid).is_err(), "{sid:?}");
        }
    }

    #[test]
    fn sid_validation_bounds_the_length_and_sub_authorities() {
        let overlong = format!("S-1-5-{}", "1".repeat(200));
        assert!(validate_windows_sid(&overlong).is_err());

        let allowed = format!("S-1-5-{}", vec!["1"; MAX_SID_SUBAUTHORITIES].join("-"));
        assert!(validate_windows_sid(&allowed).is_ok());
        let too_many = format!("S-1-5-{}", vec!["1"; MAX_SID_SUBAUTHORITIES + 1].join("-"));
        assert!(validate_windows_sid(&too_many).is_err());
    }

    #[test]
    fn sddl_is_fail_closed_without_a_user_sid() {
        assert_eq!(
            build_pipe_sddl(None).expect("base sddl"),
            "D:(A;;GA;;;SY)(A;;GA;;;BA)"
        );
    }

    #[test]
    fn sddl_grants_the_user_read_write_only() {
        let sddl = build_pipe_sddl(Some("S-1-5-21-1-2-3-1000")).expect("user sddl");
        assert_eq!(
            sddl,
            "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1-2-3-1000)"
        );
        assert!(!sddl.contains(";;;WD)"));
    }

    #[test]
    fn sddl_rejects_an_injected_sid() {
        assert!(build_pipe_sddl(Some("S-1-5-21-1)(A;;GA;;;WD")).is_err());
        assert!(build_pipe_sddl(Some("")).is_err());
    }

    #[test]
    fn pipe_name_validation_requires_the_local_pipe_prefix() {
        assert!(validate_pipe_name(r"\\.\pipe\beam-client-ipc").is_ok());
        assert!(validate_pipe_name(r"\\.\pipe\beam-client-ipc-test-1").is_ok());
        assert!(validate_pipe_name(r"\\.\pipe\").is_err());
        assert!(validate_pipe_name(r"\pipe\beam").is_err());
        assert!(validate_pipe_name("beam-client-ipc").is_err());
        assert!(validate_pipe_name(r"\\server\pipe\beam").is_err());
        assert!(validate_pipe_name("").is_err());
    }

    #[test]
    fn pipe_name_validation_rejects_a_nested_instance_name() {
        assert!(validate_pipe_name(r"\\.\pipe\a\b").is_err());
        assert!(validate_pipe_name(r"\\.\pipe\a/b").is_err());
    }

    #[test]
    fn reply_line_helper_terminates_exactly_one_line() {
        assert_eq!(reply_line_body(b"ok").expect("bare line"), b"ok");
        assert_eq!(reply_line_body(b"ok\n").expect("terminated line"), b"ok");
        assert_eq!(reply_line_body(b"").expect("empty line"), b"");
        assert_eq!(reply_line_body(b"\n").expect("empty message"), b"");
        for line in [&b"a\nb"[..], &b"a\r\nb"[..], &b"a\n\n"[..], &b"a\rb"[..]] {
            assert_eq!(
                reply_line_body(line).expect_err("multi-line").kind(),
                io::ErrorKind::InvalidInput
            );
        }
        let max_body = vec![b'x'; MAX_IPC_MESSAGE_BYTES - 1];
        assert_eq!(
            reply_line_body(&max_body).expect("exact bound").len(),
            MAX_IPC_MESSAGE_BYTES - 1
        );
        let oversized = vec![b'x'; MAX_IPC_MESSAGE_BYTES];
        assert_eq!(
            reply_line_body(&oversized)
                .expect_err("oversized reply")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    /// Runs `read_line` over a fixed script of chunks.
    fn read_script(script: &[&[u8]], max_bytes: usize, timeout_ms: u32) -> io::Result<Vec<u8>> {
        let chunks: Vec<Vec<u8>> = script.iter().map(|chunk| chunk.to_vec()).collect();
        let mut index = 0;
        read_line(max_bytes, timeout_ms, move |buffer, _budget_ms| {
            let Some(chunk) = chunks.get(index) else {
                return Ok(0);
            };
            index += 1;
            let count = chunk.len().min(buffer.len());
            buffer[..count].copy_from_slice(&chunk[..count]);
            Ok(count)
        })
    }

    #[test]
    fn read_line_strips_the_terminator() {
        assert_eq!(
            read_script(&[b"hello\n"], 64, 1_000).expect("line"),
            b"hello"
        );
        assert_eq!(
            read_script(&[b"hello\r\n"], 64, 1_000).expect("crlf line"),
            b"hello"
        );
        assert_eq!(read_script(&[b"\n"], 64, 1_000).expect("empty line"), b"");
        assert_eq!(
            read_script(&[b"{\"cmd\":\"status\"}\n"], 64, 1_000).expect("json line"),
            b"{\"cmd\":\"status\"}"
        );
    }

    #[test]
    fn read_line_joins_split_chunks() {
        assert_eq!(
            read_script(&[b"he", b"llo", b"\n"], 64, 1_000).expect("split line"),
            b"hello"
        );
        // The line fits exactly in `max_bytes`, terminator included.
        assert_eq!(
            read_script(&[b"abc\n"], 4, 1_000).expect("bounded line"),
            b"abc"
        );
    }

    #[test]
    fn read_line_rejects_an_unterminated_oversize_message() {
        let error = read_script(&[b"abcdef"], 4, 1_000).expect_err("oversize message");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        let error =
            read_script(&[b"a", b"b", b"c", b"d", b"e"], 4, 1_000).expect_err("oversize message");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_line_reports_a_closed_pipe() {
        // Nothing sent: end of stream.
        assert!(
            read_script(&[], 64, 1_000)
                .expect("end of stream")
                .is_empty()
        );
        // Closed in the middle of a line.
        let error = read_script(&[b"partial"], 64, 1_000).expect_err("partial line");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn read_line_rejects_invalid_bounds_and_timeouts() {
        assert_eq!(
            read_script(&[b"x\n"], 0, 1_000)
                .expect_err("zero bound")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_script(&[b"x\n"], MAX_IPC_MESSAGE_BYTES + 1, 1_000)
                .expect_err("unbounded")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_script(&[b"x\n"], 64, 0)
                .expect_err("zero timeout")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            read_script(&[b"x\n"], 64, u32::MAX)
                .expect_err("infinite timeout")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
