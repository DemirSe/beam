//! Windows Service Control Manager (SCM) and power-event wrappers.
//!
//! The SCM reaches the process through two C callbacks: the dispatcher entry
//! point (`SERVICE_MAIN_FUNCTION`) and the control handler
//! (`LPHANDLER_FUNCTION_EX`). Neither carries a context pointer the dispatcher
//! can fill in, so both read one process-wide [`Shared`] registration. Only one
//! service can be dispatched per process, and a second [`run_service`] call
//! fails with [`io::ErrorKind::AlreadyExists`].
//!
//! Every callback body catches panics: unwinding across an FFI boundary is
//! undefined behavior, and the SCM would abort the process instead of recording
//! the failure.

use std::ffi::c_void;
use std::io;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use windows_sys::Win32::Foundation::{
    ERROR_CALL_NOT_IMPLEMENTED, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_POWEREVENT,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOP_PENDING, SERVICE_STOPPED,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS, SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
};
use windows_sys::core::PWSTR;

/// Maximum service name length the SCM accepts, in UTF-16 code units.
const MAX_SERVICE_NAME_CHARS: usize = 256;

/// Wait hint reported with the initial `SERVICE_START_PENDING` status.
const START_WAIT_HINT_MS: u32 = 10_000;

/// Service-specific exit code reported when the service body panics.
const EXIT_CODE_PANIC: u32 = 1;

/// Service-specific exit code reported when the service body was not available.
const EXIT_CODE_NO_ENTRY: u32 = 2;

/// A control or power event the SCM delivered to the control handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceEvent {
    /// `SERVICE_CONTROL_STOP`: the service manager asked the service to stop.
    Stop,
    /// `SERVICE_CONTROL_SHUTDOWN`: the machine is shutting down.
    Shutdown,
    /// The machine resumed from sleep.
    PowerResume,
    /// The machine is about to sleep.
    PowerSuspend,
}

/// A service state reported to the SCM.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceState {
    /// The service is starting; reports a non-zero checkpoint.
    StartPending,
    /// The service is running and accepts stop, shutdown and power events.
    Running,
    /// The service is stopping; reports a non-zero checkpoint.
    StopPending,
    /// The service has stopped. The value is the service-specific exit code,
    /// where zero reports success.
    Stopped(u32),
}

impl ServiceState {
    /// Returns true for the states that require an increasing checkpoint value.
    fn is_pending(self) -> bool {
        matches!(self, Self::StartPending | Self::StopPending)
    }

    /// Returns the `SERVICE_STATUS_CURRENT_STATE` value for this state.
    fn current_state(self) -> u32 {
        match self {
            Self::StartPending => SERVICE_START_PENDING,
            Self::Running => SERVICE_RUNNING,
            Self::StopPending => SERVICE_STOP_PENDING,
            Self::Stopped(_) => SERVICE_STOPPED,
        }
    }

    /// Returns the control codes the SCM may deliver while in this state.
    ///
    /// A pending or stopped service accepts no controls; the SCM ignores them.
    fn controls_accepted(self) -> u32 {
        if matches!(self, Self::Running) {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT
        } else {
            0
        }
    }

    /// Returns `(dwWin32ExitCode, dwServiceSpecificExitCode)` for this state.
    fn exit_codes(self) -> (u32, u32) {
        match self {
            Self::Stopped(0) => (NO_ERROR, 0),
            Self::Stopped(code) => (ERROR_SERVICE_SPECIFIC_ERROR, code),
            _ => (NO_ERROR, 0),
        }
    }
}

/// Mutable state behind a [`ServiceStatusHandle`].
struct StatusState {
    /// `SERVICE_STATUS_HANDLE` as an integer so the handle stays [`Send`] and
    /// [`Sync`]; zero means "not registered". Every Win32 call below raises it
    /// back into the original pointer.
    raw: usize,
    /// Checkpoint counter for the pending states.
    checkpoint: AtomicU32,
    /// Last status the SCM accepted, replayed on `SERVICE_CONTROL_INTERROGATE`.
    last: Mutex<Option<SERVICE_STATUS>>,
}

/// Safe owner of a registered `SERVICE_STATUS_HANDLE`.
///
/// The handle came from [`RegisterServiceCtrlHandlerExW`] and stays valid until
/// the service process exits, so cloning the wrapper is cheap and safe.
#[derive(Clone)]
pub struct ServiceStatusHandle {
    state: Arc<StatusState>,
}

impl ServiceStatusHandle {
    /// Wraps a handle returned by `RegisterServiceCtrlHandlerExW`.
    fn new(raw: SERVICE_STATUS_HANDLE) -> Self {
        Self {
            state: Arc::new(StatusState {
                raw: raw as usize,
                checkpoint: AtomicU32::new(0),
                last: Mutex::new(None),
            }),
        }
    }

    /// Reports `state` to the SCM.
    ///
    /// For `StartPending` and `StopPending` the checkpoint counter increments by
    /// one on each call, which is what the SCM requires so it can tell a slow
    /// start from a hung service. `wait_hint_ms` is the caller's estimate of how
    /// long the pending state lasts; it is ignored for other states.
    pub fn set_state(&self, state: ServiceState, wait_hint_ms: u32) -> io::Result<()> {
        let status = self.build_status(state, wait_hint_ms);
        self.report(&status)
    }

    /// Builds a `SERVICE_STATUS` for `state`.
    fn build_status(&self, state: ServiceState, wait_hint_ms: u32) -> SERVICE_STATUS {
        let pending = state.is_pending();
        let (win32_exit_code, service_exit_code) = state.exit_codes();
        SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state.current_state(),
            dwControlsAccepted: state.controls_accepted(),
            dwWin32ExitCode: win32_exit_code,
            dwServiceSpecificExitCode: service_exit_code,
            dwCheckPoint: next_checkpoint(&self.state.checkpoint, pending),
            dwWaitHint: if pending { wait_hint_ms } else { 0 },
        }
    }

    /// Sends a status to the SCM and remembers it for the next interrogate.
    fn report(&self, status: &SERVICE_STATUS) -> io::Result<()> {
        if self.state.raw == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "service status handle is not registered",
            ));
        }
        self.post(status)?;
        *lock(&self.state.last) = Some(*status);
        Ok(())
    }

    /// Sends a status to the SCM without touching the remembered copy.
    fn post(&self, status: &SERVICE_STATUS) -> io::Result<()> {
        // SAFETY: `raw` is either zero (rejected above) or the pointer returned
        // by `RegisterServiceCtrlHandlerExW`, which stays valid until the
        // service process exits. `status` points at a live, fully initialized
        // `SERVICE_STATUS` for the duration of the call, and `SetServiceStatus`
        // copies it without retaining the pointer.
        let ok = unsafe { SetServiceStatus(self.state.raw as SERVICE_STATUS_HANDLE, status) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Replays the most recently accepted status, as `SERVICE_CONTROL_INTERROGATE`
    /// requires.
    fn repost(&self) -> io::Result<()> {
        let last = *lock(&self.state.last);
        match last {
            Some(status) => self.post(&status),
            None => Ok(()),
        }
    }
}

/// Advances or resets a checkpoint counter and returns the value to report.
fn next_checkpoint(counter: &AtomicU32, pending: bool) -> u32 {
    if !pending {
        counter.store(0, Ordering::Release);
        return 0;
    }
    // Saturate instead of wrapping: the SCM wants a growing value, and a reset to
    // zero would look like a fresh report. A lost race retries the loop, so
    // contention can never be reported as a jump to `u32::MAX`.
    loop {
        let current = counter.load(Ordering::Acquire);
        if current == u32::MAX {
            return u32::MAX;
        }
        if counter
            .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return current + 1;
        }
    }
}

/// Delivers a `SERVICE_CONTROL_*` code and power-event code to the callback.
fn translate_control(control: u32, event_type: u32) -> Option<ServiceEvent> {
    match control {
        SERVICE_CONTROL_STOP => Some(ServiceEvent::Stop),
        SERVICE_CONTROL_SHUTDOWN => Some(ServiceEvent::Shutdown),
        SERVICE_CONTROL_POWEREVENT => match event_type {
            PBT_APMRESUMEAUTOMATIC | PBT_APMRESUMESUSPEND => Some(ServiceEvent::PowerResume),
            PBT_APMSUSPEND => Some(ServiceEvent::PowerSuspend),
            _ => None,
        },
        _ => None,
    }
}

/// The service body handed to [`run_service`], taken once by the dispatcher.
type ServiceBody = Box<dyn FnOnce(ServiceStatusHandle) -> u32 + Send>;

/// Process-wide registration read by both SCM callbacks.
struct Shared {
    /// NUL-terminated UTF-16 service name, kept for the handler registration.
    service_name: Vec<u16>,
    /// Caller callback for control and power events.
    on_event: Arc<dyn Fn(ServiceEvent) + Send + Sync>,
    /// The service body, taken exactly once by the dispatcher entry point.
    main: Mutex<Option<ServiceBody>>,
    /// Status handle of the running service, used to answer INTERROGATE.
    status: Mutex<Option<ServiceStatusHandle>>,
}

/// The single service registration this process may have.
static SHARED: Mutex<Option<Arc<Shared>>> = Mutex::new(None);

/// Locks a mutex and recovers the guard if the mutex was poisoned.
///
/// A panic is already caught before it can poison a lock, but recovering here
/// keeps a poisoned lock from aborting a callback that must return a status to
/// the SCM.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Returns the current registration, if [`run_service`] installed one.
fn current_shared() -> Option<Arc<Shared>> {
    lock(&SHARED).clone()
}

/// Runs `service_main` as the body of the Windows service `service_name`.
///
/// `StartServiceCtrlDispatcherW` blocks for the life of the service and calls
/// `service_main` on a dispatcher thread with a [`ServiceStatusHandle`]; the
/// value `service_main` returns becomes the service-specific exit code. The
/// function always reports `SERVICE_STOPPED` after the body returns, including
/// when the body panics, so a crash never leaves the service in a pending
/// state.
///
/// `on_event` receives stop, shutdown and power events. It runs on the SCM
/// callback thread, so it must not block; hand work to the service body through
/// a channel or an event instead.
///
/// Returns the dispatcher failure when the process was not started by the SCM
/// (for example when run from a console), and
/// [`io::ErrorKind::AlreadyExists`] when a service was already dispatched.
pub fn run_service<F>(
    service_name: &str,
    on_event: Arc<dyn Fn(ServiceEvent) + Send + Sync>,
    service_main: F,
) -> io::Result<()>
where
    F: FnOnce(ServiceStatusHandle) -> u32 + Send + 'static,
{
    let service_name = checked_service_name(service_name)?;
    let shared = Arc::new(Shared {
        service_name,
        on_event,
        main: Mutex::new(Some(Box::new(service_main))),
        status: Mutex::new(None),
    });
    {
        let mut slot = lock(&SHARED);
        if slot.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a service dispatcher is already installed in this process",
            ));
        }
        *slot = Some(Arc::clone(&shared));
    }

    // `StartServiceCtrlDispatcherW` takes a mutable name pointer, so the table
    // works on its own copy of the NUL-terminated name.
    let mut table_name = shared.service_name.clone();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: table_name.as_mut_ptr(),
            lpServiceProc: Some(dispatcher_entry),
        },
        // The last entry must have a null name and no callback.
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    // SAFETY: `table` holds two live entries whose last one is all-null as the
    // API requires, and `table_name` keeps the UTF-16 name alive for the whole
    // call. The call blocks until the service stops and never keeps the table
    // or the name afterwards.
    let ok = unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) };
    if ok != 0 {
        return Ok(());
    }

    let error = io::Error::last_os_error();
    // The dispatcher never called the entry point, so release the registration
    // and let the caller retry or report the failure.
    *lock(&SHARED) = None;
    Err(error)
}

/// Verifies the service name and returns it as NUL-terminated UTF-16.
fn checked_service_name(service_name: &str) -> io::Result<Vec<u16>> {
    if service_name.is_empty() || service_name.encode_utf16().count() > MAX_SERVICE_NAME_CHARS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("service name must be 1..={MAX_SERVICE_NAME_CHARS} UTF-16 code units"),
        ));
    }
    if service_name.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "service name must not contain NUL",
        ));
    }
    Ok(nul_terminated(service_name))
}

/// Encodes `value` as UTF-16 with a trailing NUL.
fn nul_terminated(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// `SERVICE_MAIN_FUNCTION` that the SCM calls once per service start.
///
/// # Safety
///
/// Called only by `StartServiceCtrlDispatcherW` from `run_service` in this
/// process; both arguments are ignored.
// SAFETY: the function is declared `unsafe extern "system"` because the C caller
// owns the two arguments; the body ignores them and only touches state that
// `run_service` installed before the call.
unsafe extern "system" fn dispatcher_entry(_argc: u32, _argv: *mut PWSTR) {
    // A panic must never unwind across the SCM frame, so it stops here. The body
    // already catches panics from the caller's code; this is the outer guard for
    // the registration and reporting paths.
    let _ = catch_unwind(AssertUnwindSafe(run_dispatched_main));
}

/// Registers the control handler, runs the service body, and reports stopped.
fn run_dispatched_main() {
    let Some(shared) = current_shared() else {
        return;
    };
    // SAFETY: `shared.service_name` is NUL-terminated UTF-16 and lives in the
    // `Arc` the static keeps alive. The context pointer is the same `Arc`
    // allocation, so it stays valid for the process lifetime, and the handler
    // only reads it through a shared reference.
    let raw = unsafe {
        RegisterServiceCtrlHandlerExW(
            shared.service_name.as_ptr(),
            Some(control_handler),
            Arc::as_ptr(&shared).cast::<c_void>(),
        )
    };
    if raw.is_null() {
        // Without a status handle there is nothing to report; the SCM records
        // the failed start on its own.
        return;
    }

    let status = ServiceStatusHandle::new(raw);
    *lock(&shared.status) = Some(status.clone());
    // A service that does not report progress in time is killed, so announce
    // the pending state before running the caller's body.
    let _ = status.set_state(ServiceState::StartPending, START_WAIT_HINT_MS);

    let body = lock(&shared.main).take();
    let exit_code = match body {
        Some(body) => {
            let status = status.clone();
            // SAFETY of the assert: a panicking service body is contained here,
            // and the handle is only used to report the exit code afterwards.
            match catch_unwind(AssertUnwindSafe(move || body(status))) {
                Ok(exit_code) => exit_code,
                Err(_) => EXIT_CODE_PANIC,
            }
        }
        None => EXIT_CODE_NO_ENTRY,
    };

    // The SCM expects a final stopped status even when the body panicked. There
    // is no recovery path if this call fails, so the error is dropped.
    let _ = status.set_state(ServiceState::Stopped(exit_code), 0);
}

/// `LPHANDLER_FUNCTION_EX` that translates SCM controls into [`ServiceEvent`]s.
///
/// # Safety
///
/// `context` is the pointer passed to `RegisterServiceCtrlHandlerExW` in
/// `run_dispatched_main`: a live `Arc<Shared>` allocation owned by the static
/// `SHARED`. `event_data` is never dereferenced because the only control we
/// inspect that carries data reads it from `event_type`.
// SAFETY: the function is declared `unsafe extern "system"` because the C caller
// owns the four arguments; the body only uses `context`, whose contract is
// stated above, and never dereferences `event_data`.
unsafe extern "system" fn control_handler(
    control: u32,
    event_type: u32,
    _event_data: *mut c_void,
    context: *mut c_void,
) -> u32 {
    if context.is_null() {
        return ERROR_CALL_NOT_IMPLEMENTED;
    }
    // SAFETY: see the function contract. `Shared` is immutable behind the
    // pointer, and its mutable fields sit behind mutexes.
    let shared = unsafe { &*context.cast::<Shared>() };

    if let Some(event) = translate_control(control, event_type) {
        // A panic in the caller's callback must not unwind into the SCM.
        let _ = catch_unwind(AssertUnwindSafe(|| (shared.on_event)(event)));
        return NO_ERROR;
    }
    if control == SERVICE_CONTROL_INTERROGATE {
        if let Some(status) = lock(&shared.status).clone() {
            // Ignoring the error keeps the handler total; the SCM retries the
            // interrogate if it still needs the state.
            let _ = status.repost();
        }
        return NO_ERROR;
    }
    ERROR_CALL_NOT_IMPLEMENTED
}

#[cfg(test)]
mod tests {
    use super::{EXIT_CODE_PANIC, ServiceEvent, ServiceState, next_checkpoint, translate_control};
    use std::sync::atomic::AtomicU32;
    use windows_sys::Win32::Foundation::ERROR_SERVICE_SPECIFIC_ERROR;
    use windows_sys::Win32::System::Services::{
        SERVICE_ACCEPT_POWEREVENT, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
        SERVICE_CONTROL_CONTINUE, SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_POWEREVENT,
        SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
        SERVICE_STOP_PENDING, SERVICE_STOPPED,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMECRITICAL, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    };

    #[test]
    fn running_state_accepts_stop_shutdown_and_power_events() {
        assert_eq!(
            ServiceState::Running.controls_accepted(),
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_POWEREVENT
        );
        assert_eq!(ServiceState::Running.current_state(), SERVICE_RUNNING);
        assert!(!ServiceState::Running.is_pending());
    }

    #[test]
    fn pending_and_stopped_states_accept_no_controls() {
        for state in [
            ServiceState::StartPending,
            ServiceState::StopPending,
            ServiceState::Stopped(0),
            ServiceState::Stopped(7),
        ] {
            assert_eq!(state.controls_accepted(), 0, "{state:?}");
        }
        assert_eq!(
            ServiceState::StartPending.current_state(),
            SERVICE_START_PENDING
        );
        assert_eq!(
            ServiceState::StopPending.current_state(),
            SERVICE_STOP_PENDING
        );
        assert_eq!(ServiceState::Stopped(0).current_state(), SERVICE_STOPPED);
        assert!(ServiceState::StartPending.is_pending());
        assert!(ServiceState::StopPending.is_pending());
        assert!(!ServiceState::Stopped(0).is_pending());
    }

    #[test]
    fn stopped_state_uses_service_specific_exit_codes() {
        assert_eq!(ServiceState::Stopped(0).exit_codes(), (0, 0));
        assert_eq!(
            ServiceState::Stopped(7).exit_codes(),
            (ERROR_SERVICE_SPECIFIC_ERROR, 7)
        );
        assert_eq!(
            ServiceState::Stopped(EXIT_CODE_PANIC).exit_codes(),
            (ERROR_SERVICE_SPECIFIC_ERROR, 1)
        );
        assert_eq!(ServiceState::Running.exit_codes(), (0, 0));
        assert_eq!(ServiceState::StartPending.exit_codes(), (0, 0));
    }

    #[test]
    fn pending_reports_count_checkpoints_and_other_states_reset_them() {
        let counter = AtomicU32::new(0);
        assert_eq!(next_checkpoint(&counter, true), 1);
        assert_eq!(next_checkpoint(&counter, true), 2);
        assert_eq!(next_checkpoint(&counter, false), 0);
        // A pending state after a completed one starts counting from one again.
        assert_eq!(next_checkpoint(&counter, true), 1);
    }

    #[test]
    fn checkpoint_saturates_instead_of_wrapping() {
        let counter = AtomicU32::new(u32::MAX - 1);
        assert_eq!(next_checkpoint(&counter, true), u32::MAX);
        assert_eq!(next_checkpoint(&counter, true), u32::MAX);
    }

    #[test]
    fn stop_and_shutdown_controls_map_to_events() {
        assert_eq!(
            translate_control(SERVICE_CONTROL_STOP, 0),
            Some(ServiceEvent::Stop)
        );
        assert_eq!(
            translate_control(SERVICE_CONTROL_SHUTDOWN, 0),
            Some(ServiceEvent::Shutdown)
        );
    }

    #[test]
    fn power_controls_map_to_resume_and_suspend() {
        assert_eq!(
            translate_control(SERVICE_CONTROL_POWEREVENT, PBT_APMSUSPEND),
            Some(ServiceEvent::PowerSuspend)
        );
        assert_eq!(
            translate_control(SERVICE_CONTROL_POWEREVENT, PBT_APMRESUMEAUTOMATIC),
            Some(ServiceEvent::PowerResume)
        );
        assert_eq!(
            translate_control(SERVICE_CONTROL_POWEREVENT, PBT_APMRESUMESUSPEND),
            Some(ServiceEvent::PowerResume)
        );
        assert_eq!(
            translate_control(SERVICE_CONTROL_POWEREVENT, PBT_APMRESUMECRITICAL),
            None
        );
    }

    #[test]
    fn unrelated_controls_are_not_translated() {
        assert_eq!(translate_control(SERVICE_CONTROL_INTERROGATE, 0), None);
        assert_eq!(translate_control(SERVICE_CONTROL_CONTINUE, 0), None);
        assert_eq!(translate_control(0, 0), None);
    }
}
