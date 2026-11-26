//! The five JNI entrypoints of `com.beam.android.vpn.BeamNativeBridge`.
//!
//! Every exported function is a thin, panic-guarded wrapper: it converts JNI
//! arguments, calls safe crate code, and maps failures to a Java
//! `IllegalStateException` with a message that never contains a link, UUID, or
//! key. No raw pointer arithmetic and no other `unsafe` lives here.

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use beam_core::client::SocketProtector;
use beam_sys::LinuxTun;
use jni::JNIEnv;
use jni::JavaVM;
use jni::objects::{GlobalRef, JObject, JString, JValue};
use jni::sys::{jint, jlong, jstring};

use crate::config::{AndroidEngineConfig, parse_vless_link_json};
use crate::engine::{AndroidEngine, AndroidEngineStart, STATE_DISCONNECTED, StateCallback};

/// Started engines by handle. `BTreeMap::new` is `const`, so the registry needs
/// no lazy initialisation and no allocation until the first start.
static ENGINES: Mutex<BTreeMap<i64, Arc<AndroidEngine>>> = Mutex::new(BTreeMap::new());
/// Next positive handle. `0` is reserved for "start failed".
static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);

/// Label of the descriptor that `VpnService.Builder` already attached. The
/// kernel name is fixed before `detachFd()`, so it cannot be set here.
const DETACHED_TUN_NAME: &str = "tun0";

/// Telemetry that a stale or unknown handle reports: disconnected, all zero.
/// Byte counts and RTT stay `null` because nothing was measured.
const IDLE_TELEMETRY_JSON: &str = "{\"active_tcp_flows\":0,\"active_udp_sessions\":0,\
\"bytes_tx\":null,\"bytes_rx\":null,\"last_rtt_ms\":null,\"dial_failures\":0,\"drops\":0,\"state\":0}";

fn registry() -> std::sync::MutexGuard<'static, BTreeMap<i64, Arc<AndroidEngine>>> {
    ENGINES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Registers a started engine and returns its positive handle, or `0` when the
/// handle space is exhausted (the engine is dropped, which closes its TUN fd).
pub(crate) fn register(engine: AndroidEngine) -> i64 {
    let handle = NEXT_HANDLE.fetch_add(1, Ordering::Relaxed);
    if handle <= 0 {
        drop(engine);
        return 0;
    }
    registry().insert(handle, Arc::new(engine));
    handle
}

/// Removes an engine handle so its caller can stop it outside the lock.
pub(crate) fn take(handle: i64) -> Option<Arc<AndroidEngine>> {
    registry().remove(&handle)
}

/// Clones the engine for a handle, so no Java callback runs under the lock.
fn find(handle: i64) -> Option<Arc<AndroidEngine>> {
    registry().get(&handle).map(Arc::clone)
}

/// Cached JNI references of the `VpnService` and the optional state listener.
struct JavaBridge {
    vm: JavaVM,
    vpn_service: GlobalRef,
    listener: Option<GlobalRef>,
}

impl JavaBridge {
    fn new(
        env: &mut JNIEnv,
        vpn_service: &JObject,
        listener: &JObject,
    ) -> Result<Self, &'static str> {
        if vpn_service.as_raw().is_null() {
            return Err("vpnService must not be null");
        }
        let vm = env.get_java_vm().map_err(|_| "JavaVM unavailable")?;
        let vpn_service = env
            .new_global_ref(vpn_service)
            .map_err(|_| "vpnService reference rejected")?;
        let listener = if listener.as_raw().is_null() {
            None
        } else {
            Some(
                env.new_global_ref(listener)
                    .map_err(|_| "state listener reference rejected")?,
            )
        };
        Ok(Self {
            vm,
            vpn_service,
            listener,
        })
    }

    /// `VpnService.protect(fd)`, called from Tokio worker threads.
    ///
    /// The attach is scoped: it happens once per upstream socket dial, not per
    /// packet, and `AttachGuard` detaches again when the call ends, so repeated
    /// connect/disconnect cycles leak no JNI thread peers.
    fn protect(&self, fd: jint) -> io::Result<()> {
        let mut env = self.vm.attach_current_thread().map_err(jni_to_io)?;
        // shortcut: the method is looked up by name on every fresh socket;
        // caching the id would need `call_method_unchecked`, and this crate
        // keeps every `unsafe` block out of the bridge.
        let protected = env
            .call_method(
                self.vpn_service.as_obj(),
                "protect",
                "(I)Z",
                &[JValue::Int(fd)],
            )
            .ok()
            .and_then(|value| value.z().ok())
            .unwrap_or(false);
        if protected {
            Ok(())
        } else {
            let _ = env.exception_clear();
            Err(io::Error::other(
                "VpnService.protect rejected the upstream socket",
            ))
        }
    }

    fn notify_state(&self, state: u8, detail: &str) {
        let Some(listener) = self.listener.as_ref() else {
            return;
        };
        let Ok(mut env) = self.vm.attach_current_thread() else {
            return;
        };
        let Ok(text) = env.new_string(detail) else {
            return;
        };
        let args = [JValue::Int(jint::from(state)), JValue::Object(&text)];
        if env
            .call_method(
                listener.as_obj(),
                "onNativeStateChanged",
                "(ILjava/lang/String;)V",
                &args,
            )
            .is_err()
        {
            let _ = env.exception_clear();
        }
    }

    fn socket_protector(bridge: &Arc<Self>) -> SocketProtector {
        let bridge = Arc::clone(bridge);
        Arc::new(move |fd| bridge.protect(fd))
    }

    fn state_callback(bridge: &Arc<Self>) -> StateCallback {
        let bridge = Arc::clone(bridge);
        Arc::new(move |state, detail| bridge.notify_state(state, detail))
    }
}

fn jni_to_io(error: jni::errors::Error) -> io::Error {
    io::Error::other(format!("JNI call failed: {error}"))
}

fn throw_illegal_state(env: &mut JNIEnv, message: &str) {
    if env
        .throw_new("java/lang/IllegalStateException", message)
        .is_err()
    {
        let _ = env.exception_clear();
    }
}

fn start_engine(
    env: &mut JNIEnv,
    tun_fd: jint,
    config_json: &JString,
    vpn_service: &JObject,
    listener: &JObject,
) -> Result<jlong, String> {
    // Claim the descriptor before any other work: `LinuxTun` owns it from here,
    // so every `?` below closes the fd that `detachFd()` handed over.
    let tun = LinuxTun::from_detached_fd(tun_fd, DETACHED_TUN_NAME)
        .map_err(|error| format!("TUN descriptor rejected: {error}"))?;
    let raw: String = env
        .get_string(config_json)
        .map_err(|_| "config JSON is not readable".to_owned())?
        .into();
    let config: AndroidEngineConfig = serde_json::from_str(&raw).map_err(|error| {
        tracing::warn!(
            kind = ?error.classify(),
            line = error.line(),
            column = error.column(),
            "android config JSON rejected"
        );
        "config JSON rejected".to_owned()
    })?;
    crate::init_logging(&config.log_level);

    let bridge = Arc::new(JavaBridge::new(env, vpn_service, listener)?);
    let engine = AndroidEngine::start(AndroidEngineStart {
        tun,
        config,
        socket_protector: Some(JavaBridge::socket_protector(&bridge)),
        on_state: Some(JavaBridge::state_callback(&bridge)),
    })
    .map_err(|error| format!("engine start failed: {error}"))?;

    let handle = register(engine);
    if handle <= 0 {
        return Err("engine handle space exhausted".to_owned());
    }
    tracing::info!(handle, "android engine started");
    Ok(handle)
}

/// Starts the engine for a detached `VpnService` TUN descriptor.
///
/// Returns a positive handle, or `0` after throwing
/// `java/lang/IllegalStateException`.
///
/// # Safety
///
/// The JVM calls this with a valid `JNIEnv` for the current thread and with
/// arguments that match `BeamNativeBridge.nativeStart`. `tunFd` came from
/// `ParcelFileDescriptor.detachFd()`, so this function becomes its only owner
/// and closes it on every error path.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_beam_android_vpn_BeamNativeBridge_nativeStart<'local>(
    mut env: JNIEnv<'local>,
    _class: JObject<'local>,
    tun_fd: jint,
    config_json: JString<'local>,
    vpn_service: JObject<'local>,
    listener: JObject<'local>,
) -> jlong {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        match start_engine(&mut env, tun_fd, &config_json, &vpn_service, &listener) {
            Ok(handle) => handle,
            Err(message) => {
                throw_illegal_state(&mut env, &message);
                0
            }
        }
    }));
    match outcome {
        Ok(handle) => handle,
        Err(_) => {
            throw_illegal_state(&mut env, "beam engine panicked during start");
            0
        }
    }
}

/// Stops and forgets the engine behind `handle`.
///
/// # Safety
///
/// The JVM calls this with a valid `JNIEnv`. `handle` need not be known.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_beam_android_vpn_BeamNativeBridge_nativeStop<'local>(
    mut env: JNIEnv<'local>,
    _class: JObject<'local>,
    handle: jlong,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Some(engine) = take(handle) {
            engine.stop();
        }
    }));
    if outcome.is_err() {
        throw_illegal_state(&mut env, "beam engine panicked during stop");
    }
}

/// Signals a network switch, so the engine resets flows and DNS state.
///
/// # Safety
///
/// The JVM calls this with a valid `JNIEnv`. `handle` need not be known.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_beam_android_vpn_BeamNativeBridge_nativeNotifyNetworkChange<
    'local,
>(
    mut env: JNIEnv<'local>,
    _class: JObject<'local>,
    handle: jlong,
) {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if let Some(engine) = find(handle) {
            engine.notify_network_change();
        }
    }));
    if outcome.is_err() {
        throw_illegal_state(&mut env, "beam engine panicked on network change");
    }
}

/// Returns the current engine state code without serializing telemetry JSON.
///
/// An unknown handle returns `STATE_DISCONNECTED` (`0`).
///
/// # Safety
///
/// The JVM calls this with a valid `JNIEnv`. `handle` need not be known.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_beam_android_vpn_BeamNativeBridge_nativeRefreshState<'local>(
    _env: JNIEnv<'local>,
    _class: JObject<'local>,
    handle: jlong,
) -> jint {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match find(handle) {
        Some(engine) => jint::from(engine.refresh_state()),
        None => jint::from(STATE_DISCONNECTED),
    }));
    outcome.unwrap_or_else(|_| jint::from(STATE_DISCONNECTED))
}

/// Returns one telemetry snapshot as JSON; an unknown handle reports idle.
///
/// # Safety
///
/// The JVM calls this with a valid `JNIEnv`. The returned string is a new local
/// reference and can be `null` when string allocation fails.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_beam_android_vpn_BeamNativeBridge_nativePollTelemetry<'local>(
    env: JNIEnv<'local>,
    _class: JObject<'local>,
    handle: jlong,
) -> jstring {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let json = match find(handle) {
            Some(engine) => engine.telemetry_json(),
            None => IDLE_TELEMETRY_JSON.to_owned(),
        };
        match env.new_string(json) {
            Ok(text) => text.into_raw(),
            Err(_) => {
                let _ = env.exception_clear();
                std::ptr::null_mut()
            }
        }
    }));
    match outcome {
        Ok(value) => value,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Parses a `vless://` link and returns `{ok, name, server, port, sni}` or
/// `{ok, error}`. No secret field of the link is echoed.
///
/// # Safety
///
/// The JVM calls this with a valid `JNIEnv`. The returned string is a new local
/// reference and can be `null` when string allocation fails.
#[unsafe(no_mangle)]
pub extern "system" fn Java_com_beam_android_vpn_BeamNativeBridge_nativeParseVlessLink<'local>(
    mut env: JNIEnv<'local>,
    _class: JObject<'local>,
    uri: JString<'local>,
) -> jstring {
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let json = match env.get_string(&uri) {
            Ok(text) => {
                let uri: String = text.into();
                parse_vless_link_json(&uri)
            }
            Err(_) => {
                let _ = env.exception_clear();
                serde_json::json!({"ok": false, "error": "link is not readable"}).to_string()
            }
        };
        match env.new_string(json) {
            Ok(text) => text.into_raw(),
            Err(_) => {
                let _ = env.exception_clear();
                std::ptr::null_mut()
            }
        }
    }));
    match outcome {
        Ok(value) => value,
        Err(_) => std::ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TEST_VLESS_URI;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    fn test_engine() -> (AndroidEngine, UnixStream) {
        let (local, peer) = UnixStream::pair().expect("socketpair");
        let tun = LinuxTun::from_detached_fd(local.into_raw_fd(), DETACHED_TUN_NAME)
            .expect("detached descriptor");
        let engine = AndroidEngine::start(AndroidEngineStart {
            tun,
            config: AndroidEngineConfig {
                vless_uri: TEST_VLESS_URI.to_owned(),
                ..AndroidEngineConfig::default()
            },
            socket_protector: None,
            on_state: None,
        })
        .expect("engine start");
        (engine, peer)
    }

    #[test]
    fn handles_are_positive_and_unique() {
        let (first, _first_peer) = test_engine();
        let (second, _second_peer) = test_engine();
        let first_handle = register(first);
        let second_handle = register(second);
        assert!(first_handle > 0 && second_handle > 0);
        assert_ne!(first_handle, second_handle);

        for handle in [first_handle, second_handle] {
            let engine = take(handle).expect("registered handle");
            engine.stop();
        }
        assert!(take(first_handle).is_none());
        assert!(take(second_handle).is_none());
    }

    #[test]
    fn unknown_handles_are_ignored() {
        assert!(find(0).is_none());
        assert!(take(i64::MAX).is_none());
    }

    #[test]
    fn telemetry_falls_back_to_idle_for_unknown_handles() {
        let value: serde_json::Value =
            serde_json::from_str(IDLE_TELEMETRY_JSON).expect("idle telemetry JSON");
        assert_eq!(value["state"], 0);
        assert_eq!(value["active_tcp_flows"], 0);
        assert_eq!(value["drops"], 0);
        assert!(value["bytes_tx"].is_null() && value["last_rtt_ms"].is_null());
    }
}
