//! JNI bridge and mobile engine glue for the beam Android client.
//!
//! `beam-sys` owns every file descriptor and every syscall `unsafe` block. This
//! crate only declares the narrow JNI entrypoints in [`jni_bridge`] and
//! assembles the `beam-tun` engine for a detached `VpnService` descriptor.

// `#[unsafe(no_mangle)]` in `jni_bridge` is the only exception; the module
// carries the matching `allow`.
#![deny(unsafe_code)]

pub mod config;
pub mod engine;
#[allow(unsafe_code)]
pub mod jni_bridge;
pub mod tun;

/// `vless://` REALITY fixture for host tests. Not a working server.
#[cfg(test)]
pub(crate) const TEST_VLESS_URI: &str = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@\
203.0.113.10:443?encryption=none&security=reality&sni=whatsapp.net&fp=chrome&\
pbk=WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo&sid=0123456789abcdef&type=tcp&\
flow=xtls-rprx-vision#beam";

/// Installs the logcat subscriber on Android. A no-op on host builds.
///
/// Retries on a later call if `/dev/socket/logdw` was temporarily unavailable
/// on the first start.
pub fn init_logging(_level: &str) {
    #[cfg(target_os = "android")]
    {
        use std::str::FromStr;
        use std::sync::atomic::{AtomicBool, Ordering};

        use tracing_logcat::{LogcatMakeWriter, LogcatTag};
        use tracing_subscriber::fmt::format::Format;
        use tracing_subscriber::layer::SubscriberExt;

        static INITIALIZED: AtomicBool = AtomicBool::new(false);
        if INITIALIZED.load(Ordering::Acquire) {
            return;
        }
        let level = tracing::level_filters::LevelFilter::from_str(_level)
            .unwrap_or(tracing::level_filters::LevelFilter::INFO);
        let Ok(writer) = LogcatMakeWriter::new(LogcatTag::Fixed("beam".to_owned())) else {
            return;
        };
        let fmt_layer = tracing_subscriber::fmt::layer()
            .event_format(Format::default().with_level(false).without_time())
            .with_writer(writer)
            .with_ansi(false);
        let subscriber = tracing_subscriber::registry().with(fmt_layer).with(level);
        if tracing::subscriber::set_global_default(subscriber).is_ok() {
            INITIALIZED.store(true, Ordering::Release);
        }
    }
}
