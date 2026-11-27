//! Windows platform primitives for beam.
//!
//! Every `unsafe` block in this module's submodules carries a `// SAFETY:`
//! comment that states the invariant the call relies on. Networking
//! primitives live in [`socket`] so the Linux and Windows socket helpers stay
//! separate.

pub mod socket;

pub use socket::{
    bind_socket_to_interface_v4, bind_socket_to_interface_v6, set_tcp_keepalive, set_tcp_keepcnt,
    set_tcp_maxseg, set_tcp_nodelay, set_tcp_user_timeout,
};

use std::io;
use std::time::Duration;
use windows_sys::Win32::System::SystemInformation::GetTickCount64;
use windows_sys::Win32::System::WindowsProgramming::QueryUnbiasedInterruptTime;

/// Longest interface name accepted by [`validate_ifname`] (`IF_MAX_STRING_SIZE`,
/// matching `MIB_IF_ROW2::Alias = [u16; 257]` excluding the NUL terminator).
pub const MAX_IFNAME_LEN: usize = 256;

/// Validates a Windows interface name.
///
/// Windows adapter aliases are free-form display names, so the rules stay
/// narrow: a name must not contain path separators, NUL, or other control
/// characters, and it must not carry leading or trailing whitespace. The bound
/// matches the longest alias value the IP Helper API returns in
/// `MIB_IF_ROW2::Alias`.
pub fn validate_ifname(name: &str) -> io::Result<()> {
    if name.is_empty() || name.encode_utf16().count() > MAX_IFNAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name must be 1..={MAX_IFNAME_LEN} UTF-16 code units"),
        ));
    }
    if name.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must not contain NUL or control characters",
        ));
    }
    if name.contains(['/', '\\']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must not contain a path separator",
        ));
    }
    if name.trim() != name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name must not start or end with whitespace",
        ));
    }
    Ok(())
}

/// Returns the total time the system has spent suspended.
///
/// `GetTickCount64` counts every millisecond since boot, including time spent
/// in sleep. `QueryUnbiasedInterruptTime` counts the same period without
/// suspend time, so the difference between the two clocks is the accumulated
/// suspend time.
pub fn boottime_offset() -> io::Result<Duration> {
    let mut unbiased_100ns = 0_u64;
    // SAFETY: `QueryUnbiasedInterruptTime` writes exactly one `u64` to the
    // pointer it is given, so the pointer must be valid and aligned for a
    // `u64`. `unbiased_100ns` is a live local of that type, and kernel32 keeps
    // no pointer after the call.
    let ok = unsafe { QueryUnbiasedInterruptTime(&raw mut unbiased_100ns) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `GetTickCount64` takes no arguments, dereferences no user
    // pointer, cannot fail, and has no side effects beyond reading the tick
    // counter.
    let tick_ms = unsafe { GetTickCount64() };
    Ok(compute_boottime_offset(tick_ms, unbiased_100ns))
}

/// Converts a millisecond tick count and an unbiased interrupt time in 100 ns
/// units into the time the system has spent suspended.
///
/// A tick count that lags the interrupt clock yields zero instead of a
/// negative duration, which keeps a same-moment sampling race from reporting
/// time travel.
#[must_use]
pub fn compute_boottime_offset(tick_ms: u64, unbiased_100ns: u64) -> Duration {
    let uptime_ms = unbiased_100ns / 10_000;
    Duration::from_millis(tick_ms.saturating_sub(uptime_ms))
}

#[cfg(test)]
mod tests {
    use super::{MAX_IFNAME_LEN, boottime_offset, compute_boottime_offset, validate_ifname};
    use std::time::Duration;

    #[test]
    fn boottime_offset_is_the_difference_between_the_two_clocks() {
        // Same clocks: no suspend has happened yet.
        assert_eq!(compute_boottime_offset(1_000, 10_000_000), Duration::ZERO);
        // Five seconds of suspend on top of sixty seconds of uptime.
        assert_eq!(
            compute_boottime_offset(65_000, 600_000_000),
            Duration::from_secs(5)
        );
    }

    #[test]
    fn boottime_offset_saturates_when_the_tick_count_lags() {
        assert_eq!(compute_boottime_offset(0, 600_000_000), Duration::ZERO);
        assert_eq!(compute_boottime_offset(9_999, 100_000), Duration::ZERO);
    }

    #[test]
    fn boottime_offset_is_stable_across_back_to_back_calls() {
        let first = boottime_offset().expect("query clocks");
        let second = boottime_offset().expect("query clocks");
        assert!(
            first.abs_diff(second) < Duration::from_secs(1),
            "back-to-back boottime_offset calls diverged by {:?}",
            first.abs_diff(second)
        );
    }

    #[test]
    fn validate_ifname_accepts_aliases_and_rejects_malformed_names() {
        assert!(validate_ifname("Ethernet").is_ok());
        assert!(validate_ifname("Beam TUN 0").is_ok());
        assert!(validate_ifname("以太网 1").is_ok());

        assert!(validate_ifname("").is_err());
        assert!(validate_ifname(&"a".repeat(MAX_IFNAME_LEN + 1)).is_err());
        assert!(validate_ifname("tun/0").is_err());
        assert!(validate_ifname("tun\\0").is_err());
        assert!(validate_ifname("tun\0").is_err());
        assert!(validate_ifname("tun\t0").is_err());
        assert!(validate_ifname(" Ethernet").is_err());
        assert!(validate_ifname("Ethernet ").is_err());
        assert!(validate_ifname("\u{00A0}Ethernet").is_err());
        // 128 supplementary-plane chars = 256 UTF-16 code units (exact bound);
        // 129 = 258 UTF-16 code units (> 256, rejected).
        assert!(validate_ifname(&"\u{1F600}".repeat(128)).is_ok());
        assert!(validate_ifname(&"\u{1F600}".repeat(129)).is_err());
    }

    #[test]
    fn validate_ifname_accepts_the_length_bound() {
        assert!(validate_ifname(&"a".repeat(MAX_IFNAME_LEN)).is_ok());
    }
}
