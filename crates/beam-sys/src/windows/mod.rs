//! Windows platform primitives for beam.
//!
//! Every `unsafe` block in this module's submodules carries a `// SAFETY:`
//! comment that states the invariant the call relies on. Networking
//! primitives live in [`socket`] so the Linux and Windows socket helpers stay
//! separate.

pub mod iphelper;
pub mod pipe;
pub mod service;
pub mod socket;
pub mod wfp;
pub mod wintun;

pub use socket::{
    bind_socket_to_interface_v4, bind_socket_to_interface_v6, set_tcp_keepalive, set_tcp_keepcnt,
    set_tcp_maxseg, set_tcp_nodelay, set_tcp_user_timeout,
};

use std::io;
use std::path::Path;
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1, SE_FILE_OBJECT,
    SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR,
};
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

/// Restricts a file or directory's DACL to `SYSTEM` and `Administrators`
/// (`D:P(A;;FA;;;SY)(A;;FA;;;BA)`), stripping all inherited permissions.
///
/// Used before renaming a newly written `client.toml` into place so secret
/// material is never readable by non-administrator local accounts.
pub fn set_file_admin_only_acl(path: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    let sddl: Vec<u16> = "D:P(A;;FA;;;SY)(A;;FA;;;BA)\0".encode_utf16().collect();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `sddl` is a valid NUL-terminated UTF-16 string and `sd` is a live
    // out-pointer. On success Windows allocates `sd` via `LocalAlloc`, which is
    // freed unconditionally via `LocalFree` before this function returns.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 || sd.is_null() {
        return Err(io::Error::last_os_error());
    }

    struct LocalSd(PSECURITY_DESCRIPTOR);
    impl Drop for LocalSd {
        fn drop(&mut self) {
            // SAFETY: `self.0` was allocated by
            // `ConvertStringSecurityDescriptorToSecurityDescriptorW` and is
            // freed exactly once here.
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _guard = LocalSd(sd);

    let mut dacl_present = 0_i32;
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut dacl_defaulted = 0_i32;
    // SAFETY: `sd` is a valid self-relative security descriptor alive for the
    // duration of `_guard`; `dacl` receives an interior pointer into `sd`.
    let got_dacl = unsafe {
        GetSecurityDescriptorDacl(
            sd,
            &raw mut dacl_present,
            &raw mut dacl,
            &raw mut dacl_defaulted,
        )
    };
    if got_dacl == 0 || dacl_present == 0 || dacl.is_null() {
        return Err(io::Error::last_os_error());
    }

    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide_path.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains interior NUL",
        ));
    }
    wide_path.push(0);

    // SAFETY: `wide_path` is a live NUL-terminated mutable UTF-16 buffer and
    // `dacl` is a valid ACL inside `sd` (alive until `_guard` drops).
    let status = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_mut_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            dacl,
            ptr::null_mut(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    Ok(())
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
