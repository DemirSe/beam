use std::fs::OpenOptions;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[test]
fn check_reports_stdout_failure_without_panicking() {
    let stdout = OpenOptions::new().write(true).open("/dev/full").unwrap();
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_beam"))
        .arg("--check")
        .arg("--config")
        .arg(config)
        .stdout(stdout)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("could not write configuration check result")
    );
}

/// The published sample identity must stay visible in `--check` output even
/// under a restrictive `RUST_LOG`, and the warning must name fields without
/// printing the secret values.
#[test]
fn check_warns_about_the_sample_identity_without_printing_it() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    for level in ["error", "off"] {
        let output = Command::new(env!("CARGO_BIN_EXE_beam"))
            .args(["--check", "--config"])
            .arg(&config)
            .env("RUST_LOG", level)
            .output()
            .unwrap();

        assert!(output.status.success(), "{level}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stderr.contains("sample identity"), "{level}: {stderr}");
        for field in ["user.id", "reality.private_key", "reality.short_ids[0]"] {
            assert!(
                stderr.contains(field),
                "{level}: {field} missing from {stderr}"
            );
        }
        assert!(
            stdout.contains("configuration is valid"),
            "{level}: {stdout}"
        );
        // The README documents the warning as stderr-only.
        assert!(
            !stdout.contains("sample identity"),
            "{level}: warning on stdout: {stdout}"
        );
        for secret in [
            "00000000-0000-0000-0000-000000000000",
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
            "0123456789abcdef",
        ] {
            assert!(
                !stderr.contains(secret),
                "{level}: secret value in stderr: {stderr}"
            );
            assert!(
                !stdout.contains(secret),
                "{level}: secret value in stdout: {stdout}"
            );
        }
    }
}

/// A failed stderr write must not turn a valid sample check into a failure.
#[test]
fn check_tolerates_a_full_stderr() {
    let stderr = OpenOptions::new().write(true).open("/dev/full").unwrap();
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&config)
        .env("RUST_LOG", "off")
        .stderr(stderr)
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("configuration is valid"),
        "{output:?}"
    );
}

/// A loose config mode must be reported with its real scope: mode bits only.
///
/// The check reads the mode only. It never inspects the owner or group, so a
/// clean 0640 mode stays quiet without any ownership check, and a loose mode is
/// reported on the configured sink (stdout) rather than the stderr channel
/// used by the sample-identity warning.
#[test]
fn check_scopes_the_permission_warning_to_mode_bits() {
    use std::os::unix::fs::PermissionsExt;

    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let config = std::fs::read_to_string(example).unwrap();
    for (mode, reason) in [
        (0o644, Some("accessible to other users")),
        (0o620, Some("group-writable")),
        (0o640, None),
    ] {
        let path = std::env::temp_dir().join(format!("beam-mode-{mode:o}-{}", std::process::id()));
        std::fs::write(&path, &config).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();

        let output = Command::new(env!("CARGO_BIN_EXE_beam"))
            .args(["--check", "--config"])
            .arg(&path)
            .env("RUST_LOG", "warn")
            .output()
            .unwrap();
        std::fs::remove_file(&path).unwrap();

        assert!(output.status.success(), "{mode:03o}: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The permission warning reaches the configured logging sink, which is
        // stdout; stderr carries only the scoped sample-identity warning.
        let on_stdout = stdout.contains("config file");
        assert_eq!(on_stdout, reason.is_some(), "{mode:03o}: {stdout}");
        if let Some(reason) = reason {
            assert!(stdout.contains(reason), "{mode:03o}: {stdout}");
            // The rendered field must hold the low permission octal only, not
            // the file-type bits that metadata mode also carries.
            assert!(
                stdout.contains(&format!("mode=\"{mode:03o}\"")),
                "{mode:03o}: {stdout}"
            );
            assert!(
                stdout.contains("only mode bits are checked"),
                "{mode:03o}: {stdout}"
            );
            assert!(
                stdout.contains("verify the owner and group separately"),
                "{mode:03o}: {stdout}"
            );
        }
        assert!(!stderr.contains("config file"), "{mode:03o}: {stderr}");
        assert!(
            stdout.contains("configuration is valid"),
            "{mode:03o}: {stdout}"
        );
    }
}

/// A direct start must name the sample identity too, not only `--check`.
///
/// The test holds the loopback port, so startup reaches the warning and then
/// fails the bind deterministically: no root, no network, no served traffic.
#[test]
fn startup_warns_about_the_sample_identity() {
    use std::io::Read;
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
    let port = occupied.local_addr().unwrap().port();
    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let config = std::fs::read_to_string(example).unwrap().replace(
        "listen = \"0.0.0.0:443\"",
        &format!("listen = \"127.0.0.1:{port}\""),
    );
    // Without this, a changed example line would leave the sample port in
    // place and the test could pass on a bind error for the wrong port.
    assert!(
        config.contains(&format!("listen = \"127.0.0.1:{port}\"")),
        "the example config no longer holds the expected `listen` line"
    );
    let path = std::env::temp_dir().join(format!("beam-startup-{}", std::process::id()));
    std::fs::write(&path, config).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_beam"))
        .arg("--config")
        .arg(&path)
        .env("RUST_LOG", "off")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn beam");
    let status = wait_for_exit(&mut child, Duration::from_secs(20));
    if status.is_none() {
        let _ = child.kill();
    }
    child.wait().expect("reap beam");
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    std::fs::remove_file(&path).unwrap();

    let status = status.expect("startup must fail the occupied bind instead of serving");
    assert_eq!(status.code(), Some(1), "{stderr}");
    assert!(stderr.contains("sample identity"), "{stderr}");
    for field in ["user.id", "reality.private_key", "reality.short_ids[0]"] {
        assert!(stderr.contains(field), "{field} missing from {stderr}");
    }
    // The bind error proves the warning was emitted by the startup path, not
    // only before an early exit.
    assert!(stderr.contains("failed to bind"), "{stderr}");
    for secret in [
        "00000000-0000-0000-0000-000000000000",
        "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
        "0123456789abcdef",
    ] {
        assert!(!stderr.contains(secret), "secret value in stderr: {stderr}");
    }
}

/// One `key = "value"` line from `beam generate` output.
fn generated_line<'a>(identity: &'a str, prefix: &str) -> &'a str {
    identity
        .lines()
        .find(|line| line.starts_with(prefix))
        .unwrap_or_else(|| panic!("generated identity has no `{prefix}` line"))
}

/// A generated identity must pass `--check` without the sample warning.
#[test]
fn check_accepts_a_generated_identity() {
    use std::os::unix::fs::PermissionsExt;

    let generated = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["generate", "--host", "example.com", "--sni", "example.com"])
        .output()
        .unwrap();
    assert!(generated.status.success(), "{generated:?}");
    let identity = String::from_utf8_lossy(&generated.stdout);
    // The fragment must point at a cover destination that serves the SNI,
    // because the sample dest is only valid for the sample name.
    assert!(
        identity.contains("# Cover: set reality.dest")
            && identity.contains("example.com (for example \"example.com:443\")"),
        "generated output has no matching cover instruction: {identity}"
    );
    assert!(
        !identity.contains("whatsapp.net"),
        "generated output kept the sample cover name: {identity}"
    );

    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let sample = std::fs::read_to_string(example).unwrap();
    let config = sample
        .replace(
            "id = \"00000000-0000-0000-0000-000000000000\"",
            generated_line(&identity, "id = "),
        )
        .replace(
            "private_key = \"WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo\"",
            generated_line(&identity, "private_key = "),
        )
        .replace(
            "short_ids = [\"0123456789abcdef\"]",
            generated_line(&identity, "short_ids = "),
        );
    let path = std::env::temp_dir().join(format!("beam-generated-{}", std::process::id()));
    std::fs::write(&path, config).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&path)
        .env("RUST_LOG", "error")
        .output()
        .unwrap();
    std::fs::remove_file(&path).unwrap();

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("sample identity"), "{stderr}");
    let private_key = generated_line(&identity, "private_key = ")
        .trim_start_matches("private_key = ")
        .trim_matches('"');
    assert!(
        !stderr.contains(private_key),
        "generated key in stderr: {stderr}"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("configuration is valid"),
        "{output:?}"
    );
}

#[test]
fn generate_refuses_a_loose_regular_file_stdout() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let path = std::env::temp_dir().join(format!("beam-generate-{}", std::process::id()));
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(&path)
        .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["generate", "--host", "example.com", "--sni", "example.com"])
        .stdout(file)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("umask 077"));
    assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn version_does_not_build_a_runtime() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_beam"))
        .arg("--version")
        .env("TOKIO_WORKER_THREADS", "0")
        .output()
        .expect("run --version");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("beam "));
}

/// Caught-signal mask from `/proc/<pid>/status`, as a 64-bit set.
fn caught_signals(pid: u32) -> u64 {
    let status =
        std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read process status");
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("SigCgt:"))
        .expect("process status has a caught-signal mask");
    u64::from_str_radix(mask.trim(), 16).expect("hex caught-signal mask")
}

fn signal_bit(signal: u32) -> u64 {
    1 << (signal - 1)
}

fn send_signal(pid: u32, signal: &str) {
    let status = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal} {pid} failed");
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("poll child") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// A blocked config read must not swallow the operator's termination signal.
///
/// The FIFO makes `Config::from_path` block, so the test observes the startup
/// window directly: SIGHUP is already caught and ignored, while SIGTERM keeps
/// the default disposition and ends the process. The same must hold for
/// `--check`, which is how a rollout interrupts a stuck validation.
#[test]
fn startup_ignores_sighup_and_stays_terminable() {
    let directory = std::env::temp_dir().join(format!("beam-signal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("create signal test directory");
    let fifo = directory.join("beam.toml");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("run mkfifo")
            .success(),
        "mkfifo failed"
    );

    for check in [false, true] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_beam"));
        if check {
            command.arg("--check");
        }
        let mut child = command
            .arg("--config")
            .arg(&fifo)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn beam on a blocked config read");
        let pid = child.id();
        let label = if check { "--check" } else { "run" };

        // Wait until startup registered SIGHUP, which proves the process has
        // reached the blocking read rather than still starting up.
        let deadline = Instant::now() + Duration::from_secs(10);
        while caught_signals(pid) & signal_bit(1) == 0 {
            assert!(
                Instant::now() < deadline && child.try_wait().expect("poll child").is_none(),
                "{label}: beam did not reach the config read"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let caught = caught_signals(pid);
        assert_eq!(
            caught & signal_bit(2),
            0,
            "{label}: SIGINT caught too early"
        );
        assert_eq!(
            caught & signal_bit(15),
            0,
            "{label}: SIGTERM caught too early"
        );

        send_signal(pid, "HUP");
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            child.try_wait().expect("poll child").is_none(),
            "{label}: SIGHUP ended startup"
        );

        send_signal(pid, "TERM");
        let status = wait_for_exit(&mut child, Duration::from_secs(5))
            .unwrap_or_else(|| panic!("{label}: SIGTERM did not end the blocked config read"));
        assert_eq!(
            status.signal(),
            Some(15),
            "{label}: expected the default SIGTERM disposition, got {status:?}"
        );
    }

    std::fs::remove_dir_all(&directory).expect("remove signal test directory");
}

#[test]
fn check_reports_version_unbound_listener_and_effective_preauth_cap() {
    use std::net::TcpListener;
    use std::os::unix::fs::PermissionsExt;

    let version_out = Command::new(env!("CARGO_BIN_EXE_beam"))
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(version_out.status.success());
    let version = String::from_utf8_lossy(&version_out.stdout)
        .trim()
        .to_owned();

    // Hold a loopback port open while running `--check` to prove validation
    // succeeds without binding the configured listener.
    let occupied = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    let listen_addr = occupied.local_addr().unwrap();

    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let base_config = std::fs::read_to_string(example).unwrap().replace(
        "listen = \"0.0.0.0:443\"",
        &format!("listen = \"{listen_addr}\""),
    );

    // Case 1: unclamped default limits still report the effective cap.
    let unclamped_path =
        std::env::temp_dir().join(format!("beam-check-unclamped-{}", std::process::id()));
    std::fs::write(&unclamped_path, &base_config).unwrap();
    std::fs::set_permissions(&unclamped_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let unclamped = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&unclamped_path)
        .env("RUST_LOG", "error")
        .output()
        .unwrap();
    std::fs::remove_file(&unclamped_path).unwrap();

    assert!(unclamped.status.success(), "{unclamped:?}");
    let unclamped_stdout = String::from_utf8_lossy(&unclamped.stdout);
    assert!(
        unclamped_stdout.contains(&format!("({version}; listener {listen_addr} not bound)")),
        "missing version or unbound listener note in stdout: {unclamped_stdout}"
    );
    assert!(
        unclamped_stdout.contains("effective limits.max_preauth_per_ip: 128 (pre-auth slots: 256)"),
        "missing unclamped effective preauth limit in stdout: {unclamped_stdout}"
    );

    // Case 2: clamped limits report both effective and configured values.
    let clamped_config = base_config
        .replace("max_connections = 1024", "max_connections = 32")
        .replace("max_preauth_per_ip = 128", "max_preauth_per_ip = 64");
    let clamped_path =
        std::env::temp_dir().join(format!("beam-check-clamped-{}", std::process::id()));
    std::fs::write(&clamped_path, clamped_config).unwrap();
    std::fs::set_permissions(&clamped_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let clamped = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&clamped_path)
        .env("RUST_LOG", "error")
        .output()
        .unwrap();
    std::fs::remove_file(&clamped_path).unwrap();
    drop(occupied);

    assert!(clamped.status.success(), "{clamped:?}");
    let clamped_stdout = String::from_utf8_lossy(&clamped.stdout);
    assert!(
        clamped_stdout.contains(
            "effective limits.max_preauth_per_ip: 32 (configured 64, clamped to 32 pre-auth slots)"
        ),
        "missing clamped preauth limit in stdout: {clamped_stdout}"
    );
}

#[test]
fn check_includes_escaped_config_path_in_fd_budget_errors() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    let example = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let config = std::fs::read_to_string(example)
        .unwrap()
        .replace("max_connections = 1024", "max_connections = 60000");
    let dir = std::env::temp_dir().join(format!("beam-fd-path-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(OsStr::from_bytes(b"bad-\xff.toml"));
    std::fs::write(&path, config).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    // Lower the child soft RLIMIT_NOFILE only when the inherited limit exceeds
    // 4096, and fail explicitly if lowering it fails so the test never silently
    // falls back to a host-dependent limit (for example 1,048,576).
    let output = Command::new("bash")
        .args([
            "-c",
            "cur=$(ulimit -Sn); if [ \"$cur\" = unlimited ] || [ \"$cur\" -gt 4096 ]; then ulimit -Sn 4096 || exit 99; fi; exec \"$@\"",
            "--",
            env!("CARGO_BIN_EXE_beam"),
            "--check",
            "--config",
        ])
        .arg(&path)
        .env("RUST_LOG", "error")
        .output()
        .unwrap();
    std::fs::remove_dir_all(&dir).unwrap();

    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("file descriptor budget for `") && stderr.contains("bad-\\xff.toml"),
        "expected escaped config path in FD budget error: {stderr}"
    );

    // Also check a missing path containing non-UTF-8 and control bytes renders
    // consistently across both the outer context and inner Read error.
    let missing = std::env::temp_dir().join(OsStr::from_bytes(b"beam-missing-\xff-\n\x1b.toml"));
    let missing_out = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&missing)
        .env("RUST_LOG", "error")
        .output()
        .unwrap();
    assert_eq!(missing_out.status.code(), Some(1), "{missing_out:?}");
    let missing_stderr = String::from_utf8_lossy(&missing_out.stderr);
    assert!(
        missing_stderr.contains("beam-missing-\\xff-\\n\\u{1b}.toml"),
        "expected escaped missing path: {missing_stderr}"
    );
    assert!(
        !missing_stderr.contains('\u{fffd}') && !missing_stderr.contains('\x1b'),
        "lossy or raw control char in missing-file error chain: {missing_stderr:?}"
    );
}

/// Startup override and fallback diagnostics must stay visible on stderr even
/// when `RUST_LOG` is restrictive or empty, and the diagnostic privacy warning
/// must follow the *effective* filter (including `RUST_LOG=debug` over a quiet
/// config file).
#[test]
fn startup_override_and_fallback_diagnostics_stay_visible() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");

    // 1. RUST_LOG=off must not suppress the RUST_LOG override notice itself.
    let off = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&config)
        .env("RUST_LOG", "off")
        .output()
        .unwrap();
    assert!(off.status.success(), "{off:?}");
    let off_stderr = String::from_utf8_lossy(&off.stderr);
    assert!(
        off_stderr.contains("RUST_LOG is set and overrides the configured log level"),
        "RUST_LOG=off hid the override notice: {off_stderr}"
    );
    assert!(
        !off_stderr.contains("diagnostic logging is enabled"),
        "RUST_LOG=off should not trigger privacy warning: {off_stderr}"
    );

    // 2. Empty RUST_LOG="" falls back with a visible warning.
    let empty = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&config)
        .env("RUST_LOG", "")
        .output()
        .unwrap();
    assert!(empty.status.success(), "{empty:?}");
    let empty_stderr = String::from_utf8_lossy(&empty.stderr);
    assert!(
        empty_stderr.contains("RUST_LOG is set but empty"),
        "empty RUST_LOG did not warn: {empty_stderr}"
    );

    // 3. RUST_LOG=debug and target-scoped RUST_LOG=warn,beam_core=debug over
    //    config.example.toml (`level = "warn"`) both emit the diagnostic
    //    privacy warning.
    for filter in ["debug", "warn,beam_core=debug"] {
        let verbose = Command::new(env!("CARGO_BIN_EXE_beam"))
            .args(["--check", "--config"])
            .arg(&config)
            .env("RUST_LOG", filter)
            .output()
            .unwrap();
        assert!(verbose.status.success(), "{verbose:?}");
        let verbose_stderr = String::from_utf8_lossy(&verbose.stderr);
        assert!(
            verbose_stderr.contains("diagnostic logging is enabled"),
            "RUST_LOG={filter} did not emit privacy warning: {verbose_stderr}"
        );
    }

    // 4. Valid BEAM_MAX_BLOCKING_THREADS emits no fallback warning; out-of-range
    //    and non-UTF-8 values emit visible fallback warnings even under RUST_LOG=error.
    let valid_threads = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&config)
        .env("RUST_LOG", "error")
        .env("BEAM_MAX_BLOCKING_THREADS", "200")
        .output()
        .unwrap();
    assert!(valid_threads.status.success(), "{valid_threads:?}");
    assert!(
        !String::from_utf8_lossy(&valid_threads.stderr).contains("BEAM_MAX_BLOCKING_THREADS"),
        "valid override warned unexpectedly"
    );

    let bad_threads = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&config)
        .env("RUST_LOG", "error")
        .env("BEAM_MAX_BLOCKING_THREADS", "9999")
        .output()
        .unwrap();
    assert!(bad_threads.status.success(), "{bad_threads:?}");
    assert!(
        String::from_utf8_lossy(&bad_threads.stderr).contains("invalid BEAM_MAX_BLOCKING_THREADS"),
        "out-of-range BEAM_MAX_BLOCKING_THREADS did not warn"
    );

    let non_utf8_threads = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&config)
        .env("RUST_LOG", "error")
        .env("BEAM_MAX_BLOCKING_THREADS", OsStr::from_bytes(b"\xff\xfe"))
        .output()
        .unwrap();
    assert!(non_utf8_threads.status.success(), "{non_utf8_threads:?}");
    assert!(
        String::from_utf8_lossy(&non_utf8_threads.stderr)
            .contains("invalid non-UTF-8 BEAM_MAX_BLOCKING_THREADS"),
        "non-UTF-8 BEAM_MAX_BLOCKING_THREADS did not warn"
    );
}

#[test]
fn check_reports_fd_basis_xudp_per_mux_cap_and_listen_backlog() {
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.example.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args(["--check", "--config"])
        .arg(&config)
        .env("RUST_LOG", "error")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("effective fd budget basis:"),
        "missing fd budget basis in --check output: {stdout}"
    );
    assert!(
        stdout.contains("effective xudp per-mux sessions: 128 (binding limit: max_xudp_sessions"),
        "missing xudp per-mux limit in --check output: {stdout}"
    );
    assert!(
        stdout.contains("listen_backlog: requested 1024"),
        "missing listen_backlog line in --check output: {stdout}"
    );
}

#[test]
fn generate_supports_server_toml_client_link_and_warns_on_uppercase_sni() {
    let server_only = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args([
            "generate",
            "--host",
            "example.com",
            "--sni",
            "Example.COM",
            "--format",
            "server-toml",
        ])
        .output()
        .unwrap();
    assert!(server_only.status.success(), "{server_only:?}");
    let stdout = String::from_utf8_lossy(&server_only.stdout);
    let stderr = String::from_utf8_lossy(&server_only.stderr);
    assert!(stdout.contains("[user]") && stdout.contains("[reality]"));
    assert!(stdout.contains("server_names = [\"Example.COM\"]"));
    assert!(!stdout.contains("vless://"));
    assert!(stderr.contains("case-sensitively"));

    let link_only = Command::new(env!("CARGO_BIN_EXE_beam"))
        .args([
            "generate",
            "--host",
            "example.com",
            "--sni",
            "example.com",
            "--format",
            "client-link",
        ])
        .output()
        .unwrap();
    assert!(link_only.status.success(), "{link_only:?}");
    let link_stdout = String::from_utf8_lossy(&link_only.stdout);
    assert!(link_stdout.starts_with("vless://"));
    assert!(!link_stdout.contains("[reality]"));
}
