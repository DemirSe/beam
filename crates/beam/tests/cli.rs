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
