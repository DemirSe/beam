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
