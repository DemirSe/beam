use serde_json::Value;
use std::{fs, process::Command, time::Duration};

const UNREACHABLE: &str = "https://127.0.0.1:0/";

fn verdict(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).expect("verdict is a JSON object")
}

fn assert_failure(value: &Value) {
    assert_eq!(value["ok"], false);
    assert_eq!(value["hash_ok"], false);
    assert_eq!(value["connections"], 0);
    assert_eq!(value["completed"], 0);
    assert_eq!(value["bytes"], 0);
    let errors = value["errors"].as_array().expect("errors is an array");
    assert!(!errors.is_empty(), "a failure verdict names its error");
    assert!(
        errors.iter().all(|error| error.is_string()),
        "every error is a string"
    );
}

#[test]
fn early_connect_failure_writes_the_same_verdict_to_stdout_and_file() {
    let directory = std::env::temp_dir().join(format!("beam-h2-client-{}", std::process::id()));
    fs::create_dir(&directory).expect("create test output directory");
    let path = directory.join("result.json");
    let output = Command::new(env!("CARGO_BIN_EXE_h2-client"))
        .args(["--url", UNREACHABLE, "--out"])
        .arg(&path)
        .output()
        .expect("run h2-client");
    let file = fs::read(&path);
    fs::remove_dir_all(directory).expect("remove test output directory");
    let file = file.expect("read failure verdict");

    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, file);
    let value = verdict(&output.stdout);
    assert_failure(&value);
    assert_eq!(value["streams"], 16);
    assert!(
        value["errors"][0]
            .as_str()
            .expect("error text")
            .contains("could not connect")
    );
}

#[test]
fn invalid_url_fails_before_any_connection() {
    let output = Command::new(env!("CARGO_BIN_EXE_h2-client"))
        .args(["--url", "https://exa mple.com/", "--streams", "4"])
        .output()
        .expect("run h2-client");

    assert_eq!(output.status.code(), Some(1));
    let value = verdict(&output.stdout);
    assert_failure(&value);
    assert_eq!(value["streams"], 4);
    assert!(
        value["errors"][0]
            .as_str()
            .expect("error text")
            .contains("invalid URL")
    );
}

#[test]
fn unusable_output_path_preserves_stdout_verdict() {
    let output = Command::new(env!("CARGO_BIN_EXE_h2-client"))
        .args(["--url", UNREACHABLE, "--out", "."])
        .output()
        .expect("run h2-client");

    assert_eq!(output.status.code(), Some(1));
    assert_failure(&verdict(&output.stdout));
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not write ."));
}

#[test]
fn stdout_failure_preserves_file_verdict() {
    let directory = std::env::temp_dir().join(format!("beam-h2-stdout-{}", std::process::id()));
    fs::create_dir(&directory).expect("create test output directory");
    let path = directory.join("result.json");
    let stdout = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open failing stdout fixture");
    let output = Command::new(env!("CARGO_BIN_EXE_h2-client"))
        .args(["--url", UNREACHABLE, "--out"])
        .arg(&path)
        .stdout(stdout)
        .output()
        .expect("run h2-client");
    let file = fs::read_to_string(&path);
    fs::remove_dir_all(directory).expect("remove test output directory");

    assert_eq!(output.status.code(), Some(1));
    let file = file.expect("read failure verdict");
    assert_failure(&verdict(file.as_bytes()));
    assert!(String::from_utf8_lossy(&output.stderr).contains("could not write verdict to stdout"));
}

#[test]
fn aggregate_budget_rejects_huge_runs_before_connecting() {
    // 16 streams of 64 MiB would move ~1 GiB; the verdict must name the
    // budget instead of allocating or dialing.
    let output = Command::new(env!("CARGO_BIN_EXE_h2-client"))
        .args([
            "--url",
            "https://127.0.0.1:1/?bytes=67108864",
            "--streams",
            "16",
        ])
        .output()
        .expect("run h2-client");

    assert_eq!(output.status.code(), Some(1));
    let value = verdict(&output.stdout);
    assert_failure(&value);
    assert_eq!(value["streams"], 16);
    assert!(
        value["errors"][0]
            .as_str()
            .expect("error text")
            .contains("aggregate budget")
    );
}

#[test]
fn stalled_tls_handshake_reports_the_tls_stage() {
    // A listener that accepts TCP but never speaks TLS stalls the handshake
    // stage; the client must time out with a TLS-specific error.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local address");
    std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            std::thread::sleep(Duration::from_secs(30));
            drop(stream);
        }
    });
    let output = Command::new(env!("CARGO_BIN_EXE_h2-client"))
        .args(["--url", &format!("https://{addr}/"), "--streams", "1"])
        .output()
        .expect("run h2-client");

    assert_eq!(output.status.code(), Some(1));
    let value = verdict(&output.stdout);
    assert_failure(&value);
    let error = value["errors"][0].as_str().expect("error text");
    assert!(error.contains("TLS handshake"), "unexpected error: {error}");
    assert!(error.contains("timed out"), "unexpected error: {error}");
}
