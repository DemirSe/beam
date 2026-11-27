//! IPC wire format and named-pipe server for the Windows client.
//!
//! The message grammar is platform independent on purpose: the tray, the
//! service and the unit tests that run on the Linux CI job all use the same
//! parser, so a Windows-only build cannot hide a protocol bug.
//!
//! Requests are one line of at most [`MAX_REQUEST_BYTES`] bytes:
//!
//! ```text
//! STATUS
//! CONNECT
//! DISCONNECT
//! RESTART
//! IMPORT_LINK vless://<uuid>@<ip>:<port>?...
//! ```
//!
//! Replies are one line and start with `OK` or `ERR`:
//!
//! ```text
//! OK state=<state> ifname=<name|none> server=<host:port|none> rtt_ms=<ms|none> \
//!    reason=<token> bypass_ok=<0|1> dial_failures=<n> generation=<n> drops=<drops|none>
//! OK <key>=<value> ...
//! ERR code=<code> msg=<text>
//! ```
//!
//! Every value is a sanitized single-line token, so a hostile interface name,
//! server-controlled reason, or operator-supplied string can never split a
//! reply into two messages. No reply ever carries a UUID, public key, short id,
//! or the imported link.

use std::net::{IpAddr, SocketAddr};
#[cfg(windows)]
use std::path::Path;

use base64::Engine as _;
use beam_core::client::parse_client_link;

use crate::config::{ClientFileConfig, ConfigError};

/// Largest request line accepted from the pipe, excluding the line terminator.
///
/// One byte below `beam_sys::windows::pipe::MAX_IPC_MESSAGE_BYTES` (4096), so a
/// reply and a request always fit the same pipe buffer bound.
pub const MAX_REQUEST_BYTES: usize = 4095;

/// Largest reply line produced, excluding the appended `\n`.
pub const MAX_REPLY_BYTES: usize = 4095;

/// Longest state, reason, or field-name token in a reply.
pub(crate) const MAX_KEY_CHARS: usize = 32;
/// Longest interface-name token in a reply.
pub(crate) const MAX_IFNAME_CHARS: usize = 96;
/// Longest `drops` token in a reply.
pub(crate) const MAX_DROPS_CHARS: usize = 256;
/// Longest error text in a reply.
const MAX_ERROR_CHARS: usize = 512;

/// Windows client TOML used when no config exists yet.
///
/// The `[server]` table is inserted by [`import_vless_link_to_toml`]; every
/// other value matches the approved Windows defaults in `docs/WINDOWS-PLAN.md`.
const DEFAULT_WINDOWS_CONFIG: &str = r#"[tun]
name = "Beam"
address = "172.19.0.1/30"
mtu = 1500
auto_route = true
reject_quic = true
reject_ipv6 = true
strict_kill_switch = true
auto_connect = true

[dns]
enabled = true
upstream = "https://1.1.1.1/dns-query"
ipv4_only = true

[log]
level = "info"
"#;

/// One parsed IPC request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpcRequest {
    /// Report the current client status.
    Status,
    /// Start the tunnel with the configured server.
    Connect,
    /// Stop the tunnel and stay disconnected.
    Disconnect,
    /// Re-read the config and restart the tunnel.
    Restart,
    /// Replace the server with the given `vless://` link.
    ImportLink(String),
}

/// Status snapshot answered by `STATUS`.
///
/// `state` and `reason` use the same lowercase tokens as the Linux status file
/// (`connected`, `reconnecting`, `waiting_network`) plus the Windows-only
/// service states (`disconnected`, `connecting`, `stopping`, `error`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpcStatus {
    /// Lifecycle state token.
    pub state: String,
    /// TUN interface name, empty when no tunnel is open.
    pub ifname: String,
    /// Server address from the active or configured tunnel.
    pub server: Option<SocketAddr>,
    /// Last measured upstream RTT in milliseconds.
    pub rtt_ms: Option<u64>,
    /// Short machine-readable reason for `state`.
    pub reason: String,
    /// Whether every required bypass route is installed.
    pub bypass_ok: bool,
    /// Total failed authenticated upstream dials since the tunnel started.
    pub dial_failures: u64,
    /// Network generation counter (incremented on gateway changes and resume).
    pub generation: u64,
    /// Packet drop counters, when the engine has published them.
    pub drops: Option<String>,
}

impl IpcStatus {
    /// Status reported before a tunnel exists.
    pub fn disconnected(server: Option<SocketAddr>) -> Self {
        Self {
            state: "disconnected".to_owned(),
            ifname: String::new(),
            server,
            rtt_ms: None,
            reason: "not_connected".to_owned(),
            bypass_ok: true,
            dial_failures: 0,
            generation: 0,
            drops: None,
        }
    }
}

/// Parses one request line.
///
/// A single trailing `\n`, `\r\n`, or `\r` is stripped. The remainder must be
/// one UTF-8 line without control characters. The error tuple is
/// `(code, message)`, ready for [`format_err_reply`].
pub fn parse_request(line: &[u8]) -> Result<IpcRequest, (&'static str, &'static str)> {
    if line.len() > MAX_REQUEST_BYTES {
        return Err(("too_long", "request is longer than the 4095 byte limit"));
    }
    let body = strip_line_terminator(line);
    if body.iter().any(|byte| *byte == b'\r' || *byte == b'\n') {
        return Err(("bad_request", "request must contain exactly one line"));
    }
    let text =
        std::str::from_utf8(body).map_err(|_| ("bad_request", "request is not valid UTF-8"))?;
    if text.chars().any(char::is_control) {
        return Err(("bad_request", "request must not contain control characters"));
    }

    match text {
        "STATUS" => Ok(IpcRequest::Status),
        "CONNECT" => Ok(IpcRequest::Connect),
        "DISCONNECT" => Ok(IpcRequest::Disconnect),
        "RESTART" => Ok(IpcRequest::Restart),
        _ => {
            let Some(link) = text.strip_prefix("IMPORT_LINK") else {
                return Err(("unknown_command", "unknown command"));
            };
            let Some(link) = link.strip_prefix(' ') else {
                return Err((
                    "bad_request",
                    "IMPORT_LINK requires one space and a vless:// link",
                ));
            };
            if link.is_empty() {
                return Err(("missing_link", "IMPORT_LINK requires a vless:// link"));
            }
            if let Some(reason) = link_argument_error(link) {
                return Err(("bad_link", reason));
            }
            Ok(IpcRequest::ImportLink(link.to_owned()))
        }
    }
}

/// Rejects an `IMPORT_LINK` argument that cannot be a `vless://` link.
///
/// The link itself is never echoed. The bound keeps a hostile argument from
/// reaching the config writer with an unbounded size.
fn link_argument_error(link: &str) -> Option<&'static str> {
    if link.len() > MAX_REQUEST_BYTES {
        return Some("link is longer than the 4095 byte limit");
    }
    if link.chars().any(char::is_whitespace) {
        return Some("link must not contain whitespace");
    }
    if !link.starts_with("vless://") {
        return Some("link must start with vless://");
    }
    None
}

/// Removes one trailing line terminator (`\n`, `\r\n`, or `\r`).
fn strip_line_terminator(line: &[u8]) -> &[u8] {
    if let Some(rest) = line.strip_suffix(b"\r\n") {
        return rest;
    }
    if let Some(rest) = line.strip_suffix(b"\n") {
        return rest;
    }
    if let Some(rest) = line.strip_suffix(b"\r") {
        return rest;
    }
    line
}

/// Formats the `STATUS` reply for `status`.
pub fn format_status_reply(status: &IpcStatus) -> String {
    let state = token_or_none(&status.state, MAX_KEY_CHARS);
    let ifname = token_or_none(&status.ifname, MAX_IFNAME_CHARS);
    let server = match status.server {
        Some(addr) => token_or_none(&addr.to_string(), MAX_IFNAME_CHARS),
        None => "none".to_owned(),
    };
    let rtt = match status.rtt_ms {
        Some(rtt) => rtt.to_string(),
        None => "none".to_owned(),
    };
    let reason = token_or_none(&status.reason, MAX_KEY_CHARS);
    let bypass = u8::from(status.bypass_ok);
    let dial_failures = status.dial_failures;
    let generation = status.generation;
    let drops = match status.drops.as_deref() {
        Some(drops) if !drops.is_empty() => wire_token(drops, MAX_DROPS_CHARS),
        _ => "none".to_owned(),
    };
    let drops = if drops.is_empty() {
        "none".to_owned()
    } else {
        drops
    };

    let mut reply = format!(
        "OK state={state} ifname={ifname} server={server} rtt_ms={rtt} reason={reason} \
         bypass_ok={bypass} dial_failures={dial_failures} generation={generation} drops={drops}"
    );
    truncate_bytes(&mut reply, MAX_REPLY_BYTES);
    reply
}

/// Formats a generic `OK` reply carrying `fields`.
///
/// Fields that would push the reply past [`MAX_REPLY_BYTES`] are dropped, so the
/// result is always one bounded line.
pub fn format_ok_reply(fields: &[(&str, &str)]) -> String {
    let mut reply = String::from("OK");
    for (key, value) in fields {
        let key = wire_token(key, MAX_KEY_CHARS);
        let value = wire_token(value, MAX_KEY_CHARS);
        if key.is_empty() || reply.len() + key.len() + value.len() + 2 > MAX_REPLY_BYTES {
            continue;
        }
        reply.push(' ');
        reply.push_str(&key);
        reply.push('=');
        reply.push_str(&value);
    }
    reply
}

/// Formats an `ERR` reply with a sanitized `msg`.
///
/// Control characters become spaces, so a message built from an OS error can
/// never terminate the line early, and the text is bounded to fit
/// [`MAX_REPLY_BYTES`].
pub fn format_err_reply(code: &str, msg: &str) -> String {
    let code = wire_token(code, MAX_KEY_CHARS);
    let code = if code.is_empty() {
        "error".to_owned()
    } else {
        code
    };
    let mut reply = format!("ERR code={code} msg=");
    let budget = MAX_REPLY_BYTES.saturating_sub(reply.len());
    let text = message_text(msg, budget.min(MAX_ERROR_CHARS));
    reply.push_str(&text);
    reply
}

/// Rewrites `value` as one printable token of at most `max_chars` characters.
///
/// Control characters and whitespace become `_` so the result cannot start a new
/// line, and non-ASCII characters are kept because both the tray and the status
/// file are UTF-8.
pub(crate) fn wire_token(value: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_chars));
    for (index, ch) in value.chars().enumerate() {
        if index >= max_chars {
            break;
        }
        out.push(if ch.is_control() || ch.is_whitespace() {
            '_'
        } else {
            ch
        });
    }
    out
}

/// [`wire_token`] that reports an empty result as `none`.
fn token_or_none(value: &str, max_chars: usize) -> String {
    let token = wire_token(value, max_chars);
    if token.is_empty() {
        "none".to_owned()
    } else {
        token
    }
}

/// Rewrites free-form text as one line of at most `max_bytes` bytes.
///
/// Line breaks and other control characters become spaces, other characters are
/// kept, and the text is cut on a character boundary.
fn message_text(value: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(value.len().min(max_bytes));
    for ch in value.chars() {
        let rendered = if ch.is_control() { ' ' } else { ch };
        if out.len() + rendered.len_utf8() > max_bytes {
            break;
        }
        out.push(rendered);
    }
    out.trim_end().to_owned()
}

/// Cuts `value` to at most `max_bytes` bytes on a character boundary.
fn truncate_bytes(value: &mut String, max_bytes: usize) {
    if value.len() <= max_bytes {
        return;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
}

/// Builds a client TOML config from a `vless://` link.
///
/// `existing_toml` is the current config text; it is preserved except for the
/// `[server]` table, and an empty string means "no config yet" and selects
/// [`DEFAULT_WINDOWS_CONFIG`]. The rendered text is validated with
/// [`ClientFileConfig::parse_and_validate`] before it is returned, so a
/// successful call always yields a config the service can load.
///
/// The returned error never contains the link, the UUID, the public key, or the
/// short id: an invalid link is reported by its category only.
pub fn import_vless_link_to_toml(link: &str, existing_toml: &str) -> Result<String, String> {
    let parsed = parse_client_link(link).map_err(|err| format!("invalid vless link: {err}"))?;

    // A hostname would need DNS before the tunnel exists, which turns a
    // bootstrap race into a leak window; the service requires the server IP.
    let Ok(host) = parsed.host.parse::<IpAddr>() else {
        return Err("vless link host must be an IP address for beam-client".to_owned());
    };
    let server = SocketAddr::new(host, parsed.port);

    let mut table: toml::Table = if existing_toml.trim().is_empty() {
        DEFAULT_WINDOWS_CONFIG
            .parse()
            .map_err(|_| "built-in default config is not valid TOML".to_owned())?
    } else {
        existing_toml
            .parse()
            .map_err(|_| "existing config is not valid TOML".to_owned())?
    };

    let mut server_table = toml::Table::new();
    server_table.insert(
        "address".to_owned(),
        toml::Value::String(server.to_string()),
    );
    server_table.insert("sni".to_owned(), toml::Value::String(parsed.server_name));
    server_table.insert(
        "public_key".to_owned(),
        toml::Value::String(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(parsed.public_key),
        ),
    );
    server_table.insert(
        "short_id".to_owned(),
        toml::Value::String(hex_lower(&parsed.short_id)),
    );
    server_table.insert(
        "user_id".to_owned(),
        toml::Value::String(uuid::Uuid::from_bytes(parsed.user_id).to_string()),
    );
    table.insert("server".to_owned(), toml::Value::Table(server_table));

    let rendered =
        toml::to_string(&table).map_err(|_| "cannot render config as TOML".to_owned())?;
    ClientFileConfig::parse_and_validate(&rendered).map_err(|err| match err {
        // Validation text is ours and names only fields, never key material.
        ConfigError::Invalid(message) => message,
        ConfigError::Toml(_) => "imported config is not valid TOML".to_owned(),
        ConfigError::Io(err) => format!("cannot read config: {err}"),
    })?;
    Ok(rendered)
}

/// Lowercase hex encoding for the REALITY short id.
fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Reads the unelevated tray user's SID from `path`.
///
/// Returns `None` for a missing, unreadable, empty, oversized, or malformed
/// file, which makes the pipe DACL fall back to `SYSTEM` + `Administrators`
/// instead of guessing a principal.
#[cfg(windows)]
pub fn read_allowed_user_sid(path: &Path) -> Option<String> {
    use std::io::Read as _;

    // A SID string is a few dozen characters; the bound keeps a hostile or
    // accidentally huge file from being read into memory at all.
    const MAX_SID_FILE_BYTES: u64 = 512;

    let mut reader = std::fs::File::open(path).ok()?.take(MAX_SID_FILE_BYTES + 1);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_SID_FILE_BYTES {
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    let sid = text.trim();
    if sid.is_empty() {
        return None;
    }
    beam_sys::windows::pipe::validate_windows_sid(sid).ok()?;
    Some(sid.to_owned())
}

/// Number of unique temporary names tried before an atomic write gives up.
#[cfg(windows)]
const MAX_TEMP_FILE_ATTEMPTS: u32 = 8;

/// Per-process counter that makes every temporary file name unique.
#[cfg(windows)]
static TEMP_FILE_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Creates an empty sibling temporary file for `path` and returns its name
/// with the open handle.
///
/// The name carries the process id and a per-process counter and the file is
/// opened with `create_new`, so a file or symlink another account planted under
/// a predictable name is neither opened nor truncated. The handle is still
/// empty, so the caller can restrict its DACL before it writes anything.
#[cfg(windows)]
pub(crate) fn create_temp_sibling(
    path: &Path,
) -> std::io::Result<(std::path::PathBuf, std::fs::File)> {
    use std::sync::atomic::Ordering;

    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path has no parent directory",
        )
    })?;
    if !parent.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("directory {} does not exist", parent.display()),
        ));
    }
    let name = path.file_name().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no file name")
    })?;
    for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
        let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut tmp_name = name.to_os_string();
        tmp_name.push(format!(".tmp.{}.{counter}", std::process::id()));
        let tmp = parent.join(tmp_name);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(file) => return Ok((tmp, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not create a unique temporary file",
    ))
}

/// Replaces `path` with `content` through a synced, unique temporary file.
///
/// A crash leaves either the old or the new file: the temporary file lives in
/// the same directory, so the final rename is a same-volume replace and never
/// exposes a truncated file. When `admin_only` is set the `SYSTEM` +
/// `Administrators` DACL is applied to the still-empty temporary file, so no
/// secret byte ever reaches a file with an inherited ACL and a replace can
/// never widen the permissions of the file it overwrites.
#[cfg(windows)]
fn write_atomic(path: &Path, content: &str, admin_only: bool) -> std::io::Result<()> {
    use std::io::Write as _;

    let (tmp, mut file) = create_temp_sibling(path)?;
    let prepared = if admin_only {
        beam_sys::windows::set_file_admin_only_acl(&tmp)
    } else {
        Ok(())
    };
    let written = prepared
        .and_then(|()| file.write_all(content.as_bytes()))
        .and_then(|()| file.sync_all());
    drop(file);
    let result = written.and_then(|()| std::fs::rename(&tmp, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Replaces the client config at `path` with `content`, restricted to `SYSTEM`
/// and `Administrators` before the first byte is written.
#[cfg(windows)]
pub fn write_config_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    write_atomic(path, content, true)
}

/// Replaces the status file at `path` with `content`.
///
/// The status file holds no secret and unelevated tray and diagnostic tools read
/// it, so it keeps the inherited directory DACL.
#[cfg(windows)]
pub fn write_status_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    write_atomic(path, content, false)
}

/// Runs the named-pipe server on a dedicated thread.
///
/// The thread accepts one client at a time, reads one bounded request line with
/// a 3 s deadline, passes it to `handler`, writes the returned line with a 3 s
/// deadline, waits up to 200 ms for the client to close, and disconnects. Every
/// failure is logged and the loop keeps serving, so one malformed or abandoned
/// connection cannot stop Connect/Disconnect for the session.
///
/// The returned handle ends when `cancel` is signalled, which happens on service
/// stop.
#[cfg(windows)]
pub fn run_ipc_server_thread(
    pipe_name: String,
    allowed_sid: Option<String>,
    cancel: beam_sys::windows::pipe::CancelEvent,
    handler: std::sync::Arc<dyn Fn(IpcRequest) -> String + Send + Sync>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use std::sync::mpsc::sync_channel;

    use beam_sys::windows::pipe::NamedPipeServer;
    use tracing::{info, warn};

    /// Deadline for reading one request line.
    const READ_TIMEOUT_MS: u32 = 3_000;
    /// Deadline for writing one reply line.
    const WRITE_TIMEOUT_MS: u32 = 3_000;
    /// Pause after a failed accept, so a broken pipe cannot spin a core.
    const ACCEPT_RETRY_DELAY_MS: u64 = 100;
    /// Time the client gets to read the reply before the disconnect.
    const CLOSE_WAIT_MS: u32 = 200;

    // The server owns a raw `OVERLAPPED` and is not `Send`, so it is created on
    // the thread that serves it. Startup errors travel back through this
    // channel, which keeps `create` failure observable to the caller.
    let (ready_tx, ready_rx) = sync_channel(1);
    let handle = std::thread::Builder::new()
        .name("beam-ipc".to_owned())
        .spawn(move || {
            let mut server = match NamedPipeServer::create(&pipe_name, allowed_sid.as_deref()) {
                Ok(server) => server,
                Err(err) => {
                    let _ = ready_tx.send(Err(err));
                    return;
                }
            };
            let _ = ready_tx.send(Ok(()));
            info!(pipe = %pipe_name, "IPC pipe server listening");
            loop {
                match server.accept_or_cancel(&cancel) {
                    Ok(true) => {}
                    Ok(false) => break,
                    Err(err) => {
                        warn!(error = %err, "IPC accept failed");
                        std::thread::sleep(std::time::Duration::from_millis(ACCEPT_RETRY_DELAY_MS));
                        continue;
                    }
                }
                match server.read_line_bounded(MAX_REQUEST_BYTES, READ_TIMEOUT_MS) {
                    Ok(line) if !line.is_empty() => {
                        let reply = match parse_request(&line) {
                            Ok(request) => handler(request),
                            Err((code, message)) => format_err_reply(code, message),
                        };
                        if let Err(err) =
                            server.write_line_bounded(reply.as_bytes(), WRITE_TIMEOUT_MS)
                        {
                            warn!(error = %err, "IPC reply write failed");
                        }
                        let _ = server.wait_client_close(CLOSE_WAIT_MS);
                    }
                    Ok(_) => {}
                    Err(err) => warn!(error = %err, "IPC request read failed"),
                }
                if let Err(err) = server.disconnect() {
                    warn!(error = %err, "IPC disconnect failed");
                }
            }
            info!("IPC pipe server stopped");
        })?;

    match ready_rx.recv() {
        Ok(Ok(())) => Ok(handle),
        Ok(Err(err)) => {
            let _ = handle.join();
            Err(err)
        }
        Err(_) => {
            let _ = handle.join();
            Err(std::io::Error::other("IPC thread stopped during startup"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_ID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    fn public_key() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0x5a_u8; 32])
    }

    fn link(host: &str, port: u16) -> String {
        let host = if host.contains(':') {
            format!("[{host}]")
        } else {
            host.to_owned()
        };
        format!(
            "vless://{USER_ID}@{host}:{port}?encryption=none&security=reality\
             &sni=whatsapp.net&fp=chrome&pbk={}&sid=0123456789abcdef\
             &type=tcp&flow=xtls-rprx-vision",
            public_key()
        )
    }

    fn status() -> IpcStatus {
        IpcStatus {
            state: "connected".to_owned(),
            ifname: "Beam".to_owned(),
            server: Some("203.0.113.10:443".parse().expect("test address")),
            rtt_ms: Some(42),
            reason: "dial_activity".to_owned(),
            bypass_ok: true,
            dial_failures: 3,
            generation: 7,
            drops: Some("route:1,ip_parse:2".to_owned()),
        }
    }

    #[test]
    fn parses_every_command() {
        assert_eq!(parse_request(b"STATUS"), Ok(IpcRequest::Status));
        assert_eq!(parse_request(b"CONNECT\n"), Ok(IpcRequest::Connect));
        assert_eq!(parse_request(b"DISCONNECT\r\n"), Ok(IpcRequest::Disconnect));
        assert_eq!(parse_request(b"RESTART\r"), Ok(IpcRequest::Restart));
        assert_eq!(
            parse_request(b"IMPORT_LINK vless://x@203.0.113.10:443?security=reality"),
            Ok(IpcRequest::ImportLink(
                "vless://x@203.0.113.10:443?security=reality".to_owned()
            ))
        );
    }

    #[test]
    fn rejects_malformed_requests() {
        let cases: &[(&[u8], &str)] = &[
            (b"", "unknown_command"),
            (b"status", "unknown_command"),
            (b"STATUS STATUS", "unknown_command"),
            (b"IMPORT_LINK", "bad_request"),
            (b"IMPORT_LINK ", "missing_link"),
            (b"IMPORT_LINK vless://a b", "bad_link"),
            (b"IMPORT_LINK https://example.com", "bad_link"),
            (b"STATUS\nCONNECT", "bad_request"),
            (b"STATUS\x07", "bad_request"),
            (b"STATUS\xff", "bad_request"),
        ];
        for (line, code) in cases {
            let error = parse_request(line).err().unwrap_or_else(|| {
                panic!("request {line:?} must be rejected");
            });
            assert_eq!(error.0, *code, "line {line:?}");
            assert!(!error.1.contains('\n') && !error.1.contains('\r'));
        }
    }

    #[test]
    fn rejects_a_request_over_the_size_bound() {
        let over = vec![b'A'; MAX_REQUEST_BYTES + 1];
        assert_eq!(parse_request(&over).err().map(|e| e.0), Some("too_long"));

        let mut at_bound = vec![b'A'; MAX_REQUEST_BYTES];
        at_bound[MAX_REQUEST_BYTES - 1] = b'\n';
        let error = parse_request(&at_bound).expect_err("unknown command");
        assert_eq!(error.0, "unknown_command");
    }

    #[test]
    fn status_reply_is_one_exact_line() {
        assert_eq!(
            format_status_reply(&status()),
            "OK state=connected ifname=Beam server=203.0.113.10:443 rtt_ms=42 \
             reason=dial_activity bypass_ok=1 dial_failures=3 generation=7 \
             drops=route:1,ip_parse:2"
        );
    }

    #[test]
    fn status_reply_reports_none_for_missing_values() {
        let reply = format_status_reply(&IpcStatus::disconnected(None));
        assert_eq!(
            reply,
            "OK state=disconnected ifname=none server=none rtt_ms=none \
             reason=not_connected bypass_ok=1 dial_failures=0 generation=0 drops=none"
        );
    }

    #[test]
    fn status_reply_sanitizes_hostile_tokens() {
        let mut status = status();
        status.ifname = "Beam\nTun 0".to_owned();
        status.reason = "dial\rfailures".to_owned();
        status.drops = Some("line\nbreak".to_owned());
        let reply = format_status_reply(&status);
        assert!(!reply.contains('\n') && !reply.contains('\r'), "{reply}");
        assert!(reply.contains("ifname=Beam_Tun_0"), "{reply}");
        assert!(reply.contains("reason=dial_failures"), "{reply}");
        assert!(reply.contains("drops=line_break"), "{reply}");
    }

    #[test]
    fn status_reply_stays_within_the_wire_bound() {
        let mut status = status();
        status.ifname = "i".repeat(MAX_IFNAME_CHARS * 4);
        status.drops = Some("d".repeat(MAX_DROPS_CHARS * 4));
        let reply = format_status_reply(&status);
        assert!(reply.len() <= MAX_REPLY_BYTES, "{}", reply.len());
    }

    #[test]
    fn ok_reply_carries_sanitized_fields() {
        assert_eq!(
            format_ok_reply(&[("state", "connecting")]),
            "OK state=connecting"
        );
        assert_eq!(
            format_ok_reply(&[("server", "203.0.113.10:443")]),
            "OK server=203.0.113.10:443"
        );
        let hostile = format_ok_reply(&[("server", "evil\nline")]);
        assert!(!hostile.contains('\n'));
    }

    #[test]
    fn err_reply_is_bounded_and_single_line() {
        let reply = format_err_reply("import_failed", "line one\nline two\r\u{0}");
        assert!(reply.starts_with("ERR code=import_failed msg="), "{reply}");
        assert!(!reply.contains('\n') && !reply.contains('\r'), "{reply}");

        let long = format_err_reply("import_failed", &"x".repeat(MAX_REPLY_BYTES));
        assert!(long.len() <= MAX_REPLY_BYTES, "{}", long.len());
        assert_eq!(format_err_reply("", ""), "ERR code=error msg=");
    }

    #[test]
    fn imports_an_ipv4_link_with_the_windows_defaults() {
        let text = import_vless_link_to_toml(&link("203.0.113.10", 443), "").expect("import");
        let cfg = ClientFileConfig::parse_and_validate(&text).expect("imported config validates");
        assert_eq!(
            cfg.engine.client.server_addr.to_string(),
            "203.0.113.10:443"
        );
        assert_eq!(cfg.tun_name, "Beam");
        assert_eq!(cfg.tun_cidr, "172.19.0.1/30");
        assert_eq!(cfg.mtu, 1500);
        assert!(cfg.auto_route);
        assert!(cfg.strict_kill_switch);
        assert!(cfg.auto_connect);
        // IPv4-only upstream egress (mirrors sing-box `strategy: ipv4_only`):
        // AAAA answers are suppressed and IPv6 SYNs fail fast with RST so
        // dual-stack downloads use IPv4 instead of stalling on IPv6 dials.
        assert!(cfg.engine.route.reject_ipv6);
        assert!(
            cfg.engine
                .dns
                .as_ref()
                .expect("windows default enables dns")
                .ipv4_only
        );
        assert!(cfg.engine.dns.is_some());
        assert!(
            text.contains("user_id"),
            "rendered config must carry the server table"
        );
    }

    #[test]
    fn imports_an_ipv6_link() {
        let text = import_vless_link_to_toml(&link("2001:db8::1", 8443), "").expect("import");
        let cfg = ClientFileConfig::parse_and_validate(&text).expect("imported config validates");
        assert_eq!(
            cfg.engine.client.server_addr.to_string(),
            "[2001:db8::1]:8443"
        );
    }

    #[test]
    fn import_preserves_every_section_except_the_server() {
        let existing = r#"[server]
address = "198.51.100.7:443"
sni = "old.example"
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
short_id = "00"
user_id = "b831381d-6324-4d53-ad4f-8cda48b30811"

[tun]
name = "Custom"
address = "10.9.0.1/30"
mtu = 1280
auto_route = false

[dns]
enabled = false
upstream = "https://9.9.9.9/dns-query"

[bypass]
cidrs = ["192.168.0.0/16"]

[limits]
max_tcp_connections = 64

[log]
level = "debug"
"#;
        let text = import_vless_link_to_toml(&link("203.0.113.10", 443), existing).expect("import");
        let cfg = ClientFileConfig::parse_and_validate(&text).expect("imported config validates");
        assert_eq!(
            cfg.engine.client.server_addr.to_string(),
            "203.0.113.10:443"
        );
        assert_eq!(cfg.tun_name, "Custom");
        assert_eq!(cfg.mtu, 1280);
        assert!(!cfg.auto_route);
        assert!(cfg.engine.dns.is_none());
        assert_eq!(cfg.bypass_cidrs, vec!["192.168.0.0/16".to_owned()]);
        assert_eq!(cfg.log_level, "debug");
    }

    #[test]
    fn rejects_a_hostname_host() {
        let error = import_vless_link_to_toml(&link("beam.example.com", 443), "")
            .expect_err("hostname must be rejected");
        assert_eq!(
            error,
            "vless link host must be an IP address for beam-client"
        );
    }

    #[test]
    fn rejects_malformed_links_without_echoing_them() {
        for bad in [
            "not a link".to_owned(),
            format!("vless://{USER_ID}@203.0.113.10:443"),
            format!("vless://{USER_ID}@203.0.113.10:0?security=reality"),
            "vless://00000000-0000-0000-0000-000000000000@203.0.113.10:443?security=none"
                .to_owned(),
        ] {
            let error = import_vless_link_to_toml(&bad, "").expect_err("rejected");
            assert!(!error.contains(USER_ID), "{error}");
            assert!(!error.contains(&public_key()), "{error}");
            assert!(!error.contains("0123456789abcdef"), "{error}");
        }
    }

    #[test]
    fn rejects_an_unparseable_existing_config_without_echoing_it() {
        let existing = format!(
            "[server]\npublic_key = \"{}\"\nthis is not toml\n",
            public_key()
        );
        let error = import_vless_link_to_toml(&link("203.0.113.10", 443), &existing)
            .expect_err("invalid existing config must be rejected");
        assert_eq!(error, "existing config is not valid TOML");
        assert!(!error.contains(&public_key()), "{error}");
    }

    #[test]
    fn rejects_an_existing_section_that_fails_validation() {
        // Link parsing cannot produce an invalid server table, so the only way
        // to reach the validation step is a preserved section that is wrong.
        let existing = "[tun]\nmtu = 100\n";
        let error = import_vless_link_to_toml(&link("203.0.113.10", 443), existing)
            .expect_err("invalid mtu must be rejected");
        assert!(error.contains("mtu"), "{error}");
        assert!(!error.contains(&public_key()), "{error}");
    }
}
