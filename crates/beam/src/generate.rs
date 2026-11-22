//! `beam generate`: REALITY and VLESS identity generation for a new deployment.

use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;

use anyhow::{Context, Result, bail};
use beam_core::config::is_plausible_dns_name;
use beam_core::identity::{
    ClientLink, RealityKeyPair, client_link, generate_short_id, generate_uuid,
};
use clap::{Args, ValueEnum};
use zeroize::Zeroizing;

/// Output selection for `beam generate`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum GenerateFormat {
    /// Emit the delimited server TOML fragment followed by the client VLESS link.
    #[default]
    All,
    /// Emit only the standalone server TOML fragment (`[user]` and `[reality]`).
    ServerToml,
    /// Emit only the Xray-compatible client `vless://` link.
    ClientLink,
}

/// Message used for every rejected `--host` value.
const HOST_HINT: &str = "host must be a DNS name or an IP address; pass the TCP \
                        port with --port and omit any scheme or path";

/// Delimiter lines wrapping the server TOML fragment in `--format all` output.
const SERVER_CONFIG_BEGIN: &str = "# --- BEGIN BEAM SERVER CONFIG ---";
const SERVER_CONFIG_END: &str = "# --- END BEAM SERVER CONFIG ---";

/// Generates a UUID, REALITY keypair, short id, and client VLESS link.
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Host or IP address the client connects to.
    #[arg(long, value_parser = parse_host)]
    host: String,

    /// TCP port the client connects to.
    #[arg(long, default_value_t = 443, value_parser = clap::value_parser!(u16).range(1..))]
    port: u16,

    /// REALITY server name (SNI) for the link and `reality.server_names`.
    /// REALITY matches SNI case-sensitively, so use the exact letter case the
    /// client will send (typically lowercase).
    #[arg(long, value_parser = parse_server_name)]
    sni: String,

    /// Display name shown by the client.
    #[arg(long, default_value = "beam")]
    remark: String,

    /// Output format: `all` (default), `server-toml`, or `client-link`.
    #[arg(long, value_enum, default_value_t = GenerateFormat::All)]
    format: GenerateFormat,
}

/// True when a regular-file stdout is readable by group or other users.
fn loose_regular_stdout(is_regular_file: bool, mode: u32) -> bool {
    is_regular_file && mode & 0o077 != 0
}

/// Refuses a loose regular-file stdout before the secret is rendered.
fn check_stdout_mode() -> Result<()> {
    let metadata = std::fs::metadata("/proc/self/fd/1")
        .context("could not inspect stdout; use umask 077 and redirect to a mode 0600 file")?;
    if loose_regular_stdout(metadata.file_type().is_file(), metadata.mode()) {
        bail!(
            "refusing to write a secret to stdout: the regular file has group or other \
             permissions; use `(umask 077; beam generate ... > identity.txt)` so the file is 0600"
        );
    }
    Ok(())
}

/// Generates the identity and writes it to standard output.
pub fn run(args: &GenerateArgs) -> Result<()> {
    check_stdout_mode()?;
    let keys = RealityKeyPair::generate()?;
    let user_id = generate_uuid()?;
    let short_id = generate_short_id()?;
    let public_key = keys.public_key();
    let private_key = keys.private_key();
    let link = client_link(&ClientLink {
        user_id,
        host: &args.host,
        port: args.port,
        server_name: &args.sni,
        public_key: &public_key,
        short_id: &short_id,
        remark: &args.remark,
    });

    let rendered = render_with_format(
        args.format,
        &user_id.to_string(),
        private_key.as_str(),
        &short_id,
        &args.sni,
        &link,
    );
    // Propagate a closed or full stdout as an error instead of panicking.
    std::io::stdout().lock().write_all(rendered.as_bytes())?;
    // A closed or full stderr must not panic after the identity is emitted.
    if args.format != GenerateFormat::ClientLink {
        let _ = std::io::stderr().write_all(
            b"warning: this output contains the REALITY private key; set umask 077, \
              keep the config mode 0600, and never commit or paste it\n",
        );
    }
    if args.sni.bytes().any(|byte| byte.is_ascii_uppercase()) {
        let _ = std::io::stderr().write_all(
            b"note: REALITY compares SNI case-sensitively; keep the exact spelling in \
              both server_names and client configuration (lowercase is recommended)\n",
        );
    }
    Ok(())
}

/// True when `value` consists solely of non-empty ASCII-digit labels separated
/// by dots, such as `203.0.113.999` or `192.168.1`, which is almost certainly a
/// mistyped IPv4 address rather than a DNS name.
fn looks_like_malformed_ipv4(value: &str) -> bool {
    value.contains('.')
        && value
            .split('.')
            .all(|label| !label.is_empty() && label.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Accepts a DNS name or an IP literal, and returns it in link form.
///
/// An IPv6 literal may be bracketed on input; the link renderer adds exactly
/// one pair of brackets. A value with a scheme, path, or `host:port` is
/// rejected instead of producing a link the client cannot parse.
fn parse_host(value: &str) -> Result<String, String> {
    if let Some(inner) = value.strip_prefix('[') {
        let Some(inner) = inner.strip_suffix(']') else {
            return Err(HOST_HINT.to_owned());
        };
        return match inner.parse::<std::net::Ipv6Addr>() {
            Ok(address) if IpAddr::V6(address).to_canonical().is_unspecified() => {
                Err("host must be an address a client can reach, not 0.0.0.0 or ::".to_owned())
            }
            Ok(address) => Ok(address.to_string()),
            Err(_) => Err(HOST_HINT.to_owned()),
        };
    }

    if let Ok(address) = value.parse::<IpAddr>() {
        if address.to_canonical().is_unspecified() {
            return Err("host must be an address a client can reach, not 0.0.0.0 or ::".to_owned());
        }
        return Ok(address.to_string());
    }

    if looks_like_malformed_ipv4(value) {
        return Err(
            "host looks like a malformed IPv4 address; use four 0..=255 octets \
             (for example 203.0.113.10) or a DNS name"
                .to_owned(),
        );
    }

    if is_plausible_dns_name(value) {
        return Ok(value.to_owned());
    }
    Err(HOST_HINT.to_owned())
}

/// Accepts the same DNS names as `reality.server_names`.
fn parse_server_name(value: &str) -> Result<String, String> {
    if value.parse::<IpAddr>().is_ok()
        || value
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .is_some_and(|inner| inner.parse::<std::net::Ipv6Addr>().is_ok())
    {
        return Err(
            "sni must be a DNS hostname, not an IP literal (TLS SNI does not carry IP addresses)"
                .to_owned(),
        );
    }
    if is_plausible_dns_name(value) {
        Ok(value.to_owned())
    } else {
        Err(
            "sni must be a DNS name such as whatsapp.net, without a scheme, port, or path"
                .to_owned(),
        )
    }
}

/// Formats the standalone server TOML fragment (`[user]` and `[reality]`).
fn render_server_toml(
    user_id: &str,
    private_key: &str,
    short_id: &str,
    server_name: &str,
) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "# Generated identity. Keep it secret and never commit it.\n\
         \n[user]\n\
         id = \"{user_id}\"\n\
         flow = \"xtls-rprx-vision\"\n\
         \n[reality]\n\
         private_key = \"{private_key}\"\n\
         short_ids = [\"{short_id}\"]\n\
         server_names = [\"{server_name}\"]\n\
         # Cover: set reality.dest to a host:port whose certificate is valid for\n\
         # {server_name} (for example \"{server_name}:443\"), not an unrelated sample dest.\n"
    ))
}

/// Formats the server configuration fragment and/or the client link according
/// to `format`.
fn render_with_format(
    format: GenerateFormat,
    user_id: &str,
    private_key: &str,
    short_id: &str,
    server_name: &str,
    link: &str,
) -> Zeroizing<String> {
    match format {
        GenerateFormat::All => {
            let server_toml = render_server_toml(user_id, private_key, short_id, server_name);
            Zeroizing::new(format!(
                "{SERVER_CONFIG_BEGIN}\n\
                 {server}\
                 {SERVER_CONFIG_END}\n\
                 \n# Xray-compatible client link, public key only:\n\
                 {link}\n",
                server = server_toml.as_str()
            ))
        }
        GenerateFormat::ServerToml => {
            render_server_toml(user_id, private_key, short_id, server_name)
        }
        GenerateFormat::ClientLink => Zeroizing::new(format!("{link}\n")),
    }
}

/// Formats the default combined output (server fragment + client link).
#[cfg(test)]
fn render(
    user_id: &str,
    private_key: &str,
    short_id: &str,
    server_name: &str,
    link: &str,
) -> Zeroizing<String> {
    render_with_format(
        GenerateFormat::All,
        user_id,
        private_key,
        short_id,
        server_name,
        link,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loose_regular_stdout_checks_only_group_and_other_bits() {
        assert!(loose_regular_stdout(true, 0o644));
        assert!(loose_regular_stdout(true, 0o100_644));
        assert!(!loose_regular_stdout(true, 0o600));
        assert!(!loose_regular_stdout(true, 0o100_600));
        assert!(!loose_regular_stdout(false, 0o010_644)); // pipe
        assert!(!loose_regular_stdout(false, 0o020_666)); // terminal
    }

    fn generate() -> (RealityKeyPair, String, String, String) {
        let keys = RealityKeyPair::generate().expect("keypair generation");
        let user_id = generate_uuid().expect("uuid generation").to_string();
        let short_id = generate_short_id().expect("short id generation");
        let public_key = keys.public_key();
        (keys, user_id, short_id, public_key)
    }

    #[test]
    fn render_keeps_the_private_key_out_of_the_link() {
        let (keys, user_id, short_id, public_key) = generate();
        let private_key = keys.private_key();
        let link = client_link(&ClientLink {
            user_id: user_id.parse().expect("generated uuid parses"),
            host: "203.0.113.10",
            port: 443,
            server_name: "whatsapp.net",
            public_key: &public_key,
            short_id: &short_id,
            remark: "beam",
        });

        let output = render(
            &user_id,
            private_key.as_str(),
            &short_id,
            "whatsapp.net",
            &link,
        );

        assert!(!link.contains(private_key.as_str()));
        assert!(link.contains(&format!("pbk={public_key}")));
        assert!(link.contains(&format!("sid={short_id}")));
        assert_eq!(output.matches(private_key.as_str()).count(), 1);
        assert!(output.contains(&format!("id = \"{user_id}\"")));
        assert!(output.contains(&format!("short_ids = [\"{short_id}\"]")));
        assert!(output.contains("server_names = [\"whatsapp.net\"]"));
        assert!(output.ends_with(&format!("{link}\n")));
    }

    #[test]
    fn render_explains_the_cover_destination_for_the_sni() {
        let output = render(
            "00000000-0000-0000-0000-000000000000",
            "synthetic-key",
            "0123456789abcdef",
            "cover.example",
            "vless://synthetic",
        );

        assert!(output.contains("reality.dest"), "{}", output.as_str());
        assert!(
            output.contains("certificate is valid for"),
            "{}",
            output.as_str()
        );
        assert!(output.contains("cover.example:443"), "{}", output.as_str());
        assert!(
            output.contains("not an unrelated sample dest"),
            "{}",
            output.as_str()
        );
    }

    #[test]
    fn generate_args_require_the_client_endpoint() {
        use clap::Parser;

        #[derive(Debug, Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: GenerateArgs,
        }

        let args = Wrapper::parse_from(["test", "--host", "203.0.113.10", "--sni", "whatsapp.net"]);
        assert_eq!(args.args.host, "203.0.113.10");
        assert_eq!(args.args.port, 443);
        assert_eq!(args.args.sni, "whatsapp.net");
        assert_eq!(args.args.remark, "beam");

        assert!(
            Wrapper::try_parse_from(["test", "--host", "203.0.113.10"]).is_err(),
            "--sni is required"
        );
        assert!(
            Wrapper::try_parse_from(["test", "--sni", "whatsapp.net"]).is_err(),
            "--host is required"
        );
    }

    #[test]
    fn generate_args_reject_values_that_would_break_the_link() {
        use clap::Parser;

        #[derive(Debug, Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: GenerateArgs,
        }

        let invalid: &[(&str, &[&str])] = &[
            (
                "empty host",
                &["test", "--host", "", "--sni", "whatsapp.net"],
            ),
            (
                "host with a scheme",
                &[
                    "test",
                    "--host",
                    "https://example.com",
                    "--sni",
                    "whatsapp.net",
                ],
            ),
            (
                "host with a port",
                &[
                    "test",
                    "--host",
                    "example.com:8443",
                    "--sni",
                    "whatsapp.net",
                ],
            ),
            (
                "bracketed IPv4",
                &["test", "--host", "[203.0.113.10]", "--sni", "whatsapp.net"],
            ),
            (
                "unspecified IPv4",
                &["test", "--host", "0.0.0.0", "--sni", "whatsapp.net"],
            ),
            (
                "unspecified IPv6",
                &["test", "--host", "::", "--sni", "whatsapp.net"],
            ),
            (
                "bracketed unspecified IPv6",
                &["test", "--host", "[::]", "--sni", "whatsapp.net"],
            ),
            (
                "IPv4-mapped wildcard",
                &["test", "--host", "::ffff:0.0.0.0", "--sni", "whatsapp.net"],
            ),
            (
                "bracketed IPv4-mapped wildcard",
                &[
                    "test",
                    "--host",
                    "[::ffff:0.0.0.0]",
                    "--sni",
                    "whatsapp.net",
                ],
            ),
            (
                "empty sni",
                &["test", "--host", "203.0.113.10", "--sni", ""],
            ),
            (
                "sni with a scheme",
                &[
                    "test",
                    "--host",
                    "203.0.113.10",
                    "--sni",
                    "https://whatsapp.net",
                ],
            ),
            (
                "sni with a port",
                &[
                    "test",
                    "--host",
                    "203.0.113.10",
                    "--sni",
                    "whatsapp.net:443",
                ],
            ),
            (
                "port zero",
                &[
                    "test",
                    "--host",
                    "203.0.113.10",
                    "--sni",
                    "whatsapp.net",
                    "--port",
                    "0",
                ],
            ),
        ];

        for (label, argv) in invalid {
            assert!(
                Wrapper::try_parse_from(argv.iter().copied()).is_err(),
                "{label} must be rejected"
            );
        }
    }

    #[test]
    fn generate_args_canonicalize_ipv6_hosts() {
        use clap::Parser;

        #[derive(Debug, Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: GenerateArgs,
        }

        for host in ["2001:0DB8::1", "[2001:0DB8::1]"] {
            let args = Wrapper::try_parse_from(["test", "--host", host, "--sni", "whatsapp.net"])
                .expect("IPv6 host must parse");
            assert_eq!(args.args.host, "2001:db8::1");
        }
    }

    #[test]
    fn parse_server_name_rejects_ip_literals() {
        for literal in ["203.0.113.10", "127.0.0.1", "2001:db8::1", "[2001:db8::1]"] {
            let error = parse_server_name(literal).expect_err("IP literal must be rejected as SNI");
            assert!(
                error.contains("not an IP literal"),
                "unexpected error for {literal}: {error}"
            );
        }
        assert_eq!(
            parse_server_name("123.example.com").unwrap(),
            "123.example.com"
        );
    }

    #[test]
    fn parse_host_rejects_malformed_ipv4_literals_with_guidance() {
        for bad in ["203.0.113.999", "192.168.1", "1.2.3.4.5", "999.999.999.999"] {
            let error = parse_host(bad).expect_err("malformed IPv4-like host must be rejected");
            assert!(
                error.contains("malformed IPv4"),
                "unexpected error for {bad}: {error}"
            );
        }
        assert_eq!(parse_host("203.0.113.10").unwrap(), "203.0.113.10");
        assert_eq!(parse_host("123.example.com").unwrap(), "123.example.com");
        assert_eq!(
            parse_host("server1.example.com").unwrap(),
            "server1.example.com"
        );
        assert_eq!(parse_host("node.123").unwrap(), "node.123");
    }

    #[test]
    fn render_formats_support_delimited_server_toml_and_client_link_modes() {
        let (keys, user_id, short_id, public_key) = generate();
        let private_key = keys.private_key();
        let link = client_link(&ClientLink {
            user_id: user_id.parse().expect("generated uuid parses"),
            host: "203.0.113.10",
            port: 443,
            server_name: "example.com",
            public_key: &public_key,
            short_id: &short_id,
            remark: "beam",
        });

        let all = render_with_format(
            GenerateFormat::All,
            &user_id,
            private_key.as_str(),
            &short_id,
            "example.com",
            &link,
        );
        let begin = all
            .find(SERVER_CONFIG_BEGIN)
            .expect("missing server config begin marker");
        let end = all
            .find(SERVER_CONFIG_END)
            .expect("missing server config end marker");
        assert!(begin < end);
        let extracted = &all[begin + SERVER_CONFIG_BEGIN.len()..end];

        let server_only = render_with_format(
            GenerateFormat::ServerToml,
            &user_id,
            private_key.as_str(),
            &short_id,
            "example.com",
            &link,
        );
        assert_eq!(extracted.trim(), server_only.trim());
        assert!(!server_only.contains("vless://"));
        assert!(server_only.contains("[user]"));
        assert!(server_only.contains("[reality]"));

        // Verify the extracted server-only fragment parses as valid TOML when
        // combined with the remaining required sections.
        let full_toml = format!(
            "[server]\nlisten = \"127.0.0.1:443\"\n\n\
             {server}\n\
             dest = \"example.com:443\"\n\n\
             [log]\nlevel = \"warn\"\n\n\
             [limits]\n\
             max_connections = 64\n\
             max_udp_destinations = 64\n\
             max_preauth_per_ip = 16\n\
             max_xudp_sessions = 64\n\
             xudp_recv_buffer_bytes = 65536\n\
             listen_backlog = 128\n\
             shutdown_drain_ms = 1000\n\
             handshake_timeout_ms = 5000\n\
             idle_timeout_ms = 10000\n",
            server = server_only.as_str()
        );
        let parsed = beam_core::config::Config::from_toml_str(&full_toml)
            .expect("server-toml fragment must form a valid config");
        assert_eq!(parsed.user.id.to_string(), user_id);
        assert_eq!(parsed.reality.server_names, vec!["example.com"]);

        let link_only = render_with_format(
            GenerateFormat::ClientLink,
            &user_id,
            private_key.as_str(),
            &short_id,
            "example.com",
            &link,
        );
        assert_eq!(link_only.as_str(), format!("{link}\n"));
        assert!(!link_only.contains(private_key.as_str()));
    }

    #[test]
    fn generate_args_accept_format_flag() {
        use clap::Parser;

        #[derive(Debug, Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: GenerateArgs,
        }

        let default_args =
            Wrapper::parse_from(["test", "--host", "203.0.113.10", "--sni", "example.com"]);
        assert_eq!(default_args.args.format, GenerateFormat::All);

        let server_args = Wrapper::parse_from([
            "test",
            "--host",
            "203.0.113.10",
            "--sni",
            "example.com",
            "--format",
            "server-toml",
        ]);
        assert_eq!(server_args.args.format, GenerateFormat::ServerToml);

        let link_args = Wrapper::parse_from([
            "test",
            "--host",
            "203.0.113.10",
            "--sni",
            "example.com",
            "--format",
            "client-link",
        ]);
        assert_eq!(link_args.args.format, GenerateFormat::ClientLink);
    }
}
