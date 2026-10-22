//! Minimal local HTTP/3 origin for the full-TUN harness.
//!
//! The server listens on one UDP address, generates a fresh self-signed
//! certificate in memory, and answers every request with HTTP 200 and the
//! marker `beam-tun-h3-ok\n`, repeated up to `H3_BODY_BYTES` when set. It never
//! talks to an external network.
//!
//! This binary is test-only and deliberately lives outside the beam workspace.

use std::{env, net::SocketAddr, process::ExitCode, sync::Arc};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http::{Response, StatusCode};
use quinn::crypto::rustls::QuicServerConfig;
use quinn::rustls;
use quinn::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

const MARKER: &[u8] = b"beam-tun-h3-ok\n";

/// Returns the response body size. The default is the historical marker-only
/// body; a larger value exercises QUIC/XUDP flow control and backpressure.
fn body_len() -> Result<usize> {
    let Some(raw) = env::var_os("H3_BODY_BYTES") else {
        return Ok(MARKER.len());
    };
    let raw = raw.to_str().context("H3_BODY_BYTES must be valid UTF-8")?;
    let len: usize = raw
        .parse()
        .with_context(|| format!("invalid H3_BODY_BYTES: {raw}"))?;
    if !(MARKER.len()..=16 * 1024 * 1024).contains(&len) {
        bail!(
            "H3_BODY_BYTES must be between {} and 16777216",
            MARKER.len()
        );
    }
    Ok(len)
}

fn listen_addr() -> Result<SocketAddr> {
    let mut args = env::args().skip(1);
    let mut listen = "10.10.2.2:4443".to_string();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen = args
                    .next()
                    .context("--listen requires an address, for example 10.10.2.2:4443")?;
            }
            "-h" | "--help" => {
                println!("usage: h3-origin [--listen ADDR]");
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    listen
        .parse()
        .with_context(|| format!("invalid listen address: {listen}"))
}

fn tls_config() -> Result<rustls::ServerConfig> {
    // A fresh self-signed certificate is generated on every run; no private
    // key is ever written to disk or committed.
    let certified = rcgen::generate_simple_self_signed(vec![
        "localhost".to_string(),
        "10.10.2.2".to_string(),
        "fd00:2::2".to_string(),
    ])
    .context("could not generate the self-signed certificate")?;
    let certificate = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        certified.signing_key.serialize_der(),
    ));

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)
        .context("could not build the rustls server config")?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    Ok(tls)
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("h3-origin: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let addr = listen_addr()?;
    let crypto = QuicServerConfig::try_from(tls_config()?)
        .context("could not create the QUIC server crypto config")?;
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = quinn::Endpoint::server(server_config, addr)
        .with_context(|| format!("could not bind HTTP/3 origin on {addr}"))?;
    eprintln!("h3-origin: READY on {addr} (HTTP/3, self-signed certificate)");

    while let Some(incoming) = endpoint.accept().await {
        tokio::spawn(async move {
            match incoming.await {
                Ok(connection) => {
                    let peer = connection.remote_address();
                    eprintln!("h3-origin: QUIC connection from {peer}");
                    if let Err(error) = serve_connection(connection).await {
                        eprintln!("h3-origin: connection from {peer} ended: {error:#}");
                    }
                }
                Err(error) => eprintln!("h3-origin: QUIC handshake failed: {error}"),
            }
        });
    }
    Ok(())
}

async fn serve_connection(connection: quinn::Connection) -> Result<()> {
    let mut h3 = h3::server::Connection::<h3_quinn::Connection, Bytes>::new(
        h3_quinn::Connection::new(connection),
    )
    .await
    .context("could not start the HTTP/3 connection")?;

    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                tokio::spawn(async move {
                    if let Err(error) = serve_request(resolver).await {
                        eprintln!("h3-origin: request failed: {error:#}");
                    }
                });
            }
            Ok(None) => return Ok(()),
            Err(error) => {
                eprintln!("h3-origin: HTTP/3 connection ended: {error}");
                return Ok(());
            }
        }
    }
}

async fn serve_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
) -> Result<()> {
    let (request, mut stream) = resolver
        .resolve_request()
        .await
        .context("could not read the request headers")?;
    let len = body_len()?;
    let mut body = Vec::with_capacity(len);
    while body.len() < len {
        body.extend_from_slice(MARKER);
    }
    body.truncate(len);
    let body = Bytes::from(body);
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain")
        .header("content-length", body.len())
        .body(())
        .context("could not build the response")?;

    stream
        .send_response(response)
        .await
        .context("could not send the response headers")?;
    // Send bounded chunks so the h3 layer can apply QUIC stream flow control.
    // A single multi-megabyte `send_data` is not a valid large-body test: it
    // makes the origin reset the stream before the tunnel is exercised.
    const CHUNK: usize = 1024;
    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + CHUNK).min(body.len());
        stream
            .send_data(body.slice(offset..end))
            .await
            .context("could not send the response body")?;
        offset = end;
    }
    stream
        .finish()
        .await
        .context("could not finish the stream")?;
    eprintln!(
        "h3-origin: {} {} -> 200 {} bytes",
        request.method(),
        request.uri(),
        len
    );
    Ok(())
}
