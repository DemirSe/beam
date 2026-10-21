//! Regression test for a ClientHello captured from stock Xray v26.3.27.
//!
//! The fixture was captured with only test credentials: the loopback Xray
//! client used the test REALITY keypair, shortId `0123456789abcdef`, and SNI
//! `whatsapp.net`. A local TCP proxy saved the first complete TLS record.

use beam_core::tls::ClientHello;

const STOCK_CLIENT_HELLO: &[u8] = include_bytes!("fixtures/stock-client-hello.bin");

#[test]
fn parses_stock_xray_client_hello() {
    let hello = ClientHello::parse(STOCK_CLIENT_HELLO).expect("stock Xray ClientHello must parse");

    assert_eq!(hello.server_name, Some("whatsapp.net"));
    assert_eq!(
        hello.session_id.len(),
        32,
        "REALITY carries its authentication envelope in a 32-byte session id"
    );
    assert!(hello.supports_tls13());
    assert!(
        hello.has_key_share_group(0x001d),
        "stock client must advertise an X25519 key share"
    );

    let shares = hello.key_shares.as_ref().expect("key_share extension");
    let x25519 = shares.get(0x001d).expect("X25519 key exchange");
    assert_eq!(
        x25519.len(),
        32,
        "X25519 key exchange must be exactly 32 bytes"
    );

    assert_eq!(hello.raw_record, STOCK_CLIENT_HELLO);
}
