#![no_main]

use beam_core::tls::ClientHello;
use beam_core::tls::server::fuzz_client_hello_assembler;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ClientHello::parse(data);
    fuzz_client_hello_assembler(data);
});
