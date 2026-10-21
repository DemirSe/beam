//! VLESS request and response headers.
//!
//! The codec is bounded and zero-copy: addons and the trailing request body
//! borrow the input buffer. The only allocation is the destination domain name,
//! which is limited to 255 bytes by the on-wire length.

pub mod header;

pub use header::{
    Addons, Command, MAX_ADDONS_LEN, MAX_REQUEST_HEADER_LEN, RequestHeader, ResponseHeader,
    VISION_ADDONS, VISION_ADDONS_LEN, VISION_FLOW, VLESS_VERSION, VlessError, encode_response,
};
