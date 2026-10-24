//! Pure XTLS Vision padding and mode-transition state.
//!
//! This module does not own a socket or a TLS stream. It turns plaintext
//! buffers into [`VisionBlockPlan`]s and parsed [`Block`] commands into reader
//! transitions. The relay is responsible for encoding the blocks, writing the
//! padding, and moving bytes between the outer TLS stream and the raw socket.
//!
//! One [`TlsDetector`] belongs to a connection, not to a direction. On a server
//! the downlink writer owns it; inbound plaintext is fed to
//! [`VisionWriterState::inspect`] so both directions share the eight-buffer
//! filter budget described in `docs/08-vision-xudp-spec.md` section 2.3.
//!
//! ServerHellos may span inspected buffers: the detector keeps a bounded copy
//! of the current record and parses it once complete. A malformed or oversized
//! record can only fall back to End, which keeps the stream inside the outer
//! transport.

use std::fmt;

use rand::{Rng, RngExt};

use super::frame::{Block, Command, MAX_PAYLOAD_LEN};

/// Default number of buffers inspected by [`TlsDetector`].
pub const DEFAULT_FILTER_BUDGET: u8 = 8;

const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const SERVER_HELLO_PREFIX_LEN: usize = 43;
const MIN_SERVER_HELLO_LEN: usize = 79;
const MAX_SESSION_ID_LEN: usize = 32;

/// Largest plaintext TLS record (RFC 8446, 2^14) plus its record header.
const MAX_TLS_RECORD_LEN: usize = 16_384 + TLS_RECORD_HEADER_LEN;

const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

const TLS_CLIENT_HELLO_START: &[u8] = &[0x16, 0x03];
const TLS_SERVER_HELLO_START: &[u8] = &[0x16, 0x03, 0x03];
const TLS_APPLICATION_DATA_START: &[u8] = &[0x17, 0x03, 0x03];

const SUPPORTED_VERSIONS_EXTENSION: u16 = 0x002b;
const TLS13_SUPPORTED_VERSION: [u8; 2] = [0x03, 0x04];

const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

/// What a single inspected plaintext buffer looked like.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TlsObservation {
    /// The buffer starts with a TLS ClientHello record.
    pub client_hello: bool,
    /// The buffer starts with a TLS ServerHello record.
    pub server_hello: bool,
    /// The buffer starts with a TLS application-data record.
    pub application_data: bool,
}

impl TlsObservation {
    /// Returns `true` when no TLS signature was recognized.
    pub const fn is_empty(self) -> bool {
        !(self.client_hello || self.server_hello || self.application_data)
    }
}

/// Shared TLS detector for both directions of one Vision connection.
///
/// The detector consumes the eight-buffer filter budget even for buffers that
/// contain no TLS signature, matching the stock writer. Once the budget is
/// exhausted, further calls are cheap no-ops.
#[derive(PartialEq, Eq)]
pub struct TlsDetector {
    filter_budget: u8,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher: Option<u16>,
    /// A ServerHello record split across inspected buffers. The buffer is
    /// capped at [`MAX_TLS_RECORD_LEN`].
    pending_server_hello: Option<Vec<u8>>,
    pending_server_hello_len: usize,
}

// The pending ServerHello is traffic bytes; show only its length.
impl fmt::Debug for TlsDetector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsDetector")
            .field("filter_budget", &self.filter_budget)
            .field("is_tls", &self.is_tls)
            .field("is_tls12_or_above", &self.is_tls12_or_above)
            .field("enable_xtls", &self.enable_xtls)
            .field("cipher", &self.cipher)
            .field(
                "pending_server_hello_len",
                &self.pending_server_hello.as_ref().map(Vec::len),
            )
            .finish()
    }
}

impl Default for TlsDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsDetector {
    /// Creates a detector with the stock eight-buffer budget.
    pub const fn new() -> Self {
        Self {
            filter_budget: DEFAULT_FILTER_BUDGET,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: None,
            pending_server_hello: None,
            pending_server_hello_len: 0,
        }
    }

    /// Creates a detector with an explicit filter budget.
    ///
    /// A zero budget disables inspection. This is mainly useful for tests and
    /// for reproducing a connection that already exhausted its budget.
    pub const fn with_filter_budget(filter_budget: u8) -> Self {
        Self {
            filter_budget,
            is_tls: false,
            is_tls12_or_above: false,
            enable_xtls: false,
            cipher: None,
            pending_server_hello: None,
            pending_server_hello_len: 0,
        }
    }

    /// Returns the number of buffers that may still be inspected.
    pub const fn filter_budget(&self) -> u8 {
        self.filter_budget
    }

    /// Returns `true` after a ClientHello or ServerHello was seen.
    pub const fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// Returns `true` after a ServerHello was seen.
    pub const fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    /// Returns `true` when Direct mode is safe for this connection.
    pub const fn enable_xtls(&self) -> bool {
        self.enable_xtls
    }

    /// Returns the ServerHello cipher suite, if one was parsed.
    pub const fn cipher(&self) -> Option<u16> {
        self.cipher
    }

    /// Inspects one plaintext buffer and updates the shared detection state.
    ///
    /// The function never panics and never reads outside `buffer`. A malformed
    /// record simply does not contribute a signature; a malformed ServerHello
    /// cannot enable Direct.
    pub fn inspect(&mut self, buffer: &[u8]) -> TlsObservation {
        let mut observation = TlsObservation::default();
        if self.filter_budget == 0 {
            self.pending_server_hello = None;
            self.pending_server_hello_len = 0;
            return observation;
        }
        self.filter_budget -= 1;

        if self.pending_server_hello.is_some() {
            self.continue_server_hello(buffer);
            return observation;
        }

        if buffer.starts_with(TLS_APPLICATION_DATA_START) {
            observation.application_data = true;
        }

        let Some(header) = buffer.get(..6) else {
            return observation;
        };

        if header.starts_with(TLS_SERVER_HELLO_START) && header[5] == HANDSHAKE_SERVER_HELLO {
            observation.server_hello = true;
            self.is_tls = true;
            self.is_tls12_or_above = true;

            let record_len =
                usize::from(u16::from_be_bytes([header[3], header[4]])) + TLS_RECORD_HEADER_LEN;
            if record_len < MIN_SERVER_HELLO_LEN {
                // Stock cannot enable Direct from a short ServerHello.
                self.filter_budget = 0;
            } else if buffer.len() >= record_len {
                self.apply_server_hello(buffer);
            } else if record_len <= MAX_TLS_RECORD_LEN {
                self.pending_server_hello = Some(buffer.to_vec());
                self.pending_server_hello_len = record_len;
            } else {
                // A record larger than the TLS plaintext limit is malformed and
                // must not cause unbounded buffering.
                self.filter_budget = 0;
            }
        } else if header.starts_with(TLS_CLIENT_HELLO_START) && header[5] == HANDSHAKE_CLIENT_HELLO
        {
            observation.client_hello = true;
            self.is_tls = true;
        }

        observation
    }

    /// Appends a fragment to the pending ServerHello and parses it when full.
    fn continue_server_hello(&mut self, buffer: &[u8]) {
        let Some(pending) = self.pending_server_hello.as_mut() else {
            return;
        };
        let needed = self.pending_server_hello_len.saturating_sub(pending.len());
        let take = needed.min(buffer.len());
        pending.extend_from_slice(&buffer[..take]);

        if pending.len() < self.pending_server_hello_len {
            return;
        }

        if let Some(record) = self.pending_server_hello.take() {
            self.apply_server_hello(&record);
        }
        self.pending_server_hello_len = 0;
    }

    /// Parses a complete ServerHello and makes the filtering decision final.
    fn apply_server_hello(&mut self, record: &[u8]) {
        if record.len() >= MIN_SERVER_HELLO_LEN
            && let Some(info) = parse_server_hello(record)
        {
            self.cipher = Some(info.cipher);
            if info.supports_tls13
                && is_tls13_cipher(info.cipher)
                && info.cipher != TLS_AES_128_CCM_8_SHA256
            {
                self.enable_xtls = true;
            }
        }

        // A complete ServerHello is conclusive: stock stops filtering even
        // when it turns out to be TLS 1.2 or an unknown cipher.
        self.filter_budget = 0;
    }
}

/// ServerHello fields needed for the Direct decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ServerHelloInfo {
    cipher: u16,
    supports_tls13: bool,
}

/// Parses the fixed ServerHello prefix and its extension block.
///
/// Returns `None` for a truncated or structurally invalid record. The cipher
/// is read from `43 + session_id_len + 1`, as in stock Xray.
fn parse_server_hello(record: &[u8]) -> Option<ServerHelloInfo> {
    let record_len =
        usize::from(u16::from_be_bytes([*record.get(3)?, *record.get(4)?])) + TLS_RECORD_HEADER_LEN;
    let record = record.get(..record_len)?;
    if !record.starts_with(TLS_SERVER_HELLO_START) || *record.get(5)? != HANDSHAKE_SERVER_HELLO {
        return None;
    }

    let handshake_len_bytes = record.get(6..9)?;
    let handshake_len = usize::try_from(u32::from_be_bytes([
        0,
        handshake_len_bytes[0],
        handshake_len_bytes[1],
        handshake_len_bytes[2],
    ]))
    .ok()?;
    if record.len() != TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN + handshake_len {
        return None;
    }

    let body = record.get(TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN..)?;
    let mut cursor =
        body.get(SERVER_HELLO_PREFIX_LEN - TLS_RECORD_HEADER_LEN - TLS_HANDSHAKE_HEADER_LEN..)?;
    let session_id_len = usize::from(*cursor.first()?);
    if session_id_len > MAX_SESSION_ID_LEN {
        return None;
    }
    cursor = cursor.get(1 + session_id_len..)?;
    let cipher = u16::from_be_bytes([*cursor.first()?, *cursor.get(1)?]);
    cursor = cursor.get(2..)?;

    // Compression method.
    cursor = cursor.get(1..)?;

    let supports_tls13 = match cursor.get(..2) {
        Some(length_bytes) => {
            let extension_len = usize::from(u16::from_be_bytes([length_bytes[0], length_bytes[1]]));
            match cursor.get(2..2 + extension_len) {
                Some(extensions) => parse_supported_versions(extensions),
                None => false,
            }
        }
        None => false,
    };

    Some(ServerHelloInfo {
        cipher,
        supports_tls13,
    })
}

/// Searches a well-formed extension block for `supported_versions` = TLS 1.3.
fn parse_supported_versions(mut extensions: &[u8]) -> bool {
    while let Some(header) = extensions.get(..4) {
        let extension_type = u16::from_be_bytes([header[0], header[1]]);
        let extension_len = usize::from(u16::from_be_bytes([header[2], header[3]]));
        let Some(data) = extensions.get(4..4 + extension_len) else {
            return false;
        };
        if extension_type == SUPPORTED_VERSIONS_EXTENSION
            && data == TLS13_SUPPORTED_VERSION.as_slice()
        {
            return true;
        }
        let Some(rest) = extensions.get(4 + extension_len..) else {
            return false;
        };
        extensions = rest;
    }
    false
}

/// Returns `true` for the TLS 1.3 cipher suites known to stock Xray.
const fn is_tls13_cipher(cipher: u16) -> bool {
    matches!(cipher, 0x1301..=0x1305)
}

/// Padding lengths used while Vision framing is active.
///
/// Defaults match stock Xray: `seed = {900, 500, 900, 256}`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaddingPolicy {
    seed: [u32; 4],
}

impl Default for PaddingPolicy {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SEED)
    }
}

impl PaddingPolicy {
    /// Stock padding seed: threshold, long jitter, long base, short jitter.
    pub const DEFAULT_SEED: [u32; 4] = [900, 500, 900, 256];

    /// Creates a policy with an explicit seed.
    ///
    /// Zero jitter bounds are accepted and produce zero jitter, so a malformed
    /// configuration cannot trigger an empty-range panic.
    pub const fn new(seed: [u32; 4]) -> Self {
        Self { seed }
    }

    /// Returns the configured seed.
    pub const fn seed(&self) -> [u32; 4] {
        self.seed
    }

    /// Computes the padding length for one block.
    ///
    /// Long padding applies only when `tls_detected` is true and the content is
    /// shorter than `seed[0]`. Otherwise short padding is used. Both branches
    /// are clamped so content plus padding never exceeds [`MAX_PAYLOAD_LEN`].
    pub fn padding_len<R: Rng + ?Sized>(
        &self,
        content_len: usize,
        tls_detected: bool,
        rng: &mut R,
    ) -> u16 {
        let content = u32::try_from(content_len).unwrap_or(u32::MAX);
        let padding = if tls_detected && content < self.seed[0] {
            let jitter = sample_below(rng, self.seed[1]);
            jitter.saturating_add(self.seed[2]).saturating_sub(content)
        } else {
            sample_below(rng, self.seed[3])
        };

        let max_padding = MAX_PAYLOAD_LEN.saturating_sub(content_len);
        let padding = usize::try_from(padding).unwrap_or(usize::MAX);
        u16::try_from(padding.min(max_padding)).unwrap_or(u16::MAX)
    }
}

/// Returns a uniform value in `0..upper`, or zero for an empty range.
fn sample_below<R: Rng + ?Sized>(rng: &mut R, upper: u32) -> u32 {
    if upper == 0 {
        0
    } else {
        rng.random_range(0..upper)
    }
}

/// One planned Vision block.
///
/// `padding_len` is already clamped. `uuid` is true only for the first block
/// emitted in a direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VisionBlockPlan {
    /// Command to put in the block header.
    pub command: Command,
    /// Zero-padding bytes that follow the content.
    pub padding_len: u16,
    /// Whether the raw UUID prefix precedes the block header.
    pub uuid: bool,
}

/// Result of planning one plaintext write.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VisionWritePlan {
    /// Blocks for `chunks[..raw_from.unwrap_or(chunks.len())]`.
    pub blocks: Vec<VisionBlockPlan>,
    /// Index of the first chunk that must be written raw instead of framed.
    ///
    /// This is set when End is reached before the end of the write, or when the
    /// writer was already past End/Direct. For End the raw bytes still travel
    /// inside the outer transport.
    pub raw_from: Option<usize>,
    /// Stop wrapping later writes in Vision blocks.
    ///
    /// For End the bytes still travel inside the outer transport. For Direct
    /// they use the bypassed raw socket; [`Self::switch_to_direct`]
    /// distinguishes the two.
    pub switch_to_raw: bool,
    /// Switch this direction to the raw socket after this write completes.
    ///
    /// The planned blocks themselves, including the Direct block, still use the
    /// outer TLS/REALITY transport.
    pub switch_to_direct: bool,
}

/// Writer-side Vision state for one direction of one connection.
///
/// The writer owns the connection's [`TlsDetector`]. Feed reader-side plaintext
/// through [`Self::inspect`] or [`Self::detector_mut`] so both directions share
/// the same filter budget and ServerHello result.
#[derive(Debug, PartialEq, Eq)]
pub struct VisionWriterState {
    first_block: bool,
    padding_enabled: bool,
    detector: TlsDetector,
    policy: PaddingPolicy,
}

impl Default for VisionWriterState {
    fn default() -> Self {
        Self::new()
    }
}

impl VisionWriterState {
    /// Creates a writer with the stock detector and padding policy.
    pub fn new() -> Self {
        Self::with_detector(TlsDetector::new(), PaddingPolicy::default())
    }

    /// Creates a writer with a custom padding policy.
    pub fn with_policy(policy: PaddingPolicy) -> Self {
        Self::with_detector(TlsDetector::new(), policy)
    }

    /// Creates a writer with explicit detector and padding state.
    pub fn with_detector(detector: TlsDetector, policy: PaddingPolicy) -> Self {
        Self {
            first_block: true,
            padding_enabled: true,
            detector,
            policy,
        }
    }

    /// Returns the shared TLS detector.
    pub const fn detector(&self) -> &TlsDetector {
        &self.detector
    }

    /// Returns the shared TLS detector mutably.
    ///
    /// Use this for plaintext read from the opposite direction.
    pub const fn detector_mut(&mut self) -> &mut TlsDetector {
        &mut self.detector
    }

    /// Feeds one plaintext buffer from either direction into the detector.
    pub fn inspect(&mut self, buffer: &[u8]) -> TlsObservation {
        self.detector.inspect(buffer)
    }

    /// Returns `true` until the first block of this direction is planned.
    pub const fn first_block(&self) -> bool {
        self.first_block
    }

    /// Returns `false` after End or Direct; later writes are raw.
    pub const fn padding_enabled(&self) -> bool {
        self.padding_enabled
    }

    /// Returns the shared detector's `is_tls` flag.
    pub const fn is_tls(&self) -> bool {
        self.detector.is_tls()
    }

    /// Returns the shared detector's `is_tls12_or_above` flag.
    pub const fn is_tls12_or_above(&self) -> bool {
        self.detector.is_tls12_or_above()
    }

    /// Returns the shared detector's `enable_xtls` flag.
    pub const fn enable_xtls(&self) -> bool {
        self.detector.enable_xtls()
    }

    /// Returns the remaining shared filter budget.
    pub const fn filter_budget(&self) -> u8 {
        self.detector.filter_budget()
    }

    /// Plans the Vision blocks for one plaintext write.
    ///
    /// `chunks` are the writer's plaintext buffers in order. Each returned
    /// block corresponds to one chunk. `complete_app_data_records` must be true
    /// only when the concatenation of `chunks` is one or more complete TLS
    /// records (handshake, change-cipher-spec, alert, or application data) and
    /// nothing else; it is the caller's complete-record check.
    ///
    /// The first block of the direction carries the UUID. A write that triggers
    /// Direct puts Direct on its last block and Continue on earlier blocks.
    /// Without XTLS, the first complete application-data write ends padding with
    /// End and later writes are raw inside the outer transport.
    pub fn plan_write<R: Rng + ?Sized>(
        &mut self,
        chunks: &[&[u8]],
        complete_app_data_records: bool,
        rng: &mut R,
    ) -> VisionWritePlan {
        let mut plan = VisionWritePlan::default();
        if chunks.is_empty() {
            return plan;
        }
        if !self.padding_enabled {
            plan.raw_from = Some(0);
            plan.switch_to_raw = true;
            return plan;
        }
        plan.blocks.reserve(chunks.len());

        // Inspect the whole write before shaping it, like the stock writer.
        // Remember which buffer consumed the last filter credit so End lands on
        // the eighth inspected buffer rather than on the first one.
        let budget_at_entry = self.detector.filter_budget();
        let mut budget_end = if budget_at_entry == 0 { Some(0) } else { None };
        for (index, chunk) in chunks.iter().enumerate() {
            self.detector.inspect(chunk);
            if budget_at_entry > 0 && self.detector.filter_budget() == 0 && budget_end.is_none() {
                budget_end = Some(index);
            }
        }
        if self.detector.is_tls12_or_above() {
            budget_end = None;
        }

        let has_app_data = chunks
            .iter()
            .any(|chunk| chunk.starts_with(TLS_APPLICATION_DATA_START));

        if complete_app_data_records && self.detector.enable_xtls() && has_app_data {
            let last = chunks.len().saturating_sub(1);
            for (index, chunk) in chunks.iter().enumerate() {
                plan.blocks.push(VisionBlockPlan {
                    command: if index == last {
                        Command::Direct
                    } else {
                        Command::Continue
                    },
                    // The triggering write still uses the normal padding rule;
                    // long padding stops after it.
                    padding_len: self
                        .policy
                        .padding_len(chunk.len(), self.detector.is_tls(), rng),
                    uuid: self.first_block && index == 0,
                });
            }
            self.first_block = false;
            self.padding_enabled = false;
            plan.switch_to_raw = true;
            plan.switch_to_direct = true;
            return plan;
        }

        if complete_app_data_records
            && self.detector.is_tls()
            && has_app_data
            && let Some(end_index) = chunks
                .iter()
                .position(|chunk| chunk.starts_with(TLS_APPLICATION_DATA_START))
        {
            for (index, chunk) in chunks.iter().enumerate().take(end_index + 1) {
                plan.blocks.push(VisionBlockPlan {
                    command: if index == end_index {
                        Command::End
                    } else {
                        Command::Continue
                    },
                    // Handshake records and the triggering End block use the
                    // normal padding rule; later writes are raw.
                    padding_len: self
                        .policy
                        .padding_len(chunk.len(), self.detector.is_tls(), rng),
                    uuid: self.first_block && index == 0,
                });
            }
            self.first_block = false;
            self.padding_enabled = false;
            plan.switch_to_raw = true;
            if end_index + 1 < chunks.len() {
                plan.raw_from = Some(end_index + 1);
            }
            return plan;
        }

        let last_framed = budget_end.unwrap_or(chunks.len().saturating_sub(1));
        for (index, chunk) in chunks.iter().enumerate().take(last_framed + 1) {
            plan.blocks.push(VisionBlockPlan {
                command: if budget_end == Some(index) {
                    Command::End
                } else {
                    Command::Continue
                },
                padding_len: self
                    .policy
                    .padding_len(chunk.len(), self.detector.is_tls(), rng),
                uuid: self.first_block && index == 0,
            });
        }
        self.first_block = false;
        if let Some(end_index) = budget_end {
            self.padding_enabled = false;
            plan.switch_to_raw = true;
            if end_index + 1 < chunks.len() {
                plan.raw_from = Some(end_index + 1);
            }
        }
        plan
    }
}

/// Reader framing mode for one direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum VisionReaderMode {
    /// Vision blocks are expected.
    #[default]
    Framed,
    /// End was received; later bytes are raw inside the outer transport.
    Ended,
    /// Direct was received; later bytes bypass the outer transport.
    Direct,
}

/// Action the relay must take after a parsed Vision block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VisionReaderAction {
    /// Parse the next Vision block.
    Continue,
    /// Stop Vision framing and forward the rest of the current chunk raw
    /// inside the outer transport.
    End,
    /// Stop Vision framing, forward the rest of the current chunk and any
    /// outer-TLS read-ahead, then read the raw connection.
    Direct,
}

impl VisionReaderAction {
    /// Returns the wire command that produced this action.
    pub const fn command(self) -> Command {
        match self {
            Self::Continue => Command::Continue,
            Self::End => Command::End,
            Self::Direct => Command::Direct,
        }
    }

    /// Returns `true` when bytes after the block are not Vision-framed.
    pub const fn forwards_remainder(self) -> bool {
        matches!(self, Self::End | Self::Direct)
    }

    /// Returns `true` when outer-TLS read-ahead must be replayed before raw
    /// reads.
    pub const fn forwards_tls_read_ahead(self) -> bool {
        matches!(self, Self::Direct)
    }
}

/// Reader-side Vision state for one direction of one connection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VisionReaderState {
    mode: VisionReaderMode,
}

impl VisionReaderState {
    /// Creates a reader that expects Vision blocks.
    pub const fn new() -> Self {
        Self {
            mode: VisionReaderMode::Framed,
        }
    }

    /// Returns the current framing mode.
    pub const fn mode(&self) -> VisionReaderMode {
        self.mode
    }

    /// Returns `true` while Vision blocks are expected.
    pub const fn is_framed(&self) -> bool {
        matches!(self.mode, VisionReaderMode::Framed)
    }

    /// Returns `true` after End or Direct.
    pub const fn is_finished(&self) -> bool {
        !self.is_framed()
    }

    /// Returns `true` when bytes after the last block are raw inside the outer
    /// transport.
    pub const fn forwards_remainder(&self) -> bool {
        !self.is_framed()
    }

    /// Returns `true` when the caller must drain outer-TLS read-ahead before
    /// reading the raw connection.
    pub const fn forwards_tls_read_ahead(&self) -> bool {
        matches!(self.mode, VisionReaderMode::Direct)
    }

    /// Consumes one parsed block command.
    ///
    /// Continue leaves the reader framed. End and Direct finish the direction;
    /// any later Vision block is rejected because no Vision bytes may follow
    /// them.
    pub fn on_block(&mut self, block: &Block<'_>) -> Result<VisionReaderAction, VisionStateError> {
        self.on_command(block.command)
    }

    /// Consumes one command byte value decoded as [`Command`].
    pub fn on_command(&mut self, command: Command) -> Result<VisionReaderAction, VisionStateError> {
        if !self.is_framed() {
            return Err(VisionStateError::BlockAfterEnd { mode: self.mode });
        }

        let action = match command {
            Command::Continue => VisionReaderAction::Continue,
            Command::End => {
                self.mode = VisionReaderMode::Ended;
                VisionReaderAction::End
            }
            Command::Direct => {
                self.mode = VisionReaderMode::Direct;
                VisionReaderAction::Direct
            }
        };
        Ok(action)
    }
}

/// Errors produced by the pure Vision state machines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum VisionStateError {
    /// A block arrived after End or Direct in the same direction.
    #[error("Vision block received after framing stopped in {mode:?} mode")]
    BlockAfterEnd {
        /// The mode that rejected the block.
        mode: VisionReaderMode,
    },
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::{
        DEFAULT_FILTER_BUDGET, PaddingPolicy, TlsDetector, VisionReaderAction, VisionReaderMode,
        VisionReaderState, VisionStateError, VisionWriterState, parse_server_hello,
    };
    use crate::vision::frame::{Block, Command, MAX_PAYLOAD_LEN};

    fn seeded(seed: u64) -> SmallRng {
        SmallRng::seed_from_u64(seed)
    }

    fn server_hello(
        cipher: u16,
        session_id_len: usize,
        supported_versions: bool,
        padding_extension_len: usize,
    ) -> Vec<u8> {
        assert!(session_id_len <= 32);
        assert!(padding_extension_len <= usize::from(u16::MAX));

        let mut extensions = Vec::new();
        if supported_versions {
            extensions.extend_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);
        }
        if padding_extension_len > 0 {
            extensions.extend_from_slice(&[0x00, 0x15]);
            extensions.extend_from_slice(&(padding_extension_len as u16).to_be_bytes());
            extensions.extend(std::iter::repeat_n(0x5a, padding_extension_len));
        }

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0x42; 32]);
        body.push(session_id_len as u8);
        body.extend(std::iter::repeat_n(0x33, session_id_len));
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0x00);
        body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        body.extend_from_slice(&extensions);

        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x03]);
        record.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        record.push(0x02);
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&body);
        record
    }

    fn app_data_record(payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::new();
        record.extend_from_slice(&[0x17, 0x03, 0x03]);
        record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        record.extend_from_slice(payload);
        record
    }

    fn block(command: Command) -> Block<'static> {
        Block {
            uuid: None,
            command,
            content: &[],
            padding_len: 0,
        }
    }

    #[test]
    fn detects_client_hello() {
        let mut detector = TlsDetector::new();
        let observation = detector.inspect(&[0x16, 0x03, 0x01, 0x00, 0x00, 0x01]);

        assert!(observation.client_hello);
        assert!(!observation.server_hello);
        assert!(!observation.application_data);
        assert!(detector.is_tls());
        assert!(!detector.is_tls12_or_above());
        assert!(!detector.enable_xtls());
        assert_eq!(detector.filter_budget(), DEFAULT_FILTER_BUDGET - 1);
    }

    #[test]
    fn detects_server_hello_and_application_data() {
        let mut detector = TlsDetector::new();
        let hello = server_hello(0x1301, 32, true, 0);
        let observation = detector.inspect(&hello);

        assert!(observation.server_hello);
        assert!(detector.is_tls());
        assert!(detector.is_tls12_or_above());
        assert!(detector.enable_xtls());
        assert_eq!(detector.cipher(), Some(0x1301));
        assert_eq!(detector.filter_budget(), 0);

        let mut detector = TlsDetector::new();
        let observation = detector.inspect(&[0x17, 0x03, 0x03, 0x00, 0x01, 0xaa]);
        assert!(observation.application_data);
        assert!(!detector.is_tls());
    }

    #[test]
    fn parses_cipher_at_the_stock_offset() {
        for (session_id_len, padding) in [(0, 30), (8, 20), (32, 0)] {
            let hello = server_hello(0x1302, session_id_len, true, padding);
            assert!(hello.len() >= 79);

            let mut detector = TlsDetector::new();
            let observation = detector.inspect(&hello);

            assert!(observation.server_hello);
            assert_eq!(detector.cipher(), Some(0x1302));
            assert!(detector.enable_xtls());
        }
    }

    #[test]
    fn server_hello_split_across_buffers_enables_xtls() {
        let hello = server_hello(0x1301, 32, true, 0);
        let split = 30;

        let mut detector = TlsDetector::new();
        let first = detector.inspect(&hello[..split]);
        assert!(first.server_hello);
        assert!(detector.is_tls12_or_above());
        assert!(!detector.enable_xtls());

        let second = detector.inspect(&hello[split..]);
        assert!(!second.server_hello);
        assert!(detector.enable_xtls());
        assert_eq!(detector.cipher(), Some(0x1301));
        assert_eq!(detector.filter_budget(), 0);
    }

    #[test]
    fn oversized_server_hello_is_rejected_without_buffering_it() {
        let mut oversized = [0u8; 6];
        oversized[..6].copy_from_slice(&[0x16, 0x03, 0x03, 0xff, 0xff, 0x02]);

        let mut detector = TlsDetector::new();
        let observation = detector.inspect(&oversized);
        assert!(observation.server_hello);
        assert!(detector.is_tls12_or_above());
        assert!(!detector.enable_xtls());
        assert_eq!(detector.filter_budget(), 0);

        // Filtering is over, so even a valid ServerHello is ignored.
        let observation = detector.inspect(&server_hello(0x1301, 32, true, 0));
        assert!(observation.is_empty());
        assert!(!detector.enable_xtls());
    }

    #[test]
    fn enables_xtls_only_for_known_tls13_ciphers() {
        for cipher in [0x1301, 0x1302, 0x1303, 0x1304] {
            let mut detector = TlsDetector::new();
            detector.inspect(&server_hello(cipher, 32, true, 0));
            assert!(
                detector.enable_xtls(),
                "cipher {cipher:#06x} must enable XTLS"
            );
        }

        for cipher in [0x1305, 0x1300, 0xc02f, 0x9999] {
            let mut detector = TlsDetector::new();
            detector.inspect(&server_hello(cipher, 32, true, 0));
            assert!(
                !detector.enable_xtls(),
                "cipher {cipher:#06x} must not enable XTLS"
            );
        }
    }

    #[test]
    fn xtls_requires_supported_versions_and_a_long_enough_record() {
        let mut detector = TlsDetector::new();
        detector.inspect(&server_hello(0x1301, 32, false, 0));
        assert!(detector.is_tls12_or_above());
        assert!(!detector.enable_xtls());

        // 55 bytes with a supported_versions extension: the record is short.
        let short = server_hello(0x1301, 0, true, 0);
        assert!(short.len() < 79);
        let mut detector = TlsDetector::new();
        detector.inspect(&short);
        assert!(detector.is_tls12_or_above());
        assert!(!detector.enable_xtls());
    }

    #[test]
    fn supported_versions_inside_the_session_id_does_not_enable_xtls() {
        let mut hello = server_hello(0x1301, 32, false, 0);
        let session_id_start = 44;
        hello[session_id_start..session_id_start + 6]
            .copy_from_slice(&[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]);

        let mut detector = TlsDetector::new();
        detector.inspect(&hello);

        assert_eq!(detector.cipher(), Some(0x1301));
        assert!(!detector.enable_xtls());
    }

    #[test]
    fn malformed_server_hello_never_panics_or_enables_xtls() {
        let hello = server_hello(0x1301, 32, true, 0);

        for end in 0..hello.len() {
            let mut detector = TlsDetector::new();
            let observation = detector.inspect(&hello[..end]);
            if end >= 6 {
                assert!(observation.server_hello);
            }
            assert!(!detector.enable_xtls(), "truncated at {end} bytes");
        }

        let mut bad_session_id = hello.clone();
        bad_session_id[43] = 33;
        assert_eq!(parse_server_hello(&bad_session_id), None);

        let mut bad_extension_length = hello.clone();
        let extension_len_offset = 43 + 32 + 1 + 2 + 1;
        bad_extension_length[extension_len_offset..extension_len_offset + 2]
            .copy_from_slice(&u16::MAX.to_be_bytes());
        let mut detector = TlsDetector::new();
        detector.inspect(&bad_extension_length);
        assert_eq!(detector.cipher(), Some(0x1301));
        assert!(!detector.enable_xtls());

        let mut short_header = TlsDetector::new();
        assert!(short_header.inspect(&[]).is_empty());
        assert!(short_header.inspect(&[0x16]).is_empty());
        assert!(short_header.inspect(&[0x16, 0x03, 0x03]).is_empty());
    }

    #[test]
    fn filter_budget_is_shared_and_bounded() {
        let mut detector = TlsDetector::with_filter_budget(2);
        assert!(detector.inspect(&[0x16, 0x03, 0x01, 0, 0, 1]).client_hello);
        assert_eq!(detector.filter_budget(), 1);

        assert!(detector.inspect(&[0x17, 0x03, 0x03, 0, 0]).application_data);
        assert_eq!(detector.filter_budget(), 0);

        // The budget is gone, so even a valid ServerHello is ignored.
        let observation = detector.inspect(&server_hello(0x1301, 32, true, 0));
        assert!(observation.is_empty());
        assert!(!detector.is_tls12_or_above());
        assert!(!detector.enable_xtls());
    }

    #[test]
    fn long_padding_stays_in_the_stock_range() {
        let policy = PaddingPolicy::default();
        for content_len in [0, 1, 100, 899] {
            for seed in 0..64 {
                let mut rng = seeded(seed);
                let padding = usize::from(policy.padding_len(content_len, true, &mut rng));
                let minimum = 900 - content_len;
                let maximum = 500 + 900 - content_len - 1;

                assert!(
                    (minimum..=maximum).contains(&padding),
                    "content {content_len}, seed {seed}: {padding} not in {minimum}..={maximum}"
                );
                assert!(padding <= MAX_PAYLOAD_LEN - content_len);
            }
        }
    }

    #[test]
    fn short_padding_and_clamp_match_the_stock_rule() {
        let policy = PaddingPolicy::default();

        for content_len in [0, 1, 899, 900, 4096, MAX_PAYLOAD_LEN - 10] {
            for seed in 0..64 {
                let mut rng = seeded(seed);
                let padding = usize::from(policy.padding_len(content_len, false, &mut rng));
                assert!(padding < 256, "short padding {padding} out of range");
                assert!(padding <= MAX_PAYLOAD_LEN - content_len);
            }
        }

        let mut rng = seeded(7);
        assert_eq!(policy.padding_len(MAX_PAYLOAD_LEN, true, &mut rng), 0);
        let mut rng = seeded(7);
        assert_eq!(policy.padding_len(MAX_PAYLOAD_LEN + 100, true, &mut rng), 0);

        // A long branch that would exceed the block limit is clamped exactly.
        let policy = PaddingPolicy::new([900, 20_000, 20_000, 256]);
        let mut rng = seeded(8);
        assert_eq!(
            usize::from(policy.padding_len(10, true, &mut rng)),
            MAX_PAYLOAD_LEN - 10
        );
    }

    #[test]
    fn padding_is_deterministic_for_a_seeded_rng() {
        let policy = PaddingPolicy::default();
        let mut first = seeded(1234);
        let mut second = seeded(1234);

        for content_len in [0, 10, 500, 899, 900, 2000] {
            for tls in [false, true] {
                assert_eq!(
                    policy.padding_len(content_len, tls, &mut first),
                    policy.padding_len(content_len, tls, &mut second)
                );
            }
        }
    }

    #[test]
    fn custom_seed_with_zero_ranges_does_not_panic() {
        let policy = PaddingPolicy::new([0, 0, 0, 0]);
        let mut rng = seeded(1);
        assert_eq!(policy.padding_len(0, true, &mut rng), 0);
        assert_eq!(policy.padding_len(0, false, &mut rng), 0);

        let policy = PaddingPolicy::new([900, 0, 900, 0]);
        let mut rng = seeded(1);
        assert_eq!(policy.padding_len(0, true, &mut rng), 900);

        // seed[2] below the content length must saturate, not underflow.
        let policy = PaddingPolicy::new([900, 10, 10, 0]);
        let mut rng = seeded(1);
        assert_eq!(policy.padding_len(100, true, &mut rng), 0);
    }

    #[test]
    fn first_block_carries_the_uuid_once() {
        let mut writer = VisionWriterState::new();
        let mut rng = seeded(11);
        let first = [0xaa_u8; 100];
        let second = [0xbb_u8; 200];
        let chunks: [&[u8]; 2] = [&first, &second];

        let plan = writer.plan_write(&chunks, false, &mut rng);

        assert_eq!(plan.blocks.len(), 2);
        assert!(plan.blocks[0].uuid);
        assert!(!plan.blocks[1].uuid);
        assert_eq!(plan.blocks[0].command, Command::Continue);
        assert_eq!(plan.blocks[1].command, Command::Continue);
        assert!(!plan.switch_to_raw);
        assert!(!plan.switch_to_direct);
        assert_eq!(plan.raw_from, None);
        assert!(!writer.first_block());

        let plan = writer.plan_write(&chunks, false, &mut rng);
        assert_eq!(plan.blocks.len(), 2);
        assert!(!plan.blocks[0].uuid);
        assert!(!plan.blocks[1].uuid);
    }

    #[test]
    fn planning_a_server_hello_enables_direct_for_the_next_write() {
        let mut writer = VisionWriterState::new();
        let mut rng = seeded(17);
        let hello = server_hello(0x1301, 32, true, 0);

        let plan = writer.plan_write(&[&hello], false, &mut rng);
        assert!(writer.is_tls());
        assert!(writer.is_tls12_or_above());
        assert!(writer.enable_xtls());
        assert_eq!(plan.blocks.len(), 1);
        assert_eq!(plan.blocks[0].command, Command::Continue);
        // A handshake record still receives long padding.
        assert!(usize::from(plan.blocks[0].padding_len) >= 900 - hello.len());

        let app = app_data_record(b"payload");
        let plan = writer.plan_write(&[&app], true, &mut rng);
        assert_eq!(plan.blocks.len(), 1);
        assert_eq!(plan.blocks[0].command, Command::Direct);
        assert!(plan.switch_to_direct);
    }

    #[test]
    fn direct_is_triggered_only_by_complete_app_data_with_xtls() {
        let mut writer = VisionWriterState::new();
        let mut rng = seeded(12);
        writer.inspect(&server_hello(0x1301, 32, true, 0));
        assert!(writer.enable_xtls());

        let first = app_data_record(b"first");
        let second = app_data_record(b"second");
        let chunks: [&[u8]; 2] = [&first, &second];

        // Not a complete app-data write: padding continues and no Direct.
        let plan = writer.plan_write(&chunks, false, &mut rng);
        assert_eq!(plan.blocks.len(), 2);
        assert!(plan.blocks[0].uuid);
        assert!(!plan.blocks[1].uuid);
        assert_eq!(plan.blocks[0].command, Command::Continue);
        assert_eq!(plan.blocks[1].command, Command::Continue);
        assert!(!plan.switch_to_raw);
        assert!(!plan.switch_to_direct);
        assert!(writer.padding_enabled());

        let plan = writer.plan_write(&chunks, true, &mut rng);
        assert_eq!(plan.blocks.len(), 2);
        assert!(!plan.blocks[0].uuid);
        assert!(!plan.blocks[1].uuid);
        assert_eq!(plan.blocks[0].command, Command::Continue);
        assert_eq!(plan.blocks[1].command, Command::Direct);
        assert!(plan.switch_to_raw);
        assert!(plan.switch_to_direct);
        assert_eq!(plan.raw_from, None);
        assert!(!writer.padding_enabled());

        // The triggering write is the last long-padded write.
        assert!(usize::from(plan.blocks[1].padding_len) >= 900 - second.len());

        let plan = writer.plan_write(&chunks, true, &mut rng);
        assert!(plan.blocks.is_empty());
        assert_eq!(plan.raw_from, Some(0));
        assert!(plan.switch_to_raw);
        assert!(!plan.switch_to_direct);
    }

    #[test]
    fn app_data_without_xtls_ends_padding_and_leaves_the_rest_raw() {
        let mut writer = VisionWriterState::new();
        let mut rng = seeded(13);
        writer.inspect(&server_hello(0x1305, 32, true, 0));
        assert!(writer.is_tls());
        assert!(!writer.enable_xtls());

        let first = app_data_record(b"first");
        let second = app_data_record(b"second");
        let chunks: [&[u8]; 2] = [&first, &second];

        let plan = writer.plan_write(&chunks, true, &mut rng);
        assert_eq!(plan.blocks.len(), 1);
        assert!(plan.blocks[0].uuid);
        assert_eq!(plan.blocks[0].command, Command::End);
        assert!(plan.switch_to_raw);
        assert!(!plan.switch_to_direct);
        assert_eq!(plan.raw_from, Some(1));
        assert!(usize::from(plan.blocks[0].padding_len) >= 900 - first.len());
        assert!(!writer.padding_enabled());

        let plan = writer.plan_write(&chunks, true, &mut rng);
        assert!(plan.blocks.is_empty());
        assert_eq!(plan.raw_from, Some(0));
        assert!(plan.switch_to_raw);
    }

    #[test]
    fn non_tls_budget_ends_after_eight_inspected_buffers() {
        let mut writer = VisionWriterState::new();
        let mut rng = seeded(14);
        let chunk = [0x5a_u8; 32];

        for inspected in 1..=DEFAULT_FILTER_BUDGET {
            let plan = writer.plan_write(&[&chunk], false, &mut rng);
            assert_eq!(plan.blocks.len(), 1);
            let expected = if inspected == DEFAULT_FILTER_BUDGET {
                Command::End
            } else {
                Command::Continue
            };
            assert_eq!(
                plan.blocks[0].command, expected,
                "buffer {inspected} of {DEFAULT_FILTER_BUDGET}"
            );
            assert_eq!(writer.padding_enabled(), inspected < DEFAULT_FILTER_BUDGET);
        }

        let plan = writer.plan_write(&[&chunk], false, &mut rng);
        assert!(plan.blocks.is_empty());
        assert_eq!(plan.raw_from, Some(0));
        assert!(plan.switch_to_raw);
    }

    #[test]
    fn reader_side_inspection_shares_the_filter_budget() {
        let mut writer = VisionWriterState::new();
        let mut rng = seeded(15);

        for _ in 0..DEFAULT_FILTER_BUDGET - 1 {
            writer.inspect(&[0u8; 6]);
        }
        assert_eq!(writer.filter_budget(), 1);

        let plan = writer.plan_write(&[&[0u8; 16]], false, &mut rng);
        assert_eq!(plan.blocks[0].command, Command::End);
        assert_eq!(writer.filter_budget(), 0);
    }

    #[test]
    fn batch_budget_end_marks_the_eighth_chunk_and_keeps_the_tail_raw() {
        let mut writer = VisionWriterState::new();
        let mut rng = seeded(16);
        let chunks = [[0u8; 8]; 10];
        let chunk_refs: Vec<&[u8]> = chunks.iter().map(|chunk| chunk.as_slice()).collect();

        let plan = writer.plan_write(&chunk_refs, false, &mut rng);

        assert_eq!(plan.blocks.len(), 8);
        for block in &plan.blocks[..7] {
            assert_eq!(block.command, Command::Continue);
        }
        assert_eq!(plan.blocks[7].command, Command::End);
        assert!(plan.blocks[0].uuid);
        assert!(!plan.blocks[7].uuid);
        assert!(plan.switch_to_raw);
        assert_eq!(plan.raw_from, Some(8));
        assert!(!writer.padding_enabled());
    }

    #[test]
    fn reader_transitions_and_rejects_bytes_after_end_or_direct() {
        let mut reader = VisionReaderState::new();
        assert!(reader.is_framed());
        assert_eq!(
            reader.on_block(&block(Command::Continue)),
            Ok(VisionReaderAction::Continue)
        );
        assert!(reader.is_framed());

        assert_eq!(
            reader.on_block(&block(Command::End)),
            Ok(VisionReaderAction::End)
        );
        assert_eq!(reader.mode(), VisionReaderMode::Ended);
        assert!(reader.is_finished());
        assert!(reader.forwards_remainder());
        assert!(!reader.forwards_tls_read_ahead());
        assert_eq!(
            reader.on_command(Command::Continue),
            Err(VisionStateError::BlockAfterEnd {
                mode: VisionReaderMode::Ended
            })
        );

        let mut reader = VisionReaderState::new();
        assert_eq!(
            reader.on_block(&block(Command::Direct)),
            Ok(VisionReaderAction::Direct)
        );
        assert_eq!(reader.mode(), VisionReaderMode::Direct);
        assert!(reader.forwards_remainder());
        assert!(reader.forwards_tls_read_ahead());
        assert_eq!(
            reader.on_command(Command::Direct),
            Err(VisionStateError::BlockAfterEnd {
                mode: VisionReaderMode::Direct
            })
        );
    }

    #[test]
    fn reader_action_maps_back_to_wire_commands() {
        for (action, command) in [
            (VisionReaderAction::Continue, Command::Continue),
            (VisionReaderAction::End, Command::End),
            (VisionReaderAction::Direct, Command::Direct),
        ] {
            assert_eq!(action.command(), command);
        }

        assert!(!VisionReaderAction::Continue.forwards_remainder());
        assert!(VisionReaderAction::End.forwards_remainder());
        assert!(VisionReaderAction::Direct.forwards_remainder());
        assert!(!VisionReaderAction::End.forwards_tls_read_ahead());
        assert!(VisionReaderAction::Direct.forwards_tls_read_ahead());
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        #[test]
        fn arbitrary_bytes_never_panic_in_the_detector(
            data in prop::collection::vec(any::<u8>(), 0..=512),
        ) {
            let mut detector = TlsDetector::new();
            let _ = detector.inspect(&data);
        }

        #[test]
        fn arbitrary_split_input_never_panics(
            data in prop::collection::vec(any::<u8>(), 0..=512),
            split in 0_usize..=512,
        ) {
            let split = split.min(data.len());
            let mut detector = TlsDetector::new();
            let _ = detector.inspect(&data[..split]);
            let _ = detector.inspect(&data[split..]);
        }

        #[test]
        fn padding_never_exceeds_the_block_clamp(
            content_len in 0_usize..=MAX_PAYLOAD_LEN,
            tls in any::<bool>(),
            seed in any::<u64>(),
        ) {
            let mut rng = SmallRng::seed_from_u64(seed);
            let padding = PaddingPolicy::default()
                .padding_len(content_len, tls, &mut rng);
            prop_assert!(usize::from(padding) <= MAX_PAYLOAD_LEN - content_len);
        }
    }
}
