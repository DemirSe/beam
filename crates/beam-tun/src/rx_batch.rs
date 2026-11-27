//! Length-prefixed batching for TUN receive queues.
//!
//! The Windows WinTun reader thread used to forward one heap `Vec`, one
//! channel send, and one task wakeup per packet. At download rates (~8.6k
//! packets/s at 101 Mbps / 1460 B payload, counting the small per-data ACKs
//! the app pushes back into the TUN) that per-packet cost dominates the
//! reader. Batching drains up to [`RX_BATCH_MAX_PACKETS`] packets (or
//! [`RX_BATCH_MAX_BYTES`] bytes) per wakeup into one buffer of
//! `[len: u16 BE][packet]...` frames, so a single allocation and a single
//! channel message carry the whole burst.
//!
//! The RAM bound stays explicit: the Windows adapter queues at most its
//! channel capacity of full batches, each at most [`RX_BATCH_MAX_BYTES`]
//! bytes (plus 2 framing bytes per packet), i.e. the same order as one
//! max-size packet per queued slot before.

/// Max packets drained from the ring per wakeup.
pub const RX_BATCH_MAX_PACKETS: usize = 32;

/// Max total bytes per batch, framing included.
pub const RX_BATCH_MAX_BYTES: usize = 64 * 1024;

/// Framing bytes prepended to each packet (u16 big-endian length).
pub const RX_BATCH_FRAME_LEN: usize = 2;

/// Largest single packet a frame can carry (u16 length field).
pub const RX_BATCH_MAX_PACKET_LEN: usize = u16::MAX as usize;

/// Appends `packet` as one length-prefixed frame.
///
/// Returns `false` without touching `batch` when the frame would push the
/// batch past [`RX_BATCH_MAX_BYTES`] or the packet does not fit a u16 length.
/// Callers then ship the full batch and start a new one; a packet that alone
/// exceeds the cap goes out via [`push_frame_forced`].
pub fn push_frame(batch: &mut Vec<u8>, packet: &[u8]) -> bool {
    if packet.is_empty() || packet.len() > RX_BATCH_MAX_PACKET_LEN {
        return false;
    }
    if batch.len() + RX_BATCH_FRAME_LEN + packet.len() > RX_BATCH_MAX_BYTES {
        return false;
    }
    push_frame_unchecked(batch, packet);
    true
}

/// Appends `packet` as one length-prefixed frame without the batch size
/// check, for a lone packet that alone exceeds [`RX_BATCH_MAX_BYTES`] (only
/// possible for jumbo ring reads above the TUN MTU; still bounded by the
/// caller's ring buffer). Truncates only what cannot fit a u16 length.
pub fn push_frame_forced(batch: &mut Vec<u8>, packet: &[u8]) {
    let len = packet.len().min(RX_BATCH_MAX_PACKET_LEN);
    push_frame_unchecked(batch, &packet[..len]);
}

fn push_frame_unchecked(batch: &mut Vec<u8>, packet: &[u8]) {
    batch.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    batch.extend_from_slice(packet);
}

/// Returns the next frame in `batch` at `*offset`, advancing past it.
///
/// Returns `None` at the end of the batch or on a truncated/corrupt tail;
/// callers then drop the rest of the batch (only our own encoder produces
/// batches, so this is unreachable except on memory corruption).
pub fn pop_frame<'a>(batch: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
    let rest = batch.get(*offset..)?;
    let len_bytes: [u8; 2] = rest.get(..RX_BATCH_FRAME_LEN)?.try_into().ok()?;
    let len = usize::from(u16::from_be_bytes(len_bytes));
    let start = (*offset).checked_add(RX_BATCH_FRAME_LEN)?;
    let end = start.checked_add(len)?;
    let frame = batch.get(start..end)?;
    *offset = end;
    Some(frame)
}

/// Number of whole frames remaining in `batch` at `offset` (test/debug aid).
#[cfg(test)]
fn frame_count(batch: &[u8]) -> usize {
    let mut off = 0;
    let mut n = 0;
    while pop_frame(batch, &mut off).is_some() {
        n += 1;
    }
    n
}

/// Decodes length-prefixed batches back into packets, holding one batch.
///
/// The Windows adapter owns one of these: its reader thread pushes whole
/// batches (`push_batch`) and the async side pops one packet at a time
/// (`next_packet`). A fully consumed batch releases its buffer
/// (`release_if_drained`), so steady state holds at most one batch (~64 KiB)
/// outside the bounded queue.
#[derive(Debug, Default)]
pub struct BatchDecoder {
    batch: Vec<u8>,
    off: usize,
}

impl BatchDecoder {
    /// Empty decoder; the first `next_packet` returns `None` until a batch
    /// arrives.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the batch under decode. Any undecoded remainder means the
    /// previous batch ended in a corrupt tail: only our own encoder produces
    /// batches, so this is unreachable outside memory corruption.
    pub fn push_batch(&mut self, batch: Vec<u8>) {
        debug_assert!(
            self.batch.is_empty() || self.off >= self.batch.len(),
            "replacing a half-consumed batch drops {} undecoded bytes",
            self.batch.len().saturating_sub(self.off)
        );
        self.batch = batch;
        self.off = 0;
    }

    /// Returns the next packet in the current batch, or `None` when it is
    /// exhausted or ends in a truncated/corrupt tail.
    pub fn next_packet(&mut self) -> Option<&[u8]> {
        pop_frame(&self.batch, &mut self.off)
    }

    /// Frees the batch buffer once it holds no complete frame.
    ///
    /// A corrupt tail can never become a frame, so it is released here too
    /// instead of pinning up to [`RX_BATCH_MAX_BYTES`] until the next batch.
    pub fn release_if_drained(&mut self) {
        if self.off >= self.batch.len() || !self.has_complete_frame() {
            self.batch = Vec::new();
            self.off = 0;
        }
    }

    /// True when a whole frame remains at the current offset.
    fn has_complete_frame(&self) -> bool {
        let mut probe = self.off;
        pop_frame(&self.batch, &mut probe).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_preserves_packets_and_order() {
        let packets: Vec<Vec<u8>> = (0u8..64).map(|i| vec![i; i as usize + 1]).collect();
        let mut batch = Vec::new();
        for p in &packets {
            assert!(push_frame(&mut batch, p));
        }
        assert_eq!(frame_count(&batch), packets.len());
        let mut off = 0;
        for p in &packets {
            assert_eq!(pop_frame(&batch, &mut off), Some(p.as_slice()));
        }
        assert_eq!(pop_frame(&batch, &mut off), None);
    }

    #[test]
    fn mtu_sized_packets_fill_batch_within_bound() {
        let mtu = vec![0xABu8; 1500];
        let mut batch = Vec::new();
        let mut n = 0;
        while push_frame(&mut batch, &mtu) {
            n += 1;
        }
        // 1500 + 2 framing per packet fits 43 packets in 64 KiB.
        assert_eq!(n, RX_BATCH_MAX_BYTES / (1500 + RX_BATCH_FRAME_LEN));
        assert!(batch.len() <= RX_BATCH_MAX_BYTES);
        assert_eq!(frame_count(&batch), n);
    }

    #[test]
    fn single_small_acks_batch_together() {
        // Download ACKs are ~40-60 B: 32 of them must fit one batch easily.
        let ack = vec![0u8; 52];
        let mut batch = Vec::new();
        for _ in 0..RX_BATCH_MAX_PACKETS {
            assert!(push_frame(&mut batch, &ack));
        }
        assert!(batch.len() < 4 * 1024);
        assert_eq!(frame_count(&batch), RX_BATCH_MAX_PACKETS);
    }

    #[test]
    fn empty_and_oversize_packets_are_rejected() {
        let mut batch = Vec::new();
        assert!(!push_frame(&mut batch, &[]));
        assert!(batch.is_empty());
        assert!(!push_frame(
            &mut batch,
            &vec![0u8; RX_BATCH_MAX_PACKET_LEN + 1]
        ));
        assert!(batch.is_empty());
    }

    #[test]
    fn truncated_tail_decodes_to_none() {
        let mut batch = Vec::new();
        assert!(push_frame(&mut batch, &[1, 2, 3]));
        assert!(push_frame(&mut batch, &[4, 5]));
        let mut off = 0;
        assert_eq!(pop_frame(&batch, &mut off), Some([1, 2, 3].as_slice()));
        // Corrupt the second length prefix to claim far more than remains.
        let corrupt_at = off;
        batch[corrupt_at] = 0xFF;
        batch[corrupt_at + 1] = 0xFF;
        assert_eq!(pop_frame(&batch, &mut off), None);
        // Truncated length prefix and truncated payload also decode to None.
        let mut off = batch.len() - 1;
        assert_eq!(pop_frame(&batch, &mut off), None);
        let mut off = batch.len();
        assert_eq!(pop_frame(&batch, &mut off), None);
    }

    #[test]
    fn decoder_streams_batches_and_releases_memory() {
        let mut enc = Vec::new();
        let first: Vec<Vec<u8>> = vec![vec![1, 2], vec![3, 4, 5]];
        for p in &first {
            assert!(push_frame(&mut enc, p));
        }
        let mut second = Vec::new();
        assert!(push_frame(&mut second, &[9, 9, 9, 9]));

        let mut dec = BatchDecoder::new();
        assert_eq!(dec.next_packet(), None);
        dec.push_batch(enc);
        assert_eq!(dec.next_packet(), Some(first[0].as_slice()));
        assert_eq!(dec.next_packet(), Some(first[1].as_slice()));
        assert_eq!(dec.next_packet(), None);
        dec.release_if_drained();
        dec.push_batch(second);
        assert_eq!(dec.next_packet(), Some([9, 9, 9, 9].as_slice()));
        dec.release_if_drained();
        assert_eq!(dec.next_packet(), None);
    }

    #[test]
    fn corrupt_tail_is_released_instead_of_pinned() {
        // A truncated tail can never become a frame, so the decoder must drop
        // the buffer instead of pinning it until the next batch arrives.
        let mut enc = Vec::new();
        assert!(push_frame(&mut enc, &[1, 2, 3]));
        enc.push(0x00); // length byte with no payload behind it
        let mut dec = BatchDecoder::new();
        dec.push_batch(enc);
        assert_eq!(dec.next_packet(), Some([1u8, 2, 3].as_slice()));
        assert_eq!(dec.next_packet(), None);
        dec.release_if_drained();
        // `push_batch` debug-asserts that no half-consumed batch is replaced,
        // so reaching the next line proves the release reset the offset.
        let mut next = Vec::new();
        assert!(push_frame(&mut next, &[7, 7]));
        dec.push_batch(next);
        assert_eq!(dec.next_packet(), Some([7u8, 7].as_slice()));
        assert_eq!(dec.next_packet(), None);
    }

    #[test]
    fn forced_push_carries_a_lone_jumbo_packet() {
        // Largest encodable packet still exceeds the batch cap on its own.
        let jumbo = vec![0xCDu8; RX_BATCH_MAX_PACKET_LEN];
        let mut batch = Vec::new();
        assert!(!push_frame(&mut batch, &jumbo));
        push_frame_forced(&mut batch, &jumbo);
        let mut off = 0;
        assert_eq!(pop_frame(&batch, &mut off), Some(jumbo.as_slice()));
        assert_eq!(pop_frame(&batch, &mut off), None);
    }
}
