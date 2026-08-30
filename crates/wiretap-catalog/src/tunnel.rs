//! Tunnelled-protocol decoding: recovering messages from a byte stream that
//! was chopped across consecutive frames.
//!
//! [`crate::decode`] is stateless — one frame's bytes in, that frame's signals
//! out. A tunnel breaks that: a Sungrow SBR's CAN `0x1E0` carries a Modbus RTU
//! stream where a 17-byte response arrives as 8 + 8 + 1, and both the request
//! and the reply land on the same CAN id. Nothing in a bit-layout catalogue can
//! express "concatenate the next N payloads", so the framing lives here and the
//! catalogue only declares that the frame *is* a tunnel ([`FrameTunnel`]).
//!
//! There is no transport header — no sequence numbers, no length prefix, no
//! first/consecutive frame distinction. Message boundaries come from the Modbus
//! RTU length rules alone, gated by CRC-16/Modbus. Ported from the offline
//! Python reassembler used for the 0x1F0 firmware extraction, with one change:
//! that parser held the whole stream, so a CRC failure meant "resync". Here a
//! failure usually means "the rest hasn't arrived yet", so we wait until the
//! buffer is provably longer than any candidate before dropping a byte.

use crate::model::{FrameTunnel, TunnelProtocol};
use wiretap_checksum::algorithms::crc16_modbus_valid;

/// Which side of the exchange a message came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Request,
    Response,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Request => "request",
            Direction::Response => "response",
        }
    }
}

/// One complete, CRC-validated Modbus RTU message recovered from the stream.
#[derive(Debug, Clone, PartialEq)]
pub struct TunnelMessage {
    pub direction: Direction,
    pub device_address: u8,
    pub function: u8,
    /// First register. Present on requests and on write responses, which echo
    /// it; a read response carries only data, so this is filled in from the
    /// request it answers.
    pub start_register: Option<u16>,
    /// Register/coil count. Same provenance as `start_register`.
    pub quantity: Option<u16>,
    /// Register values, for messages that carry a data block.
    pub registers: Vec<u16>,
    /// Exception code, when the function code had its high bit set.
    pub exception: Option<u8>,
    /// The reassembled message, CRC included.
    pub raw: Vec<u8>,
    /// How many frames contributed bytes to this message.
    pub frame_count: u32,
}

impl TunnelMessage {
    /// The register block as big-endian bytes, for [`crate::decode`].
    pub fn register_bytes(&self) -> Vec<u8> {
        crate::modbus::manifest::registers_to_bytes(&self.registers)
    }
}

/// Longest Modbus RTU message: address + function + byte count + 252 data + CRC.
const MAX_RTU_LEN: usize = 256;

/// Buffer ceiling. Two full messages of slack is enough to hold a
/// request/response pair mid-reassembly; past that the stream is desynced and
/// holding more bytes only delays recovery.
const MAX_BUFFER: usize = MAX_RTU_LEN * 2;

/// A candidate message layout at the head of the buffer.
#[derive(Debug, Clone, Copy)]
struct Candidate {
    len: usize,
    direction: Direction,
}

/// What one pass over the head of the buffer achieved.
enum Step {
    Message(TunnelMessage),
    /// A junk byte was dropped — the head moved, so it is worth another pass.
    Resynced,
    /// Nothing to do until more bytes arrive.
    NeedMore,
}

/// Reassembles one tunnel's byte stream and yields complete Modbus RTU messages.
///
/// One instance per (session, frame id) — the buffer is the tunnel's serial
/// line, and interleaving two tunnels into it would corrupt both.
#[derive(Debug)]
pub struct ModbusTunnel {
    buf: Vec<u8>,
    device_address: Option<u8>,
    /// Frames whose bytes are still sitting unconsumed in `buf`, so a completed
    /// message can report how many frames it spanned.
    pending_frames: u32,
    /// The last request seen, as `(function, start_register, quantity)`. Read
    /// responses carry no register address, and FC06's request and response are
    /// byte-identical in shape, so both lean on this.
    last_request: Option<(u8, u16, u16)>,
}

impl ModbusTunnel {
    pub fn new(tunnel: &FrameTunnel) -> Self {
        debug_assert!(matches!(tunnel.protocol, TunnelProtocol::ModbusRtu));
        Self {
            buf: Vec::with_capacity(MAX_RTU_LEN),
            device_address: tunnel.device_address,
            pending_frames: 0,
            last_request: None,
        }
    }

    /// Feed one frame's payload; return every message it completed.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<TunnelMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.buf.extend_from_slice(bytes);
        self.pending_frames += 1;

        let mut out = Vec::new();
        loop {
            // Discard anything before a plausible address byte; a message can
            // only start there.
            let skip = self
                .buf
                .iter()
                .position(|&b| self.address_matches(b))
                .unwrap_or(self.buf.len());
            self.buf.drain(..skip);

            match self.take_message() {
                Step::Message(msg) => {
                    // Bytes still buffered came from the newest frame, so it is
                    // shared with whatever message comes next.
                    self.pending_frames = u32::from(!self.buf.is_empty());
                    out.push(msg);
                }
                // The real message may be right behind the byte we dropped.
                Step::Resynced => continue,
                Step::NeedMore => break,
            }
        }

        // A desynced stream would otherwise grow without bound.
        if self.buf.len() > MAX_BUFFER {
            let excess = self.buf.len() - MAX_BUFFER;
            self.buf.drain(..excess);
        }
        out
    }

    fn address_matches(&self, byte: u8) -> bool {
        match self.device_address {
            Some(addr) => byte == addr,
            // Broadcast (0) never gets a reply, so it cannot start a message
            // here; 248..=255 are reserved.
            None => (1..=247).contains(&byte),
        }
    }

    /// Try to consume one message from the head of the buffer.
    fn take_message(&mut self) -> Step {
        if self.buf.len() < 4 {
            return Step::NeedMore;
        }
        // Sorted longest-first, so the first CRC hit is also the longest: a
        // data-bearing message outranks a short one that might coincidentally
        // validate.
        let candidates = self.candidates();
        let longest = candidates.first().map_or(0, |c| c.len);
        let chosen = candidates
            .into_iter()
            .find(|c| c.len <= self.buf.len() && crc16_modbus_valid(&self.buf[..c.len]));

        let Some(chosen) = chosen else {
            // Only resync once no candidate could still be completed by more
            // bytes — otherwise we would eat the head of a split message.
            // Equality counts: every candidate has been evaluated in full.
            if self.buf.len() >= longest {
                self.buf.drain(..1);
                return Step::Resynced;
            }
            return Step::NeedMore;
        };

        let raw: Vec<u8> = self.buf.drain(..chosen.len).collect();
        Step::Message(self.build(raw, chosen.direction))
    }

    /// Candidate layouts for the function code at the head of the buffer,
    /// longest first.
    fn candidates(&self) -> Vec<Candidate> {
        let buf = &self.buf;
        let func = buf[1];
        let req = |len: usize| Candidate {
            len,
            direction: Direction::Request,
        };
        let resp = |len: usize| Candidate {
            len,
            direction: Direction::Response,
        };
        // `byte_count` at `idx`, when that byte has arrived.
        let bc = |idx: usize| buf.get(idx).map(|&b| b as usize);

        let mut out = match func {
            // Exception: address, function, code, CRC.
            f if f & 0x80 != 0 => vec![resp(5)],
            // Reads: an 8-byte request, or a `5 + byte_count` response. The two
            // never collide — a read response is always odd-length.
            0x01..=0x04 => {
                let mut v = vec![req(8)];
                v.extend(bc(2).map(|n| resp(5 + n)));
                v
            }
            // Write single coil/register: request and response are identical.
            // Direction comes from `last_request` in `build`.
            0x05 | 0x06 => vec![req(8)],
            // Write multiple: `9 + byte_count` request, 8-byte response.
            0x0F | 0x10 => {
                let mut v = vec![resp(8)];
                v.extend(bc(6).map(|n| req(9 + n)));
                v
            }
            _ => Vec::new(),
        };
        out.sort_by_key(|c| std::cmp::Reverse(c.len));
        out
    }

    /// Turn validated bytes into a message, resolving what the wire leaves out.
    fn build(&mut self, raw: Vec<u8>, direction: Direction) -> TunnelMessage {
        let device_address = raw[0];
        let function = raw[1];
        let frame_count = self.pending_frames;

        let mut msg = TunnelMessage {
            direction,
            device_address,
            function,
            start_register: None,
            quantity: None,
            registers: Vec::new(),
            exception: None,
            raw,
            frame_count,
        };

        match (function, direction) {
            // Exception: a bare code, answering whatever was outstanding.
            (f, _) if f & 0x80 != 0 => msg.exception = Some(msg.raw[2]),
            // Read request, or a write-multiple response echoing its header.
            (0x01..=0x04, Direction::Request) | (0x0F | 0x10, Direction::Response) => {
                msg.start_register = Some(be(&msg.raw, 2));
                msg.quantity = Some(be(&msg.raw, 4));
            }
            // Read response: data only — the address comes from the request.
            (0x01..=0x04, Direction::Response) => {
                let count = msg.raw[2] as usize;
                msg.registers = registers_be(&msg.raw[3..3 + count]);
            }
            // Write single: the value is the payload. Identical on both sides,
            // so the outstanding request decides which this is.
            (0x05 | 0x06, _) => {
                msg.start_register = Some(be(&msg.raw, 2));
                msg.quantity = Some(1);
                msg.registers = vec![be(&msg.raw, 4)];
                msg.direction = match self.last_request.take() {
                    Some((f, _, _)) if f == function => Direction::Response,
                    _ => Direction::Request,
                };
            }
            // Write-multiple request: header plus the data being written.
            (0x0F | 0x10, Direction::Request) => {
                msg.start_register = Some(be(&msg.raw, 2));
                msg.quantity = Some(be(&msg.raw, 4));
                let count = msg.raw[6] as usize;
                msg.registers = registers_be(&msg.raw[7..7 + count]);
            }
            _ => {}
        }

        // A response that carries no address of its own takes the outstanding
        // request's — the only record of what was asked for.
        if msg.direction == Direction::Response && msg.start_register.is_none() {
            if let Some((_, start, qty)) = self.last_request.take() {
                msg.start_register = Some(start);
                msg.quantity = Some(qty);
            }
        }
        if msg.direction == Direction::Request {
            self.last_request = Some((
                function,
                msg.start_register.unwrap_or(0),
                msg.quantity.unwrap_or(0),
            ));
        }
        msg
    }
}

/// A data block as big-endian `u16` registers. A trailing odd byte — only
/// reachable from an odd `byte_count`, which no read or write produces — is
/// dropped rather than zero-extended into a bogus register.
fn registers_be(block: &[u8]) -> Vec<u16> {
    block
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

/// Big-endian `u16` at `i`.
fn be(raw: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([raw[i], raw[i + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiretap_checksum::algorithms::crc16_modbus_checksum;

    fn tunnel(device_address: Option<u8>) -> ModbusTunnel {
        ModbusTunnel::new(&FrameTunnel {
            protocol: TunnelProtocol::ModbusRtu,
            device_address,
            notes: Vec::new(),
        })
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// A message body plus the CRC the device would append.
    fn with_crc(body: &str) -> Vec<u8> {
        let mut m = hex(body);
        m.extend(crc16_modbus_checksum(&m).to_le_bytes());
        m
    }

    /// Feed a message the way CAN carries it: split at 8-byte boundaries.
    fn push_chunked(t: &mut ModbusTunnel, msg: &[u8]) -> Vec<TunnelMessage> {
        msg.chunks(8).flat_map(|c| t.push(c)).collect()
    }

    // The four exchanges observed on a Sungrow SBR's CAN 0x1E0.

    #[test]
    fn decodes_read_input_request() {
        let mut t = tunnel(Some(1));
        let msgs = push_chunked(&mut t, &hex("01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].function, 0x04);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].quantity, Some(2));
        assert_eq!(msgs[0].frame_count, 1);
    }

    #[test]
    fn decodes_read_input_response_split_8_plus_1() {
        let mut t = tunnel(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        let msgs = push_chunked(&mut t, &hex("01040401F40000BB8A"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].registers, vec![500, 0]);
        // Inherited from the request it answers.
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].frame_count, 2);
    }

    #[test]
    fn decodes_read_holding_response_split_8_plus_8_plus_1() {
        let mut t = tunnel(Some(1));
        let req = push_chunked(&mut t, &hex("01034DE200067292"));
        assert_eq!(req[0].quantity, Some(6));

        let msgs = push_chunked(&mut t, &hex("01030C01F40000012C000000C80000D570"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].registers, vec![500, 0, 300, 0, 200, 0]);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].frame_count, 3);
    }

    #[test]
    fn register_bytes_are_big_endian() {
        let mut t = tunnel(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        let msgs = push_chunked(&mut t, &hex("01040401F40000BB8A"));
        assert_eq!(msgs[0].register_bytes(), hex("01F40000"));
    }

    #[test]
    fn a_partial_message_yields_nothing_until_complete() {
        let mut t = tunnel(Some(1));
        assert!(t.push(&hex("01030C01F40000012C")).is_empty());
        assert!(t.push(&hex("000000C80000")).is_empty());
        assert_eq!(t.push(&hex("D570")).len(), 1);
    }

    #[test]
    fn resyncs_past_leading_junk() {
        let mut t = tunnel(Some(1));
        // A stray byte that is not the device address is skipped outright.
        let msgs = t.push(&hex("FF01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn resyncs_past_a_false_address_byte() {
        let mut t = tunnel(Some(1));
        // A leading 0x01 that starts nothing valid must be dropped, not left to
        // block the real message behind it.
        let msgs = t.push(&hex("0101044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].function, 0x04);
    }

    #[test]
    fn back_to_back_messages_in_one_push() {
        let mut t = tunnel(Some(1));
        let msgs = t.push(&hex("01044DE20002C69101040401F40000BB8A"));
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[1].direction, Direction::Response);
        assert_eq!(msgs[1].registers, vec![500, 0]);
    }

    #[test]
    fn decodes_exception_response() {
        let mut t = tunnel(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        // Illegal data address.
        let msgs = t.push(&with_crc("018402"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].exception, Some(0x02));
        assert_eq!(msgs[0].direction, Direction::Response);
        // It answers the request, so it names the register that failed.
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn write_single_pairs_request_then_response() {
        let mut t = tunnel(Some(1));
        let raw = with_crc("0106138800C8");
        let first = t.push(&raw);
        assert_eq!(first[0].direction, Direction::Request);
        assert_eq!(first[0].registers, vec![0xC8]);
        // The echo is byte-identical; only the outstanding request tells them
        // apart.
        let second = t.push(&raw);
        assert_eq!(second[0].direction, Direction::Response);
    }

    #[test]
    fn decodes_write_multiple_request_and_response() {
        let mut t = tunnel(Some(1));
        let msgs = push_chunked(&mut t, &with_crc("0110138800020400C801F4"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].registers, vec![0xC8, 0x01F4]);

        let msgs = t.push(&with_crc("011013880002"));
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].start_register, Some(0x1388));
    }

    #[test]
    fn unconstrained_address_accepts_any_slave() {
        let mut t = tunnel(None);
        let msgs = t.push(&with_crc("2A044DE20002"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].device_address, 42);
    }

    #[test]
    fn a_desynced_stream_does_not_grow_without_bound() {
        let mut t = tunnel(Some(1));
        // 0x01 0x07 is a valid address but an unhandled function, so nothing
        // ever completes.
        for _ in 0..500 {
            t.push(&hex("0107010101010101"));
        }
        assert!(t.buf.len() <= MAX_BUFFER);
    }
}
