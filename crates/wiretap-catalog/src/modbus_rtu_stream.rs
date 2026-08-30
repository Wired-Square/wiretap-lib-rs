//! Modbus RTU reassembly: recovering messages from a byte stream, whether it
//! arrives on a serial port or chopped across consecutive frames.
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
//!
//! The same reassembler serves a real serial port, where the RTU stream is not
//! tunnelled inside anything — which is why the type is named for the stream it
//! recovers rather than for the CAN tunnel it was written for.
//! [`ModbusRtuStream::push`] counts frames, [`ModbusRtuStream::push_bytes`] does
//! not, and [`ModbusRtuStream::interpret`] takes a boundary somebody else
//! already found. [`CrcPolicy::Lenient`] relaxes the CRC gate for a line whose
//! CRCs cannot be trusted; see its docs for the cost.

use crate::modbus::protocol::{MAX_DATA_BYTES, MAX_RTU_LEN};
use crate::model::{FrameTunnel, RegisterType, TunnelProtocol};
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

/// What a boundary that fails its CRC is worth.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrcPolicy {
    /// Only a CRC-valid boundary is a message. A stream is never guessed at.
    #[default]
    Strict,
    /// A CRC-valid boundary still wins outright; only where [`CrcPolicy::Strict`]
    /// would give up and drop a byte does this emit the longest *structurally
    /// plausible* candidate instead, flagged `crc_valid: false`. On a stream
    /// whose CRCs are correct the two policies are identical.
    ///
    /// For a device with a broken CRC, or a line dropping bytes — the cases
    /// where strict framing shows nothing at all. The cost is real: with no
    /// declared `device_address` on a genuinely noisy line this will fabricate
    /// messages out of anything shaped like an address and a function code, and
    /// a fabricated request updates the outstanding-request state, so it can
    /// mis-pair the message after it. The `crc_valid` flag on every message is
    /// what keeps that honest.
    Lenient,
}

/// One complete Modbus RTU message recovered from the stream. CRC-validated
/// unless [`CrcPolicy::Lenient`] is in force — check `crc_valid`.
#[derive(Debug, Clone, PartialEq)]
pub struct ModbusRtuMessage {
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
    /// Whether the trailing CRC matches the body. Only ever false under
    /// [`CrcPolicy::Lenient`], where the boundary came from the length rules
    /// alone.
    pub crc_valid: bool,
    /// How many frames contributed bytes to this message. Always 1 for a
    /// message recovered from a raw byte stream or handed over already framed.
    pub frame_count: u32,
}

impl ModbusRtuMessage {
    /// The register block as big-endian bytes, for [`crate::decode`].
    pub fn register_bytes(&self) -> Vec<u8> {
        crate::modbus::manifest::registers_to_bytes(&self.registers)
    }
}

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
    Message(ModbusRtuMessage),
    /// No message starts here. The caller decides what that means: mid-stream a
    /// byte is junk and gets dropped, at end of stream it is the head of the
    /// residue and gets kept.
    NoMessage,
    /// Nothing to do until more bytes arrive.
    NeedMore,
}

/// Reassembles one tunnel's byte stream and yields complete Modbus RTU messages.
///
/// One instance per (session, frame id) — the buffer is the tunnel's serial
/// line, and interleaving two tunnels into it would corrupt both.
#[derive(Debug)]
pub struct ModbusRtuStream {
    buf: Vec<u8>,
    device_address: Option<u8>,
    policy: CrcPolicy,
    /// Frames whose bytes are still sitting unconsumed in `buf`, so a completed
    /// message can report how many frames it spanned.
    pending_frames: u32,
    /// The last request seen, as `(function, start_register, quantity)`. Read
    /// responses carry no register address, and FC06's request and response are
    /// byte-identical in shape, so both lean on this.
    last_request: Option<(u8, u16, u16)>,
}

impl ModbusRtuStream {
    /// A tunnel the catalogue declared.
    pub fn new(tunnel: &FrameTunnel) -> Self {
        debug_assert!(matches!(tunnel.protocol, TunnelProtocol::ModbusRtu));
        Self::for_address(tunnel.device_address)
    }

    /// An RTU stream nothing in a catalogue describes — a serial port, where the
    /// device address comes from the io profile rather than a `[…tunnel]` table.
    pub fn for_address(device_address: Option<u8>) -> Self {
        Self::with_crc_policy(device_address, CrcPolicy::Strict)
    }

    pub fn with_crc_policy(device_address: Option<u8>, policy: CrcPolicy) -> Self {
        Self {
            buf: Vec::with_capacity(MAX_RTU_LEN),
            device_address,
            policy,
            pending_frames: 0,
            last_request: None,
        }
    }

    /// Feed one frame's payload; return every message it completed.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<ModbusRtuMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.pending_frames += 1;
        self.push_bytes(bytes)
    }

    /// Feed raw bytes from a serial line. Same reassembly as [`Self::push`],
    /// without the frame accounting — there are no frames to count, so every
    /// message reports `frame_count: 1`.
    pub fn push_bytes(&mut self, bytes: &[u8]) -> Vec<ModbusRtuMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.buf.extend_from_slice(bytes);
        let out = self.drain_messages(false);

        // A desynced stream would otherwise grow without bound.
        if self.buf.len() > MAX_BUFFER {
            let excess = self.buf.len() - MAX_BUFFER;
            self.buf.drain(..excess);
        }
        out
    }

    /// One message somebody else already framed — a serial reader that framed
    /// the port, or a replayed frame that holds a whole message.
    ///
    /// The boundary is taken as given: this reports whether the CRC agrees
    /// rather than using it to find the boundary, so a CRC-invalid message comes
    /// back flagged under either policy instead of being swallowed. It reads the
    /// same candidate table as [`Self::push_bytes`], so a message framed here and
    /// one recovered from a byte stream are labelled identically. The reassembly
    /// buffer is never touched, so the two can share an instance — which they
    /// must, because the outstanding-request state lives here.
    pub fn interpret(&mut self, raw: &[u8]) -> Option<ModbusRtuMessage> {
        if raw.len() < 4 || !self.address_matches(raw[0]) {
            return None;
        }
        let chosen = candidates(raw)
            .into_iter()
            .flatten()
            .find(|c| c.len == raw.len())?;
        let crc_valid = crc16_modbus_valid(raw);
        // A CRC that agrees vouches for the message outright, implausible header
        // or not — the length table does not model every function code, and the
        // checksum is far stronger evidence than the table is. Without one, the
        // header has to be self-consistent, which is the same bar
        // [`CrcPolicy::Lenient`] sets for a boundary it guessed. Otherwise any
        // five bytes that open like an address and a function code would be
        // reported as a response carrying no registers.
        if !crc_valid && !is_plausible(raw, &chosen) {
            return None;
        }
        Some(self.build(raw.to_vec(), chosen.direction, crc_valid))
    }

    /// End of stream: no more bytes are coming.
    ///
    /// [`Self::push_bytes`] withholds a message while a longer candidate could
    /// still be completed by bytes that have not arrived. At end of stream they
    /// never will, so that rule is dropped and whatever the buffer can still
    /// yield is yielded. Returns the messages recovered and the bytes left over,
    /// which are by construction not a message — a truncated message is reported
    /// whole rather than resynced away a byte at a time.
    pub fn finish(&mut self) -> (Vec<ModbusRtuMessage>, Vec<u8>) {
        let out = self.drain_messages(true);
        self.pending_frames = 0;
        (out, std::mem::take(&mut self.buf))
    }

    /// Drain every message the buffer can yield. `at_end` also drops the
    /// wait-for-a-longer-candidate rule: mid-stream a byte that starts nothing
    /// is junk to be dropped, at end of stream it is the head of the residue.
    fn drain_messages(&mut self, at_end: bool) -> Vec<ModbusRtuMessage> {
        let mut out = Vec::new();
        loop {
            self.skip_to_address();
            match self.take_message(at_end) {
                Step::Message(msg) => {
                    // Bytes still buffered came from the newest frame, so it is
                    // shared with whatever message comes next.
                    self.pending_frames = u32::from(!self.buf.is_empty());
                    out.push(msg);
                }
                // The real message may be right behind the byte we drop.
                Step::NoMessage if !at_end => {
                    self.buf.drain(..1);
                }
                _ => break,
            }
        }
        out
    }

    /// Discard anything before a plausible address byte; a message can only
    /// start there.
    fn skip_to_address(&mut self) {
        let skip = self
            .buf
            .iter()
            .position(|&b| self.address_matches(b))
            .unwrap_or(self.buf.len());
        self.buf.drain(..skip);
    }

    fn address_matches(&self, byte: u8) -> bool {
        match self.device_address {
            Some(addr) => byte == addr,
            // Broadcast (0) never gets a reply, so it cannot start a message
            // here; 248..=255 are reserved.
            None => (1..=247).contains(&byte),
        }
    }

    /// Try to consume one message from the head of the buffer. `at_end` drops
    /// the "wait for a longer candidate" rule, which only makes sense while more
    /// bytes could still arrive.
    fn take_message(&mut self, at_end: bool) -> Step {
        let buffered = self.buf.len();
        if buffered < 4 {
            return Step::NeedMore;
        }
        let candidates = candidates(&self.buf);

        // Candidates come longest-first, so the first CRC hit is also the
        // longest: a data-bearing message outranks a short one that might
        // coincidentally validate. A 16-bit check is overwhelming evidence, so
        // it is not second-guessed by the structural rules below.
        let valid = candidates
            .into_iter()
            .flatten()
            .find(|c| c.len <= buffered && crc16_modbus_valid(&self.buf[..c.len]));
        if let Some(c) = valid {
            return self.take(c, true);
        }

        // Only give up on a CRC hit once no candidate could still be completed
        // by more bytes — otherwise we would eat the head of a split message.
        // A candidate that contradicts its own header is not one we could be
        // halfway through, so it does not earn the wait; without that, one
        // corrupt byte where a `byte_count` should be invents a 200-byte
        // candidate and stalls the stream until `MAX_BUFFER` evicts it.
        if !at_end
            && candidates
                .into_iter()
                .flatten()
                .find(|c| is_plausible(&self.buf, c))
                .is_some_and(|c| c.len > buffered)
        {
            return Step::NeedMore;
        }

        // Nothing validated, and nothing more is coming for these candidates.
        if self.policy == CrcPolicy::Lenient {
            let guess = candidates
                .into_iter()
                .flatten()
                .find(|c| c.len <= buffered && is_plausible(&self.buf, c));
            if let Some(c) = guess {
                return self.take(c, false);
            }
        }

        Step::NoMessage
    }

    /// Consume a candidate's bytes off the head of the buffer as a message.
    fn take(&mut self, candidate: Candidate, crc_valid: bool) -> Step {
        let raw: Vec<u8> = self.buf.drain(..candidate.len).collect();
        Step::Message(self.build(raw, candidate.direction, crc_valid))
    }

    /// Turn validated bytes into a message, resolving what the wire leaves out.
    fn build(&mut self, raw: Vec<u8>, direction: Direction, crc_valid: bool) -> ModbusRtuMessage {
        let device_address = raw[0];
        let function = raw[1];
        // 0 on the byte-stream and pre-framed paths, which count no frames.
        let frame_count = self.pending_frames.max(1);

        let mut msg = ModbusRtuMessage {
            direction,
            device_address,
            function,
            start_register: None,
            quantity: None,
            registers: Vec::new(),
            exception: None,
            raw,
            crc_valid,
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

/// Candidate layouts for the function code at the head of `buf`, longest first.
///
/// There are never more than two, so this is an array rather than a `Vec`: it is
/// built once per byte fed on the byte-stream path, where an allocation and a
/// sort per byte are the whole cost. `buf` must be at least 2 bytes. Lengths a
/// `byte_count` decides are only offered once that byte has arrived.
fn candidates(buf: &[u8]) -> [Option<Candidate>; 2] {
    let func = buf[1];
    let req = |len: usize| {
        Some(Candidate {
            len,
            direction: Direction::Request,
        })
    };
    let resp = |len: usize| {
        Some(Candidate {
            len,
            direction: Direction::Response,
        })
    };
    // `byte_count` at `idx`, when that byte has arrived.
    let bc = |idx: usize| buf.get(idx).map(|&b| b as usize);

    let pair = match func {
        // Exception: address, function, code, CRC.
        f if f & 0x80 != 0 => (resp(5), None),
        // Reads: an 8-byte request, or a `5 + byte_count` response. For FC03/04
        // the two cannot collide, because a register byte count is even. For
        // FC01/02 they can: 17..=24 coils pack into 3 bytes, making an 8-byte
        // response. The tie below goes to the request, so that one case reads as
        // a request — wrong, but consistently so, and `interpret` shares this
        // table precisely so both paths agree.
        0x01..=0x04 => (req(8), bc(2).and_then(|n| resp(5 + n))),
        // Write single coil/register: request and response are identical.
        // Direction comes from `last_request` in `build`.
        0x05 | 0x06 => (req(8), None),
        // Write multiple: `9 + byte_count` request, 8-byte response.
        0x0F | 0x10 => (resp(8), bc(6).and_then(|n| req(9 + n))),
        _ => (None, None),
    };
    // Longest first, swapping only on strictly longer so an equal-length pair
    // keeps the order above.
    match pair {
        (Some(first), Some(second)) if second.len > first.len => [pair.1, pair.0],
        _ => [pair.0, pair.1],
    }
}

/// Whether a candidate's own header is self-consistent — the only evidence left
/// when the CRC has already failed to vouch for it.
///
/// Used for two things: deciding which candidates earn the "wait for a longer
/// one" rule, and gating what [`CrcPolicy::Lenient`] is willing to guess.
/// Without it, line noise fabricates a message out of every byte pair that looks
/// like an address and a function code.
///
/// Only checks what the wire format guarantees independently of the CRC, so a
/// real message can never be rejected. A candidate whose header bytes have not
/// arrived yet is undecidable, and counts as plausible so that it still earns
/// the wait. The fixed-length layouts have nothing left to check — their length
/// rule *is* the check.
fn is_plausible(buf: &[u8], candidate: &Candidate) -> bool {
    let func = buf[1];
    match (func, candidate.direction) {
        // Exception: a code that actually exists. 0x0B is the highest the spec
        // defines, and there is no exception 0 — without this, any noise byte
        // with its high bit set invents a five-byte exception.
        (f, _) if f & 0x80 != 0 => buf.get(2).is_none_or(|&code| (0x01..=0x0B).contains(&code)),
        // Read request: a quantity the bank can actually serve.
        (0x01..=0x04, Direction::Request) => {
            RegisterType::from_function_code(func).is_some_and(|bank| {
                be_at(buf, 4).is_none_or(|quantity| (1..=bank.max_per_read()).contains(&quantity))
            })
        }
        // Read response: a data block, two bytes per register for the register
        // banks. Coil banks pack eight to a byte, so any count is possible.
        (0x01..=0x04, Direction::Response) => {
            let register_bank =
                RegisterType::from_function_code(func).is_some_and(RegisterType::is_register_bank);
            buf.get(2).is_none_or(|&n| {
                let n = n as usize;
                (1..=MAX_DATA_BYTES).contains(&n) && (!register_bank || n.is_multiple_of(2))
            })
        }
        // Write-multiple request: the byte count has to match the quantity it
        // claims to be writing. Both codes address a writable bank, so the cap
        // and the packing rule come from the bank rather than the code.
        (0x0F | 0x10, Direction::Request) => {
            RegisterType::from_function_code(func).is_some_and(|bank| {
                let max = bank.max_per_write().unwrap_or(0);
                be_at(buf, 4).zip(buf.get(6)).is_none_or(|(quantity, &n)| {
                    (1..=max).contains(&quantity) && n as usize == bank.data_bytes(quantity)
                })
            })
        }
        _ => true,
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

/// Big-endian `u16` at `i`, when both its bytes have arrived.
fn be_at(raw: &[u8], i: usize) -> Option<u16> {
    raw.get(i..i + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiretap_checksum::algorithms::crc16_modbus_checksum;

    fn strict(device_address: Option<u8>) -> ModbusRtuStream {
        ModbusRtuStream::new(&FrameTunnel {
            protocol: TunnelProtocol::ModbusRtu,
            device_address,
            notes: Vec::new(),
        })
    }

    fn lenient(device_address: Option<u8>) -> ModbusRtuStream {
        ModbusRtuStream::with_crc_policy(device_address, CrcPolicy::Lenient)
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

    /// A message body with a CRC that is definitely wrong.
    fn with_bad_crc(body: &str) -> Vec<u8> {
        let mut m = with_crc(body);
        *m.last_mut().expect("crc appended") ^= 0xFF;
        m
    }

    /// Feed a message the way CAN carries it: split at 8-byte boundaries.
    fn push_chunked(t: &mut ModbusRtuStream, msg: &[u8]) -> Vec<ModbusRtuMessage> {
        msg.chunks(8).flat_map(|c| t.push(c)).collect()
    }

    // The four exchanges observed on a Sungrow SBR's CAN 0x1E0.

    #[test]
    fn decodes_read_input_request() {
        let mut t = strict(Some(1));
        let msgs = push_chunked(&mut t, &hex("01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[0].function, 0x04);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].quantity, Some(2));
        assert_eq!(msgs[0].frame_count, 1);
        assert!(msgs[0].crc_valid);
    }

    #[test]
    fn decodes_read_input_response_split_8_plus_1() {
        let mut t = strict(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        let msgs = push_chunked(&mut t, &hex("01040401F40000BB8A"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].registers, vec![500, 0]);
        // Inherited from the request it answers.
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].frame_count, 2);
        assert!(msgs[0].crc_valid);
    }

    #[test]
    fn decodes_read_holding_response_split_8_plus_8_plus_1() {
        let mut t = strict(Some(1));
        let req = push_chunked(&mut t, &hex("01034DE200067292"));
        assert_eq!(req[0].quantity, Some(6));

        let msgs = push_chunked(&mut t, &hex("01030C01F40000012C000000C80000D570"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].direction, Direction::Response);
        assert_eq!(msgs[0].registers, vec![500, 0, 300, 0, 200, 0]);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
        assert_eq!(msgs[0].frame_count, 3);
        assert!(msgs[0].crc_valid);
    }

    #[test]
    fn register_bytes_are_big_endian() {
        let mut t = strict(Some(1));
        push_chunked(&mut t, &hex("01044DE20002C691"));
        let msgs = push_chunked(&mut t, &hex("01040401F40000BB8A"));
        assert_eq!(msgs[0].register_bytes(), hex("01F40000"));
    }

    #[test]
    fn a_partial_message_yields_nothing_until_complete() {
        let mut t = strict(Some(1));
        assert!(t.push(&hex("01030C01F40000012C")).is_empty());
        assert!(t.push(&hex("000000C80000")).is_empty());
        assert_eq!(t.push(&hex("D570")).len(), 1);
    }

    #[test]
    fn resyncs_past_leading_junk() {
        let mut t = strict(Some(1));
        // A stray byte that is not the device address is skipped outright.
        let msgs = t.push(&hex("FF01044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn resyncs_past_a_false_address_byte() {
        let mut t = strict(Some(1));
        // A leading 0x01 that starts nothing valid must be dropped, not left to
        // block the real message behind it.
        let msgs = t.push(&hex("0101044DE20002C691"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].function, 0x04);
    }

    #[test]
    fn back_to_back_messages_in_one_push() {
        let mut t = strict(Some(1));
        let msgs = t.push(&hex("01044DE20002C69101040401F40000BB8A"));
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].direction, Direction::Request);
        assert_eq!(msgs[1].direction, Direction::Response);
        assert_eq!(msgs[1].registers, vec![500, 0]);
    }

    #[test]
    fn decodes_exception_response() {
        let mut t = strict(Some(1));
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
        let mut t = strict(Some(1));
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
        let mut t = strict(Some(1));
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
        let mut t = strict(None);
        let msgs = t.push(&with_crc("2A044DE20002"));
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].device_address, 42);
    }

    #[test]
    fn a_desynced_stream_does_not_grow_without_bound() {
        let mut t = strict(Some(1));
        // 0x01 0x07 is a valid address but an unhandled function, so nothing
        // ever completes.
        for _ in 0..500 {
            t.push(&hex("0107010101010101"));
        }
        assert!(t.buf.len() <= MAX_BUFFER);
    }

    #[test]
    fn for_address_matches_the_catalogue_constructor() {
        let stream = with_crc("01044DE20002");
        let declared = strict(Some(1)).push_bytes(&stream);
        let bare = ModbusRtuStream::for_address(Some(1)).push_bytes(&stream);
        assert_eq!(declared, bare);
        assert_eq!(declared.len(), 1);
    }

    // ---- Lenient CRC policy ----

    #[test]
    fn lenient_emits_the_bad_crc_message_strict_discards() {
        let bytes = with_bad_crc("01040401F40000");
        assert!(strict(Some(1)).push_bytes(&bytes).is_empty());

        let msgs = lenient(Some(1)).push_bytes(&bytes);
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].crc_valid);
        // The boundary came from the length rules, so the block still decodes.
        assert_eq!(msgs[0].registers, vec![500, 0]);
    }

    #[test]
    fn lenient_still_prefers_a_valid_crc_candidate() {
        // An 8-byte read request whose CRC is good sits inside the buffer at the
        // same head as a longer response candidate that is not valid. The valid
        // one must win outright rather than the guess consuming it.
        let mut t = lenient(Some(1));
        let msgs = t.push_bytes(&with_crc("01044DE20002"));
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].crc_valid);
        assert_eq!(msgs[0].start_register, Some(0x4DE2));
    }

    #[test]
    fn lenient_waits_for_the_longest_candidate_before_guessing() {
        let mut t = lenient(Some(1));
        // Eight bytes of a 17-byte FC03 response. The 8-byte request candidate
        // fits, but the response candidate could still be completed, so nothing
        // may be emitted yet.
        assert!(t.push_bytes(&hex("01030C01F40000012C")).is_empty());
    }

    #[test]
    fn lenient_recovers_after_a_bad_crc_message() {
        let mut t = lenient(Some(1));
        let mut stream = with_bad_crc("01044DE20002");
        stream.extend(with_crc("01040401F40000"));
        let msgs = t.push_bytes(&stream);
        assert_eq!(msgs.len(), 2);
        assert!(!msgs[0].crc_valid);
        assert!(msgs[1].crc_valid);
        assert_eq!(msgs[1].registers, vec![500, 0]);
    }

    #[test]
    fn lenient_rejects_an_implausible_byte_count() {
        // An FC04 response claiming an odd byte count cannot be real: registers
        // are two bytes each. Without the plausibility gate this fabricates a
        // message.
        let mut t = lenient(Some(1));
        assert!(t.push_bytes(&with_bad_crc("01040301F400")).is_empty());
        // And a zero byte count.
        let mut t = lenient(Some(1));
        assert!(t.push_bytes(&with_bad_crc("010400")).is_empty());
    }

    #[test]
    fn lenient_rejects_a_write_multiple_whose_count_contradicts_its_quantity() {
        // Claims two registers but carries six bytes, so the 15-byte request
        // reading contradicts itself and must never be emitted. (The shorter
        // response reading of the same head has nothing left to contradict; a
        // guess is a guess, and it is flagged as one.)
        let mut t = lenient(Some(1));
        let msgs = t.push_bytes(&with_bad_crc("0110138800020600C801F40000"));
        assert!(msgs.iter().all(|m| m.raw.len() != 15), "{msgs:?}");
        assert!(msgs.iter().all(|m| !m.crc_valid));
    }

    #[test]
    fn lenient_drops_a_byte_when_no_candidate_exists() {
        // 0x07 is an unhandled function, so there is nothing to guess at; the
        // real message behind it must still be found.
        let mut t = lenient(Some(1));
        let mut stream = hex("0107");
        stream.extend(with_crc("01044DE20002"));
        let msgs = t.push_bytes(&stream);
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].crc_valid);
        assert_eq!(msgs[0].function, 0x04);
    }

    // ---- interpret: one already-framed message ----

    /// Without a CRC to vouch for it, a candidate whose own header contradicts
    /// itself is not a message. Five bytes opening like an address and a read
    /// function code match the `5 + byte_count` response layout with a byte
    /// count of zero — which no device sends.
    #[test]
    fn interpret_rejects_an_implausible_message_with_a_bad_crc() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        assert!(t.interpret(&hex("0103006B00")).is_none());
    }

    /// A CRC that agrees still wins, whatever the length table makes of it.
    #[test]
    fn interpret_trusts_a_valid_crc_over_the_length_table() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let framed = with_crc("010300");
        assert!(t.interpret(&framed).is_some());
    }

    #[test]
    fn interpret_reads_one_framed_request() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let msg = t.interpret(&hex("01044DE20002C691")).unwrap();
        assert_eq!(msg.direction, Direction::Request);
        assert_eq!(msg.start_register, Some(0x4DE2));
        assert_eq!(msg.quantity, Some(2));
        assert_eq!(msg.frame_count, 1);
        assert!(msg.crc_valid);
    }

    #[test]
    fn interpret_pairs_a_response_with_the_preceding_request() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        t.interpret(&hex("01044DE20002C691")).unwrap();
        let msg = t.interpret(&hex("01040401F40000BB8A")).unwrap();
        assert_eq!(msg.direction, Direction::Response);
        assert_eq!(msg.registers, vec![500, 0]);
        assert_eq!(msg.start_register, Some(0x4DE2));
    }

    #[test]
    fn interpret_resolves_write_single_direction_from_the_outstanding_request() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let raw = with_crc("0106138800C8");
        assert_eq!(t.interpret(&raw).unwrap().direction, Direction::Request);
        assert_eq!(t.interpret(&raw).unwrap().direction, Direction::Response);
    }

    #[test]
    fn interpret_rejects_a_length_no_candidate_explains() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        assert!(t.interpret(&hex("01044DE2000200")).is_none());
        assert!(t.interpret(&hex("0104")).is_none());
        // Wrong slave.
        assert!(t.interpret(&hex("02044DE20002B441")).is_none());
    }

    #[test]
    fn interpret_flags_a_bad_crc_rather_than_rejecting_it() {
        // The caller supplied the boundary, so the CRC is a verdict, not a gate
        // — in either policy.
        for mut t in [ModbusRtuStream::for_address(Some(1)), lenient(Some(1))] {
            let msg = t.interpret(&with_bad_crc("01044DE20002")).unwrap();
            assert!(!msg.crc_valid);
            assert_eq!(msg.start_register, Some(0x4DE2));
        }
    }

    #[test]
    fn interpret_prefers_the_request_reading_when_lengths_collide() {
        // An FC01 response for 17..=24 coils packs into 3 bytes, making it 8
        // bytes long — exactly a request. Both paths must read it the same way.
        let raw = with_crc("010103010203");
        let framed = ModbusRtuStream::for_address(Some(1))
            .interpret(&raw)
            .unwrap()
            .direction;
        let streamed = ModbusRtuStream::for_address(Some(1)).push_bytes(&raw)[0].direction;
        assert_eq!(framed, streamed);
        assert_eq!(framed, Direction::Request);
    }

    #[test]
    fn interpret_leaves_the_buffer_untouched() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        // Half a message in the reassembly buffer.
        t.push_bytes(&hex("01030C01F40000012C"));
        let buffered = t.buf.clone();
        t.interpret(&hex("01044DE20002C691")).unwrap();
        assert_eq!(t.buf, buffered);
    }

    // ---- byte streams and end of stream ----

    #[test]
    fn push_bytes_reassembles_a_message_fed_one_byte_at_a_time() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let raw = hex("01030C01F40000012C000000C80000D570");
        let msgs: Vec<_> = raw.iter().flat_map(|b| t.push_bytes(&[*b])).collect();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].registers, vec![500, 0, 300, 0, 200, 0]);
        // 17 separate pushes, and still one message spanning no frames at all.
        assert_eq!(msgs[0].frame_count, 1);
    }

    #[test]
    fn back_to_back_messages_fed_one_byte_at_a_time() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let mut stream = with_crc("01044DE20002");
        stream.extend(with_crc("01040401F40000"));
        let msgs: Vec<_> = stream.iter().flat_map(|b| t.push_bytes(&[*b])).collect();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[1].registers, vec![500, 0]);
        let (rest, residue) = t.finish();
        assert!(rest.is_empty());
        assert!(residue.is_empty());
    }

    #[test]
    fn finish_emits_a_candidate_the_wait_for_longest_rule_withheld() {
        let mut t = lenient(Some(1));
        // A complete but CRC-invalid 8-byte read request whose third byte also
        // reads as a plausible `byte_count` of 4, so a 9-byte response candidate
        // might still arrive. Mid-stream that candidate earns the wait.
        assert!(t.push_bytes(&with_bad_crc("010304000002")).is_empty());
        // At end of stream it never will, so the guess is finally made.
        let (msgs, residue) = t.finish();
        assert_eq!(msgs.len(), 1);
        assert!(!msgs[0].crc_valid);
        assert_eq!(msgs[0].raw.len(), 8);
        assert!(residue.is_empty());
    }

    #[test]
    fn finish_reports_a_truncated_message_whole() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        // Nine bytes of a 17-byte response: not a message, and not noise either.
        let partial = hex("01030C01F40000012C00");
        t.push_bytes(&partial);
        let (msgs, residue) = t.finish();
        assert!(msgs.is_empty());
        assert_eq!(residue, partial);
        // And the buffer is now empty.
        assert!(t.buf.is_empty());
    }

    #[test]
    fn finish_recovers_a_message_then_reports_the_residue() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        let mut stream = with_crc("01044DE20002");
        stream.extend(hex("010401"));
        let streamed = t.push_bytes(&stream);
        let (finished, residue) = t.finish();
        // The valid message came out as soon as its CRC closed; the trailing
        // three bytes are not a message and are handed back whole.
        assert_eq!(streamed.len(), 1);
        assert_eq!(streamed[0].start_register, Some(0x4DE2));
        assert!(finished.is_empty());
        assert_eq!(residue, hex("010401"));
    }

    #[test]
    fn finish_is_idempotent() {
        let mut t = ModbusRtuStream::for_address(Some(1));
        t.push_bytes(&hex("01030C01F4"));
        let first = t.finish();
        assert!(!first.1.is_empty());
        assert_eq!(t.finish(), (Vec::new(), Vec::new()));
    }
}
