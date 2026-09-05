//! The wire protocols WireTAP speaks, as scalars.
//!
//! Every consumer of these codecs has its own captured-frame type — `CanSample`
//! in the capture server, `FrameMessage` behind a serde Tauri IPC contract in
//! the desktop — and they are not reconcilable: one is CAN-only and does not
//! store the data length code, the other is multi-protocol and does, and its
//! shape is a frontend contract. So nothing here names a frame type. Encoders
//! take scalars and a caller's buffer; decoders return scalars; each repository
//! adapts at its own boundary, which every one of them already does.
//!
//! Consequently: no serde, no async runtime, no driver. A client that speaks
//! one of these protocols should not have to take a capture stack to do it.
//!
//! - [`dlc`] — the CAN data length code table, and the two directions across
//!   it. Shared by both protocols below and by every archive writer, because
//!   the wire carries a code and a database column stores a length.
//! - [`gvret`] — the GVRET serial protocol: the live bridge the WireTAP desktop
//!   and SavvyCAN connect to.
//! - [`ingest`] — the id-flag layout of the binary ingest protocol.

pub mod dlc;
pub mod gvret;
pub mod ingest;

/// Arbitration id masks. Named for the id width rather than for a protocol,
/// because that is what they are: every protocol here masks the same 29 and 11
/// bits, and differs only in where it packs the flags alongside them. Defined
/// once so [`gvret`] and [`ingest`] cannot disagree about the width of a CAN
/// id — which is the whole premise of this crate, applied to itself.
pub const ARB_MASK_EXT: u32 = 0x1FFF_FFFF;
pub const ARB_MASK_STD: u32 = 0x0000_07FF;

pub use dlc::{dlc_to_len, len_to_dlc, payload_dlc, FD_DLC_LEN};
