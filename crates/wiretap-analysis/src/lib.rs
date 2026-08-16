//! Payload analysis for WireTAP frames.
//!
//! - [`checksum`] — the identification pass: which bytes are worth handing to
//!   [`wiretap_checksum`]'s solvers, and why the rest were not.
//!
//! Per-byte-column statistics live in [`wiretap_checksum::columns`], beside the
//! end-relative addressing they are indexed by, and are re-exported here for
//! callers that only speak to this crate.
//!
//! The two crates split on a real seam. `wiretap-checksum` answers *what
//! algorithm is this byte*; this one answers *is this byte a checksum at all*.
//! The second question is the cheaper one and, on a real bus, usually the one
//! that decides the answer — most links carry no checksum on most frame ids.

pub mod checksum;

pub use checksum::{
    checksum_evidence, checksum_evidence_with_columns, solve_targets, ChecksumEvidence, Rejection,
};
