//! Payload analysis for WireTAP frames.
//!
//! - [`columns`] — per-byte-column statistics, end-relative so frames of
//!   different lengths on one link line up.
//! - [`checksum`] — the identification pass: which bytes are worth handing to
//!   [`wiretap_checksum`]'s solvers, and why the rest were not.
//!
//! The two crates split on a real seam. `wiretap-checksum` answers *what
//! algorithm is this byte*; this one answers *is this byte a checksum at all*.
//! The second question is the cheaper one and, on a real bus, usually the one
//! that decides the answer — most links carry no checksum on most frame ids.

pub mod checksum;
pub mod columns;

pub use checksum::{checksum_evidence, solve_targets, ChecksumEvidence, Rejection};
pub use columns::{analyse_columns, ColumnStats};
