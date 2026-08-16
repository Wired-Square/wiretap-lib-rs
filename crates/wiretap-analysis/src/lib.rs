//! Payload analysis for WireTAP frames.
//!
//! - [`checksum`] — the identification pass: which bytes are worth handing to
//!   [`wiretap_checksum`]'s solvers, and why the rest were not.
//! - [`scan`] — the orchestration over a whole capture: group by frame id,
//!   sample, identify, sweep, solve, rank.
//!
//! Per-byte-column statistics live in [`wiretap_checksum::columns`], beside the
//! end-relative addressing they are indexed by, and are re-exported here for
//! callers that only speak to this crate.
//!
//! `wiretap-checksum` answers *what algorithm is this byte*; this crate answers
//! the prior question — *is this byte a checksum at all* — and drives the scan
//! that puts the two together.
//!
//! **The split is thinner than it was.** Moving the orchestration in consumed
//! the seam: nothing outside this crate calls the identification pass any more,
//! and every type here composes a `wiretap-checksum` one. The two are better
//! read as one subject for now. Folding them, and giving this crate the byte-role
//! classifier instead, is the open question — see the milestone plan.

pub mod checksum;
pub mod scan;

pub use checksum::{
    checksum_evidence, checksum_evidence_with_columns, solve_targets, ChecksumEvidence,
    RankedTarget, Rejection,
};
pub use scan::{
    analyse_group, scan_frames, scan_groups, ChecksumScanOptions, ChecksumScanResult,
    DiscoveredChecksum, FrameChecksumFinding, FrameKey, DEFAULT_MIN_LIKENESS,
};
