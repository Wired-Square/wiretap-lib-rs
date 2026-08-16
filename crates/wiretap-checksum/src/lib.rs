//! Checksum algorithms and a scored detection engine for WireTAP frames.
//!
//! - [`algorithms`] — the eleven named algorithms plus parameterised CRC-8/16.
//!   Bytes in, value out; nothing here knows about frames.
//! - [`frame`] — end-relative byte addressing, reading a stored checksum out of
//!   a frame, and validating one against the other.
//! - [`spec`] — [`ChecksumSpec`], one point in the candidate space, and the
//!   grouped sweep that measures many specs against many frames.
//! - [`detect`] — the engine: build the candidate space from column priors,
//!   sweep it, score and rank what survives, and explain the verdict.
//! - [`notes`] — the translatable note type every explanation crosses as.
//!
//! Offsets are end-relative throughout (a negative index counts from the end),
//! because that is the only way frames of different lengths on one link line up.
//! A one-byte acknowledgement sharing a link with 20-byte payload frames is the
//! case that breaks length assumptions, and it is a real capture, not a corner.

pub mod algorithms;
pub mod detect;
pub mod frame;
pub mod notes;
pub mod sampling;
pub mod solve;
pub mod spec;

#[cfg(test)]
mod testing;

pub use algorithms::{
    calculate_checksum_simple, crc16_parameterised, crc8_parameterised, ChecksumAlgorithm,
    ALL_ALGORITHMS,
};
pub use detect::{
    analyse_tail_columns, build_checksum_specs, detect_checksum, CalcRange, ChecksumCandidate,
    ChecksumColumnStat, ChecksumDetectionOptions, ChecksumDetectionResult, MAX_SAMPLES,
    MIN_TAIL_DEPTH,
};
pub use frame::{
    calculate_checksum, extract_checksum, resolve_byte_index, validate_checksum,
    ChecksumValidationResult,
};
pub use notes::ChecksumNote;
pub use sampling::{deduplicate, diverse_samples};
pub use solve::{
    solve_additive, solve_crc, AdditiveOp, CrcAlternative, CrcParameters, CrcSolveOptions,
    SolveTarget, SolvedChecksum, SolvedKind,
};
pub use spec::{sweep_specs, ChecksumSpec, ChecksumSpecResult};
