//! The detection engine: sweep a candidate space, score each candidate with a
//! composite confidence, return them ranked with notes explaining the verdict.
//!
//! This lives beside the algorithms rather than in the caller so there is exactly
//! one implementation of each — an earlier split put the scoring on the far side
//! of an IPC boundary and needed a hand-maintained copy of all eleven algorithms
//! just to test it.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::algorithms::{ChecksumAlgorithm, ALL_ALGORITHMS};
use crate::frame::resolve_byte_index;
use crate::notes::ChecksumNote;
use crate::spec::{sweep_specs, ChecksumSpec};

/// How many end-relative byte columns to profile, at minimum. The priors have to
/// reach every position being swept — a candidate past the profiled depth would
/// silently skip the constant-column rejection the whole design rests on.
pub const MIN_TAIL_DEPTH: i32 = 4;

/// Below this many samples, a constant column is not yet evidence of padding.
const CONSTANT_COLUMN_MIN_SAMPLES: usize = 8;

/// Cap on the returned candidate list.
const MAX_CANDIDATES: usize = 12;

/// Frames sampled for detection. The dialog reads the same number from the
/// capture, so both halves measure against one set.
pub const MAX_SAMPLES: usize = 200;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ChecksumDetectionOptions {
    /// Checksum offsets to try, end-relative.
    pub positions: Vec<i32>,
    /// Restrict to checksums of these byte lengths. Empty means both.
    pub lengths: Vec<usize>,
    /// Byte offsets just past a declared header field, from the view's ID/Source
    /// chips. These widen the calculation-range candidates and earn a small
    /// confidence bonus; they never narrow the search.
    pub header_boundaries: Vec<i32>,
    /// Percentage below which a candidate is discarded.
    pub min_match_rate: f64,
    /// Confidence below which a candidate is discarded.
    pub min_confidence: u8,
}

impl Default for ChecksumDetectionOptions {
    fn default() -> Self {
        Self {
            positions: vec![-1, -2, -3],
            lengths: Vec::new(),
            header_boundaries: Vec::new(),
            min_match_rate: 50.0,
            min_confidence: 35,
        }
    }
}

/// What one end-relative byte column looks like across the sample. This is the
/// structural evidence behind the priors: a column that never changes cannot be
/// a checksum, and one that takes many values probably is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumColumnStat {
    /// Negative index, e.g. -1 for the last byte.
    pub position: i32,
    pub distinct_values: usize,
    /// Set when the column holds one value across every sampled frame.
    pub constant_value: Option<u8>,
    pub sample_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CalcRange {
    pub calc_start_byte: i32,
    pub calc_end_byte: i32,
}

/// A checksum configuration that reproduces some or all of the sampled frames.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumCandidate {
    pub algorithm: ChecksumAlgorithm,
    pub position: i32,
    pub length: usize,
    pub big_endian: bool,
    pub calc_start_byte: i32,
    pub calc_end_byte: i32,
    pub match_count: usize,
    pub total_count: usize,
    /// 0-100
    pub match_rate: f64,
    /// 0-100 composite score.
    pub confidence: u8,
    pub notes: Vec<ChecksumNote>,
    /// Other calculation ranges that scored identically. Kept rather than
    /// dropped, so a user who disagrees with the winner can see the alternatives.
    pub equivalent_ranges: Vec<CalcRange>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumDetectionResult {
    pub candidates: Vec<ChecksumCandidate>,
    pub best_candidate: Option<ChecksumCandidate>,
    pub tail_columns: Vec<ChecksumColumnStat>,
    /// Result-level explanation, including why nothing was found.
    pub notes: Vec<ChecksumNote>,
}

/// Profile the last `depth` byte columns (at least [`MIN_TAIL_DEPTH`]),
/// end-relative so frames of different lengths line up. Frames too short for a
/// column do not contribute.
pub fn analyse_tail_columns(frames: &[Vec<u8>], depth: i32) -> Vec<ChecksumColumnStat> {
    (1..=depth.max(MIN_TAIL_DEPTH))
        .filter_map(|k| {
            let mut values = BTreeSet::new();
            let mut sample_count = 0usize;
            for frame in frames {
                if frame.len() < k as usize {
                    continue;
                }
                values.insert(frame[frame.len() - k as usize]);
                sample_count += 1;
            }
            (sample_count > 0).then(|| ChecksumColumnStat {
                position: -k,
                distinct_values: values.len(),
                constant_value: (values.len() == 1).then(|| *values.iter().next().unwrap()),
                sample_count,
            })
        })
        .collect()
}

fn column_at(columns: &[ChecksumColumnStat], position: i32) -> Option<&ChecksumColumnStat> {
    columns.iter().find(|c| c.position == position)
}

/// Number of constant columns sitting immediately before `position`.
fn constant_run_before(position: i32, columns: &[ChecksumColumnStat]) -> i32 {
    let mut run = 0;
    let mut p = position - 1;
    while let Some(column) = column_at(columns, p) {
        if column.constant_value.is_none() {
            break;
        }
        run += 1;
        p -= 1;
    }
    run
}

/// Enumerate the configurations worth testing.
///
/// Length is not a free axis — the algorithm fixes it — so the space is
/// (algorithm × position) × calcStart × calcEnd × endianness, which stays in the
/// low hundreds rather than the thousands.
pub fn build_checksum_specs(
    frames: &[Vec<u8>],
    options: &ChecksumDetectionOptions,
    columns: &[ChecksumColumnStat],
) -> Vec<ChecksumSpec> {
    // The longest frame, not the shortest. Feasibility here asks "can any frame
    // carry this configuration", because `sweep_specs` already excludes the
    // frames that individually cannot. Asking it of the shortest frame instead
    // lets one runt — a bare one-byte acknowledgement sharing the link — empty
    // the entire search space.
    let max_length = frames.iter().map(|f| f.len()).max().unwrap_or(0);

    // `1` is not arbitrary: a leading type/ID byte excluded from the calculation
    // is a common shape, and it is the one the declared-header hints cannot
    // supply when a field starts at byte 0. Starts that overrun the frame are
    // left to the degenerate-range check below rather than filtered here.
    let calc_starts: BTreeSet<i32> = [0, 1, 2]
        .iter()
        .chain(options.header_boundaries.iter())
        .copied()
        .filter(|s| *s >= 0)
        .collect();

    // Runs are per position, and every algorithm at a position shares them.
    let calc_ends: HashMap<i32, Vec<i32>> = options
        .positions
        .iter()
        .map(|p| {
            let run = constant_run_before(*p, columns);
            let ends: Vec<i32> = if run > 0 {
                vec![*p, *p - run]
            } else {
                vec![*p]
            };
            (*p, ends)
        })
        .collect();

    let mut specs = Vec::new();

    for algorithm in ALL_ALGORITHMS {
        let byte_length = algorithm.output_bytes();
        if !options.lengths.is_empty() && !options.lengths.contains(&byte_length) {
            continue;
        }
        // The checksum, plus at least one byte to calculate over, has to fit
        // inside a frame.
        if max_length < byte_length + 1 {
            continue;
        }
        // Endianness only means something for a multi-byte checksum.
        let endiannesses: &[bool] = if byte_length == 2 {
            &[false, true]
        } else {
            &[true]
        };

        for position in &options.positions {
            // The checksum must not overrun the end of the frame.
            if position + byte_length as i32 > 0 {
                continue;
            }

            for calc_end_byte in &calc_ends[position] {
                for calc_start_byte in &calc_starts {
                    // Degenerate for every frame: an end-relative range is at
                    // its widest in the longest frame, so if even that one has
                    // nothing to calculate over, none of them do.
                    if resolve_byte_index(*calc_end_byte, max_length) <= *calc_start_byte as usize {
                        continue;
                    }
                    for big_endian in endiannesses {
                        specs.push(ChecksumSpec {
                            algorithm,
                            position: *position,
                            byte_length,
                            big_endian: *big_endian,
                            calc_start_byte: *calc_start_byte,
                            calc_end_byte: *calc_end_byte,
                        });
                    }
                }
            }
        }
    }

    specs
}

struct ScoringContext<'a> {
    columns: &'a [ChecksumColumnStat],
    header_boundaries: &'a [i32],
    frames: &'a [Vec<u8>],
}

/// The narrowest range this configuration ever actually calculates over, across
/// the frames it fits. Frames it does not fit are excluded here for the same
/// reason `sweep_specs` excludes them: they are not evidence about this spec.
fn narrowest_calc_span(spec: &ChecksumSpec, frames: &[Vec<u8>]) -> usize {
    frames
        .iter()
        .filter_map(|frame| {
            let len = frame.len();
            let start = resolve_byte_index(spec.calc_start_byte, len).min(len);
            let end = resolve_byte_index(spec.calc_end_byte, len).min(len);
            (start < end).then(|| end - start)
        })
        .min()
        .unwrap_or(0)
}

/// Score one swept configuration, or reject it.
///
/// Additive tiers plus corroboration bonuses and suspicion penalties. The
/// rejections matter as much as the score: an XOR or sum over an all-zero range
/// yields zero, which "matches" a constant 0x00 padding column perfectly and
/// would otherwise outrank the real answer.
fn score_candidate(
    spec: &ChecksumSpec,
    match_count: usize,
    total_count: usize,
    ctx: &ScoringContext,
) -> Option<ChecksumCandidate> {
    let match_rate = match_count as f64 / total_count as f64 * 100.0;
    let column = column_at(ctx.columns, spec.position);

    // A constant column is padding, not a checksum — however well it matches.
    if let Some(column) = column {
        if column.constant_value.is_some() && column.sample_count >= CONSTANT_COLUMN_MIN_SAMPLES {
            return None;
        }
    }

    let mut notes: Vec<ChecksumNote> = Vec::new();
    let mut score: i32 = 0;

    if match_rate >= 100.0 {
        score += 55;
        notes.push(ChecksumNote::new(
            "matchesAll",
            &[("count", total_count.into())],
        ));
    } else {
        score += if match_rate >= 99.0 {
            48
        } else if match_rate >= 95.0 {
            40
        } else if match_rate >= 80.0 {
            25
        } else {
            10
        };
        notes.push(ChecksumNote::new(
            "matchesSome",
            &[
                ("matched", match_count.into()),
                ("total", total_count.into()),
            ],
        ));
    }

    if total_count >= 200 {
        score += 20;
    } else if total_count >= 50 {
        score += 15;
    } else if total_count >= 20 {
        score += 10;
    } else if total_count >= 8 {
        score += 5;
    } else {
        notes.push(ChecksumNote::new(
            "fewSamples",
            &[("count", total_count.into())],
        ));
    }

    // A real checksum column varies. This is the same class of check as the
    // 0xC0-frequency test in the framing detector: cheap, structural, decisive.
    if let Some(column) = column {
        let span = column
            .sample_count
            .min(if spec.byte_length == 2 { 65536 } else { 256 });
        let distinct_ratio = column.distinct_values as f64 / span as f64;
        if distinct_ratio >= 0.5 {
            score += 15;
            notes.push(ChecksumNote::new(
                "columnVaries",
                &[
                    ("distinct", column.distinct_values.into()),
                    ("samples", column.sample_count.into()),
                ],
            ));
        } else if distinct_ratio >= 0.2 {
            score += 8;
        } else if distinct_ratio < 0.05 {
            score -= 30;
            notes.push(ChecksumNote::new(
                "columnNearlyConstant",
                &[("distinct", column.distinct_values.into())],
            ));
        }
    }

    if spec.calc_end_byte == spec.position {
        score += 10;
    }

    if ctx.header_boundaries.contains(&spec.calc_start_byte) {
        score += 5;
        notes.push(ChecksumNote::new(
            "startsAfterHeader",
            &[("byte", spec.calc_start_byte.into())],
        ));
    }

    if spec.calc_end_byte < spec.position {
        if let Some(value) =
            column_at(ctx.columns, spec.calc_end_byte).and_then(|c| c.constant_value)
        {
            score += 5;
            notes.push(ChecksumNote::new(
                "constantExcluded",
                &[("value", format!("0x{value:02X}").into())],
            ));
        }
    }

    // A short calculated range is matched by chance far too easily.
    if narrowest_calc_span(spec, ctx.frames) < 2 {
        score -= 15;
        notes.push(ChecksumNote::new("shortRange", &[]));
    }

    // A 2-byte column whose high byte never moves is really a 1-byte checksum.
    if spec.byte_length == 2 {
        let high = if spec.big_endian {
            spec.position
        } else {
            spec.position + 1
        };
        if column_at(ctx.columns, high).is_some_and(|c| c.constant_value.is_some()) {
            score -= 10;
            notes.push(ChecksumNote::new("highByteConstant", &[]));
        }
    }

    Some(ChecksumCandidate {
        algorithm: spec.algorithm,
        position: spec.position,
        length: spec.byte_length,
        big_endian: spec.big_endian,
        calc_start_byte: spec.calc_start_byte,
        calc_end_byte: spec.calc_end_byte,
        match_count,
        total_count,
        match_rate,
        confidence: score.clamp(0, 100) as u8,
        notes,
        equivalent_ranges: Vec::new(),
    })
}

fn algorithm_rank(algorithm: ChecksumAlgorithm) -> usize {
    ALL_ALGORITHMS
        .iter()
        .position(|a| *a == algorithm)
        .unwrap_or(ALL_ALGORITHMS.len())
}

/// Confidence, then match rate, then parsimony: simpler explanations first.
fn compare_candidates(a: &ChecksumCandidate, b: &ChecksumCandidate) -> std::cmp::Ordering {
    b.confidence
        .cmp(&a.confidence)
        .then_with(|| b.match_rate.total_cmp(&a.match_rate))
        .then_with(|| a.length.cmp(&b.length))
        .then_with(|| a.calc_start_byte.cmp(&b.calc_start_byte))
        .then_with(|| algorithm_rank(a.algorithm).cmp(&algorithm_rank(b.algorithm)))
}

/// Rank, then fold configurations that differ only in calculation range into the
/// winner's `equivalent_ranges`.
///
/// Keying on the algorithm as well as the geometry keeps genuinely different
/// explanations visible while still collapsing the noise.
fn collapse_equivalent(mut candidates: Vec<ChecksumCandidate>) -> Vec<ChecksumCandidate> {
    candidates.sort_by(compare_candidates);

    let mut kept: Vec<ChecksumCandidate> = Vec::new();
    for candidate in candidates {
        let key = |c: &ChecksumCandidate| (c.algorithm, c.position, c.length, c.big_endian);
        match kept.iter_mut().find(|k| key(k) == key(&candidate)) {
            Some(winner) => {
                if winner.match_rate == candidate.match_rate {
                    winner.equivalent_ranges.push(CalcRange {
                        calc_start_byte: candidate.calc_start_byte,
                        calc_end_byte: candidate.calc_end_byte,
                    });
                }
            }
            None => kept.push(candidate),
        }
    }
    kept
}

/// Say why the search came up empty. A silent 0% reads as "your data is wrong";
/// naming what was looked at and what the tail actually looks like points at the
/// next thing to try.
fn explain_no_candidates(last: &ChecksumColumnStat, frame_count: usize) -> ChecksumNote {
    match last.constant_value {
        Some(value) => ChecksumNote::new(
            "noneLastByteConstant",
            &[
                ("value", format!("0x{value:02X}").into()),
                ("frames", frame_count.into()),
            ],
        ),
        None => ChecksumNote::new(
            "noneButLastByteVaries",
            &[
                ("distinct", last.distinct_values.into()),
                ("frames", frame_count.into()),
            ],
        ),
    }
}

/// Report constant tail columns as runs rather than one note each.
///
/// An all-zero frame profiles four constant columns and produced four lines
/// saying the same thing in different words. Only columns sharing a value join a
/// run — `0x00` beside `0xFF` is two facts, not one.
fn constant_padding_notes(columns: &[ChecksumColumnStat]) -> Vec<ChecksumNote> {
    let padding: Vec<&ChecksumColumnStat> = columns
        .iter()
        .filter(|c| c.sample_count >= CONSTANT_COLUMN_MIN_SAMPLES)
        .collect();

    let mut notes = Vec::new();
    let mut index = 0;

    while index < padding.len() {
        let Some(value) = padding[index].constant_value else {
            index += 1;
            continue;
        };

        // Columns arrive -1, -2, -3…, so a run is contiguous in this order.
        let start = index;
        while index + 1 < padding.len()
            && padding[index + 1].constant_value == Some(value)
            && padding[index + 1].position == padding[index].position - 1
        {
            index += 1;
        }

        let hex = format!("0x{value:02X}");
        notes.push(if index > start {
            ChecksumNote::new(
                "constantPaddingRun",
                &[
                    ("from", padding[index].position.into()),
                    ("to", padding[start].position.into()),
                    ("value", hex.into()),
                ],
            )
        } else {
            ChecksumNote::new(
                "constantPadding",
                &[
                    ("position", padding[start].position.into()),
                    ("value", hex.into()),
                ],
            )
        });
        index += 1;
    }

    notes
}

/// Find the checksum configurations that best explain a set of frames.
pub fn detect_checksum(
    frames: &[Vec<u8>],
    options: &ChecksumDetectionOptions,
) -> ChecksumDetectionResult {
    let samples: Vec<Vec<u8>> = frames
        .iter()
        .filter(|f| !f.is_empty())
        .take(MAX_SAMPLES)
        .cloned()
        .collect();

    if samples.is_empty() {
        return ChecksumDetectionResult {
            candidates: Vec::new(),
            best_candidate: None,
            tail_columns: Vec::new(),
            notes: vec![ChecksumNote::new("noFrames", &[])],
        };
    }

    let min_length = samples.iter().map(|f| f.len()).min().unwrap_or(0);
    let max_length = samples.iter().map(|f| f.len()).max().unwrap_or(0);
    // Profile at least as deep as the deepest position being swept.
    let depth = -options.positions.iter().copied().min().unwrap_or(-1);
    let tail_columns = analyse_tail_columns(&samples, depth);

    let mut notes = vec![ChecksumNote::new(
        "analysed",
        &[
            ("frames", samples.len().into()),
            ("minLength", min_length.into()),
            ("maxLength", max_length.into()),
        ],
    )];
    notes.extend(constant_padding_notes(&tail_columns));

    let specs = build_checksum_specs(&samples, options, &tail_columns);
    let results = sweep_specs(&samples, &specs);

    notes.push(ChecksumNote::new(
        "configurationsTested",
        &[
            ("specs", specs.len().into()),
            ("algorithms", ALL_ALGORITHMS.len().into()),
        ],
    ));

    let ctx = ScoringContext {
        columns: &tail_columns,
        header_boundaries: &options.header_boundaries,
        frames: &samples,
    };

    let scored: Vec<ChecksumCandidate> = results
        .iter()
        .filter(|r| r.match_count as f64 / r.total_count as f64 * 100.0 >= options.min_match_rate)
        .filter_map(|r| score_candidate(&specs[r.spec_index], r.match_count, r.total_count, &ctx))
        .collect();

    let mut candidates = collapse_equivalent(scored);
    candidates.retain(|c| c.confidence >= options.min_confidence);
    candidates.truncate(MAX_CANDIDATES);

    // Non-empty samples always yield a -1 column, so there is always something to
    // say about the byte a checksum would most likely occupy.
    if let (true, Some(last)) = (candidates.is_empty(), column_at(&tail_columns, -1)) {
        notes.push(explain_no_candidates(last, samples.len()));
    }

    ChecksumDetectionResult {
        best_candidate: candidates.first().cloned(),
        candidates,
        tail_columns,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{
        many_real_frames, modbus_frames, real_serial_frames, real_serial_frames_with_acks,
    };
    use serde_json::json;

    /// Default profiling depth, matching what `detect_checksum` uses for the
    /// default positions.
    fn tail_columns(frames: &[Vec<u8>]) -> Vec<ChecksumColumnStat> {
        analyse_tail_columns(frames, MIN_TAIL_DEPTH)
    }

    fn note_codes(notes: &[ChecksumNote]) -> Vec<&str> {
        notes.iter().map(|n| n.code.as_str()).collect()
    }

    // ---- The reported bug -------------------------------------------------

    #[test]
    fn test_detect_finds_sum8_over_the_real_capture() {
        // The dialog used to seed CRC-16 Modbus at -2 and report 0/20 here.
        let result = detect_checksum(&many_real_frames(), &Default::default());
        let best = result.best_candidate.expect("a candidate");

        assert_eq!(best.algorithm, ChecksumAlgorithm::Sum8);
        assert_eq!(best.position, -1);
        assert_eq!(best.length, 1);
        assert_eq!(best.calc_start_byte, 1);
        assert_eq!(best.calc_end_byte, -1);
        assert_eq!(best.match_rate, 100.0);
    }

    #[test]
    fn test_detect_finds_sum8_despite_one_byte_acknowledgements() {
        // The shortest frame on the link must not gate the search: a bare ACK
        // cannot hold a checksum, and the frames that can still deserve one.
        let frames = real_serial_frames_with_acks();
        let specs = build_checksum_specs(&frames, &Default::default(), &tail_columns(&frames));
        assert!(!specs.is_empty(), "the ACKs emptied the search space");

        let best = detect_checksum(&frames, &Default::default())
            .best_candidate
            .expect("a candidate");
        assert_eq!(best.algorithm, ChecksumAlgorithm::Sum8);
        assert_eq!(best.position, -1);
        assert_eq!(best.calc_start_byte, 1);
        assert_eq!(best.calc_end_byte, -1);
        assert_eq!(best.match_rate, 100.0);
        // The acknowledgements are excluded from the denominator, not counted
        // as misses against a checksum they were never going to carry.
        assert_eq!(best.total_count, 72);
    }

    /// Adjacent constant columns sharing a value are one fact, not four. The
    /// fixture pads bytes -4 through -2 with zeros, so that is one note.
    #[test]
    fn test_detect_reports_constant_padding_as_a_single_run() {
        let result = detect_checksum(&many_real_frames(), &Default::default());

        let minus_two = result
            .tail_columns
            .iter()
            .find(|c| c.position == -2)
            .unwrap();
        assert_eq!(minus_two.constant_value, Some(0x00));

        let padding: Vec<&ChecksumNote> = result
            .notes
            .iter()
            .filter(|n| n.code.starts_with("constantPadding"))
            .collect();

        assert_eq!(padding.len(), 1, "{padding:?}");
        assert_eq!(padding[0].code, "constantPaddingRun");
        assert_eq!(padding[0].values["from"], json!(-4));
        assert_eq!(padding[0].values["to"], json!(-2));
    }

    /// A lone constant column still reads as one, not as a run of one.
    #[test]
    fn test_detect_reports_a_single_constant_column_without_a_range() {
        // Byte -2 is constant; -1 and -3 vary, so it cannot join a run.
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| vec![0x10, (i * 7) as u8, (i * 13) as u8, 0xAA, (i * 3) as u8])
            .collect();
        let result = detect_checksum(&frames, &Default::default());

        let padding: Vec<&ChecksumNote> = result
            .notes
            .iter()
            .filter(|n| n.code.starts_with("constantPadding"))
            .collect();

        assert_eq!(padding.len(), 1, "{padding:?}");
        assert_eq!(padding[0].code, "constantPadding");
        assert_eq!(padding[0].values["position"], json!(-2));
    }

    /// Different constants are different facts, so they must not merge.
    #[test]
    fn test_detect_does_not_merge_constant_columns_of_different_values() {
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| vec![0x10, (i * 7) as u8, 0xFF, 0x00, (i * 3) as u8])
            .collect();
        let result = detect_checksum(&frames, &Default::default());

        let padding: Vec<&ChecksumNote> = result
            .notes
            .iter()
            .filter(|n| n.code.starts_with("constantPadding"))
            .collect();

        assert_eq!(padding.len(), 2, "{padding:?}");
        assert!(padding.iter().all(|n| n.code == "constantPadding"));
    }

    #[test]
    fn test_detect_ranks_a_coincidental_match_below_the_real_answer() {
        // XOR over the same range reproduces one frame in five by chance, which
        // is why a raw match count is not on its own evidence.
        let result = detect_checksum(&many_real_frames(), &Default::default());
        let best = result.best_candidate.clone().unwrap();

        assert_eq!(best.algorithm, ChecksumAlgorithm::Sum8);
        for candidate in &result.candidates {
            if candidate.algorithm == ChecksumAlgorithm::Xor {
                assert!(candidate.confidence < best.confidence);
            }
        }
    }

    // ---- Priors and rejections -------------------------------------------

    #[test]
    fn test_detect_rejects_a_constant_checksum_column() {
        // Every frame ends 0x00 and the body is all zeros, so XOR and sum both
        // "match" perfectly — but the column is padding, not a checksum.
        let frames: Vec<Vec<u8>> = (0..40u8).map(|i| vec![0x01, i, 0x00, 0x00, 0x00]).collect();
        let result = detect_checksum(&frames, &Default::default());
        assert!(result.candidates.iter().all(|c| c.position != -1));
    }

    #[test]
    fn test_detect_explains_itself_when_nothing_matches() {
        let frames: Vec<Vec<u8>> = (0..40u32)
            .map(|i| vec![0x10, 0x20, i as u8, (i * 37 + 11) as u8])
            .collect();
        let result = detect_checksum(&frames, &Default::default());

        assert!(result.candidates.is_empty());
        assert!(note_codes(&result.notes).contains(&"noneButLastByteVaries"));
    }

    #[test]
    fn test_detect_says_so_when_there_are_no_frames() {
        let result = detect_checksum(&[], &Default::default());
        assert_eq!(note_codes(&result.notes), vec!["noFrames"]);
        assert!(result.best_candidate.is_none());
    }

    #[test]
    fn test_analyse_tail_columns_is_end_relative() {
        let columns = tail_columns(&real_serial_frames());

        let last = columns.iter().find(|c| c.position == -1).unwrap();
        assert_eq!(last.distinct_values, 4);
        assert_eq!(last.sample_count, 5);
        assert_eq!(
            columns
                .iter()
                .find(|c| c.position == -2)
                .unwrap()
                .constant_value,
            Some(0x00)
        );
    }

    #[test]
    fn test_analyse_tail_columns_skips_frames_too_short() {
        let columns = tail_columns(&[vec![1, 2, 3, 4], vec![9]]);
        assert_eq!(
            columns
                .iter()
                .find(|c| c.position == -1)
                .unwrap()
                .sample_count,
            2
        );
        assert_eq!(
            columns
                .iter()
                .find(|c| c.position == -4)
                .unwrap()
                .sample_count,
            1
        );
    }

    // ---- Candidate space --------------------------------------------------

    #[test]
    fn test_build_specs_includes_the_configuration_the_old_sweep_could_not_express() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions::default();
        let specs = build_checksum_specs(&frames, &options, &tail_columns(&frames));

        assert!(specs.iter().any(|s| s.algorithm == ChecksumAlgorithm::Sum8
            && s.position == -1
            && s.calc_start_byte == 1
            && s.calc_end_byte == -1));
    }

    #[test]
    fn test_build_specs_tries_both_endiannesses_only_for_two_byte_algorithms() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions::default();
        let specs = build_checksum_specs(&frames, &options, &tail_columns(&frames));

        let crc16: BTreeSet<bool> = specs
            .iter()
            .filter(|s| s.algorithm == ChecksumAlgorithm::Crc16Modbus)
            .map(|s| s.big_endian)
            .collect();
        assert_eq!(crc16, BTreeSet::from([false, true]));

        let sum8: BTreeSet<bool> = specs
            .iter()
            .filter(|s| s.algorithm == ChecksumAlgorithm::Sum8)
            .map(|s| s.big_endian)
            .collect();
        assert_eq!(sum8, BTreeSet::from([true]));
    }

    #[test]
    fn test_build_specs_widens_with_header_hints_without_narrowing() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions {
            header_boundaries: vec![4],
            ..Default::default()
        };
        let specs = build_checksum_specs(&frames, &options, &tail_columns(&frames));

        assert!(specs.iter().any(|s| s.calc_start_byte == 4));
        // The real answer starts at byte 1, which is not a declared boundary —
        // hints must never replace the defaults.
        assert!(specs.iter().any(|s| s.calc_start_byte == 1));
    }

    #[test]
    fn test_build_specs_honours_a_length_restriction() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions {
            lengths: vec![1],
            ..Default::default()
        };
        let specs = build_checksum_specs(&frames, &options, &tail_columns(&frames));

        assert!(!specs.is_empty());
        assert!(specs.iter().all(|s| s.byte_length == 1));
    }

    #[test]
    fn test_build_specs_stays_within_a_sane_search_size() {
        let frames = real_serial_frames();
        let options = ChecksumDetectionOptions::default();
        let specs = build_checksum_specs(&frames, &options, &tail_columns(&frames));

        assert!(specs.len() > 50, "{} specs", specs.len());
        assert!(specs.len() < 400, "{} specs", specs.len());
    }

    // ---- Endianness, lengths, ranges --------------------------------------

    #[test]
    fn test_detect_distinguishes_a_little_endian_crc16() {
        // The TS sweep this replaced hardcoded big-endian, so a Modbus CRC was
        // undiscoverable on that path.
        let result = detect_checksum(&modbus_frames(), &Default::default());
        let best = result.best_candidate.expect("a candidate");

        assert_eq!(best.algorithm, ChecksumAlgorithm::Crc16Modbus);
        assert!(!best.big_endian);
        assert_eq!(best.position, -2);
        assert_eq!(best.length, 2);
        assert_eq!(best.match_rate, 100.0);
    }

    #[test]
    fn test_detect_keeps_an_equally_scoring_range_as_an_alternative() {
        // [1:-1] and [1:-2] both reproduce the frames, since byte -2 is zero.
        let result = detect_checksum(&many_real_frames(), &Default::default());
        let best = result.best_candidate.unwrap();

        assert_eq!(best.calc_end_byte, -1);
        assert!(!best.equivalent_ranges.is_empty());
    }

    #[test]
    fn test_detect_resolves_positions_across_mixed_frame_lengths() {
        // The fixture mixes 16- and 20-byte frames, so a candidate matching every
        // one of them proves the position resolved per frame, not per capture.
        let frames = many_real_frames();
        assert_eq!(frames.iter().map(|f| f.len()).min(), Some(16));
        assert_eq!(frames.iter().map(|f| f.len()).max(), Some(20));

        let result = detect_checksum(&frames, &Default::default());
        assert_eq!(result.best_candidate.unwrap().total_count, frames.len());
    }

    #[test]
    fn test_detect_caps_the_sample() {
        // 600 frames in, MAX_SAMPLES out — the dialog reads the same number from
        // the capture so both halves measure against one set.
        let many: Vec<Vec<u8>> = real_serial_frames().into_iter().cycle().take(600).collect();
        let result = detect_checksum(&many, &Default::default());
        assert_eq!(result.best_candidate.unwrap().total_count, MAX_SAMPLES);
    }
}
