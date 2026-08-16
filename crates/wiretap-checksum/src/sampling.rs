//! Choosing which frames to solve against.
//!
//! A periodic link repeats itself. Taking the first N frames off one CAN id can
//! hand the solver a hundred copies of the same payload — enough samples by
//! count, and almost no evidence. What a solver actually needs is payloads that
//! *differ*, because every candidate it tests is killed by a disagreement and
//! nothing else.

use std::collections::HashSet;

/// How many deduplicated payloads the farthest-point pass will consider, before
/// the pool is strided down to bound it at `MAX_POOL × limit` distance
/// computations.
///
/// Absolute, not a multiple of the limit. Striding is a blunt instrument — it
/// runs before the greedy pass and so can discard the outlier that would have
/// been the most informative pick — so it must not engage on a pool the greedy
/// pass could simply have handled.
const MAX_POOL: usize = 2048;

/// Number of differing bits between two payloads. Bytes past the shorter one
/// count as fully different, so a length difference reads as the large
/// distinction it is.
fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let common: u32 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum();
    common + (a.len().abs_diff(b.len()) as u32) * 8
}

/// Keep one of each distinct payload, in first-seen order.
pub fn deduplicate(frames: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut seen: HashSet<&[u8]> = HashSet::new();
    frames
        .iter()
        .filter(|f| !f.is_empty() && seen.insert(f.as_slice()))
        .cloned()
        .collect()
}

/// Up to `limit` payloads chosen to differ from each other as much as possible.
///
/// Deduplicates first — repeats carry no information a solver can use — then, if
/// still over the limit, strides the pool down and runs greedy farthest-point
/// selection on what is left. The first frame is always kept, so a caller
/// eyeballing the result recognises where it came from.
pub fn diverse_samples(frames: &[Vec<u8>], limit: usize) -> Vec<Vec<u8>> {
    let distinct = deduplicate(frames);
    if limit == 0 || distinct.len() <= limit {
        return distinct;
    }

    // Stride rather than truncate: the deduplicated set is in arrival order, so
    // taking a prefix would confine the pool to the start of the capture.
    let pool: Vec<Vec<u8>> = if distinct.len() > MAX_POOL {
        let stride = distinct.len().div_ceil(MAX_POOL);
        distinct.into_iter().step_by(stride).collect()
    } else {
        distinct
    };

    let mut chosen = vec![pool[0].clone()];
    // Distance from each pool entry to the nearest already-chosen payload,
    // maintained incrementally so each round is one pass, not a re-scan.
    let mut nearest: Vec<u32> = pool.iter().map(|f| hamming_distance(f, &pool[0])).collect();

    while chosen.len() < limit {
        let Some((next, _)) = nearest
            .iter()
            .enumerate()
            .max_by_key(|(_, d)| **d)
            .filter(|(_, d)| **d > 0)
        else {
            break;
        };

        chosen.push(pool[next].clone());
        for (i, entry) in pool.iter().enumerate() {
            nearest[i] = nearest[i].min(hamming_distance(entry, &pool[next]));
        }
    }

    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deduplicate_keeps_first_occurrence_order() {
        let frames = vec![vec![1, 2], vec![3, 4], vec![1, 2], vec![5, 6]];
        assert_eq!(
            deduplicate(&frames),
            vec![vec![1, 2], vec![3, 4], vec![5, 6]]
        );
    }

    #[test]
    fn test_deduplicate_drops_empty_frames() {
        assert_eq!(deduplicate(&[vec![], vec![1]]), vec![vec![1]]);
    }

    /// The case this exists for: a periodic link where the first hundred frames
    /// are two payloads alternating.
    #[test]
    fn test_diverse_samples_collapses_a_repeating_link() {
        let frames: Vec<Vec<u8>> = [vec![0xAAu8, 0x01], vec![0x55, 0x02]]
            .into_iter()
            .cycle()
            .take(500)
            .collect();

        assert_eq!(diverse_samples(&frames, 200).len(), 2);
    }

    #[test]
    fn test_diverse_samples_returns_everything_under_the_limit() {
        let frames: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i, i]).collect();
        assert_eq!(diverse_samples(&frames, 200).len(), 10);
    }

    /// Greedy farthest-point should reach for the opposite corners first, not
    /// simply take the first `limit` entries.
    #[test]
    fn test_diverse_samples_prefers_distant_payloads() {
        let mut frames: Vec<Vec<u8>> = (0..64u8).map(|i| vec![i, 0x00]).collect();
        frames.push(vec![0xFF, 0xFF]);

        let chosen = diverse_samples(&frames, 3);
        assert_eq!(chosen.len(), 3);
        assert_eq!(chosen[0], vec![0x00, 0x00]);
        assert!(
            chosen.contains(&vec![0xFF, 0xFF]),
            "the outlier is the most informative sample and was dropped: {chosen:?}"
        );
    }

    #[test]
    fn test_diverse_samples_honours_the_limit_on_a_large_pool() {
        let frames: Vec<Vec<u8>> = (0..5000u32).map(|i| i.to_le_bytes().to_vec()).collect();

        assert_eq!(diverse_samples(&frames, 50).len(), 50);
    }

    #[test]
    fn test_hamming_distance_counts_length_as_difference() {
        assert_eq!(hamming_distance(&[0x00], &[0xFF]), 8);
        assert_eq!(hamming_distance(&[0x00], &[0x00, 0x00]), 8);
        assert_eq!(hamming_distance(&[0x0F], &[0x0F]), 0);
    }
}
