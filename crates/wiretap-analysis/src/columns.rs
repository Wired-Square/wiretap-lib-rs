//! Per-byte-column statistics over a set of payloads.
//!
//! Columns are indexed from the *end* of the payload, because that is where
//! checksums live and it is the only indexing that lines up across frames of
//! different lengths on one link.

use serde::Serialize;

/// What one byte column does across the sample.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ColumnStats {
    /// End-relative index: -1 is the last byte.
    pub position: i32,
    pub distinct_values: usize,
    pub min: u8,
    pub max: u8,
    /// Set when the column holds one value across every sampled payload.
    pub constant_value: Option<u8>,
    /// Consecutive payload pairs in which this byte differed.
    pub changes: usize,
    /// Consecutive payload pairs the column took part in.
    pub transitions: usize,
    /// Shannon entropy of the observed values, in bits. 8.0 is the most a byte
    /// can carry; a counter over 16 values reaches 4.0.
    pub entropy_bits: f64,
    pub sample_count: usize,
}

impl ColumnStats {
    /// Distinct values against the most this column could have shown, which is
    /// bounded by the sample count as well as by the 256 a byte can hold.
    pub fn distinct_ratio(&self) -> f64 {
        let ceiling = self.sample_count.min(256);
        if ceiling == 0 {
            return 0.0;
        }
        self.distinct_values as f64 / ceiling as f64
    }
}

/// Profile every column of `payloads`, end-relative, out to the longest payload.
///
/// Payloads too short to reach a column simply do not contribute to it, the same
/// rule the checksum sweep uses — a one-byte acknowledgement sharing a link is
/// not evidence about byte -8.
pub fn analyse_columns(payloads: &[Vec<u8>]) -> Vec<ColumnStats> {
    let depth = payloads.iter().map(|p| p.len()).max().unwrap_or(0);

    (1..=depth)
        .filter_map(|k| {
            let mut counts = [0usize; 256];
            let mut sample_count = 0usize;
            let mut previous: Option<u8> = None;
            let (mut changes, mut transitions) = (0usize, 0usize);

            for payload in payloads {
                let Some(&byte) = payload.len().checked_sub(k).and_then(|i| payload.get(i)) else {
                    // Too short for this column. It breaks the run of
                    // consecutive samples as well as contributing nothing —
                    // otherwise two payloads either side of a runt would read as
                    // adjacent.
                    previous = None;
                    continue;
                };

                counts[byte as usize] += 1;
                sample_count += 1;

                if let Some(prev) = previous {
                    transitions += 1;
                    if prev != byte {
                        changes += 1;
                    }
                }
                previous = Some(byte);
            }

            if sample_count == 0 {
                return None;
            }

            let observed: Vec<(u8, usize)> = counts
                .iter()
                .enumerate()
                .filter(|(_, n)| **n > 0)
                .map(|(value, n)| (value as u8, *n))
                .collect();

            let total = sample_count as f64;
            let entropy_bits = -observed
                .iter()
                .map(|(_, n)| {
                    let p = *n as f64 / total;
                    p * p.log2()
                })
                .sum::<f64>();

            Some(ColumnStats {
                position: -(k as i32),
                distinct_values: observed.len(),
                min: observed.first().map(|(v, _)| *v).unwrap_or(0),
                max: observed.last().map(|(v, _)| *v).unwrap_or(0),
                constant_value: (observed.len() == 1).then(|| observed[0].0),
                changes,
                transitions,
                entropy_bits,
                sample_count,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx(a: f64, b: f64) -> bool {
        (a - b).abs() < 1e-9
    }

    #[test]
    fn a_constant_column_carries_no_entropy() {
        let payloads: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i, 0x00]).collect();
        let columns = analyse_columns(&payloads);

        let last = columns.iter().find(|c| c.position == -1).unwrap();
        assert_eq!(last.constant_value, Some(0x00));
        assert_eq!(last.distinct_values, 1);
        assert_eq!(last.changes, 0);
        assert!(approx(last.entropy_bits, 0.0));
    }

    #[test]
    fn a_uniform_column_carries_its_full_bits() {
        // 256 values, each once: exactly 8 bits.
        let payloads: Vec<Vec<u8>> = (0..=255u8).map(|i| vec![i]).collect();
        let last = &analyse_columns(&payloads)[0];

        assert_eq!(last.distinct_values, 256);
        assert!(approx(last.entropy_bits, 8.0), "{}", last.entropy_bits);
        assert_eq!(last.changes, 255);
        assert_eq!(last.transitions, 255);
    }

    #[test]
    fn columns_are_end_relative_across_mixed_lengths() {
        let payloads = vec![vec![0x01, 0x02, 0xAA], vec![0x09, 0xAA], vec![0xAA]];
        let columns = analyse_columns(&payloads);

        let last = columns.iter().find(|c| c.position == -1).unwrap();
        assert_eq!(last.constant_value, Some(0xAA));
        assert_eq!(last.sample_count, 3);

        // Only the two longer payloads reach -2, and only the longest reaches -3.
        assert_eq!(
            columns
                .iter()
                .find(|c| c.position == -2)
                .unwrap()
                .sample_count,
            2
        );
        assert_eq!(
            columns
                .iter()
                .find(|c| c.position == -3)
                .unwrap()
                .sample_count,
            1
        );
    }

    /// A payload too short to reach a column must not make its neighbours look
    /// adjacent — that would invent a transition that never happened.
    #[test]
    fn a_short_payload_breaks_the_run_rather_than_joining_it() {
        let payloads = vec![vec![0x01, 0x11], vec![0x09], vec![0x01, 0x22]];
        let minus_two = analyse_columns(&payloads)
            .into_iter()
            .find(|c| c.position == -2)
            .unwrap();

        assert_eq!(minus_two.sample_count, 2);
        assert_eq!(minus_two.transitions, 0);
        assert_eq!(minus_two.changes, 0);
    }

    #[test]
    fn distinct_ratio_is_bounded_by_the_sample_count() {
        let payloads: Vec<Vec<u8>> = (0..4u8).map(|i| vec![i]).collect();
        let last = &analyse_columns(&payloads)[0];

        // Four distinct in four samples is saturated, not 4/256.
        assert!(approx(last.distinct_ratio(), 1.0));
    }
}
