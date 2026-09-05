# wiretap-checksum

Checksum algorithms and the scored detection engine of the
[`wiretap-lib`](../../) workspace. Given frames off a link, it answers *which
checksum configuration explains these bytes* — and says why when nothing does.

## What's here

- **algorithms** — XOR, Sum8, seven CRC-8 variants, CRC-16 Modbus and CCITT,
  all through `crc8_parameterised` / `crc16_parameterised`
- **frame addressing** — `resolve_byte_index`, `extract_checksum`,
  `validate_checksum`; offsets are end-relative, so mixed frame lengths on one
  link line up
- **columns** — `analyse_columns`, the per-byte-column statistics the rest rests
  on, beside the addressing they are indexed by
- **calculation ranges** — `calc_ranges`, the one candidate space for what a
  checksum is computed over, shared by the sweep and the solvers
- **sweep** — `ChecksumSpec` and `sweep_specs`, grouping specs that share a
  calculation so each CRC runs once per frame
- **detection** — `detect_checksum`, which builds the candidate space from
  column priors, scores survivors, then ranks and folds equivalent ranges
- **solving** — `solve_additive`, `solve_crc`, and `solve_all`, which computes
  the answer rather than enumerating candidates and folds the duplicates the
  range space produces
- **sampling** — `diverse_samples`, because a periodic link otherwise hands a
  solver a hundred copies of one payload

Explanations cross as `ChecksumNote { code, values }` rather than English, so
the caller translates.

## Using it

Consumed by path within the workspace; released as part of the workspace
`vX.Y.Z` tag, not pinned directly.

Two caveats a caller must not get wrong are documented where they are
implemented rather than here: `init` and `xorOut` are not separately
identifiable for fixed-length payloads (`solve.rs`), and a widened range space
produces several spellings of one answer (`detect.rs`).
