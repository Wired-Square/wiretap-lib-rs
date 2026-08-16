# wiretap-checksum

Checksum algorithms and the scored detection engine of the
[`wiretap-lib`](../../) workspace. Given a set of frames off a link, it answers
*which checksum configuration explains these bytes* — and says why when nothing
does.

- **algorithms** — XOR, Sum8, seven CRC-8 variants, CRC-16 Modbus and CCITT,
  all funnelling through `crc8_parameterised` / `crc16_parameterised`
- **frame addressing** — `resolve_byte_index`, `extract_checksum`,
  `validate_checksum`; offsets are end-relative, so mixed frame lengths on one
  link line up
- **sweep** — `ChecksumSpec` (algorithm × position × calc range × endianness)
  and `sweep_specs`, which groups specs sharing a calculation so each CRC runs
  once per frame rather than once per spec
- **detection** — `detect_checksum` builds the candidate space from column
  priors, scores each survivor on match rate, sample count, column variance and
  range plausibility, then ranks and folds equivalent ranges together

Two rejections carry most of the weight. A **constant column is padding, not a
checksum**, however perfectly XOR-over-zeros "matches" it. And feasibility is
judged against the **longest** frame, not the shortest — `sweep_specs` already
excludes frames that individually cannot carry a spec, so gating the whole
search on the shortest lets one bare acknowledgement empty the space.

Explanations cross as `ChecksumNote { code, values }` rather than English, so
the caller translates.

This crate is consumed by path within the workspace and is released as part of
the workspace `vX.Y.Z` tag — it is not pinned directly.
