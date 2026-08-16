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
- **columns** — `analyse_columns`, the per-byte-column statistics every other
  part rests on. They live here, beside the addressing they are indexed by,
  because both the sweep and the identification pass upstream need them
- **calculation ranges** — `calc_ranges`, the one candidate space for *what a
  checksum is calculated over*, shared by the sweep and the solver
- **sweep** — `ChecksumSpec` (algorithm × position × calc range × endianness)
  and `sweep_specs`, which groups specs sharing a calculation so each CRC runs
  once per frame rather than once per spec
- **detection** — `detect_checksum` builds the candidate space from column
  priors, scores each survivor on match rate, sample count, column variance and
  range plausibility, then ranks and folds equivalent ranges together
- **solving** — `solve_additive` and `solve_crc` for when the answer is not one
  of the eleven
- **sampling** — `diverse_samples`, because a periodic link hands a solver a
  hundred copies of one payload unless you ask for better

## Solving beats searching

`detect_checksum` asks *is it one of the usual ones*. `solve_*` asks *what is
it*, and computes the answer rather than enumerating candidates.

**Additive checksums fall out in one pass.** If a checksum is `sum(range) + k`,
then `observed − sum(range)` is `k` for every sample — so compute that residue
and see whether it moves. This also catches the offset and two's-complement
variants that a fixed algorithm list cannot express.

**A CRC's `init` and `xorOut` are not search axes.** The register is affine in
its initial value, so for messages of equal length those two terms collapse into
one constant. Define `K = observed ⊕ CRC(m, init=0, xorOut=0)`; a polynomial is
correct exactly when `K` is the same for every sample. The search drops from
`poly × init × xorOut × reflect` to `poly × reflect`:

| | enumerating init/xorOut | residue agreement |
|---|---|---|
| CRC-8 | 4,080 configurations | 510 |
| CRC-16 | 4,194,240 | 262,140 |

In wall-clock, an exhaustive 16-bit sweep over 200 samples is **~8 ms**.

The flip side is a limit worth stating: for fixed-length payloads `init` and
`xorOut` are *not separately identifiable*. `(init = 0, xorOut = K)` is reported
because it always reproduces the data, and `CrcParameters::alternatives` carries
the conventional inits with the `xorOut` each would imply. None of them is more
true than the others, and a caller must not present one as the answer.

Two rejections carry most of the weight in `detect_checksum`. A **constant column is padding, not a
checksum**, however perfectly XOR-over-zeros "matches" it. And feasibility is
judged against the **longest** frame, not the shortest — `sweep_specs` already
excludes frames that individually cannot carry a spec, so gating the whole
search on the shortest lets one bare acknowledgement empty the space.

## One range space, or the solver searches less than the sweep

`calc_ranges` exists because these two halves disagreed. The sweep tried starts
`{0, 1, 2}`; the solver calculated from byte 0 and nowhere else. So a checksum
over `1..n` — a leading type or id byte excluded, which is exactly what the
Tesla HPWC sum does — could be *matched* and never *solved*, and ticking
"search custom polynomials" on such a frame reported nothing with no knob to
turn. A solve is microseconds; there was never a cost reason for the narrower
space, only an accident of where the constant lived.

The flip side is that widening it makes duplicates, and a caller must fold them.
A constant range contributes a constant, which a sum absorbs into its offset and
a CRC into its residue — so when the excluded bytes never change, *every* start
solves, with a different offset each. Those are one answer written several ways.
Report the widest and carry the rest as equivalents; when only one range solves,
the excluded bytes did move, and that answer is the real one.

Explanations cross as `ChecksumNote { code, values }` rather than English, so
the caller translates.

This crate is consumed by path within the workspace and is released as part of
the workspace `vX.Y.Z` tag — it is not pinned directly.
