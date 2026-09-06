# wiretap-analysis

Payload analysis for WireTAP frames in the [`wiretap-lib`](../../) workspace:
which bytes are worth solving as a checksum at all, the geometries to solve them
over, and the scan that drives both across a capture.

Where [`wiretap-checksum`](../wiretap-checksum) answers *what algorithm is this
byte*, this crate answers the prior and cheaper question — *is this byte a
checksum* — which usually decides the answer, because most links carry no
checksum on most frame ids.

## What's here

- **`checksum_evidence`** — the per-column verdict: which bytes could be a
  checksum at all
- **`solve_targets`** — each surviving column crossed with every calculation
  range `wiretap-checksum::calc_ranges` offers, so a checksum that skips a
  leading type byte reaches the solver and not only the sweep
- **`scan_frames` / `scan_groups`** — group by frame id, sample, identify,
  sweep, solve, rank

Per-byte-column statistics live in [`wiretap-checksum`](../wiretap-checksum),
beside the addressing they are indexed by; reach for them there directly.

## Using it

```toml
wiretap-analysis = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.15.1" }
```

Nothing in this workspace depends on it; its consumers are outside.

Identification **narrows** the search rather than deciding it, and the property
the tests pin is the one that matters — a real checksum must never be filtered
out. That argument is in `src/checksum.rs`, beside the test that holds it.
