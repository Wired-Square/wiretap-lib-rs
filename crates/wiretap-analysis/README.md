# wiretap-analysis

Payload analysis for WireTAP frames in the [`wiretap-lib`](../../) workspace:
which bytes are worth solving as a checksum at all, the geometries to solve them
over, and the scan that drives both across a capture.

Where [`wiretap-checksum`](../wiretap-checksum) answers *what algorithm is this
byte*, this crate answers the prior and cheaper question — *is this byte a
checksum* — which usually decides the answer, because most links carry no
checksum on most frame ids.

## What's here

- **`checksum_evidence`** — the per-column verdict. A checksum is a function of
  the other bytes, so two payloads differing only in this column rule it out
  outright; what survives is separated on responsiveness and near-injectivity
- **`solve_targets`** — each surviving column crossed with every calculation
  range `wiretap-checksum::calc_ranges` offers, so a checksum that skips a
  leading type byte reaches the solver and not only the sweep
- **`scan_frames` / `scan_groups`** — group by frame id, sample, identify,
  sweep, solve, rank. It lives here rather than in an application because it is
  a pure function of payloads, and the other consumers cannot reach into an app
  binary

Per-byte-column statistics live in [`wiretap-checksum`](../wiretap-checksum),
beside the addressing they are indexed by, and are re-exported here.

Measured on a 62-id Sungrow BMS capture: 496 byte columns reduce to 27
candidates across 5 frame ids in 650 µs, and solving all of them exhaustively
for custom CRC polynomials takes a further 800 µs.

## Using it

Consumed by path within the workspace; released as part of the workspace
`vX.Y.Z` tag, not pinned directly.

Identification **narrows** the search and does not decide it: where every field
moves on every frame, a data byte is as responsive as a checksum and both
survive. The property that matters is the other direction — a real checksum must
never be filtered out — and that is what the tests pin.
