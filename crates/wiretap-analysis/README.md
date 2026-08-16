# wiretap-analysis

Payload analysis for WireTAP frames: the identification pass that says which
bytes are worth solving as a checksum, and the geometries to solve them over.

Per-byte-column statistics live in
[`wiretap-checksum`](../wiretap-checksum), beside the end-relative addressing
they are indexed by, and are re-exported here. They used to exist twice, once on
each side of this boundary, and the two copies had already drifted into
disagreeing about when a column counts as padding.

The split from [`wiretap-checksum`](../wiretap-checksum) is a real seam. That
crate answers *what algorithm is this byte*. This one answers the prior and
cheaper question — *is this byte a checksum at all* — which on a real bus is
usually the one that decides the answer, because most links carry no checksum on
most frame ids.

## The decisive test is a rejection, not a score

A checksum is a **function of the other bytes**. So if two payloads agree on
every byte except this column and this column differs, no function can produce
both. That is arithmetic, not a heuristic, and it needs no threshold — it
removes counters, sequence numbers and free-running timers outright.

What survives is separated by two further facts:

- **responsiveness** — a checksum changes almost every time the payload does,
  colliding about one time in `2^bits`; a sensor byte sits still while other
  bytes move, because it measures one quantity and they measure others;
- **near-injectivity** — `n` distinct payloads should produce close to
  `256(1 - e^(-n/256))` distinct checksum bytes. A byte oscillating over four
  values while a hundred different payloads go past is measuring something else.

Entropy alone cannot make the first distinction, which is the trap worth naming:
cell-voltage frames jitter constantly, reach near-maximum entropy, and contain
no checksum.

## What it is not

Identification **narrows** the search; it does not decide the answer. Where every
field moves on every frame, a data byte is as responsive as a checksum and both
survive. The property that matters is the other direction — the real checksum
must never be filtered out — and that is what the tests pin.

`solve_targets` follows the same rule about ranges. Each surviving column is
crossed with every calculation range `wiretap-checksum::calc_ranges` offers,
rather than assuming the calculation starts at byte 0 — so a checksum that skips
a leading type byte reaches the solver instead of only the sweep. Several of
those ranges will often solve the same frame, and folding them back into one
answer is the caller's job; see that crate's README for why.

Measured on a 62-id Sungrow BMS capture: 496 byte columns reduce to 27
candidates across 5 frame ids in 650µs, and solving all of those exhaustively
for custom CRC polynomials takes a further 800µs.

This crate is consumed by path within the workspace and is released as part of
the workspace `vX.Y.Z` tag — it is not pinned directly.
