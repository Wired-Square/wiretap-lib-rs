# wiretap-protocol

The wire protocols WireTAP speaks, as scalars — the part of the
[`wiretap-lib`](../../) workspace that two repositories have to agree on byte
for byte.

- **`dlc`** — the CAN data length code table, `dlc_to_len`, `len_to_dlc` and
  `payload_dlc`. The wire carries a *code*, a database column stores a
  *length*, and above 8 bytes on CAN FD the two differ
- **`gvret`** — the GVRET serial protocol: an incremental `Decoder` for the
  command stream, and encoders for captured frames and every control reply.
  This is the live bridge the WireTAP desktop and SavvyCAN connect to
- **`ingest`** — the id-flag layout of the binary ingest protocol. Only the
  layout: the framing and CRC live with both of their ends, in
  WireTAP-Server's `wiretap-ingest-proto`

## Why it speaks scalars

Each consumer has its own captured-frame type, and they are not reconcilable.
The capture server's `CanSample` is CAN-only and deliberately does not store the
data length code; the desktop's `FrameMessage` is multi-protocol, stores it, and
is a serde contract with a frontend. A codec that spoke either type would cost
the other a per-frame conversion on a hot capture path, or a frontend-visible
type change.

So `encode_frame_into(out, ts_us, arb_id, extended, bus, data, is_fd)` takes a
caller's buffer and seven scalars, and each repository adapts at its own
boundary. It follows that this crate has **no dependencies at all** — no serde,
no async runtime, no driver. A client speaking one of these protocols should not
have to take a capture stack to do it.

## Before you change `gvret`

The trailing byte after a frame's payload is a checksum that every participant
guesses differently, and the dialect they all actually speak is written down
correctly in none of them. It is documented in the module header and
deliberately left alone: all four ends are live, so changing it is a protocol
change rather than a refactor.

## Pinning it

Released as part of the workspace `vX.Y.Z` tag, like every crate here — this
crate first appears in **v0.15.0**, so nothing earlier can be pinned. Unlike the
workspace's internal crates this one *is* pinned directly, by WireTAP-Server:

```toml
wiretap-protocol = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.15.0" }
```

`https`, not the `ssh` form the workspace README shows: this repository is
public, and the things that build WireTAP-Server — a stock CI runner, a
container, a musl cross-build — have no key between them.
