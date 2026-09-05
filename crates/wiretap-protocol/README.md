# wiretap-protocol

The wire protocols WireTAP speaks, as scalars — the part of the
[`wiretap-lib`](../../) workspace that two repositories have to agree on byte
for byte. It depends on nothing at all: no serde, no async runtime, no driver.

## What's here

- **`dlc`** — the CAN data length code table, `dlc_to_len`, `len_to_dlc` and
  `payload_dlc`. The wire carries a *code*, a database column stores a
  *length*, and above 8 bytes on CAN FD the two differ
- **`gvret`** — the GVRET serial protocol: an incremental `Decoder` for the
  command stream, and encoders for captured frames and every control reply.
  This is the live bridge the WireTAP desktop and SavvyCAN connect to
- **`ingest`** — the id-flag layout of the binary ingest protocol. Only the
  layout; the framing and CRC live with both of their ends, in WireTAP-Server

## Using it

```toml
wiretap-protocol = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.15.0" }
```

`https`, not the `ssh` form the workspace README shows: this repository is
public, and the things that build WireTAP-Server — a stock CI runner, a
container, a musl cross-build — have no key between them. First released in
v0.15.0, so nothing earlier can be pinned.

Encoders take a caller's buffer and scalars —
`encode_frame_into(out, ts_us, arb_id, extended, bus, data, is_fd)` — because
each consumer's frame type is its own and they are not reconcilable: the capture
server's is CAN-only and stores no length code, the desktop's is multi-protocol
and is a serde contract with its frontend.

**Before changing `gvret`:** the trailing byte after a frame's payload is a
checksum every participant guesses differently, and the dialect they all
actually speak is written down correctly in none of them. The module header
records it and it is deliberately left alone — all four ends are live, so
changing it is a protocol change rather than a refactor.
