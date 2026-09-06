# wiretap-protocol

The wire protocols WireTAP speaks, as scalars — the part of the
[`wiretap-lib`](../../) workspace that two repositories have to agree on byte
for byte. It depends on nothing at all: no serde, no async runtime, no driver.

## What's here

Each module has a reference document beside it in [`docs/`](docs/), which says
what the protocol is and what part of it this crate implements.

- **`dlc`** — the CAN data length code table, `dlc_to_len`, `len_to_dlc` and
  `payload_dlc`. The wire carries a *code*, a database column stores a
  *length*, and above 8 bytes on CAN FD the two differ
- **`gvret`** ([docs](docs/gvret.md)) — the GVRET serial protocol, both ends:
  the host end a client speaks, and the device end a capture server speaks to
  look like an adapter. SavvyCAN is the reference client
- **`slcan`** ([docs](docs/slcan.md)) — the Lawicel ASCII protocol most USB-CAN
  adapters speak, with the CAN FD extension the CANable 2.5 firmware added:
  line framing, frames, commands and version replies
- **`gs_usb`** ([docs](docs/gs_usb.md)) — the candleLight USB protocol: host
  frames, the control-transfer layouts and the bit timing maths
- **`socketcan`** ([docs](docs/socketcan.md)) — Linux's `can_frame` and
  `canfd_frame`, and the flags packed alongside an id. A kernel ABI rather than
  a wire format; see the module header
- **`testpattern`** ([docs](docs/test-pattern.md)) — two endpoints proving a CAN
  link carries what it claims to: a length sweep across every data length code,
  plus ping, latency and the control handshake that binds a run. Both sides,
  with the reply half as a sans-io state machine
- **`ingest`** ([docs](docs/ingest.md)) — the id-flag layout of the binary
  ingest protocol. Only the layout: the framing and the CRC stay where both ends
  of that wire already are

## Using it

```toml
wiretap-protocol = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.16.0" }
```

First released in v0.15.0, so nothing earlier can be pinned. Either URL form
works, and the workspace README says why `https` is usually the one a consumer
wants.

Encoders take a caller's buffer and scalars —
`encode_frame_into(out, ts_us, arb_id, extended, bus, data, is_fd)` — because
each consumer's frame type is its own and they are not reconcilable: one is
CAN-only and stores no length code, the next is multi-protocol and is a serde
contract with a frontend. It follows that the crate depends on nothing: a client
speaking one of these protocols should not have to take a capture stack to do
it.

Where a protocol packs several independent flags into one field — SLCAN's prefix
character, a gs_usb host frame's id word — a module names a struct for its own
wire shape instead, because an encoder taking six positional booleans is a
defect waiting to happen. That struct is still the wire's, never a consumer's.

**Before changing `gvret`:** the trailing byte after a frame's payload is a
checksum every participant guesses differently, and the dialect they all
actually speak is written down correctly in none of them. The module header
records it and it is deliberately left alone — all four ends are live, so
changing it is a protocol change rather than a refactor.
