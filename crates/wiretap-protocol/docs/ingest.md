# WireTAP binary ingest protocol (v1)

A compact TCP protocol for pushing batches of CAN frames into a capture server
from microcontroller-class devices — ESP32, STM32 and the like. The server feeds
them into the same pipeline as local capture: batching, a PostgreSQL COPY write,
and a disk cache for outage resilience.

Design priorities, in order: a tiny client footprint (fixed little-endian
layouts that pack directly as C structs — no varints, no text), buffer sizes
known at compile time, and at-least-once delivery with explicit backpressure.

> **This document is the protocol. This crate implements one part of it:**
> [§4.1](#41-the-id-flags-word), the id-flag layout, and nothing else. The
> framing, the CRC and the message types are implemented where both ends of the
> wire already are, together, and nothing is gained by moving them. See
> [§7](#7-what-this-crate-implements).

---

## 1. Transport and framing

One TCP connection per device. **All integers are little-endian.** Every
message, in both directions:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 2 | `length` | u16 — bytes from `type` to the end of the body, CRC excluded |
| 2 | 1 | `type` | message type |
| 3 | N | body | `length - 1` bytes |
| 3+N | 4 | `crc32` | IEEE CRC-32 over `type` and body |

`length` ≤ 65535, so a message is at most ~64 KiB. A message failing its CRC is
not processed: a corrupt `BATCH` gets a `status = 1` ACK so the client can
resend, and anything else is ignored.

Message types — the high bit set means server → client:

| Type | Name | Direction |
|------|------|-----------|
| `0x01` | `HELLO` | client → server |
| `0x81` | `HELLO_ACK` | server → client |
| `0x02` | `BATCH` | client → server |
| `0x82` | `ACK` | server → client |
| `0x03` | `PING` | client → server |
| `0x83` | `PONG` | server → client |

Unknown types are ignored, for forward compatibility.

---

## 2. Session start: HELLO / HELLO_ACK

`HELLO` comes first. A `BATCH` before a successful one drops the connection.

`HELLO` body:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | magic | ASCII `WTAP` |
| 4 | 1 | `proto_version` | 1 |
| 5 | 1 | `flags` | bit 0 = `TIME_RELATIVE` (§3) |
| 6 | 1 | `token_len` | 0–255 |
| 7 | n | token | API key, compared in constant time |
| 7+n | 1 | `db_len` | 0–63; absent means 0 |
| 8+n | m | database | target capture database, `[a-z0-9_]+` |

The database field chooses where the frames land. Empty — or absent, from an
older client — means the server's default. A gateway may **auto-create** an
unknown database when it is configured to allow it and the key permits, so a
freshly flashed ingestor for a new capture provisions its own on first connect.
A key may be pinned to one database, in which case a `HELLO` naming any other is
rejected as bad auth.

`HELLO_ACK` body:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 1 | `status` | 0 ok, 1 bad auth, 2 bad version, 3 bad database |
| 1 | 1 | `accepted_version` | the server's protocol version |
| 2 | 8 | `server_time_us` | u64 — server wall clock, epoch µs |

On any non-zero status the server closes the connection after the ACK.
`server_time_us` lets a clock-capable device synchronise before it starts
sending absolute timestamps.

The token is sent in clear text. Deploy on a trusted network, or wrap the
connection, if it crosses anything else.

---

## 3. Frame delivery: BATCH / ACK

`BATCH` body:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | `seq` | u32 — client-chosen, echoed in the ACK |
| 4 | 8 | `base_ts_us` | u64 — epoch µs, or 0 under `TIME_RELATIVE` |
| 12 | 2 | `count` | u16 — records following, ≤ 256 by default |
| 14 | … | records | `count` of them, in ascending `delta_ts_us` |

Each record:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | `delta_ts_us` | u32 — µs after `base_ts_us` |
| 4 | 4 | `id_flags` | §4.1 |
| 8 | 1 | `bus` | bus number |
| 9 | 1 | `len` | payload length, 0–64 |
| 10 | `len` | payload | raw bytes |

Per-record overhead is 10 bytes, so a classic 8-byte frame costs 18 on the wire.
The u32 delta bounds a batch's span at ~71 minutes, which is irrelevant in
practice — a batch should flush every few seconds at worst.

**Timestamps.** With a real clock (NTP, GPS, or synced from `server_time_us`),
set `base_ts_us` to epoch µs and the deltas relative to it. Without one, set the
`TIME_RELATIVE` flag in `HELLO`, use any monotonic µs counter as the base and
send `base_ts_us = 0`: the server stamps the **last** record with its arrival
time and back-dates the rest by their delta differences, which is accurate to
within network latency and preserves inter-frame spacing exactly. Records must
therefore be in ascending delta order.

`ACK` body:

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0 | 4 | `seq` | echoes the `BATCH` |
| 4 | 1 | `status` | 0 ok — durably stored; 1 CRC error; 2 malformed; 3 cannot store now |
| 5 | 1 | `queue_pct` | reserved, always 0 |

**ACK-after-write.** The gateway writes a batch to PostgreSQL *before* replying,
so `status = 0` means durably stored, not buffered — there is no in-gateway
queue to lose on a restart. `status = 3` means the database is unavailable and
the client should cache and back off.

**At-least-once.** Keep each batch until its seq is ACKed with status 0. Resend
on status 1 or 2 (after checking the encoder, for 2), on status 3 after a
backoff, on no ACK within a timeout, and on reconnect. Occasional duplicates
from a resend are acceptable in the archive; exactly-once is deliberately not
attempted. Sequence numbers only correlate ACKs to batches — they need not be
contiguous, and the server does not deduplicate.

---

## 4. The record id

### 4.1 The id-flags word

| Bit(s) | Mask | Meaning |
|--------|------|---------|
| 31 | `0x80000000` | direction: 0 received, 1 transmitted by this device |
| 30 | `0x40000000` | CAN FD |
| 29 | `0x20000000` | extended (29-bit) id |
| 28–0 | `0x1FFFFFFF` | the arbitration id |

The three flags and the id partition the word exactly: no overlap, so a 29-bit
id cannot set a flag, and no gap, so there is no spare bit. That last part is
the constraint that makes a new message type the only way to carry anything but
a CAN frame.

**These positions are this protocol's own.** GVRET marks an extended id with the
top bit; this marks it with bit 29. Only the id *width* is common, and it comes
from one constant so the two cannot drift.

---

## 5. Keepalive: PING / PONG

Both bodies are empty. Send `PING` at the agreed interval — 30 s by default —
whenever no batches are flowing; a server drops a connection silent for three
times that. Any received message counts as activity, so a busy device never
pings.

---

## 6. Sizing a client

A worst-case batch of 256 classic frames with 8-byte payloads is
`7 + 14 + 256 × 18 = 4629` bytes — one static buffer. A 500 kbit/s bus at full
load is about 4000 frames/s, so 256-frame batches mean ~16 batches/s and about
74 KB/s of TCP, comfortably inside an ESP32's Wi-Fi. Flush partial batches on a
timer — 250 ms, say — so a quiet bus still records promptly.

---

## 7. What this crate implements

[`ingest`](../src/ingest.rs): the four constants of §4.1, and a test asserting
they partition the word.

Nothing else. §1's framing and CRC, and the message types of §2, §3 and §5, are
implemented alongside both of their ends, which is where they belong: a codec
shared by two halves of one program is not a library.

The id-flag layout is here because a *third* encoder packs an arbitration id and
these flags the same way while sharing nothing else with either end of this wire
— and because those three had to agree about it with nothing making them. That
encoder's own record layout is its business, not this crate's.
