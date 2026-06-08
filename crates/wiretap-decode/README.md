# wiretap-decode

The protocol-agnostic decode core of the [`wiretap-lib`](../../) workspace: the
numeric/bit primitives shared across WireTAP's catalogue decoders (CAN, Serial,
Modbus), with no dependency on the catalogue model.

- **bit extraction** — `extract_bits` (endianness + sign) and `apply_word_swap`
  (16-bit "CDAB" word order)
- **exact scaling** — `scale(raw, factor, offset) -> Decimal`, so
  `raw × factor + offset` carries no binary-float noise (`3374 × 0.1` is
  `337.4`, not `337.40000000000003`)
- **formatting** — `format_decimal`, `format_hex`, `format_unix_time`,
  `decode_text`

[`wiretap-catalog`](../wiretap-catalog) builds its `decode_by_id` path and its
Modbus manifest poller on top of these, so there is one extraction + scaling
implementation. This crate is consumed by path within the workspace and is
released as part of the workspace `vX.Y.Z` tag — it is not pinned directly.
