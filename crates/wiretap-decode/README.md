# wiretap-decode

The protocol-agnostic decode core of the [`wiretap-lib`](../../) workspace: the
numeric and bit primitives every catalogue decoder shares, with no dependency on
the catalogue model.

## What's here

- **`extract_bits`** — a bitfield as `f64`, honouring endianness and sign
- **`apply_word_swap`** — 16-bit "CDAB" word order
- **`scale`** — `raw × factor + offset` as an exact `Decimal`, so `3374 × 0.1`
  is `337.4` and not `337.40000000000003`
- **`format_decimal`, `format_hex`, `format_unix_time`, `decode_text`** — value
  formatting

## Using it

Consumed by path within the workspace — [`wiretap-catalog`](../wiretap-catalog)
builds its `decode_by_id` path and its Modbus poller on these, so there is one
extraction and scaling implementation. Released as part of the workspace
`vX.Y.Z` tag; not pinned directly.
