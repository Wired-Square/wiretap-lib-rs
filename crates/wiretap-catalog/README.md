# wiretap-catalog

The canonical parser, validator, decoder, and writer for **WireTAP-format device
catalogues** (TOML) — across **CAN, Serial, and Modbus**.

A device catalogue describes a device's frames/registers and how to decode them
(an inverter, a battery, a meter, a CAN ECU). The same schema is used by
[WireTAP](https://github.com/Wired-Square) and the Home Assistant ESS add-on;
this crate is the shared, versioned implementation so they consume one source of
truth — and so decoding can happen once, in Rust, instead of being re-implemented
per consumer.

```rust
use wiretap_catalog::{Catalog, decode, validate};

// Parse any protocol (CAN / Serial / Modbus) into one resolved model.
let cat = Catalog::parse(toml_text)?;          // shorthands + mirror/copy resolved
let errors = validate::validate(toml_text);    // field-path + message findings

// Decode a frame's bytes → signal values (factor/offset, endian, mux, formats).
let frame = cat.frame(0x123).unwrap();
let out = decode::decode_frame(&cat, frame, &bytes);
for s in &out.signals {
    println!("{} = {} {}", s.name, s.display, s.unit.as_deref().unwrap_or(""));
}
```

The Modbus model is also available directly (`wiretap_catalog::modbus`) for the
register-poll/encode workflow. Its `decode_frame` returns `DecodedSignal`s whose
`value` is an exact `Decimal` — scaling is done in `rust_decimal`, so
`factor`/`offset` never introduce binary-float artefacts when a value is
stringified for display or an entity state.

## Capabilities

- **Parse** — `Catalog::parse` resolves CAN, Serial and Modbus frame sections
  into one [`Catalog`] model: mirror/copy inheritance, header-field masks, mux
  trees, and the Modbus authoring shorthands (below).
- **Validate** — `validate::validate` returns `{ field, message }` findings
  (meta/CAN signal & mux rules, DBC-name compatibility, Modbus register
  resolution).
- **Decode** — `decode::decode_frame` turns raw bytes into signal values:
  16/64-bit signed/unsigned, `factor`/`offset`, byte + word order (Sungrow
  "CDAB"), `enum`/`hex`/`ascii`/`utf8`/`unix_time` formats, and mux selection
  (single / range `0-3` / list `1,2,5` / nested). One implementation — the
  Modbus register decoder shares the same bit-extraction core.
- **Tunnel** — `tunnel::ModbusTunnel` reassembles a protocol carried *inside* a
  frame id. A `[frame.can.<id>.tunnel]` declaration marks the id as a Modbus RTU
  byte stream: consecutive payloads concatenate, message boundaries come from the
  RTU length rules, and CRC-16/Modbus gates every message. Both directions share
  the id, so a read response inherits its register address from the request it
  answers. Unlike the rest of decode this is stateful and order-dependent — feed
  every frame, in order, one tunnel per stream.
- **Encode** (Modbus) — values → register writes (inverse of decode): masked
  bit-fields, register-contiguous batching, `register_type` writability check.
- **DBC** — import a Vector `.dbc` to catalogue TOML and export back
  (`dbc::convert_dbc_to_toml`, `dbc::render_catalog_as_dbc_with_mode`), including
  extended (`SG_MUL_VAL_`) and flattened multiplex modes.
- **Edit** — comment-/formatting-preserving in-place edits via `toml_edit`
  (`edit::apply_edit`): set a table, upsert a frame/signal in sorted position,
  rename a key, delete — only the targeted entry changes, every `#` comment survives.
- **Migrate** — `migrate::migrate` upgrades a catalogue's *text* to the current
  schema (comment-preserving, idempotent): synthesise a slave node from a legacy
  `[meta.modbus].device_address` (registers get `node_address`), and flatten a
  frame's `[tx]` interval to the top-level `interval_ms`.

```toml
[meta]
name = "Sungrow SHx"

[meta.modbus]
register_base = 0            # 0 = IEC/0-based, 1 = traditional 3xxxx/4xxxx
default_word_order = "little"

[node."Slave 1"]            # a Modbus slave; it owns the device address
device_address = 1

[frame.modbus.battery_status]   # one Modbus read of a register block
node_address = 1                # the slave to read from (matched to a node by address)
register_number = 13019
register_type = "input"         # input | holding | coil | discrete
length = 9                      # register count
interval_ms = 5000              # poll interval (ms); legacy [tx] table also accepted

[[frame.modbus.battery_status.signals]]   # a bit-slice of the block
name = "Battery_SoC"
start_bit = 48
bit_length = 16
factor = 0.1
unit = "%"
```

### Modbus slaves (nodes)

- **The slave owns the device address** — declare each slave as `[node.<name>]`
  with a `device_address`, and point a register at it with `node_address = <N>`
  (matched to the node by its address). One catalogue can describe several slaves,
  each polled at its own address; renaming a node never breaks a register reference.
- **Legacy fallback + migration** — an older catalogue that set
  `[meta.modbus].device_address` and declared no nodes still parses: every
  register resolves that address, and a slave node is synthesised from it (with
  the orphaned registers attached) so the editor shows them grouped. A register
  with no `node_address` falls back to the legacy address, else `1`.

### Modbus shorthands

- **Register from the key** — omit `register_number` and name the frame by its
  register: `[frame.modbus.0x32F9]` or `[frame.modbus.13049]`. An explicit
  `register_number` still wins.
- **Signal-less register** — a register that *is* a single value needs no
  `[[signals]]` block; put the decoding fields at the frame level and one
  full-width signal (`length × 16` bits) is synthesised.
- **Poll interval** — a register's cadence is the top-level `interval_ms` (the
  legacy `[tx]` table — `tx.interval_ms` / `tx.interval` — is still read), else
  `[meta.modbus].default_interval`, else 5000 ms.

## Versioning

Released as git tags (`vMAJOR.MINOR.PATCH`); consumers pin a tag:

```toml
wiretap-catalog = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.13.0" }
```

Dev loop: pin the tag, but add a local `[patch]`/`path` override against a working
checkout while iterating, so changes don't need a push/tag to test. Bump the
version + tag a new `vX.Y.Z` to release.

## Version history

- **v0.6.2** — repo restructured into a Cargo workspace; this crate moved to
  `crates/wiretap-catalog/`. No API change — consumers resolve the member by
  name and need no pin change beyond the tag.
- **v0.6.1** — Modbus `DecodedSignal.value` is now an exact `Decimal`: scaling
  (`raw × factor + offset`) is done in `rust_decimal`, so a value like `3374 ×
  0.1` decodes to `337.4` rather than the f64 `337.40000000000003` that
  stringified with float noise for display/entity state.
- **v0.6.0** — serial header byte-positions are derived at parse time: `SerialConfig`
  now carries `frame_id_*`, `source_address_*` and a `header_fields` list (each with
  `start_byte`/`bytes`) resolved from the field masks, so consumers read them instead
  of re-deriving.
- **v0.5.0** — carry each signal's `format` through to the decoded output.
- **v0.4.0** — each decoded mux-case signal carries its `mux_value` (the selector
  value of its mux), so consumers can track each mux case's signals independently.
- **v0.3.0** — `decode::decode_by_id` (apply `frame_id_mask`, look up the frame,
  decode signals/mux **and** extract header fields — CAN from the id, serial from
  the header bytes — plus source-address resolution). This is what the live stream
  calls per frame.
- **v0.2.0** — grown from Modbus-only into the canonical catalogue library:
  unified `Catalog` model, `Catalog::parse` (CAN + Serial + Modbus), `validate`,
  `decode::decode_frame` (ported from WireTAP's `bits.ts`/`signalDecode.ts`/
  `muxCaseMatch.ts`, single-sourced with the Modbus decoder), and DBC
  import/export. CI (fmt · clippy `-D warnings` · test).
- **v0.1.0** — Modbus catalogue parse / decode / encode + shorthands. Extracted
  from the Home Assistant ESS add-on.

## Licence

MIT © Wired Square.
