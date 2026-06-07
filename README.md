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
register-poll/encode workflow.

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
- **Encode** (Modbus) — values → register writes (inverse of decode): masked
  bit-fields, register-contiguous batching, `register_type` writability check.
- **DBC** — import a Vector `.dbc` to catalogue TOML and export back
  (`dbc::convert_dbc_to_toml`, `dbc::render_catalog_as_dbc_with_mode`), including
  extended (`SG_MUL_VAL_`) and flattened multiplex modes.
- **Edit** — toggle a Modbus frame's `disabled` flag in place via `toml_edit`,
  preserving comments and formatting.

```toml
[meta]
name = "Sungrow SHx"

[meta.modbus]
register_base = 0            # 0 = IEC/0-based, 1 = traditional 3xxxx/4xxxx
default_word_order = "little"

[frame.modbus.battery_status]   # one Modbus read of a register block
register_number = 13019
register_type = "input"         # input | holding | coil | discrete
length = 9                      # register count

[[frame.modbus.battery_status.signals]]   # a bit-slice of the block
name = "Battery_SoC"
start_bit = 48
bit_length = 16
factor = 0.1
unit = "%"
```

### Modbus shorthands

- **Register from the key** — omit `register_number` and name the frame by its
  register: `[frame.modbus.0x32F9]` or `[frame.modbus.13049]`. An explicit
  `register_number` still wins.
- **Signal-less register** — a register that *is* a single value needs no
  `[[signals]]` block; put the decoding fields at the frame level and one
  full-width signal (`length × 16` bits) is synthesised.

## Versioning

Released as git tags (`vMAJOR.MINOR.PATCH`); consumers pin a tag:

```toml
wiretap-catalog = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.6.0" }
```

Dev loop: pin the tag, but add a local `[patch]`/`path` override against a working
checkout while iterating, so changes don't need a push/tag to test. Bump the
version + tag a new `vX.Y.Z` to release.

## Version history

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
