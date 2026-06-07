# wiretap-catalog

Parser, decoder, and writer for **WireTAP-format Modbus device catalogues** (TOML).

A device catalogue describes the Modbus registers of a device (an inverter, a
battery, a meter) and how to decode them. The same `[frame.modbus.*]` schema is
used by [WireTAP](https://github.com/Wired-Square) and the Home Assistant ESS
add-on; this crate is the shared, versioned implementation so both consume one
source of truth.

```toml
[meta.modbus]
device_address = 1
register_base = 0            # 0 = IEC/0-based, 1 = traditional 3xxxx/4xxxx
default_interval = 5000      # ms
default_word_order = "little"

[frame.modbus.battery_status]   # one Modbus read of a register block
register_number = 13019
register_type = "input"         # input | holding | coil | discrete
length = 9                      # register count
tx.interval_ms = 10000

[[frame.modbus.battery_status.signals]]   # a bit-slice of the block
name = "Battery_SoC"
start_bit = 48
bit_length = 16
factor = 0.1
unit = "%"
```

```rust
use wiretap_catalog::modbus::{ModbusManifest, decode_frame};

let m = ModbusManifest::parse(toml_text)?;
let frame = &m.frames[0];
let values = decode_frame(frame, &registers, &m.meta); // (name, scaled value, unit)
```

## Capabilities

- **Parse** the catalogue model (frames, signals, meta) with serde.
- **Decode** register blocks → scaled values: 16/32/64-bit signed/unsigned,
  `factor`/`offset`, byte order, and multi-register word-swap (Sungrow "CDAB").
  String-ish formats (`ascii`/`hex`/`utf8`/`unix_time`) are skipped by the
  numeric decoder.
- **Encode** values → register writes (the inverse), with masked bit-fields,
  register-contiguous batching, and a `register_type` writability check.
- **Edit** a frame's `disabled` flag in place via `toml_edit`, preserving the
  manifest's comments and formatting.

### Shorthands

Two authoring conveniences on top of the base schema:

- **Register from the key** — omit `register_number` and name the frame by its
  register: `[frame.modbus.0x32F9]` or `[frame.modbus.13049]`. An explicit
  `register_number` still wins.
- **Signal-less register** — a register that *is* a single value needs no
  `[[signals]]` block; put the decoding fields at the frame level and one
  full-width signal (`length × 16` bits) is synthesised:

  ```toml
  [frame.modbus.0x138F]
  register_type = "input"
  length = 1
  name = "Inverter_Temperature"
  factor = 0.1
  unit = "°C"
  ```

## Versioning

Released as git tags (`vMAJOR.MINOR.PATCH`); consumers pin a tag:

```toml
wiretap-catalog = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.1.0" }
```

## Status & roadmap

- **v0.1.0** — Modbus catalogue parse / decode / encode, both shorthands above,
  31 tests, CI (fmt · clippy `-D warnings` · test). Extracted from the Home
  Assistant ESS add-on so it and WireTAP can share one implementation.
- **Next:** WireTAP's `src-tauri` moves Modbus poll-building onto this crate
  (the backend parses the catalogue and owns the polls; a `parse_modbus_catalog`
  command hands the resolved model — shorthands applied — to the frontend, which
  keeps decoding in TS for now). Then the ESS add-on drops its private
  `manifest.rs` and depends on this crate.

Dev loop: pin the tag in `Cargo.toml`, but add a local `[patch]`/`path` override
against a working checkout while iterating, so changes don't need a push/tag to
test. Bump the version + tag a new `vX.Y.Z` to release.

## Licence

MIT © Wired Square.
