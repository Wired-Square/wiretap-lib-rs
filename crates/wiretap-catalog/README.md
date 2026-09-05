# wiretap-catalog

Parser, validator, decoder, writer and DBC bridge for **WireTAP-format device
catalogues** (TOML), across **CAN, Serial and Modbus**. The top of the
[`wiretap-lib`](../../) workspace.

A catalogue describes a device's frames and registers and how to decode them —
an inverter, a battery, a meter, a CAN ECU. WireTAP and the Home Assistant ESS
add-on share this schema, and this crate is the one implementation of it, so
decoding happens once in Rust rather than per consumer.

## What's here

- **`Catalog::parse`** — CAN, Serial and Modbus sections into one resolved
  model: mirror/copy inheritance, header-field masks, mux trees, and the Modbus
  authoring shorthands
- **`validate::validate`** — `{ field, message }` findings: signal and mux
  rules, DBC-name compatibility, Modbus register resolution
- **`decode::decode_frame` / `decode_by_id`** — bytes to signal values.
  16/64-bit signed and unsigned, `factor`/`offset`, byte and word order
  (Sungrow "CDAB"), `enum`/`hex`/`ascii`/`utf8`/`unix_time`, and mux selection
  (single, range `0-3`, list `1,2,5`, nested)
- **`modbus`** — the register poll/encode workflow, sharing the same
  bit-extraction core. Values are exact `Decimal`, so scaling never introduces
  binary-float artefacts
- **`modbus_rtu_stream::ModbusRtuStream`** — reassembles an RTU byte stream,
  boundaries from the RTU length rules and CRC-16/Modbus gating every message.
  Serves a plain serial port and a protocol tunnelled inside a CAN frame id.
  Stateful and order-dependent: feed every frame, in order, one stream per source
- **`dbc`** — import a Vector `.dbc` and export back, including extended
  (`SG_MUL_VAL_`) and flattened multiplex modes
- **`edit::apply_edit`** — comment- and formatting-preserving in-place edits via
  `toml_edit`; only the targeted entry changes
- **`migrate::migrate`** — upgrade a catalogue's *text* to the current schema,
  comment-preserving and idempotent

## Using it

```toml
wiretap-catalog = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "v0.15.0" }
```

```rust
use wiretap_catalog::{Catalog, decode, validate};

let cat = Catalog::parse(toml_text)?;          // shorthands + mirror/copy resolved
let errors = validate::validate(toml_text);    // field-path + message findings

let frame = cat.frame(0x123).unwrap();
let out = decode::decode_frame(&cat, frame, &bytes);
for s in &out.signals {
    println!("{} = {} {}", s.name, s.display, s.unit.as_deref().unwrap_or(""));
}
```

While iterating, pin the tag but add a local `[patch]` or `path` override
against a working checkout, so a change needs no push and no tag to test.

## The schema, briefly

```toml
[meta]
name = "Sungrow SHx"

[meta.modbus]
register_base = 0            # 0 = IEC/0-based, 1 = traditional 3xxxx/4xxxx
default_word_order = "little"

[node."Slave 1"]             # a Modbus slave; it owns the device address
device_address = 1

[frame.modbus.battery_status]   # one Modbus read of a register block
node_address = 1                # which slave, matched by address
register_number = 13019
register_type = "input"         # input | holding | coil | discrete
length = 9                      # register count
interval_ms = 5000              # poll interval

[[frame.modbus.battery_status.signals]]   # a bit-slice of the block
name = "Battery_SoC"
start_bit = 48
bit_length = 16
factor = 0.1
unit = "%"
```

Three shorthands and one fallback are worth knowing:

- **Register from the key** — omit `register_number` and name the frame by its
  register: `[frame.modbus.0x32F9]` or `[frame.modbus.13049]`. An explicit
  `register_number` still wins.
- **Signal-less register** — a register that *is* a single value needs no
  `[[signals]]`; put the decoding fields at frame level and one full-width
  signal (`length × 16` bits) is synthesised.
- **Poll interval** — top-level `interval_ms`, else `[meta.modbus]
  .default_interval`, else 5000 ms. The legacy `[tx]` table is still read.
- **Legacy device address** — a catalogue setting `[meta.modbus]
  .device_address` with no nodes still parses: a slave node is synthesised from
  it and orphaned registers attach to it. A register with no `node_address`
  falls back to that, else `1`.
