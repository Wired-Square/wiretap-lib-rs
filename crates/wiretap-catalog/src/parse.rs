//! Parse a TOML catalogue into the unified [`Catalog`] model.
//!
//! This is a Rust port of WireTAP's `src/utils/catalogParser.ts`
//! (`parseCatalogText`): it resolves the CAN/Serial frame sections including
//! mirror/copy inheritance and header-field masks, and reuses
//! [`crate::modbus::ModbusManifest`] for the Modbus section so the two Modbus
//! authoring shorthands (register-from-key, signal-less register) stay
//! single-sourced.

use std::collections::BTreeMap;

use toml::Value;

use crate::modbus::{ManifestError, ModbusManifest};
use crate::model::*;

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("catalogue is not valid TOML: {0}")]
    Toml(#[from] toml::de::Error),
}

// ---------- small typed accessors over toml::Value ----------

fn get<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    v.as_table().and_then(|t| t.get(key))
}

fn as_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    get(v, key).and_then(Value::as_str)
}

fn as_i64(v: &Value, key: &str) -> Option<i64> {
    get(v, key).and_then(Value::as_integer)
}

/// A number that may be written as an integer or float in TOML.
fn as_f64(v: &Value, key: &str) -> Option<f64> {
    get(v, key).and_then(|n| n.as_float().or_else(|| n.as_integer().map(|i| i as f64)))
}

fn as_bool(v: &Value, key: &str) -> Option<bool> {
    get(v, key).and_then(Value::as_bool)
}

fn as_u32(v: &Value, key: &str) -> Option<u32> {
    as_i64(v, key).and_then(|i| u32::try_from(i).ok())
}

fn parse_endianness(s: &str) -> Option<Endianness> {
    match s {
        "big" => Some(Endianness::Big),
        "little" => Some(Endianness::Little),
        _ => None,
    }
}

fn endianness_at(v: &Value, key: &str) -> Option<Endianness> {
    as_str(v, key).and_then(parse_endianness)
}

fn parse_format(s: &str) -> Option<SignalFormat> {
    match s {
        "enum" => Some(SignalFormat::Enum),
        "ascii" => Some(SignalFormat::Ascii),
        "utf8" => Some(SignalFormat::Utf8),
        "hex" => Some(SignalFormat::Hex),
        "unix_time" => Some(SignalFormat::UnixTime),
        _ => None,
    }
}

fn parse_confidence(s: &str) -> Option<Confidence> {
    match s {
        "none" => Some(Confidence::None),
        "low" => Some(Confidence::Low),
        "medium" => Some(Confidence::Medium),
        "high" => Some(Confidence::High),
        _ => None,
    }
}

/// Parse a CAN/serial/modbus id key (hex `0x..` or decimal) to a number.
/// Mirrors `parseCanId`.
pub fn parse_id(id: &str) -> Option<u32> {
    let t = id.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).ok()
    } else if t.chars().all(|c| c.is_ascii_digit()) && !t.is_empty() {
        t.parse::<u32>().ok()
    } else {
        None
    }
}

/// Find a frame body in a section by its numeric id value (so `0x123` and `291`
/// match). Mirrors `findFrameByNumericId`.
fn find_frame_by_numeric_id<'a>(target: &str, section: &'a Value) -> Option<&'a Value> {
    let target_num = parse_id(target)?;
    let table = section.as_table()?;
    table
        .iter()
        .find(|(k, _)| parse_id(k) == Some(target_num))
        .map(|(_, v)| v)
}

/// `value` may be a number (`copy = 291`) or a string (`copy = "0x123"`).
fn id_ref_to_string(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Integer(i) => Some(i.to_string()),
        _ => None,
    }
}

// ---------- signals / mux ----------

/// Port of `normaliseSignal`: map `byte_order` → `endianness`, carry fields.
fn normalise_signal(raw: &Value, inherited: bool) -> Signal {
    let endianness = endianness_at(raw, "byte_order").or_else(|| endianness_at(raw, "endianness"));
    Signal {
        name: as_str(raw, "name").map(str::to_string),
        start_bit: as_u32(raw, "start_bit"),
        bit_length: as_u32(raw, "bit_length"),
        signed: as_bool(raw, "signed"),
        endianness,
        word_order: endianness_at(raw, "word_order"),
        factor: as_f64(raw, "factor"),
        offset: as_f64(raw, "offset"),
        unit: as_str(raw, "unit").map(str::to_string),
        min: as_f64(raw, "min"),
        max: as_f64(raw, "max"),
        format: as_str(raw, "format").and_then(parse_format),
        enum_map: parse_enum_map(get(raw, "enum")),
        confidence: as_str(raw, "confidence").and_then(parse_confidence),
        inherited: inherited || as_bool(raw, "_inherited").unwrap_or(false),
        ..Default::default()
    }
}

fn parse_enum_map(v: Option<&Value>) -> Option<BTreeMap<i64, String>> {
    let table = v?.as_table()?;
    let mut out = BTreeMap::new();
    for (k, val) in table {
        if let (Ok(key), Some(label)) = (k.parse::<i64>(), val.as_str()) {
            out.insert(key, label.to_string());
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn normalise_signals(arr: Option<&Value>) -> Vec<Signal> {
    arr.and_then(Value::as_array)
        .map(|a| a.iter().map(|s| normalise_signal(s, false)).collect())
        .unwrap_or_default()
}

/// Whether a mux table key denotes a case (numeric, range `0-3`, or list
/// `1,2,5`) rather than a reserved key. Mirrors `isMuxCaseKey`.
fn is_mux_case_key(key: &str) -> bool {
    if matches!(key, "name" | "start_bit" | "bit_length" | "default") {
        return false;
    }
    key.split(',').all(|part| {
        let part = part.trim();
        match part.split_once('-') {
            Some((a, b)) => {
                !a.is_empty()
                    && a.chars().all(|c| c.is_ascii_digit())
                    && !b.is_empty()
                    && b.chars().all(|c| c.is_ascii_digit())
            }
            None => !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()),
        }
    })
}

/// Port of `parseMux`.
fn parse_mux(mux: Option<&Value>) -> Option<Mux> {
    let mux = mux?;
    let table = mux.as_table()?;
    let mut cases = BTreeMap::new();
    for (key, case_data) in table {
        if !is_mux_case_key(key) {
            continue;
        }
        let signals = normalise_signals(get(case_data, "signals"));
        let nested = parse_mux(get(case_data, "mux")).map(Box::new);
        cases.insert(
            key.clone(),
            MuxCase {
                signals,
                mux: nested,
                notes: parse_notes(case_data),
            },
        );
    }
    Some(Mux {
        name: as_str(mux, "name").map(str::to_string),
        start_bit: as_u32(mux, "start_bit").unwrap_or(0),
        bit_length: as_u32(mux, "bit_length").unwrap_or(8),
        default: as_str(mux, "default").map(str::to_string),
        notes: parse_notes(mux),
        cases,
    })
}

/// Normalise the `notes` key (a string or an array of strings) to a list.
fn parse_notes(body: &Value) -> Vec<String> {
    match get(body, "notes") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
        _ => Vec::new(),
    }
}

/// Parse a serial frame's `delimiter` byte array.
fn parse_delimiter(body: &Value) -> Option<Vec<u8>> {
    let arr = get(body, "delimiter")?.as_array()?;
    let bytes: Vec<u8> = arr
        .iter()
        .filter_map(|v| v.as_integer().and_then(|i| u8::try_from(i).ok()))
        .collect();
    (!bytes.is_empty()).then_some(bytes)
}

/// Parse per-frame `[[…checksum]]` (array) or `[…checksum]` (single table).
fn parse_frame_checksums(body: &Value) -> Vec<FrameChecksum> {
    let one_checksum = |c: &Value| -> Option<FrameChecksum> {
        Some(FrameChecksum {
            name: as_str(c, "name").map(str::to_string),
            algorithm: as_str(c, "algorithm")?.to_string(),
            start_byte: as_u32(c, "start_byte")?,
            byte_length: as_u32(c, "byte_length").unwrap_or(1),
            endianness: endianness_at(c, "byte_order").or_else(|| endianness_at(c, "endianness")),
            calc_start_byte: as_u32(c, "calc_start_byte").unwrap_or(0),
            calc_end_byte: as_u32(c, "calc_end_byte"),
        })
    };
    match get(body, "checksum") {
        Some(Value::Array(a)) => a.iter().filter_map(one_checksum).collect(),
        Some(t @ Value::Table(_)) => one_checksum(t).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// Parse the `[node]` table into ordered peer definitions.
fn parse_nodes(root: &Value) -> Vec<NodeDef> {
    let Some(table) = get(root, "node").and_then(Value::as_table) else {
        return Vec::new();
    };
    table
        .iter()
        .map(|(name, body)| NodeDef {
            name: name.clone(),
            notes: parse_notes(body),
        })
        .collect()
}

/// Frame `tx.interval` / `tx.interval_ms` (either spelling).
fn frame_interval(body: &Value) -> Option<u64> {
    let tx = get(body, "tx")?;
    as_i64(tx, "interval")
        .or_else(|| as_i64(tx, "interval_ms"))
        .and_then(|i| u64::try_from(i).ok())
}

// ---------- mirror / copy inheritance ----------

#[derive(Default)]
struct InheritedMeta {
    length: Option<u32>,
    transmitter: Option<String>,
    interval: Option<u64>,
}

struct Resolution {
    signals: Vec<Signal>,
    mux: Option<Mux>,
    mirror_of: Option<String>,
    copy_from: Option<String>,
    inherited: InheritedMeta,
}

fn bit_key(s: &Value) -> String {
    format!(
        "{}:{}",
        as_i64(s, "start_bit").unwrap_or(0),
        as_i64(s, "bit_length").unwrap_or(0)
    )
}

fn raw_signals(body: &Value) -> Vec<Value> {
    get(body, "signals")
        .or_else(|| get(body, "signal"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Port of `resolveMirrorInheritance`.
fn resolve_mirror_inheritance(body: &Value, all_frames: &Value) -> Resolution {
    let copy_from = get(body, "copy").and_then(id_ref_to_string);
    let mirror_of = get(body, "mirror_of").and_then(id_ref_to_string);

    let signals_raw = raw_signals(body);
    let mut mux = get(body, "mux").cloned();
    let mut inherited = InheritedMeta::default();

    // copy: metadata only.
    if let Some(src) = copy_from
        .as_deref()
        .and_then(|c| find_frame_by_numeric_id(c, all_frames))
    {
        inherit_metadata(body, src, &mut inherited);
    }

    // mirror: signals + metadata.
    let mut result_signals: Vec<Signal>;
    if let Some(src) = mirror_of
        .as_deref()
        .and_then(|m| find_frame_by_numeric_id(m, all_frames))
    {
        let primary = raw_signals(src);
        let mirror_by_pos: BTreeMap<String, &Value> =
            signals_raw.iter().map(|s| (bit_key(s), s)).collect();

        // Start with primary signals, overridden by position; inherited unless
        // overridden.
        result_signals = primary
            .iter()
            .map(|ps| match mirror_by_pos.get(&bit_key(ps)) {
                Some(over) => normalise_signal(over, false),
                None => normalise_signal(ps, true),
            })
            .collect();

        // Add mirror signals at new positions (not inherited).
        let primary_positions: std::collections::BTreeSet<String> =
            primary.iter().map(bit_key).collect();
        for ms in &signals_raw {
            if !primary_positions.contains(&bit_key(ms)) {
                result_signals.push(normalise_signal(ms, false));
            }
        }

        // Inherit mux if not locally defined.
        if mux.is_none() {
            if let Some(src_mux) = get(src, "mux") {
                mux = Some(src_mux.clone());
            }
        }

        // Inherit metadata unless this frame is also a copy (copy already did it).
        if copy_from.is_none() {
            inherit_metadata(body, src, &mut inherited);
        }
    } else {
        result_signals = signals_raw
            .iter()
            .map(|s| normalise_signal(s, false))
            .collect();
    }

    Resolution {
        signals: result_signals,
        mux: parse_mux(mux.as_ref()),
        mirror_of,
        copy_from,
        inherited,
    }
}

fn inherit_metadata(body: &Value, src: &Value, out: &mut InheritedMeta) {
    if as_i64(body, "length").is_none() {
        if let Some(len) = as_u32(src, "length") {
            out.length = Some(len);
        }
    }
    if as_str(body, "transmitter").is_none() {
        if let Some(tx) = as_str(src, "transmitter") {
            out.transmitter = Some(tx.to_string());
        }
    }
    if frame_interval(body).is_none() {
        if let Some(iv) = frame_interval(src) {
            out.interval = Some(iv);
        }
    }
}

// ---------- protocol configs ----------

fn parse_header_fields(section: Option<&Value>, serial: bool) -> BTreeMap<String, HeaderField> {
    let mut out = BTreeMap::new();
    let Some(table) = section.and_then(Value::as_table) else {
        return out;
    };
    for (name, def) in table {
        // mask, or (serial only) legacy start_byte + bytes.
        let mask = if let Some(m) = as_u32(def, "mask") {
            m
        } else if serial {
            match as_u32(def, "start_byte") {
                Some(start_byte) => {
                    let bytes = as_u32(def, "bytes").unwrap_or(1);
                    let num_bits = bytes * 8;
                    let base = if num_bits >= 32 {
                        u32::MAX
                    } else {
                        (1u32 << num_bits) - 1
                    };
                    base.wrapping_shl(start_byte * 8)
                }
                None => continue,
            }
        } else {
            continue;
        };

        let endianness =
            endianness_at(def, "endianness").or_else(|| endianness_at(def, "byte_order"));
        let format = as_str(def, "format")
            .filter(|f| *f == "hex" || *f == "decimal")
            .map(str::to_string);
        out.insert(
            name.clone(),
            HeaderField {
                mask,
                shift: as_u32(def, "shift"),
                format,
                endianness,
            },
        );
    }
    out
}

fn parse_can_config(root: &Value) -> Option<CanConfig> {
    let section = get(root, "meta").and_then(|m| get(m, "can")).or_else(|| {
        get(root, "frame")
            .and_then(|f| get(f, "can"))
            .and_then(|c| get(c, "config"))
    })?;

    let cfg = CanConfig {
        default_byte_order: endianness_at(section, "default_byte_order")
            .or_else(|| endianness_at(section, "default_endianness")),
        default_interval: as_i64(section, "default_interval").and_then(|i| u64::try_from(i).ok()),
        default_extended: as_bool(section, "default_extended"),
        default_fd: as_bool(section, "default_fd"),
        frame_id_mask: as_u32(section, "frame_id_mask"),
        fields: parse_header_fields(get(section, "fields"), false),
    };
    if cfg == CanConfig::default() {
        None
    } else {
        Some(cfg)
    }
}

fn parse_serial_config(root: &Value) -> Option<SerialConfig> {
    let section = get(root, "meta").and_then(|m| get(m, "serial"))?;

    let encoding = as_str(section, "encoding")
        .filter(|e| matches!(*e, "slip" | "cobs" | "raw" | "length_prefixed"))
        .map(str::to_string);

    let checksum = get(section, "checksum").and_then(parse_checksum);
    let fields = parse_header_fields(get(section, "fields"), true);

    // Derive byte positions from the field masks once, here, so consumers
    // (WireTAP's adapter, decode) don't each re-derive them.
    let mut cfg = SerialConfig {
        encoding,
        byte_order: endianness_at(section, "byte_order"),
        frame_id_mask: as_u32(section, "frame_id_mask"),
        header_length: as_u32(section, "header_length"),
        min_frame_length: as_u32(section, "min_frame_length"),
        checksum,
        fields,
        ..SerialConfig::default()
    };
    for (name, field) in &cfg.fields {
        let Some((start_byte, bytes)) = crate::decode::mask_to_byte_position(field.mask) else {
            continue;
        };
        let (start_byte, bytes) = (start_byte as u32, bytes as u32);
        let byte_order = field.endianness.unwrap_or(Endianness::Big);
        cfg.header_fields.push(HeaderFieldPosition {
            name: name.clone(),
            mask: field.mask,
            byte_order,
            format: field.format.clone().unwrap_or_else(|| "hex".to_string()),
            start_byte,
            bytes,
        });
        match name.as_str() {
            "id" => {
                cfg.frame_id_start_byte = Some(start_byte);
                cfg.frame_id_bytes = Some(bytes);
                cfg.frame_id_byte_order = Some(byte_order);
            }
            "source_address" => {
                cfg.source_address_start_byte = Some(start_byte);
                cfg.source_address_bytes = Some(bytes);
                cfg.source_address_byte_order = Some(byte_order);
            }
            _ => {}
        }
    }

    if cfg == SerialConfig::default() {
        None
    } else {
        Some(cfg)
    }
}

fn parse_checksum(section: &Value) -> Option<ChecksumConfig> {
    let algorithm = as_str(section, "algorithm")?.to_string();
    let start_byte = as_u32(section, "start_byte")?;
    Some(ChecksumConfig {
        algorithm,
        start_byte,
        byte_length: as_u32(section, "byte_length").unwrap_or(1),
        calc_start_byte: as_u32(section, "calc_start_byte").unwrap_or(0),
        calc_end_byte: as_u32(section, "calc_end_byte"),
        big_endian: as_bool(section, "big_endian").unwrap_or(false),
    })
}

fn parse_modbus_config(root: &Value) -> Option<ModbusConfig> {
    let section = get(root, "meta").and_then(|m| get(m, "modbus"))?;
    let register_base = match as_i64(section, "register_base") {
        Some(0) => Some(0),
        Some(1) => Some(1),
        _ => None,
    };
    let cfg = ModbusConfig {
        device_address: as_i64(section, "device_address").and_then(|i| u8::try_from(i).ok()),
        register_base,
        default_interval: as_i64(section, "default_interval").and_then(|i| u64::try_from(i).ok()),
        default_byte_order: endianness_at(section, "default_byte_order")
            .or_else(|| endianness_at(section, "byte_order")),
        default_word_order: endianness_at(section, "default_word_order"),
    };
    if cfg == ModbusConfig::default() {
        None
    } else {
        Some(cfg)
    }
}

// ---------- modbus frame mapping (reuse ModbusManifest) ----------

fn map_modbus_signal(
    s: &crate::modbus::ModbusSignal,
    base_register: u32,
    register_type: RegisterType,
) -> Signal {
    let enum_map = s.enum_map.as_ref().map(|m| {
        m.iter()
            .filter_map(|(k, v)| k.parse::<i64>().ok().map(|n| (n, v.clone())))
            .collect::<BTreeMap<i64, String>>()
    });
    // Synthesise the signal's own register address + span from its bit offset.
    // Word registers (holding/input) hold 16 bits each; coils/discretes are
    // 1 bit each, so the bit offset maps straight to a coil offset.
    let bits_per_register = if register_type.is_register_bank() {
        16
    } else {
        1
    };
    let modbus_register = base_register + s.start_bit / bits_per_register;
    let modbus_register_count = s.bit_length.div_ceil(bits_per_register) as u16;
    Signal {
        name: Some(s.name.clone()),
        start_bit: Some(s.start_bit),
        bit_length: Some(s.bit_length),
        signed: Some(s.signed),
        endianness: s.byte_order,
        word_order: s.word_order,
        factor: s.factor,
        offset: s.offset,
        unit: s.unit.clone(),
        format: s.format,
        enum_map: enum_map.filter(|m| !m.is_empty()),
        modbus_register: Some(modbus_register),
        modbus_register_count: Some(modbus_register_count),
        ..Default::default()
    }
}

fn modbus_frames(text: &str) -> Vec<Frame> {
    let manifest = match ModbusManifest::parse(text) {
        Ok(m) => m,
        Err(ManifestError::NoFrames) => return Vec::new(),
        // A parse error here means the modbus section is malformed; CAN/serial
        // frames still parse independently, so we just skip modbus frames.
        Err(_) => return Vec::new(),
    };
    manifest
        .frames
        .iter()
        .map(|f| {
            let count = f.length;
            let length = if matches!(f.register_type, RegisterType::Coil | RegisterType::Discrete) {
                (count as u32).div_ceil(8)
            } else {
                count as u32 * 2
            };
            Frame {
                key: f.name.clone(),
                frame_id: f.register_number as u32,
                protocol: Protocol::Modbus,
                name: Some(f.name.clone()),
                length,
                transmitter: None,
                // ModbusFrame.interval_ms is already resolved (frame tx → meta
                // default → built-in default).
                interval: Some(f.interval_ms),
                bus: None,
                is_extended: None,
                is_fd: None,
                signals: f
                    .signals
                    .iter()
                    .map(|s| map_modbus_signal(s, f.register_number as u32, f.register_type))
                    .collect(),
                mux: None,
                mirror_of: None,
                copy_from: None,
                modbus_register_type: Some(f.register_type),
                modbus_register_count: Some(f.length),
                delimiter: None,
                // notes + inherited_fields are filled by a post-pass in
                // `parse()` (the manifest doesn't carry the raw frame body).
                notes: Vec::new(),
                checksums: Vec::new(),
                inherited_fields: Vec::new(),
            }
        })
        .collect()
}

// ---------- top-level ----------

impl Catalog {
    /// Parse a TOML catalogue into the resolved model. Mirrors
    /// `parseCatalogText`.
    pub fn parse(text: &str) -> Result<Catalog, CatalogError> {
        let root: Value = toml::from_str(text)?;

        let meta = Meta {
            name: get(&root, "meta")
                .and_then(|m| as_str(m, "name"))
                .unwrap_or("")
                .to_string(),
            version: get(&root, "meta")
                .and_then(|m| as_u32(m, "version"))
                .unwrap_or(1),
            default_frame: get(&root, "meta")
                .and_then(|m| as_str(m, "default_frame"))
                .and_then(|p| match p {
                    "can" => Some(Protocol::Can),
                    "serial" => Some(Protocol::Serial),
                    "modbus" => Some(Protocol::Modbus),
                    _ => None,
                }),
        };

        let can = parse_can_config(&root);
        let serial = parse_serial_config(&root);
        let modbus = parse_modbus_config(&root);

        let empty = Value::Table(Default::default());
        let can_frames = get(&root, "frame")
            .and_then(|f| get(f, "can"))
            .unwrap_or(&empty);
        let serial_frames = get(&root, "frame")
            .and_then(|f| get(f, "serial"))
            .unwrap_or(&empty);
        let modbus_frames_section = get(&root, "frame")
            .and_then(|f| get(f, "modbus"))
            .unwrap_or(&empty);

        let mut frames: Vec<Frame> = Vec::new();

        // CAN frames.
        if let Some(table) = can_frames.as_table() {
            for (id_key, body) in table {
                if id_key == "config" {
                    continue;
                }
                let Some(num_id) = parse_id(id_key) else {
                    continue;
                };
                let resolved = resolve_mirror_inheritance(body, can_frames);
                let length = as_u32(body, "length")
                    .or(resolved.inherited.length)
                    .unwrap_or(8);
                let is_extended = as_bool(body, "extended")
                    .or(can.as_ref().and_then(|c| c.default_extended))
                    .unwrap_or(num_id > 0x7ff);
                let is_fd = as_bool(body, "fd")
                    .or(can.as_ref().and_then(|c| c.default_fd))
                    .unwrap_or(false);
                // Interval: explicit → copy/mirror source → catalogue default.
                let default_interval = can.as_ref().and_then(|c| c.default_interval);
                let interval = frame_interval(body)
                    .or(resolved.inherited.interval)
                    .or(default_interval);

                // Track which fields were inherited rather than set explicitly
                // (mirrors the per-protocol handlers in the TS catalog parser).
                let mut inherited_fields = Vec::new();
                if as_i64(body, "length").is_none() && resolved.inherited.length.is_some() {
                    inherited_fields.push("length".to_string());
                }
                if as_str(body, "transmitter").is_none() && resolved.inherited.transmitter.is_some()
                {
                    inherited_fields.push("transmitter".to_string());
                }
                if frame_interval(body).is_none() && interval.is_some() {
                    inherited_fields.push("interval".to_string());
                }
                // `extended` is inherited whenever not set explicitly (whether
                // from the catalogue default or auto-detected from the id).
                if as_bool(body, "extended").is_none() {
                    inherited_fields.push("extended".to_string());
                }
                if as_bool(body, "fd").is_none()
                    && can.as_ref().and_then(|c| c.default_fd).is_some()
                {
                    inherited_fields.push("fd".to_string());
                }

                frames.push(Frame {
                    key: id_key.clone(),
                    frame_id: num_id,
                    protocol: Protocol::Can,
                    name: None,
                    length,
                    transmitter: as_str(body, "transmitter")
                        .map(str::to_string)
                        .or(resolved.inherited.transmitter),
                    interval,
                    bus: as_u32(body, "bus"),
                    is_extended: Some(is_extended),
                    is_fd: Some(is_fd),
                    signals: resolved.signals,
                    mux: resolved.mux,
                    mirror_of: resolved.mirror_of,
                    copy_from: resolved.copy_from,
                    modbus_register_type: None,
                    modbus_register_count: None,
                    delimiter: None,
                    notes: parse_notes(body),
                    checksums: parse_frame_checksums(body),
                    inherited_fields,
                });
            }
        }

        // Serial frames (no inheritance).
        if let Some(table) = serial_frames.as_table() {
            for (id_key, body) in table {
                if id_key == "config" {
                    continue;
                }
                let Some(num_id) = parse_id(id_key) else {
                    continue;
                };
                frames.push(Frame {
                    key: id_key.clone(),
                    frame_id: num_id,
                    protocol: Protocol::Serial,
                    name: None,
                    length: as_u32(body, "length").unwrap_or(0),
                    transmitter: as_str(body, "transmitter").map(str::to_string),
                    interval: frame_interval(body),
                    bus: as_u32(body, "bus"),
                    is_extended: None,
                    is_fd: None,
                    signals: normalise_signals(get(body, "signals")),
                    mux: parse_mux(get(body, "mux")),
                    mirror_of: None,
                    copy_from: None,
                    modbus_register_type: None,
                    modbus_register_count: None,
                    delimiter: parse_delimiter(body),
                    notes: parse_notes(body),
                    checksums: parse_frame_checksums(body),
                    inherited_fields: Vec::new(),
                });
            }
        }

        // Modbus frames (reuse ModbusManifest for shorthands). The manifest
        // drops the raw frame body, so backfill notes + inheritance flags from
        // the `[frame.modbus]` table here (device address / register base come
        // from `[meta.modbus]`, so they're always inherited when present).
        let modbus_base = frames.len();
        frames.extend(modbus_frames(text));
        let modbus_default_interval = modbus.as_ref().and_then(|m| m.default_interval);
        for frame in &mut frames[modbus_base..] {
            let body = get(modbus_frames_section, &frame.key);
            frame.notes = body.map(parse_notes).unwrap_or_default();
            let mut inherited = Vec::new();
            if modbus.as_ref().and_then(|m| m.device_address).is_some() {
                inherited.push("deviceAddress".to_string());
            }
            if modbus.as_ref().and_then(|m| m.register_base).is_some() {
                inherited.push("registerBase".to_string());
            }
            let explicit_interval = body.and_then(frame_interval);
            if explicit_interval.is_none() && modbus_default_interval.is_some() {
                inherited.push("interval".to_string());
            }
            frame.inherited_fields = inherited;
        }

        // Protocol determination (mirror TS).
        let has = |section: &Value| {
            section
                .as_table()
                .map(|t| t.keys().any(|k| k != "config"))
                .unwrap_or(false)
        };
        let has_can = has(can_frames);
        let has_serial = has(serial_frames);
        let has_modbus = has(modbus_frames_section);
        let protocol = match meta.default_frame {
            Some(p) => p,
            None if has_modbus && !has_can && !has_serial => Protocol::Modbus,
            None if has_serial && !has_can => Protocol::Serial,
            None => Protocol::Can,
        };

        Ok(Catalog {
            meta,
            protocol,
            can,
            serial,
            modbus,
            frames,
            nodes: parse_nodes(&root),
        })
    }

    /// Find a parsed frame by its numeric id.
    pub fn frame(&self, id: u32) -> Option<&Frame> {
        self.frames.iter().find(|f| f.frame_id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sig<'a>(f: &'a Frame, name: &str) -> &'a Signal {
        f.signals
            .iter()
            .find(|s| s.name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("signal {name} present"))
    }

    #[test]
    fn preserves_authored_key_and_tracks_inheritance() {
        let toml = r#"
[meta]
name = "x"
[meta.can]
default_interval = 500
default_fd = true
[frame.can.0x100]
length = 8
transmitter = "ECU1"
[frame.can.0x101]
copy = "0x100"
"#;
        let c = Catalog::parse(toml).unwrap();
        let base = c.frame(0x100).unwrap();
        assert_eq!(base.key, "0x100"); // authored key preserved (frame_id is numeric)
                                       // 0x100: extended auto-detected, fd from default, interval from default.
        assert!(base.inherited_fields.contains(&"extended".to_string()));
        assert!(base.inherited_fields.contains(&"fd".to_string()));
        assert!(base.inherited_fields.contains(&"interval".to_string()));
        assert!(!base.inherited_fields.contains(&"length".to_string()));
        // 0x101 copies 0x100: length + transmitter inherited from the copy source.
        let cp = c.frame(0x101).unwrap();
        assert_eq!(cp.length, 8);
        assert_eq!(cp.transmitter.as_deref(), Some("ECU1"));
        assert!(cp.inherited_fields.contains(&"length".to_string()));
        assert!(cp.inherited_fields.contains(&"transmitter".to_string()));
    }

    #[test]
    fn parses_frame_notes_both_forms_and_checksums() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 8
notes = "single note"
[[frame.can.0x100.checksum]]
algorithm = "sum8"
start_byte = 7
byte_length = 1
calc_start_byte = 0
calc_end_byte = 7
[frame.can.0x200]
length = 8
notes = ["line one", "line two"]
"#;
        let c = Catalog::parse(toml).unwrap();
        let f1 = c.frame(0x100).unwrap();
        assert_eq!(f1.notes, vec!["single note".to_string()]);
        assert_eq!(f1.checksums.len(), 1);
        assert_eq!(f1.checksums[0].algorithm, "sum8");
        assert_eq!(f1.checksums[0].start_byte, 7);
        assert_eq!(f1.checksums[0].calc_end_byte, Some(7));
        let f2 = c.frame(0x200).unwrap();
        assert_eq!(
            f2.notes,
            vec!["line one".to_string(), "line two".to_string()]
        );
    }

    #[test]
    fn parses_node_table_and_modbus_notes() {
        let toml = r#"
[meta]
name = "x"
[meta.modbus]
device_address = 1
default_interval = 1000
[node.ECU_1]
notes = "the main controller"
[node.Sensor]
[frame.modbus.ems_control]
register_number = 13049
register_type = "holding"
length = 3
notes = "energy management"
"#;
        let c = Catalog::parse(toml).unwrap();
        // Nodes parsed in key order, notes carried.
        let names: Vec<&str> = c.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["ECU_1", "Sensor"]);
        assert_eq!(c.nodes[0].notes, vec!["the main controller".to_string()]);
        // Modbus frame: key, notes, and inherited device address / interval.
        let f = c.frames.iter().find(|f| f.key == "ems_control").unwrap();
        assert_eq!(f.frame_id, 13049);
        assert_eq!(f.modbus_register_type, Some(RegisterType::Holding));
        assert_eq!(f.notes, vec!["energy management".to_string()]);
        assert!(f.inherited_fields.contains(&"deviceAddress".to_string()));
        // explicit frame interval absent → inherited from meta default.
        assert!(f.inherited_fields.contains(&"interval".to_string()));
    }

    #[test]
    fn parses_can_frame_with_signal_and_defaults() {
        let toml = r#"
[meta]
name = "Test"
version = 1

[meta.can]
default_byte_order = "little"

[frame.can.0x123]
length = 8
transmitter = "ECU1"
tx.interval_ms = 100

[[frame.can.0x123.signals]]
name = "RPM"
start_bit = 0
bit_length = 16
factor = 0.25
unit = "rpm"
byte_order = "big"
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.protocol, Protocol::Can);
        assert_eq!(c.meta.name, "Test");
        assert_eq!(
            c.can.as_ref().unwrap().default_byte_order,
            Some(Endianness::Little)
        );
        let f = c.frame(0x123).unwrap();
        assert_eq!(f.length, 8);
        assert_eq!(f.transmitter.as_deref(), Some("ECU1"));
        assert_eq!(f.interval, Some(100));
        assert_eq!(f.is_extended, Some(false)); // 0x123 <= 0x7ff
        assert_eq!(f.is_fd, Some(false));
        let s = sig(f, "RPM");
        assert_eq!(s.start_bit, Some(0));
        assert_eq!(s.bit_length, Some(16));
        assert_eq!(s.factor, Some(0.25));
        // byte_order key maps onto endianness.
        assert_eq!(s.endianness, Some(Endianness::Big));
    }

    #[test]
    fn extended_auto_detected_and_overridable() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x1ABCDE]
length = 8
[frame.can.0x100]
length = 8
extended = true
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.frame(0x1ABCDE).unwrap().is_extended, Some(true)); // > 0x7ff
        assert_eq!(c.frame(0x100).unwrap().is_extended, Some(true)); // explicit
    }

    #[test]
    fn default_extended_and_fd_from_config() {
        let toml = r#"
[meta]
name = "x"
[meta.can]
default_extended = true
default_fd = true
[frame.can.0x10]
length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x10).unwrap();
        assert_eq!(f.is_extended, Some(true)); // config default beats auto-detect
        assert_eq!(f.is_fd, Some(true));
    }

    #[test]
    fn mirror_inherits_signals_and_marks_inherited() {
        let toml = r#"
[meta]
name = "x"

[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "A"
start_bit = 0
bit_length = 8
[[frame.can.0x100.signals]]
name = "B"
start_bit = 8
bit_length = 8

[frame.can.0x200]
mirror_of = "0x100"
[[frame.can.0x200.signals]]
name = "B_override"
start_bit = 8
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x200).unwrap();
        assert_eq!(f.mirror_of.as_deref(), Some("0x100"));
        // A inherited from primary (same position, no override).
        let a = sig(f, "A");
        assert!(a.inherited);
        // Position 8:8 overridden by the mirror's own signal.
        let b = sig(f, "B_override");
        assert!(!b.inherited);
        // Length inherited from the mirror source.
        assert_eq!(f.length, 8);
    }

    #[test]
    fn copy_inherits_metadata_only() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x100]
length = 6
transmitter = "ECU"
tx.interval_ms = 250
[frame.can.0x200]
copy = "0x100"
[[frame.can.0x200.signals]]
name = "S"
start_bit = 0
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(0x200).unwrap();
        assert_eq!(f.copy_from.as_deref(), Some("0x100"));
        assert_eq!(f.length, 6);
        assert_eq!(f.transmitter.as_deref(), Some("ECU"));
        assert_eq!(f.interval, Some(250));
        // copy carries metadata only — signals are the frame's own.
        assert_eq!(f.signals.len(), 1);
        assert!(!sig(f, "S").inherited);
    }

    #[test]
    fn parses_mux_with_ranges_lists_and_nesting() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x300]
length = 8
[frame.can.0x300.mux]
name = "sel"
start_bit = 0
bit_length = 8
[[frame.can.0x300.mux."0-3".signals]]
name = "low"
start_bit = 8
bit_length = 8
[[frame.can.0x300.mux."4,5".signals]]
name = "mid"
start_bit = 8
bit_length = 8
[frame.can.0x300.mux."6".mux]
name = "inner"
start_bit = 16
bit_length = 4
[[frame.can.0x300.mux."6".mux."0".signals]]
name = "deep"
start_bit = 24
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let m = c.frame(0x300).unwrap().mux.as_ref().unwrap();
        assert_eq!(m.name.as_deref(), Some("sel"));
        assert!(m.cases.contains_key("0-3"));
        assert!(m.cases.contains_key("4,5"));
        let nested = m.cases.get("6").unwrap().mux.as_ref().unwrap();
        assert_eq!(nested.name.as_deref(), Some("inner"));
        assert_eq!(
            nested.cases.get("0").unwrap().signals[0].name.as_deref(),
            Some("deep")
        );
    }

    #[test]
    fn parses_mux_and_case_notes() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x300]
length = 8
[frame.can.0x300.mux]
name = "sel"
start_bit = 0
bit_length = 8
notes = "the selector"
[frame.can.0x300.mux."0"]
notes = ["case zero", "second line"]
[[frame.can.0x300.mux."0".signals]]
name = "a"
start_bit = 8
bit_length = 8
"#;
        let m = Catalog::parse(toml)
            .unwrap()
            .frame(0x300)
            .unwrap()
            .mux
            .clone()
            .unwrap();
        assert_eq!(m.notes, vec!["the selector".to_string()]);
        assert_eq!(
            m.cases.get("0").unwrap().notes,
            vec!["case zero".to_string(), "second line".to_string()]
        );
    }

    #[test]
    fn parses_serial_config_and_frames() {
        let toml = r#"
[meta]
name = "ser"
[meta.serial]
encoding = "slip"
byte_order = "big"

[meta.serial.checksum]
algorithm = "crc16"
start_byte = 6
byte_length = 2

[meta.serial.fields]
id = { start_byte = 0, bytes = 2 }
source_address = { start_byte = 2, bytes = 1 }

[frame.serial.0xFDE0]
length = 8
[[frame.serial.0xFDE0.signals]]
name = "V"
start_bit = 0
bit_length = 16
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.protocol, Protocol::Serial);
        let s = c.serial.as_ref().unwrap();
        assert_eq!(s.encoding.as_deref(), Some("slip"));
        assert_eq!(s.byte_order, Some(Endianness::Big));
        assert_eq!(s.checksum.as_ref().unwrap().algorithm, "crc16");
        assert_eq!(s.checksum.as_ref().unwrap().byte_length, 2);
        // legacy start_byte/bytes → mask 0xFFFF for the first two bytes.
        assert_eq!(s.fields.get("id").unwrap().mask, 0xFFFF);
        // Byte positions derived from the masks at parse time.
        assert_eq!(s.frame_id_start_byte, Some(0));
        assert_eq!(s.frame_id_bytes, Some(2));
        assert_eq!(s.frame_id_byte_order, Some(Endianness::Big));
        assert_eq!(s.source_address_start_byte, Some(2));
        assert_eq!(s.source_address_bytes, Some(1));
        // One header_fields position entry per field (sorted by name in the map).
        assert_eq!(s.header_fields.len(), 2);
        let id_pos = s.header_fields.iter().find(|h| h.name == "id").unwrap();
        assert_eq!((id_pos.start_byte, id_pos.bytes), (0, 2));
        assert_eq!(id_pos.format, "hex");
        assert_eq!(c.frame(0xFDE0).unwrap().signals.len(), 1);
    }

    #[test]
    fn reuses_modbus_shorthands() {
        let toml = r#"
[meta]
name = "mb"
[meta.modbus]
register_base = 0
default_word_order = "little"

[frame.modbus.0x138F]
register_type = "input"
length = 1
name = "Inverter_Temperature"
factor = 0.1
unit = "C"
"#;
        let c = Catalog::parse(toml).unwrap();
        assert_eq!(c.protocol, Protocol::Modbus);
        assert_eq!(
            c.modbus.as_ref().unwrap().default_word_order,
            Some(Endianness::Little)
        );
        let f = c.frame(0x138F).unwrap();
        // register-from-key + signal-less shorthands resolved by ModbusManifest.
        assert_eq!(f.modbus_register_type, Some(RegisterType::Input));
        assert_eq!(f.modbus_register_count, Some(1));
        assert_eq!(f.length, 2); // 1 register = 2 bytes
        let s = sig(f, "Inverter_Temperature");
        assert_eq!(s.factor, Some(0.1));
        assert_eq!(s.bit_length, Some(16));
        // Single-register signal sits on the frame's base register.
        assert_eq!(s.modbus_register, Some(0x138F));
        assert_eq!(s.modbus_register_count, Some(1));
    }

    #[test]
    fn synthesises_per_signal_modbus_registers() {
        // A multi-register block: signals carry their own register + span,
        // derived from the frame's base register and each signal's bit offset.
        let toml = r#"
[meta]
name = "mb"
[meta.modbus]
register_base = 0

[frame.modbus.13019]
register_type = "input"
length = 9
name = "Battery_Block"
[[frame.modbus.13019.signals]]
name = "Battery_Voltage"
start_bit = 0
bit_length = 16
[[frame.modbus.13019.signals]]
name = "Battery_Energy"
start_bit = 32
bit_length = 32
"#;
        let c = Catalog::parse(toml).unwrap();
        let f = c.frame(13019).unwrap();
        let v = sig(f, "Battery_Voltage");
        assert_eq!(v.modbus_register, Some(13019)); // base + 0/16
        assert_eq!(v.modbus_register_count, Some(1)); // 16 bits → 1 register
        let e = sig(f, "Battery_Energy");
        assert_eq!(e.modbus_register, Some(13021)); // base + 32/16
        assert_eq!(e.modbus_register_count, Some(2)); // 32 bits → 2 registers
    }

    #[test]
    fn protocol_defaults_to_can_and_respects_default_frame() {
        let mixed = r#"
[meta]
name = "x"
default_frame = "serial"
[frame.can.0x1]
length = 8
[frame.serial.0x2]
length = 8
"#;
        assert_eq!(Catalog::parse(mixed).unwrap().protocol, Protocol::Serial);

        let only_can = "[meta]\nname='x'\n[frame.can.0x1]\nlength=8\n";
        assert_eq!(Catalog::parse(only_can).unwrap().protocol, Protocol::Can);
    }

    #[test]
    fn invalid_toml_errors() {
        assert!(matches!(
            Catalog::parse("not = valid = toml ="),
            Err(CatalogError::Toml(_))
        ));
    }

    #[test]
    fn round_trips_through_json() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x123]
length = 8
[[frame.can.0x123.signals]]
name = "A"
start_bit = 0
bit_length = 8
"#;
        let c = Catalog::parse(toml).unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: Catalog = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}
