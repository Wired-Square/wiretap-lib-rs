//! Validate a TOML catalogue, returning field-path + message findings.
//!
//! Port of WireTAP's `src-tauri/src/catalog.rs::validate_catalog` (CAN + meta
//! rules) so the editor's validation output is unchanged, plus a Modbus
//! structural check via [`crate::modbus::ModbusManifest`].

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use toml::Value;

use crate::modbus::{ManifestError, ModbusManifest};
use crate::model::{Endianness, FrameChecksum, ValidationError};
use crate::parse::parse_id;

fn err(field: impl Into<String>, message: impl Into<String>) -> ValidationError {
    ValidationError {
        field: field.into(),
        message: message.into(),
    }
}

/// Validate catalogue TOML. Returns all findings (empty = valid). A TOML
/// syntax error yields a single `toml`-field error, matching the previous
/// backend behaviour.
pub fn validate(content: &str) -> Vec<ValidationError> {
    let parsed: Value = match toml::from_str(content) {
        Ok(v) => v,
        Err(e) => return vec![err("toml", format!("TOML syntax error: {e}"))],
    };
    let Some(table) = parsed.as_table() else {
        return vec![err("toml", "Catalog must be a TOML table")];
    };

    let mut errors = Vec::new();
    validate_meta(table, &mut errors);

    // CAN frames.
    if let Some(can) = table
        .get("frame")
        .and_then(Value::as_table)
        .and_then(|f| f.get("can"))
        .and_then(Value::as_table)
    {
        for (frame_id, frame_def) in can {
            if frame_id == "config" {
                continue;
            }
            validate_can_frame(frame_id, frame_def, &mut errors);
        }
    }

    // Modbus structural check (register resolution / shorthands).
    if table
        .get("frame")
        .and_then(Value::as_table)
        .and_then(|f| f.get("modbus"))
        .is_some()
    {
        if let Err(ManifestError::BadRegister(name)) = ModbusManifest::parse(content) {
            errors.push(err(
                format!("frame.modbus.{name}"),
                format!(
                    "frame '{name}' has no register_number and its name is not a register address (decimal or 0x-hex)"
                ),
            ));
        }
    }

    validate_serial_encoding(table, &mut errors);

    errors
}

/// Serial frames require an encoding (declared in `[meta.serial]` or the legacy
/// `[frame.serial.config]`). Ports the editor's `validateSerialConfig`.
fn validate_serial_encoding(
    table: &toml::map::Map<String, Value>,
    errors: &mut Vec<ValidationError>,
) {
    let serial = table
        .get("frame")
        .and_then(Value::as_table)
        .and_then(|f| f.get("serial"))
        .and_then(Value::as_table);
    let has_serial_frames = serial
        .map(|s| s.keys().any(|k| k != "config"))
        .unwrap_or(false);
    if !has_serial_frames {
        return;
    }
    let encoding_in = |t: Option<&toml::map::Map<String, Value>>| {
        t.and_then(|s| s.get("encoding"))
            .and_then(Value::as_str)
            .map(|e| !e.is_empty())
            .unwrap_or(false)
    };
    let meta_serial = table
        .get("meta")
        .and_then(Value::as_table)
        .and_then(|m| m.get("serial"))
        .and_then(Value::as_table);
    let frame_serial_config = serial
        .and_then(|s| s.get("config"))
        .and_then(Value::as_table);
    if !encoding_in(meta_serial) && !encoding_in(frame_serial_config) {
        errors.push(err(
            "frame.serial.config.encoding",
            "Encoding is required when serial frames exist. Add [frame.serial.config] with encoding = \"slip\", \"cobs\", \"raw\", or \"length_prefixed\".",
        ));
    }
}

fn validate_meta(table: &toml::map::Map<String, Value>, errors: &mut Vec<ValidationError>) {
    let Some(meta) = table.get("meta").and_then(Value::as_table) else {
        errors.push(err("meta", "Missing [meta] section"));
        return;
    };
    if !meta.contains_key("name") {
        errors.push(err(
            "meta.name",
            "Catalog name is required in [meta] section",
        ));
    }
    if let Some(v) = meta.get("version").and_then(Value::as_integer) {
        if v < 1 {
            errors.push(err("meta.version", "Version must be at least 1"));
        }
    }
    if let Some(e) = meta.get("default_endianness").and_then(Value::as_str) {
        if e != "little" && e != "big" {
            errors.push(err(
                "meta.default_endianness",
                format!("Invalid endianness '{e}'. Must be 'little' or 'big'"),
            ));
        }
    }
}

fn validate_can_frame(frame_id: &str, frame_def: &Value, errors: &mut Vec<ValidationError>) {
    let prefix = format!("frame.can.{frame_id}");
    let Some(frame) = frame_def.as_table() else {
        errors.push(err(prefix, "Frame definition must be a table"));
        return;
    };

    if let Some(len) = frame.get("length").and_then(Value::as_integer) {
        if !(0..=64).contains(&len) {
            errors.push(err(
                format!("{prefix}.length"),
                format!("Length {len} must be between 0 and 64"),
            ));
        }
    }

    // signals: accept both the legacy `signal` and the current `signals` key.
    let signals = frame.get("signal").or_else(|| frame.get("signals"));
    if let Some(arr) = signals.and_then(Value::as_array) {
        let mut names: HashMap<String, usize> = HashMap::new();
        for (idx, signal) in arr.iter().enumerate() {
            validate_signal(&prefix, idx, signal, &mut names, errors);
        }
    }

    if let Some(mux) = frame.get("mux") {
        validate_mux_object(&prefix, mux, errors);
    }

    if let Some(tunnel) = frame.get("tunnel") {
        validate_tunnel(&prefix, tunnel, errors);
    }
}

/// A `[frame.can.<id>.tunnel]` declaration. The parser drops a tunnel it can't
/// understand rather than failing the file, so a typo would otherwise decode as
/// silence — these are the findings that say why.
fn validate_tunnel(prefix: &str, tunnel: &Value, errors: &mut Vec<ValidationError>) {
    let prefix = format!("{prefix}.tunnel");
    let Some(table) = tunnel.as_table() else {
        errors.push(err(prefix, "Tunnel definition must be a table"));
        return;
    };

    match table.get("protocol").and_then(Value::as_str) {
        Some("modbus_rtu") => {}
        Some(other) => errors.push(err(
            format!("{prefix}.protocol"),
            format!("Unknown tunnel protocol '{other}' (expected 'modbus_rtu')"),
        )),
        None => errors.push(err(
            format!("{prefix}.protocol"),
            "Tunnel requires a protocol (expected 'modbus_rtu')",
        )),
    }

    if let Some(addr) = table.get("device_address").and_then(Value::as_integer) {
        if !(1..=247).contains(&addr) {
            errors.push(err(
                format!("{prefix}.device_address"),
                format!("Device address {addr} must be between 1 and 247"),
            ));
        }
    }
}

fn validate_signal(
    prefix: &str,
    idx: usize,
    signal: &Value,
    names: &mut HashMap<String, usize>,
    errors: &mut Vec<ValidationError>,
) {
    let Some(table) = signal.as_table() else {
        errors.push(err(
            format!("{prefix}.signal[{idx}]"),
            "Signal must be a table",
        ));
        return;
    };

    let name = match table.get("name") {
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            errors.push(err(
                format!("{prefix}.signal[{idx}].name"),
                "Signal name must be a string",
            ));
            return;
        }
        None => {
            errors.push(err(
                format!("{prefix}.signal[{idx}]"),
                "Signal must have a name",
            ));
            return;
        }
    };

    if let Some(prev) = names.get(&name) {
        errors.push(err(
            format!("{prefix}.signal[{idx}].name"),
            format!("Duplicate signal name '{name}' (first defined at index {prev})"),
        ));
    } else {
        names.insert(name.clone(), idx);
    }

    // DBC-compat: max 32 chars, alphanumeric + underscore only.
    if name.len() > 32 {
        errors.push(err(
            format!("{prefix}.signal[{idx}].name"),
            format!(
                "Signal name '{name}' exceeds DBC limit of 32 characters ({} chars)",
                name.len()
            ),
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        errors.push(err(
            format!("{prefix}.signal[{idx}].name"),
            format!("Signal name '{name}' contains invalid characters for DBC export (only A-Z, a-z, 0-9, _ allowed)"),
        ));
    }

    match table.get("start_bit") {
        Some(sb) => {
            if let Some(bit) = sb.as_integer() {
                if bit < 0 {
                    errors.push(err(
                        format!("{prefix}.signal[{idx}].start_bit"),
                        "start_bit must be non-negative",
                    ));
                }
            }
        }
        None => errors.push(err(
            format!("{prefix}.signal[{idx}]"),
            format!("Signal '{name}' must have start_bit"),
        )),
    }

    match table.get("bit_length") {
        Some(bl) => {
            if let Some(len) = bl.as_integer() {
                if !(1..=64).contains(&len) {
                    errors.push(err(
                        format!("{prefix}.signal[{idx}].bit_length"),
                        format!("bit_length {len} must be between 1 and 64"),
                    ));
                }
            }
        }
        None => errors.push(err(
            format!("{prefix}.signal[{idx}]"),
            format!("Signal '{name}' must have bit_length"),
        )),
    }

    if let Some(e) = table.get("endianness").and_then(Value::as_str) {
        if e != "little" && e != "big" {
            errors.push(err(
                format!("{prefix}.signal[{idx}].endianness"),
                format!("Invalid endianness '{e}'. Must be 'little' or 'big'"),
            ));
        }
    }

    let num = |v: &Value| v.as_float().or_else(|| v.as_integer().map(|i| i as f64));
    if let (Some(min), Some(max)) = (
        table.get("min").and_then(num),
        table.get("max").and_then(num),
    ) {
        if min > max {
            errors.push(err(
                format!("{prefix}.signal[{idx}]"),
                format!("Signal '{name}' has min ({min}) greater than max ({max})"),
            ));
        }
    }
}

fn validate_mux_object(prefix: &str, mux: &Value, errors: &mut Vec<ValidationError>) {
    let mux_prefix = format!("{prefix}.mux");
    let Some(table) = mux.as_table() else {
        errors.push(err(mux_prefix, "Mux must be a table"));
        return;
    };

    let mux_name = match table.get("name") {
        Some(Value::String(s)) => s.clone(),
        Some(_) => {
            errors.push(err(
                format!("{mux_prefix}.name"),
                "Mux name must be a string",
            ));
            "unknown".to_string()
        }
        None => {
            errors.push(err(mux_prefix.clone(), "Mux must have a name"));
            "unknown".to_string()
        }
    };

    if !table.contains_key("start_bit") {
        errors.push(err(
            mux_prefix.clone(),
            format!("Mux '{mux_name}' must have start_bit"),
        ));
    }
    if !table.contains_key("bit_length") {
        errors.push(err(
            mux_prefix.clone(),
            format!("Mux '{mux_name}' must have bit_length"),
        ));
    }

    let reserved: HashSet<&str> = ["name", "start_bit", "bit_length", "default"]
        .into_iter()
        .collect();
    for (key, case_value) in table {
        if reserved.contains(key.as_str()) || key.parse::<i64>().is_err() {
            continue;
        }
        let case_prefix = format!("{mux_prefix}.{key}");
        let Some(case) = case_value.as_table() else {
            continue;
        };
        if let Some(arr) = case.get("signals").and_then(Value::as_array) {
            let mut names: HashMap<String, usize> = HashMap::new();
            for (i, signal) in arr.iter().enumerate() {
                validate_signal(&case_prefix, i, signal, &mut names, errors);
            }
        }
        if let Some(nested) = case.get("mux") {
            validate_mux_object(&case_prefix, nested, errors);
        }
    }
}

// ===========================================================================
// Granular field validators — the single source of truth for the editor's
// per-form, save-time validation (ported verbatim from the former TS
// `validate.ts` + `protocols/*.ts`). Exposed over WS as `catalog.validate*`.
// ===========================================================================

/// The algorithm ids a catalogue may declare.
///
/// Owned by [`wiretap_checksum`], beside the specification they serialise — this
/// list had been transcribed from the editor, so it could not know about a
/// twelfth algorithm nor about the two parameterised shapes discovery now
/// solves.
fn checksum_algorithm_ids() -> Vec<&'static str> {
    wiretap_checksum::all_algorithm_ids()
}

fn is_hex_id(s: &str) -> bool {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or(false)
}

fn is_dec_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}

fn is_identifier(s: &str) -> bool {
    let mut cs = s.chars();
    match cs.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    cs.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Resolve a possibly-negative byte index against a frame length (mirrors the
/// editor's `resolveByteIndexSync`: `-1` → last byte).
fn resolve_byte_index(index: i64, frame_length: i64) -> i64 {
    if index >= 0 {
        index
    } else {
        (frame_length + index).max(0)
    }
}

// ---- meta ----

#[derive(Debug, Default, Deserialize)]
pub struct MetaInput {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: i64,
}

pub fn validate_meta_fields(m: &MetaInput) -> Vec<ValidationError> {
    let mut e = Vec::new();
    if m.name.trim().is_empty() {
        e.push(err("meta.name", "Name is required"));
    }
    if m.version < 1 {
        e.push(err("meta.version", "Version must be at least 1"));
    }
    e
}

// ---- signal ----

#[derive(Debug, Default, Deserialize)]
pub struct SignalInput {
    #[serde(default)]
    pub name: String,
    pub start_bit: Option<i64>,
    pub bit_length: Option<i64>,
    pub endianness: Option<String>,
    pub min: Option<f64>,
    pub max: Option<f64>,
    pub format: Option<String>,
    #[serde(rename = "enum")]
    pub enum_map: Option<serde_json::Value>,
}

pub fn validate_signal_fields(s: &SignalInput) -> Vec<ValidationError> {
    let mut e = Vec::new();
    if s.name.trim().is_empty() {
        e.push(err("signal.name", "Name is required"));
    }
    match s.start_bit {
        Some(b) if b >= 0 => {}
        _ => e.push(err(
            "signal.start_bit",
            "Start bit must be a non-negative integer",
        )),
    }
    let is_string_format = matches!(s.format.as_deref(), Some("utf8" | "ascii" | "hex"));
    let max_bits = if is_string_format { 2048 } else { 64 };
    match s.bit_length {
        Some(b) if b >= 1 && b <= max_bits => {}
        _ => e.push(err(
            "signal.bit_length",
            if is_string_format {
                "Bit length must be an integer between 1 and 2048 for string formats".to_string()
            } else {
                "Bit length must be an integer between 1 and 64".to_string()
            },
        )),
    }
    if let Some(end) = s.endianness.as_deref() {
        if end != "little" && end != "big" {
            e.push(err(
                "signal.endianness",
                "Endianness must be \"little\" or \"big\"",
            ));
        }
    }
    if let (Some(min), Some(max)) = (s.min, s.max) {
        if min > max {
            e.push(err("signal.range", "Min cannot be greater than max"));
        }
    }
    if let Some(v) = &s.enum_map {
        if !v.is_object() {
            e.push(err(
                "signal.enum",
                "Enum must be a map of string keys to string values",
            ));
        }
    }
    e
}

// ---- checksum ----

fn default_frame_length() -> i64 {
    256
}

#[derive(Debug, Deserialize)]
pub struct ChecksumInput {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub algorithm: String,
    pub start_byte: Option<i64>,
    pub byte_length: Option<i64>,
    pub endianness: Option<String>,
    pub calc_start_byte: Option<i64>,
    pub calc_end_byte: Option<i64>,
    #[serde(default = "default_frame_length")]
    pub frame_length: i64,
}

/// How well a declared checksum reproduces real frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumVerification {
    /// Frames the declaration reproduced.
    pub matched: usize,
    /// Frames it was measured against. Frames that cannot carry the checksum, or
    /// leave nothing to calculate over, are excluded rather than counted as
    /// failures — one bare acknowledgement sharing a link must not condemn the
    /// declaration.
    pub total: usize,
}

impl ChecksumVerification {
    pub fn holds(&self) -> bool {
        self.total > 0 && self.matched == self.total
    }
}

/// Check a declared checksum against real frames.
///
/// The payoff of depending on [`wiretap_checksum`]: a catalogue's declaration is
/// evaluated by the engine that discovers checksums, rather than by a second
/// implementation that can disagree with it.
///
/// It goes through [`FrameChecksum::specification`] rather than the algorithm id,
/// and that distinction is the whole point — a sum with a constant offset is
/// stored as `sum8` with the offset beside it, so a verifier reading only the id
/// would reproduce a *different* checksum and report a correct declaration as
/// completely broken.
///
/// `None` when the declaration is not coherent enough to evaluate: an unknown
/// algorithm, or a `crc_custom` missing its polynomial.
pub fn verify_frame_checksum(
    declared: &FrameChecksum,
    frames: &[Vec<u8>],
) -> Option<ChecksumVerification> {
    let specification = declared.specification()?;
    let big_endian = !matches!(declared.endianness, Some(Endianness::Little));
    let byte_length = declared.byte_length as usize;
    let calc_end = declared.calc_end_byte.unwrap_or(declared.start_byte);

    let mut matched = 0;
    let mut total = 0;
    for frame in frames {
        let Some(range) = wiretap_checksum::calculated_range(
            frame.len(),
            declared.start_byte,
            byte_length,
            declared.calc_start_byte,
            calc_end,
        ) else {
            continue;
        };
        total += 1;
        let expected =
            wiretap_checksum::extract_checksum(frame, declared.start_byte, byte_length, big_endian);
        if specification.calculate(&frame[range]) == expected {
            matched += 1;
        }
    }

    Some(ChecksumVerification { matched, total })
}

pub fn validate_checksum_fields(c: &ChecksumInput) -> Vec<ValidationError> {
    let mut e = Vec::new();
    let frame_length = c.frame_length;

    if c.name.trim().is_empty() {
        e.push(err("checksum.name", "Name is required"));
    }
    if !checksum_algorithm_ids().contains(&c.algorithm.as_str()) {
        e.push(err(
            "checksum.algorithm",
            format!(
                "Algorithm must be one of: {}",
                checksum_algorithm_ids().join(", ")
            ),
        ));
    }

    // start_byte (supports negative indexing).
    match c.start_byte {
        None => e.push(err("checksum.start_byte", "Start byte must be an integer")),
        Some(sb) => {
            let resolved = resolve_byte_index(sb, frame_length);
            if resolved < 0 || resolved >= frame_length {
                e.push(err(
                    "checksum.start_byte",
                    if sb < 0 {
                        format!(
                            "Start byte {sb} resolves to {resolved}, which is out of range [0, {}]",
                            frame_length - 1
                        )
                    } else {
                        format!("Start byte must be less than frame length ({frame_length})")
                    },
                ));
            }
        }
    }

    // byte_length.
    let byte_length = c.byte_length.unwrap_or(0);
    if !(1..=4).contains(&byte_length) {
        e.push(err(
            "checksum.byte_length",
            "Byte length must be an integer between 1 and 4",
        ));
    }

    // Fits in frame (resolved start + length).
    if let Some(sb) = c.start_byte {
        let resolved = resolve_byte_index(sb, frame_length);
        if resolved >= 0 && resolved + byte_length > frame_length {
            e.push(err(
                "checksum.start_byte",
                format!("Checksum position (byte {resolved} + {byte_length}) exceeds frame length ({frame_length})"),
            ));
        }
    }

    if let Some(end) = c.endianness.as_deref() {
        if end != "little" && end != "big" {
            e.push(err(
                "checksum.endianness",
                "Endianness must be \"little\" or \"big\"",
            ));
        }
    }

    // calc range (supports negative indexing).
    match c.calc_start_byte {
        None => e.push(err(
            "checksum.calc_start_byte",
            "Calculation start byte must be an integer",
        )),
        Some(cs) => {
            let resolved = resolve_byte_index(cs, frame_length);
            if resolved < 0 || resolved >= frame_length {
                e.push(err(
                    "checksum.calc_start_byte",
                    if cs < 0 {
                        format!("Calculation start byte {cs} resolves to {resolved}, which is out of range")
                    } else {
                        "Calculation start byte must be within frame bounds".to_string()
                    },
                ));
            }
        }
    }
    match c.calc_end_byte {
        None => e.push(err(
            "checksum.calc_end_byte",
            "Calculation end byte must be an integer",
        )),
        Some(ce) => {
            let resolved = resolve_byte_index(ce, frame_length);
            if resolved < 1 || resolved > frame_length {
                e.push(err(
                    "checksum.calc_end_byte",
                    if ce < 0 {
                        format!("Calculation end byte {ce} resolves to {resolved}, which is out of range")
                    } else {
                        format!("Calculation end byte ({ce}) exceeds frame length ({frame_length})")
                    },
                ));
            }
        }
    }
    if let (Some(cs), Some(ce)) = (c.calc_start_byte, c.calc_end_byte) {
        let rs = resolve_byte_index(cs, frame_length);
        let re = resolve_byte_index(ce, frame_length);
        if rs >= re {
            e.push(err(
                "checksum.calc_range",
                format!("Calculation range is invalid: start ({rs}) must be less than end ({re})"),
            ));
        }
    }
    e
}

// ---- frame (common + protocol config) ----

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FrameInput {
    #[serde(default)]
    pub protocol: String,
    /// Identity: CAN id, serial frame_id, or the Modbus table key.
    #[serde(default)]
    pub key: String,
    pub length: Option<i64>,
    pub transmitter: Option<String>,
    pub interval: Option<i64>,
    pub max_length: Option<i64>,
    // CAN
    pub extended: Option<bool>,
    // Modbus
    pub register_number: Option<i64>,
    pub device_address: Option<i64>,
    pub register_type: Option<String>,
    pub register_base: Option<i64>,
    /// The device (slave) address a register is read from; matched to a node.
    pub node_address: Option<i64>,
    // Serial
    pub delimiter: Option<Vec<i64>>,
    // Context
    #[serde(default)]
    pub existing_keys: Vec<String>,
    pub original_key: Option<String>,
    #[serde(default)]
    pub available_peers: Vec<String>,
}

pub fn validate_frame_fields(f: &FrameInput) -> Vec<ValidationError> {
    let mut e = Vec::new();

    // Common fields.
    let max_len = f.max_length.unwrap_or(64);
    if let Some(len) = f.length {
        if len < 0 || len > max_len {
            e.push(err(
                "length",
                format!("Length must be between 0 and {max_len}"),
            ));
        }
    }
    if let Some(iv) = f.interval {
        if iv < 0 {
            e.push(err("interval", "Interval must be >= 0"));
        }
    }
    if let Some(tx) = f.transmitter.as_deref().filter(|t| !t.is_empty()) {
        if !f.available_peers.is_empty() && !f.available_peers.iter().any(|p| p == tx) {
            e.push(err(
                "transmitter",
                format!(
                    "Transmitter must be one of the known peers ({})",
                    f.available_peers.join(", ")
                ),
            ));
        }
    }

    let is_unique = |id: &str| {
        let original = f.original_key.as_deref();
        original != Some(id) && f.existing_keys.iter().any(|k| k == id)
    };

    match f.protocol.as_str() {
        "can" => {
            let id = f.key.trim();
            if id.is_empty() {
                e.push(err("id", "ID is required"));
                return e;
            }
            if !is_hex_id(id) && !is_dec_id(id) {
                e.push(err(
                    "id",
                    "ID must be hex (e.g., \"0x123\") or decimal (e.g., \"291\")",
                ));
            } else if let Some(num) = parse_id(id) {
                // Extended when explicitly set, else inferred from the id width
                // (so the legacy editor, which doesn't pass `extended`, isn't
                // newly rejected).
                let extended = f.extended.unwrap_or(num > 0x7ff);
                let max = if extended { 0x1FFF_FFFF } else { 0x7FF };
                if num > max {
                    e.push(err(
                        "id",
                        if extended {
                            "Extended ID must be 0-536870911 (0x1FFFFFFF)"
                        } else {
                            "Standard ID must be 0-2047 (0x7FF)"
                        },
                    ));
                }
            }
            if is_unique(id) {
                e.push(err("id", format!("CAN frame with ID {id} already exists")));
            }
        }
        "modbus" => {
            if let Some(reg) = f.register_number {
                if !(0..=65535).contains(&reg) {
                    e.push(err("register_number", "Register number must be 0-65535"));
                }
            }
            // A register names its slave by address (matched to a node by
            // `device_address`). Valid Modbus slave addresses are 1-247
            // (0 is broadcast, 248-255 reserved).
            if let Some(addr) = f.node_address {
                if !(1..=247).contains(&addr) {
                    e.push(err(
                        "node_address",
                        "Slave address must be between 1 and 247",
                    ));
                }
            }
            if let Some(rt) = f.register_type.as_deref() {
                if !matches!(rt, "holding" | "input" | "coil" | "discrete") {
                    e.push(err(
                        "register_type",
                        "Register type must be: holding, input, coil, or discrete",
                    ));
                }
            }
            if let Some(rb) = f.register_base {
                if rb != 0 && rb != 1 {
                    e.push(err("register_base", "Register base must be 0 or 1"));
                }
            }
            // Register comes from a numeric key OR an explicit register_number.
            if parse_id(&f.key).is_none() && f.register_number.is_none() {
                e.push(err(
                    "register_number",
                    "Name isn't a register — enter a register number, or name the frame by its register (e.g. 2581 or 0x32F9).",
                ));
            }
        }
        "serial" => {
            let id = f.key.trim();
            if id.is_empty() {
                e.push(err("frame_id", "Frame identifier is required"));
            } else if !is_hex_id(id) && !is_dec_id(id) && !is_identifier(id) {
                e.push(err(
                    "frame_id",
                    "Frame identifier must be hex like \"0x123\", a decimal number, or a valid identifier",
                ));
            }
            if !id.is_empty() && is_unique(id) {
                e.push(err(
                    "frame_id",
                    format!("Serial frame \"{id}\" already exists"),
                ));
            }
            if let Some(delim) = &f.delimiter {
                if delim.iter().any(|b| !(0..=255).contains(b)) {
                    e.push(err("delimiter", "Delimiter bytes must be integers 0-255"));
                }
            }
        }
        other => e.push(err("protocol", format!("Unknown protocol: {other}"))),
    }
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(errs: &[ValidationError]) -> Vec<&str> {
        errs.iter().map(|e| e.field.as_str()).collect()
    }

    #[test]
    fn valid_catalogue_has_no_errors() {
        let toml = r#"
[meta]
name = "ok"
version = 1
[frame.can.0x123]
length = 8
[[frame.can.0x123.signals]]
name = "RPM"
start_bit = 0
bit_length = 16
"#;
        assert!(validate(toml).is_empty());
    }

    #[test]
    fn missing_meta_and_name() {
        assert_eq!(
            fields(&validate("[frame.can.0x1]\nlength=8\n")),
            vec!["meta"]
        );
        let errs = validate("[meta]\nversion=1\n");
        assert_eq!(fields(&errs), vec!["meta.name"]);
    }

    #[test]
    fn signal_rules() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x10]
length = 80
[[frame.can.0x10.signals]]
name = "Has Space"
start_bit = 0
bit_length = 100
[[frame.can.0x10.signals]]
name = "Has Space"
start_bit = 8
bit_length = 8
"#;
        let errs = validate(toml);
        let msgs: Vec<&str> = errs.iter().map(|e| e.message.as_str()).collect();
        assert!(errs.iter().any(|e| e.field == "frame.can.0x10.length"));
        assert!(msgs.iter().any(|m| m.contains("between 1 and 64")));
        assert!(msgs.iter().any(|m| m.contains("invalid characters")));
        assert!(msgs.iter().any(|m| m.contains("Duplicate signal name")));
    }

    #[test]
    fn mux_requires_selector_fields() {
        let toml = r#"
[meta]
name = "x"
[frame.can.0x20]
length = 8
[frame.can.0x20.mux]
name = "sel"
"#;
        let errs = validate(toml);
        let msgs: Vec<&str> = errs.iter().map(|e| e.message.as_str()).collect();
        assert!(msgs.iter().any(|m| m.contains("must have start_bit")));
        assert!(msgs.iter().any(|m| m.contains("must have bit_length")));
    }

    #[test]
    fn modbus_bad_register_reported() {
        let toml = r#"
[meta]
name = "x"
[frame.modbus.not_a_register]
register_type = "input"
length = 1
[[frame.modbus.not_a_register.signals]]
name = "A"
start_bit = 0
bit_length = 16
"#;
        let errs = validate(toml);
        assert_eq!(fields(&errs), vec!["frame.modbus.not_a_register"]);
    }

    #[test]
    fn tunnel_rules() {
        let case = |body: &str| {
            let toml = format!(
                "[meta]\nname = \"x\"\n[frame.can.\"0x1E0\"]\nlength = 8\n[frame.can.\"0x1E0\".tunnel]\n{body}"
            );
            validate(&toml)
                .into_iter()
                .map(|e| e.field)
                .collect::<Vec<_>>()
        };

        assert!(case("protocol = \"modbus_rtu\"\ndevice_address = 1\n").is_empty());
        assert!(case("protocol = \"modbus_rtu\"\n").is_empty());
        assert_eq!(
            case("protocol = \"j1939_tp\"\n"),
            vec!["frame.can.0x1E0.tunnel.protocol"]
        );
        assert_eq!(
            case("device_address = 1\n"),
            vec!["frame.can.0x1E0.tunnel.protocol"]
        );
        assert_eq!(
            case("protocol = \"modbus_rtu\"\ndevice_address = 0\n"),
            vec!["frame.can.0x1E0.tunnel.device_address"]
        );
        assert_eq!(
            case("protocol = \"modbus_rtu\"\ndevice_address = 248\n"),
            vec!["frame.can.0x1E0.tunnel.device_address"]
        );
    }

    #[test]
    fn toml_syntax_error_is_single_finding() {
        let errs = validate("not = valid = toml =");
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].field, "toml");
    }

    #[test]
    fn serial_frames_require_encoding() {
        let with_frames = r#"
[meta]
name = "x"
[frame.serial.heartbeat]
length = 4
"#;
        let errs = validate(with_frames);
        assert!(errs
            .iter()
            .any(|e| e.field == "frame.serial.config.encoding"));
        // Encoding present (in [meta.serial]) → no finding.
        let ok = r#"
[meta]
name = "x"
[meta.serial]
encoding = "slip"
[frame.serial.heartbeat]
length = 4
"#;
        assert!(!validate(ok)
            .iter()
            .any(|e| e.field == "frame.serial.config.encoding"));
    }

    fn frame(json: serde_json::Value) -> Vec<ValidationError> {
        validate_frame_fields(&serde_json::from_value(json).unwrap())
    }

    #[test]
    fn can_frame_id_format_range_and_uniqueness() {
        // Bad format.
        assert!(
            frame(serde_json::json!({ "protocol": "can", "key": "xyz" }))
                .iter()
                .any(|e| e.field == "id")
        );
        // Standard id out of range (extended explicitly false, as the generic
        // editor sends it).
        assert!(
            frame(serde_json::json!({ "protocol": "can", "key": "0x800", "extended": false }))
                .iter()
                .any(|e| e.message.contains("0x7FF"))
        );
        // Allowed up to 0x1FFFFFFF when extended.
        assert!(
            frame(serde_json::json!({ "protocol": "can", "key": "0x800", "extended": true }))
                .is_empty()
        );
        // Legacy path (no `extended`) infers from id width — not wrongly rejected.
        assert!(frame(serde_json::json!({ "protocol": "can", "key": "0x18FF50E5" })).is_empty());
        // Duplicate (not the original).
        assert!(frame(serde_json::json!({
            "protocol": "can", "key": "0x100",
            "existingKeys": ["0x100"], "originalKey": "0x200"
        }))
        .iter()
        .any(|e| e.message.contains("already exists")));
        // Valid, editing the same key.
        assert!(frame(serde_json::json!({
            "protocol": "can", "key": "0x100",
            "existingKeys": ["0x100"], "originalKey": "0x100"
        }))
        .is_empty());
    }

    #[test]
    fn modbus_needs_register_and_bounds() {
        // Non-numeric name + no register_number.
        assert!(frame(serde_json::json!({
            "protocol": "modbus", "key": "ems_control"
        }))
        .iter()
        .any(|e| e.field == "register_number"));
        // Numeric key supplies the register → ok (no device address on the frame).
        assert!(frame(serde_json::json!({ "protocol": "modbus", "key": "2581" })).is_empty());
        // A valid slave address is accepted.
        assert!(frame(serde_json::json!({
            "protocol": "modbus", "key": "2581", "nodeAddress": 1
        }))
        .is_empty());
        // An out-of-range slave address is rejected.
        assert!(frame(serde_json::json!({
            "protocol": "modbus", "key": "2581", "nodeAddress": 300
        }))
        .iter()
        .any(|e| e.field == "node_address"));
    }

    #[test]
    fn transmitter_must_be_known_peer() {
        let errs = frame(serde_json::json!({
            "protocol": "can", "key": "0x100",
            "transmitter": "Ghost", "availablePeers": ["ECU1", "ECU2"]
        }));
        assert!(errs.iter().any(|e| e.field == "transmitter"));
    }

    #[test]
    fn signal_bounds() {
        let bad: SignalInput = serde_json::from_value(serde_json::json!({
            "name": "", "start_bit": -1, "bit_length": 0
        }))
        .unwrap();
        let errs = validate_signal_fields(&bad);
        assert!(errs.iter().any(|e| e.field == "signal.name"));
        assert!(errs.iter().any(|e| e.field == "signal.start_bit"));
        assert!(errs.iter().any(|e| e.field == "signal.bit_length"));
        // String format allows longer bit lengths.
        let ok: SignalInput = serde_json::from_value(serde_json::json!({
            "name": "vin", "start_bit": 0, "bit_length": 136, "format": "ascii"
        }))
        .unwrap();
        assert!(validate_signal_fields(&ok).is_empty());
    }

    #[test]
    fn checksum_algorithm_and_range() {
        let bad: ChecksumInput = serde_json::from_value(serde_json::json!({
            "name": "crc", "algorithm": "made_up", "start_byte": 7, "byte_length": 1,
            "calc_start_byte": 5, "calc_end_byte": 2, "frame_length": 8
        }))
        .unwrap();
        let errs = validate_checksum_fields(&bad);
        assert!(errs.iter().any(|e| e.field == "checksum.algorithm"));
        assert!(errs.iter().any(|e| e.field == "checksum.calc_range"));
        // Negative start byte resolves against frame length.
        let ok: ChecksumInput = serde_json::from_value(serde_json::json!({
            "name": "crc", "algorithm": "sum8", "start_byte": -1, "byte_length": 1,
            "calc_start_byte": 0, "calc_end_byte": 7, "frame_length": 8
        }))
        .unwrap();
        assert!(validate_checksum_fields(&ok).is_empty());
    }
    /// A declaration, with only the fields a test actually varies.
    fn declared(algorithm: &str, calc_start_byte: i32) -> FrameChecksum {
        FrameChecksum {
            name: None,
            algorithm: algorithm.into(),
            start_byte: -1,
            byte_length: 1,
            endianness: None,
            calc_start_byte,
            calc_end_byte: Some(-1),
            parameters: Default::default(),
            notes: Vec::new(),
        }
    }

    /// Frames whose last byte is `sum8` over `body[from..]`.
    fn summed(count: u8, from: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|i| {
                let mut f = vec![0x10, i, i.wrapping_mul(7)];
                f.push(wiretap_checksum::algorithms::sum8_checksum(&f[from..]));
                f
            })
            .collect()
    }

    /// The payoff of the dependency: a declaration is checked by the engine that
    /// discovers checksums, not by a second implementation that can disagree.
    #[test]
    fn a_declared_checksum_is_verified_against_real_frames() {
        let frames = summed(20, 1);
        let holds = verify_frame_checksum(&declared("sum8", 1), &frames).unwrap();

        assert!(holds.holds(), "{holds:?}");
        assert_eq!(holds.total, 20);
        // The same declaration over the wrong range must not.
        assert!(!verify_frame_checksum(&declared("sum8", 0), &frames)
            .unwrap()
            .holds());
    }

    /// Frames too short to carry the checksum are not evidence against it — the
    /// bare-acknowledgement case that has bitten this engine before.
    #[test]
    fn frames_too_short_are_excluded_rather_than_counted_as_failures() {
        let mut frames = summed(10, 0);
        frames.push(vec![0xF8]);

        let result = verify_frame_checksum(&declared("sum8", 0), &frames).unwrap();
        assert_eq!(result.total, 10, "the acknowledgement was counted");
        assert!(result.holds());
    }

    /// The case a verifier reading only the algorithm id gets *wrong*, rather
    /// than declining: a sum with a constant offset is stored as `sum8`, so
    /// reproducing it from the id alone yields a different byte and calls a
    /// correct declaration completely broken.
    #[test]
    fn a_sum_with_an_offset_is_verified_by_its_parameters_not_its_id() {
        let frames: Vec<Vec<u8>> = (0..20u8)
            .map(|i| {
                let mut f = vec![0x10, i, i.wrapping_mul(7)];
                f.push(wiretap_checksum::algorithms::sum8_checksum(&f).wrapping_add(0xA5));
                f
            })
            .collect();

        let solved = wiretap_checksum::SolvedChecksum {
            target: wiretap_checksum::SolveTarget {
                position: -1,
                byte_length: 1,
                big_endian: true,
                calc_start_byte: 0,
                calc_end_byte: -1,
            },
            specification: wiretap_checksum::ChecksumSpecification::Additive {
                op: wiretap_checksum::AdditiveOp::Sum,
                offset: 0xA5,
            },
            sample_count: 20,
            excluded_count: 0,
            equivalent_ranges: Vec::new(),
        };

        let declared = FrameChecksum::from_solved(Some("cs".into()), &solved);
        assert_eq!(declared.algorithm, "sum8", "stored under the named id");
        assert_eq!(declared.parameters.offset, Some(0xA5));

        let result = verify_frame_checksum(&declared, &frames).unwrap();
        assert!(
            result.holds(),
            "correct declaration reported broken: {result:?}"
        );
    }

    /// The conversion has to survive both directions, or a saved answer is not
    /// the answer that was found.
    #[test]
    fn a_solved_configuration_round_trips_through_the_catalogue_shape() {
        let specifications = [
            wiretap_checksum::ChecksumSpecification::Additive {
                op: wiretap_checksum::AdditiveOp::NegatedSum,
                offset: 0x11,
            },
            wiretap_checksum::ChecksumSpecification::Crc(wiretap_checksum::CrcParameters {
                width: 8,
                polynomial: 0x4D,
                reflect_in: true,
                reflect_out: false,
                init: 0,
                xor_out: 0xB7,
                well_known: false,
                alternatives: Vec::new(),
            }),
        ];

        for specification in specifications {
            let solved = wiretap_checksum::SolvedChecksum {
                target: wiretap_checksum::SolveTarget {
                    position: -1,
                    byte_length: 1,
                    big_endian: true,
                    calc_start_byte: 1,
                    calc_end_byte: -1,
                },
                specification: specification.clone(),
                sample_count: 20,
                excluded_count: 0,
                equivalent_ranges: Vec::new(),
            };
            let declared = FrameChecksum::from_solved(None, &solved);
            assert_eq!(
                declared.specification(),
                Some(specification.clone()),
                "{} did not round trip",
                declared.algorithm
            );
            assert_eq!(declared.start_byte, -1);
            assert_eq!(declared.calc_start_byte, 1);
        }
    }

    /// A solved CRC names no algorithm the sweep knows, so this declines rather
    /// than reporting a failure it did not measure.
    #[test]
    fn a_custom_polynomial_is_declined_not_failed() {
        let incoherent = declared(wiretap_checksum::CRC_CUSTOM, 0);
        assert!(verify_frame_checksum(&incoherent, &[vec![1, 2, 3]]).is_none());
    }

    /// The list is the engine's, not a transcription of it.
    #[test]
    fn every_named_algorithm_is_accepted_by_the_validator() {
        let ids = checksum_algorithm_ids();
        for algorithm in wiretap_checksum::ALL_ALGORITHMS {
            assert!(ids.contains(&algorithm.as_str()), "{algorithm:?} rejected");
        }
        for id in [wiretap_checksum::CRC_CUSTOM, wiretap_checksum::SUM8_NEGATED] {
            assert!(ids.contains(&id), "{id} rejected");
        }
    }
}
