//! Unified catalogue model shared by all protocols (CAN, Serial, Modbus).
//!
//! This is the *resolved* representation produced by [`crate::parse`]: authoring
//! shorthands are expanded, mirror/copy inheritance is applied, and per-frame
//! defaults are folded in. It serialises to JSON for the frontend (camelCase, so
//! the generated TypeScript reads idiomatically) and is the input to
//! [`crate::decode`].
//!
//! The catalogue enums ([`SignalFormat`], [`RegisterType`]) live here; the
//! `modbus` module re-exports them so its public API is unchanged. [`Endianness`]
//! is the protocol-agnostic byte/word ordering — it lives in `wiretap-decode`
//! (the numeric core) and is re-exported here so callers keep using
//! `model::Endianness`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Byte / word ordering — re-exported from the `wiretap-decode` numeric core.
pub use wiretap_decode::Endianness;

/// Which wire protocol a frame/catalogue uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Can,
    Serial,
    Modbus,
}

/// Modbus register class — determines the function code the poller uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegisterType {
    Input,
    #[default]
    Holding,
    Coil,
    Discrete,
}

impl RegisterType {
    /// Read-only telemetry only reads register banks (input/holding);
    /// coil/discrete are parsed but not polled in v1.
    pub fn is_register_bank(self) -> bool {
        matches!(self, RegisterType::Input | RegisterType::Holding)
    }

    /// Whether this register class can be written. In Modbus, `holding`
    /// (FC06/16) and `coil` (FC05/15) are read/write; `input` (FC04) and
    /// `discrete` (FC02) are read-only.
    pub fn is_writable(self) -> bool {
        matches!(self, RegisterType::Holding | RegisterType::Coil)
    }

    /// Lowercase tag, matching the manifest spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            RegisterType::Input => "input",
            RegisterType::Holding => "holding",
            RegisterType::Coil => "coil",
            RegisterType::Discrete => "discrete",
        }
    }
}

/// A signal's data format. Any value here marks the signal as non-numeric
/// (string/opaque) — [`crate::decode`] renders it specially rather than as a
/// plain scaled number. Absent = a plain scaled number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalFormat {
    Ascii,
    Utf8,
    Hex,
    Enum,
    UnixTime,
    #[serde(other)]
    Other,
}

/// Reverse-engineering confidence marker (carried through from the catalogue
/// for the editor/discovery UI; not used by decode).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    None,
    Low,
    Medium,
    High,
}

/// A single decoded field, resolved from the catalogue. Fields are optional
/// because mux-case and inherited signals may carry only overrides; a fully
/// resolved signal for decode has `name`/`start_bit`/`bit_length` set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signal {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_bit: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bit_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
    /// Byte order (the catalogue's legacy key is `endianness`; the newer key is
    /// `byte_order`). Stored here as the resolved byte order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub word_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub factor: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<SignalFormat>,
    /// Value↔label map (`enum` table in the catalogue). Keys are the numeric
    /// register/field value.
    #[serde(default, rename = "enum", skip_serializing_if = "Option::is_none")]
    pub enum_map: Option<BTreeMap<i64, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<Confidence>,
    /// True when this signal was inherited from a mirror/copy source rather
    /// than defined directly on the frame.
    #[serde(default, skip_serializing_if = "is_false")]
    pub inherited: bool,
}

fn is_false(b: &bool) -> bool {
    !*b
}

/// One case of a multiplexer: the signals (and optional nested mux) active when
/// the selector matches this case's key.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MuxCase {
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<Box<Mux>>,
}

/// A multiplexer: a selector bit-field plus the per-case signal sets. Case keys
/// are kept as strings to preserve the catalogue's range/list syntax
/// (`"0"`, `"0-3"`, `"1,2,5"`); [`crate::decode`] matches them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mux {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub start_bit: u32,
    pub bit_length: u32,
    pub cases: BTreeMap<String, MuxCase>,
}

/// A resolved frame: one CAN message / serial frame / Modbus register read,
/// with its signals, mux, and inheritance applied.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Frame {
    /// Numeric identifier: CAN arbitration ID, serial frame id, or Modbus
    /// register number.
    pub frame_id: u32,
    pub protocol: Protocol,
    /// The catalogue table key, when it carries meaning (e.g. a Modbus frame's
    /// `ems_control`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Frame length in bytes.
    pub length: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transmitter: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_extended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_fd: Option<bool>,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<Mux>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror_of: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_from: Option<String>,
    /// Modbus-specific: register class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_register_type: Option<RegisterType>,
    /// Modbus-specific: register count (not bytes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus_register_count: Option<u16>,
}

/// A header field defined by a bitmask over the frame's header bytes (CAN ID
/// bits, or serial header bytes).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderField {
    pub mask: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shift: Option<u32>,
    /// `hex` or `decimal` display.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endianness: Option<Endianness>,
}

/// A serial header field with its byte position derived from the mask at parse
/// time (so consumers don't re-derive it). One entry per `[meta.serial.fields]`
/// field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HeaderFieldPosition {
    pub name: String,
    pub mask: u32,
    pub byte_order: Endianness,
    /// `hex` or `decimal` display.
    pub format: String,
    pub start_byte: u32,
    pub bytes: u32,
}

/// `[meta.can]` defaults.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CanConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_byte_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_extended: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_fd: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_mask: Option<u32>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, HeaderField>,
}

/// `[meta.serial.checksum]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumConfig {
    pub algorithm: String,
    pub start_byte: u32,
    #[serde(default = "one")]
    pub byte_length: u32,
    #[serde(default)]
    pub calc_start_byte: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calc_end_byte: Option<u32>,
    #[serde(default)]
    pub big_endian: bool,
}

fn one() -> u32 {
    1
}

/// `[meta.serial]` defaults.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SerialConfig {
    /// `slip` | `cobs` | `raw` | `length_prefixed`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_mask: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_frame_length: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<ChecksumConfig>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, HeaderField>,
    // ── Derived from `fields` at parse time (byte positions of named fields) ──
    /// Byte position of the `id` field, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_start_byte: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame_id_byte_order: Option<Endianness>,
    /// Byte position of the `source_address` field, when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address_start_byte: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address_bytes: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address_byte_order: Option<Endianness>,
    /// One position entry per header field (the resolved form of `fields`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub header_fields: Vec<HeaderFieldPosition>,
}

/// `[meta.modbus]` defaults.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ModbusConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_address: Option<u8>,
    /// 0 = IEC (0-based); 1 = traditional 1-based with a type prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub register_base: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_byte_order: Option<Endianness>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_word_order: Option<Endianness>,
}

/// `[meta]` — catalogue identity.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Meta {
    pub name: String,
    #[serde(default = "one")]
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_frame: Option<Protocol>,
}

/// A fully parsed, resolved catalogue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub meta: Meta,
    /// The catalogue's dominant protocol (from `meta.default_frame`, else
    /// inferred from which frame sections are present).
    pub protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub can: Option<CanConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial: Option<SerialConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modbus: Option<ModbusConfig>,
    #[serde(default)]
    pub frames: Vec<Frame>,
}

/// A single validation finding (field path + human message).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationError {
    pub field: String,
    pub message: String,
}
