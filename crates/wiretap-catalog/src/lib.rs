//! WireTAP catalogue library — the canonical parser, validator, decoder, and
//! writer for WireTAP-format device catalogues (TOML), across CAN, Serial, and
//! Modbus.
//!
//! - [`parse`] — `Catalog::parse` resolves all three frame sections into the
//!   unified [`model`] (`Catalog`/`Frame`/`Signal`/`Mux`).
//! - [`validate`] — field-path + message findings for the editor.
//! - [`decode`] — raw bytes → signal values (the single decode implementation;
//!   [`modbus`] shares its bit-extraction core).
//! - [`modbus`] — the Modbus register-poll/encode model and shorthands.
//! - [`dbc`] — Vector DBC ↔ catalogue TOML import/export.
//!
//! The Modbus parser/decoder was originally extracted from the Home Assistant
//! ESS add-on (MIT, © Wired Square) so WireTAP and the add-on share one
//! implementation.

pub mod dbc;
pub mod decode;
pub mod edit;
pub mod modbus;
pub mod model;
pub mod parse;
pub mod validate;

pub use model::{
    CanConfig, Catalog, ChecksumConfig, Confidence, Endianness, Frame, HeaderField, Meta,
    ModbusConfig, Mux, MuxCase, Protocol, RegisterType, SerialConfig, Signal, SignalFormat,
    ValidationError,
};
pub use parse::CatalogError;
