//! Modbus catalogue: manifest model, TOML parse, register decode/encode.

pub(crate) mod manifest;
pub use manifest::*;

// The shared enums now live in `crate::model`; re-export so `modbus::Endianness`
// (and friends) remain part of this module's public API.
pub use crate::model::{Endianness, RegisterType, SignalFormat};
