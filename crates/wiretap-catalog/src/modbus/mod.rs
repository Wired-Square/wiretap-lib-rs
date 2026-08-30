//! Modbus catalogue: manifest model, TOML parse, register decode/encode, and
//! the wire-protocol constants every layer that talks to a device shares.

pub(crate) mod manifest;
pub mod protocol;
pub use manifest::*;
pub use protocol::*;

// The shared enums now live in `crate::model`; re-export so `modbus::Endianness`
// (and friends) remain part of this module's public API.
pub use crate::model::{Endianness, RegisterType, SignalFormat};
