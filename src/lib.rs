//! WireTAP catalogue library.
//!
//! Parse, decode, and encode WireTAP-format device catalogues (TOML). The
//! first protocol is Modbus (`[frame.modbus.*]`) — see [`modbus`].
//!
//! The Modbus parser/decoder was extracted from the Home Assistant ESS add-on
//! (`homeassistant-ess-addon`, MIT, © Wired Square) so WireTAP and the add-on
//! can share one implementation.

pub mod modbus;
