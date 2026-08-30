//! Modbus wire-protocol facts: what a request may ask for, and which bank a
//! function code speaks to.
//!
//! These are properties of Modbus itself, not of any catalogue, and every layer
//! that talks to a device needs them — the RTU reassembler to judge whether a
//! candidate message contradicts itself, a poller to size a read, a scanner to
//! clamp a chunk. Each had grown its own copy. This is the one place the numbers
//! and the function-code table appear.

use crate::model::RegisterType;

/// Longest Modbus RTU message: address + function + byte count + 252 data + CRC.
pub const MAX_RTU_LEN: usize = 256;

/// Largest data block any read or write carries: 125 registers, or 2000 coils
/// packed eight to a byte.
pub const MAX_DATA_BYTES: usize = 250;

/// What one Modbus request may read or write, per the spec. A message claiming
/// more than this contradicts itself, whatever its CRC says, and a read asking
/// for more than this is one the device is entitled to refuse.
pub const MAX_REGISTERS_PER_READ: u16 = 125;
pub const MAX_COILS_PER_READ: u16 = 2000;
pub const MAX_REGISTERS_PER_WRITE: u16 = 123;
pub const MAX_COILS_PER_WRITE: u16 = 1968;

/// The name of a Modbus function code, or `None` for one this library does not
/// model. Bare names: how they are presented — with the code, translated, or at
/// all — is the caller's business.
pub fn function_name(function: u8) -> Option<&'static str> {
    Some(match function {
        0x01 => "Read Coils",
        0x02 => "Read Discrete Inputs",
        0x03 => "Read Holding Registers",
        0x04 => "Read Input Registers",
        0x05 => "Write Single Coil",
        0x06 => "Write Single Register",
        0x0F => "Write Multiple Coils",
        0x10 => "Write Multiple Registers",
        _ => return None,
    })
}

/// The function-code half of [`RegisterType`]. Kept beside the wire constants
/// rather than with the bank semantics in [`crate::model`], because it is the
/// same table the caps below are chosen from.
impl RegisterType {
    /// Which bank a function code reads or writes, or `None` for a code that
    /// addresses no register bank (diagnostics, file records, and anything not
    /// modelled here). The high bit is masked first, so an exception response
    /// resolves to the bank its request asked for.
    pub fn from_function_code(function: u8) -> Option<RegisterType> {
        Some(match function & 0x7F {
            0x01 | 0x05 | 0x0F => RegisterType::Coil,
            0x02 => RegisterType::Discrete,
            0x03 | 0x06 | 0x10 => RegisterType::Holding,
            0x04 => RegisterType::Input,
            _ => return None,
        })
    }

    /// The function code that reads this bank.
    pub fn read_function_code(self) -> u8 {
        match self {
            RegisterType::Coil => 0x01,
            RegisterType::Discrete => 0x02,
            RegisterType::Holding => 0x03,
            RegisterType::Input => 0x04,
        }
    }

    /// How many of this bank one request may read. Coils pack eight to a byte,
    /// so far more of them fit in the same data block.
    pub fn max_per_read(self) -> u16 {
        if self.is_register_bank() {
            MAX_REGISTERS_PER_READ
        } else {
            MAX_COILS_PER_READ
        }
    }

    /// How many data bytes `quantity` of this bank occupies on the wire.
    /// Register banks take two bytes each; coil banks pack eight to a byte.
    pub fn data_bytes(self, quantity: u16) -> usize {
        let quantity = quantity as usize;
        if self.is_register_bank() {
            quantity * 2
        } else {
            quantity.div_ceil(8)
        }
    }

    /// How many of this bank one request may write, or `None` for a read-only
    /// bank. Lower than the read cap: a write request spends header bytes on the
    /// quantity and byte count that a read response does not.
    pub fn max_per_write(self) -> Option<u16> {
        match self {
            RegisterType::Holding => Some(MAX_REGISTERS_PER_WRITE),
            RegisterType::Coil => Some(MAX_COILS_PER_WRITE),
            RegisterType::Input | RegisterType::Discrete => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_codes_round_trip_through_their_bank() {
        for rt in [
            RegisterType::Coil,
            RegisterType::Discrete,
            RegisterType::Holding,
            RegisterType::Input,
        ] {
            assert_eq!(
                RegisterType::from_function_code(rt.read_function_code()),
                Some(rt)
            );
        }
    }

    #[test]
    fn an_exception_resolves_to_the_bank_its_request_asked_for() {
        assert_eq!(
            RegisterType::from_function_code(0x83),
            Some(RegisterType::Holding)
        );
        assert_eq!(
            RegisterType::from_function_code(0x81),
            Some(RegisterType::Coil)
        );
    }

    #[test]
    fn write_codes_map_to_their_bank() {
        for (func, bank) in [
            (0x05, RegisterType::Coil),
            (0x0F, RegisterType::Coil),
            (0x06, RegisterType::Holding),
            (0x10, RegisterType::Holding),
        ] {
            assert_eq!(RegisterType::from_function_code(func), Some(bank));
        }
    }

    #[test]
    fn unmodelled_codes_have_no_bank_and_no_name() {
        // 0x07 (Read Exception Status), 0x14 (Read File Record) and 0x2B
        // (Encapsulated Transport) are real codes that address no bank.
        for func in [0x00, 0x07, 0x14, 0x2B] {
            assert_eq!(RegisterType::from_function_code(func), None);
            assert_eq!(function_name(func), None);
        }
    }

    #[test]
    fn only_writable_banks_have_a_write_cap() {
        for rt in [
            RegisterType::Coil,
            RegisterType::Discrete,
            RegisterType::Holding,
            RegisterType::Input,
        ] {
            assert_eq!(rt.max_per_write().is_some(), rt.is_writable());
        }
    }

    #[test]
    fn coils_pack_eight_to_a_byte_and_registers_take_two() {
        assert_eq!(RegisterType::Holding.data_bytes(10), 20);
        assert_eq!(RegisterType::Input.data_bytes(1), 2);
        assert_eq!(RegisterType::Coil.data_bytes(8), 1);
        // A partial byte still costs a whole one.
        assert_eq!(RegisterType::Coil.data_bytes(9), 2);
        assert_eq!(RegisterType::Discrete.data_bytes(0), 0);
    }

    #[test]
    fn caps_match_the_bank_they_describe() {
        assert_eq!(RegisterType::Holding.max_per_read(), MAX_REGISTERS_PER_READ);
        assert_eq!(RegisterType::Input.max_per_read(), MAX_REGISTERS_PER_READ);
        assert_eq!(RegisterType::Coil.max_per_read(), MAX_COILS_PER_READ);
        assert_eq!(RegisterType::Discrete.max_per_read(), MAX_COILS_PER_READ);
    }
}
