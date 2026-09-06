//! The id-flag layout of the WireTAP binary ingest protocol.
//!
//! Only the layout. The framing, the CRC and the message types stay where both
//! ends of that wire already are, together; this is here because a *third*
//! encoder packs an arbitration id and these flags the same way and shares
//! nothing else at all with either of them. That encoder's own record layout is
//! not shared, and is not this crate's business.
//!
//! The flag positions differ from GVRET's, which marks an extended id with the
//! top bit rather than bit 29. Only the id width is common, and it comes from
//! [`crate::ARB_MASK_EXT`] so the two cannot drift.

/// Bit 29: the arbitration id is 29-bit rather than 11-bit.
pub const ID_EXTENDED: u32 = 1 << 29;
/// Bit 30: a CAN FD frame.
pub const ID_FD: u32 = 1 << 30;
/// Bit 31: a frame this device transmitted, rather than one it observed.
pub const ID_TX: u32 = 1 << 31;
/// What is left once the three flags are masked off.
pub const ID_ARB_MASK: u32 = crate::ARB_MASK_EXT;

#[cfg(test)]
mod tests {
    use super::*;

    /// The three flags and the id must partition the word: no overlap, and
    /// nothing spare. An overlap would let a 29-bit id set a flag; a gap would
    /// be a bit the protocol cannot spell, which is the constraint that makes a
    /// new message type the only way to carry anything but a CAN frame.
    #[test]
    fn the_flags_and_the_id_partition_the_word() {
        assert_eq!(ID_ARB_MASK | ID_EXTENDED | ID_FD | ID_TX, u32::MAX, "a gap");
        assert_eq!(ID_ARB_MASK & (ID_EXTENDED | ID_FD | ID_TX), 0, "an overlap");
    }
}
