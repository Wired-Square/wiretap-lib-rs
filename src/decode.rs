//! Decode raw frame bytes into signal values against a [`Catalog`].
//!
//! Faithful Rust port of WireTAP's `src/utils/bits.ts`,
//! `src/utils/signalDecode.ts` and `src/utils/muxCaseMatch.ts`, plus the
//! plain/mux signal orchestration from `decoderStore.ts`. This is the single
//! decode implementation: the `modbus` module's `decode_frame` reuses
//! [`extract_bits`]/[`apply_word_swap`] from here.

use crate::model::{Catalog, Endianness, Frame, Mux, Protocol, Signal, SignalFormat};

/// A decoded signal value. Mirrors the TS `DecodedValue`.
#[derive(Debug, Clone, PartialEq)]
pub struct Decoded {
    pub name: String,
    /// Raw integer value (pre-scale), as `f64` (lossless to 53 bits).
    pub value: f64,
    /// Scaled numeric value (`raw * factor + offset`), or the raw value for
    /// formats where scaling doesn't apply (enum/text).
    pub scaled: f64,
    /// Human display string (hex digits, enum label, decoded text, timestamp,
    /// or the scaled number).
    pub display: String,
    pub unit: Option<String>,
}

/// A mux selector reading + the case it matched.
#[derive(Debug, Clone, PartialEq)]
pub struct MuxSelector {
    pub name: Option<String>,
    pub value: i64,
    pub matched_case: Option<String>,
    pub start_bit: u32,
    pub bit_length: u32,
}

/// The full decode of one frame: its signals plus any mux selector readings.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FrameDecode {
    pub signals: Vec<Decoded>,
    pub selectors: Vec<MuxSelector>,
}

// ---------- bit extraction (shared with modbus) ----------

/// Extract a bitfield as an `f64`, honouring endianness and sign. Faithful
/// port of `extractBits` (i128 accumulator covers up to 64-bit signals without
/// precision loss; the TS BigInt path is the same algorithm).
pub fn extract_bits(
    bytes: &[u8],
    start_bit: u32,
    bit_length: u32,
    endian: Endianness,
    signed: bool,
) -> f64 {
    if bit_length == 0 {
        return 0.0;
    }
    let mut bits: Vec<u8> = Vec::with_capacity(bytes.len() * 8);
    match endian {
        Endianness::Big => {
            for &b in bytes {
                for k in (0..8).rev() {
                    bits.push((b >> k) & 1);
                }
            }
        }
        Endianness::Little => {
            for &b in bytes {
                for k in 0..8 {
                    bits.push((b >> k) & 1);
                }
            }
        }
    }
    let start = (start_bit as usize).min(bits.len());
    let end = (start + bit_length as usize).min(bits.len());
    let slice = &bits[start..end];

    let mut value: i128 = 0;
    match endian {
        Endianness::Big => {
            for &bit in slice {
                value = (value << 1) | bit as i128;
            }
        }
        Endianness::Little => {
            for &bit in slice.iter().rev() {
                value = (value << 1) | bit as i128;
            }
        }
    }
    if signed {
        let sign_bit: i128 = 1 << (bit_length - 1);
        if value & sign_bit != 0 {
            value -= 1 << bit_length;
        }
    }
    value as f64
}

/// Swap 16-bit words within a signal's byte span (low-word-first →
/// high-word-first) before big-endian extraction — the Sungrow "CDAB" case.
/// Mirrors the word-swap in `decodeSignal` / modbus `apply_word_swap`.
pub fn apply_word_swap(bytes: &mut [u8], start_bit: u32, bit_length: u32) {
    let start_byte = (start_bit / 8) as usize;
    let num_bytes = bit_length.div_ceil(8) as usize;
    let num_words = num_bytes.div_ceil(2);
    let mut words: Vec<(u8, u8)> = Vec::with_capacity(num_words);
    for i in 0..num_words {
        let idx = start_byte + i * 2;
        let a = bytes.get(idx).copied().unwrap_or(0);
        let b = bytes.get(idx + 1).copied().unwrap_or(0);
        words.push((a, b));
    }
    words.reverse();
    for (i, (a, b)) in words.into_iter().enumerate() {
        let idx = start_byte + i * 2;
        if idx < bytes.len() {
            bytes[idx] = a;
        }
        if idx + 1 < bytes.len() {
            bytes[idx + 1] = b;
        }
    }
}

// ---------- single-signal decode (port of signalDecode.ts) ----------

/// Decode one signal from `bytes`. `default_endianness` applies when the signal
/// has no `byte_order`; `default_word_order` likewise (the meta word order, so
/// Modbus multi-register values word-swap without per-signal config).
pub fn decode_signal(
    bytes: &[u8],
    sig: &Signal,
    fallback_name: &str,
    default_endianness: Endianness,
    default_word_order: Option<Endianness>,
) -> Decoded {
    let name = sig
        .name
        .clone()
        .unwrap_or_else(|| fallback_name.to_string());
    let start = sig.start_bit.unwrap_or(0);
    let len = sig.bit_length.unwrap_or(0);
    let endianness = sig.endianness.unwrap_or(default_endianness);
    let word_order = sig.word_order.or(default_word_order);

    // Word-swap for multi-register (>16-bit) little-word-order values.
    let raw = if word_order == Some(Endianness::Little) && len > 16 {
        let mut swapped = bytes.to_vec();
        apply_word_swap(&mut swapped, start, len);
        extract_bits(
            &swapped,
            start,
            len,
            endianness,
            sig.signed.unwrap_or(false),
        )
    } else {
        extract_bits(bytes, start, len, endianness, sig.signed.unwrap_or(false))
    };

    let factor = sig.factor.unwrap_or(1.0);
    let offset = sig.offset.unwrap_or(0.0);
    let scaled = raw * factor + offset;
    let unit = sig.unit.clone();

    match sig.format {
        Some(SignalFormat::Hex) => Decoded {
            name,
            value: raw,
            scaled,
            display: format_hex(raw, len, endianness),
            unit,
        },
        Some(SignalFormat::Enum) => {
            let label = sig
                .enum_map
                .as_ref()
                .and_then(|m| m.get(&(raw as i64)).cloned());
            Decoded {
                name,
                value: raw,
                scaled: raw,
                display: label.unwrap_or_else(|| format!("Unknown ({})", raw as i64)),
                unit: None,
            }
        }
        Some(SignalFormat::Utf8) | Some(SignalFormat::Ascii) => {
            let text = decode_text(bytes, start, len);
            Decoded {
                name,
                value: raw,
                scaled: raw,
                display: if text.is_empty() {
                    "(empty)".to_string()
                } else {
                    text
                },
                unit: None,
            }
        }
        Some(SignalFormat::UnixTime) => Decoded {
            name,
            value: raw,
            scaled,
            display: format_unix_time(scaled),
            unit: None,
        },
        Some(SignalFormat::Other) | None => Decoded {
            name,
            value: raw,
            scaled,
            display: format_number(scaled),
            unit,
        },
    }
}

/// Format a raw value as byte-separated hex (`"1A 2B 3C"`), MSB-first for big
/// endian. Port of `formatHex`.
fn format_hex(value: f64, bit_length: u32, endian: Endianness) -> String {
    let num_bytes = bit_length.div_ceil(8).max(1) as usize;
    let mask: u128 = if bit_length >= 128 {
        u128::MAX
    } else {
        (1u128 << bit_length) - 1
    };
    let mut v = (value as i128 as u128) & mask;
    let mut bytes = Vec::with_capacity(num_bytes);
    for _ in 0..num_bytes {
        bytes.push((v & 0xff) as u8);
        v >>= 8;
    }
    if endian == Endianness::Big {
        bytes.reverse();
    }
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Extract the bytes a text signal spans and decode to a string, dropping NULs.
/// Port of `extractTextBytes` + `bytesToText`.
fn decode_text(bytes: &[u8], start_bit: u32, bit_length: u32) -> String {
    let start_byte = (start_bit / 8) as usize;
    let num_bytes = bit_length.div_ceil(8) as usize;
    let mut out = String::new();
    for i in 0..num_bytes {
        let b = bytes.get(start_byte + i).copied().unwrap_or(0);
        if b != 0 {
            out.push(b as char);
        }
    }
    out
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SS` (UTC). The TS version uses
/// the browser's local timezone; we use UTC for determinism (the frontend may
/// re-localise). Seconds vs milliseconds is auto-detected as in the TS.
fn format_unix_time(value: f64) -> String {
    if !value.is_finite() {
        return format!("Invalid ({value})");
    }
    // > year ~3000 in seconds ⇒ treat as milliseconds.
    let secs = if value > 32_503_680_000.0 {
        (value / 1000.0) as i64
    } else {
        value as i64
    };
    let (y, mo, d, h, mi, s) = civil_from_unix(secs);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

/// Convert a unix timestamp (seconds, UTC) to a civil date-time. Uses Howard
/// Hinnant's days→civil algorithm (proleptic Gregorian).
fn civil_from_unix(secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d, h as u32, mi as u32, s as u32)
}

/// Format a scaled number cleanly, trimming float artefacts (so `555 * 0.1`
/// renders `55.5`, not `55.50000000000001`). Approximates the TS `Decimal`
/// display.
fn format_number(value: f64) -> String {
    if !value.is_finite() {
        return value.to_string();
    }
    if value == value.trunc() && value.abs() < 1e15 {
        return format!("{}", value as i64);
    }
    // Round to 12 significant-ish decimals, then trim trailing zeros.
    let mut s = format!("{value:.12}");
    while s.contains('.') && s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    s
}

// ---------- mux matching (port of muxCaseMatch.ts) ----------

/// Expand a mux case key (`"0"`, `"0-3"`, `"1,2,5"`, `"0-3,7"`) to the set of
/// values it matches. `None` if the key has no numeric parts.
fn parse_mux_case_values(key: &str) -> Option<Vec<i64>> {
    if matches!(key, "name" | "start_bit" | "bit_length" | "default") {
        return None;
    }
    let mut values = Vec::new();
    for part in key.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        // Range a-b (allowing a leading '-' on each bound).
        if let Some((a, b)) = split_range(part) {
            let (min, max) = (a.min(b), a.max(b));
            let capped = if max - min > 1000 { min + 1000 } else { max };
            for v in min..=capped {
                values.push(v);
            }
        } else if let Ok(n) = part.parse::<i64>() {
            values.push(n);
        }
    }
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

/// Split `"a-b"` into signed integer bounds, matching the TS regex
/// `^(-?\d+)-(-?\d+)$`.
fn split_range(part: &str) -> Option<(i64, i64)> {
    let body = part.strip_prefix('-');
    let (neg_a, rest) = match body {
        Some(r) => (true, r),
        None => (false, part),
    };
    let dash = rest.find('-')?;
    let a_digits = &rest[..dash];
    let b_str = &rest[dash + 1..];
    if a_digits.is_empty() || !a_digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let a: i64 = a_digits.parse().ok()?;
    let a = if neg_a { -a } else { a };
    let b: i64 = b_str.parse().ok()?;
    Some((a, b))
}

/// True if `selector` matches the case key pattern.
pub fn mux_case_matches(selector: i64, case_key: &str) -> bool {
    parse_mux_case_values(case_key)
        .map(|vs| vs.contains(&selector))
        .unwrap_or(false)
}

/// First case key matching `selector`, in iteration order.
pub fn find_matching_mux_case<'a>(
    selector: i64,
    keys: impl IntoIterator<Item = &'a str>,
) -> Option<&'a str> {
    keys.into_iter().find(|k| mux_case_matches(selector, k))
}

// ---------- frame decode orchestration (port of decoderStore) ----------

/// Decode every signal (and resolve any mux) in `frame` from `bytes`, choosing
/// the per-protocol default byte/word order from `catalog`.
pub fn decode_frame(catalog: &Catalog, frame: &Frame, bytes: &[u8]) -> FrameDecode {
    let (default_endianness, default_word_order) = frame_defaults(catalog, frame);
    let mut out = FrameDecode::default();

    for (idx, sig) in frame.signals.iter().enumerate() {
        out.signals.push(decode_signal(
            bytes,
            sig,
            &format!("Signal {}", idx + 1),
            default_endianness,
            default_word_order,
        ));
    }

    if let Some(mux) = &frame.mux {
        decode_mux(bytes, mux, default_endianness, default_word_order, &mut out);
    }

    out
}

fn decode_mux(
    bytes: &[u8],
    mux: &Mux,
    default_endianness: Endianness,
    default_word_order: Option<Endianness>,
    out: &mut FrameDecode,
) {
    let selector = extract_bits(
        bytes,
        mux.start_bit,
        mux.bit_length,
        default_endianness,
        false,
    ) as i64;
    let matched =
        find_matching_mux_case(selector, mux.cases.keys().map(String::as_str)).map(str::to_string);

    out.selectors.push(MuxSelector {
        name: mux.name.clone(),
        value: selector,
        matched_case: matched.clone(),
        start_bit: mux.start_bit,
        bit_length: mux.bit_length,
    });

    if let Some(case) = matched.as_deref().and_then(|k| mux.cases.get(k)) {
        for (idx, sig) in case.signals.iter().enumerate() {
            out.signals.push(decode_signal(
                bytes,
                sig,
                &format!("Mux Signal {}", idx + 1),
                default_endianness,
                default_word_order,
            ));
        }
        if let Some(nested) = &case.mux {
            decode_mux(bytes, nested, default_endianness, default_word_order, out);
        }
    }
}

/// The default byte/word order to apply for a frame's protocol.
fn frame_defaults(catalog: &Catalog, frame: &Frame) -> (Endianness, Option<Endianness>) {
    match frame.protocol {
        Protocol::Modbus => {
            let be = catalog
                .modbus
                .as_ref()
                .and_then(|c| c.default_byte_order)
                .unwrap_or(Endianness::Big);
            let wo = catalog.modbus.as_ref().and_then(|c| c.default_word_order);
            (be, wo)
        }
        Protocol::Can => {
            let be = catalog
                .can
                .as_ref()
                .and_then(|c| c.default_byte_order)
                .unwrap_or(Endianness::Little);
            (be, None)
        }
        Protocol::Serial => {
            let be = catalog
                .serial
                .as_ref()
                .and_then(|c| c.byte_order)
                .unwrap_or(Endianness::Little);
            (be, None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    fn parse(toml: &str) -> Catalog {
        Catalog::parse(toml).unwrap()
    }

    fn decoded<'a>(d: &'a FrameDecode, name: &str) -> &'a Decoded {
        d.signals
            .iter()
            .find(|s| s.name == name)
            .unwrap_or_else(|| panic!("decoded {name}"))
    }

    #[test]
    fn can_signal_scales_and_picks_default_endianness() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x100]
length = 8
[[frame.can.0x100.signals]]
name = "RPM"
start_bit = 0
bit_length = 16
factor = 0.25
unit = "rpm"
"#,
        );
        let f = c.frame(0x100).unwrap();
        // 0x0190 = 400 ×0.25 = 100 rpm (big-endian).
        let d = decode_frame(&c, f, &[0x01, 0x90, 0, 0, 0, 0, 0, 0]);
        let rpm = decoded(&d, "RPM");
        assert!((rpm.scaled - 100.0).abs() < 1e-9);
        assert_eq!(rpm.display, "100");
        assert_eq!(rpm.unit.as_deref(), Some("rpm"));
    }

    #[test]
    fn float_scale_display_is_clean() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x101]
length = 8
[[frame.can.0x101.signals]]
name = "SoC"
start_bit = 0
bit_length = 16
factor = 0.1
unit = "%"
"#,
        );
        let f = c.frame(0x101).unwrap();
        // 555 ×0.1 = 55.5 — must not render 55.50000000000001.
        let d = decode_frame(&c, f, &[0x02, 0x2B, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoded(&d, "SoC").display, "55.5");
    }

    #[test]
    fn enum_hex_text_formats() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x102]
length = 8
[[frame.can.0x102.signals]]
name = "Mode"
start_bit = 0
bit_length = 8
format = "enum"
enum = { 1 = "run", 2 = "stop" }
[[frame.can.0x102.signals]]
name = "Raw"
start_bit = 8
bit_length = 16
format = "hex"
[[frame.can.0x102.signals]]
name = "Tag"
start_bit = 24
bit_length = 24
format = "ascii"
"#,
        );
        let f = c.frame(0x102).unwrap();
        let bytes = [0x02, 0xAB, 0xCD, b'A', b'B', b'C', 0, 0];
        let d = decode_frame(&c, f, &bytes);
        assert_eq!(decoded(&d, "Mode").display, "stop");
        assert_eq!(decoded(&d, "Raw").display, "AB CD");
        assert_eq!(decoded(&d, "Tag").display, "ABC");
    }

    #[test]
    fn unknown_enum_value_labelled() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x103]
length = 8
[[frame.can.0x103.signals]]
name = "M"
start_bit = 0
bit_length = 8
format = "enum"
enum = { 1 = "a" }
"#,
        );
        let f = c.frame(0x103).unwrap();
        let d = decode_frame(&c, f, &[9, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(decoded(&d, "M").display, "Unknown (9)");
    }

    #[test]
    fn mux_selects_case_and_decodes_nested() {
        let c = parse(
            r#"
[meta]
name = "x"
[meta.can]
default_byte_order = "big"
[frame.can.0x200]
length = 8
[frame.can.0x200.mux]
name = "sel"
start_bit = 0
bit_length = 8
[[frame.can.0x200.mux."0-3".signals]]
name = "low"
start_bit = 8
bit_length = 8
[[frame.can.0x200.mux."4,5".signals]]
name = "mid"
start_bit = 8
bit_length = 8
"#,
        );
        let f = c.frame(0x200).unwrap();
        // selector = 2 → matches "0-3".
        let d = decode_frame(&c, f, &[2, 0x37, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d.selectors[0].value, 2);
        assert_eq!(d.selectors[0].matched_case.as_deref(), Some("0-3"));
        assert_eq!(decoded(&d, "low").value, 0x37 as f64);
        // selector = 5 → matches "4,5", not "0-3".
        let d2 = decode_frame(&c, f, &[5, 0x42, 0, 0, 0, 0, 0, 0]);
        assert_eq!(d2.selectors[0].matched_case.as_deref(), Some("4,5"));
        assert!(d2.signals.iter().any(|s| s.name == "mid"));
    }

    #[test]
    fn modbus_word_swapped_signed_32bit_matches_modbus_module() {
        // Parity with modbus::decode_frame for the Sungrow word-swap case.
        let c = parse(
            r#"
[meta]
name = "x"
[meta.modbus]
register_base = 0
default_byte_order = "big"
default_word_order = "little"
[frame.modbus.13007]
register_type = "input"
length = 2
[[frame.modbus.13007.signals]]
name = "Battery_Power"
start_bit = 0
bit_length = 32
signed = true
unit = "W"
"#,
        );
        let f = c.frame(13007).unwrap();
        // -1000 W: registers [low=0xFC18, high=0xFFFF] → bytes FC 18 FF FF.
        let d = decode_frame(&c, f, &[0xFC, 0x18, 0xFF, 0xFF]);
        assert!((decoded(&d, "Battery_Power").scaled - -1000.0).abs() < 1e-9);
    }

    #[test]
    fn unix_time_formats_utc() {
        // 2021-01-01 00:00:00 UTC = 1609459200.
        assert_eq!(format_unix_time(1_609_459_200.0), "2021-01-01 00:00:00");
        // millisecond input auto-detected.
        assert_eq!(format_unix_time(1_609_459_200_000.0), "2021-01-01 00:00:00");
    }

    #[test]
    fn mux_range_matching() {
        assert!(mux_case_matches(3, "0-3"));
        assert!(!mux_case_matches(4, "0-3"));
        assert!(mux_case_matches(5, "1,2,5"));
        assert!(mux_case_matches(11, "0-3,7,10-12"));
        assert_eq!(find_matching_mux_case(7, ["0-3", "7", "8"]), Some("7"));
    }
}
