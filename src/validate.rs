//! Validate a TOML catalogue, returning field-path + message findings.
//!
//! Port of WireTAP's `src-tauri/src/catalog.rs::validate_catalog` (CAN + meta
//! rules) so the editor's validation output is unchanged, plus a Modbus
//! structural check via [`crate::modbus::ModbusManifest`].

use std::collections::{HashMap, HashSet};

use toml::Value;

use crate::modbus::{ManifestError, ModbusManifest};
use crate::model::ValidationError;

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

    errors
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
    fn toml_syntax_error_is_single_finding() {
        let errs = validate("not = valid = toml =");
        assert_eq!(errs.len(), 1);
        assert_eq!(errs[0].field, "toml");
    }
}
