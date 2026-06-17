use super::*;
use serde_json::json;

/// Build an `EditOp` from a JSON object the way the WS layer does.
fn op(v: Json) -> EditOp {
    serde_json::from_value(v).expect("valid EditOp")
}

fn edit(text: &str, v: Json) -> String {
    apply_edit(text, op(v)).expect("edit ok")
}

const SIGNAL_SORT: [&str; 3] = ["start_bit", "bit_length", "name"];

// ── headline: add one signal, lose nothing ───────────────────────────────────

#[test]
fn add_signal_preserves_comments_and_only_adds_entry() {
    let toml = r#"# catalogue header comment
[meta]
name = "demo"
version = 1

# the temperature frame
[frame.can.0x100]
length = 8  # full frame

[[frame.can.0x100.signals]]
name = "temp"          # degrees C
start_bit = 0
bit_length = 16

# a second, untouched frame
[frame.can.0x200]
length = 8
"#;

    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x100", "signals"],
            "value": { "name": "soc", "start_bit": 16, "bit_length": 8 },
            "sort_keys": SIGNAL_SORT,
        }),
    );

    // Every comment survives.
    assert!(out.contains("# catalogue header comment"));
    assert!(out.contains("# the temperature frame"));
    assert!(out.contains("# full frame"));
    assert!(out.contains("# degrees C"));
    assert!(out.contains("# a second, untouched frame"));
    // The new signal landed.
    assert!(out.contains(r#"name = "soc""#));
    // The untouched sibling frame is byte-for-byte intact.
    assert!(out.contains("# a second, untouched frame\n[frame.can.0x200]\nlength = 8\n"));
    // It parses and now has two signals on 0x100.
    let cat = crate::Catalog::parse(&out).expect("parses");
    let f = cat.frames.iter().find(|f| f.frame_id == 0x100).unwrap();
    assert_eq!(f.signals.len(), 2);
}

#[test]
fn signal_inserts_in_sorted_position() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x10]
length = 8
[[frame.can.0x10.signals]]
name = "a"
start_bit = 0
bit_length = 8
[[frame.can.0x10.signals]]
name = "c"
start_bit = 16
bit_length = 8
"#;
    // start_bit 8 sorts between a(0) and c(16).
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": { "name": "b", "start_bit": 8, "bit_length": 8 },
            "sort_keys": SIGNAL_SORT,
        }),
    );
    let a = out.find(r#"name = "a""#).unwrap();
    let b = out.find(r#"name = "b""#).unwrap();
    let c = out.find(r#"name = "c""#).unwrap();
    assert!(a < b && b < c, "expected a<b<c order, got:\n{out}");
}

#[test]
fn signal_replace_in_place_keeps_other_signals_comment() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x10]
length = 8
[[frame.can.0x10.signals]]
name = "keep"   # important note
start_bit = 0
bit_length = 8
[[frame.can.0x10.signals]]
name = "edit_me"
start_bit = 8
bit_length = 8
"#;
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": { "name": "edited", "start_bit": 8, "bit_length": 8, "unit": "V" },
            "index": 1,
            "sort_keys": SIGNAL_SORT,
        }),
    );
    assert!(out.contains("# important note"));
    assert!(out.contains(r#"name = "edited""#));
    assert!(out.contains(r#"unit = "V""#));
    assert!(!out.contains("edit_me"));
}

#[test]
fn add_signal_with_enum_subtable_round_trips() {
    let toml = "[meta]\nname = \"d\"\nversion = 1\n[frame.can.0x10]\nlength = 8\n";
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": {
                "name": "mode",
                "start_bit": 0,
                "bit_length": 8,
                "enum": { "0": "off", "2": "on" }
            },
            "sort_keys": SIGNAL_SORT,
        }),
    );
    let cat = crate::Catalog::parse(&out).expect("parses");
    let f = cat.frames.iter().find(|f| f.frame_id == 0x10).unwrap();
    let sig = f
        .signals
        .iter()
        .find(|s| s.name.as_deref() == Some("mode"))
        .unwrap();
    let enum_map = sig.enum_map.as_ref().expect("enum map present");
    assert_eq!(enum_map.get(&0).map(String::as_str), Some("off"));
    assert_eq!(enum_map.get(&2).map(String::as_str), Some("on"));
}

// ── hex rendering of masks ────────────────────────────────────────────────────

#[test]
fn frame_id_mask_renders_as_hex() {
    let toml = "[meta]\nname = \"d\"\nversion = 1\n";
    for (mask, expect) in [
        (0xFFu64, "0xFF"),
        (0xFF00, "0xFF00"),
        (0x1FFF_FF00, "0x1FFFFF00"),
    ] {
        let out = edit(
            toml,
            json!({
                "op": "SetTable",
                "path": ["meta", "can"],
                "value": { "default_byte_order": "little", "frame_id_mask": mask },
                "replace_contents": true,
            }),
        );
        assert!(
            out.contains(&format!("frame_id_mask = {expect}")),
            "mask {mask:#x} -> {out}"
        );
    }
}

#[test]
fn header_field_mask_renders_as_hex() {
    let toml = "[meta]\nname = \"d\"\nversion = 1\n";
    let out = edit(
        toml,
        json!({
            "op": "SetTable",
            "path": ["meta", "can"],
            "value": {
                "default_byte_order": "big",
                "fields": { "priority": { "mask": 0xFF00_0000u64, "shift": 24 } }
            },
            "replace_contents": true,
        }),
    );
    assert!(out.contains("mask = 0xFF000000"), "{out}");
    assert!(out.contains("shift = 24"));
}

// ── meta update preserves protocol configs ───────────────────────────────────

#[test]
fn update_meta_preserves_protocol_config() {
    let toml = r#"[meta]
name = "old"
version = 1

[meta.can]
default_byte_order = "little"  # keep me
"#;
    let out = edit(
        toml,
        json!({
            "op": "SetTable",
            "path": ["meta"],
            "value": { "name": "new", "version": 2 },
            "managed_keys": ["name", "version"],
        }),
    );
    assert!(out.contains(r#"name = "new""#));
    assert!(out.contains("version = 2"));
    assert!(out.contains("[meta.can]"));
    assert!(out.contains("# keep me"));
}

// ── CAN frame upsert: rename + numeric sort + sub-table preservation ─────────

#[test]
fn can_frame_rename_carries_signals_and_sorts() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x200]
length = 8
[[frame.can.0x200.signals]]
name = "s"
start_bit = 0
bit_length = 8
[frame.can.0x050]
length = 8
"#;
    // Rename 0x200 -> 0x010; result should sort before 0x050 and keep its signal.
    let out = edit(
        toml,
        json!({
            "op": "UpsertFrame",
            "protocol": "can",
            "key": "0x010",
            "rename_from": "0x200",
            "value": { "length": 8 },
            "managed_keys": ["length", "notes", "transmitter", "tx"],
        }),
    );
    let p010 = out.find("[frame.can.0x010]").expect("renamed");
    let p050 = out.find("[frame.can.0x050]").expect("present");
    assert!(p010 < p050, "0x010 should sort before 0x050:\n{out}");
    let cat = crate::Catalog::parse(&out).unwrap();
    let f = cat.frames.iter().find(|f| f.frame_id == 0x010).unwrap();
    assert_eq!(f.signals.len(), 1);
}

#[test]
fn can_frame_inherited_field_is_removed() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x100]
length = 8
transmitter = "ECU"
"#;
    // transmitter omitted from value + managed -> dropped (now inherited).
    let out = edit(
        toml,
        json!({
            "op": "UpsertFrame",
            "protocol": "can",
            "key": "0x100",
            "value": { "length": 8 },
            "managed_keys": ["length", "notes", "transmitter", "tx"],
        }),
    );
    assert!(!out.contains("transmitter"), "{out}");
}

// ── nodes: rename rewrites transmitter references ─────────────────────────────

#[test]
fn node_rename_updates_transmitter_refs() {
    let toml = r#"[meta]
name = "d"
version = 1
[node.ecu_a]
notes = "the ECU"
[frame.can.0x100]
length = 8
transmitter = "ecu_a"
"#;
    let out = edit(
        toml,
        json!({
            "op": "RenameKey",
            "parent_path": ["node"],
            "old": "ecu_a",
            "new": "ecu_b",
            "set_value": { "notes": "the ECU" },
            "managed_keys": ["notes"],
            "sort_numeric": true,
            "update_transmitter_refs": true,
            "error_if_exists": true,
        }),
    );
    assert!(out.contains("[node.ecu_b]"));
    assert!(out.contains(r#"transmitter = "ecu_b""#));
    assert!(out.contains(r#"notes = "the ECU""#));
}

#[test]
fn mux_case_collision_is_error() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x100]
length = 8
[frame.can.0x100.mux]
name = "m"
start_bit = 0
bit_length = 8
[frame.can.0x100.mux.0]
[frame.can.0x100.mux.1]
"#;
    let res = apply_edit(
        toml,
        op(json!({
            "op": "RenameKey",
            "parent_path": ["frame", "can", "0x100", "mux"],
            "old": "0",
            "new": "1",
            "error_if_exists": true,
        })),
    );
    assert!(res.is_err());
}

// ── checksum array empty-cleanup ──────────────────────────────────────────────

#[test]
fn remove_last_checksum_drops_the_array() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.serial.0x01]
length = 4
[[frame.serial.0x01.checksum]]
name = "crc"
algorithm = "crc16"
start_byte = 2
"#;
    let out = edit(
        toml,
        json!({
            "op": "RemoveArrayItem",
            "array_path": ["frame", "serial", "0x01", "checksum"],
            "index": 0,
            "remove_if_empty": true,
        }),
    );
    assert!(!out.contains("checksum"), "{out}");
}

// ── inline signals array fallback ─────────────────────────────────────────────

#[test]
fn inline_signal_array_is_supported() {
    let toml = r#"[meta]
name = "d"
version = 1
[frame.can.0x10]
length = 8
signals = [ { name = "a", start_bit = 0, bit_length = 8 } ]
"#;
    let out = edit(
        toml,
        json!({
            "op": "UpsertArrayItem",
            "array_path": ["frame", "can", "0x10", "signals"],
            "value": { "name": "b", "start_bit": 8, "bit_length": 8 },
            "sort_keys": SIGNAL_SORT,
        }),
    );
    let cat = crate::Catalog::parse(&out).unwrap();
    let f = cat.frames.iter().find(|f| f.frame_id == 0x10).unwrap();
    assert_eq!(f.signals.len(), 2);
}

// ── serde: a stray `content` key in the params is ignored ─────────────────────

#[test]
fn editop_ignores_extra_content_key() {
    let parsed: EditOp = serde_json::from_value(json!({
        "op": "DeleteAtPath",
        "path": ["frame", "can", "0x100"],
        "content": "[meta]\nname=\"x\"\n",
    }))
    .expect("deserialises with extra content key");
    assert!(matches!(parsed, EditOp::DeleteAtPath { .. }));
}

#[test]
fn invalid_toml_errors() {
    let res = apply_edit(
        "this is = = not toml",
        op(json!({ "op": "DeleteAtPath", "path": ["x"] })),
    );
    assert!(res.is_err());
}
