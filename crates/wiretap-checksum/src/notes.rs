//! Notes cross the boundary as a code plus interpolation values, so the prose
//! stays translatable at the edge instead of shipping English from Rust.
//!
//! WireTAP renders these as ``t(`serial.checksumNote.${code}`, values)``, and a
//! test there pins every code emitted here against the locale file in both
//! directions — a new code without a translation fails that test, so add both.

use serde::Serialize;

/// A translatable note: the frontend renders `t(code, values)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumNote {
    pub code: String,
    pub values: serde_json::Map<String, serde_json::Value>,
}

impl ChecksumNote {
    pub fn new(code: &str, values: &[(&str, serde_json::Value)]) -> Self {
        Self {
            code: code.to_string(),
            values: values
                .iter()
                .map(|(k, v)| ((*k).to_string(), v.clone()))
                .collect(),
        }
    }
}
