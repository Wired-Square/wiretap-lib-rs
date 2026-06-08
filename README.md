# wiretap-lib-rs

A Cargo workspace of related **WireTAP** Rust libraries. Each crate lives under
[`crates/`](crates/) and is distributed by git tag (consumers pin
`tag = "vX.Y.Z"` and build from source), not via crates.io.

## Crates

| Crate | What it is |
| --- | --- |
| [`wiretap-catalog`](crates/wiretap-catalog) | Parser, validator, decoder, and writer for WireTAP-format device catalogues (TOML) across CAN, Serial, and Modbus. |
| [`wiretap-decode`](crates/wiretap-decode) | Protocol-agnostic decode core — bit extraction, 16-bit word-swap, exact `Decimal` scaling, and value formatting. `wiretap-catalog` builds on it; it has no dependency on the catalogue model. |

## Develop

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --all
```

These three are the CI gate (`.github/workflows/ci.yml`, on `main` + PRs) — run
them locally before pushing.

## Release

Releases go through [`cargo-release`](https://github.com/crate-ci/cargo-release)
(config in [`release.toml`](release.toml)):

```sh
cargo release -p wiretap-catalog patch        # dry-run preview
cargo release -p wiretap-catalog patch -x     # --execute: bump, commit, tag, push
```

The pre-release hook runs the CI gate, so a tag is never cut from a red tree.

`wiretap-catalog` depends on `wiretap-decode` by path, so the catalogue release
tag's tree already contains the matching `wiretap-decode` source — consumers
pin only the `wiretap-catalog` tag and the path dependency resolves inside that
checkout. `wiretap-decode` is not tagged separately.
