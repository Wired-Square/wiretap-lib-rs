# wiretap-lib-rs

A Cargo workspace of related **WireTAP** Rust libraries. Each crate lives under
[`crates/`](crates/) and is distributed by git tag (consumers pin
`tag = "vX.Y.Z"` and build from source), not via crates.io.

## Crates

| Crate | What it is |
| --- | --- |
| [`wiretap-catalog`](crates/wiretap-catalog) | Parser, validator, decoder, and writer for WireTAP-format device catalogues (TOML) across CAN, Serial, and Modbus. |
| [`wiretap-decode`](crates/wiretap-decode) | Protocol-agnostic decode core — bit extraction, 16-bit word-swap, exact `Decimal` scaling, and value formatting. `wiretap-catalog` builds on it; it has no dependency on the catalogue model. |
| [`wiretap-checksum`](crates/wiretap-checksum) | Checksum algorithms (XOR, Sum8, CRC-8/16) and the engine that works out which one a link is using — a scored sweep of the named algorithms, plus solvers that recover an arbitrary CRC polynomial or an offset sum outright. |
| [`wiretap-analysis`](crates/wiretap-analysis) | Payload analysis: per-byte-column statistics, and the identification pass that decides which bytes are worth solving as a checksum at all. Builds on `wiretap-checksum`. |

`wiretap-catalog` is the top of the stack; `wiretap-decode` and
`wiretap-checksum` are primitives with no dependency on the catalogue model, and
`wiretap-analysis` sits on top of `wiretap-checksum`. Read a crate's own README
for what it does and why it does it that way.

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
cargo release patch        # dry-run preview
cargo release minor -x     # --execute: bump every crate, commit, tag, push
```

The whole workspace is versioned and released **as one unit** — `shared-version
= true`, so every crate carries the same number and one `vX.Y.Z` tag covers them
all. There is no per-crate release. Releases run from `main` only, and the
pre-release hook runs the CI gate, so a tag is never cut from a red tree.

Crates depend on each other by path, so a tag's tree already contains every
crate's matching source. A consumer pins whichever crate it needs at that tag
and the path dependencies resolve inside the checkout:

```toml
wiretap-catalog = { git = "ssh://git@github.com/Wired-Square/wiretap-lib-rs.git", tag = "vX.Y.Z" }
```

(Left as a placeholder deliberately — `pre-release-replacements` rewrites the
pin in each *crate's* README, but the workspace root is not a package, so a real
version here would go stale on the next release.)
