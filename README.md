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
| [`wiretap-protocol`](crates/wiretap-protocol) | The wire protocols WireTAP speaks, as scalars: the CAN data length code table, the GVRET serial protocol, and the ingest id-flag layout. No dependencies at all — not even serde. |

`wiretap-catalog` is the top of the stack; `wiretap-decode` and
`wiretap-checksum` are primitives with no dependency on the catalogue model, and
`wiretap-analysis` sits on top of `wiretap-checksum`. `wiretap-protocol` stands
apart from all of them: it is what two repositories have to agree on byte for
byte, and it depends on nothing. Read a crate's own README for what it is and how
to use it; the reasoning lives in the module docs of the code it describes.

## Develop

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --all
scripts/check-release-contract.sh
```

These four are the CI gate (`.github/workflows/ci.yml`, on `main` + PRs) — run
them locally before pushing. The first three also run in the pre-release hook;
the fourth checks that they still do, and is the one to run after editing
`release.toml` or a README pin.

## Release

Releases go through [`cargo-release`](https://github.com/crate-ci/cargo-release)
(config in [`release.toml`](release.toml)):

```sh
cargo release patch        # dry-run preview
cargo release minor -x     # --execute: bump every crate, commit, tag, push
```

The whole workspace is versioned and released **as one unit** — `shared-version
= true`, so every crate carries the same number and one `vX.Y.Z` tag covers them
all. There is no per-crate release. Releases run from `main` only.

Crates depend on each other by path, so a tag's tree already contains every
crate's matching source. A consumer pins whichever crate it needs at that tag
and the path dependencies resolve inside the checkout:

```toml
wiretap-catalog  = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "vX.Y.Z" }
wiretap-protocol = { git = "https://github.com/Wired-Square/wiretap-lib-rs.git", tag = "vX.Y.Z" }
```

Both URL forms work; the choice belongs to the consumer. This repository is
public, so `https` needs no key — WireTAP-Server pins over `https` because a
stock CI runner, a container build and a musl cross-build all have to resolve it
and none of them has a key.

Two things consumers rely on that are not visible from their side: a tag names a
tree whose tests passed, and a crate README's pin names a tag that exists.
`scripts/check-release-contract.sh` holds `release.toml` to both and runs first
in the pre-release hook. And **a tag is immutable once pinned** — moving one
changes what a consumer builds with no lockfile change to show for it. Cut a new
patch instead.

## Licence

MIT © Wired Square.
