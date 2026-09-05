#!/usr/bin/env bash
#
# Assert the release config still keeps the promises consumers pin against.
#
# This workspace is distributed by git tag. A consumer takes a tag on two
# unstated assumptions: that the tree it names passed the tests, and that the
# pin example in the crate's README names a tag that exists. Neither is visible
# from the consumer's side, and both are one careless edit to release.toml away
# from being false — silently, because a release that checks nothing succeeds.
# WireTAP-Server leans on the first of them hard: it does not run
# wiretap-protocol's GVRET golden-byte tests in its own CI, on the grounds that
# a tag cannot name a tree where they failed.
#
# So the checks below read release.toml and hold it to what it claims, rather
# than restating its rules somewhere they can drift.
#
# It cannot save you from deleting the pre-release hook outright — nothing run
# *by* the hook can — but it does catch the hook being weakened, which is the
# way this actually goes wrong.
#
# A new promise is one check below, not a paragraph in three READMEs.
#
# Run by the pre-release hook, which cargo-release invokes once per releasable
# package with the working directory set to that package — hence the cd below,
# and hence "$WORKSPACE_ROOT" on the call in release.toml. These checks are
# workspace-wide, so the output repeats per package; that is expected.
#
# Safe to run by hand at any time.

set -euo pipefail

cd "$(dirname "$0")/.."

fail=0

# --- 1. The hook still runs the tests --------------------------------------
#
# Read out of release.toml rather than assumed, so this cannot pass by
# describing a hook that is no longer there.
hook=$(sed -nE '/^pre-release-hook = \[/,/^\]/p' release.toml)
if [ -z "$hook" ]; then
    echo "  ✗ pre-release hook: release.toml has none"
    fail=1
elif ! grep -qE 'cargo test' <<<"$hook"; then
    echo "  ✗ pre-release hook: does not run 'cargo test' — a tag could name a red tree,"
    echo "    and WireTAP-Server skips this workspace's tests because it cannot"
    fail=1
else
    echo "  ✓ pre-release hook runs the tests"
fi

# --- 2. Every README pin will actually be rewritten -------------------------
#
# `min = 0` on the replacement is forced: three of the five crates carry no pin
# line at all, and a missing match must not fail their release. The cost is that
# a *malformed* pin line — `tag="v0.15.0"`, say — matches nothing, is rewritten
# to nothing, and ships a stale version behind a green release. So take the
# search pattern from release.toml itself and check every pin line against it.
search=$(sed -nE "s/.*search = '([^']*)'.*/\1/p" release.toml)
if [ -z "$search" ]; then
    echo "  ✗ pre-release replacements: no search pattern in release.toml"
    fail=1
else
    for readme in crates/*/README.md; do
        crate=$(basename "$(dirname "$readme")")
        # Any line mentioning a git tag pin is in scope; the question is only
        # whether it is in the exact form the replacement will rewrite.
        pins=$(grep -c 'tag *=' "$readme" || true)
        [ "$pins" -eq 0 ] && continue
        matched=$(grep -cE "$search" "$readme" || true)
        if [ "$pins" -ne "$matched" ]; then
            echo "  ✗ $crate: $pins pin line(s), $matched in the form release.toml rewrites"
            echo "    → it will go stale silently; min = 0 means nothing fails"
            fail=1
        else
            echo "  ✓ $crate: $pins pin line(s), all rewritable"
        fi
    done
fi

# --- 3. The workspace README stays a placeholder ----------------------------
#
# `pre-release-replacements` resolves `file` per package, and the workspace root
# is not a package — so nothing rewrites this file, ever. A real version here
# would be correct for exactly one release and wrong afterwards, which is worse
# than an obvious placeholder.
if grep -qE 'tag = "v[0-9]' README.md; then
    echo "  ✗ README.md: names a real version, and nothing rewrites the root README"
    echo "    → use the vX.Y.Z placeholder"
    fail=1
else
    echo "  ✓ README.md keeps the vX.Y.Z placeholder"
fi

if [ "$fail" -ne 0 ]; then
    cat >&2 <<'EOF'

release.toml no longer backs what this workspace's consumers are told to expect.
Fix the config rather than the message: a pin that goes stale quietly, or a tag
cut from an untested tree, is a confident wrong answer to somebody who cannot
see this repository at all.
EOF
    exit 1
fi
