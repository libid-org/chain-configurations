#!/usr/bin/env bash
# Vendor the Platform Verifier artifacts this crate embeds.
#
# WHY THIS EXISTS: libid-contracts ships compiled artifacts for the stack it
# deploys, but its COVERED list (rust/contracts/src/artifacts.rs) stops at the
# four core proxies — the Platform Verifiers are not in it, and its own
# script/Deploy.s.sol registers none. This repository deploys them, so it
# compiles them from the SAME tag its libid-contracts dependency comes from and
# embeds the result.
#
# The output is committed, unlike libid-contracts' own vendored artifacts:
# a release build of this binary must not need forge, solc or a contracts
# checkout. Regenerate it whenever the libid-contracts dependency moves.
#
# Determinism: solidity/foundry.toml pins solc 0.8.33, builds with via_ir, and
# sets bytecode_hash = "none" / cbor_metadata = false, so two builds of the same
# sources produce byte-identical bytecode on any machine. A regenerated artifact
# that differs from the committed one means the SOURCES moved, not the build.
#
# Usage:
#   scripts/vendor-platform-verifiers.sh                 # clone the pinned tag
#   scripts/vendor-platform-verifiers.sh --contracts DIR # use a checkout
#
# DIR must be a libid-contracts working tree at the pinned tag with its
# solidity/lib submodules initialized.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$REPO_ROOT/bin/libid-deploy/artifacts"
MANIFEST="$REPO_ROOT/bin/libid-deploy/Cargo.toml"
UPSTREAM="https://github.com/libid-org/libid-contracts.git"

# "<File>:<Contract>" — the artifact lands at <File>.sol/<Contract>.json,
# the layout libid_contracts::Artifacts::from_dir reads.
ARTIFACTS=(
    "XPlatformVerifier:XPlatformVerifier"
    "GitHubPlatformVerifier:GitHubPlatformVerifier"
    "GooglePlatformVerifier:GooglePlatformVerifier"
)

CONTRACTS_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --contracts) CONTRACTS_DIR="${2:-}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

command -v jq >/dev/null || { echo "jq is required" >&2; exit 1; }
command -v forge >/dev/null || { echo "forge is required" >&2; exit 1; }

# The tag is DERIVED from the dependency, never restated: vendored bytecode
# from a different release than the bindings compile against is exactly the
# mismatch this script exists to prevent.
VERSION="$(sed -n 's/^libid-contracts = "\(.*\)"$/\1/p' "$MANIFEST")"
[[ -n "$VERSION" ]] || { echo "no libid-contracts version in $MANIFEST" >&2; exit 1; }
TAG="v$VERSION"
echo "==> libid-contracts $TAG"

WORK=""
if [[ -z "$CONTRACTS_DIR" ]]; then
    WORK="$(mktemp -d)"
    trap 'rm -rf "$WORK"' EXIT
    git clone --quiet --depth 1 --branch "$TAG" --recurse-submodules \
        "$UPSTREAM" "$WORK/libid-contracts"
    CONTRACTS_DIR="$WORK/libid-contracts"
else
    CONTRACTS_DIR="$(cd "$CONTRACTS_DIR" && pwd)"
    described="$(git -C "$CONTRACTS_DIR" describe --tags --exact-match 2>/dev/null || true)"
    if [[ "$described" != "$TAG" ]]; then
        echo "$CONTRACTS_DIR is not at $TAG (got '${described:-none}')" >&2
        exit 1
    fi
fi

echo "==> forge build"
(cd "$CONTRACTS_DIR/solidity" && forge build)

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE" ${WORK:+"$WORK"}' EXIT

for entry in "${ARTIFACTS[@]}"; do
    file="${entry%%:*}"
    contract="${entry##*:}"
    src="$CONTRACTS_DIR/solidity/out/$file.sol/$contract.json"
    [[ -f "$src" ]] || { echo "missing artifact: $src" >&2; exit 1; }
    # Only the fields the loader reads, sorted, so the committed file diffs
    # cleanly and carries nothing about the machine that built it.
    mkdir -p "$STAGE/$file.sol"
    jq -S '{
        bytecode: {
            object: .bytecode.object,
            linkReferences: .bytecode.linkReferences
        },
        methodIdentifiers: .methodIdentifiers
    }' "$src" > "$STAGE/$file.sol/$contract.json"
done

rm -rf "$DEST"
mkdir -p "$(dirname "$DEST")"
cp -R "$STAGE" "$DEST"
echo "==> vendored $(find "$DEST" -name '*.json' | wc -l | tr -d ' ') artifacts into $DEST"
