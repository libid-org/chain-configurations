#!/usr/bin/env bash
# Vendor every compiled artifact this crate embeds: the three Platform
# Verifiers, and the two ceremony circuits' bb-generated UltraHonk verifiers
# with the libraries they link.
#
# WHY THIS EXISTS: libid-contracts ships compiled artifacts for the stack it
# deploys, but its COVERED list (rust/contracts/src/artifacts.rs) stops at the
# four core proxies — the Platform Verifiers are not in it, and its own
# script/Deploy.s.sol registers none. Nor does anything upstream ship a Honk
# verifier: it derives from a circuit's verification key, which libid-circuits
# publishes as a release asset. This repository deploys all of them, so it
# builds them here and embeds the result.
#
# The output is gitignored, like libid-contracts' own vendored artifacts: CI
# runs this before every cargo step, and a local build runs it once and again
# whenever either pin moves. The circuits manifest it rewrites IS committed:
# that is the pin.
#
# Determinism: solidity/foundry.toml pins solc 0.8.33, builds with via_ir, and
# sets bytecode_hash = "none" / cbor_metadata = false, so two builds of the same
# sources produce byte-identical bytecode on any machine. A Honk verifier
# derives from the vk alone, and the vk comes from the pinned release rather
# than a local circuit build, so it is byte-identical too. Two runs that
# differ mean the SOURCES moved, not the build.
#
# Usage:
#   scripts/vendor-artifacts.sh                     # both pins as committed
#   scripts/vendor-artifacts.sh --contracts DIR     # use a libid-contracts checkout
#   scripts/vendor-artifacts.sh --circuits 0.4.0    # move the circuits pin
#
# DIR must be a libid-contracts working tree at the pinned tag with its
# solidity/lib submodules initialized.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$REPO_ROOT/bin/libid-deploy"
DEST="$CRATE/artifacts"
MANIFEST="$CRATE/Cargo.toml"
# The circuits pin: the release's own manifest, committed verbatim. It carries
# the version, the toolchain the assets were built by, and a sha256 per file,
# so the pin and the integrity check are one document rather than three values
# retyped beside each other.
CIRCUITS_PIN="$CRATE/circuits-manifest.json"
UPSTREAM="https://github.com/libid-org/libid-contracts.git"
CIRCUITS_RELEASES="https://github.com/libid-org/libid-circuits/releases/download"

# "<File>:<Contract>" — the artifact lands at <File>.sol/<Contract>.json,
# the layout libid_contracts::Artifacts::from_dir reads.
ARTIFACTS=(
    "XPlatformVerifier:XPlatformVerifier"
    "GitHubPlatformVerifier:GitHubPlatformVerifier"
    "GooglePlatformVerifier:GooglePlatformVerifier"
)

# "<circuit>:<Contract>" — the circuit directory in the libid-circuits release
# (hence the tarball's name) and the contract the generated verifier is renamed
# to. bb always emits `HonkVerifier`; two of them in one forge project would
# collide, and the artifact path is what the Rust side looks the bytecode up by.
CIRCUITS=(
    "bearer-link:BearerLinkHonkVerifier"
    "oidc-google:OidcGoogleHonkVerifier"
)

# The libraries a bb verifier links. They hold `external` functions, so they are
# real deployed libraries rather than inlined code, and the creation bytecode
# carries a placeholder per call site until each one's address is substituted.
HONK_LIBRARIES=(RelationsLib ZKTranscriptLib)

# Where the generated sources are dropped inside the contracts checkout. FIXED,
# not a mktemp name: solc records the source path in `linkReferences`, and a
# path that changed per run would churn the artifact between runs.
CIRCUITS_SRC_REL="contracts/circuits"

CONTRACTS_DIR=""
CIRCUITS_VERSION=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --contracts) CONTRACTS_DIR="${2:-}"; shift 2 ;;
        --circuits) CIRCUITS_VERSION="${2:-}"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

for tool in jq forge curl shasum; do
    command -v "$tool" >/dev/null || { echo "$tool is required" >&2; exit 1; }
done

# Both tags are DERIVED from their pin, never restated: vendored bytecode from a
# different release than the bindings compile against is exactly the mismatch
# this script exists to prevent.
VERSION="$(sed -n 's/^libid-contracts = "\(.*\)"$/\1/p' "$MANIFEST")"
[[ -n "$VERSION" ]] || { echo "no libid-contracts version in $MANIFEST" >&2; exit 1; }
TAG="v$VERSION"
echo "==> libid-contracts $TAG"

if [[ -z "$CIRCUITS_VERSION" ]]; then
    CIRCUITS_VERSION="$(jq -r '.version' "$CIRCUITS_PIN")"
    [[ -n "$CIRCUITS_VERSION" && "$CIRCUITS_VERSION" != "null" ]] ||
        { echo "no version in $CIRCUITS_PIN" >&2; exit 1; }
fi
CIRCUITS_TAG="v$CIRCUITS_VERSION"
echo "==> libid-circuits $CIRCUITS_TAG"

WORK="$(mktemp -d)"
STAGE="$(mktemp -d)"
CLEANUP_SRC=""
cleanup() {
    rm -rf "$WORK" "$STAGE"
    [[ -n "$CLEANUP_SRC" ]] && rm -rf "$CLEANUP_SRC"
    return 0
}
trap cleanup EXIT

# ── The circuits release ─────────────────────────────────────────────────────
# The manifest comes down with the assets and is committed as the new pin, so
# the digests checked here are the ones the next run checks against.
echo "==> fetching the libid-circuits $CIRCUITS_TAG release"
curl -fsSL -o "$WORK/manifest.json" "$CIRCUITS_RELEASES/$CIRCUITS_TAG/manifest.json"
released="$(jq -r '.version' "$WORK/manifest.json")"
[[ "$released" == "$CIRCUITS_VERSION" ]] ||
    { echo "the $CIRCUITS_TAG manifest declares version '$released'" >&2; exit 1; }

# bb turns a vk into Solidity, so the artifact is only reproducible under the
# version that wrote the vk — which the manifest names.
BB_VERSION="$(jq -r '.toolchain.bb' "$WORK/manifest.json")"
have_bb="$(bb --version 2>/dev/null | tail -1)"
if [[ "$have_bb" != "$BB_VERSION" ]]; then
    echo "error: bb $BB_VERSION required (the $CIRCUITS_TAG manifest), found '${have_bb:-not installed}'." >&2
    echo "  install: bbup --version $BB_VERSION" >&2
    exit 1
fi
echo "==> bb $BB_VERSION"

for entry in "${CIRCUITS[@]}"; do
    circuit="${entry%%:*}"
    tarball="libid-circuits-$CIRCUITS_VERSION-$circuit.tar.gz"
    curl -fsSL -o "$WORK/$tarball" "$CIRCUITS_RELEASES/$CIRCUITS_TAG/$tarball"
    want="$(jq -r --arg t "$tarball" '.tarballs[$t].sha256' "$WORK/manifest.json")"
    got="$(shasum -a 256 "$WORK/$tarball" | cut -d' ' -f1)"
    [[ "$want" == "$got" ]] ||
        { echo "$tarball: sha256 $got, the manifest says $want" >&2; exit 1; }
    mkdir -p "$WORK/$circuit"
    tar xzf "$WORK/$tarball" -C "$WORK/$circuit"
    want_vk="$(jq -r --arg t "$tarball" '.tarballs[$t].files.vk' "$WORK/manifest.json")"
    got_vk="$(shasum -a 256 "$WORK/$circuit/vk" | cut -d' ' -f1)"
    [[ "$want_vk" == "$got_vk" ]] ||
        { echo "$circuit/vk: sha256 $got_vk, the manifest says $want_vk" >&2; exit 1; }
    echo "==> $circuit: vk verified against the manifest"
done

# ── The contracts checkout ───────────────────────────────────────────────────
if [[ -z "$CONTRACTS_DIR" ]]; then
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

# The generated verifiers build under the SAME foundry.toml the Platform
# Verifiers do, so one solc pin and one optimizer setting cover every artifact
# here. They are removed again on exit: with `--contracts DIR` that tree belongs
# to the caller.
CIRCUITS_SRC="$CONTRACTS_DIR/solidity/$CIRCUITS_SRC_REL"
[[ -e "$CIRCUITS_SRC" ]] && { echo "$CIRCUITS_SRC already exists" >&2; exit 1; }
mkdir -p "$CIRCUITS_SRC"
CLEANUP_SRC="$CIRCUITS_SRC"

for entry in "${CIRCUITS[@]}"; do
    circuit="${entry%%:*}"
    contract="${entry##*:}"
    out="$CIRCUITS_SRC/$contract.sol"
    # The verifier derives from the vk ALONE — no ACIR, no recompile — which is
    # why the release's vk is a sufficient input.
    bb write_solidity_verifier -k "$WORK/$circuit/vk" -o "$out" -t evm >/dev/null
    # The two canonical rewrites from libid-circuits' scripts/gen-verifier.sh:
    # via_ir consumers need the memory-safe annotation on every assembly block,
    # and the concrete contract is renamed off bb's fixed `HonkVerifier`.
    perl -i -pe 's/assembly \{/assembly ("memory-safe") \{/g' "$out"
    perl -i -pe "s/contract HonkVerifier is BaseZKHonkVerifier/contract $contract is BaseZKHonkVerifier/g" "$out"
    grep -q "contract $contract is BaseZKHonkVerifier" "$out" ||
        { echo "$circuit: bb emitted a shape the rename does not match" >&2; exit 1; }
    ARTIFACTS+=("$contract:$contract")
    for lib in "${HONK_LIBRARIES[@]}"; do
        ARTIFACTS+=("$contract:$lib")
    done
    echo "==> $circuit -> $contract.sol"
done

echo "==> forge build"
(cd "$CONTRACTS_DIR/solidity" && forge build)

for entry in "${ARTIFACTS[@]}"; do
    file="${entry%%:*}"
    contract="${entry##*:}"
    src="$CONTRACTS_DIR/solidity/out/$file.sol/$contract.json"
    [[ -f "$src" ]] || { echo "missing artifact: $src" >&2; exit 1; }
    # Only the fields the loader reads, sorted, so two runs diff cleanly and
    # the file carries nothing about the machine that built it.
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
cp "$WORK/manifest.json" "$CIRCUITS_PIN"
echo "==> vendored $(find "$DEST" -name '*.json' | wc -l | tr -d ' ') artifacts into $DEST"
