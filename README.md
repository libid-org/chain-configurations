# chain-configurations

Desired-state configuration for the libid identity stack, one file per
network, plus the `libid-deploy` binary and the GitHub Actions that apply a
file to its chain with an AWS KMS signer.

The model is DECLARATIVE:

1. `networks/<name>.toml` declares what should exist on a chain — including
   **every address, pre-filled up front**. Canonical contracts live at
   CREATE3-deterministic addresses, so the file carries the full address
   table before the chain has anything on it; `validate` rejects a
   canonical key whose value is not exactly `predict_address(factory,
   name)`, naming the expected value.
2. Deployed-vs-not is determined from **chain state** (`eth_getCode` at the
   declared address / the factory's `deployedAt` record) — never from
   config emptiness.
3. `libid-deploy plan` compares the declarations with the chain, read-only:
   each component is "declared + present" (ok) or "declared + missing"
   (DEPLOY — apply would put it at exactly the declared address). A wrong
   declared address never gets that far: it fails validation at load.
4. `libid-deploy apply` deploys whatever the CHAIN lacks, re-sends the
   idempotent configuration, and performs explicitly requested upgrades.
   It **never rewrites the file** — after an apply the config is
   byte-identical, and there is no write-back PR. Integration tests can
   therefore use identical config data regardless of which chain (or how
   little of the stack) exists yet.

Contract bytecode is embedded in the binary through the
[`libID-contracts`](https://github.com/libid-org/libID-contracts) crate —
the core stack, the Platform Verifiers and the ceremony circuits' Honk
verifiers alike, compiled once upstream from the pinned sources. There is
no forge build, no bb and no artifact directory anywhere in this
repository. The platform tables come from `libid-identity` and
`libid-profiles`, generated from the same sources the contracts are, so
nothing here restates a value the chain also holds.

## The stack

Four UUPS proxies, in dependency order — the order
`libid-contracts`' own `script/Deploy.s.sol` uses:

1. **NotaryService** — the ONE place a notary attestation is
   authenticated. It derives the digest from the attested bytes itself and
   charges the Notary Fee. Deployed first so its proxy address can be
   wired into every consumer's `initialize`.
2. **CeremonyProofVerifier** — the Supported Version Set: which Platform
   Verifier answers for a `(platformId, verifierVersion)` pair. Without it
   the naming system's `proofVerifier` reads zero and every resolver
   reverts.
3. **IdentityNames** — the naming system, pointed at the Proof Verifier
   and given a keyspace per platform (`x`, `github`, `google`). The
   normalization rules come from `libid-identity`'s generated table.
4. **GoogleJwtRoots** — the Google signing keys the `google/v1` Platform
   Verifier trusts, verified through the Notary Service like any other
   notarized session. It deploys **EMPTY**: point a keeper at it before
   Google names work, or every Google claim reverts `UntrustedModulus`.

Then two steps `Deploy.s.sol` does not have:

5. **A Honk verifier per ceremony circuit** — the bb-generated UltraHonk
   verifier each platform's proofs are checked under, deployed through the
   factory under a CREATE3 name carrying the pinned circuits release, on
   one shared deployment of each library it links.
6. **A Platform Verifier per platform** — `XPlatformVerifier`,
   `GitHubPlatformVerifier`, `GooglePlatformVerifier` — deployed behind its
   own CREATE3 proxy, pinned to its circuit's verifier by address and code
   hash, and registered into the Supported Version Set with
   `CeremonyProofVerifier.setVerifier(platformId, 1, verifier)`. Until that
   registration lands, a platform owns a keyspace and can verify nothing:
   `claim` reverts `UnknownVersion` and every resolver reverts
   `UnknownPlatform`.

## The ceremony contracts

### Where the bytecode comes from

Not from here. Each derivation runs once, in the repository that owns its
tool: [`libID-circuits`](https://github.com/libid-org/libID-circuits) runs
`bb` and publishes each circuit's generated verifier in its release
tarball, `libid-contracts` vendors that Solidity from the release it pins
(by sha256 literal, downloaded in its CI, never committed), compiles it
beside the Platform Verifiers under one `foundry.toml`, and embeds the
artifacts in the crate. This repository deploys them. The three `libid-*`
pins in `bin/libid-deploy/Cargo.toml` are the one place every artifact
moves from — the circuits release the Honk verifiers derive from included
— and `Cargo.lock` is the only other file a bump touches.

The circuits release the embedded verifiers came from is read back out of
the crate (`libid_contracts::circuits::version`) and becomes part of each
verifier's factory name below, so the name follows the pin and cannot be
restated. The crate's own tests hold the bindings to the artifacts: every
bound selector against `methodIdentifiers`, `verify(bytes,bytes32[])` on
every circuit verifier, both libraries covered beside every verifier that
links them.

### How the circuit verifier is wired

`PlatformVerifierBase._setTrustRoots` pins the verifier a platform's proofs
are checked under **by address and by code hash**: it reads
`address(honkVerifier_).codehash` and refuses a value that does not match
the hash the caller named, refusing the zero and empty hashes outright. A
bb verifier embeds its verification key as code constants and exposes no
getter, so the code hash is the only handle on which circuit a deployed
verifier answers for.

So apply deploys the verifier and reads the hash back off the chain. There
are two circuits, not three: `oidc-google` proves the Google JWT, and
`bearer-link` ties a token exchange to an identity for X and GitHub alike,
because their statements are byte-identical — so both TLSNotary platforms
pin one deployed verifier.

Each one deploys through the factory under
`libid.circuits.<circuit>.<version>`, so its address is a pure function of
which artifact it is. That is what makes apply idempotent here: a second
run finds code at the same address and sends nothing. It is also the
rotation path — a circuits release is a new name, a new address and a
`setTrustRoots`, while the Platform Verifier proxy and its registration do
not move.

A verifier links `RelationsLib` and `ZKTranscriptLib`: their functions are
`external`, so they are deployed contracts, and bb writes a copy of both
into every verifier it generates. The copies compile to identical
bytecode, and apply deploys each distinct bytecode **once** — through the
CREATE2 deployer under an empty salt, so a library's address is a function
of its code (`libid_contracts::deploy::library_address`): the same on
every chain, found rather than deployed again on a re-run or by a later
circuit, and shared by every verifier that links it. A fresh chain pays
for two libraries and two verifiers. Because a verifier's runtime code
carries those addresses, its code hash — the one the Platform Verifiers
pin — is network-invariant too.

Both verifiers are about 18 KiB of runtime code, comfortably under the
EIP-170 limit of 24576; the anvil tests run the default code-size limit, so
their passing is the proof.

## Factory-first deterministic addresses

Every top-level (entry) contract deploys THROUGH the deterministic
`LibidFactory` via CREATE3, with `salt = keccak256(name)` for a fixed
canonical name. The factory itself lives at one canonical address on every
EVM network (deployed via the keyless Arachnid CREATE2 deployer with frozen
init code), so **each entry address is a pure function of its name** — the
same on every chain, computable before anything is deployed:

```sh
cargo run -- plan --network networks/mainnet.toml.example --print-addresses
```

The authoritative name table (`bin/libid-deploy/src/names.rs`). Renaming an
entry = a NEW address, forever, on every network — names are frozen:

| Config key | Canonical name | Address (every network) |
|---|---|---|
| `contracts.factory` | — (CREATE2, frozen init code) | `0xa92244c3f4462aad08bd1a33c3940b9b936321ad` |
| `contracts.notary_service` | `libid.NotaryService` | `0xbb5871167b0128939cab6850877981421e8dcbf5` |
| `contracts.ceremony_proof_verifier` | `libid.CeremonyProofVerifier` | `0x76bdc18f21c2db0ff796c7cc50348528b2899275` |
| `contracts.identity_names` | `libid.IdentityNames` | `0xd467d48769c26faee36ba6b6fc9228f14aef6dd2` |
| `contracts.google_jwt_roots` | `libid.GoogleJwtRoots` | `0xb7a2ce28e71dbb9c877d2b5a48de33b5f0e6838d` |
| `contracts.x_platform_verifier` | `libid.XPlatformVerifier` | `0xcfc880f62f2744dc000687edf47a98b585d9eb35` |
| `contracts.github_platform_verifier` | `libid.GitHubPlatformVerifier` | `0xac878389da7a1b58826182da0d8b4cae5e6e4178` |
| `contracts.google_platform_verifier` | `libid.GooglePlatformVerifier` | `0xf3d537022362d187715b28bc547f8b2532e6d0cf` |

The circuit verifiers go through the same factory but are not in that
table and not in any network file: their names carry the circuits release
`libid-contracts` vendors, so they move when the contracts pin does. The
libraries they link are not in it either: those land through the CREATE2
deployer at an address derived from their bytecode, so they move only when
the bytecode does. At `libid-circuits` 0.4.0 (`libid-contracts` 0.12.0)
they are

| Component | Name | Address (every network) |
|---|---|---|
| `circuits.bearer-link` | `libid.circuits.bearer-link.0.4.0` | `0xab8c8aabbcd921a8bd944ca693cd2426369d702f` |
| `circuits.oidc-google` | `libid.circuits.oidc-google.0.4.0` | `0xc1150bc7e095aa56654b5c9f6b4561c1751b8352` |
| `circuits.library.RelationsLib` | — (CREATE2, bytecode-derived) | `0x306319f854a5596e1e9e2ec59f99f82ea48abeef` |
| `circuits.library.ZKTranscriptLib` | — (CREATE2, bytecode-derived) | `0x7bb464aa25203cc5b199e0fd7a4258580d71d2a1` |

`plan --print-addresses` prints all of them together with the canonical
table.

Implementations stay plain CREATE deploys: their addresses are referenced
by a proxy slot, not canonical, and upgrades replace them **without moving
any entry address**.

How apply gets there, in order:

1. **Onboarding gate.** The keyless CREATE2 deployer
   (`0x4e59b4…956C`) must exist or be installable via its presigned
   pre-EIP-155 transaction (apply funds the one-time signer with exactly
   0.01 native and broadcasts it). There is deliberately no fallback: a
   chain that rejects the transaction (EIP-155-only) or ships different
   CREATE2 semantics **cannot host the stack** and apply hard-errors.
2. **Factory.** `ensure_factory` deploys the LibidFactory implementation
   and proxy at their frozen-init-code CREATE2 addresses (idempotent).
3. **Canary.** The factory must sit at exactly its predicted canonical
   address; any mismatch means the chain derives CREATE2 addresses
   non-standardly (zkSync-Era-style) and apply aborts before sending
   anything else.
4. **Ownership.** `factory.deploy` is owner-gated (Ownable2Step) and the
   genesis owner baked into the frozen init code is the libID deployer KMS
   address — on real networks the apply signer IS that key. On dev chains
   (anvil/hardhat, detected via `web3_clientVersion`) apply impersonates
   the genesis admin and transfers factory ownership to the local signer;
   impersonation is refused on anything that does not look like a dev
   chain, `--dev` flag or not.
5. **CREATE3 deploys.** Every entry contract goes through
   `factory.deploy(name, creationCode)` and is verified to land on
   `predict_address(factory, name)`.

## Config schema

Every value in a network file is public: addresses and a public RPC. The
only secret in the flow is the KMS key, which never leaves AWS.

| Section | Kind | Contents |
|---|---|---|
| `[network]` | input | `name`, `chain_id` (apply refuses a mismatch, whichever endpoint answers), `rpc_url` (the endpoint the file's own environment reaches; `--rpc-url` names another without touching the file) |
| `[aws]` | input | `region`, `kms_deployer` (key id / `alias/...` / ARN; the default signer) |
| `[accounts]` | input | `notary` (the notary **signer** — see below), `owner` (the operational owner the factory ends up with; empty = the deployer) — addresses of **keys**, not contracts |
| `[notary_service]` | input | `fee_wei` — what one attestation verification costs, as a decimal string |
| `[contracts]` | declared | `factory`, `notary_service`, `ceremony_proof_verifier`, `identity_names`, `google_jwt_roots`, `x_platform_verifier`, `github_platform_verifier`, `google_platform_verifier` — always present, pre-filled with the canonical table, validated against the prediction |

The circuit verifiers are not in the file. They are a property of the
binary's contracts pin — which carries the circuits release — not of a
network, and their addresses derive from it the same way the canonical
table derives from its names.

The `[accounts].owner` flow: the factory's genesis owner is the libID
deployer KMS address baked into its frozen init code. `apply` needs factory
ownership only while it has names left to `factory.deploy`; at the end of
every run it converges ownership onto `owner`. Empty `owner` = the deployer
— exact on real networks, where the KMS genesis admin IS the apply signer.
A different `owner` makes apply INITIATE the Ownable2Step handover (that
key must `acceptOwnership` itself). Local dev configs set
`owner = <anvil #0>` explicitly, and on a dev chain (anvil/hardhat) apply
completes the handover by impersonation, so the stack ends fully owned by
the declared operational owner.

The notary split:

- `accounts.notary` is the notary **signer** — the identity whose
  attestations the stack accepts. `contracts.notary_service` is the Notary
  Service **contract** (a UUPS proxy) that holds the trusted key set; every
  other contract takes the proxy address at initialize and verifies
  through it.
- On a fresh deploy the Notary Service deploys **first**
  (`initialize(owner = deployer, notary = accounts.notary, fee =
  notary_service.fee_wei)`) and its proxy is wired into everything else.
- Rotation is half declarative: `plan` shows whether the declared signer is
  trusted, `apply` sends the one `setNotary` that adds it. Dropping the
  outgoing key is a separate governance call on purpose — the service holds
  a SET so a rotation can overlap, and which key to stop trusting is not
  something the file can say.

Declared-address semantics:

- Every canonical key is **always present and pre-filled** with the
  canonical table; `validate` errors on a value that does not equal
  `predict_address(factory, name)` (naming the expected value) and on an
  empty canonical key. Presence on-chain is checked via `eth_getCode` at
  plan/apply time; `apply` deploys whatever the CHAIN lacks and never
  touches the file.
- The **fresh-deploy guard keys on chain state**: `--confirm-fresh-deploy`
  is required exactly when the FACTORY has no code on-chain (a virgin
  network — that first apply publishes the entire declared stack). With
  the factory present, apply converges incrementally without the flag.
- The three keyspaces are **re-sent every run**. `IdentityNames` exposes no
  getter for a platform's rules, so writing them is the only way to
  converge on what the generated table says; the call is owner-only and
  idempotent.

## Running locally

```sh
# parse + sanity checks (add --check-rpc to also probe the endpoint)
cargo run -- validate --network networks/eden-testnet.toml

# read-only diff against the chain; --json for machine output. The plan
# leads with the onboarding gate (CREATE2 deployer + factory) and quotes
# the predicted CREATE3 address of everything missing — even on an empty
# chain. --print-addresses prints the canonical table offline and exits.
cargo run -- plan --network networks/eden-testnet.toml

# converge; the signer defaults to aws.kms_deployer (needs ambient AWS
# credentials), or pass a local key for anvil rehearsal
cargo run -- apply --network networks/eden-testnet.toml \
  --signer <64-hex-key-or-kms-id> [--upgrade identity-names] [--yes] \
  [--confirm-fresh-deploy]
```

The `--signer` spec is classified by shape: 64 hex chars is a local private
key, anything else goes to AWS KMS (region/credentials from the ambient AWS
environment). An all-hex value of the wrong length is rejected as a mangled
key rather than shipped to AWS.

Every command that contacts a chain takes `--rpc-url <URL>`. A network
file names the endpoint its own environment reaches (`network.rpc_url`);
the flag is for a caller somewhere else — the host outside a compose
network, a CI job with a bare anvil — and it wins outright, the file being
the default. Only the transport moves: the declared chain id is still
enforced against whatever answers, every address is still the file's, and
the file is still never rewritten. A value that does not parse or does not
answer is an error, never a fallback to the file. `plan --print-addresses`
is offline and rejects the flag.

Upgrade components: `notary-service`, `proof-verifier`, `identity-names`,
`google-jwt-roots`, `x-platform-verifier`, `github-platform-verifier`,
`google-platform-verifier`. Each is a UUPS `upgradeToAndCall`: the entry
address, its storage and its owner all survive, so an upgrade never moves a
canonical address and never disturbs a registration. Each upgrade runs
inside its component's own step, before apply reads or wires that
component: a proxy whose running implementation predates a getter the
wiring reads (`plan` flags it as `WARN ... read failed`) converges in the
same `apply --upgrade` run instead of aborting at the read.

For anvil rehearsal, `apply --dev` (or just letting apply detect anvil)
covers the factory-ownership wrinkle: the local signer is not the baked
genesis admin, so apply impersonates the admin and Ownable2Step-transfers
factory ownership to the signer for the deploys, then converges it onto
the declared `[accounts].owner` (the anvil #0 wallet in the local dev
configs), completing the handover by impersonation. This path is refused
on real chains.

## How the Apply action works

`.github/workflows/apply.yml`, manual only (`workflow_dispatch`):

1. Inputs: `network` (choice), `mode` (`plan` default / `apply`), `upgrade`
   (comma list), `confirm_fresh_deploy`, `source` (`release` downloads the
   latest release binary; `branch` builds with cargo).
2. Assumes `AWS_DEPLOYER_ROLE_ARN` via GitHub OIDC in the region parsed
   from the network file.
3. KMS preflight before any transaction: `describe-key` must report an
   enabled `ECC_SECG_P256K1`/`SIGN_VERIFY` key, the deployer address is
   derived from `get-public-key` via `cast keccak`, and its balance must be
   nonzero.
4. Runs `plan` always; `apply` only when `mode: apply`. Both render into
   the step summary.
5. There is **no write-back and no PR step**: the file already declares
   every canonical address, so an apply discovers nothing to record — a
   post-apply check fails the job if the working tree changed at all. The
   permissions are read-only on repo contents accordingly.

One apply per network at a time (`concurrency`, no cancel-in-progress:
a half-applied upgrade is worse than a queued one). The job runs in the
GitHub **environment named after the network**, so production networks can
demand reviewers.

## Local development chain

`networks/local-dev.toml` is the stack on a throwaway anvil: chain 31337,
anvil account #0 as deployer and operational owner, anvil account #1 as the
notary signer, and a **non-zero** Notary Fee — a local stack that meters at
no charge lets a client attaching the wrong value pass, and `WrongValue` is
then first seen where it costs something. The deployer spec in the file is
anvil's own published test key: `--signer` specs are classified by shape,
so 64 hex characters is a local key and no AWS call happens.

Its `rpc_url` is the compose service name, `http://anvil:8545`, which only
resolves inside that network. From anywhere else — the host, a CI job that
started `anvil --host 127.0.0.1 --port 8545` — the file is consumed as it
is and `--rpc-url` names the endpoint:

```sh
# inside the compose network
docker compose up -d anvil
libid-deploy apply --network networks/local-dev.toml --yes \
  --confirm-fresh-deploy --dev

# from the host, or a CI runner with a bare anvil
anvil --host 127.0.0.1 --port 8545 &
libid-deploy apply --network networks/local-dev.toml \
  --rpc-url http://127.0.0.1:8545 --yes --confirm-fresh-deploy --dev
```

Integration tests apply the committed file, unmodified, against a real
anvil through `--rpc-url`, so it cannot rot into something that only
parses, and prove the flag moves nothing but the transport: the same
addresses land, the file's chain id is enforced against the override, and
an override that does not answer fails instead of falling back to the file.

## Adding a network

Copy `networks/mainnet.toml.example` — it ships FULLY pre-filled with the
canonical address table, which is valid on every EVM network — fill the
input keys (chain, RPC, AWS, accounts, Notary Fee), add the name to the
`network` choice list in `apply.yml`, and run the workflow with `mode:
plan` first. The first apply on a virgin network needs
`confirm_fresh_deploy`.

## Release process

Publish a GitHub Release (tag `vX.Y.Z`). `release.yml` re-runs the CI
checks on the released ref, then builds `libid-deploy` for four targets —
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`aarch64-apple-darwin` and `x86_64-apple-darwin`, each natively on a runner
of its architecture — and uploads `libid-deploy-<version>-<target>.tar.gz`
for each as a release asset. The apply workflow's default `source:
release` consumes the newest Linux x86_64 asset.

## Development

- The crate embeds nothing of its own: every contract artifact comes with
  the `libid-contracts` crate, so `cargo build` needs no script, no forge
  and no bb. Moving a contract, a circuit or a Platform Verifier is a bump
  of the three `libid-*` pins in `bin/libid-deploy/Cargo.toml`.
- `cargo +nightly fmt` only — stable rustfmt silently ignores the
  nightly-only options in `rustfmt.toml`.
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test` — the integration tests need `anvil` on PATH (spawned bare:
  `--disable-default-create2-deployer`, proving the install path) and cover
  the critical declarative cycle — pre-filled file → fresh apply on a
  virgin anvil lands everything AT the declared addresses → second apply is
  a no-op without any flag → the file is BYTE-IDENTICAL throughout — plus
  drift repair, the Platform Verifier deploy/register/rotate path, the
  network-invariance proof: two separate bare anvils converge onto the same
  declared canonical addresses, and the `--rpc-url` contract: the committed
  local-dev file, unmodified, converges an anvil the file does not name,
  while a wrong chain id or a dead override is refused. The circuit
  verifiers those tests deploy are the real Honk verifiers: each is handed
  a wrong-length proof and must answer with its own circuit's `logN`, the
  two must differ, and both must carry the one shared address of each
  library, deployed exactly once. A stand-in contract with unrelated code
  is used only to drift a trust root, so the pull-back is exercised on a
  pin that could never verify a proof.
- Every commit must be signed off (`git commit -s`); see CONTRIBUTING.md.
