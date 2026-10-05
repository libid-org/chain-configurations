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

Five UUPS proxies, in dependency order: the four `libid-contracts`' own
`script/Deploy.s.sol` deploys, in its order, and the handle escrow right
after the identity registry it resolves through:

1. **NotaryService** — the ONE place a notary attestation is
   authenticated. It derives the digest from the attested bytes itself and
   charges the Notary Fee. Deployed first so its proxy address can be
   wired into every consumer's `initialize`.
2. **CeremonyProofVerifier** — the Supported Version Set: which Platform
   Verifier answers for a `(platformId, verifierVersion)` pair. Without it
   the identity registry's `proofVerifier` reads zero and every resolver
   reverts.
3. **IdentityRegistry** — the identity registry, pointed at the Proof
   Verifier and given handle rules per platform key (`x`, `github`,
   `google`) from `libid-identity`'s generated table.
4. **HandleEscrow** — value sent to a handle before anyone holds it,
   claimed by the holder the registry binds the handle to. `initialize`
   takes the registry's address and refuses one that does not answer the
   escrow's reads. No setter moves the escrow to another registry
   afterwards.
5. **GoogleJwtRoots** — the Google signing keys the `google/v1` Platform
   Verifier trusts, verified through the Notary Service like any other
   notarized session. It deploys **EMPTY**: point a keeper at it, or every
   Google binding reverts `UntrustedModulus`.

Then two steps `Deploy.s.sol` does not have:

6. **A Honk verifier per ceremony circuit** — the bb-generated UltraHonk
   verifier each platform's proofs are checked under, deployed through the
   factory under a CREATE3 name carrying the pinned circuits release.
7. **A Platform Verifier per platform** — `XPlatformVerifier`,
   `GitHubPlatformVerifier`, `GooglePlatformVerifier` — deployed behind its
   own CREATE3 proxy, pinned to its circuit's verifier by address and code
   hash, and registered into the Supported Version Set with
   `CeremonyProofVerifier.setVerifier(platformId, 1, verifier)`. Until that
   registration lands, a platform has its rules and can verify nothing:
   `bind` reverts `UnknownVersion` and every resolver reverts
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
bound selector against `methodIdentifiers`, and `verify(bytes,bytes32[])`
on every circuit verifier.

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

Each verifier is bb's optimized template, one contract that links
nothing: a fresh chain pays for two verifiers, and a verifier's code hash —
the one the Platform Verifiers pin — is the same on every chain.

Both verifiers are under 17 KiB of runtime code, under the EIP-170 limit of
24576; the anvil tests run the default code-size limit, so their passing is
the proof.

## Factory-first deterministic addresses

Every top-level (entry) contract deploys THROUGH the deterministic
`LibidFactory` via CREATE3, with `salt = keccak256(name)` for a fixed
canonical name. The factory itself lives at one address on every EVM
network its deployer deploys to (via the keyless Arachnid CREATE2 deployer,
with init code whose only varying input is `accounts.deployer`, the genesis
admin), so **each entry address is a pure function of the deployer and the
name** — computable before anything is deployed:

```sh
cargo run -- plan --network networks/eden-testnet.toml --print-addresses
```

One deployer key per environment: testnet's lives in the libid-testnet AWS
account and serves eden-testnet and Sepolia, mainnet's in libid-mainnet, so
the two environments have different tables. The authoritative name table
(`bin/libid-deploy/src/names.rs`). Renaming an entry = a NEW address,
forever, on every network — names are frozen. The testnet table, deployer
`0xdaeb247f5a90c53f2d7a80a81f6cb6acb0d8b907`:

| Config key | Canonical name | Address (testnet) |
|---|---|---|
| `contracts.factory` | — (CREATE2, frozen init code) | `0x9dbf2b5f96cb31a48cca4e25d2c8348be414ebc8` |
| `contracts.notary_service` | `libid.NotaryService` | `0xa773ec5e7500d1c87827ab1b899bbd992c1b5931` |
| `contracts.ceremony_proof_verifier` | `libid.CeremonyProofVerifier` | `0xa795b14a2e09daf273bc6971058b0462c7d6be42` |
| `contracts.identity_registry` | `libid.IdentityRegistry` | `0x25f29c8c765db2f27d1e2b23987a7b0655c7d640` |
| `contracts.handle_escrow` | `libid.HandleEscrow.2` | `0x57355e1d1bcf61fec9b2e5cad60dcccdddc4d8e5` |
| `contracts.google_jwt_roots` | `libid.GoogleJwtRoots` | `0x8a14a5dda7662f88a5448b9b8b2ca9f1d5742904` |
| `contracts.x_platform_verifier` | `libid.XPlatformVerifier` | `0x9f655c2fe778260d90f3202d97da0a46510aa3d0` |
| `contracts.github_platform_verifier` | `libid.GitHubPlatformVerifier` | `0xb5fdf35eedf7c849f3d1e41675d8b8a41487e248` |
| `contracts.google_platform_verifier` | `libid.GooglePlatformVerifier` | `0x5cfb807545e0e2ce4d7dac7d97ab0583e3fbe1c6` |

The mainnet table, deployer `0x7e00d33b5c571ca2b2879309c4846ddd80f4128e`
(Ethereum, `networks/ethereum.toml`):

| Config key | Address (mainnet) |
|---|---|
| `contracts.factory` | `0xb7432c991be3167689d5e80c9e2bf1ff5cccd2e0` |
| `contracts.notary_service` | `0x2feee7c87bec78853afc223135735d4786e75177` |
| `contracts.ceremony_proof_verifier` | `0x36e6d6cf465cb9f0615ceb0fc37ef30927dac66e` |
| `contracts.identity_registry` | `0xbefd300aff7d4a67fb381afe8b3596793d3e9a83` |
| `contracts.handle_escrow` | `0x17a244e23ef1f12071298a1862194fea3d00bbf7` |
| `contracts.google_jwt_roots` | `0x1f3d9b49efde0c12ed2ffeab67165ebe0c97517a` |
| `contracts.x_platform_verifier` | `0x61d79debf1b7e512ae8b305ba76c6f82f4609142` |
| `contracts.github_platform_verifier` | `0xdd7d34f2302bc2ccac36bdcec5fdafe0ca91f888` |
| `contracts.google_platform_verifier` | `0x727f4a1c9040a94ca27f74667c70d1c2951a0b5a` |

The circuit verifiers go through the same factory but are not in that
table and not in any network file: their names carry the circuits release
`libid-contracts` vendors, so they move when the contracts pin does. At
`libid-circuits` 0.6.0 (`libid-contracts` 0.16.0) they are

| Component | Name | Address (testnet) |
|---|---|---|
| `circuits.bearer-link` | `libid.circuits.bearer-link.0.6.0` | `0xb152321148f37c13147f4313a82c72d4e1a95d14` |
| `circuits.oidc-google` | `libid.circuits.oidc-google.0.6.0` | `0x5301b6c527410565c82dff20b44a71c3e1d151b2` |

On mainnet they are `0x8bcd52dd0f75c0936f00c40ab78fb9430df50d91` and
`0x14b342b4faf09f0462bbd611906d33622e33fdfc`.

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
2. **Factory.** `FactoryGenesis::ensure` deploys the LibidFactory
   implementation and proxy at their CREATE2 addresses, the proxy's init
   code carrying `accounts.deployer` as the genesis admin (idempotent).
3. **Canary.** The factory must sit at exactly its predicted address; any
   mismatch means the chain derives CREATE2 addresses non-standardly
   (zkSync-Era-style) and apply aborts before sending anything else.
4. **Ownership.** `factory.deploy` is owner-gated (Ownable2Step) and the
   genesis owner is `accounts.deployer`, so apply refuses any signer but
   that key, on every chain, anvil included. A factory that an earlier
   apply handed to a different `owner` has to be handed back before new
   names can deploy.
5. **CREATE3 deploys.** Every entry contract goes through
   `factory.deploy(name, creationCode)` and is verified to land on
   `predict_address(factory, name)`.

## Config schema

Every value in a network file is public: addresses, accounts, the fee.
The endpoint is not in the file: it is the `RPC_URL` secret of the
network's GitHub environment, or `--rpc-url` on a host. The other secret
in the flow is the KMS key, which never leaves AWS.

| Section | Kind | Contents |
|---|---|---|
| `[network]` | input | `name`, `chain_id` (apply refuses a mismatch, whichever endpoint answers); `rpc_url` only where the environment's endpoint is no secret (`local-dev`'s compose service) — a real network's file names none, and `--rpc-url` supplies it |
| `[aws]` | input | `region`, `kms_deployer` (key id / `alias/...` / ARN; the default signer) |
| `[accounts]` | input | `notary` (the notary **signer** — see below), `owner` (the operational owner the factory ends up with; empty = the deployer) — addresses of **keys**, not contracts |
| `[notary_service]` | input | `fee_wei` — what one attestation verification costs, as a decimal string |
| `[contracts]` | declared | `factory`, `notary_service`, `ceremony_proof_verifier`, `identity_registry`, `handle_escrow`, `google_jwt_roots`, `x_platform_verifier`, `github_platform_verifier`, `google_platform_verifier` — always present, pre-filled with the canonical table, validated against the prediction |

The circuit verifiers are not in the file. They are a property of the
binary's contracts pin — which carries the circuits release — not of a
network, and their addresses derive from it the same way the canonical
table derives from its names.

The `[accounts].owner` flow: the factory's genesis owner is
`accounts.deployer`, the apply signer. `apply` needs factory ownership only
while it has names left to `factory.deploy`; at the end of every run it
converges ownership onto `owner`. Empty `owner` = the deployer, exact. A
different `owner` makes apply INITIATE the Ownable2Step handover (that key
must `acceptOwnership` itself); on a dev chain (anvil/hardhat, detected via
`web3_clientVersion`) apply completes the handover by impersonation, so a
local stack ends fully owned by the declared operational owner.

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
- The three platforms' handle rules are **re-sent every run**; the call is
  owner-only and idempotent.

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
  --signer <64-hex-key-or-kms-id> [--upgrade identity-registry] [--yes] \
  [--confirm-fresh-deploy]
```

The `--signer` spec is classified by shape: 64 hex chars is a local private
key, anything else goes to AWS KMS (region/credentials from the ambient AWS
environment). An all-hex value of the wrong length is rejected as a mangled
key rather than shipped to AWS.

Every command that contacts a chain takes `--rpc-url <URL>`, and for a
real network that is where the endpoint comes from: its file names none,
because where a node listens is a property of the caller's environment,
not of the network, and a provider's endpoint carries a key. A file may
name the endpoint its own environment reaches — `local-dev` names its
compose service — and then the flag, for a caller somewhere else, wins
outright with the file as the default. Only the transport moves: the
declared chain id is still enforced against whatever answers, every
address is still the file's, and the file is still never rewritten. A
value that does not parse or does not answer is an error, never a
fallback; a file without an endpoint and no flag is an error naming both.
`validate` contacts the chain only under `--check-rpc`, so without it a
file needs no endpoint. `plan --print-addresses` is offline and rejects the
flag.

In the apply workflow the flag is the `RPC_URL` secret of the network's
GitHub environment, passed on every call; a network whose environment
lacks it fails before anything is read. Everything written about an
endpoint — the plan's first line, the apply log, a prompt — names it by
origin alone, scheme, host and port, so the key reaches no step summary.

Upgrade components: `notary-service`, `proof-verifier`, `identity-registry`,
`handle-escrow`, `google-jwt-roots`, `x-platform-verifier`,
`github-platform-verifier`, `google-platform-verifier`. Each is a UUPS
`upgradeToAndCall`: the entry address, its storage and its owner all
survive, so an upgrade never moves a canonical address and never disturbs
a registration. Each upgrade runs inside its component's own step, before
apply reads or wires that component: a proxy whose running implementation
predates a getter the wiring reads (`plan` flags it as `WARN ... read
failed`) converges in the same `apply --upgrade` run instead of aborting
at the read.

For anvil rehearsal the local dev config names anvil #0 as `deployer` and
`owner` alike, so the local signer owns the factory from genesis and no
handover happens. A rehearsal of a handover sets a different `owner`:
apply initiates it and, on anvil, completes it by impersonation.

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
  --confirm-fresh-deploy

# from the host, or a CI runner with a bare anvil
anvil --host 127.0.0.1 --port 8545 &
libid-deploy apply --network networks/local-dev.toml \
  --rpc-url http://127.0.0.1:8545 --yes --confirm-fresh-deploy
```

Integration tests apply the committed file, unmodified, against a real
anvil through `--rpc-url`, so it cannot rot into something that only
parses, and prove the flag moves nothing but the transport: the same
addresses land, the file's chain id is enforced against the override, and
an override that does not answer fails instead of falling back to the file.

## Adding a network

Copy `networks/mainnet.toml.example`, fill the input keys (chain, AWS,
accounts, Notary Fee), regenerate `[contracts]` for the file's deployer with
`plan --network <file> --print-addresses` (the template's table is anvil
#0's), add the name to the
`network` choice list in `apply.yml`, and create the GitHub environment of
that name with an `RPC_URL` secret holding its endpoint: the file names
none. Run the workflow with `mode: plan` first. The first apply on a
virgin network needs `confirm_fresh_deploy`.

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
  drift repair, the handle escrow bound to the IdentityRegistry beside it,
  the Platform Verifier deploy/register/rotate path, the network-invariance
  proof: two separate bare anvils converge onto the same
  declared canonical addresses, and the `--rpc-url` contract: the committed
  local-dev file, unmodified, converges an anvil the file does not name,
  while a wrong chain id or a dead override is refused. The circuit
  verifiers those tests deploy are the real Honk verifiers: each is handed
  a wrong-length proof and must answer with its own circuit's `logN`, and
  the two must differ. A stand-in contract with unrelated code
  is used only to drift a trust root, so the pull-back is exercised on a
  pin that could never verify a proof.
- Every commit must be signed off (`git commit -s`); see CONTRIBUTING.md.
