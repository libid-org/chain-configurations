# chain-configurations

Desired-state configuration for the libid contract stack, one file per
network, plus the `libid-deploy` binary and the GitHub Actions that apply a
file to its chain with an AWS KMS signer.

The model is DECLARATIVE (0.4.0):

1. `networks/<name>.toml` declares what should exist on a chain — including
   **every address, pre-filled up front**. Canonical contracts live at
   CREATE3-deterministic addresses, so the file carries the full address
   table before the chain has anything on it; `validate` rejects a
   canonical key whose value is not exactly `predict_address(factory,
   name)`, naming the expected value.
2. Deployed-vs-not is determined from **chain state** (`eth_getCode` at the
   declared address / the factory's `deployedAt` record) — never from
   config emptiness. The old "empty = not deployed" convention is dead on
   declarative files.
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

All contract bytecode is embedded in the binary via the
[`libid-contracts`](https://github.com/libid-org/libid-contracts) crate —
there is no forge build and no artifact directory at runtime.

> The generated UltraHonk circuit verifiers exceed the EIP-170 code-size
> limit. Target chains must allow big code (Eden does — they are deployed
> there today). Local rehearsal needs `anvil --disable-code-size-limit`.

## Factory-first deterministic addresses (libid-contracts 0.3.0)

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
| `contracts.notary` | `libid.Notary` | `0x4bddfe9fb875d03838e5013c338e2dea9dcc2fc5` |
| `contracts.wallet_factory` | `libid.WalletFactory` | `0x945b8a7a480a2552ec3c61c24d4363c9558107a8` |
| `contracts.registry` | `libid.Registry` | `0x03c2b8d5f4d5cf7b7f81f876035046e262c4c9c9` |
| `contracts.bank` | `libid.Bank` | `0x060708036a9ee89c6513346abab0929427bc9b06` |
| `contracts.x_zk_verifier` | `libid.XZkVerifier` | `0xf8ddccfebfefdc5cbae308f0aac9a12e275eda5f` |
| `contracts.google_oidc_verifier` | `libid.GoogleOidcVerifier` | `0xef53a51e3a46e5f82248a39ddff0b7b901ab438c` |
| `identity.identity_names` | `libid.IdentityNames` | `0xd467d48769c26faee36ba6b6fc9228f14aef6dd2` |
| `identity.github_identity_verifier` | `libid.GitHubIdentityVerifier` | `0x936067c1b5d77c67358210e77f664382191d2015` |
| `identity.x_identity_verifier` | `libid.XIdentityVerifier` | `0xda66811e494a918e9ae0e5797206fca04333c055` |
| `identity.google_identity_verifier` | `libid.GoogleIdentityVerifier` | `0x1b9db690ee040ca92d44d1585b3aab625a475c27` |
| `identity.identity_jwks_roots` | `libid.IdentityJwksRoots` | `0x589b56f95d5df5483c79e46e7b20293135c9ebd9` |

Implementations, Bank facets, and the Honk circuit verifiers stay plain
CREATE deploys: their addresses are referenced (by a proxy slot, the
diamond, or the Registry), not canonical, and upgrades replace them
**without moving any entry address**.

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

One exception: `--upgrade oidc-verifier` REPLACES the GoogleOidcVerifier
with a plain CREATE deployment — the canonical name is single-use and the
replacement's address is meant to change. The new address is recorded
**on-chain only**: `Registry.oidcVerifierOf` is the record, and the config
keeps declaring the canonical first-deploy address (the file is never
rewritten). `plan` knows the pattern and reports the divergence as ok, not
a warning.

## Config schema

Every value in a network file is public: addresses, a public RPC, OAuth
*client ids*. The only secret in the flow is the KMS key, which never
leaves AWS.

| Section | Kind | Contents |
|---|---|---|
| `[network]` | input | `name`, `chain_id` (apply refuses a mismatch), `rpc_url`, `legacy_addresses` (marks a pre-factory record — see below) |
| `[aws]` | input | `region`, `kms_deployer` (key id / `alias/...` / ARN; the default signer) |
| `[accounts]` | input | `notary` (the notary **signer** — see below), `backend`, `owner` (the operational owner the factory ends up with; empty = the deployer) — addresses of **keys**, not contracts. `oidc_notary` is accepted for legacy pre-Notary files but no longer wired anywhere |
| `[contracts]` | declared | `factory` (the deterministic LibidFactory), `notary` (the Notary **proxy**), `bank`, `registry`, `wallet_factory`, `x_zk_verifier`, `google_oidc_verifier` — always present, pre-filled with the canonical table, validated against the prediction |
| `[identity]` | declared | `identity_names`, `github_identity_verifier`, `x_identity_verifier`, `google_identity_verifier`, `identity_jwks_roots` — same rules; the optional keys signal wanted-ness by presence |
| `[platforms]` | input | `x_client_id`, `google_client_id`, `github_bot_handle`, `x_bot_handle` |
| `[[tokens]]` | input | `symbol`, `address` (zero address = native; token addresses are non-canonical and stay free-form) |
| `[templates]` | input | per-platform comment templates (string or array), keyed by platform domain |

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

The Notary split (libid-contracts 0.2.0):

- `accounts.notary` is the notary **signer** — the EOA/KMS identity whose
  attestations the stack accepts. `contracts.notary` is the Notary
  **contract** (a UUPS proxy) that stores that signer; every other
  contract takes the proxy address at initialize and verifies through it.
- On a fresh deploy the Notary deploys **first**
  (`initialize(owner = deployer, notary = accounts.notary)`) and its proxy
  is wired into everything else.
- Rotation is declarative: edit `accounts.notary`, `plan` diffs it against
  the on-chain `Notary.notary()` and shows the pending rotation, `apply`
  sends the one `setNotary` — every consumer follows the contract.
- `plan` also spot-checks consumers' `notaryContract()` wiring; a mismatch
  (or a pre-Notary contract without the getter) is a WARN that apply does
  not fix silently.

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
- `[identity]` absent = the identity-names stack is not wanted. Once the
  section exists, `identity_names` and `github_identity_verifier` are
  always converged; `x_identity_verifier` / `google_identity_verifier` are
  requested by their key being *present* (carrying the canonical address).
  Google requires `identity_jwks_roots` declared alongside; the roots
  contract starts EMPTY — point a JWKS rotation listener at it before
  Google names work.
- The verifiers are guarded: the X ZK verifier deploys only when
  `x_client_id` is set and the Registry slot is zero; the Google OIDC
  verifier only when `google_client_id` is set and the slot is zero. A
  changed client id is **not** applied to an already-deployed verifier —
  that is what `--upgrade oidc-verifier` is for.
- **Legacy files** (`network.legacy_addresses = true`, today only
  `networks/eden-testnet.toml`) record a pre-factory deployment verbatim:
  the canonical equality check is skipped, `plan` keeps the old
  empty-means-not-deployed reading, and `apply` refuses to run — the
  planned fresh redeploy replaces such stacks.

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
  --signer <64-hex-key-or-kms-id> [--upgrade bank,registry] [--yes] \
  [--confirm-fresh-deploy]
```

The `--signer` spec is classified by shape: 64 hex chars is a local private
key, anything else goes to AWS KMS (region/credentials from the ambient AWS
environment). An all-hex value of the wrong length is rejected as a mangled
key rather than shipped to AWS.

Upgrade components: `registry`, `wallet-factory`, `notary` (UUPS
`upgradeToAndCall`; the proxy address and its stored signer survive),
`bank` (diamond facet REPLACE — the diamond is the storage, the facets are
the code), `oidc-verifier` (redeploy + re-point; the new address is
recorded on-chain in `Registry.oidcVerifierOf`, not in the file). Upgrades
never move an entry address — the canonical CREATE3 addresses are stable
across every upgrade except the OIDC REPLACE, whose address change is the
point.

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

## Adding a network

Copy `networks/mainnet.toml.example` — it ships FULLY pre-filled with the
canonical address table, which is valid on every EVM network — fill the
input keys (chain, RPC, AWS, accounts, platforms, tokens, templates), add
the name to the `network` choice list in `apply.yml`, and run the workflow
with `mode: plan` first. The first apply on a virgin network needs
`confirm_fresh_deploy`.

## Release process

Publish a GitHub Release (tag `vX.Y.Z`). `release.yml` re-runs the CI
checks, then builds `libid-deploy` for `x86_64-unknown-linux-gnu` and
`aarch64-unknown-linux-gnu` (natively, on arm64 runners) and uploads
`libid-deploy-<version>-<target>.tar.gz` as release assets. The apply
workflow's default `source: release` consumes the newest x86_64 asset.

## Development

- `cargo +nightly fmt` only — stable rustfmt silently ignores the
  nightly-only options in `rustfmt.toml`.
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test` — the integration tests need `anvil` on PATH (spawned bare:
  `--disable-default-create2-deployer`, proving the install path) and cover
  the critical declarative cycle — pre-filled file → fresh apply on a
  virgin anvil lands everything AT the declared addresses → second apply is
  a no-op without any flag → the file is BYTE-IDENTICAL throughout — plus
  the network-invariance proof: two separate bare anvils converge onto the
  same declared canonical addresses.
- Every commit must be signed off (`git commit -s`); see CONTRIBUTING.md.
