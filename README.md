# chain-configurations

Desired-state configuration for the libid contract stack, one file per
network, plus the `libid-deploy` binary and the GitHub Actions that apply a
file to its chain with an AWS KMS signer.

The model is converge-and-record:

1. `networks/<name>.toml` says what should exist on a chain.
2. `libid-deploy plan` compares it with what does — read-only.
3. `libid-deploy apply` deploys whatever is missing, re-sends the idempotent
   configuration, performs explicitly requested upgrades, and **rewrites the
   file** with the addresses it minted.
4. The apply workflow opens a PR with the modified file, so the
   configuration catches up with reality and the next run reconciles
   instead of redeploying.

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
replacement's address is meant to change. After a replace, the live
(config) address legitimately diverges from the factory's `deployedAt`
record; `plan` knows and does not warn.

## Config schema

Every value in a network file is public: addresses, a public RPC, OAuth
*client ids*. The only secret in the flow is the KMS key, which never
leaves AWS.

| Section | Kind | Contents |
|---|---|---|
| `[network]` | input | `name`, `chain_id` (apply refuses a mismatch), `rpc_url` |
| `[aws]` | input | `region`, `kms_deployer` (key id / `alias/...` / ARN; the default signer) |
| `[accounts]` | input | `notary` (the notary **signer** — see below), `backend` — addresses of **keys**, not contracts. `oidc_notary` is accepted for legacy pre-Notary files but no longer wired anywhere |
| `[contracts]` | output | `factory` (the deterministic LibidFactory — predictable, recorded anyway), `notary` (the Notary **proxy**), `bank`, `registry`, `wallet_factory`, `x_zk_verifier`, `google_oidc_verifier` |
| `[identity]` | output | `identity_names`, `github_identity_verifier`, `x_identity_verifier`, `google_identity_verifier`, `identity_jwks_roots` |
| `[platforms]` | input | `x_client_id`, `google_client_id`, `github_bot_handle`, `x_bot_handle` |
| `[[tokens]]` | input | `symbol`, `address` (zero address = native) |
| `[templates]` | input | per-platform comment templates (string or array), keyed by platform domain |

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

Output-key semantics:

- **Empty (`""`) or absent** = not deployed yet; `apply` deploys and fills
  it. `apply` never overwrites a non-empty value — except
  `--upgrade oidc-verifier`, which REPLACES that verifier so its address
  genuinely changes.
- An entirely empty `[contracts]` section is a **fresh deploy** and
  requires `--confirm-fresh-deploy` (it orphans anything already on the
  chain, including balances).
- `[identity]` absent = the identity-names stack is not wanted. Once the
  section exists, `identity_names` and `github_identity_verifier` are
  always converged; `x_identity_verifier` / `google_identity_verifier` are
  requested by their key being *present* (even if empty). Google also
  deploys `identity_jwks_roots`, which starts EMPTY — point a JWKS rotation
  listener at it before Google names work.
- The verifiers are guarded: the X ZK verifier deploys only when
  `x_client_id` is set and the Registry slot is zero; the Google OIDC
  verifier only when `google_client_id` is set and the slot is zero. A
  changed client id is **not** applied to an already-deployed verifier —
  that is what `--upgrade oidc-verifier` is for.

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
the code), `oidc-verifier` (redeploy + re-point; new address, recorded in
the PR). Upgrades never move an entry address — the canonical CREATE3
addresses are stable across every upgrade except the OIDC REPLACE, whose
address change is the point.

For anvil rehearsal, `apply --dev` (or just letting apply detect anvil)
covers the factory-ownership wrinkle: the local signer is not the baked
genesis admin, so apply impersonates the admin and Ownable2Step-transfers
factory ownership to the signer. This path is refused on real chains.

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
4. Runs `plan` always; `apply` only when `mode: apply`.
5. Opens a PR (`apply/<network>-<run id>`) with the rewritten network file,
   including the deployer identity and a downstream-propagation checklist.
   No changes → no PR.

One apply per network at a time (`concurrency`, no cancel-in-progress:
a half-applied upgrade is worse than a queued one). The job runs in the
GitHub **environment named after the network**, so production networks can
demand reviewers.

## Adding a network

Copy `networks/mainnet.toml.example`, fill the input keys, add the name to
the `network` choice list in `apply.yml`, and run the workflow with
`mode: plan` first.

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
  the critical cycle — empty file → fresh apply → file rewritten → second
  apply is a no-op — plus the network-invariance proof: two separate bare
  anvils converge to IDENTICAL canonical addresses matching the offline
  prediction.
- Every commit must be signed off (`git commit -s`); see CONTRIBUTING.md.
