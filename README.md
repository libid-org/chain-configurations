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

## Config schema

Every value in a network file is public: addresses, a public RPC, OAuth
*client ids*. The only secret in the flow is the KMS key, which never
leaves AWS.

| Section | Kind | Contents |
|---|---|---|
| `[network]` | input | `name`, `chain_id` (apply refuses a mismatch), `rpc_url` |
| `[aws]` | input | `region`, `kms_deployer` (key id / `alias/...` / ARN; the default signer) |
| `[accounts]` | input | `notary`, `oidc_notary`, `backend` — addresses of **keys**, not contracts |
| `[contracts]` | output | `bank`, `registry`, `wallet_factory`, `notary_registry`, `x_zk_verifier`, `google_oidc_verifier` |
| `[identity]` | output | `identity_names`, `github_identity_verifier`, `x_identity_verifier`, `google_identity_verifier`, `identity_jwks_roots` |
| `[platforms]` | input | `x_client_id`, `google_client_id`, `github_bot_handle`, `x_bot_handle` |
| `[[tokens]]` | input | `symbol`, `address` (zero address = native) |
| `[templates]` | input | per-platform comment templates (string or array), keyed by platform domain |

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
  verifier only when `oidc_notary` and `google_client_id` are set and the
  slot is zero. A changed client id is **not** applied to an
  already-deployed verifier — that is what `--upgrade oidc-verifier` is
  for.

## Running locally

```sh
# parse + sanity checks (add --check-rpc to also probe the endpoint)
cargo run -- validate --network networks/eden-testnet.toml

# read-only diff against the chain; --json for machine output
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

Upgrade components: `registry`, `wallet-factory`, `notary-registry` (UUPS
`upgradeToAndCall`), `bank` (diamond facet REPLACE — the diamond is the
storage, the facets are the code), `oidc-verifier` (redeploy + re-point;
new address, recorded in the PR).

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

## One-time setup

1. **AWS**: create the deployer KMS key (`ECC_SECG_P256K1`, `SIGN_VERIFY`)
   and an IAM role trusted by GitHub's OIDC provider for this repository,
   with `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` on that key.
2. **Secrets**: set `AWS_DEPLOYER_ROLE_ARN` (repository or environment
   secret).
3. **Environments**: create a GitHub environment per network (e.g.
   `eden-testnet`, later `mainnet`) and add required reviewers on
   production ones.
4. **Fund** the KMS key's derived address with native gas token.
5. **New network**: copy `networks/mainnet.toml.example`, fill the input
   keys, add the name to the `network` choice list in `apply.yml`, and run
   the workflow with `mode: plan` first.

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
- `cargo test` — the integration tests need `anvil` on PATH and cover the
  critical cycle: empty file → fresh apply → file rewritten → second apply
  is a no-op.
- Every commit must be signed off (`git commit -s`); see CONTRIBUTING.md.
