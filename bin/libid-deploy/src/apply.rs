//! Converge a chain onto the network file: deploy whatever the CHAIN lacks
//! (in dependency order), re-send the idempotent configuration ops, and
//! perform any explicitly requested upgrades.
//!
//! The file pre-declares every canonical address (validated to equal
//! `predict_address(factory, name)` at load), so apply reads presence from
//! chain state (`eth_getCode` at the declared address / the factory's
//! `deployedAt` record) and NEVER rewrites the file — after an apply the
//! config is byte-identical to before it.
//!
//! The flow is FACTORY-FIRST: step 0 makes sure the keyless CREATE2
//! deployer and the deterministic `LibidFactory` exist (installing them
//! where missing), verifies the factory sits at exactly its predicted
//! canonical address (the CANARY — a mismatch means the chain derives
//! CREATE2 addresses differently and the run aborts), and then every entry
//! contract deploys THROUGH the factory via CREATE3 under its canonical
//! name from [`crate::names`], so its address is a pure function of the
//! name — identical on every network. Implementations stay plain CREATE
//! deploys: their addresses are referenced by a proxy slot, not canonical,
//! and upgrades replace them without moving any entry address.
//!
//! The stack order is `script/Deploy.s.sol`'s: the Notary Service every
//! notarized session is authenticated through, the Proof Verifier the
//! naming system dispatches claims through, the naming system itself with
//! a keyspace per platform, and the Google JWT root list that pays the
//! Notary Service for each rotation.

use std::path::Path;

use alloy::{
    network::TransactionBuilder,
    primitives::{
        Address,
        Bytes,
    },
    providers::{
        Provider,
        ProviderBuilder,
    },
    rpc::types::TransactionRequest,
    sol_types::{
        SolCall,
        SolValue,
    },
};
use anyhow::{
    anyhow,
    bail,
    Context,
    Result,
};
use libid_contracts::{
    bindings::{
        ceremony::{
            CeremonyProofVerifier,
            GoogleJwtRoots,
            NotaryService,
        },
        factory::LibidFactory,
        identity::IdentityNames,
    },
    deploy::{
        deploy_contract_from,
        upgrade_uups,
    },
    factory::{
        ensure_create2_deployer,
        ensure_factory,
        predict_address,
        predict_factory_address,
    },
    send_with_nonce_retry,
    Artifacts,
};
use tracing::{
    info,
    warn,
};

use crate::{
    config::{
        required_address,
        NetworkConfig,
    },
    names,
    platforms,
    signer::SignerSource,
};

/// A component an operator can explicitly upgrade. Every one is a UUPS
/// proxy: the implementation is replaced and the entry address, its
/// storage and its owner all survive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upgrade {
    /// The Notary Service — the trusted key set and the fee survive.
    NotaryService,
    /// The Proof Verifier — the Supported Version Set survives.
    ProofVerifier,
    /// The naming system — every binding and keyspace survives.
    IdentityNames,
    /// The Google JWT root list — both key generations survive.
    GoogleJwtRoots,
}

impl Upgrade {
    /// The proxy's `[contracts]` key.
    fn contracts_key(self) -> &'static str {
        match self {
            Self::NotaryService => "notary_service",
            Self::ProofVerifier => "ceremony_proof_verifier",
            Self::IdentityNames => "identity_names",
            Self::GoogleJwtRoots => "google_jwt_roots",
        }
    }

    /// The compiled contract whose implementation is redeployed.
    fn contract(self) -> &'static str {
        match self {
            Self::NotaryService => "NotaryService",
            Self::ProofVerifier => "CeremonyProofVerifier",
            Self::IdentityNames => "IdentityNames",
            Self::GoogleJwtRoots => "GoogleJwtRoots",
        }
    }

    /// Every value `--upgrade` accepts, for the CLI help and the error.
    pub const VALUES: &'static [&'static str] = &[
        "notary-service",
        "proof-verifier",
        "identity-names",
        "google-jwt-roots",
    ];
}

impl std::str::FromStr for Upgrade {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "notary-service" => Ok(Self::NotaryService),
            "proof-verifier" => Ok(Self::ProofVerifier),
            "identity-names" => Ok(Self::IdentityNames),
            "google-jwt-roots" => Ok(Self::GoogleJwtRoots),
            other => bail!(
                "unknown upgrade component '{other}' (expected {})",
                Self::VALUES.join(", ")
            ),
        }
    }
}

/// Options for [`run`].
#[derive(Debug, Default)]
pub struct Options {
    /// Components to explicitly upgrade.
    pub upgrades: Vec<Upgrade>,
    /// Required when the FACTORY has no code on-chain (a virgin network):
    /// that first apply publishes the entire declared stack. With the
    /// factory present, apply converges incrementally without the flag.
    pub confirm_fresh_deploy: bool,
    /// Dev-chain mode: allow taking factory ownership from the baked
    /// genesis admin via impersonation. Impersonation only ever happens
    /// when `web3_clientVersion` ALSO reports anvil/hardhat — this flag on
    /// a real chain is a hard error, never a fallback.
    pub dev: bool,
}

/// What an apply run did. The network file is declarative and NEVER
/// rewritten, so there is nothing to report about it: every deployed
/// component landed at exactly the address the file already declares.
#[derive(Debug, Default)]
pub struct Summary {
    /// Freshly deployed components, as `(component, address)`.
    pub deployed: Vec<(String, Address)>,
    /// Explicitly upgraded components.
    pub upgraded: Vec<String>,
    /// On-chain configuration changes beyond the always-resent idempotent
    /// ops — signer and fee convergence, wiring, ownership handovers.
    pub configured: Vec<String>,
}

impl Summary {
    /// Render for humans / the CI step summary.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        if self.deployed.is_empty() {
            let _ = writeln!(out, "Deployed: none");
        } else {
            let _ =
                writeln!(out, "Deployed (all at their declared canonical addresses):");
            for (component, addr) in &self.deployed {
                let _ = writeln!(out, "  {component} = {addr:#x}");
            }
        }
        if self.upgraded.is_empty() {
            let _ = writeln!(out, "Upgraded: none");
        } else {
            let _ = writeln!(out, "Upgraded: {}", self.upgraded.join(", "));
        }
        if !self.configured.is_empty() {
            let _ = writeln!(out, "Configured: {}", self.configured.join(", "));
        }
        let _ = writeln!(out, "Config: declarative — never rewritten");
        out
    }
}

/// Run the apply: converge the chain onto the declared state. The file is
/// never rewritten.
pub async fn run(
    path: &Path,
    cfg: &NetworkConfig,
    signer: &SignerSource,
    opts: &Options,
) -> Result<Summary> {
    let rpc_url: url::Url = cfg
        .network
        .rpc_url
        .parse()
        .map_err(|e| anyhow!("invalid RPC URL: {e}"))?;

    let (wallet, sender) = signer.build_wallet(None).await?;
    info!("applying as {sender:#x} via {}", signer.describe());
    let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc_url);

    let chain_id = provider
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to read the chain id: {e}"))?;
    if chain_id != cfg.network.chain_id {
        bail!(
            "chain id mismatch: {} expects {}, the RPC reports {chain_id} — refusing \
             to send anything",
            cfg.network.name,
            cfg.network.chain_id
        );
    }

    let artifacts = Artifacts::embedded();
    let notary_signer = required_address(&cfg.accounts.notary, "accounts.notary")?;
    let notary_fee = cfg.notary_service.fee()?;
    // The operational owner the factory should END up with; defaults to
    // the deployer (on real networks the KMS genesis admin IS the deployer).
    let operational_owner = cfg.accounts.owner_address()?.unwrap_or(sender);

    let mut summary = Summary::default();

    // ── Step 0: the deterministic-deployment substrate ────────────────────
    // The keyless CREATE2 deployer and the LibidFactory are the hard
    // onboarding gate: a chain that cannot host them cannot host the stack.
    let predicted_factory = predict_factory_address(&artifacts)?;
    let factory_was_present = code_present(&provider, predicted_factory).await?;

    // The fresh-deploy guard keys on CHAIN STATE, not config emptiness: a
    // factory with no code means a virgin network, and this apply would
    // publish the entire declared stack.
    if !factory_was_present && !opts.confirm_fresh_deploy {
        bail!(
            "the LibidFactory has no code at its canonical address \
             {predicted_factory:#x} on '{}' — this chain is VIRGIN, so this apply \
             would be a FRESH DEPLOY of the whole stack declared in {}. Re-run \
             with --confirm-fresh-deploy if the network is genuinely new; once \
             the factory exists, apply converges incrementally without the flag.",
            cfg.network.name,
            path.display()
        );
    }

    ensure_create2_deployer(&provider)
        .await
        .context("the canonical CREATE2 deployer is the onboarding gate")?;
    let libid_factory = ensure_factory(&provider, &artifacts).await?;

    // CANARY: after any install the factory must sit at exactly the
    // predicted address. A mismatch (or missing code) means the chain does
    // not derive CREATE2 addresses the standard way — every "deterministic"
    // address downstream would be wrong, so abort before sending anything.
    if libid_factory != predicted_factory
        || !code_present(&provider, predicted_factory).await?
    {
        bail!(
            "FACTORY CANARY FAILED: the LibidFactory is not at its canonical \
             predicted address {predicted_factory:#x} (got {libid_factory:#x}). \
             This chain does not derive CREATE2 addresses the standard way \
             (zkSync-Era-style derivation?), so cross-network address parity is \
             impossible here — refusing to proceed."
        );
    }
    if !factory_was_present {
        info!("LibidFactory installed at its canonical address {libid_factory:#x}");
        summary
            .deployed
            .push(("contracts.factory".into(), libid_factory));
    }

    // ── Presence: what does the CHAIN have, of what the file declares? ───
    // Deployed-vs-not is read from chain state at the declared (canonical,
    // validated) addresses — config emptiness no longer means anything.
    let notary_service =
        required_address(&cfg.contracts.notary_service, "contracts.notary_service")?;
    let proof_verifier = required_address(
        &cfg.contracts.ceremony_proof_verifier,
        "contracts.ceremony_proof_verifier",
    )?;
    let identity_names =
        required_address(&cfg.contracts.identity_names, "contracts.identity_names")?;
    let jwt_roots = required_address(
        &cfg.contracts.google_jwt_roots,
        "contracts.google_jwt_roots",
    )?;

    let notary_service_present = code_present(&provider, notary_service).await?;
    let proof_verifier_present = code_present(&provider, proof_verifier).await?;
    let identity_names_present = code_present(&provider, identity_names).await?;
    let jwt_roots_present = code_present(&provider, jwt_roots).await?;

    // Does anything need `factory.deploy` (owner-gated)? Only then must the
    // apply signer own the factory. On real networks the signer IS the KMS
    // genesis owner; on dev chains ownership is impersonation-transferred.
    if !(notary_service_present
        && proof_verifier_present
        && identity_names_present
        && jwt_roots_present)
    {
        ensure_factory_ownership(&provider, libid_factory, sender, opts.dev).await?;
    }

    // ── 1. The Notary Service: everything else takes its proxy address ───
    if !notary_service_present {
        let addr = deploy_named_proxy(
            &provider,
            &artifacts,
            libid_factory,
            names::NOTARY_SERVICE,
            "NotaryService",
            &NotaryService::initializeCall {
                owner_: sender,
                notary_: notary_signer,
                fee_: notary_fee,
            },
            sender,
        )
        .await?;
        info!(
            "NotaryService proxy deployed at {addr:#x} ({})",
            names::NOTARY_SERVICE
        );
        debug_assert_eq!(addr, notary_service);
        summary
            .deployed
            .push(("contracts.notary_service".into(), addr));
    }

    // Declarative key trust: the file says which signer the stack accepts.
    // Only the ADDITION is inferable — the service holds a SET so a
    // rotation can overlap, and which outgoing key to stop trusting is a
    // decision the file does not carry.
    let service = NotaryService::new(notary_service, &provider);
    let trusted = service
        .isTrustedNotary(notary_signer)
        .call()
        .await
        .map_err(|e| anyhow!("NotaryService.isTrustedNotary read failed: {e}"))?;
    if !trusted {
        send_with_nonce_retry!(
            service.setNotary(notary_signer, true),
            "NotaryService.setNotary",
            &provider,
            sender
        )?;
        info!("notary key {notary_signer:#x} is now trusted");
        summary
            .configured
            .push(format!("notary key {notary_signer:#x} trusted"));
    }

    let on_chain_fee = service
        .fee()
        .call()
        .await
        .map_err(|e| anyhow!("NotaryService.fee read failed: {e}"))?;
    if on_chain_fee != notary_fee {
        send_with_nonce_retry!(
            service.setFee(notary_fee),
            "NotaryService.setFee",
            &provider,
            sender
        )?;
        info!("notary fee set: {on_chain_fee} -> {notary_fee} wei");
        summary
            .configured
            .push(format!("notary fee {on_chain_fee} -> {notary_fee} wei"));
    }

    // ── 2. The Proof Verifier the naming system dispatches through ───────
    if !proof_verifier_present {
        let addr = deploy_named_proxy(
            &provider,
            &artifacts,
            libid_factory,
            names::CEREMONY_PROOF_VERIFIER,
            "CeremonyProofVerifier",
            &CeremonyProofVerifier::initializeCall { owner_: sender },
            sender,
        )
        .await?;
        info!(
            "CeremonyProofVerifier proxy deployed at {addr:#x} ({})",
            names::CEREMONY_PROOF_VERIFIER
        );
        debug_assert_eq!(addr, proof_verifier);
        summary
            .deployed
            .push(("contracts.ceremony_proof_verifier".into(), addr));
    }

    // ── 3. The naming system, with a keyspace per platform ───────────────
    if !identity_names_present {
        let addr = deploy_named_proxy(
            &provider,
            &artifacts,
            libid_factory,
            names::IDENTITY_NAMES,
            "IdentityNames",
            &IdentityNames::initializeCall { owner_: sender },
            sender,
        )
        .await?;
        info!(
            "IdentityNames proxy deployed at {addr:#x} ({})",
            names::IDENTITY_NAMES
        );
        debug_assert_eq!(addr, identity_names);
        summary
            .deployed
            .push(("contracts.identity_names".into(), addr));
    }

    let names_contract = IdentityNames::new(identity_names, &provider);
    let wired = names_contract
        .proofVerifier()
        .call()
        .await
        .map_err(|e| anyhow!("IdentityNames.proofVerifier read failed: {e}"))?;
    if wired != proof_verifier {
        send_with_nonce_retry!(
            names_contract.setProofVerifier(proof_verifier),
            "IdentityNames.setProofVerifier",
            &provider,
            sender
        )?;
        info!("IdentityNames dispatches through {proof_verifier:#x}");
        summary.configured.push(format!(
            "identity names -> proof verifier {proof_verifier:#x}"
        ));
    }

    // A keyspace per platform. Re-sent every run: the contract exposes no
    // getter for a platform's rules, so writing them is the only way to
    // converge on what the generated table says. The call is owner-only and
    // idempotent.
    for platform in platforms::LAUNCH {
        let platform_id = platforms::platform_id(platform.domain);
        send_with_nonce_retry!(
            names_contract.setPlatform(platform_id, platform.rules.clone()),
            format!("IdentityNames.setPlatform({})", platform.label),
            &provider,
            sender
        )?;
        info!(
            "keyspace configured for {} ({platform_id:#x})",
            platform.label
        );
    }

    // ── 4. The Google JWT root list, beside the verifier it serves ───────
    if !jwt_roots_present {
        let addr = deploy_named_proxy(
            &provider,
            &artifacts,
            libid_factory,
            names::GOOGLE_JWT_ROOTS,
            "GoogleJwtRoots",
            &GoogleJwtRoots::initializeCall {
                owner_: sender,
                notary_: notary_service,
            },
            sender,
        )
        .await?;
        info!(
            "GoogleJwtRoots proxy deployed at {addr:#x} ({}) — the trust list starts \
             EMPTY; point a keeper at it before Google names work",
            names::GOOGLE_JWT_ROOTS
        );
        debug_assert_eq!(addr, jwt_roots);
        summary
            .deployed
            .push(("contracts.google_jwt_roots".into(), addr));
    }

    let roots = GoogleJwtRoots::new(jwt_roots, &provider);
    let roots_notary = roots
        .notaryService()
        .call()
        .await
        .map_err(|e| anyhow!("GoogleJwtRoots.notaryService read failed: {e}"))?;
    if roots_notary != notary_service {
        send_with_nonce_retry!(
            roots.setNotaryService(notary_service),
            "GoogleJwtRoots.setNotaryService",
            &provider,
            sender
        )?;
        info!("GoogleJwtRoots verifies through {notary_service:#x}");
        summary
            .configured
            .push(format!("jwt roots -> notary service {notary_service:#x}"));
    }

    // ── Explicit upgrades ────────────────────────────────────────────────
    for upgrade in &opts.upgrades {
        let key = upgrade.contracts_key();
        let proxy = required_address(
            cfg.contracts
                .raw(key)
                .ok_or_else(|| anyhow!("{key} is not a canonical contract"))?,
            &format!("contracts.{key}"),
        )?;
        let new_impl = upgrade_uups(
            &provider,
            &artifacts,
            proxy,
            upgrade.contract(),
            Bytes::new(),
            Some(sender),
        )
        .await?;
        info!(
            "{} upgraded: proxy {proxy:#x} now points at {new_impl:#x}",
            upgrade.contract()
        );
        summary
            .upgraded
            .push(format!("{} -> {new_impl:#x}", upgrade.contract()));
    }

    // ── Factory ownership converges to the declared operational owner ────
    converge_factory_owner(
        &provider,
        libid_factory,
        sender,
        operational_owner,
        &mut summary,
    )
    .await?;

    // Nothing is recorded back: the file already declares every canonical
    // address and the chain records the rest.
    Ok(summary)
}

/// Whether `addr` has code on-chain — the declarative presence check.
async fn code_present<P: Provider>(provider: &P, addr: Address) -> Result<bool> {
    Ok(!provider
        .get_code_at(addr)
        .await
        .map_err(|e| anyhow!("get_code({addr:#x}) failed: {e}"))?
        .is_empty())
}

/// Hand the factory over to the declared `[accounts].owner` (default: the
/// deployer). Ownable2Step: from the sender this INITIATES the handover;
/// on a dev chain (anvil/hardhat) the acceptance is completed by
/// impersonating the new owner, so local stacks end fully converged.
async fn converge_factory_owner<P: Provider>(
    provider: &P,
    factory: Address,
    sender: Address,
    desired: Address,
    summary: &mut Summary,
) -> Result<()> {
    let contract = LibidFactory::new(factory, provider);
    let current = contract
        .owner()
        .call()
        .await
        .map_err(|e| anyhow!("LibidFactory.owner read failed: {e}"))?;
    if current == desired {
        return Ok(());
    }
    if current != sender {
        // Nothing this signer can do; say so instead of failing the whole
        // apply after the chain already converged.
        warn!(
            "factory owner is {current:#x}, not the apply signer {sender:#x} — \
             cannot hand ownership to accounts.owner {desired:#x}"
        );
        summary.configured.push(format!(
            "factory ownership NOT converged: owned by {current:#x}, wanted \
             {desired:#x}"
        ));
        return Ok(());
    }

    let pending = contract
        .pendingOwner()
        .call()
        .await
        .map_err(|e| anyhow!("LibidFactory.pendingOwner read failed: {e}"))?;
    if pending != desired {
        send_with_nonce_retry!(
            contract.transferOwnership(desired),
            "LibidFactory.transferOwnership",
            provider,
            sender
        )?;
        info!("factory ownership handover initiated: {sender:#x} -> {desired:#x}");
    }

    let (is_dev, _) = detect_dev_client(provider).await?;
    if is_dev {
        // Complete the two-step locally: impersonate the operational owner
        // (e.g. the anvil #0 wallet) and accept.
        provider
            .raw_request::<_, serde_json::Value>(
                "anvil_setBalance".into(),
                (desired, "0xde0b6b3a7640000"),
            )
            .await
            .map_err(|e| anyhow!("anvil_setBalance failed: {e}"))?;
        provider
            .raw_request::<_, serde_json::Value>(
                "anvil_impersonateAccount".into(),
                (desired,),
            )
            .await
            .map_err(|e| anyhow!("anvil_impersonateAccount failed: {e}"))?;
        let accept = LibidFactory::acceptOwnershipCall {}.abi_encode();
        provider
            .raw_request::<_, serde_json::Value>(
                "eth_sendTransaction".into(),
                (serde_json::json!({
                    "from": desired,
                    "to": factory,
                    "data": Bytes::from(accept),
                }),),
            )
            .await
            .map_err(|e| anyhow!("impersonated acceptOwnership failed: {e}"))?;
        provider
            .raw_request::<_, serde_json::Value>(
                "anvil_stopImpersonatingAccount".into(),
                (desired,),
            )
            .await
            .map_err(|e| anyhow!("anvil_stopImpersonatingAccount failed: {e}"))?;
        info!("factory ownership converged (dev): {sender:#x} -> {desired:#x}");
        summary.configured.push(format!(
            "factory ownership transferred to accounts.owner {desired:#x} (dev)"
        ));
    } else {
        summary.configured.push(format!(
            "factory ownership handover to accounts.owner {desired:#x} initiated — \
             pending acceptOwnership by that key"
        ));
    }
    Ok(())
}

/// Whether the RPC's `web3_clientVersion` reports a dev chain (anvil or
/// hardhat). Returns the raw version string for error messages.
async fn detect_dev_client<P: Provider>(provider: &P) -> Result<(bool, String)> {
    let version: String = provider
        .raw_request("web3_clientVersion".into(), ())
        .await
        .map_err(|e| anyhow!("web3_clientVersion failed: {e}"))?;
    let lower = version.to_lowercase();
    let is_dev = lower.contains("anvil") || lower.contains("hardhat");
    Ok((is_dev, version))
}

/// Make sure the apply signer owns the factory (its `deploy` is
/// owner-gated).
///
/// - Signer already the owner: nothing to do.
/// - Signer is the pending owner (an interrupted Ownable2Step handover):
///   `acceptOwnership`.
/// - Otherwise, ONLY on a dev chain (anvil/hardhat, confirmed via
///   `web3_clientVersion` regardless of the `--dev` flag): impersonate the
///   current owner (the baked genesis admin nobody holds a dev key for) and
///   Ownable2Step-transfer ownership to the signer. On any other chain this
///   is a hard error: the apply signer must BE the factory owner — the
///   libID deployer KMS key.
async fn ensure_factory_ownership<P: Provider>(
    provider: &P,
    factory: Address,
    sender: Address,
    dev_requested: bool,
) -> Result<()> {
    let contract = LibidFactory::new(factory, provider);
    let owner = contract
        .owner()
        .call()
        .await
        .map_err(|e| anyhow!("LibidFactory.owner read failed: {e}"))?;
    if owner == sender {
        return Ok(());
    }
    let pending = contract
        .pendingOwner()
        .call()
        .await
        .map_err(|e| anyhow!("LibidFactory.pendingOwner read failed: {e}"))?;
    if pending == sender {
        send_with_nonce_retry!(
            contract.acceptOwnership(),
            "LibidFactory.acceptOwnership",
            provider,
            sender
        )?;
        info!("factory ownership accepted: {owner:#x} -> {sender:#x}");
        return Ok(());
    }

    let (is_dev, version) = detect_dev_client(provider).await?;
    if !is_dev {
        if dev_requested {
            bail!(
                "--dev was passed but the RPC client is '{version}', not \
                 anvil/hardhat — refusing to impersonate the factory owner on \
                 what looks like a real chain"
            );
        }
        bail!(
            "the factory at {factory:#x} is owned by {owner:#x} but apply signs \
             as {sender:#x}. factory.deploy is owner-gated: on real networks the \
             apply signer must BE the factory owner (the libID deployer KMS \
             key). Impersonation is only available on dev chains (anvil/hardhat)."
        );
    }

    // Dev chain: impersonate the current owner and hand ownership over,
    // exactly the pattern libid-contracts' own anvil test uses.
    info!(
        "dev chain ({version}): impersonating the factory owner {owner:#x} to \
         transfer ownership to {sender:#x}"
    );
    provider
        .raw_request::<_, serde_json::Value>(
            "anvil_setBalance".into(),
            (owner, "0xde0b6b3a7640000"),
        )
        .await
        .map_err(|e| anyhow!("anvil_setBalance failed: {e}"))?;
    provider
        .raw_request::<_, serde_json::Value>("anvil_impersonateAccount".into(), (owner,))
        .await
        .map_err(|e| anyhow!("anvil_impersonateAccount failed: {e}"))?;
    let transfer = LibidFactory::transferOwnershipCall { newOwner: sender }.abi_encode();
    provider
        .raw_request::<_, serde_json::Value>(
            "eth_sendTransaction".into(),
            (serde_json::json!({
                "from": owner,
                "to": factory,
                "data": Bytes::from(transfer),
            }),),
        )
        .await
        .map_err(|e| anyhow!("impersonated transferOwnership failed: {e}"))?;
    provider
        .raw_request::<_, serde_json::Value>(
            "anvil_stopImpersonatingAccount".into(),
            (owner,),
        )
        .await
        .map_err(|e| anyhow!("anvil_stopImpersonatingAccount failed: {e}"))?;
    send_with_nonce_retry!(
        contract.acceptOwnership(),
        "LibidFactory.acceptOwnership",
        provider,
        sender
    )?;
    info!("factory ownership transferred (dev): {owner:#x} -> {sender:#x}");
    Ok(())
}

/// CREATE3-deploy `creation_code` under `name` through the factory, with an
/// explicit chain-fetched nonce (the rest of the apply flow manages nonces
/// explicitly, so the provider's cached filler cannot be trusted here).
/// Idempotent: a name the factory already deployed returns its recorded
/// address without sending anything — that is how a partially-failed apply
/// converges instead of tripping on the single-use name.
///
/// The returned address is verified to equal `predict_address(factory,
/// name)` — the whole point of the exercise.
pub(crate) async fn factory_deploy_named<P: Provider>(
    provider: &P,
    factory: Address,
    name: &str,
    creation_code: Bytes,
    sender: Address,
) -> Result<Address> {
    let contract = LibidFactory::new(factory, provider);
    let predicted = predict_address(factory, name);

    let existing = contract
        .deployedAt(name.to_string())
        .call()
        .await
        .map_err(|e| anyhow!("factory deployedAt({name}) read failed: {e}"))?;
    if existing != Address::ZERO {
        info!("{name} already deployed by the factory at {existing:#x} — reusing");
        if existing != predicted {
            bail!(
                "factory record for {name} is {existing:#x} but predict says \
                 {predicted:#x} — the deterministic invariant is broken"
            );
        }
        return Ok(existing);
    }

    // `deploy` is sent as raw calldata: alloy's `sol!` reserves the `deploy`
    // method name on generated contract instances.
    let call = LibidFactory::deployCall {
        name: name.to_string(),
        creationCode: creation_code,
    };
    let nonce = provider
        .get_transaction_count(sender)
        .await
        .map_err(|e| anyhow!("factory deploy of {name} failed to fetch nonce: {e}"))?;
    let tx = TransactionRequest::default()
        .with_to(factory)
        .with_input(Bytes::from(call.abi_encode()))
        .with_nonce(nonce);
    let pending = provider
        .send_transaction(tx)
        .await
        .map_err(|e| anyhow!("factory deploy of {name} send failed: {e}"))?;
    pending
        .get_receipt()
        .await
        .map_err(|e| anyhow!("factory deploy of {name} confirmation failed: {e}"))?;

    let deployed = contract
        .deployedAt(name.to_string())
        .call()
        .await
        .map_err(|e| anyhow!("factory deployedAt({name}) re-read failed: {e}"))?;
    if deployed != predicted {
        bail!(
            "factory deployed {name} at {deployed:#x} but predict says \
             {predicted:#x} — the deterministic invariant is broken"
        );
    }
    Ok(deployed)
}

/// Deploy `contract`'s implementation via plain CREATE (its address is
/// referenced, not canonical), then CREATE3-deploy an ERC1967 proxy for it
/// under `name` through the factory. The named-proxy shape of every UUPS
/// entry contract.
#[allow(clippy::too_many_arguments)]
async fn deploy_named_proxy<P: Provider, C: SolCall>(
    provider: &P,
    artifacts: &Artifacts,
    factory: Address,
    name: &str,
    contract: &str,
    init_call: &C,
    sender: Address,
) -> Result<Address> {
    // Reuse before paying for an implementation nobody will point at.
    let record = LibidFactory::new(factory, provider)
        .deployedAt(name.to_string())
        .call()
        .await
        .map_err(|e| anyhow!("factory deployedAt({name}) read failed: {e}"))?;
    if record != Address::ZERO {
        return factory_deploy_named(provider, factory, name, Bytes::new(), sender).await;
    }

    let implementation = deploy_contract_from(
        provider,
        artifacts.bytecode(contract)?,
        &format!("{contract} (impl)"),
        Some(sender),
    )
    .await?;
    let creation_code = proxy_creation_code(artifacts, implementation, init_call)?;
    factory_deploy_named(provider, factory, name, creation_code, sender).await
}

/// ERC1967Proxy creation code ++ `abi.encode(implementation, initData)` —
/// the bytes a CREATE3 name is deployed from.
pub(crate) fn proxy_creation_code<C: SolCall>(
    artifacts: &Artifacts,
    implementation: Address,
    init_call: &C,
) -> Result<Bytes> {
    let mut code = artifacts.bytecode("ERC1967Proxy")?.to_vec();
    code.extend_from_slice(
        &(implementation, Bytes::from(init_call.abi_encode())).abi_encode_params(),
    );
    Ok(code.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `--upgrade` value round-trips, and each names a canonical
    /// contract the config actually declares.
    #[test]
    fn every_upgrade_value_parses_and_names_a_canonical_proxy() {
        for value in Upgrade::VALUES {
            let upgrade: Upgrade = value.parse().expect("value parses");
            assert!(
                names::canonical_name(upgrade.contracts_key()).is_some(),
                "{value} names no canonical contract"
            );
        }
    }

    /// An unknown component lists the ones that exist rather than failing
    /// bare. `notary` is the name the Notary Service used to answer to, so
    /// a stale runbook fails loudly instead of upgrading nothing.
    #[test]
    fn an_unknown_upgrade_value_lists_the_known_ones() {
        let err = "notary".parse::<Upgrade>().unwrap_err().to_string();
        assert!(err.contains("notary-service"), "got: {err}");
        assert!(err.contains("identity-names"), "got: {err}");
    }
}
