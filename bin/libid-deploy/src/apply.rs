//! Converge a chain onto the network file: deploy whatever the CHAIN lacks
//! (in dependency order), re-send the idempotent configuration ops, and
//! perform any explicitly requested upgrades.
//!
//! DECLARATIVE (0.4.0): the file pre-declares every canonical address
//! (validated to equal `predict_address(factory, name)` at load), so apply
//! reads presence from chain state (`eth_getCode` at the declared address /
//! the factory's `deployedAt` record) and NEVER rewrites the file — after
//! an apply the config is byte-identical to before it. The one address that
//! can legitimately diverge from its declaration, a REPLACED
//! GoogleOidcVerifier, is recorded on-chain only (`Registry.oidcVerifierOf`
//! is the record). Legacy files (`network.legacy_addresses`) are refused.
//!
//! The orchestration order is ported from dyaka's deployers:
//! `dyaka-auth::deploy::run` (login stack), `dyaka-transfer::deploy`
//! (Bank diamond + reconcile), and `dyaka-identity::deploy::run` (the
//! identity-names stack, only when `[identity]` is present) — with one
//! 0.2.0 addition in front: the shared Notary contract deploys FIRST,
//! because every other contract takes its proxy address at initialize.
//!
//! Since libid-contracts 0.3.0 the flow is FACTORY-FIRST: step 0 makes sure
//! the keyless CREATE2 deployer and the deterministic `LibidFactory` exist
//! (installing them where missing), verifies the factory sits at exactly
//! its predicted canonical address (the CANARY — a mismatch means the chain
//! derives CREATE2 addresses differently and the run aborts), and then
//! every top-level entry contract deploys THROUGH the factory via CREATE3
//! under its canonical name from [`crate::names`], so its address is a pure
//! function of the name — identical on every network. Implementations,
//! facets, and Honk verifiers stay plain CREATE deploys: their addresses
//! are referenced, not canonical, and upgrades replace them without moving
//! any entry address.

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
        factory::LibidFactory,
        identity::{
            GitHubIdentityVerifier,
            GoogleIdentityVerifier,
            IdentityJwksRoots,
            IdentityNames,
            XIdentityVerifier,
        },
        login::{
            IRegistryAdmin,
            Registry,
            WalletFactory,
            XZkVerifier,
        },
        notary::Notary,
        oidc::GoogleOidcVerifier,
        transfer::{
            Bank,
            BankInit,
            IDiamondCut,
        },
    },
    deploy::{
        deploy_behind_proxy,
        deploy_contract_from,
        upgrade_uups,
    },
    diamond::{
        facet_cut_action,
        replace_bank_facets,
        BANK_FACETS,
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
    platforms::{
        identity_platform_id,
        IdentityPlatform,
        GITHUB_SHAPE,
        GOOGLE_DOMAIN,
        IDENTITY_GITHUB,
        IDENTITY_GOOGLE,
        IDENTITY_X,
        PLATFORM_CONFIGS,
        WEB_PREFIXES,
        X_DOMAIN,
        X_ENDPOINT,
        X_HANDLE_PREFIX,
    },
    signer::SignerSource,
};

/// A component an operator can explicitly upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Upgrade {
    /// UUPS `upgradeToAndCall` on the Registry proxy.
    Registry,
    /// UUPS `upgradeToAndCall` on the WalletFactory proxy.
    WalletFactory,
    /// UUPS `upgradeToAndCall` on the shared Notary proxy. State (the
    /// stored notary signer) lives in the proxy and survives the upgrade.
    Notary,
    /// Diamond facet REPLACE on the Bank — there is no implementation slot;
    /// the diamond is the storage, the facets are the code.
    Bank,
    /// Redeploy + re-point: the GoogleOidcVerifier is replaced and its
    /// ADDRESS CHANGES. The new address is recorded on-chain only —
    /// `Registry.oidcVerifierOf` is the record; the config keeps declaring
    /// the canonical first-deploy address.
    OidcVerifier,
}

impl std::str::FromStr for Upgrade {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.trim() {
            "registry" => Ok(Self::Registry),
            "wallet-factory" => Ok(Self::WalletFactory),
            "notary" => Ok(Self::Notary),
            "bank" => Ok(Self::Bank),
            "oidc-verifier" => Ok(Self::OidcVerifier),
            other => bail!(
                "unknown upgrade component '{other}' (expected registry, \
                 wallet-factory, notary, bank, oidc-verifier)"
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
    /// ops — the Notary signer rotation and factory ownership handovers.
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
    if cfg.network.legacy_addresses {
        bail!(
            "{} records a LEGACY (pre-factory) deployment \
             (network.legacy_addresses = true); apply only supports the canonical \
             declarative schema. The planned fresh redeploy replaces legacy stacks \
             — see the file header.",
            path.display()
        );
    }

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
    let backend = required_address(&cfg.accounts.backend, "accounts.backend")?;
    // The operational owner the factory should END up with; defaults to
    // the deployer (on real networks the KMS genesis admin IS the deployer).
    let operational_owner = cfg.accounts.owner_address()?.unwrap_or(sender);

    let mut summary = Summary::default();

    // ── Step 0: the deterministic-deployment substrate ────────────────────
    // The keyless CREATE2 deployer and the LibidFactory are the hard
    // onboarding gate: a chain that cannot host them cannot host the stack.
    let predicted_factory = predict_factory_address(&artifacts)?;
    let factory_was_present = !provider
        .get_code_at(predicted_factory)
        .await
        .map_err(|e| anyhow!("failed to read code at the factory address: {e}"))?
        .is_empty();

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
        || provider
            .get_code_at(predicted_factory)
            .await
            .map_err(|e| anyhow!("factory canary code read failed: {e}"))?
            .is_empty()
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
    let notary_contract = required_address(&cfg.contracts.notary, "contracts.notary")?;
    let wallet_factory_declared =
        required_address(&cfg.contracts.wallet_factory, "contracts.wallet_factory")?;
    let registry_declared =
        required_address(&cfg.contracts.registry, "contracts.registry")?;
    let bank_declared = required_address(&cfg.contracts.bank, "contracts.bank")?;

    let notary_present = code_present(&provider, notary_contract).await?;
    let wallet_factory_present = code_present(&provider, wallet_factory_declared).await?;
    let registry_present = code_present(&provider, registry_declared).await?;
    let bank_present = code_present(&provider, bank_declared).await?;

    // Does anything need `factory.deploy` (owner-gated)? Only then must the
    // apply signer own the factory. On real networks the signer IS the KMS
    // genesis owner; on dev chains ownership is impersonation-transferred.
    let mut needs_factory_deploy =
        !(notary_present && wallet_factory_present && registry_present && bank_present);
    if !cfg.platforms.x_client_id.trim().is_empty() {
        let declared =
            required_address(&cfg.contracts.x_zk_verifier, "contracts.x_zk_verifier")?;
        needs_factory_deploy |= !code_present(&provider, declared).await?;
    }
    if !cfg.platforms.google_client_id.trim().is_empty() {
        let declared = required_address(
            &cfg.contracts.google_oidc_verifier,
            "contracts.google_oidc_verifier",
        )?;
        needs_factory_deploy |= !code_present(&provider, declared).await?;
    }
    // Identity wanted-ness is key presence, read via canonical_raw.
    for key in [
        "identity_names",
        "github_identity_verifier",
        "x_identity_verifier",
        "google_identity_verifier",
        "identity_jwks_roots",
    ] {
        if let Some(raw) = cfg.canonical_raw("identity", key) {
            let declared = required_address(raw, key)?;
            needs_factory_deploy |= !code_present(&provider, declared).await?;
        }
    }
    if needs_factory_deploy {
        ensure_factory_ownership(&provider, libid_factory, sender, opts.dev).await?;
    }

    // ── Notary FIRST: everything else takes its proxy at initialize ──────
    if !notary_present {
        let addr = deploy_named_proxy(
            &provider,
            &artifacts,
            libid_factory,
            names::NOTARY,
            "Notary",
            &Notary::initializeCall {
                owner_: sender,
                notary_: notary_signer,
            },
            sender,
        )
        .await?;
        info!("Notary proxy deployed at {addr:#x} ({})", names::NOTARY);
        debug_assert_eq!(addr, notary_contract);
        summary.deployed.push(("contracts.notary".into(), addr));
    }

    // Declarative signer rotation: the file says who the notary signer IS;
    // a differing on-chain signer is drift and `setNotary` converges it.
    let notary_views = Notary::new(notary_contract, &provider);
    let on_chain_signer = notary_views
        .notary()
        .call()
        .await
        .map_err(|e| anyhow!("Notary.notary read failed: {e}"))?;
    if on_chain_signer != notary_signer {
        send_with_nonce_retry!(
            notary_views.setNotary(notary_signer),
            "Notary.setNotary",
            &provider,
            sender
        )?;
        info!(
            "Notary signer rotated: {on_chain_signer:#x} -> {notary_signer:#x} \
             (one transaction; every consumer follows the Notary contract)"
        );
        summary.configured.push(format!(
            "notary signer rotated {on_chain_signer:#x} -> {notary_signer:#x}"
        ));
    }

    // ── Login stack ──────────────────────────────────────────────────────
    let factory = wallet_factory_declared;
    if !wallet_factory_present {
        let wallet_impl = deploy_contract_from(
            &provider,
            artifacts.bytecode("WebWallet")?,
            "WebWallet (impl)",
            Some(sender),
        )
        .await?;
        info!("WebWallet impl deployed at {wallet_impl:#x}");
        let addr = deploy_named_proxy(
            &provider,
            &artifacts,
            libid_factory,
            names::WALLET_FACTORY,
            "WalletFactory",
            &WalletFactory::initializeCall {
                owner_: sender,
                walletImpl_: wallet_impl,
                // The registry proxy may have no code yet; it is pointed in
                // below once it does.
                registry_: if registry_present {
                    registry_declared
                } else {
                    Address::ZERO
                },
            },
            sender,
        )
        .await?;
        info!("WalletFactory proxy deployed at {addr:#x}");
        debug_assert_eq!(addr, factory);
        summary
            .deployed
            .push(("contracts.wallet_factory".into(), addr));
    }

    let registry = registry_declared;
    if !registry_present {
        let addr = deploy_named_proxy(
            &provider,
            &artifacts,
            libid_factory,
            names::REGISTRY,
            "Registry",
            &IRegistryAdmin::initializeCall {
                _notaryContract: notary_contract,
                _backend: backend,
                _walletFactory: factory,
                _owner: sender,
            },
            sender,
        )
        .await?;
        info!("Registry proxy deployed at {addr:#x}");
        debug_assert_eq!(addr, registry);
        let factory_contract = WalletFactory::new(factory, &provider);
        send_with_nonce_retry!(
            factory_contract.setRegistry(addr),
            "WalletFactory.setRegistry",
            &provider,
            sender
        )?;
        summary.deployed.push(("contracts.registry".into(), addr));
    }

    // ── Bank diamond ─────────────────────────────────────────────────────
    let bank = bank_declared;
    if !bank_present {
        let addr = deploy_bank_diamond_via_factory(
            &provider,
            &artifacts,
            libid_factory,
            sender,
            notary_contract,
            backend,
            registry,
        )
        .await?;
        info!("Bank diamond deployed at {addr:#x}");
        debug_assert_eq!(addr, bank);
        summary.deployed.push(("contracts.bank".into(), addr));
    }

    // ── Verifiers (guarded: deploy only when the Registry slot is zero) ──
    let registry_views = Registry::new(registry, &provider);
    let admin = IRegistryAdmin::new(registry, &provider);

    let x_client_id = cfg.platforms.x_client_id.trim();
    if !x_client_id.is_empty() {
        let on_chain = registry_views
            .zkVerifierOf(X_DOMAIN.into())
            .call()
            .await
            .map_err(|e| anyhow!("Registry.zkVerifierOf({X_DOMAIN}) read failed: {e}"))?;
        if on_chain == Address::ZERO {
            // The verifier and the Registry share the ONE Notary contract,
            // so a signer rotation reaches both in a single setNotary.
            let addr = deploy_x_zk_verifier(
                &provider,
                &artifacts,
                libid_factory,
                sender,
                notary_contract,
                x_client_id,
            )
            .await?;
            send_with_nonce_retry!(
                admin.setZkVerifier(X_DOMAIN.into(), addr),
                "Registry.setZkVerifier(api.x.com)",
                &provider,
                sender
            )?;
            info!("Registry.setZkVerifier({X_DOMAIN}, {addr:#x}) done");
            summary
                .deployed
                .push(("contracts.x_zk_verifier".into(), addr));
        } else {
            // Idempotency guard: a nonzero verifier is never redeployed. A
            // CHANGED x_client_id is NOT applied — the deployed verifier
            // keeps the client id baked in at first deploy.
            info!("XZkVerifier already wired at {on_chain:#x} — nothing to do");
        }
    } else {
        warn!("platforms.x_client_id is empty — skipping the XZkVerifier");
    }

    let google_client_id = cfg.platforms.google_client_id.trim();
    let upgrade_oidc = opts.upgrades.contains(&Upgrade::OidcVerifier);
    if upgrade_oidc && google_client_id.is_empty() {
        // An explicit upgrade request that cannot be honoured must not fall
        // through to a silent no-op — that is the exact failure the flag
        // exists to fix.
        bail!(
            "--upgrade oidc-verifier needs platforms.google_client_id set: the \
             verifier is constructed with the JWT audience it enforces"
        );
    }
    if !google_client_id.is_empty() {
        let on_chain = registry_views
            .oidcVerifierOf(GOOGLE_DOMAIN.into())
            .call()
            .await
            .map_err(|e| {
                anyhow!("Registry.oidcVerifierOf({GOOGLE_DOMAIN}) read failed: {e}")
            })?;
        if on_chain == Address::ZERO || upgrade_oidc {
            if on_chain != Address::ZERO {
                info!(
                    "replacing GoogleOidcVerifier {on_chain:#x} — the new deployment \
                     gets a NEW address (plain CREATE: the canonical factory name is \
                     single-use); the old verifier stays on-chain but nothing points \
                     at it"
                );
            }
            // A REPLACE cannot go through the factory: the canonical name
            // was consumed by the first deploy, and the address is meant to
            // change anyway.
            let via_factory = (on_chain == Address::ZERO).then_some(libid_factory);
            let addr = deploy_oidc_verifier(
                &provider,
                &artifacts,
                via_factory,
                sender,
                notary_contract,
                google_client_id,
            )
            .await?;
            send_with_nonce_retry!(
                admin.setOidcVerifier(GOOGLE_DOMAIN.into(), addr),
                "Registry.setOidcVerifier(www.googleapis.com)",
                &provider,
                sender
            )?;
            info!("Registry.setOidcVerifier({GOOGLE_DOMAIN}, {addr:#x}) done");
            if on_chain != Address::ZERO {
                // The replacement's address is recorded ON-CHAIN ONLY: the
                // Registry pointer is the record, and the config keeps
                // declaring the canonical first-deploy address.
                summary
                    .upgraded
                    .push(format!("google_oidc_verifier (replaced -> {addr:#x})"));
            } else {
                summary
                    .deployed
                    .push(("contracts.google_oidc_verifier".into(), addr));
            }
        } else {
            info!("GoogleOidcVerifier already wired at {on_chain:#x} — nothing to do");
        }
    } else {
        warn!("platforms.google_client_id is empty — skipping the GoogleOidcVerifier");
    }

    // ── Explicit upgrades ────────────────────────────────────────────────
    for upgrade in &opts.upgrades {
        match upgrade {
            Upgrade::Registry => {
                upgrade_uups(
                    &provider,
                    &artifacts,
                    registry,
                    "Registry",
                    Bytes::new(),
                    Some(sender),
                )
                .await?;
                summary.upgraded.push("registry".into());
            }
            Upgrade::WalletFactory => {
                upgrade_uups(
                    &provider,
                    &artifacts,
                    factory,
                    "WalletFactory",
                    Bytes::new(),
                    Some(sender),
                )
                .await?;
                summary.upgraded.push("wallet-factory".into());
            }
            Upgrade::Notary => {
                upgrade_uups(
                    &provider,
                    &artifacts,
                    notary_contract,
                    "Notary",
                    Bytes::new(),
                    Some(sender),
                )
                .await?;
                summary.upgraded.push("notary".into());
            }
            Upgrade::Bank => {
                replace_bank_facets(&provider, &artifacts, bank, Some(sender)).await?;
                summary.upgraded.push("bank".into());
            }
            // Handled above, where the deploy inputs live.
            Upgrade::OidcVerifier => {}
        }
    }

    // ── Idempotent configuration (always re-sent, mirroring reconcile) ───
    // getPlatform exposes only endpoint+handlePrefix, so a skip keyed on
    // those would miss idPrefix/idSuffix drift. setPlatform is owner-only
    // and idempotent on-chain, so re-sending is safe.
    for &(domain, endpoint, handle_prefix, id_prefix, id_suffix) in PLATFORM_CONFIGS {
        send_with_nonce_retry!(
            admin.setPlatform(
                domain.into(),
                endpoint.into(),
                handle_prefix.into(),
                id_prefix.into(),
                id_suffix.into(),
            ),
            format!("Registry.setPlatform({domain})"),
            &provider,
            sender
        )?;
        info!("Registry.setPlatform({domain}) done");
    }

    let bank_contract = Bank::new(bank, &provider);

    // Token registration tolerates "already registered" reverts: the call
    // dry-runs first, so a duplicate fails at send without costing gas.
    for token in &cfg.tokens {
        let token_addr: Address = token
            .address
            .parse()
            .map_err(|e| anyhow!("invalid token address for {}: {e}", token.symbol))?;
        match bank_contract
            .registerToken(token.symbol.clone(), token_addr)
            .send()
            .await
        {
            Ok(pending) => match pending.get_receipt().await {
                Ok(_) => info!("Bank.registerToken({}) done", token.symbol),
                Err(e) => info!(
                    "Bank.registerToken({}) confirmation failed (may already exist): {e}",
                    token.symbol
                ),
            },
            Err(e) => info!(
                "Bank.registerToken({}) send failed (may already exist): {e}",
                token.symbol
            ),
        }
    }

    // Templates: setPlatformTemplate is append-only on-chain, so replacing
    // needs a clear first. Clear + re-seed each platform back-to-back so a
    // transient failure mid-run leaves at most one platform bare, and a
    // re-run fully repairs it.
    for (platform, templates) in &cfg.templates {
        send_with_nonce_retry!(
            bank_contract.clearPlatformTemplates(platform.clone()),
            format!("Bank.clearPlatformTemplates({platform})"),
            &provider,
            sender
        )?;
        for template in templates.as_vec() {
            send_with_nonce_retry!(
                bank_contract.setPlatformTemplate(platform.clone(), template.clone()),
                format!("Bank.setPlatformTemplate({platform})"),
                &provider,
                sender
            )?;
        }
        info!("Bank templates re-seeded for {platform}");
    }

    // Web prefixes: cheap to diff, so only drift is sent.
    for (platform, prefix) in WEB_PREFIXES {
        let on_chain = bank_contract
            .getPlatformWebPrefix(platform.to_string())
            .call()
            .await
            .unwrap_or_default();
        if on_chain == *prefix {
            continue;
        }
        send_with_nonce_retry!(
            bank_contract.setPlatformWebPrefix(platform.to_string(), prefix.to_string()),
            format!("Bank.setPlatformWebPrefix({platform})"),
            &provider,
            sender
        )?;
        info!("Bank.setPlatformWebPrefix({platform}, {prefix}) done");
    }

    // ── Identity-names stack (only when the section is present) ──────────
    if let Some(identity) = &cfg.identity {
        apply_identity(
            &provider,
            &artifacts,
            libid_factory,
            sender,
            notary_contract,
            backend,
            identity,
            &mut summary,
        )
        .await?;
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
async fn factory_deploy_named<P: Provider>(
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
/// entry contract since 0.3.0.
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
    let mut creation_code = artifacts.bytecode("ERC1967Proxy")?.to_vec();
    creation_code.extend_from_slice(
        &(implementation, Bytes::from(init_call.abi_encode())).abi_encode_params(),
    );
    factory_deploy_named(provider, factory, name, creation_code.into(), sender).await
}

/// Deploy a fresh Bank diamond THROUGH the factory under [`names::BANK`].
///
/// Same construction as `libid_contracts::diamond::deploy_bank_diamond`,
/// except the Diamond itself is CREATE3-deployed so its address is
/// name-derived — CREATE3 makes the constructor args (owner, cut facet)
/// irrelevant to the address. The facets, `BankInit`, and the follow-up
/// `diamondCut` are plain: they are code behind the diamond, not entries.
#[allow(clippy::too_many_arguments)]
async fn deploy_bank_diamond_via_factory<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    factory: Address,
    owner: Address,
    notary_contract: Address,
    backend: Address,
    registry: Address,
) -> Result<Address> {
    // A name already consumed means a previous apply got at least as far as
    // the diamond constructor; reuse it and let the cut below be the judge.
    let record = LibidFactory::new(factory, provider)
        .deployedAt(names::BANK.to_string())
        .call()
        .await
        .map_err(|e| anyhow!("factory deployedAt(libid.Bank) read failed: {e}"))?;
    if record != Address::ZERO {
        info!("Bank diamond already deployed by the factory at {record:#x} — reusing");
        return Ok(record);
    }

    // DiamondCutFacet — the one facet the Diamond ctor wires in itself.
    let cut_facet_addr = deploy_contract_from(
        provider,
        artifacts.bytecode("DiamondCutFacet")?,
        "DiamondCutFacet",
        Some(owner),
    )
    .await?;

    // Diamond(address owner, address diamondCutFacet), CREATE3 under the
    // canonical name.
    let mut creation_code = artifacts.bytecode("Diamond")?.to_vec();
    creation_code.extend_from_slice(&(owner, cut_facet_addr).abi_encode_params());
    let diamond_addr =
        factory_deploy_named(provider, factory, names::BANK, creation_code.into(), owner)
            .await?;

    // Remaining facets: deploy each and collect its selectors for one ADD
    // cut. (DiamondCutFacet is intentionally absent — already cut in.)
    let mut cut = Vec::with_capacity(BANK_FACETS.len());
    for &facet in BANK_FACETS {
        let facet_addr = deploy_contract_from(
            provider,
            artifacts.bytecode(facet)?,
            facet,
            Some(owner),
        )
        .await?;
        cut.push(IDiamondCut::FacetCut {
            facetAddress: facet_addr,
            action: facet_cut_action::ADD,
            functionSelectors: artifacts.facet_selectors(facet)?,
        });
    }

    // One-shot initializer, delegatecalled by diamondCut in diamond storage.
    let bank_init_addr = deploy_contract_from(
        provider,
        artifacts.bytecode("BankInit")?,
        "BankInit",
        Some(owner),
    )
    .await?;
    let init_calldata: Bytes = BankInit::initCall {
        notary: notary_contract,
        backend,
        registry,
    }
    .abi_encode()
    .into();

    let diamond = IDiamondCut::new(diamond_addr, provider);
    send_with_nonce_retry!(
        diamond.diamondCut(cut.clone(), bank_init_addr, init_calldata.clone()),
        "Diamond.diamondCut",
        provider,
        owner
    )?;
    Ok(diamond_addr)
}

/// Deploy the X ZK login verifier stack (XHonkVerifier + XZkVerifier UUPS
/// proxy, the latter CREATE3-named). Does NOT register it on the Registry.
async fn deploy_x_zk_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    factory: Address,
    sender: Address,
    notary_contract: Address,
    client_id: &str,
) -> Result<Address> {
    // The generated UltraHonk verifiers exceed EIP-170; the target chain
    // must allow big code (Eden does).
    info!("deploying XHonkVerifier (exceeds EIP-170; the chain must allow big code)");
    let honk_bytecode = artifacts
        .linked_bytecode(provider, "XHonkVerifier", "XHonkVerifier", Some(sender))
        .await?;
    let honk =
        deploy_contract_from(provider, honk_bytecode, "XHonkVerifier", Some(sender))
            .await?;
    info!("XHonkVerifier deployed at {honk:#x}");

    let addr = deploy_named_proxy(
        provider,
        artifacts,
        factory,
        names::X_ZK_VERIFIER,
        "XZkVerifier",
        &XZkVerifier::initializeCall {
            _owner: sender,
            _notaryContract: notary_contract,
            _honkVerifier: honk,
            _xClientId: Bytes::from(client_id.as_bytes().to_vec()),
            _endpoint: X_ENDPOINT.into(),
            _handlePrefix: X_HANDLE_PREFIX.into(),
            _platformName: X_DOMAIN.into(),
        },
        sender,
    )
    .await?;
    info!("XZkVerifier proxy deployed at {addr:#x}");
    Ok(addr)
}

/// Deploy the Google OIDC verifier stack (HonkVerifier + GoogleOidcVerifier
/// behind an ERC1967 proxy). Does NOT register it on the Registry.
///
/// `factory`: `Some` deploys the proxy CREATE3-named through the factory
/// (the first, canonical deployment); `None` is the `--upgrade
/// oidc-verifier` REPLACE path — plain CREATE, because the canonical name
/// is single-use and the replacement's address is meant to change.
///
/// The proxy is not optional: GoogleOidcVerifier's constructor calls
/// `_disableInitializers()`, so the bare implementation can never be
/// initialized.
async fn deploy_oidc_verifier<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    factory: Option<Address>,
    sender: Address,
    notary_contract: Address,
    initial_aud: &str,
) -> Result<Address> {
    // The circuit binds the JWT `aud` and the contract enforces it, so an
    // empty client id yields a verifier that rejects every real proof.
    if initial_aud.trim().is_empty() {
        bail!(
            "platforms.google_client_id is required to deploy the OIDC verifier: it \
             becomes the expected JWT audience, and a verifier deployed without it \
             rejects every proof"
        );
    }
    info!("deploying OIDC HonkVerifier (exceeds EIP-170; the chain must allow big code)");
    let honk_bytecode = artifacts
        .linked_bytecode(provider, "Verifier", "HonkVerifier", Some(sender))
        .await?;
    let honk =
        deploy_contract_from(provider, honk_bytecode, "OIDC HonkVerifier", Some(sender))
            .await?;
    info!("OIDC HonkVerifier deployed at {honk:#x}");

    let init_call = GoogleOidcVerifier::initializeCall {
        _verifier: honk,
        _owner: sender,
        notaryContract_: notary_contract,
        initialAud: initial_aud.into(),
    };
    let addr = match factory {
        Some(factory) => {
            deploy_named_proxy(
                provider,
                artifacts,
                factory,
                names::GOOGLE_OIDC_VERIFIER,
                "GoogleOidcVerifier",
                &init_call,
                sender,
            )
            .await?
        }
        None => {
            deploy_behind_proxy(
                provider,
                artifacts,
                "GoogleOidcVerifier",
                &init_call,
                Some(sender),
            )
            .await?
        }
    };
    info!("GoogleOidcVerifier proxy deployed at {addr:#x}");
    Ok(addr)
}

/// Converge the identity-names stack. GitHub needs only the Notary contract
/// and the backend key and is always wired; X and Google each need a large
/// Honk circuit verifier and are requested by their key being PRESENT in
/// the section. Deployed-vs-not is read from chain state at the declared
/// canonical addresses.
#[allow(clippy::too_many_arguments)]
async fn apply_identity<P: Provider>(
    provider: &P,
    artifacts: &Artifacts,
    libid_factory: Address,
    sender: Address,
    notary_contract: Address,
    backend: Address,
    identity: &crate::config::Identity,
    summary: &mut Summary,
) -> Result<()> {
    // The naming contract first: every setPlatform below is a call to it.
    let names_declared =
        required_address(&identity.identity_names, "identity.identity_names")?;
    let names = if code_present(provider, names_declared).await? {
        names_declared
    } else {
        let addr = deploy_named_proxy(
            provider,
            artifacts,
            libid_factory,
            names::IDENTITY_NAMES,
            "IdentityNames",
            &IdentityNames::initializeCall { owner_: sender },
            sender,
        )
        .await?;
        info!("IdentityNames deployed at {addr:#x}");
        summary
            .deployed
            .push(("identity.identity_names".into(), addr));
        addr
    };

    let mut wired: Vec<(&IdentityPlatform, Address)> = Vec::new();

    // GitHub: always wired once the section exists.
    let github_declared = required_address(
        &identity.github_identity_verifier,
        "identity.github_identity_verifier",
    )?;
    let github = if code_present(provider, github_declared).await? {
        github_declared
    } else {
        let (endpoint, handle_prefix, id_prefix, id_suffix) = GITHUB_SHAPE;
        let addr = deploy_named_proxy(
            provider,
            artifacts,
            libid_factory,
            names::GITHUB_IDENTITY_VERIFIER,
            "GitHubIdentityVerifier",
            &GitHubIdentityVerifier::initializeCall {
                owner_: sender,
                notaryContract_: notary_contract,
                backend_: backend,
                shape_: GitHubIdentityVerifier::ResponseShape {
                    endpoint: endpoint.into(),
                    handlePrefix: handle_prefix.into(),
                    idPrefix: id_prefix.into(),
                    idSuffix: id_suffix.into(),
                },
            },
            sender,
        )
        .await?;
        info!("GitHubIdentityVerifier deployed at {addr:#x}");
        summary
            .deployed
            .push(("identity.github_identity_verifier".into(), addr));
        addr
    };
    wired.push((&IDENTITY_GITHUB, github));

    // X: requested by the key being present.
    if let Some(value) = &identity.x_identity_verifier {
        let declared = required_address(value, "identity.x_identity_verifier")?;
        let addr = if code_present(provider, declared).await? {
            declared
        } else {
            info!(
                "deploying XHonkVerifier for identity (exceeds EIP-170; the chain \
                 must allow big code)"
            );
            let honk_bytecode = artifacts
                .linked_bytecode(provider, "XHonkVerifier", "XHonkVerifier", Some(sender))
                .await?;
            let honk = deploy_contract_from(
                provider,
                honk_bytecode,
                "XHonkVerifier (identity)",
                Some(sender),
            )
            .await?;
            let addr = deploy_named_proxy(
                provider,
                artifacts,
                libid_factory,
                names::X_IDENTITY_VERIFIER,
                "XIdentityVerifier",
                &XIdentityVerifier::initializeCall {
                    owner_: sender,
                    notaryContract_: notary_contract,
                    honkVerifier_: honk,
                    shape_: XIdentityVerifier::ResponseShape {
                        platformName: X_DOMAIN.into(),
                        endpoint: X_ENDPOINT.into(),
                        handlePrefix: X_HANDLE_PREFIX.into(),
                        idPrefix: crate::platforms::X_ID_PREFIX.into(),
                        idSuffix: crate::platforms::X_ID_SUFFIX.into(),
                    },
                },
                sender,
            )
            .await?;
            info!("XIdentityVerifier deployed at {addr:#x}");
            summary
                .deployed
                .push(("identity.x_identity_verifier".into(), addr));
            addr
        };
        wired.push((&IDENTITY_X, addr));
    }

    // Google: requested by the key being present. Also needs the JWKS
    // trust list (validate guarantees its key is declared alongside).
    if let Some(value) = &identity.google_identity_verifier {
        let declared = required_address(value, "identity.google_identity_verifier")?;
        let addr = if code_present(provider, declared).await? {
            declared
        } else {
            let roots_declared = required_address(
                identity.identity_jwks_roots.as_deref().unwrap_or(""),
                "identity.identity_jwks_roots",
            )?;
            let roots = if code_present(provider, roots_declared).await? {
                roots_declared
            } else {
                let roots = deploy_named_proxy(
                    provider,
                    artifacts,
                    libid_factory,
                    names::IDENTITY_JWKS_ROOTS,
                    "IdentityJwksRoots",
                    &IdentityJwksRoots::initializeCall {
                        owner_: sender,
                        notaryContract_: notary_contract,
                    },
                    sender,
                )
                .await?;
                info!("IdentityJwksRoots deployed at {roots:#x}");
                summary
                    .deployed
                    .push(("identity.identity_jwks_roots".into(), roots));
                roots
            };
            info!(
                "deploying Google HonkVerifier for identity (exceeds EIP-170; the \
                 chain must allow big code)"
            );
            let honk_bytecode = artifacts
                .linked_bytecode(provider, "Verifier", "HonkVerifier", Some(sender))
                .await?;
            let honk = deploy_contract_from(
                provider,
                honk_bytecode,
                "HonkVerifier (Google identity)",
                Some(sender),
            )
            .await?;
            let addr = deploy_named_proxy(
                provider,
                artifacts,
                libid_factory,
                names::GOOGLE_IDENTITY_VERIFIER,
                "GoogleIdentityVerifier",
                &GoogleIdentityVerifier::initializeCall {
                    owner_: sender,
                    honkVerifier_: honk,
                    jwksRoots_: roots,
                },
                sender,
            )
            .await?;
            info!("GoogleIdentityVerifier deployed at {addr:#x}");
            warn!(
                "IdentityJwksRoots at {roots:#x} starts EMPTY. Point a JWKS \
                 rotation listener at it before Google names work."
            );
            summary
                .deployed
                .push(("identity.google_identity_verifier".into(), addr));
            addr
        };
        wired.push((&IDENTITY_GOOGLE, addr));
    }

    // Wire every known platform. Owner-only and idempotent, so re-sending
    // converges wiring drift too.
    let names_contract = IdentityNames::new(names, provider);
    for (platform, verifier) in wired {
        send_with_nonce_retry!(
            names_contract.setPlatform(
                identity_platform_id(platform.domain),
                verifier,
                platform.allowance,
                platform.rules.clone(),
            ),
            format!("IdentityNames.setPlatform({})", platform.label),
            provider,
            sender
        )?;
        info!("IdentityNames.setPlatform({}) done", platform.label);
    }

    Ok(())
}
